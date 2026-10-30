import Foundation
import AppShared
import AuthenticationServices
import LocalAuthentication
import Security

/// Face ID / passcode before any credential leaves the extension. Returns the Keychain vault opened
/// with the authenticated context (the local key is a `.userPresence` item).
@MainActor
protocol AutoFillAuthenticating {
    func authenticate(reason: String) async throws -> any KeychainVault
}

/// Opens the store read-only for the extension: `LocalStore.open` with the Keychain local key only,
/// no password KDF, no bootstrap.
protocol AutoFillStoreOpening: Sendable {
    func open(vault: any KeychainVault) throws -> any ItemStore
    /// The store's committed revision, read without the key (before Face ID); nil when unknown.
    func committedRevision() -> Int64?
}

struct ExtensionStoreOpener: AutoFillStoreOpening {
    let directory: @Sendable () throws -> URL
    init(directory: @escaping @Sendable () throws -> URL = { try AppGroup.vaultDirectory() }) { self.directory = directory }
    func open(vault: any KeychainVault) throws -> any ItemStore {
        try LocalStore.open(directory: try directory(), vault: vault)
    }
    func committedRevision() -> Int64? { (try? directory()).flatMap { LocalStore.committedRevision(directory: $0) } }
}

/// Copies the TOTP code local-only with the 60-second expiry (`SecretClipboard`).
@MainActor
protocol CodeCopying { func copy(_ text: String) }
extension SecretClipboard: CodeCopying {}

/// The extension's logic, apart from UIKit: authenticate, load, match, fill. Only passkey creation
/// (`PasskeyFlow.register`) commits, through the store opened here.
@MainActor
final class CredentialFlow {
    enum Failure: Error, Equatable {
        case notFound
        /// The app's "Erase this iPhone's vault" has not finished: never fill from a partly wiped vault.
        case erasePending
    }

    let auth: any AutoFillAuthenticating
    let opener: any AutoFillStoreOpening
    let matcher: AutoFillMatcher
    let clipboard: any CodeCopying
    let clock: any UnixClock
    /// The app's choices (app group): whether to copy the 2FA code on fill.
    let settings: AppSettings
    private(set) var snapshot: StoreSnapshot?
    /// The store opened by the last unlock (for `PasskeyFlow.register`'s commit); dropped with the snapshot.
    private(set) var store: (any ItemStore)?

    static let reason = String(localized: "Unlock LocalGateKeys to fill your password.")

    /// Awaited once when Face ID fails with `LAError.notInteractive` (-1004: the extension's UI was not on
    /// screen yet), before the single retry. The driver replaces it with "the next viewDidAppear, or its retry
    /// delay if the view already appeared". Throws on cancellation.
    var waitForInteractive: @MainActor () async throws -> Void = { try await Task.sleep(for: .milliseconds(300)) }

    init(auth: any AutoFillAuthenticating, opener: any AutoFillStoreOpening, matcher: AutoFillMatcher,
         clipboard: any CodeCopying, clock: any UnixClock, settings: AppSettings = .shared) {
        self.auth = auth; self.opener = opener; self.matcher = matcher; self.clipboard = clipboard; self.clock = clock
        self.settings = settings
    }

    /// Authenticates once per request (the driver calls `reset` after each one), then reads the current
    /// snapshot. `reason` is the Face ID prompt's text.
    func unlock(reason: String = CredentialFlow.reason) async throws -> StoreSnapshot {
        AutoFillTrace.log("unlock begin cancelled=\(Task.isCancelled) erasePending=\(settings.erasePending) cachedSnapshot=\(snapshot != nil)")
        try Task.checkCancellation()   // cancelled before the task first ran: no Face ID prompt
        guard !settings.erasePending else { reset(); throw Failure.erasePending }
        if let snapshot { return snapshot }
        let vault: any KeychainVault
        do { vault = try await authenticate(reason: reason) } catch {
            AutoFillTrace.log("unlock auth failed error=\(error: error) laCode=\((error as? LAError)?.code.rawValue ?? 0)")
            throw error
        }
        AutoFillTrace.log("unlock auth ok cancelled=\(Task.isCancelled)")
        try Task.checkCancellation()   // cancelled while Face ID was up: never open the store
        let s: StoreSnapshot, opened: any ItemStore
        do {
            opened = try opener.open(vault: vault)
            s = try opened.load()
        } catch {
            AutoFillTrace.log("unlock snapshot load failed error=\(error: error)")
            throw error
        }
        AutoFillTrace.log("unlock snapshot loaded records=\(s.records.count) revision=\(s.revision)")
        snapshot = s; store = opened
        return s
    }

    /// Face ID, retried once after `waitForInteractive` when it fails with notInteractive (-1004). A second
    /// failure, or a cancel during the wait, is thrown (no second prompt after a cancel).
    private func authenticate(reason: String) async throws -> any KeychainVault {
        do { return try await auth.authenticate(reason: reason) } catch where AutoFillErrorMapping.isRetryable(error) {
            AutoFillTrace.log("unlock auth notInteractive: waiting to retry once")
            do { try await waitForInteractive() } catch {
                AutoFillTrace.log("unlock retry abandoned during wait error=\(error: error)")
                throw error
            }
            try Task.checkCancellation()
            AutoFillTrace.log("unlock auth retry")
            return try await auth.authenticate(reason: reason)
        }
    }

    /// Logins for the page, best first (`prepareCredentialList`).
    func candidates(urls: [String]) async throws -> [AutoFillLogin] {
        matcher.matches(try await unlock(), urls: urls)
    }

    /// The login for a QuickType identity (`prepareInterfaceToProvideCredential`).
    func login(recordID: String) async throws -> AutoFillLogin {
        let snapshot = try await unlock()
        guard let l = matcher.login(id: recordID, in: snapshot) else {
            AutoFillTrace.log("lookup recordID=\(rid: recordID) found=false \(AutoFillMatcher.traceKind(id: recordID, in: snapshot))")
            throw Failure.notFound
        }
        AutoFillTrace.log("lookup recordID=\(rid: recordID) found=true kind=web hasUser=\(!l.username.isEmpty) hasPassword=\(!l.password.isEmpty) hasTOTP=\(l.totp != nil)")
        return l
    }

    /// Forgets the decrypted vault (after completing or cancelling a request).
    func reset() { snapshot = nil; store = nil }

    /// Called when a login is returned: copies its TOTP code (if it has one and "Copy 2FA code when filling"
    /// is on). Returns (user, password).
    func fill(_ login: AutoFillLogin) -> (user: String, password: String) {
        precondition(snapshot != nil, "fill before authentication")
        if settings.copyCodeOnFill, let t = login.totp,
           let code = try? TOTP.code(secret: t.secret, algorithm: t.algorithm, digits: t.digits, period: t.period, at: clock.now) {
            clipboard.copy(code)
        }
        return (login.username, login.password)
    }
}

/// Runs an AutoFill entry point's work on the main actor, whatever thread the system delivered it on.
/// The no-UI `provideCredentialWithoutUserInteraction` in particular can arrive on a background queue: in
/// Swift 6 the @objc thunk of a main-actor override then traps (`_checkExpectedExecutor`) before its body runs,
/// so a QuickType pick fills nothing and never reaches Face ID. The view controller's entry points are
/// `nonisolated` and come through here. On the main thread the work runs before `run` returns.
enum MainThreadEntry {
    static func run(_ body: @escaping @MainActor @Sendable () -> Void) {
        AutoFillTrace.log("entry hop onMain=\(Thread.isMainThread)")
        if Thread.isMainThread { MainActor.assumeIsolated(body) } else { DispatchQueue.main.async { MainActor.assumeIsolated(body) } }
    }
}

/// What a credential request names, read on the delivering thread (`ASCredentialRequest` is not Sendable)
/// before the hop to the main actor.
enum CredentialRequestRoute: Equatable, Sendable {
    /// A password (QuickType) identity: its record identifier is the store item id.
    case password(recordID: String)
    case passkey(recordID: String, rpID: String, clientDataHash: Data)
    /// No record identifier: answered at once, without unlocking.
    case identityNotFound

    static func of(_ request: any ASCredentialRequest) -> CredentialRequestRoute {
        if let pk = request as? ASPasskeyCredentialRequest {
            guard let identity = pk.credentialIdentity as? ASPasskeyCredentialIdentity,
                  let id = identity.recordIdentifier else { return .identityNotFound }
            return .passkey(recordID: id, rpID: identity.relyingPartyIdentifier, clientDataHash: pk.clientDataHash)
        }
        guard let id = request.credentialIdentity.recordIdentifier else { return .identityNotFound }
        return .password(recordID: id)
    }
}

/// Holds an interactive request until the extension's view has appeared. LocalAuthentication refuses Face ID
/// with -1004 (notInteractive) while the UI is not on screen, and a QuickType pick delivers
/// `prepareInterfaceToProvideCredential` about half a second before `viewDidAppear`. Fires at most once (one
/// request per extension instance); `cancel` suppresses it for good.
@MainActor
final class AppearanceGate {
    enum Outcome: Equatable { case queued, fired, dropped }

    private(set) var appeared = false
    private var pending: (@MainActor () -> Void)?
    /// Fired or cancelled: later requests are dropped.
    private var closed = false

    /// A request arrived: runs it now if the view has appeared, else keeps it for `didAppear`.
    @discardableResult
    func requestArrived(_ action: @escaping @MainActor () -> Void) -> Outcome {
        guard !closed, pending == nil else { return .dropped }
        guard appeared else { pending = action; return .queued }
        closed = true
        action()
        return .fired
    }

    /// The view appeared (any number of times). Returns whether a queued request fired.
    @discardableResult
    func didAppear() -> Bool {
        appeared = true
        guard !closed, let action = pending else { return false }
        pending = nil; closed = true
        action()
        return true
    }

    /// Returns whether a queued request was dropped.
    @discardableResult
    func cancel() -> Bool {
        let had = pending != nil
        pending = nil; closed = true
        return had
    }
}

/// Where a request's outcome goes (the view controller; a recorder in tests).
@MainActor
protocol CredentialRequestSink: AnyObject {
    func showList(_ logins: [AutoFillLogin])
    func completeRequest(user: String, password: String)
    func cancelRequest(_ code: ASExtensionError.Code)
    func showPasskeys(_ rows: [PasskeyCandidate])
    func completePasskey(_ assertion: PasskeyAssertion)
    func completeRegistration(_ registration: PasskeyRegistration)
    /// Text insertion (iOS 18+, UX workstream 11): the card and identity fields, after the unlock.
    func showTextFields(_ fields: [TextInsertionField])
    /// Exactly one per text-insertion request: the picked field's text.
    func completeText(_ text: String)
}

/// One AutoFill request at a time, finished exactly once. Cancel stops the in-flight task; a task that
/// resumes after its request finished (or was superseded) drops its result and the decrypted snapshot,
/// so nothing is listed, filled or copied after the user cancelled, and the extension context gets
/// exactly one `completeRequest` or `cancelRequest`.
@MainActor
final class CredentialRequestDriver {
    let flow: CredentialFlow
    weak var sink: (any CredentialRequestSink)?
    private(set) var task: Task<Void, Never>?
    private var generation = 0
    /// False until this extension instance has reported an outcome, so a cancel that arrives before any
    /// request began is still reported once; `start` re-arms it for each new request.
    private(set) var finished = false

    /// Passkey sign-in over the same unlock, snapshot and lifecycle.
    let passkeys: PasskeyFlow
    /// The open passkey list's request (relying party and client data hash), for `selectPasskey`.
    private var passkeyRequest: (rpID: String, clientDataHash: Data)?
    /// Set by the first Create: a second tap must not restart the registration (a second Face ID prompt,
    /// or a second passkey once the first one has committed).
    private var registrationStarted = false

    /// Interactive requests wait here for the view to appear (`whenAppeared`, `viewDidAppear`).
    let gate = AppearanceGate()
    /// The pause before the one notInteractive retry when the view has already appeared.
    var retryDelay: Duration = .milliseconds(300)
    /// Unlocks waiting for the next `viewDidAppear` before their retry.
    private var appearWaiters: [UUID: CheckedContinuation<Void, Error>] = [:]

    convenience init(flow: CredentialFlow) { self.init(passkeys: PasskeyFlow(credentials: flow)) }
    init(passkeys: PasskeyFlow) {
        self.passkeys = passkeys; flow = passkeys.credentials
        flow.waitForInteractive = { [weak self] in
            guard let self else { throw CancellationError() }
            try await self.waitUntilInteractive()
        }
    }

    /// Runs an interactive request (one that needs Face ID) once the view has appeared: now if it already has.
    func whenAppeared(_ label: StaticString, _ body: @escaping @MainActor () -> Void) {
        switch gate.requestArrived(body) {
        case .queued: AutoFillTrace.log("gate.queued request=\(name: label) (view not appeared yet)")
        case .fired: AutoFillTrace.log("gate.fired request=\(name: label) (view already appeared)")
        case .dropped: AutoFillTrace.log("gate.dropped request=\(name: label) (cancelled, or not the first request)")
        }
    }

    /// The view controller's `viewDidAppear`: fires a queued request and wakes an unlock waiting to retry.
    func viewDidAppear() {
        if gate.didAppear() { AutoFillTrace.log("gate.fired on viewDidAppear") }
        let waiters = appearWaiters.values
        appearWaiters = [:]
        if !waiters.isEmpty { AutoFillTrace.log("retry.wake on viewDidAppear waiters=\(waiters.count)") }
        waiters.forEach { $0.resume() }
    }

    /// Before the notInteractive retry: the next `viewDidAppear`, or `retryDelay` if the view already appeared.
    /// Throws `CancellationError` when the request is cancelled meanwhile.
    func waitUntilInteractive() async throws {
        if gate.appeared {
            AutoFillTrace.log("retry.wait delay (view already appeared)")
            try await Task.sleep(for: retryDelay)
            return
        }
        AutoFillTrace.log("retry.wait for viewDidAppear")
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                if Task.isCancelled { c.resume(throwing: CancellationError()) } else { appearWaiters[id] = c }
            }
        } onCancel: {
            Task { @MainActor [weak self] in self?.appearWaiters.removeValue(forKey: id)?.resume(throwing: CancellationError()) }
        }
    }

    private func start(_ body: @escaping @MainActor (_ isLive: @escaping @MainActor () -> Bool) async -> Void) {
        task?.cancel()
        generation += 1
        finished = false
        let gen = generation
        AutoFillTrace.log("driver.start generation=\(gen)")
        let isLive: @MainActor () -> Bool = { [weak self] in
            guard let self else { AutoFillTrace.log("driver.isLive=false (driver gone) generation=\(gen)"); return false }
            let live = !Task.isCancelled && !self.finished && self.generation == gen
            AutoFillTrace.log("driver.isLive=\(live) cancelled=\(Task.isCancelled) finished=\(self.finished) generation=\(gen) current=\(self.generation)")
            return live
        }
        task = Task { @MainActor in
            AutoFillTrace.log("driver.task running generation=\(gen)")
            await body(isLive)
        }
    }

    /// `prepareCredentialList`.
    func beginList(urls: [String]) {
        AutoFillTrace.log("driver.beginList services=\(hosts: urls)")
        start { [weak self] isLive in
            guard let self else { return }
            guard isLive() else { return }
            do {
                let logins = try await self.flow.candidates(urls: urls)
                guard isLive() else { return self.dropStale() }
                self.sink?.showList(logins)
            } catch {
                guard isLive() else { return self.dropStale() }
                self.cancel(AutoFillErrorMapping.code(for: error))
            }
        }
    }

    /// `prepareInterfaceToProvideCredential`: a password identity, a passkey, or none.
    func begin(_ route: CredentialRequestRoute) {
        switch route {
        case .password(let id): AutoFillTrace.log("driver.begin route=password recordID=\(rid: id)")
        case .passkey(let id, let rp, _): AutoFillTrace.log("driver.begin route=passkey recordID=\(rid: id) rp=\(host: rp)")
        case .identityNotFound: AutoFillTrace.log("driver.begin route=identityNotFound")
        }
        switch route {
        case .password(let id): beginIdentity(recordID: id)
        case let .passkey(id, rpID, hash): beginPasskey(recordID: id, rpID: rpID, clientDataHash: hash)
        case .identityNotFound: finishImmediately(.credentialIdentityNotFound)
        }
    }

    /// `prepareInterfaceToProvideCredential` for a QuickType identity.
    func beginIdentity(recordID: String) {
        AutoFillTrace.log("driver.beginIdentity recordID=\(rid: recordID)")
        start { [weak self] isLive in
            guard let self else { return }
            guard isLive() else { return }
            do {
                let login = try await self.flow.login(recordID: recordID)
                guard isLive() else { return self.dropStale() }
                self.complete(login)
            } catch {
                AutoFillTrace.log("driver.beginIdentity error=\(error: error)")
                guard isLive() else { return self.dropStale() }
                self.cancel(error as? CredentialFlow.Failure == .notFound ? .credentialIdentityNotFound
                                                                           : AutoFillErrorMapping.code(for: error))
            }
        }
    }

    /// `prepareCredentialList(for:requestParameters:)`: the usable passkeys for the relying party.
    func beginPasskeyList(rpID: String, allowed: [Data], clientDataHash: Data) {
        AutoFillTrace.log("driver.beginPasskeyList rp=\(host: rpID) allowed=\(allowed.count)")
        passkeyRequest = (rpID, clientDataHash)
        start { [weak self] isLive in
            guard let self else { return }
            guard isLive() else { return }
            do {
                let list = try await self.passkeys.candidates(rpID: rpID, allowed: allowed)
                guard isLive() else { return self.dropStale() }
                self.sink?.showPasskeys(list)
            } catch {
                guard isLive() else { return self.dropStale() }
                self.cancel(AutoFillErrorMapping.code(for: error))
            }
        }
    }

    /// The user picked a passkey in the list.
    func selectPasskey(_ row: PasskeyCandidate) {
        guard !finished, let req = passkeyRequest else { return }
        beginPasskey(recordID: row.itemID, rpID: req.rpID, clientDataHash: req.clientDataHash)
    }

    /// `prepareInterfaceToProvideCredential` for an `ASPasskeyCredentialRequest`. UV is claimed because Face ID
    /// runs in `unlock` for this request: that holds only because every request ends in `flow.reset()`
    /// (`completePasskey`, `complete`, `cancel`, `completeRegistration`), so no request reuses an earlier unlock.
    func beginPasskey(recordID: String, rpID: String, clientDataHash: Data) {
        AutoFillTrace.log("driver.beginPasskey recordID=\(rid: recordID) rp=\(host: rpID)")
        start { [weak self] isLive in
            guard let self else { return }
            guard isLive() else { return }
            do {
                let a = try await self.passkeys.assert(recordID: recordID, rpID: rpID, clientDataHash: clientDataHash,
                                                       userVerified: true)
                guard isLive() else { return self.dropStale() }
                self.completePasskey(a)
            } catch {
                guard isLive() else { return self.dropStale() }
                self.cancel(error as? PasskeyFlow.Failure == .notFound ? .credentialIdentityNotFound
                                                                       : AutoFillErrorMapping.code(for: error))
            }
        }
    }

    /// `prepareInterface(forPasskeyRegistration:)`, after the user tapped Create on the confirmation sheet.
    /// Face ID runs for this request (see `beginPasskey` on UV and `flow.reset()`).
    func beginRegistration(_ r: PasskeyRegistrationRequest) {
        guard !registrationStarted else { return }
        registrationStarted = true
        start { [weak self] isLive in
            guard let self else { return }
            guard isLive() else { return }
            do {
                let out = try await self.passkeys.register(rpID: r.rpID, rpName: r.rpName, userName: r.userName,
                                                           userDisplayName: r.userDisplayName, userHandle: r.userHandle,
                                                           clientDataHash: r.clientDataHash, algorithms: r.algorithms)
                // Committed: the passkey exists even if this request was cancelled meanwhile; the site just
                // never hears of it (like a desktop create the page abandoned).
                guard isLive() else { return self.dropStale() }
                self.completeRegistration(PasskeyRegistration(rpID: PasskeyRecord.normaliseRPID(r.rpID),
                                                              clientDataHash: r.clientDataHash,
                                                              credentialID: out.credentialID,
                                                              attestationObject: out.attestationObject))
            } catch {
                guard isLive() else { return self.dropStale() }
                self.cancel(AutoFillErrorMapping.code(for: error))
            }
        }
    }

    private func completeRegistration(_ r: PasskeyRegistration) {
        guard !finished else { return }
        finished = true
        flow.reset()
        sink?.completeRegistration(r)
    }

    private func completePasskey(_ a: PasskeyAssertion) {
        guard !finished else { return }
        finished = true
        passkeyRequest = nil
        flow.reset()   // drops the snapshot, and with it every decoded key
        sink?.completePasskey(a)
    }

    /// A request that can be answered without unlocking (e.g. a QuickType identity with no record id):
    /// finishes now, starts no task, never prompts.
    /// The fields' unlock prompt: the card number and security code are behind it, every time.
    static let textReason = String(localized: "Unlock LocalGateKeys to fill a card or identity.")

    /// `prepareInterfaceForUserChoosingTextToInsert` (iOS 18+): Face ID, then the card and identity fields.
    /// Nothing is pre-selected; the user picks one row (`selectText`).
    func beginTextInsertion() {
        AutoFillTrace.log("driver.beginTextInsertion")
        start { [weak self] isLive in
            guard let self else { return }
            guard isLive() else { return }
            do {
                let snapshot = try await self.flow.unlock(reason: Self.textReason)
                guard isLive() else { return self.dropStale() }
                self.sink?.showTextFields(TextInsertionCatalog.fields(snapshot))
            } catch {
                guard isLive() else { return self.dropStale() }
                self.cancel(AutoFillErrorMapping.code(for: error))
            }
        }
    }

    /// The user picked a field: its text goes back once and the snapshot is dropped. Nothing is inserted
    /// without the unlock that built the list.
    func selectText(_ field: TextInsertionField) {
        AutoFillTrace.log("driver.selectText isCard=\(field.isCard) finished=\(finished)")
        guard !finished, flow.snapshot != nil else { return }
        finished = true
        flow.reset()
        sink?.completeText(field.value)
    }

    func finishImmediately(_ code: ASExtensionError.Code) {
        AutoFillTrace.log("driver.finishImmediately code=\(code.rawValue)")
        task?.cancel()
        cancel(code)
    }

    /// The user picked a row in the list.
    func select(_ login: AutoFillLogin) { complete(login) }

    func complete(_ login: AutoFillLogin) {
        AutoFillTrace.log("driver.complete recordID=\(rid: login.id) finished=\(finished)")
        guard !finished else { return }
        finished = true
        let filled = flow.fill(login)
        flow.reset()
        sink?.completeRequest(user: filled.user, password: filled.password)
    }

    func cancel(_ code: ASExtensionError.Code) {
        AutoFillTrace.log("driver.cancel code=\(code.rawValue) finished=\(finished)")
        if gate.cancel() { AutoFillTrace.log("gate.cancelled a queued request before the view appeared") }
        guard !finished else { return }
        finished = true
        task?.cancel()
        passkeyRequest = nil
        flow.reset()
        sink?.cancelRequest(code)
    }

    /// A stale task's unlock may have re-filled the snapshot: forget it unless a newer request is live.
    private func dropStale() {
        AutoFillTrace.log("driver.dropStale finished=\(finished)")
        if finished { flow.reset() }
    }
}

/// Which `ASExtensionError` a failed unlock/load reports: only a user/system/app cancellation counts as
/// `userCanceled`; everything else (no local key, corrupt store, biometry lockout, ...) is `failed`.
enum AutoFillErrorMapping {
    static func code(for error: Error) -> ASExtensionError.Code {
        if let la = error as? LAError, [.userCancel, .systemCancel, .appCancel].contains(la.code) { return .userCanceled }
        if case KeychainVaultError.status(let st) = error, st == errSecUserCanceled { return .userCanceled }
        return .failed   // notInteractive (-1004) too, once its one retry has failed
    }

    /// `LAError.notInteractive` (-1004): Face ID was asked for before the extension's UI was on screen. Not a
    /// user cancel; the unlock waits for the view and retries once.
    static func isRetryable(_ error: Error) -> Bool {
        let ns = error as NSError
        return ns.domain == LAErrorDomain && ns.code == LAError.Code.notInteractive.rawValue
    }
}
