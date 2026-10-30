import Foundation
import Observation
import AuthenticationServices
import AppSharedMac

/// What a macOS credential request names, read on the delivering thread (`ASCredentialRequest` is not
/// Sendable) before the hop to the main actor.
enum MacAutoFillRequest: Equatable, Sendable {
    /// `prepareCredentialList`: the page's logins first, then search all.
    case list(urls: [String])
    /// `prepareOneTimeCodeCredentialList` (macOS 15+): the page's logins with a 2FA secret.
    case oneTimeCodeList(urls: [String])
    /// A password identity picked in Safari's suggestions; its record identifier is the store item id.
    case password(recordID: String)
    /// A one-time code identity (macOS 15+).
    case oneTimeCode(recordID: String)
    /// `prepareCredentialList(for:requestParameters:)`: the relying party's usable passkeys (filtered by the
    /// site's allow-list), then the page's logins. With "Offer passkeys" off, the plain login list.
    case passkeyList(urls: [String], rpID: String, allowed: [Data], clientDataHash: Data)
    /// A passkey identity picked in Safari's suggestions; its record identifier is the store item id.
    case passkey(recordID: String, rpID: String, clientDataHash: Data)
    /// No record identifier, or a kind this extension does not fill here.
    case identityNotFound
    /// A passkey registration (`prepareInterface(forPasskeyRegistration:)`).
    case passkeyRegistration(PasskeyRegistrationRequest)
    /// A registration request that is not a passkey request: refused (`.failed`, the system falls back).
    case unsupportedRegistration
    /// `prepareInterfaceForUserChoosingTextToInsert` (UX workstream 11): a card or identity field to insert.
    case textToInsert

    static func of(_ request: any ASCredentialRequest) -> MacAutoFillRequest {
        if let pk = request as? ASPasskeyCredentialRequest {
            guard let identity = pk.credentialIdentity as? ASPasskeyCredentialIdentity,
                  let id = identity.recordIdentifier else { return .identityNotFound }
            return .passkey(recordID: id, rpID: identity.relyingPartyIdentifier, clientDataHash: pk.clientDataHash)
        }
        if #available(macOS 15.0, *), request.type == .oneTimeCode {
            guard let id = request.credentialIdentity.recordIdentifier else { return .identityNotFound }
            return .oneTimeCode(recordID: id)
        }
        guard request.type == .password, let id = request.credentialIdentity.recordIdentifier else { return .identityNotFound }
        return .password(recordID: id)
    }

    /// `prepareInterface(forPasskeyRegistration:)`. No relying-party name or display name is handed over:
    /// the title falls back to the rp id (iPhone behaviour).
    static func registration(_ request: any ASCredentialRequest) -> MacAutoFillRequest {
        guard let pk = request as? ASPasskeyCredentialRequest,
              let identity = pk.credentialIdentity as? ASPasskeyCredentialIdentity else { return .unsupportedRegistration }
        return .passkeyRegistration(PasskeyRegistrationRequest(
            rpID: identity.relyingPartyIdentifier, rpName: "", userName: identity.userName, userDisplayName: "",
            userHandle: identity.userHandle, clientDataHash: pk.clientDataHash,
            algorithms: pk.supportedAlgorithms.map { $0.rawValue }))
    }
}

/// Where a request's outcome goes (the view controller; a recorder in tests). Exactly one call per request.
@MainActor
protocol MacAutoFillSink: AnyObject {
    func completePassword(user: String, password: String)
    func completeOneTimeCode(_ code: String)
    func completePasskey(_ assertion: PasskeyAssertion)
    func completeRegistration(_ registration: PasskeyRegistration)
    func cancelRequest(_ code: ASExtensionError.Code)
    /// A text-insertion request's picked field (UX workstream 11).
    func completeText(_ text: String)
}

/// A login row: whether it needs the master password (`policy.require_master_password`).
struct MacAutoFillRow: Identifiable, Equatable, Sendable {
    let login: AutoFillLogin
    let strict: Bool
    var id: String { login.id }
}

/// The extension's logic, apart from AppKit: unlock (Touch ID item or master password, through
/// `ExtensionVaultOpener` and its shared throttle), list, strict check, fill. Reads only; never writes the
/// store, never touches the clipboard. Each request unlocks afresh, and the snapshot is dropped as soon as
/// the request finishes.
@MainActor @Observable
final class MacAutoFillModel {
    enum Screen: Equatable {
        /// Waiting for a request.
        case idle
        case unlock
        case list
        /// A strict login was picked: the master password again, even after a Touch ID unlock.
        case strict(MacAutoFillRow)
        /// A passkey registration after the unlock: site and account, Create or Cancel. Nothing is generated
        /// or written before Create.
        case createPasskey(rpID: String, userName: String)
        case finished
    }

    private(set) var screen: Screen = .idle
    private(set) var request: MacAutoFillRequest?
    /// The page's logins, best first.
    private(set) var matches: [MacAutoFillRow] = []
    /// Every live login (search all), by title.
    private(set) var all: [MacAutoFillRow] = []
    /// The relying party's usable passkeys (a passkey-capable page), shown above the logins.
    private(set) var passkeys: [PasskeyCandidate] = []
    /// A text-insertion request's card and identity fields, after the unlock; none is pre-selected.
    private(set) var textFields: [TextInsertionField] = []
    var isTextInsertion: Bool { request == .textToInsert }
    private(set) var message: String?
    private(set) var busy = false
    var query = ""

    @ObservationIgnored weak var sink: (any MacAutoFillSink)?
    @ObservationIgnored let opener: ExtensionVaultOpener
    @ObservationIgnored let matcher: AutoFillMatcher
    @ObservationIgnored let settings: AppSettings
    @ObservationIgnored let clock: any UnixClock
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored let pro: any ProEntitlementChecking
    @ObservationIgnored let licenseKeys: [String: [UInt8]]
    @ObservationIgnored let identities: (any PasskeyIdentityRefreshing)?
    @ObservationIgnored let random: any RandomSource
    @ObservationIgnored let today: @Sendable () -> String
    @ObservationIgnored private var snapshot: StoreSnapshot?
    /// The store the unlock opened: a passkey registration's only commit goes through it.
    @ObservationIgnored private var store: LocalStore?
    /// StoreKit's answer, asked at most once per request and only when the free plan is full.
    @ObservationIgnored private var entitled: Bool?
    /// The registration's plan-full check before the unlock (StoreKit), while it runs (tests await it).
    @ObservationIgnored private(set) var preflight: Task<Void, Never>?
    /// How this request was unlocked; a strict login still asks again after Touch ID.
    @ObservationIgnored private var unlockedWithPassword = false
    /// Bumped by each `begin`: an unlock finishing after a newer request began delivers nothing.
    @ObservationIgnored private var generation = 0

    /// Whether a decrypted snapshot is held (tests).
    var holdsSnapshot: Bool { snapshot != nil }

    static let touchIDReason = String(localized: "unlock LocalGateKeys to fill your password")

    init(opener: ExtensionVaultOpener, matcher: AutoFillMatcher, settings: AppSettings = .shared,
         clock: any UnixClock = SystemClock(), now: @escaping () -> Date = Date.init,
         pro: any ProEntitlementChecking = NoEntitlement(), licenseKeys: [String: [UInt8]] = LicenseKeys.production,
         identities: (any PasskeyIdentityRefreshing)? = nil, random: any RandomSource = SystemRandomSource(),
         today: @escaping @Sendable () -> String = PasskeyVault.localToday) {
        self.opener = opener; self.matcher = matcher; self.settings = settings; self.clock = clock; self.now = now
        self.pro = pro; self.licenseKeys = licenseKeys; self.identities = identities; self.random = random
        self.today = today
    }

    var touchIDAvailable: Bool { opener.touchIDAvailable }
    var isOneTimeCode: Bool {
        switch request {
        case .oneTimeCodeList, .oneTimeCode: return true
        default: return false
        }
    }

    /// Rows the list shows when the user searches: every login whose title or username contains the query.
    var searchResults: [MacAutoFillRow] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return [] }
        return all.filter { $0.login.title.localizedCaseInsensitiveContains(q) || $0.login.username.localizedCaseInsensitiveContains(q) }
    }

    /// A new request from the system. Nothing is answered before an unlock, except a request naming no record.
    func begin(_ r: MacAutoFillRequest) {
        generation += 1
        reset()
        message = nil
        var r = r
        switch r {
        case .identityNotFound: request = r; return finish(.credentialIdentityNotFound)
        case .unsupportedRegistration: request = r; return finish(.failed)
        // "Offer passkeys" off: a passkey request is declined before any prompt; a passkey-capable page
        // gets the plain login list.
        case .passkey, .passkeyRegistration:
            guard settings.offerPasskeys else { request = r; return finish(.failed) }
        case .passkeyList(let urls, _, _, _):
            if !settings.offerPasskeys { r = .list(urls: urls) }
        default: break
        }
        request = r
        // The app's "Erase this Mac's vault" has not finished: never fill from a partly wiped vault.
        guard !settings.erasePending else { return finish(.failed) }
        guard opener.exists else { return finish(.failed) }
        if case .passkeyRegistration(let req) = r {
            // ES256 only: otherwise the system offers another way to create it.
            guard req.algorithms.contains(PasskeyVault.es256) else { return finish(.failed) }
            // Over the limit at the store's current revision with no synced licence (`LocalStore` hint):
            // without the App Store entitlement, refused before the unlock.
            if let hinted = settings.planFullRevision, hinted == LocalStore.committedRevision(directory: opener.directory) {
                let gen = generation
                preflight = Task { [weak self, pro] in
                    let ok = await pro.isEntitled()
                    guard let self, gen == self.generation, self.screen == .idle else { return }
                    self.entitled = ok
                    guard ok else { return self.finish(.failed) }
                    self.screen = .unlock
                    self.message = self.throttleMessage()
                }
                return
            }
        }
        screen = .unlock
        message = throttleMessage()
    }

    func unlockWithTouchID() async {
        guard screen == .unlock, !busy else { return }
        busy = true; defer { busy = false }
        let gen = generation
        do {
            let store = try await opener.openWithTouchID(reason: Self.touchIDReason)
            guard gen == generation else { return }
            try loaded(store, password: false)
        } catch where gen != generation {
            return
        } catch BiometricKeyError.cancelled {
            message = nil
        } catch MacVaultError.biometricUnavailable {
            message = String(localized: "Touch ID is not available. Enter your master password.")
        } catch {
            fail(error)
        }
    }

    func unlock(password: String) async {
        guard screen == .unlock, !busy, !password.isEmpty else { return }
        busy = true; defer { busy = false }
        let gen = generation
        do {
            let store = try await opener.open(password: password)
            guard gen == generation else { return }
            try loaded(store, password: true)
        } catch where gen != generation {
            return
        } catch {
            fail(error)
        }
    }

    /// The user picked a card or identity field: inserted once, then the snapshot is dropped. The card number
    /// and security code are only ever listed after this request's own unlock.
    func selectText(_ field: TextInsertionField) {
        guard screen == .list, request == .textToInsert, snapshot != nil else { return }
        screen = .finished; reset()
        sink?.completeText(field.value)
    }

    /// The user picked a row.
    func select(_ row: MacAutoFillRow) {
        guard screen == .list else { return }
        if row.strict && !unlockedWithPassword {
            message = nil
            screen = .strict(row)
            return
        }
        fill(row.login)
    }

    /// The master password for a strict login; the shared throttle applies.
    func confirmStrict(password: String) async {
        guard case .strict(let row) = screen, !busy, !password.isEmpty else { return }
        busy = true; defer { busy = false }
        let gen = generation
        do {
            try await opener.verifyMasterPassword(password)
            guard gen == generation else { return }
            fill(row.login)
        } catch where gen != generation {
            return
        } catch {
            fail(error)
        }
    }

    /// Back from the strict prompt to the list.
    func cancelStrict() {
        guard case .strict = screen else { return }
        message = nil
        screen = .list
    }

    func cancel() { finish(.userCanceled) }

    /// The user picked a passkey in the list: signed with UV (Touch ID or the master password ran for this
    /// request).
    func selectPasskey(_ c: PasskeyCandidate) {
        guard screen == .list, case .passkeyList(_, let rpID, _, let hash)? = request else { return }
        sign(recordID: c.itemID, rpID: rpID, clientDataHash: hash)
    }

    /// Create on the registration sheet: the free-plan check again on each commit base, the key, one commit
    /// (one retry on a stale store), the AutoFill identities republished, then the registration.
    func createPasskey() async {
        guard case .createPasskey = screen, !busy, case .passkeyRegistration(let r)? = request,
              let store, let first = snapshot else { return }
        busy = true; defer { busy = false }
        let gen = generation
        let keys = licenseKeys, pro = pro, settings = settings
        do {
            let out = try await PasskeyVault.register(
                store: store, first: first, rpID: r.rpID, rpName: r.rpName, userName: r.userName,
                userDisplayName: r.userDisplayName, userHandle: r.userHandle, now: clock.now, random: random, today: today(),
                isPro: { [weak self] snap in
                    if ItemLimit.validLicense(in: snap, keys: keys) != nil { return true }
                    if self?.entitled == nil { self?.entitled = await pro.isEntitled() }
                    return self?.entitled == true
                },
                beforeWrite: { [weak self] in
                    // Cancelled or dismissed while StoreKit was asked: the system was told, so never write.
                    guard let self, gen == self.generation, case .createPasskey = self.screen else { throw CancellationError() }
                    // "Erase this Mac's vault" may have started meanwhile: never write into it.
                    if settings.erasePending { throw PasskeyFailure.storeBusy }
                })
            // Committed: the passkey exists even if the request went away meanwhile (iPhone behaviour).
            snapshot = nil
            if let identities { await identities.refresh(out.committed) }
            guard gen == generation else { return }
            let reg = PasskeyRegistration(rpID: PasskeyRecord.normaliseRPID(r.rpID), clientDataHash: r.clientDataHash,
                                          credentialID: out.credentialID, attestationObject: out.attestationObject)
            guard screen != .finished else { return }
            screen = .finished; reset()
            sink?.completeRegistration(reg)
        } catch where gen != generation {
            return
        } catch {
            finish(.failed)
        }
    }

    /// The system dismissed the sheet: forget the vault, and answer the request if it is still open.
    func dismissed() {
        generation += 1
        if screen == .idle || screen == .finished { reset() } else { finish(.userCanceled) }
    }

    // MARK: -

    private func loaded(_ store: LocalStore, password: Bool) throws {
        let s = try store.load()
        guard screen == .unlock else { return }
        snapshot = s; self.store = store; unlockedWithPassword = password; message = nil
        let strictIDs = Set(AutoFillMatcher.logins(s).filter { Self.isStrict($0.record) }.map(\.login.id))
        func row(_ l: AutoFillLogin) -> MacAutoFillRow { MacAutoFillRow(login: l, strict: strictIDs.contains(l.id)) }
        switch request {
        case .list(let urls), .oneTimeCodeList(let urls):
            let codes = isOneTimeCode
            let keep: (AutoFillLogin) -> Bool = { !codes || $0.totp != nil }
            matches = matcher.matches(s, urls: urls).filter(keep).map(row)
            all = AutoFillMatcher.logins(s).map(\.login).filter(keep)
                .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }.map(row)
            screen = .list
        case .password(let id), .oneTimeCode(let id):
            guard let l = matcher.login(id: id, in: s), !isOneTimeCode || l.totp != nil else {
                return finish(.credentialIdentityNotFound)
            }
            screen = .list
            select(row(l))
        case .passkeyList(let urls, let rpID, let allowed, _):
            passkeys = PasskeyVault.candidates(s, rpID: rpID, allowed: allowed)
            matches = matcher.matches(s, urls: urls).map(row)
            all = AutoFillMatcher.logins(s).map(\.login)
                .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }.map(row)
            screen = .list
        case .passkey(let id, let rpID, let hash):
            screen = .list
            sign(recordID: id, rpID: rpID, clientDataHash: hash)
        case .passkeyRegistration(let r):
            screen = .createPasskey(rpID: PasskeyRecord.normaliseRPID(r.rpID), userName: r.userName)
        case .textToInsert:
            textFields = TextInsertionCatalog.fields(s)
            screen = .list
        default:
            finish(.failed)
        }
    }

    static func isStrict(_ record: [String: JSONValue]) -> Bool {
        guard case .object(let policy)? = record["policy"], case .bool(true)? = policy["require_master_password"] else { return false }
        return true
    }

    private func sign(recordID: String, rpID: String, clientDataHash: Data) {
        guard let s = snapshot else { return finish(.failed) }
        do {
            let a = try PasskeyVault.assert(s, recordID: recordID, rpID: rpID, clientDataHash: clientDataHash, userVerified: true)
            guard screen != .finished else { return }
            screen = .finished; reset()   // drops the snapshot, and with it every decoded key
            sink?.completePasskey(a)
        } catch PasskeyFailure.notFound {
            finish(.credentialIdentityNotFound)
        } catch {
            finish(.failed)
        }
    }

    private func fill(_ login: AutoFillLogin) {
        if isOneTimeCode {
            guard let t = login.totp,
                  let code = try? TOTP.code(secret: t.secret, algorithm: t.algorithm, digits: t.digits, period: t.period, at: clock.now)
            else { return finish(.failed) }
            guard screen != .finished else { return }
            screen = .finished; reset()
            sink?.completeOneTimeCode(code)
        } else {
            guard screen != .finished else { return }
            screen = .finished; reset()
            sink?.completePassword(user: login.username, password: login.password)
        }
    }

    private func finish(_ code: ASExtensionError.Code) {
        guard screen != .finished else { return }
        screen = .finished; reset()
        sink?.cancelRequest(code)
    }

    /// Forgets the decrypted vault.
    private func reset() {
        snapshot = nil; store = nil; matches = []; all = []; passkeys = []; textFields = []; query = ""; unlockedWithPassword = false
        entitled = nil; preflight = nil
    }

    private func fail(_ error: Error) {
        switch error {
        case MacVaultError.wrongPassword(let until?), MacVaultError.throttled(let until):
            message = Self.throttleMessage(until: until, now: now())
        case MacVaultError.wrongPassword(nil): message = String(localized: "Wrong master password.")
        case MacVaultError.busy: break
        case MacVaultError.noVault: finish(.failed)
        default: message = String(localized: "The vault could not be opened.")
        }
    }

    private func throttleMessage() -> String? {
        opener.retryAfter.map { Self.throttleMessage(until: $0, now: now()) }
    }

    static func throttleMessage(until: Date, now: Date) -> String {
        String(localized: "Too many attempts. Try again in \(max(1, Int(until.timeIntervalSince(now).rounded(.up)))) s.")
    }
}
