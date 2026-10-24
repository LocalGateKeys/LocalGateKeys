import Foundation
import Observation
import AppShared

// MARK: seams

/// Called after every sync run so AutoFill's `ASCredentialIdentityStore` matches the vault
/// (`IdentityStoreSync`: username + domain only, replaced only while AutoFill is enabled).
protocol AutoFillIdentityRefreshing: Sendable {
    func syncDidFinish(store: any ItemStore) async
}

extension IdentityStoreSync: AutoFillIdentityRefreshing {
    func syncDidFinish(store: any ItemStore) async {
        // After lock the gated store refuses `load()`, so a locked vault is never decrypted again here.
        guard SyncCoordinator.stillOpen(store), let snapshot = try? store.load() else { return }
        await refresh(snapshot)
    }
}

/// The Wi-Fi transport as the coordinator uses it. Production: `LiveLanTransport`; tests: fakes.
protocol LanTransporting: Sendable {
    /// One LAN view exchange with the paired peer; throws `LanSyncError` (desktop issue codes) or any
    /// transport error (reported as `unreachable`).
    func exchangeViews(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                       ownCounter: Int64) async throws -> [ItemState]
    /// The one enrollment request of a scanned offer; returns the inviter's reply bytes. `onConnected` is
    /// called once the connection is up (the screen then stops offering Cancel).
    func enroll(endpoint: LanEndpoint, request: [UInt8], onConnected: @escaping @Sendable () -> Void) async throws -> [UInt8]
}

/// `LanClient` over Network.framework with the retry-once connector; hello counters in the Keychain.
struct LiveLanTransport: LanTransporting {
    let dialer: any LanDialer
    let counters: HelloCounterSource
    let random: any RandomSource
    let clock: any UnixClock

    func exchangeViews(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                       ownCounter: Int64) async throws -> [ItemState] {
        let client = LanClient(identity: identity, groupKey: groupKey, counters: counters, random: random, clock: clock)
        let connector = PairedLanConnector(paired: peer, dialer: dialer)
        return try await client.sync(peer: peer, localStates: localStates, ownCounter: ownCounter, connector: connector)
    }

    func enroll(endpoint: LanEndpoint, request: [UInt8], onConnected: @escaping @Sendable () -> Void) async throws -> [UInt8] {
        try await SocketEnroller(dialer: dialer).enroll(endpoint: endpoint, request: request, onConnected: onConnected)
    }
}

struct SyncDependencies: Sendable {
    /// Only the sync slots; the full vault (local key, hello counters) stays at the composition root.
    var keychain: any SyncKeychain
    var folders: any FolderOpening
    var lan: any LanTransporting
    var autoFill: any AutoFillIdentityRefreshing
    var random: any RandomSource
    var clock: any UnixClock
    var licenseKeys: [String: [UInt8]]
    var deviceName: String = SyncWording.deviceName
    var newIdentity: @Sendable (any RandomSource) throws -> DeviceIdentity = { try DeviceIdentity.generate(random: $0) }
    /// Waits before a sync triggered by an edit (debounce).
    var sleep: @Sendable (UInt64) async -> Void = { try? await Task.sleep(nanoseconds: $0) }
    var editDebounceNanos: UInt64 = 2_000_000_000
    /// This phone's Wi-Fi IPv4 subnet, read before a pairing dial (nil: unknown, nothing is compared).
    var localSubnet: @Sendable () -> IPv4Subnet? = { nil }

    /// The app's dependencies for an unlocked vault (main app only; AutoFill never syncs).
    static func live(keychain: any KeychainVault) -> SyncDependencies {
        let clock = SystemClock(), random = SystemRandomSource()
        let counters = HelloCounterSource(store: VaultCounterStore(vault: keychain), clock: clock)
        return SyncDependencies(keychain: keychain, folders: SecurityScopedFolderOpener(),
                                lan: LiveLanTransport(dialer: NWLanDialer(), counters: counters, random: random, clock: clock),
                                autoFill: IdentityStoreSync(), random: random, clock: clock,
                                licenseKeys: LicenseKeys.production,
                                localSubnet: { IPv4Interface.currentWiFiSubnet() })
    }
}

/// A refused join/leave step; `reason` is a desktop `ERROR_COPY` / `ISSUE_COPY` key.
struct SyncActionError: Error, Equatable {
    let reason: String
    init(_ reason: String) { self.reason = reason }
}

/// The enrollment dial to a scanned offer's address failed (nothing of the join was stored).
/// `offSubnet`: the offer's IPv4 host is outside this phone's Wi-Fi subnet (read before dialling).
struct EnrollConnectError: Error, Equatable {
    let failure: LanFailure
    let endpoint: LanEndpoint
    var offSubnet: IPv4Subnet?
}

/// What one sync run found.
struct SyncRunResult: Sendable, Equatable {
    var issues: [SyncIssue] = []
    var conflicts = 0
    var ran = false
    /// The run ended with the store still open: republish the AutoFill identities (through the coordinator's
    /// ordered `refreshIdentities` chain, never from inside the run).
    var publish = false
}

/// Closed when the vault locks: from then on no sync may commit (checked right before each commit).
final class SessionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var closed = false
    func close() { lock.withLock { closed = true } }
    var isOpen: Bool { lock.withLock { !closed } }
}

/// The coordinator's view of the store: reads and commits are refused once the vault has locked.
final class GatedStore: ItemStore, @unchecked Sendable {
    let base: any ItemStore
    let gate: SessionGate
    init(_ base: any ItemStore, gate: SessionGate) { self.base = base; self.gate = gate }
    func load() throws -> StoreSnapshot {
        guard gate.isOpen else { throw SyncActionError("locked") }
        return try base.load()
    }
    func commit(_ change: StoreChange) throws {
        guard gate.isOpen else { throw SyncActionError("locked") }
        try base.commit(change)
    }
}

// MARK: coordinator

/// The Sync screen's state machine: `idle` → `syncing` → `idle`, or `idle` → `joining` → (`syncing`) → `idle`.
///
/// * Sync runs on app open (unlock), on pull-to-refresh, and 2 s after the last local edit.
/// * Never two runs at once: a request while one runs is folded into one more run after it.
/// * The store is only ever written through `ItemStore.commit` inside LGKCore's transports (folder) or
///   after a complete LAN exchange; a failed run leaves it untouched.
/// * After each run (joined or not) and after each local commit, the AutoFill identity hook is called.
@MainActor
@Observable
final class SyncCoordinator {
    enum Phase: Equatable { case idle, syncing, joining }
    enum Trigger: Equatable { case appOpen, pullToRefresh, localEdit, manual }

    struct Membership: Equatable {
        var joined = false
        var hasFolder = false
        var hasBookmark = false
        var peer: PinnedPeer?
        var deviceID: String?
    }

    static let maxPasswordAttempts = 5
    static let passwordBackoffSeconds: Int64 = 30

    private(set) var phase: Phase = .idle
    private(set) var membership = Membership()
    private(set) var issues: [SyncWording.IssueView] = []
    private(set) var lastSyncedAt: Int64?
    /// Conflict copies made since unlock (the desktop shows the same count).
    private(set) var conflictCopies = 0
    /// Bumped after every run, so lists reload.
    private(set) var completedRuns = 0
    /// Text for the last refused action (join, leave, reset), desktop `error_text` wording.
    private(set) var actionError: String?
    /// Text for the last completed action.
    private(set) var actionInfo: String?
    /// The last refused join was iOS Local Network privacy: the screen offers to open Settings.
    private(set) var actionOffersSettings = false
    /// The address a QR join is dialling (spinner text); nil otherwise.
    private(set) var connecting: LanEndpoint?
    /// The 6-digit verification code of the QR join in flight, shown while the inviting device waits for its
    /// user's Accept (the same code is shown there); nil otherwise.
    private(set) var verificationCode: String?

    @ObservationIgnored let store: any ItemStore
    @ObservationIgnored let gate = SessionGate()
    @ObservationIgnored private var syncAfterAction = false
    @ObservationIgnored let deps: SyncDependencies
    @ObservationIgnored private var runner: Task<Void, Never>?
    @ObservationIgnored private var rerun = false
    @ObservationIgnored private var editTask: Task<Void, Never>?
    @ObservationIgnored private var wrongPasswords = 0
    @ObservationIgnored private var backoffUntil: Int64 = 0
    @ObservationIgnored private let background: any BackgroundTasking
    /// The latest Settings-driven identity update (QuickType on/off); each one waits for the one before.
    @ObservationIgnored private var identityTask: Task<Void, Never>?
    /// The QR join in flight (`cancelJoin`).
    @ObservationIgnored private var joinTask: Task<Void, Error>?
    /// Numbers each QR join, so a late "connected" hop never clears a later join's address.
    @ObservationIgnored private var joinSerial = 0

    init(store: any ItemStore, deps: SyncDependencies, background: (any BackgroundTasking)? = nil) {
        self.store = GatedStore(store, gate: gate); self.deps = deps
        self.background = background ?? UIKitBackgroundTasks()
        refreshMembership()
    }

    var isBusy: Bool { phase != .idle }

    /// The vault locked: stop the edit timer and the run in flight; nothing commits after this.
    func shutdown() {
        gate.close()
        editTask?.cancel(); editTask = nil
        joinTask?.cancel()
        runner?.cancel()
        identityTask?.cancel()
    }

    /// `shutdown`, then waits for the run and identity update in flight, so nothing (an AutoFill identity
    /// refresh included) writes after this returns.
    func shutdownAndWait() async {
        let join = joinTask
        shutdown()
        _ = try? await join?.value
        await runner?.value
        await identityTask?.value
    }

    /// Settings toggled "Show logins in the QuickType bar", "Include exact-site logins" or "Offer passkeys":
    /// republish the AutoFill identities (or remove them), in order. `IdentityStoreSync` reads the settings
    /// itself and re-checks QuickType after a replace.
    func identitySettingsChanged() { refreshIdentities() }

    /// Republishes the AutoFill identities from the store, after the update queued before it. Called for
    /// Settings changes and after every local commit (editor save/delete, passkey rename/delete), so the
    /// QuickType bar matches the vault without waiting for a sync (or a joined group).
    func refreshIdentities() {
        let previous = identityTask
        let autoFill = deps.autoFill, store = store, gate = gate
        identityTask = Task {
            await previous?.value
            guard gate.isOpen, !Task.isCancelled else { return }
            await autoFill.syncDidFinish(store: store)
        }
    }

    /// Waits for the identity updates queued so far (tests).
    func identitiesSettled() async { await identityTask?.value }

    func refreshMembership() {
        guard gate.isOpen else { return }   // locked: no reads
        let snap = try? store.load()
        let state = snap?.sync
        membership = Membership(joined: state != nil, hasFolder: state?.hasFolder ?? false,
                                hasBookmark: ((try? deps.keychain.readSlot(.folderBookmark)) ?? nil) != nil,
                                peer: state == nil ? nil : (try? deps.keychain.pairedPeer()) ?? nil,
                                deviceID: state?.deviceID)
    }

    // MARK: sync

    /// Runs one sync, or joins the one in flight and asks it for one more run.
    func sync(_ trigger: Trigger = .manual) async {
        guard gate.isOpen else { return }
        if phase == .joining { syncAfterAction = true; return }   // run once the join/leave has finished
        if let runner { rerun = true; await runner.value; return }
        let task = Task { await self.runLoop() }
        runner = task
        await task.value
    }

    /// After a local edit: sync once the user has stopped editing for `editDebounceNanos`.
    func noteLocalEdit() {
        refreshIdentities()
        editTask?.cancel()
        let wait = deps.editDebounceNanos, sleep = deps.sleep
        editTask = Task { [weak self] in
            await sleep(wait)
            guard !Task.isCancelled else { return }
            await self?.sync(.localEdit)
        }
    }

    private func runLoop() async {
        // The run may commit under the store's flock: keep the app alive until it is done (0xdead10cc).
        // On expiry the run is cancelled; it stops before its next step and the task is ended.
        let task = BackgroundTaskScope(background, name: "LocalGateKeys sync") { [weak self] in self?.runner?.cancel() }
        defer { task.end() }
        repeat {
            rerun = false
            phase = .syncing
            let result = await Self.runAll(store: store, deps: deps)
            apply(result)
            await publish(result)
        } while rerun && gate.isOpen && !Task.isCancelled
        phase = .idle
        runner = nil
    }

    /// Queues the identity update after the ones before it and waits for it, so a finished sync has published.
    private func publish(_ result: SyncRunResult) async {
        guard result.publish, gate.isOpen else { return }
        refreshIdentities()
        await identityTask?.value
    }

    private func apply(_ result: SyncRunResult) {
        guard gate.isOpen else { return }
        refreshMembership()
        if result.ran {
            lastSyncedAt = deps.clock.now
            conflictCopies += result.conflicts
            issues = SyncWording.views(result.issues, ownID: membership.deviceID, folder: membership.hasFolder)
        } else {
            issues = []
        }
        completedRuns += 1
    }

    /// False once the vault has locked (gate closed) or the run was cancelled: stop before the next step.
    nonisolated static func stillOpen(_ store: any ItemStore) -> Bool {
        !Task.isCancelled && ((store as? GatedStore)?.gate.isOpen ?? true)
    }

    /// One full run off the main actor: the folder (when the group uses one), then the paired LAN peer.
    /// Between steps it stops as soon as the vault locks, so nothing is read, refreshed or committed after.
    nonisolated static func runAll(store: any ItemStore, deps: SyncDependencies) async -> SyncRunResult {
        var out = SyncRunResult()
        let snapshot: StoreSnapshot
        do { snapshot = try store.load() } catch {
            return SyncRunResult(issues: [SyncIssue("local-data", "\(error)")], ran: true)
        }
        guard let state = snapshot.sync else {
            // Not joined: nothing to sync, but unlock (app open) still publishes the identities.
            out.publish = stillOpen(store)
            return out
        }
        out.ran = true
        let installID: String
        do { installID = try deps.keychain.installID(random: deps.random) } catch {
            out.issues.append(SyncIssue("state-corrupt", "\(error)"))
            out.publish = stillOpen(store)
            return out
        }
        if state.hasFolder {
            guard stillOpen(store) else { return out }
            // The folder step blocks (NSFileCoordinator, up to 30 s waiting for iCloud downloads in
            // `CoordinatedFolder.ensureDownloaded`): run it on a GCD thread, never a cooperative one.
            let report: RunReport = await withCheckedContinuation { c in
                DispatchQueue.global(qos: .utility).async {
                    c.resume(returning: SyncCoordinator.folderRun(store: store, deps: deps, installID: installID))
                }
            }
            out.issues += report.issues; out.conflicts += report.conflicts
        }
        let peer: PinnedPeer?
        do { peer = try deps.keychain.pairedPeer() } catch {
            peer = nil
            out.issues.append(SyncIssue("identity-mismatch", "\(error)"))
        }
        if let peer {
            guard stillOpen(store) else { return out }
            let report = await lanRun(store: store, deps: deps, installID: installID, peer: peer)
            out.issues += report.issues; out.conflicts += report.conflicts
        }
        out.publish = stillOpen(store)
        return out
    }

    /// The QR-paired peer's signing key (device id -> base64), the only key its folder view may be signed
    /// with (desktop `_paired_keys`, audit M-7). An unreadable pairing leaves the first-use pin in charge.
    nonisolated static func pairedKeys(_ deps: SyncDependencies) -> [String: String] {
        guard let peer = (try? deps.keychain.pairedPeer()) ?? nil else { return [:] }
        return [peer.deviceID: Base64.encode(peer.signingPublic)]
    }

    nonisolated static func folderRun(store: any ItemStore, deps: SyncDependencies, installID: String) -> RunReport {
        var fail = RunReport()
        let bookmark: [UInt8]?
        do { bookmark = try deps.keychain.readSlot(.folderBookmark) } catch {
            fail.issues = [SyncIssue("folder-missing", "\(error)")]; return fail
        }
        guard let bookmark else { fail.issues = [SyncIssue("folder-missing", "no folder chosen on this device")]; return fail }
        do {
            let (folder, refreshed) = try deps.folders.open(bookmark: bookmark)
            if let refreshed { try? deps.keychain.writeSlot(.folderBookmark, refreshed) }
            let fs = try FolderSync(access: folder, installID: installID, licenseKeys: deps.licenseKeys,
                                    pairedKeys: pairedKeys(deps))
            return fs.runOnce(store: store, random: deps.random, clock: deps.clock)
        } catch {
            fail.issues = [SyncIssue("folder-missing", "\(error)")]
            return fail
        }
    }

    /// One LAN sync with the paired peer (desktop `lan_sync.sync_with` + `run_merge`). Nothing is
    /// committed unless the whole exchange succeeded.
    nonisolated static func lanRun(store: any ItemStore, deps: SyncDependencies, installID: String,
                                   peer: PinnedPeer) async -> RunReport {
        var fail = RunReport()
        let now = deps.clock.now
        let snapshot: StoreSnapshot
        do { snapshot = try store.load() } catch { fail.issues = [SyncIssue("local-data", "\(error)")]; return fail }
        guard let state = snapshot.sync else { fail.issues = [SyncIssue("not-joined")]; return fail }
        guard state.installID == installID else { fail.issues = [SyncIssue("rejoin-required", "install-mismatch")]; return fail }
        guard peer.groupID == state.groupID, peer.deviceID != state.deviceID else {
            fail.issues = [SyncIssue("peer-mismatch", peer.deviceID)]; return fail
        }
        // Only the paired peer, only at a private LAN address.
        guard let endpoint = peer.endpoint else { fail.issues = [SyncIssue("no-endpoint", peer.deviceID)]; return fail }
        guard LanAddress.isLAN(endpoint.host) else {
            fail.issues = [SyncIssue("unreachable", "\(endpoint.host) is not a private LAN address")]; return fail
        }
        let groupKey: GroupKey
        let local: [ItemState]
        do {
            groupKey = try GroupKey(groupID: state.groupID, epoch: state.epoch, key: state.key)
            local = try SyncMeta.localView(records: snapshot.records, meta: snapshot.meta, device: state.deviceID, now: now)
                .states.values.sorted { $0.itemID < $1.itemID }
        } catch {
            fail.issues = [SyncIssue("local-data", "\(error)")]; return fail
        }
        let peerStates: [ItemState]
        do {
            peerStates = try await deps.lan.exchangeViews(peer: peer, identity: state.identity, groupKey: groupKey,
                                                          localStates: local, ownCounter: state.ownCounter)
        } catch let e as LanSyncError {
            fail.issues = [SyncIssue(e.reason == "bad-message" ? "bad-reply" : e.reason, e.detail)]; return fail
        } catch {
            fail.issues = [SyncIssue("unreachable", "\(error)")]; return fail
        }
        var report = SyncRunner.run(store: snapshot, views: [PeerView(deviceID: peer.deviceID, states: peerStates)],
                                    device: state.deviceID, now: now, licenseKeys: deps.licenseKeys)
        let records = report.records ?? snapshot.records, meta = report.meta ?? snapshot.meta
        if records != snapshot.records || meta != snapshot.meta {
            do {
                try store.commit(StoreChange(baseRevision: snapshot.revision, records: records, meta: meta, sync: snapshot.sync))
            } catch {
                report.issues.append(SyncIssue("busy", "\(error)"))
            }
        }
        report.wrote = true
        return report
    }

    // MARK: joining

    /// Wi-Fi: scanned (or pasted) QR text → enrollment → pin the inviter → first sync.
    @discardableResult
    func joinByQR(_ text: String) async -> Bool {
        guard beginAction() else { return false }
        connecting = (try? PairingOffer.parseQR(text.trimmingCharacters(in: .whitespacesAndNewlines)))?.endpoint
        joinSerial += 1
        let serial = joinSerial
        let onConnected: @Sendable () -> Void = { [weak self] in
            Task { @MainActor in if self?.joinSerial == serial { self?.connecting = nil } }
        }
        // Only while this join is still running: a late hop never shows the code of a finished join.
        let onCode: @Sendable (String) -> Void = { [weak self] code in
            Task { @MainActor in
                if let self, self.joinSerial == serial, self.phase == .joining, self.joinTask != nil { self.verificationCode = code }
            }
        }
        let store = store, deps = deps
        let task = Task { try await Self.enroll(text: text, store: store, deps: deps, onConnected: onConnected, onCode: onCode) }
        joinTask = task
        do {
            try await task.value
            joinTask = nil; connecting = nil; verificationCode = nil
            phase = .idle
            syncAfterAction = false   // the first sync below includes any edit made meanwhile
            actionInfo = "This iPhone joined the sync group. The first sync is running."
            refreshMembership()
            await sync(.manual)
            return true
        } catch let e as EnrollConnectError where e.failure == .cancelled {
            joinTask = nil; connecting = nil; verificationCode = nil
            phase = .idle
            actionInfo = "Pairing was cancelled."
            refreshMembership()
            runPendingSync()
            return false
        } catch {
            joinTask = nil; connecting = nil; verificationCode = nil
            fail(error)
            return false
        }
    }

    /// Stops a QR join that is still connecting (the Cancel button next to "Connecting to …"). Once the
    /// connection is up (`connecting` is nil) it does nothing: the join completes or fails on its own.
    func cancelJoin() {
        guard connecting != nil else { return }
        joinTask?.cancel()
    }

    /// `onCode` receives the 6-digit verification code before the request is sent (desktop `on_code`): the
    /// inviting device shows the same code next to Accept and answers only after Accept (or `declined`).
    nonisolated static func enroll(text: String, store: any ItemStore, deps: SyncDependencies,
                                   onConnected: @escaping @Sendable () -> Void = {},
                                   onCode: @escaping @Sendable (String) -> Void = { _ in }) async throws {
        let snapshot = try store.load()
        guard snapshot.sync == nil else { throw SyncActionError("already-joined") }
        let offer: PairingOffer
        do { offer = try PairingOffer.parseQR(text.trimmingCharacters(in: .whitespacesAndNewlines)) } catch {
            throw SyncActionError("bad-offer")
        }
        guard LanAddress.isLAN(offer.endpoint.host) else { throw SyncActionError("bad-offer") }
        let identity = try deps.newIdentity(deps.random)
        let request: [UInt8]
        let code: String
        do {
            // A phone never listens: it announces no endpoint and always initiates. The name is the generic one
            // it also gives itself in the keyring; the inviting device shows it on its Accept prompt.
            request = try Enrollment.buildRequest(offer: offer, identity: identity, endpoint: nil, name: deps.deviceName,
                                                  random: deps.random, now: deps.clock)
            code = try Enrollment.verificationCode(offer: offer, identity: identity, endpoint: nil, name: deps.deviceName)
        } catch PairingError.expired {
            throw SyncActionError("offer-used-or-expired")
        } catch {
            throw SyncActionError("bad-offer")
        }
        // Read before dialling: an address outside this Wi-Fi is still tried (it may be routed), but if
        // the dial fails the message says which address the PC should put in its code.
        let offSubnet = IPv4Subnet.mismatch(host: offer.endpoint.host, subnet: deps.localSubnet())
        onCode(code)
        // The reply comes once the user chose Accept on the inviting device: the connection waits up to
        // `Enrollment.replySeconds` (75 s) for it (`NWLanDialer.enrollReplyTimeout`).
        let reply: [UInt8]
        do { reply = try await deps.lan.enroll(endpoint: offer.endpoint, request: request, onConnected: onConnected) } catch {
            let kind = (error as? LanSocketError)?.kind ?? .other
            let failure: LanFailure = Task.isCancelled || error is CancellationError ? .cancelled : kind
            throw EnrollConnectError(failure: failure, endpoint: offer.endpoint, offSubnet: offSubnet)
        }
        let groupKey: GroupKey
        do { groupKey = try Enrollment.openReply(offer: offer, identity: identity, raw: reply, endpoint: nil, name: deps.deviceName) }
        catch PairingError.refused(let reason) {
            if reason == "used-or-expired" { throw SyncActionError("offer-used-or-expired") }
            if reason == "full" { throw SyncActionError("too-many-peers") }
            if reason == "declined" { throw SyncActionError("declined") }   // Decline, or no Accept within 60 s
            if reason == "update-needed" { throw SyncActionError("update-needed") }   // this iPhone sent an older request
            throw SyncActionError("refused")
        } catch {
            throw SyncActionError("refused")
        }
        let installID = try deps.keychain.installID(random: deps.random)
        let state = SyncGroupState(groupID: groupKey.groupID, epoch: groupKey.epoch, key: groupKey.key, identity: identity,
                                   installID: installID, hasFolder: false)
        try deps.keychain.setPairedPeer(offer.inviterPeer)
        do {
            let now = try store.load()
            guard now.sync == nil else { throw SyncActionError("already-joined") }
            try store.commit(StoreChange(baseRevision: now.revision, records: now.records, meta: now.meta, sync: state))
        } catch {
            try? deps.keychain.deleteSlot(.pairedPeer)
            throw error
        }
    }

    /// Cloud folder: picked folder bookmark + sync password → join (new member), or attach when this
    /// phone is already in the group by QR (P4). Both run the first sync.
    @discardableResult
    func joinFolder(bookmark: [UInt8], password: String) async -> Bool {
        let now = deps.clock.now
        // The wrong-password back-off guards only paths that check the password; re-picking the folder
        // of a group this phone already syncs through does not.
        if now < backoffUntil, !Self.isRepick(store: store, deps: deps) {
            actionError = SyncWording.passwordBackoffText; return false
        }
        guard beginAction() else { return false }
        do {
            let result = try await Self.joinFolderWork(bookmark: bookmark, password: password, store: store, deps: deps)
            wrongPasswords = 0
            phase = .idle
            refreshMembership()
            apply(result)
            await publish(result)
            actionInfo = "This iPhone now syncs through the cloud folder."
            runPendingSync()
            return true
        } catch let e as FolderSyncError where e.reason == "password" {
            wrongPasswords += 1
            if wrongPasswords >= Self.maxPasswordAttempts {
                wrongPasswords = 0
                backoffUntil = now + Self.passwordBackoffSeconds
            }
            fail(e)
            return false
        } catch {
            fail(error)
            return false
        }
    }

    /// True when `joinFolderWork` would take the "choose the folder again" branch (no password).
    nonisolated static func isRepick(store: any ItemStore, deps: SyncDependencies) -> Bool {
        guard let state = (try? store.load())?.sync, state.hasFolder,
              let raw = (try? deps.keychain.readSlot(.installID)) ?? nil,
              let installID = String(bytes: raw, encoding: .utf8) else { return false }  // never creates the slot
        return state.installID == installID
    }

    nonisolated static func joinFolderWork(bookmark: [UInt8], password: String, store: any ItemStore,
                                           deps: SyncDependencies) async throws -> SyncRunResult {
        let folder: any FolderAccess
        let refreshed: [UInt8]?
        do { (folder, refreshed) = try deps.folders.open(bookmark: bookmark) } catch { throw SyncActionError("folder-missing") }
        let installID = try deps.keychain.installID(random: deps.random)
        let fs = try FolderSync(access: folder, installID: installID, licenseKeys: deps.licenseKeys,
                                pairedKeys: pairedKeys(deps))
        let snapshot = try store.load()
        let report: RunReport
        if let state = snapshot.sync, state.hasFolder, state.installID == installID {
            // Already syncing through a folder (e.g. the bookmark was lost): the picked folder must hold
            // this group's key file; then only the bookmark is stored. No password, no join.
            let raw: [UInt8]
            do { raw = try folder.read(FolderLayout.keyringPath, limit: 256 * 1024 + 1) }
            catch FolderAccessError.notFound { throw SyncActionError("no-group") }
            catch { throw SyncActionError("keyring-unreadable") }
            guard let ring = try? Keyring.parse(raw) else { throw SyncActionError("keyring-corrupt") }
            guard case .object(let o) = ring, o["group_id"] == .string(state.groupID) else {
                throw SyncActionError("folder-has-other-group")
            }
            try deps.keychain.writeSlot(.folderBookmark, refreshed ?? bookmark)
            report = fs.runOnce(store: store, random: deps.random, clock: deps.clock)
        } else if let state = snapshot.sync, !state.hasFolder, state.installID == installID {
            report = try fs.attach(store: store, password: password, deviceName: deps.deviceName, random: deps.random, clock: deps.clock)
        } else {
            report = try fs.join(store: store, password: password, deviceName: deps.deviceName, random: deps.random, clock: deps.clock)
        }
        // After a join the group already uses the folder; if this write fails, "Choose the folder again"
        // (the branch above) stores it without joining.
        try deps.keychain.writeSlot(.folderBookmark, refreshed ?? bookmark)
        var out = SyncRunResult(issues: report.issues, conflicts: report.conflicts, ran: true)
        // A QR peer keeps syncing after an attach.
        if stillOpen(store), let peer = try? deps.keychain.pairedPeer() {
            let lan = await lanRun(store: store, deps: deps, installID: installID, peer: peer)
            out.issues += lan.issues; out.conflicts += lan.conflicts
        }
        out.publish = stillOpen(store)
        return out
    }

    // MARK: leave and reset (each after two confirmations in the UI)

    /// Stops syncing and forgets the paired device and folder; items and their sync history stay.
    func leave() async {
        guard beginAction() else { return }
        do {
            try Self.clear(store: store, deps: deps, history: false)
            phase = .idle
            actionInfo = SyncWording.onPhone(SyncWording.leftText)
            issues = []
            refreshMembership()
        } catch { fail(error) }
    }

    /// Forgets the group, its keys and the sync history; items stay.
    func reset() async {
        guard beginAction() else { return }
        do {
            let cleared = try Self.clear(store: store, deps: deps, history: true)
            phase = .idle
            actionInfo = SyncWording.onPhone(SyncWording.resetResultText(cleared))
            issues = []
            refreshMembership()
        } catch { fail(error) }
    }

    @discardableResult
    nonisolated static func clear(store: any ItemStore, deps: SyncDependencies, history: Bool) throws -> Bool {
        let snap = try store.load()
        let had = snap.sync != nil || (history && !snap.meta.isEmpty)
        if had {
            try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records,
                                         meta: history ? [:] : snap.meta, sync: nil))
        }
        try deps.keychain.deleteSlot(.pairedPeer)
        try deps.keychain.deleteSlot(.folderBookmark)
        // Peer counters are per pinned peer and that pairing is gone, so they are dropped. The hello
        // counter is this device's own monotonic counter: it is kept, because resetting it would let a
        // re-paired peer (or a recorded old session) see a counter it already accepted (replay window).
        try deps.keychain.deleteSlot(.peerCounters)
        return had
    }

    // MARK: helpers

    private func beginAction() -> Bool {
        guard phase == .idle, runner == nil else { actionError = SyncWording.errorText(reason: "busy"); return false }
        actionError = nil; actionInfo = nil; actionOffersSettings = false
        phase = .joining
        return true
    }

    private func fail(_ error: Error) {
        phase = .idle
        actionError = Self.text(for: error)
        actionOffersSettings = (error as? EnrollConnectError)?.failure == .localNetworkDenied
        refreshMembership()
        runPendingSync()
    }

    /// An edit sync that arrived during a join runs now.
    private func runPendingSync() {
        guard syncAfterAction else { return }
        syncAfterAction = false
        Task { await self.sync(.localEdit) }
    }

    nonisolated static func text(for error: Error) -> String {
        switch error {
        case let e as EnrollConnectError: return SyncWording.enrollFailureText(e)
        case let e as SyncActionError: return SyncWording.errorText(reason: e.reason)
        case let e as FolderSyncError: return SyncWording.errorText(reason: e.reason)
        case let e as LanSyncError: return SyncWording.errorText(reason: e.reason)
        case let e as KeyringError: return SyncWording.errorText(reason: e.reason)
        default: return SyncWording.stepFailedCopy
        }
    }
}
