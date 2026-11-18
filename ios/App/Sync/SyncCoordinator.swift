import Foundation
import Observation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

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
    /// `enroll` for a version-2 offer: the inviter's interim reveal frame goes to `onInterim` (which throws to abort)
    /// before the reply is read. Default (older fakes): `enroll`, no interim frame.
    func enroll(endpoint: LanEndpoint, request: [UInt8], onConnected: @escaping @Sendable () -> Void,
                onInterim: @escaping @Sendable ([UInt8]) throws -> Void) async throws -> [UInt8]
    /// `exchangeViews`, and when the pinned address does not answer, the paired host found by Bonjour
    /// (`HostFinder`): `moved` is the address it answered at with its pinned keys.
    func exchangeViewsFindingHost(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                                  ownCounter: Int64) async throws -> HostFinder.Result
    /// `exchangeViewsFindingHost` carrying rollback witnesses (2026-10-29): with `vaultGeneration` the own view is
    /// format 2; the result keeps the peer's view header. Default (older fakes): no witness, no header.
    func exchangeWitnessViews(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                              ownCounter: Int64, vaultGeneration: Int64?,
                              witness: [String: Int64]?) async throws -> HostFinder.Result
    /// One LAN `witness` message after a format-1 exchange; returns the peer's answer. Default: nil (not sent).
    func sendWitness(_ raw: [UInt8], peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async throws -> LanMessage?
    /// Attachment sync: one verified blob from the peer. Default (older fakes): an older peer.
    func fetchBlob(_ ref: AttachmentRef, peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async throws -> [UInt8]
    /// Attachment sync probe: true reads documents, false an older build, nil unknown. Default: nil.
    func probeAttachments(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async throws -> Bool?
    /// Personal collections (sub-plan 07): one `features` message after the view exchange (`LanClient.exchangeFeatures`):
    /// true reads collection states, false an older build, nil unknown. Default (older fakes): nil.
    func exchangeFeatures(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async throws -> Bool?
    /// Emergency access: one `heir-hello` (`LanClient.probeHeir`). True reads the plan, false older, nil unknown.
    func probeHeir(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async -> Bool?
}

extension LanTransporting {
    func enroll(endpoint: LanEndpoint, request: [UInt8], onConnected: @escaping @Sendable () -> Void,
                onInterim: @escaping @Sendable ([UInt8]) throws -> Void) async throws -> [UInt8] {
        try await enroll(endpoint: endpoint, request: request, onConnected: onConnected)
    }

    func exchangeWitnessViews(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                              ownCounter: Int64, vaultGeneration: Int64?,
                              witness: [String: Int64]?) async throws -> HostFinder.Result {
        try await exchangeViewsFindingHost(peer: peer, identity: identity, groupKey: groupKey, localStates: localStates,
                                           ownCounter: ownCounter)
    }

    func sendWitness(_ raw: [UInt8], peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async throws -> LanMessage? {
        nil
    }

    /// Attachment sync: one blob from the peer (`LanClient.fetchBlob`). Default (older fakes): an older peer.
    func fetchBlob(_ ref: AttachmentRef, peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async throws -> [UInt8] {
        throw LanSyncError("peer-refused", "bad-message")
    }

    /// Attachment sync: whether the peer knows `blob-get` (`LanClient.probeAttachments`). Default: no.
    func probeAttachments(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async throws -> Bool? { nil }
    /// Personal collections: whether the peer reads collection states. Default (older fakes): unknown.
    func exchangeFeatures(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async throws -> Bool? { nil }
    /// Emergency access probe. Default (test fakes): nothing learnt.
    func probeHeir(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async -> Bool? { nil }
    /// No discovery: the pinned address only.
    func exchangeViewsFindingHost(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                                  ownCounter: Int64) async throws -> HostFinder.Result {
        HostFinder.Result(states: try await exchangeViews(peer: peer, identity: identity, groupKey: groupKey,
                                                          localStates: localStates, ownCounter: ownCounter), moved: nil)
    }
}

/// `LanClient` over Network.framework with the retry-once connector; hello counters in the Keychain.
struct LiveLanTransport: LanTransporting {
    let dialer: any LanDialer
    let counters: HelloCounterSource
    let random: any RandomSource
    let clock: any UnixClock
    /// Bonjour browse used when the pinned address does not answer (the iPhone); nil: no discovery.
    var browser: (any ServiceBrowsing)? = nil

    func exchangeViews(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                       ownCounter: Int64) async throws -> [ItemState] {
        let client = LanClient(identity: identity, groupKey: groupKey, counters: counters, random: random, clock: clock)
        let connector = PairedLanConnector(paired: peer, dialer: dialer)
        return try await client.sync(peer: peer, localStates: localStates, ownCounter: ownCounter, connector: connector)
    }

    func exchangeViewsFindingHost(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                                  ownCounter: Int64) async throws -> HostFinder.Result {
        let client = LanClient(identity: identity, groupKey: groupKey, counters: counters, random: random, clock: clock)
        let dialer = self.dialer
        return try await HostFinder.exchange(peer: peer, groupKey: groupKey, now: clock.now, browser: browser) { p in
            try await client.sync(peer: p, localStates: localStates, ownCounter: ownCounter,
                                  connector: PairedLanConnector(paired: p, dialer: dialer))
        }
    }

    func exchangeWitnessViews(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                              ownCounter: Int64, vaultGeneration: Int64?,
                              witness: [String: Int64]?) async throws -> HostFinder.Result {
        let client = LanClient(identity: identity, groupKey: groupKey, counters: counters, random: random, clock: clock)
        let dialer = self.dialer
        return try await HostFinder.exchangeWithHeader(peer: peer, groupKey: groupKey, now: clock.now, browser: browser) { p in
            try await client.exchange(peer: p, localStates: localStates, ownCounter: ownCounter,
                                      connector: PairedLanConnector(paired: p, dialer: dialer),
                                      vaultGeneration: vaultGeneration, witness: witness)
        }
    }

    func sendWitness(_ raw: [UInt8], peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async throws -> LanMessage? {
        let client = LanClient(identity: identity, groupKey: groupKey, counters: counters, random: random, clock: clock)
        return try await client.sendWitness(raw, peer: peer, connector: PairedLanConnector(paired: peer, dialer: dialer))
    }

    func fetchBlob(_ ref: AttachmentRef, peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async throws -> [UInt8] {
        let client = LanClient(identity: identity, groupKey: groupKey, counters: counters, random: random, clock: clock)
        return try await client.fetchBlob(ref, peer: peer, connector: PairedLanConnector(paired: peer, dialer: dialer))
    }

    func probeAttachments(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async throws -> Bool? {
        let client = LanClient(identity: identity, groupKey: groupKey, counters: counters, random: random, clock: clock)
        return try await client.probeAttachments(peer: peer, connector: PairedLanConnector(paired: peer, dialer: dialer))
    }

    func exchangeFeatures(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async throws -> Bool? {
        let client = LanClient(identity: identity, groupKey: groupKey, counters: counters, random: random, clock: clock)
        return try await client.exchangeFeatures(peer: peer, connector: PairedLanConnector(paired: peer, dialer: dialer))
    }

    func probeHeir(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey) async -> Bool? {
        let client = LanClient(identity: identity, groupKey: groupKey, counters: counters, random: random, clock: clock)
        return await client.probeHeir(peer: peer, connector: PairedLanConnector(paired: peer, dialer: dialer))
    }

    func enroll(endpoint: LanEndpoint, request: [UInt8], onConnected: @escaping @Sendable () -> Void) async throws -> [UInt8] {
        try await SocketEnroller(dialer: dialer).enroll(endpoint: endpoint, request: request, onConnected: onConnected)
    }

    func enroll(endpoint: LanEndpoint, request: [UInt8], onConnected: @escaping @Sendable () -> Void,
                onInterim: @escaping @Sendable ([UInt8]) throws -> Void) async throws -> [UInt8] {
        try await SocketEnroller(dialer: dialer).enroll(endpoint: endpoint, request: request, onConnected: onConnected,
                                                        onInterim: onInterim)
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
    /// "Sync automatically" (the phone's setting, default on). Off: the unlock, the return to the app and an edit
    /// start no run; "Sync now" and pull-to-refresh still do. The Mac keeps its own schedule and leaves this on.
    var autoSync: @MainActor @Sendable () -> Bool = { true }
    /// This phone's Wi-Fi IPv4 subnet, read before a pairing dial (nil: unknown, nothing is compared).
    var localSubnet: @Sendable () -> IPv4Subnet? = { nil }
    /// Set when this build cannot keep the sync secrets safely (Mac Release without the app-only Keychain
    /// group): sync stays off, every action is refused and this text is the one issue shown.
    var unavailableText: String? = nil
    /// Sub-plan 08: the duress password's second vault never syncs. Nothing runs, no AutoFill identity is published,
    /// and every join ends with the plain "couldn't save" (no word about why).
    var inert = false
    /// Why an action is refused before it starts (nil: it may run).
    var refusal: String? { unavailableText ?? (inert ? DuressText.generic : nil) }
    /// The unlock session's in-memory peer generations (rollback witnesses), shared by the folder run, the LAN
    /// initiator and the Mac's responder; saved throttled and flushed at the end of every run.
    var witnessMemory = WitnessMemory()
    /// This device's attachment files (attachment sync); nil: documents are neither published nor received.
    var attachmentBlobs: (any AttachmentBlobStore)? = nil
    /// Wi-Fi peers that read documents (answered or sent a `blob-get` this session), shared with the Mac's responder.
    var attachmentPeers = AttachmentPeerMemory()
    /// The removal watch file next to the vault (`RemovalWatch`): refreshed by every folder run, read by the
    /// removal check, deleted by Leave and Reset. nil: none (tests).
    var watchFile: URL? = nil

    /// `<vault directory>/vault.sync-watch.json` (desktop `watch_path`; the Mac passes its own vault directory).
    static func watchFileURL(in vaultDirectory: URL) -> URL {
        vaultDirectory.appendingPathComponent(RemovalWatch.fileName(forVault: "vault"))
    }

    /// The app's dependencies for an unlocked vault (main app only; AutoFill never syncs).
    static func live(keychain: any KeychainVault) -> SyncDependencies {
        let clock = SystemClock(), random = SystemRandomSource()
        let counters = HelloCounterSource(store: VaultCounterStore(vault: keychain), clock: clock)
        return SyncDependencies(keychain: keychain, folders: SecurityScopedFolderOpener(),
                                lan: LiveLanTransport(dialer: NWLanDialer(), counters: counters, random: random, clock: clock,
                                                     browser: NWServiceBrowser()),
                                autoFill: IdentityStoreSync(oneTimeCodes: IdentityStoreSync.platformOneTimeCodes), random: random, clock: clock,
                                licenseKeys: LicenseKeys.production,
                                localSubnet: { IPv4Interface.currentWiFiSubnet() },
                                attachmentBlobs: AttachmentFiles.localFolder(),
                                watchFile: (try? AppGroup.vaultDirectory()).map(watchFileURL(in:)))
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

/// The reveal of a version-2 offer as the enrollment read it (once), or that it was refused.
final class RevealBox: @unchecked Sendable {
    private let lock = NSLock()
    private var reveal: [UInt8]?
    private var refused = false
    var has: Bool { lock.withLock { reveal != nil } }
    var value: [UInt8]? { lock.withLock { reveal } }
    var failed: Bool { lock.withLock { refused } }
    func set(_ r: [UInt8]) { lock.withLock { reveal = r } }
    func fail() { lock.withLock { refused = true } }
}

/// What one sync run found.
struct SyncRunResult: Sendable, Equatable {
    var issues: [SyncIssue] = []
    var conflicts = 0
    /// Items this run added, changed or deleted here (conflict copies included): shown as "N items updated".
    var changed = 0
    var ran = false
    /// The run ended with the store still open: republish the AutoFill identities (through the coordinator's
    /// ordered `refreshIdentities` chain, never from inside the run).
    var publish = false
    /// The share groups' runs after the personal group (sub-plan 07); nil when none ran (no share, or no Recently
    /// deleted to put a share's deletes in yet).
    var shares: ShareSync.Runs?
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
        // Versions a sync run replaces are kept as `sync` history (feature pack §1.3).
        try HistoryContext.$changeType.withValue(.sync) { try base.commit(change) }
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
    enum Trigger: Equatable {
        case appOpen, foreground, pullToRefresh, localEdit, manual
        /// Started by the app, not the person: held back while "Sync automatically" is off.
        var isAutomatic: Bool { self == .appOpen || self == .foreground || self == .localEdit }
    }

    struct Membership: Equatable {
        var joined = false
        var hasFolder = false
        var hasBookmark = false
        var peer: PinnedPeer?
        var deviceID: String?
        /// Workstream 6 (Sync status): keyring members, Wi-Fi peers (the paired host and any devices this Mac
        /// pinned), their enrolled names and when each one's changes were last accepted here (local only).
        var members: [String] = []
        var wifiPeers: [String] = []
        var names: [String: String] = [:]
        var peerSyncedAt: [String: Int64] = [:]
        /// Keyring members added by another device and not confirmed here (`SyncGroupState.unackedMembers`).
        var unacked: [String] = []
    }

    static let maxPasswordAttempts = 5
    /// A Wi-Fi host closed the connection right after this device's hello: almost always, it no longer accepts it.
    nonisolated static let notAccepted = "not-accepted"
    static let passwordBackoffSeconds: Int64 = 30

    private(set) var phase: Phase = .idle
    private(set) var membership = Membership()
    private(set) var issues: [SyncWording.IssueView] = []
    /// Called on the main actor after a run that verified a signed removal notice for this device (desktop
    /// `removal-notice`): the app erases (setting on) or the Messages say so (off). It must not wait for the run from
    /// inside this call. Never called for the "maybe removed" issues.
    @ObservationIgnored var onRemovalNotice: @MainActor () -> Void = {}
    private(set) var lastSyncedAt: Int64?
    /// Conflict copies made since unlock (the desktop shows the same count).
    private(set) var conflictCopies = 0
    /// Bumped after every run, so lists reload.
    private(set) var completedRuns = 0
    /// Shows "N items updated from your other devices" after a run that changed items here.
    /// The Mac window sets its own toast (CopyToast is iPhone-only).
    #if os(iOS)
    @ObservationIgnored var announce: @MainActor (String) -> Void = { CopyToast.shared.show($0, for: .seconds(3)) }
    #else
    @ObservationIgnored var announce: @MainActor (String) -> Void = { _ in }
    #endif
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

    // Shared collections (sub-plan 07): each share group syncs through its own folder after the personal group.
    /// The last run's issues of each share group (group id -> issues; empty: it synced). Words: `SyncWording.shareStatus`.
    private(set) var shareIssues: [String: [SyncIssue]] = [:]
    /// Collections this device was removed from since unlock (collection id -> the `share-removed` issue): the share
    /// group is gone, so the status stays with the collection, whose items went to Recently deleted.
    private(set) var removedShares: [String: SyncIssue] = [:]
    /// The reason code of the last refused share action (`ShareSync.reason`); nil after one that worked.
    private(set) var shareActionReason: String?
    /// After a member removal: false when the removal notice or the rotated keyring could not be written to the folder.
    private(set) var shareRemovalWritten = true
    /// Pro on this device, read on the main actor when a run or a share action starts: creating, joining and syncing a
    /// shared collection need Pro. The iPhone and the Mac set it at unlock; the default runs no share.
    @ObservationIgnored var isPro: @MainActor () -> Bool = { false }
    /// Recently deleted for shared collections (the iPhone's local data, the Mac's lock model). Nil: no share runs,
    /// since a share's deletes and a removal would have nowhere to go.
    @ObservationIgnored weak var shareTrash: (any ShareTrashHosting)?
    /// True when `store` itself copies every live item a commit takes out to Recently deleted (the Mac's
    /// `SyncSourceStore`); otherwise share commits do (`ShareTrashingStore`).
    @ObservationIgnored var storeMovesDeletesToTrash = false

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
        self.background = background ?? PlatformBackgroundTasks.make()
        if let text = deps.unavailableText {
            issues = [SyncWording.IssueView(kind: "sync-unavailable", severity: .error, text: text, resetOffered: false)]
            return
        }
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
        guard !deps.inert else { return }
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

    /// The iPhone's Wi-Fi host (`PhoneWiFiHost`) committed outside a run: a device it serves pushed changes, or a
    /// pairing created the group or added a device. The lists reload (`completedRuns`), the membership is read
    /// again and the AutoFill identities are republished. Nothing runs or commits here.
    func noteServedMerge() {
        guard gate.isOpen else { return }
        refreshMembership()
        completedRuns += 1
        refreshIdentities()
    }

    func refreshMembership() {
        guard gate.isOpen else { return }   // locked: no reads
        let snap = try? store.load()
        let state = snap?.sync
        membership = Membership(joined: state != nil, hasFolder: state?.hasFolder ?? false,
                                hasBookmark: ((try? deps.keychain.readSlot(.folderBookmark)) ?? nil) != nil,
                                peer: state == nil ? nil : (try? deps.keychain.pairedPeer()) ?? nil,
                                deviceID: state?.deviceID)
        if let state {
            let lan = state.lanPeers.filter { !$0.revoked }
            var wifi = Set(lan.map(\.deviceID))
            if let paired = membership.peer?.deviceID { wifi.insert(paired) }
            membership.members = state.members
            membership.wifiPeers = wifi.sorted()
            membership.names = Dictionary(lan.compactMap { p in p.name.map { (p.deviceID, $0) } }) { first, _ in first }
            membership.peerSyncedAt = PeerSeenAt.merged(groupID: state.groupID, saved: state.peerSyncedAt)
            membership.unacked = state.unackedMembers
        }
    }

    /// The stored group (nil when not joined or locked), for the member list and the removal plan.
    func groupState() -> SyncGroupState? {
        guard gate.isOpen else { return nil }
        return (try? store.load())?.sync
    }

    /// The Sync status pill and sheet (workstream 6); nil when this device does not sync.
    func statusSummary(now: Int64? = nil) -> SyncStatusSummary? {
        SyncStatusSummary.make(membership: membership, issues: issues, lastSyncedAt: lastSyncedAt, now: now ?? deps.clock.now)
    }

    // MARK: sync

    /// The user's "Sync now": drops the message of an earlier folder or pairing action (it would otherwise stay
    /// beside "Last synced" and read as this sync failing), then runs one sync.
    func syncNow() async {
        if phase == .idle { actionError = nil; actionInfo = nil; actionOffersSettings = false }
        await sync(.manual)
    }

    /// Runs one sync, or joins the one in flight and asks it for one more run.
    func sync(_ trigger: Trigger = .manual) async {
        guard gate.isOpen, deps.refusal == nil else { return }
        if trigger.isAutomatic, !deps.autoSync() { return }
        if phase == .joining { syncAfterAction = true; return }   // run once the join/leave has finished
        if let runner { rerun = true; await runner.value; return }
        let task = Task { await self.runLoop() }
        runner = task
        await task.value
    }

    /// After a local edit: sync once the user has stopped editing for `editDebounceNanos`.
    func noteLocalEdit() {
        guard !deps.inert else { return }
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
            // Share runs stay inside this background task: an expiry cancels the run before the next share.
            let result = await Self.runAll(store: store, deps: deps, shareHost: shareHost(), isPro: isPro())
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
            // A host that refused this device synced nothing: "Last synced" keeps its time and
            // "The first sync is running" goes away.
            if !result.issues.contains(where: { $0.kind == Self.notAccepted }) {
                lastSyncedAt = deps.clock.now
            } else if actionInfo == String(localized: "This \(SyncWording.thisDevice) joined the sync group. The first sync is running.") {
                actionInfo = nil
            }
            // A clean run makes an earlier action's error (e.g. a folder pick with no group) stale.
            if result.issues.isEmpty { actionError = nil; actionOffersSettings = false }
            conflictCopies += result.conflicts
            issues = SyncWording.views(result.issues, ownID: membership.deviceID, folder: membership.hasFolder)
            if result.issues.contains(where: { $0.kind == RemovalNotice.issueKind }) { onRemovalNotice() }
        } else {
            issues = []
        }
        if let shares = result.shares {
            if !result.ran { conflictCopies += shares.conflicts }   // a joined run counted them in `conflicts`
            shareIssues = shares.issues
            // The group of a removal is gone: its status stays with the collection.
            for issue in shares.issues.values.joined() where issue.kind == "share-removed" { removedShares[issue.detail] = issue }
        }
        if result.changed > 0 { announce(SyncWording.itemsUpdated(result.changed)) }
        completedRuns += 1
    }

    /// The share host of one run: nil without Recently deleted (no share runs then; each group reports `item-error`).
    private func shareHost() -> ShareHost? {
        guard let shareTrash else { return nil }
        return ShareHost(isPro: isPro(), trash: shareTrash, storeTrashes: storeMovesDeletesToTrash)
    }

    /// The status of share group `groupID`'s last run: nil only when it synced. A group with no run since unlock
    /// (`shareRan` false) has no status yet: the screen says nothing about it rather than "synced".
    func shareStatus(groupID: String) -> SyncWording.ShareStatus? {
        SyncWording.shareStatus(shareIssues[groupID] ?? [])
    }

    /// Whether share group `groupID` was run (or held back, with its reason) since unlock.
    func shareRan(groupID: String) -> Bool { shareIssues[groupID] != nil }

    /// False once the vault has locked (gate closed) or the run was cancelled: stop before the next step.
    nonisolated static func stillOpen(_ store: any ItemStore) -> Bool {
        !Task.isCancelled && ((store as? GatedStore)?.gate.isOpen ?? true)
    }

    /// One full run off the main actor: the personal group (the folder when the group uses one, then the paired LAN
    /// peer), then every share group (`shareHost`; sub-plan 07), whether or not this vault is in a personal group.
    /// Between steps it stops as soon as the vault locks, so nothing is read, refreshed or committed after.
    /// `isPro`: Pro now, for the shares' status when they cannot run (`ShareSync.notRun`; nil: the host's).
    nonisolated static func runAll(store: any ItemStore, deps: SyncDependencies, shareHost: ShareHost? = nil,
                                   isPro: Bool? = nil) async -> SyncRunResult {
        let snapshot: StoreSnapshot
        do { snapshot = try store.load() } catch {
            return SyncRunResult(issues: [SyncIssue("local-data", "\(error)")], ran: true)
        }
        // Not joined: no personal run, but unlock (app open) still publishes the identities.
        var out = SyncRunResult()
        if let state = snapshot.sync { out = await personalRun(store: store, deps: deps, state: state) }
        if snapshot.shares != nil, stillOpen(store) {
            guard let shareHost else {
                out.shares = ShareSync.notRun(snapshot, isPro: isPro ?? true)
                out.publish = stillOpen(store)
                return out
            }
            let shares = await ShareSync.runAll(store: store, deps: deps, host: shareHost)
            out.conflicts += shares.conflicts
            out.changed += shares.changed
            out.shares = shares
        }
        out.publish = stillOpen(store)
        return out
    }

    /// The personal group's run (`runAll`): the folder, then the paired LAN peer, then the witness flush.
    nonisolated static func personalRun(store: any ItemStore, deps: SyncDependencies, state: SyncGroupState) async -> SyncRunResult {
        var out = SyncRunResult()
        out.ran = true
        let installID: String
        do { installID = try deps.keychain.installID(random: deps.random) } catch {
            out.issues.append(SyncIssue("state-corrupt", "\(error)"))
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
            out.changed += report.applied + report.deleted + report.conflicts
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
            out.changed += report.applied + report.deleted + report.conflicts
        }
        // Peer generations the LAN save throttle held back are saved at the end of every run, so a lock loses at
        // most one run's rises, never a stored value (desktop `SyncService._run_transports` flush).
        if stillOpen(store) { Witness.flush(store: store, memory: deps.witnessMemory, extra: witnessExtra(deps)) }
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
        // Personal collections on every personal run, with this vault's share records (sub-plan 07): no run without them.
        let shares: CollectionShares
        do { shares = try ShareSync.collectionShares(store) } catch {
            fail.issues = [SyncIssue("local-data", "\(error)")]; return fail
        }
        do {
            let (folder, refreshed) = try deps.folders.open(bookmark: bookmark)
            if let refreshed { try? deps.keychain.writeSlot(.folderBookmark, refreshed) }
            let fs = try FolderSync(access: folder, installID: installID, licenseKeys: deps.licenseKeys,
                                    pairedKeys: pairedKeys(deps), witnessMemory: deps.witnessMemory,
                                    attachmentBlobs: deps.attachmentBlobs, removalWatch: removalWatch(deps, folder),
                                    collections: true, collectionShares: shares)
            return fs.runOnce(store: store, random: deps.random, clock: deps.clock)
        } catch {
            fail.issues = [SyncIssue("folder-missing", "\(error)")]
            return fail
        }
    }

    /// The watch file store for a run over `folder` (nil without `deps.watchFile`); the folder text is its path.
    nonisolated static func removalWatch(_ deps: SyncDependencies, _ folder: any FolderAccess) -> (any RemovalWatchStore)? {
        guard let url = deps.watchFile else { return nil }
        return FileRemovalWatchStore(url: url, folder: (folder as? CoordinatedFolder)?.root.path ?? FolderLayout.syncDir)
    }

    /// The group's folder (the stored bookmark) for an action on its keyring: remove, confirm members. `store`: the
    /// vault the action runs on (its share records go to the rotation's run, as on every personal run).
    nonisolated static func folderSync(_ deps: SyncDependencies, store: any ItemStore) throws -> FolderSync {
        guard let bookmark = try deps.keychain.readSlot(.folderBookmark) else {
            throw FolderSyncError("folder-missing", "no folder chosen on this device")
        }
        let (folder, refreshed) = try deps.folders.open(bookmark: bookmark)
        if let refreshed { try? deps.keychain.writeSlot(.folderBookmark, refreshed) }
        return try FolderSync(access: folder, installID: try deps.keychain.installID(random: deps.random),
                              licenseKeys: deps.licenseKeys, pairedKeys: pairedKeys(deps),
                              witnessMemory: deps.witnessMemory, attachmentBlobs: deps.attachmentBlobs,
                              removalWatch: removalWatch(deps, folder), collections: true,
                              collectionShares: try ShareSync.collectionShares(store))
    }

    /// Peers whose generations this device publishes besides the state's members and LAN peers: the paired PC.
    nonisolated static func witnessExtra(_ deps: SyncDependencies) -> Set<String> {
        guard let peer = (try? deps.keychain.pairedPeer()) ?? nil else { return [] }
        return [peer.deviceID]
    }

    /// After a LAN exchange (desktop `sync_with`): check the peer's format-2 header, or after a format-1 exchange
    /// send one `witness` message and check the answer. A peer of an older version answers `bad-message`, and a
    /// lost connection gives nothing: both are silent (the next exchange tries again).
    nonisolated static func lanWitness(store: any ItemStore, deps: SyncDependencies, peer: PinnedPeer,
                                       header: ViewHeader?, inline: Bool) async -> [SyncIssue] {
        guard stillOpen(store) else { return [] }
        let extra = witnessExtra(deps).union([peer.deviceID])
        if let header, let obs = Witness.observation(header) {
            return Witness.apply(store: store, observations: [obs], memory: deps.witnessMemory, extra: extra)
        }
        guard !inline, let snapshot = try? store.load(), let state = snapshot.sync,
              let raw = try? Witness.lanWitnessFile(snapshot, memory: deps.witnessMemory, extra: extra,
                                                     now: deps.clock, random: deps.random),
              let groupKey = try? GroupKey(groupID: state.groupID, epoch: state.epoch, key: state.key) else { return [] }
        guard let reply = try? await deps.lan.sendWitness(raw, peer: peer, identity: state.identity, groupKey: groupKey),
              case let .witness(g, e, v) = reply, stillOpen(store) else { return [] }
        switch Witness.openLanWitness(state, peerID: peer.deviceID, groupID: g, epoch: e, view: v) {
        case .failure(let refusal): return [refusal.issue]
        case .success(let obs): return Witness.apply(store: store, observations: [obs], memory: deps.witnessMemory, extra: extra)
        }
    }

    /// A refused LAN exchange: a `bad-view` refusal of a format-2 view counts, and `Witness.formatRefusalsToDrop`
    /// in a row (no successful format-2 exchange in between) drop the peer from `witnessPeers`, so the next
    /// exchange is format 1 (an older app's refusal carries no reason; one damaged transfer must not switch back).
    nonisolated static func noteRefusal(_ error: LanSyncError, store: any ItemStore, deps: SyncDependencies,
                                        peer: PinnedPeer, state: SyncGroupState, inline: Bool) {
        guard inline, error.reason == "peer-refused", error.detail == "bad-view" else { return }
        let count = deps.witnessMemory.noteRefusal(peer.deviceID, groupID: state.groupID, deviceID: state.deviceID)
        guard count >= Witness.formatRefusalsToDrop else { return }
        deps.witnessMemory.clearRefusals(peer.deviceID)
        _ = Witness.apply(store: store, observations: [], memory: deps.witnessMemory,
                          extra: witnessExtra(deps).union([peer.deviceID]), dropCapable: peer.deviceID)
    }

    /// Attachment sync after the view exchange (desktop `lan_sync._fetch_blobs` + `attachment_flow.import_missing`):
    /// fetches every file the peer's live documents name that this device lacks, verifies it and stores it, so the
    /// merge can apply those documents. When nothing was needed and the peer is not known to read documents, one
    /// probe `blob-get` finds out. A file that fails stays missing: its document waits (`attachment-missing`).
    /// Returns the issues and what was learnt about the peer (true reads documents, false older, nil unknown);
    /// the caller saves the latter in the run's one commit.
    nonisolated static func fetchAttachments(peerStates: [ItemState], deps: SyncDependencies, peer: PinnedPeer,
                                             state: SyncGroupState, groupKey: GroupKey) async -> (issues: [SyncIssue], capable: Bool?) {
        guard let blobs = deps.attachmentBlobs else { return ([], nil) }
        var issues: [SyncIssue] = []
        let wanted: [AttachmentRef]
        do { wanted = try AttachmentSync.wanted(AttachmentDocuments.refs(peerStates), presentBlobs: blobs.ids()) } catch {
            return ([SyncIssue("attachment-refused", "\(error)")], nil)
        }
        // Only `no-blob` or a valid chunk marks the peer as reading documents; `bad-message` (an older build)
        // removes it; any other failure leaves what is known unchanged.
        var answered: Bool?
        for ref in wanted {
            do {
                let blob = try await deps.lan.fetchBlob(ref, peer: peer, identity: state.identity, groupKey: groupKey)
                answered = true
                try blobs.write(blob)
            } catch let e as LanSyncError {
                switch e.reason {
                case "no-blob": answered = true
                case "attachment-refused": issues.append(SyncIssue("attachment-refused", e.detail))
                case "peer-refused" where e.detail == "bad-message": answered = false
                default: break
                }
                if answered == false { break }
            } catch {
                issues.append(SyncIssue("attachment-missing", "\(ref.attachmentID): \(error)"))
            }
        }
        if wanted.isEmpty && !deps.attachmentPeers.contains(peer.deviceID) && !state.attachmentPeers.contains(peer.deviceID) {
            answered = (try? await deps.lan.probeAttachments(peer: peer, identity: state.identity, groupKey: groupKey)) ?? nil
        }
        if let answered { deps.attachmentPeers.set(peer.deviceID, capable: answered) }
        return (issues, answered)
    }

    /// One LAN sync with the paired peer (desktop `lan_sync.sync_with` + `run_merge`). Nothing is
    /// committed unless the whole exchange succeeded, except the version vectors of this device's own view, which are
    /// saved before they are sent (review H-1).
    nonisolated static func lanRun(store: any ItemStore, deps: SyncDependencies, installID: String,
                                   peer: PinnedPeer) async -> RunReport {
        var fail = RunReport()
        let now = deps.clock.now
        var snapshot: StoreSnapshot
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
        // Personal collections (sub-plan 07): collection states only with a peer that listed `collections`; this vault's
        // share records apply on every run (read-only share items are never changed by another of this person's devices).
        let collections = state.collectionPeers.contains(peer.deviceID)
        let shares = ShareGroups.collectionShares(in: snapshot)
        let viewMeta: [String: SyncMeta]
        do {
            groupKey = try GroupKey(groupID: state.groupID, epoch: state.epoch, key: state.key)
            let view = try SyncMeta.localView(records: snapshot.records, meta: snapshot.meta, device: state.deviceID, now: now,
                                              collections: collections, shares: shares)
            viewMeta = view.meta
            let all = view.states.values.sorted { $0.itemID < $1.itemID }
            // Documents only to a peer that showed it reads them (attachment sync); older builds would refuse them.
            local = lanLocalView(all, state: state, peerID: peer.deviceID, documents: deps.attachmentBlobs != nil
                                    && (state.attachmentPeers.contains(peer.deviceID)
                                        || deps.attachmentPeers.contains(peer.deviceID)))
        } catch {
            fail.issues = [SyncIssue("local-data", "\(error)")]; return fail
        }
        // Review H-1 (desktop `_local_view` saves its meta at once): the bumped vectors and tombstones about to be
        // sent are saved before the exchange. A host can keep them even when its reply never arrives here; unsaved,
        // the next local edit or delete would reuse the same counter (a delete coming back, or a conflict copy).
        if viewMeta != snapshot.meta {
            do {
                try store.commit(StoreChange(baseRevision: snapshot.revision, records: snapshot.records, meta: viewMeta,
                                             sync: snapshot.sync))
                // The merge below and its commit start from the saved state (new revision, saved vectors).
                snapshot = try store.load()
            } catch {
                fail.issues = [SyncIssue("busy", "\(error)")]; return fail
            }
        }
        let peerStates: [ItemState]
        let moved: LanEndpoint?
        let peerHeader: ViewHeader?
        // Format 2 only to a peer that showed support (`witnessPeers`); else format 1 and a `witness` message after.
        let generation = Witness.generation(snapshot)
        let inline = generation != nil && state.witnessPeers.contains(peer.deviceID)
        do {
            let witness = inline
                ? Witness.publishedWitness(state, memory: deps.witnessMemory, extra: witnessExtra(deps).union([peer.deviceID]))
                : nil
            let found = try await deps.lan.exchangeWitnessViews(peer: peer, identity: state.identity, groupKey: groupKey,
                                                                localStates: local, ownCounter: state.ownCounter,
                                                                vaultGeneration: inline ? generation : nil, witness: witness)
            peerStates = found.states; moved = found.moved; peerHeader = found.header
        } catch let e as LanSyncError {
            noteRefusal(e, store: store, deps: deps, peer: peer, state: state, inline: inline)
            fail.issues = [SyncIssue(e.reason == "bad-message" ? "bad-reply" : e.reason, e.detail)]; return fail
        } catch let e as LanPeerNotAnswering {
            // Closed right after the hello: the host no longer accepts this device (removed there, or it left or
            // reset sync); it says nothing on purpose, so this is the only sign.
            fail.issues = [SyncIssue(e.closedByPeer ? Self.notAccepted : "unreachable", "\(e)")]; return fail
        } catch {
            fail.issues = [SyncIssue("unreachable", "\(error)")]; return fail
        }
        // The host answered at a new address with its pinned keys: dial it there next time (only while the same
        // peer is still paired; a Leave or a new pairing during the run wins).
        if let moved, stillOpen(store), (try? deps.keychain.pairedPeer()) == peer {
            try? deps.keychain.setPairedPeer(PinnedPeer(deviceID: peer.deviceID, groupID: peer.groupID,
                                                        signingPublic: peer.signingPublic,
                                                        exchangePublic: peer.exchangePublic, endpoint: moved))
        }
        let attachments = await fetchAttachments(peerStates: peerStates, deps: deps, peer: peer, state: state,
                                                 groupKey: groupKey)
        // Emergency access (sub-plan 08): ask a peer not yet known to read the plan once (desktop `_probe_heir`).
        var heirPeers = state.heirPeers
        if !heirPeers.contains(peer.deviceID) {
            let reached = moved.map { PinnedPeer(deviceID: peer.deviceID, groupID: peer.groupID, signingPublic: peer.signingPublic,
                                                 exchangePublic: peer.exchangePublic, endpoint: $0) } ?? peer
            let answered = await deps.lan.probeHeir(peer: reached, identity: state.identity, groupKey: groupKey)
            // Pruned on each add (review M3): devices no longer paired or in the group are dropped, so the cap never
            // keeps a newly paired device out.
            let known = Set(state.members).union(state.lanPeers.filter { !$0.revoked }.map(\.deviceID))
            let kept = heirPeers.filter { known.contains($0) }
            if answered == true, kept.count < 64 {
                heirPeers = (kept + [peer.deviceID]).sorted()
            }
        }
        var report = SyncRunner.run(store: snapshot, views: [PeerView(deviceID: peer.deviceID, states: peerStates)],
                                    device: state.deviceID, now: now, licenseKeys: deps.licenseKeys, blobs: deps.attachmentBlobs,
                                    collections: collections, shares: shares)
        report.issues += attachments.issues
        let records = report.records ?? snapshot.records, meta = report.meta ?? snapshot.meta
        // The peer's attachment capability is saved in the same commit (desktop `attachment_peers`).
        var sync = snapshot.sync
        if let capable = attachments.capable, var st = sync,
           let next = AttachmentDocuments.peers(st.attachmentPeers, setting: peer.deviceID, capable: capable) {
            st.attachmentPeers = next
            sync = st
        }
        if var st = sync, st.heirPeers != heirPeers {
            st.heirPeers = heirPeers
            sync = st
        }
        // LAN protocol version 3: the exchange used the sealed hello (`LanClient` sends no other), so a listed peer
        // (the Mac's PCs) is pinned to it and its clear-text hello is refused from now on (desktop `save_sealed`).
        if let st = sync, let pinned = LanPeers.pinningSealed(peer.deviceID, in: st) {
            sync = pinned
        }
        // Workstream 6: the peer's changes were accepted now (local only; no extra commit when nothing changed).
        if records != snapshot.records || meta != snapshot.meta {
            sync = sync?.synced(with: [peer.deviceID], now: now)
        }
        if records != snapshot.records || meta != snapshot.meta || sync != snapshot.sync {
            do {
                try store.commit(StoreChange(baseRevision: snapshot.revision, records: records, meta: meta, sync: sync))
            } catch {
                report.issues.append(SyncIssue("busy", "\(error)"))
            }
        }
        PeerSeenAt.note(groupID: state.groupID, peer: peer.deviceID, now: now)
        if inline { deps.witnessMemory.clearRefusals(peer.deviceID) }   // a format-2 exchange went through
        // A peer not known to read collection states is asked once per exchange, after the merge and before the
        // witness (desktop `_exchange_features`): true or false is recorded; no answer records nothing (ask again).
        if !collections, stillOpen(store),
           let reads = (try? await deps.lan.exchangeFeatures(peer: peer, identity: state.identity, groupKey: groupKey)) ?? nil {
            LanFeatures.setPeer(peer.deviceID, capable: reads, store: store)
        }
        report.issues += await lanWitness(store: store, deps: deps, peer: peer, header: peerHeader, inline: inline)
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
            actionInfo = String(localized: "This \(SyncWording.thisDevice) joined the sync group. The first sync is running.")
            refreshMembership()
            await sync(.manual)
            return true
        } catch let e as EnrollConnectError where e.failure == .cancelled {
            joinTask = nil; connecting = nil; verificationCode = nil
            phase = .idle
            actionInfo = String(localized: "Pairing was cancelled.")
            refreshMembership()
            runPendingSync()
            return false
        } catch {
            joinTask = nil; connecting = nil; verificationCode = nil
            fail(error)
            return false
        }
    }

    /// The last Wi-Fi run could not reach the paired host, at its pinned address or by discovery: the Sync screen
    /// shows "Can't find the paired device on this network" with Find again.
    var hostNotFound: Bool {
        membership.peer != nil && issues.contains { $0.kind == "unreachable" || $0.kind == "no-endpoint" }
    }

    /// Find again: a fresh pairing QR from the paired PC moves its pinned address (keys must match; no
    /// enrollment), then syncs. Another device's QR is refused and nothing changes.
    @discardableResult
    func findAgain(_ text: String) async -> Bool {
        if let unavailable = deps.refusal { actionError = unavailable; return false }
        guard phase == .idle, runner == nil else { actionError = SyncWording.errorText(reason: "busy"); return false }
        actionError = nil; actionInfo = nil; actionOffersSettings = false
        guard let peer = (try? deps.keychain.pairedPeer()) ?? nil else {
            actionError = SyncWording.findAgainText(.otherDevice); return false
        }
        let moved: PinnedPeer
        do { moved = try PeerAddressRefresh.refreshed(peer, qrText: text) } catch let r as PeerAddressRefresh.Refusal {
            actionError = SyncWording.findAgainText(r); return false
        } catch {
            actionError = SyncWording.findAgainText(.notAPairingCode); return false
        }
        do { try deps.keychain.setPairedPeer(moved) } catch {
            actionError = SyncWording.stepFailedCopy; return false
        }
        refreshMembership()
        if let ep = moved.endpoint { actionInfo = SyncWording.foundAgainText(ep) }
        await sync(.manual)
        return true
    }

    /// Stops a QR join that is still connecting (the Cancel button next to "Connecting to …"). Once the
    /// connection is up (`connecting` is nil) it does nothing: the join completes or fails on its own.
    func cancelJoin() {
        guard connecting != nil else { return }
        joinTask?.cancel()
    }

    /// `onCode` receives the 6-digit verification code before the request is sent (a version-2 offer: once the
    /// inviter's reveal arrived and matched the QR's commitment) (desktop `on_code`): the
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
        // Pairing again into the group this device left: the identity it kept, so the host has it once (rule 3).
        let kept = snapshot.keptIdentity.flatMap {
            $0.fits(groupID: offer.groupID) && $0.deviceID != offer.inviterDeviceID ? $0 : nil
        }
        let identity = try kept?.identity ?? deps.newIdentity(deps.random)
        let request: [UInt8]
        let code: String
        do {
            // A phone never listens: it announces no endpoint and always initiates. The name is the generic one
            // it also gives itself in the keyring; the inviting device shows it on its Accept prompt.
            request = try Enrollment.buildRequest(offer: offer, identity: identity, endpoint: nil, name: deps.deviceName,
                                                  random: deps.random, now: deps.clock)
            // A version-2 offer's code needs the inviter's reveal (computed when it arrives, below).
            code = offer.commit != nil ? ""
                : try Enrollment.verificationCode(offer: offer, identity: identity, endpoint: nil, name: deps.deviceName)
        } catch PairingError.expired {
            throw SyncActionError("offer-used-or-expired")
        } catch {
            throw SyncActionError("bad-offer")
        }
        // Read before dialling: an address outside this Wi-Fi is still tried (it may be routed), but if
        // the dial fails the message says which address the PC should put in its code.
        let offSubnet = IPv4Subnet.mismatch(host: offer.endpoint.host, subnet: deps.localSubnet())
        // A version-1 offer: the code is known now. A version-2 offer (commit-then-reveal): the code covers the
        // inviter's reveal, so it is shown only once the reveal arrived and matched the QR's commitment.
        let revealed = RevealBox()
        if offer.commit == nil { onCode(code) }
        // The reply comes once the user chose Accept on the inviting device: the connection waits up to
        // `Enrollment.replySeconds` (75 s) for it (`NWLanDialer.enrollReplyTimeout`).
        let reply: [UInt8]
        do {
            if offer.commit == nil {
                reply = try await deps.lan.enroll(endpoint: offer.endpoint, request: request, onConnected: onConnected)
            } else {
                let deviceName = deps.deviceName
                reply = try await deps.lan.enroll(endpoint: offer.endpoint, request: request, onConnected: onConnected) { frame in
                    let reveal: [UInt8]
                    do {
                        guard !revealed.has else { throw PairingError.malformed("A second reveal frame") }
                        reveal = try Enrollment.openReveal(offer: offer, raw: frame)   // must match the QR's commitment
                    } catch {
                        revealed.fail()
                        throw error
                    }
                    revealed.set(reveal)
                    onCode(try Enrollment.verificationCode(offer: offer, identity: identity, endpoint: nil, name: deviceName,
                                                           reveal: reveal))
                }
            }
        } catch {
            if revealed.failed { throw SyncActionError("refused") }
            let kind = (error as? LanSocketError)?.kind ?? .other
            let failure: LanFailure = Task.isCancelled || error is CancellationError ? .cancelled : kind
            throw EnrollConnectError(failure: failure, endpoint: offer.endpoint, offSubnet: offSubnet)
        }
        let groupKey: GroupKey
        do {
            groupKey = try Enrollment.openReply(offer: offer, identity: identity, raw: reply, endpoint: nil, name: deps.deviceName,
                                                reveal: revealed.value)
        } catch PairingError.refused(let reason) {
            if reason == "used-or-expired" { throw SyncActionError("offer-used-or-expired") }
            if reason == "full" { throw SyncActionError("too-many-peers") }
            if reason == "declined" { throw SyncActionError("declined") }   // Decline, or no Accept within 60 s
            if reason == "update-needed" { throw SyncActionError("update-needed") }   // this iPhone sent an older request
            // Rule 5: a host on a released build refuses a known id with the plain refusal. The kept identity is
            // dropped, so the next pairing makes a new one as before.
            if let kept {
                try? dropKeptIdentity(kept, store: store)
                throw SyncActionError("rejoin-refused")
            }
            throw SyncActionError("refused")
        } catch {
            throw SyncActionError("refused")
        }
        let installID = try deps.keychain.installID(random: deps.random)
        // A kept identity continues its counters (its view counter and generation offset), so the host and the other
        // devices, which still know this id, never see them go back.
        let state = kept?.joinedState(groupKey, installID: installID, hasFolder: false)
            ?? SyncGroupState(groupID: groupKey.groupID, epoch: groupKey.epoch, key: groupKey.key, identity: identity,
                              installID: installID, hasFolder: false)
        try deps.keychain.setPairedPeer(offer.inviterPeer)
        do {
            let now = try store.load()
            guard now.sync == nil else { throw SyncActionError("already-joined") }
            // The join that used the kept identity makes it the live one again: it is no longer kept.
            try store.commit(StoreChange(baseRevision: now.revision, records: now.records, meta: now.meta, sync: state,
                                         keptIdentity: kept != nil ? .set(nil) : .keep))
        } catch {
            try? deps.keychain.deleteSlot(.pairedPeer)
            throw error
        }
    }

    /// Cloud folder: picked folder bookmark + sync password → join (new member), or attach when this
    /// phone is already in the group by QR (P4). Both run the first sync.
    @discardableResult
    func joinFolder(bookmark: [UInt8], password: String) async -> Bool {
        if let text = deps.refusal { actionError = text; return false }
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
            actionInfo = String(localized: "This \(SyncWording.thisDevice) now syncs through the cloud folder.")
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

    /// Cloud folder, desktop side: start a new group in the picked folder (`add == false`, vault not in a
    /// group) or give this vault's Wi-Fi-only group the folder (`add == true`), each with a new sync password,
    /// then store the bookmark and run once. The caller checks Pro first.
    @discardableResult
    func createFolder(bookmark: [UInt8], password: String, add: Bool, freshKey: Bool = false) async -> Bool {
        if let text = deps.refusal { actionError = text; return false }
        guard beginAction() else { return false }
        do {
            let result = try await Self.createFolderWork(bookmark: bookmark, password: password, add: add,
                                                         freshKey: freshKey, store: store, deps: deps)
            phase = .idle
            refreshMembership()
            apply(result)
            await publish(result)
            actionInfo = String(localized: "This \(SyncWording.thisDevice) now syncs through the cloud folder.")
            runPendingSync()
            return true
        } catch {
            fail(error)
            return false
        }
    }

    nonisolated static func createFolderWork(bookmark: [UInt8], password: String, add: Bool, freshKey: Bool = false,
                                             store: any ItemStore, deps: SyncDependencies) async throws -> SyncRunResult {
        let folder: any FolderAccess
        let refreshed: [UInt8]?
        do { (folder, refreshed) = try deps.folders.open(bookmark: bookmark) } catch { throw SyncActionError("folder-missing") }
        let installID = try deps.keychain.installID(random: deps.random)
        let fs = try FolderSync(access: folder, installID: installID, licenseKeys: deps.licenseKeys,
                                pairedKeys: pairedKeys(deps), attachmentBlobs: deps.attachmentBlobs,
                                collections: true, collectionShares: try ShareSync.collectionShares(store))
        let report = add
            ? try fs.addFolder(toGroup: store, password: password, deviceName: deps.deviceName, freshKey: freshKey, random: deps.random, clock: deps.clock)
            : try fs.create(store: store, password: password, deviceName: deps.deviceName, random: deps.random, clock: deps.clock)
        try deps.keychain.writeSlot(.folderBookmark, refreshed ?? bookmark)
        var out = SyncRunResult(issues: report.issues, conflicts: report.conflicts, ran: true)
        out.publish = stillOpen(store)
        return out
    }

    /// "Choose the folder again": stores the bookmark of this group's folder, never joining. When this vault is no
    /// longer a re-pick (left, or set up on another installation) it is refused, and the back-off is untouched.
    @discardableResult
    func repickFolder(bookmark: [UInt8]) async -> Bool {
        if let text = deps.refusal { actionError = text; return false }
        guard Self.isRepick(store: store, deps: deps) else {
            actionInfo = nil; actionOffersSettings = false
            let hasFolder = (try? store.load())?.sync?.hasFolder ?? false
            actionError = SyncWording.errorText(reason: hasFolder ? "rejoin-required" : "not-joined")
            return false
        }
        return await joinFolder(bookmark: bookmark, password: "")
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
                                pairedKeys: pairedKeys(deps), attachmentBlobs: deps.attachmentBlobs,
                                collections: true, collectionShares: try ShareSync.collectionShares(store))
        let snapshot = try store.load()
        let report: RunReport
        if let state = snapshot.sync, state.hasFolder, state.installID == installID {
            // Already syncing through a folder (e.g. the bookmark was lost): the picked folder must hold
            // this group's key file; then only the bookmark is stored. No password, no join.
            let raw: [UInt8]
            do { raw = try folder.read(FolderLayout.keyringPath, limit: 256 * 1024 + 1) }
            catch FolderAccessError.notFound { throw SyncActionError("no-group") }
            catch { throw SyncActionError("keyring-unreadable") }
            // A shared collection's keyring is not this group's (and not a damaged one): `share-group`.
            let ring: JSONValue
            do { ring = try Keyring.parse(raw) } catch let e as KeyringError where e.reason == "share-group" {
                throw SyncActionError("share-group")
            } catch {
                throw SyncActionError("keyring-corrupt")
            }
            guard case .object(let o) = ring, o["group_id"] == .string(state.groupID) else {
                throw SyncActionError("folder-has-other-group")
            }
            try deps.keychain.writeSlot(.folderBookmark, refreshed ?? bookmark)
            report = fs.runOnce(store: store, random: deps.random, clock: deps.clock)
        } else if let state = snapshot.sync, !state.hasFolder, state.installID == installID {
            // Already in the group over Wi-Fi: an empty folder gets the copy that fits ("Create one" is not offered here).
            do {
                report = try fs.attach(store: store, password: password, deviceName: deps.deviceName, random: deps.random, clock: deps.clock)
            } catch let e as FolderSyncError where e.reason == "no-group" {
                throw SyncActionError("no-group-paired")
            }
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

    // MARK: rollback warnings (desktop `acknowledge_rollback` / `dismiss_peer_rollback`)

    /// "This was me — keep this copy" for `vault-rollback`, after the UI's confirmation. `reauthenticate` is the
    /// screen's prompt (Face ID or the device passcode on the iPhone, Touch ID or the master password on the Mac);
    /// nothing changes unless it succeeds. Raises the vault generation above every witness and clears the warning
    /// in one commit. There is no automatic acknowledgement: only this explicit, re-authenticated step clears it.
    @discardableResult
    func acknowledgeRollback(reauthenticate: @MainActor () async -> Bool) async -> Bool {
        // The warning may come from this run or from a served exchange (Mac host); the store says whether one is open.
        guard ((try? store.load())?.sync?.rollbackSuspected ?? 0) > 0 else { return false }
        guard beginAction() else { return false }
        guard await reauthenticate(), gate.isOpen else {
            phase = .idle
            runPendingSync()
            return false
        }
        do {
            guard try Witness.acknowledgeRollback(store: store) else {
                phase = .idle; runPendingSync(); return false
            }
            phase = .idle
            issues.removeAll { $0.kind == "vault-rollback" }
            actionInfo = SyncWording.text(SyncIssue("rollback-acknowledged"))
            runPendingSync()
            return true
        } catch {
            fail(error)
            return false
        }
    }

    /// Dismiss `peer-vault-rollback` for one device: its older copy is accepted from now on.
    @discardableResult
    func dismissPeerRollback(_ deviceID: String) async -> Bool {
        guard !deviceID.isEmpty else { return false }
        guard beginAction() else { return false }
        do {
            try Witness.forgetPeerGeneration(store: store, peerID: deviceID, memory: deps.witnessMemory)
            phase = .idle
            issues.removeAll { $0.kind == "peer-vault-rollback" && $0.detail == deviceID }
            runPendingSync()
            return true
        } catch {
            fail(error)
            return false
        }
    }

    // MARK: cloud folder members (remove, confirm)

    /// Removes `plan.ids` from the cloud-folder group in ONE rotation with the new sync password (`again` must
    /// match): epoch + 1, the new key wrapped only to `plan.keep` and this device, the removed devices' files
    /// deleted and a signed removal notice written for each (`FolderSync.rotate`). The caller checks Pro first.
    @discardableResult
    func removeMembers(_ plan: DeviceRemoval.Plan, password: String, again: String) async -> Bool {
        guard password == again else { actionError = DeviceRemoval.mismatchText; return false }
        guard beginAction() else { return false }
        let store = store, deps = deps
        do {
            let report: RunReport = try await withCheckedThrowingContinuation { c in
                // Argon2id and the folder (NSFileCoordinator) block: a GCD thread, never a cooperative one.
                DispatchQueue.global(qos: .userInitiated).async {
                    c.resume(with: Result {
                        try Self.folderSync(deps, store: store).rotate(store: store, newPassword: password, remove: plan.ids, keep: plan.keep,
                                                         random: deps.random, clock: deps.clock)
                    })
                }
            }
            phase = .idle
            refreshMembership()
            // The rotation's run is a normal folder run: "N items updated" and the AutoFill republish as in `runLoop`.
            var result = SyncRunResult(issues: report.issues, conflicts: report.conflicts, ran: true)
            result.changed = report.applied + report.deleted + report.conflicts
            result.publish = Self.stillOpen(store)
            apply(result)
            actionInfo = DeviceRemoval.removedText(plan.names)
            await publish(result)
            runPendingSync()
            return true
        } catch {
            fail(error)
            return false
        }
    }

    /// "These are my devices": only `ids` stop being unconfirmed (one that arrived after the list was drawn stays).
    /// Returns how many were confirmed, nil when it failed (`actionError` says why).
    @discardableResult
    func acknowledgeMembers(_ ids: [String]) async -> Int? {
        guard !ids.isEmpty, beginAction() else { return nil }
        do {
            let n = try Self.folderSync(deps, store: store).acknowledgeMembers(store: store, ids)
            phase = .idle
            refreshMembership()
            actionInfo = n == 1 ? String(localized: "1 device confirmed.") : String(localized: "\(n) devices confirmed.")
            runPendingSync()
            return n
        } catch {
            fail(error)
            return nil
        }
    }

    // MARK: shared collections (sub-plan 07; desktop `CollectionShareService`)
    //
    // Each action runs under the coordinator's action lock (never beside a sync run, so never interleaved with a run's
    // store writes), off the main actor (Argon2id and the folder block), inside a background task. Create, join and
    // join again need Pro (checked before any key derivation); approve, remove and leave do not. A refusal sets
    // `shareActionReason` and changes nothing. Share passwords are only passed through, never kept.

    /// Share `collectionID` through the folder of `bookmark`, with this device as its owner named `deviceName`.
    /// `password` is what the other people type to join; `membersCanEdit` is fixed for the life of the share.
    @discardableResult
    func createShare(collectionID: String, bookmark: [UInt8], password: String, deviceName: String,
                     membersCanEdit: Bool) async -> ShareGroups.Group? {
        let mode = membersCanEdit ? "edit" : "read"
        return await shareAction { store, deps, isPro in
            try ShareSync.create(store: store, deps: deps, isPro: isPro, collectionID: collectionID, bookmark: bookmark,
                                 password: password, deviceName: deviceName, mode: mode)
        }
    }

    /// Join the shared collection in the folder of `bookmark` as `deviceName`; this device waits for the owner's approval.
    @discardableResult
    func joinShare(bookmark: [UInt8], password: String, deviceName: String) async -> ShareGroups.Group? {
        await shareAction { store, deps, isPro in
            try ShareSync.join(store: store, deps: deps, isPro: isPro, bookmark: bookmark, password: password,
                               deviceName: deviceName)
        }
    }

    /// Join again after someone else's join at the same moment won (`superseded`: the status offers Join again).
    @discardableResult
    func rejoinShare(groupID: String, password: String, deviceName: String) async -> ShareGroups.Group? {
        await shareAction { store, deps, isPro in
            try ShareSync.rejoin(store: store, deps: deps, isPro: isPro, groupID: groupID, password: password,
                                 deviceName: deviceName)
        }
    }

    /// The owner lets the waiting `deviceIDs` in (each shown by name first). Returns the members approved.
    @discardableResult
    func approveShare(groupID: String, deviceIDs: [String]) async -> [ShareGroups.Member]? {
        await shareAction { store, deps, _ in
            try ShareSync.approve(store: store, deps: deps, groupID: groupID, deviceIDs: deviceIDs)
        }
    }

    /// The owner removes `deviceID` with a new share password (`again` must match; the removed person knows the old
    /// one). True once removed; `shareRemovalWritten` says whether the folder got the notice and the new keyring.
    @discardableResult
    func removeShareMember(groupID: String, deviceID: String, newPassword: String, again: String) async -> Bool {
        guard newPassword == again else { shareActionReason = "password-mismatch"; return false }
        let written = await shareAction { store, deps, _ in
            try ShareSync.removeMember(store: store, deps: deps, groupID: groupID, deviceID: deviceID,
                                       newPassword: newPassword)
        }
        guard let written else { return false }
        shareRemovalWritten = written
        return true
    }

    /// The owner upgrades a share v1 collection to share v2 (only the people let in can open its items), with
    /// `password` (`again` must match) as the share password from now on; it may be the current one. Works without
    /// Pro. True once upgraded; the share run writes the keyring when the folder could not take it now.
    @discardableResult
    func upgradeShare(groupID: String, password: String, again: String) async -> Bool {
        guard password == again else { shareActionReason = "password-mismatch"; return false }
        let done = await shareAction { store, deps, _ in
            try ShareSync.upgrade(store: store, deps: deps, groupID: groupID, password: password)
        }
        return done != nil
    }

    /// Leave a shared collection (a member), or stop sharing it (the owner): the collection and its items stay here.
    @discardableResult
    func leaveShare(groupID: String) async -> Bool {
        let left: Void? = await shareAction(syncAfter: false) { store, _, _ in
            try ShareSync.leave(store: store, groupID: groupID)
        }
        guard left != nil else { return false }
        shareIssues[groupID] = nil
        return true
    }

    /// Forget the share link of `collectionID` that another of this person's devices published (final review finding
    /// 4): for a device that was lost or reset. The run after it publishes the link's tombstone; a device that still
    /// holds the share publishes its link again. Works without Pro.
    @discardableResult
    func forgetShareLink(collectionID: String) async -> Bool {
        let done: Void? = await shareAction { store, _, _ in
            try ShareSync.forgetLink(store: store, collectionID: collectionID)
        }
        return done != nil
    }

    /// One share action: the action lock, the work off the main actor, then (`syncAfter`) a run so the share's folder is
    /// read and written now. Nil when refused (`shareActionReason`).
    private func shareAction<T: Sendable>(syncAfter: Bool = true,
                                          _ work: @escaping @Sendable (any ItemStore, SyncDependencies, Bool) throws -> T) async -> T? {
        shareActionReason = nil
        shareRemovalWritten = true
        guard beginAction() else { shareActionReason = deps.unavailableText == nil ? "busy" : "sync-unavailable"; return nil }
        let store = store, deps = deps, pro = isPro()
        let scope = BackgroundTaskScope(background, name: "LocalGateKeys shared collection")
        defer { scope.end() }
        let value: T
        do {
            value = try await Self.offMain { try work(store, deps, pro) }
        } catch {
            phase = .idle
            shareActionReason = ShareSync.reason(error)
            refreshMembership()
            runPendingSync()
            return nil
        }
        phase = .idle
        refreshMembership()
        if syncAfter {
            syncAfterAction = false   // the run below includes any edit made meanwhile
            await sync(.manual)
        } else {
            runPendingSync()
        }
        return value
    }

    /// Runs blocking work (Argon2id, the folder) on a GCD thread, never a cooperative one.
    nonisolated static func offMain<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { c in
            DispatchQueue.global(qos: .userInitiated).async { c.resume(with: Result { try body() }) }
        }
    }

    /// Drops the kept identity `kept` (still the stored one) in one commit.
    nonisolated static func dropKeptIdentity(_ kept: KeptIdentity, store: any ItemStore) throws {
        let snap = try store.load()
        guard snap.keptIdentity == kept else { return }
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync,
                                     keptIdentity: .set(nil)))
    }

    // MARK: leave and reset (each after two confirmations in the UI)

    /// Issues of the last run that say this device was (or may have been) removed from its group: Leave keeps no
    /// identity after them (rule 2), so a removed device never comes back under its old id.
    static let removedKinds: Set<String> = [RemovalNotice.issueKind, "removed-or-conflict", "rejoin-required", "not-member",
                                            "missed-rotation"]

    /// Stops syncing and forgets the paired device and folder; items and their sync history stay. The device's identity
    /// in the group is kept (rule 1) unless the last run said it was removed or a verified removal notice is in the folder.
    func leave() async {
        guard beginAction() else { return }
        let ownID = membership.deviceID
        let removed = issues.contains { Self.removedKinds.contains($0.kind) || ($0.kind == "member-dropped" && $0.detail == ownID) }
        let deps = deps
        let noticed = removed ? true : await Self.offMainOrTrue { Self.removalNoticeVerified(deps) }
        do {
            try Self.clear(store: store, deps: deps, history: false, keepIdentity: !noticed)
            phase = .idle
            actionInfo = SyncWording.leftText
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
            actionInfo = SyncWording.resetResultText(cleared)
            issues = []
            refreshMembership()
        } catch { fail(error) }
    }

    /// `body` off the main actor; true when it could not run (the safe answer for `removalNoticeVerified`).
    nonisolated static func offMainOrTrue(_ body: @escaping @Sendable () -> Bool) async -> Bool {
        (try? await offMain(body)) ?? true
    }

    /// True when the group's folder holds a removal notice for this device that verifies against the watch file (the
    /// check the removal guard makes). False without a watch file, a folder or a notice. Blocks (the folder).
    nonisolated static func removalNoticeVerified(_ deps: SyncDependencies) -> Bool {
        guard let url = deps.watchFile, let raw = FileRemovalWatchStore(url: url, folder: "").load(),
              let watch = RemovalWatch.parse(raw),
              let bookmark = (try? deps.keychain.readSlot(.folderBookmark)) ?? nil,
              let idBytes = (try? deps.keychain.readSlot(.installID)) ?? nil,
              let installID = String(bytes: idBytes, encoding: .utf8), !installID.isEmpty,
              let opened = try? deps.folders.open(bookmark: bookmark) else { return false }
        return RemovalNotice.check(watch, access: opened.folder, installID: installID) != nil
    }

    /// Leave (`history` false) or Reset (`history` true). Leave stores the device's identity in the group as the kept
    /// identity in the same commit that clears the group (rule 1), replacing an earlier one, when `keepIdentity` and the
    /// group was set up on this installation; otherwise, and on every Reset, none is kept (rule 2). The second (duress)
    /// vault never keeps one.
    @discardableResult
    nonisolated static func clear(store: any ItemStore, deps: SyncDependencies, history: Bool,
                                  keepIdentity: Bool = false) throws -> Bool {
        // Left or reset: a later removal notice must not erase this vault (desktop `forget_session_watch`). First,
        // before anything that can throw: a Leave that stops half way never leaves the watch behind.
        if let url = deps.watchFile { try? FileManager.default.removeItem(at: url) }
        let snap = try store.load()
        let had = snap.sync != nil || (history && !snap.meta.isEmpty)
        // Reset drops it; a Leave of a group replaces it; a Leave with no group leaves it as it is.
        var kept = history ? nil : snap.keptIdentity
        if !history, let state = snap.sync {
            let sameInstall = ((try? deps.keychain.readSlot(.installID)) ?? nil).map { String(decoding: $0, as: UTF8.self) }
                == state.installID
            kept = keepIdentity && !deps.inert && sameInstall ? KeptIdentity(leaving: state) : nil
        }
        if had || snap.keptIdentity != kept {
            try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records,
                                         meta: history ? [:] : snap.meta, sync: nil, keptIdentity: .set(kept)))
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
        if let text = deps.refusal { actionError = text; return false }
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
        Task { await self.sync(.manual) }   // part of the join or leave the person started
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

/// What one Wi-Fi run offers `peerID`: documents only when `documents`, and the emergency access plan only to a
/// peer that answered `heir-hello` (desktop `heir_peers`).
func lanLocalView(_ all: [ItemState], state: SyncGroupState, peerID: String, documents: Bool) -> [ItemState] {
    Heir.publishable(AttachmentDocuments.publishable(all, documents: documents), heir: state.heirPeers.contains(peerID))
}
