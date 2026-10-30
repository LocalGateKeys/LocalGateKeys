/// This device's membership of a sync group (desktop `vault_bridge.SyncGroupState`).
public struct SyncGroupState: Equatable, Sendable {
    public var groupID: String
    public var epoch: Int64
    public var key: [UInt8]
    public var identity: DeviceIdentity
    public var installID: String
    /// True once the group uses the cloud folder (joined or attached there).
    public var hasFolder: Bool
    /// Last counter and sha256 hex of the last file accepted per peer.
    public var lastSeen: [String: Int64]
    public var peerDigests: [String: String]
    public var membersEpoch: Int64
    public var members: [String]
    /// Bytes of the last accepted keyring (restored over a rolled-back or tampered one).
    public var keyring: [UInt8]?
    /// The last own-file counter reserved; saved before the file carrying it is written.
    public var ownCounter: Int64
    /// Device id -> base64 Ed25519 key its view files are signed with (desktop `view_signers`, audit M-7): this
    /// device's own key once it wrote a signed view, and each peer's once a signed view of it verified. A pinned
    /// peer's views must carry a valid signature by that key. Adopting a new epoch keeps only the own entry.
    /// The app's store must persist it (an empty map just means no peer is pinned yet).
    public var viewSigners: [String: String]
    /// The LAN peers this device pinned (at most `LanPeers.maxPeers`, revoked ones included); empty in
    /// states stored before the field existed.
    public var lanPeers: [LanPeer]
    /// Keyring members added by another device since the user last confirmed the member list (desktop
    /// `unacked_members`, audit M10). A rotation with no explicit `keep` never wraps the new key to them;
    /// the Sync page asks the user to confirm them (`FolderSync.acknowledgeMembers`). Empty in older states.
    public var unackedMembers: [String]
    /// Rollback witnesses (desktop `peer_generations`, 2026-10-29): the highest vault generation each peer
    /// published; never lowered. Survives an epoch change.
    public var peerGenerations: [String: Int64]
    /// The highest generation of THIS vault a peer has seen above our own (0 = none). Sticky: only the user's
    /// "This was me" (`Witness.acknowledgeRollback`) clears it.
    public var rollbackSuspected: Int64
    /// Peer ids that showed view-format-2 support (desktop `witness_peers`), sorted.
    public var witnessPeers: [String]
    /// Folder: the view counter of each peer's last view that published a generation (desktop
    /// `witness_counters`); cleared on an epoch change.
    public var witnessCounters: [String: Int64]
    /// Added to the store's committed revision to give this vault's generation (plan B5): raised only by the
    /// acknowledgement, so a restored store publishes a lower generation than before.
    public var generationOffset: Int64
    /// Wi-Fi peers that showed they read documents (desktop `attachment_peers`, attachment sync 2026-10-29), sorted.
    /// They get document items in LAN views. Stored only when not empty.
    public var attachmentPeers: [String]
    /// Peer device id -> wall-clock time (Unix seconds) this device last accepted that peer's changes (UX plan
    /// workstream 6, desktop `peer_synced_at`, Android `peerSyncedAt`). Local only: never written to the folder or
    /// sent over Wi-Fi. Stored only when not empty.
    public var peerSyncedAt: [String: Int64]

    public init(groupID: String, epoch: Int64, key: [UInt8], identity: DeviceIdentity, installID: String,
                hasFolder: Bool = true, lastSeen: [String: Int64] = [:], peerDigests: [String: String] = [:],
                membersEpoch: Int64 = 0, members: [String] = [], keyring: [UInt8]? = nil, ownCounter: Int64 = 0,
                viewSigners: [String: String] = [:], lanPeers: [LanPeer] = [], unackedMembers: [String] = [],
                peerGenerations: [String: Int64] = [:], rollbackSuspected: Int64 = 0, witnessPeers: [String] = [],
                witnessCounters: [String: Int64] = [:], generationOffset: Int64 = 0,
                attachmentPeers: [String] = [], peerSyncedAt: [String: Int64] = [:]) {
        self.groupID = groupID; self.epoch = epoch; self.key = key; self.identity = identity
        self.installID = installID; self.hasFolder = hasFolder; self.lastSeen = lastSeen
        self.peerDigests = peerDigests; self.membersEpoch = membersEpoch; self.members = members
        self.keyring = keyring; self.ownCounter = ownCounter; self.viewSigners = viewSigners
        self.lanPeers = lanPeers
        self.unackedMembers = unackedMembers
        self.peerGenerations = peerGenerations; self.rollbackSuspected = rollbackSuspected
        self.witnessPeers = witnessPeers; self.witnessCounters = witnessCounters
        self.generationOffset = generationOffset
        self.attachmentPeers = attachmentPeers
        self.peerSyncedAt = peerSyncedAt
    }

    /// Most peers kept in `peerSyncedAt` (desktop `MAX_PEERS_SEEN`).
    public static let maxPeerSyncedAt = 64
    /// Largest stored time (desktop `_MAX_INT53`).
    public static let maxSyncedAtValue: Int64 = 9_007_199_254_740_991

    /// This state with `peers` accepted at `now` (desktop `synced_with`): own id ignored, the `limit` most recent
    /// peers kept. Unchanged when no other peer is given.
    public func synced(with peers: some Collection<String>, now: Int64, limit: Int = maxPeerSyncedAt) -> SyncGroupState {
        let others = peers.filter { $0 != deviceID }
        guard !others.isEmpty else { return self }
        let at = min(max(0, now), Self.maxSyncedAtValue)
        var times = peerSyncedAt
        for p in others { times[p] = at }
        if times.count > limit {
            // Most recent first; equal times by id so the kept set does not depend on dictionary order.
            let kept = times.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }.prefix(limit)
            times = Dictionary(uniqueKeysWithValues: kept.map { ($0.key, $0.value) })
        }
        var next = self
        next.peerSyncedAt = times
        return next
    }

    public var deviceID: String { identity.deviceID }
    func groupKey() throws -> GroupKey { try GroupKey(groupID: groupID, epoch: epoch, key: key) }
}

/// What the store holds for sync: every record as its synced wrapper, the per-id sync meta and the group state.
public struct StoreSnapshot: Equatable, Sendable {
    public var records: [String: JSONValue]
    public var meta: [String: SyncMeta]
    public var sync: SyncGroupState?
    /// Changes on every commit; a commit against an older revision is refused.
    public var revision: Int64

    public init(records: [String: JSONValue] = [:], meta: [String: SyncMeta] = [:], sync: SyncGroupState? = nil,
                revision: Int64 = 0) {
        self.records = records; self.meta = meta; self.sync = sync; self.revision = revision
    }
}

/// One atomic store write: the full new records, meta and group state, based on `baseRevision`.
public struct StoreChange: Equatable, Sendable {
    public var baseRevision: Int64
    public var records: [String: JSONValue]
    public var meta: [String: SyncMeta]
    public var sync: SyncGroupState?

    public init(baseRevision: Int64, records: [String: JSONValue], meta: [String: SyncMeta], sync: SyncGroupState?) {
        self.baseRevision = baseRevision; self.records = records; self.meta = meta; self.sync = sync
    }
}

/// The local vault as sync sees it. `commit` is atomic and durable before it returns, and throws when the
/// store changed since `baseRevision` (the caller syncs again).
public protocol ItemStore: AnyObject, Sendable {
    func load() throws -> StoreSnapshot
    func commit(_ change: StoreChange) throws
}
