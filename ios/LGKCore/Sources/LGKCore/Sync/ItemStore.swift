/// This device's membership of a sync group (desktop `vault_bridge.SyncGroupState`, without the LAN fields).
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

    public init(groupID: String, epoch: Int64, key: [UInt8], identity: DeviceIdentity, installID: String,
                hasFolder: Bool = true, lastSeen: [String: Int64] = [:], peerDigests: [String: String] = [:],
                membersEpoch: Int64 = 0, members: [String] = [], keyring: [UInt8]? = nil, ownCounter: Int64 = 0,
                viewSigners: [String: String] = [:]) {
        self.groupID = groupID; self.epoch = epoch; self.key = key; self.identity = identity
        self.installID = installID; self.hasFolder = hasFolder; self.lastSeen = lastSeen
        self.peerDigests = peerDigests; self.membersEpoch = membersEpoch; self.members = members
        self.keyring = keyring; self.ownCounter = ownCounter; self.viewSigners = viewSigners
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
