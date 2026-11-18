/// A share-group operation that is refused; `reason` is a stable code (desktop `share_group.ShareGroupError`):
/// `bad-state`, `not-joined`, `not-share`, `personal-group`, `already-joined`, `own-share`, `collection-exists`,
/// `no-collection`, `already-shared`, `not-owner`, `not-pending`, `not-member`, `trash-full`, `item-error`,
/// `bad-remote`, `store-changed`. Never carries a key, a password or a keyring.
public struct ShareGroupError: Error, Equatable, Sendable, CustomStringConvertible {
    public let reason: String
    public let detail: String
    public init(_ reason: String, _ detail: String = "") { self.reason = reason; self.detail = detail }
    public var description: String { detail.isEmpty ? reason : "\(reason): \(detail)" }
}

/// What Recently deleted holds when a share runs (the host's `LocalData.trash`, read before the run): how many rows
/// (a removal checks `trash-full` first; nil: unknown, so a removal is refused) and the collections of each deleted
/// record (an incoming share item may bring back only a deleted item of its own collection, never a personal one).
public struct ShareTrash: Equatable, Sendable {
    public var count: Int?
    /// Deleted record id -> its `collection_ids` (empty for none).
    public var collections: [String: [String]]
    /// Deleted record id -> the record as deleted (the newest row of that id): an item a share brings back keeps this
    /// device's own tags, favourite, other collections and `document_ids` from it (desktop `_Applier.store`).
    public var records: [String: [String: JSONValue]]

    public init(count: Int?, collections: [String: [String]] = [:], records: [String: [String: JSONValue]] = [:]) {
        self.count = count; self.collections = collections; self.records = records
    }

    /// From the host's Recently deleted rows.
    public static func of(_ rows: [LocalData.TrashRow]) -> ShareTrash {
        var out: [String: [String]] = [:]
        var records: [String: [String: JSONValue]] = [:]
        for row in rows {
            guard case .object(let r)? = try? row.record(), case .string(let id)? = r["id"] else { continue }
            out[id, default: []] += CollectionCatalog.strings(r["collection_ids"])
            records[id] = r
        }
        return ShareTrash(count: rows.count, collections: out, records: records)
    }
}

/// One share group of this vault as stored in the item store's sealed state (`StoreSnapshot.shares`, desktop
/// `payload["share_groups"]`): the role, the pinned facts (collection, owner device and key, mode), the group's own
/// sync state (keys, keyring, counters), its own per-record sync meta (desktop `share_sync_meta`), the members the
/// owner removed and an opaque folder reference (a security-scoped bookmark the host resolves).
///
/// Everything here stays on the device: it is never a record, so never in a sync view (personal or share), a backup
/// or an export. `description` names no key, password, keyring or member.
public struct ShareRecord: Equatable, Sendable, CustomStringConvertible {
    public enum Role: String, Sendable { case owner, member }

    /// One member the owner removed (desktop `removed` rows): the name when it could be read, and when.
    public struct Removed: Equatable, Sendable {
        public let name: String?
        public let at: Int64
        public init(name: String?, at: Int64) { self.name = name; self.at = at }
    }

    public static let version: Int64 = 1
    public static let maxRemoved = 50
    static let maxName = 100
    static let maxFolderBytes = 64 * 1024

    public var role: Role
    public var pin: ShareKeyring.Pin
    public var state: SyncGroupState
    public var meta: [String: SyncMeta]
    public var removed: [Removed]
    public var folder: [UInt8]?

    public init(role: Role, pin: ShareKeyring.Pin, state: SyncGroupState, meta: [String: SyncMeta] = [:],
                removed: [Removed] = [], folder: [UInt8]? = nil) {
        self.role = role; self.pin = pin; self.state = state; self.meta = meta; self.removed = removed
        self.folder = folder
    }

    public var groupID: String { state.groupID }
    public var collectionID: String { pin.collectionID }
    /// This device may not publish local changes: a member of a `read` share.
    public var isReadOnly: Bool { role == .member && pin.sharedMode == "read" }

    public var description: String {
        "ShareRecord(group=\(state.groupID), collection=\(pin.collectionID), role=\(role.rawValue), mode=\(pin.sharedMode))"
    }

    // MARK: - stored shape

    static let fields: Set<String> = ["version", "role", "collection_id", "owner", "owner_key", "shared_mode", "state",
                                      "meta"]
    static let optionalFields: Set<String> = ["removed", "folder"]
    static let stateFields: Set<String> = ["group_id", "epoch", "key", "device_id", "signing", "exchange", "install_id",
                                           "last_seen", "peer_digests", "members_epoch", "members", "keyring",
                                           "own_counter", "view_signers", "unacked_members", "peer_synced_at"]
    static let metaFields: Set<String> = ["digest", "body", "updated_at", "vv", "deleted", "deleted_at"]

    /// The stored JSON of every group: `{group id: record}`; nil for none (the key is then left out of the store).
    public static func encode(_ records: [String: ShareRecord]) -> JSONValue? {
        if records.isEmpty { return nil }
        return .object(records.mapValues { $0.json })
    }

    var json: JSONValue {
        var o: [String: JSONValue] = [
            "version": .int(Self.version), "role": .string(role.rawValue), "collection_id": .string(pin.collectionID),
            "owner": .string(pin.owner), "owner_key": .string(pin.ownerKey), "shared_mode": .string(pin.sharedMode),
            "state": Self.encodeState(state), "meta": .object(meta.mapValues(Self.encodeMeta)),
        ]
        if !removed.isEmpty {
            var rows: [JSONValue] = []
            for r in removed { rows.append(.object(["name": Self.optText(r.name), "at": .int(r.at)])) }
            o["removed"] = .array(rows)
        }
        if let folder { o["folder"] = .string(Base64.encode(folder)) }
        return .object(o)
    }

    static func optText(_ s: String?) -> JSONValue {
        guard let s else { return .null }
        return .string(s)
    }

    static func optInt(_ n: Int64?) -> JSONValue {
        guard let n else { return .null }
        return .int(n)
    }

    static func ints(_ d: [String: Int64]) -> JSONValue { .object(d.mapValues { JSONValue.int($0) }) }
    static func texts(_ d: [String: String]) -> JSONValue { .object(d.mapValues { JSONValue.string($0) }) }
    static func strings(_ a: [String]) -> JSONValue { .array(a.map { JSONValue.string($0) }) }

    static func encodeState(_ s: SyncGroupState) -> JSONValue {
        var o: [String: JSONValue] = [:]
        o["group_id"] = .string(s.groupID)
        o["epoch"] = .int(s.epoch)
        o["key"] = .string(Base64.encode(s.key))
        o["device_id"] = .string(s.identity.deviceID)
        o["signing"] = .string(Base64.encode(s.identity.signingPrivateKey))
        o["exchange"] = .string(Base64.encode(s.identity.exchangePrivateKey))
        o["install_id"] = .string(s.installID)
        o["last_seen"] = ints(s.lastSeen)
        o["peer_digests"] = texts(s.peerDigests)
        o["members_epoch"] = .int(s.membersEpoch)
        o["members"] = strings(s.members)
        o["keyring"] = s.keyring.map { JSONValue.string(Base64.encode($0)) } ?? JSONValue.null
        o["own_counter"] = .int(s.ownCounter)
        o["view_signers"] = texts(s.viewSigners)
        o["unacked_members"] = strings(s.unackedMembers)
        o["peer_synced_at"] = ints(s.peerSyncedAt)
        return .object(o)
    }

    static func encodeMeta(_ m: SyncMeta) -> JSONValue {
        .object(["digest": optText(m.digest), "body": optText(m.body), "updated_at": optInt(m.updatedAt),
                 "vv": ints(m.vv), "deleted": .bool(m.deleted), "deleted_at": optInt(m.deletedAt)])
    }

    // MARK: - strict decode

    static func bad(_ what: String) -> ShareGroupError { ShareGroupError("bad-state", "stored share group is malformed: \(what)") }

    /// Every stored group, each checked (desktop `_records` / `_check_record`); `bad-state` for anything off.
    public static func decodeAll(_ raw: JSONValue?) throws -> [String: ShareRecord] {
        guard let raw else { return [:] }
        guard case .object(let groups) = raw else { throw bad("groups") }
        var out: [String: ShareRecord] = [:]
        for (groupID, value) in groups { out[groupID] = try decode(groupID: groupID, value) }
        return out
    }

    /// One stored group: exact fields and types, the stored keyring re-verified (structure and owner signature), and
    /// the pinned facts equal to its metadata; the owner role only on the owner's device.
    public static func decode(groupID: String, _ value: JSONValue) throws -> ShareRecord {
        guard Identifier.isValid(groupID), case .object(let o) = value else { throw bad("group id") }
        let keys = Set(o.keys)
        guard fields.isSubset(of: keys), keys.subtracting(fields).isSubset(of: optionalFields) else { throw bad("fields") }
        guard o["version"] == .int(version) else { throw bad("version") }
        guard case .string(let roleText)? = o["role"], let role = Role(rawValue: roleText) else { throw bad("role") }
        let pin = ShareKeyring.Pin(collectionID: try text(o["collection_id"], "collection_id"),
                                   owner: try text(o["owner"], "owner"), ownerKey: try text(o["owner_key"], "owner_key"),
                                   sharedMode: try text(o["shared_mode"], "shared_mode"))
        let state = try decodeState(o["state"])
        guard case .object(let metaObject)? = o["meta"], metaObject.count <= SyncMeta.maxRecords else { throw bad("meta") }
        var meta: [String: SyncMeta] = [:]
        for (id, m) in metaObject { meta[id] = try decodeMeta(m) }
        var removed: [Removed] = []
        if let rows = o["removed"] {
            guard case .array(let list) = rows, list.count <= maxRemoved else { throw bad("removed") }
            for row in list {
                guard case .object(let r) = row, Set(r.keys) == ["name", "at"], case .int(let at)? = r["at"], at >= 0 else {
                    throw bad("removed")
                }
                switch r["name"] {
                case .null?: removed.append(Removed(name: nil, at: at))
                case .string(let n)? where n.unicodeScalars.count <= maxName: removed.append(Removed(name: n, at: at))
                default: throw bad("removed")
                }
            }
        }
        var folder: [UInt8]?
        if let f = o["folder"] {
            guard case .string(let t) = f, let bytes = try? Base64.decodeStrict(t), bytes.count <= maxFolderBytes else {
                throw bad("folder")
            }
            folder = bytes
        }
        let record = ShareRecord(role: role, pin: pin, state: state, meta: meta, removed: removed, folder: folder)
        try record.check(groupID: groupID)
        return record
    }

    /// The pinned facts against the stored keyring (desktop `_check_record`).
    func check(groupID: String) throws {
        guard ShareKeyring.same(state.groupID, groupID) else { throw Self.bad("group id") }
        guard let bytes = state.keyring, let ring = try? ShareKeyring.parse(bytes), let got = try? ShareKeyring.Pin.of(ring),
              got.matches(pin) else { throw Self.bad("keyring") }
        guard ShareKeyring.same(Keyring.str(Keyring.obj(ring)["group_id"]), groupID) else { throw Self.bad("keyring") }
        guard (role == .owner) == ShareKeyring.same(state.deviceID, pin.owner) else { throw Self.bad("role") }
    }

    static func text(_ v: JSONValue?, _ what: String) throws -> String {
        guard case .string(let s)? = v else { throw bad(what) }
        return s
    }

    static func intMap(_ v: JSONValue?, _ what: String) throws -> [String: Int64] {
        guard case .object(let d)? = v else { throw bad(what) }
        var out: [String: Int64] = [:]
        for (k, x) in d {
            guard case .int(let n) = x, n >= 0 else { throw bad(what) }
            out[k] = n
        }
        return out
    }

    static func textMap(_ v: JSONValue?, _ what: String) throws -> [String: String] {
        guard case .object(let d)? = v else { throw bad(what) }
        var out: [String: String] = [:]
        for (k, x) in d {
            guard case .string(let s) = x else { throw bad(what) }
            out[k] = s
        }
        return out
    }

    static func ids(_ v: JSONValue?, _ what: String) throws -> [String] {
        guard case .array(let a)? = v else { throw bad(what) }
        return try a.map { x -> String in
            guard case .string(let s) = x, Identifier.isValid(s) else { throw bad(what) }
            return s
        }
    }

    static func bytes(_ v: JSONValue?, _ what: String) throws -> [UInt8] {
        guard case .string(let t)? = v, let b = try? Base64.decodeStrict(t) else { throw bad(what) }
        return b
    }

    static func decodeState(_ v: JSONValue?) throws -> SyncGroupState {
        guard case .object(let o)? = v, Set(o.keys) == stateFields else { throw bad("state") }
        guard case .string(let deviceID)? = o["device_id"],
              let identity = try? DeviceIdentity(deviceID: deviceID, signingPrivate: try bytes(o["signing"], "signing"),
                                                 exchangePrivate: try bytes(o["exchange"], "exchange")) else {
            throw bad("identity")
        }
        guard case .int(let epoch)? = o["epoch"], case .int(let membersEpoch)? = o["members_epoch"],
              case .int(let ownCounter)? = o["own_counter"], ownCounter >= 0 else { throw bad("counters") }
        let key = try bytes(o["key"], "key")
        let groupID = try text(o["group_id"], "group_id")
        // A share always holds the keyring it last accepted or wrote, and a usable key for it.
        guard (try? GroupKey(groupID: groupID, epoch: epoch, key: key)) != nil else { throw bad("key") }
        let keyring = try bytes(o["keyring"], "keyring")
        let installID = try text(o["install_id"], "install_id")
        guard !installID.isEmpty, installID.unicodeScalars.count <= FolderSync.maxInstallID else { throw bad("install_id") }
        return SyncGroupState(
            groupID: groupID, epoch: epoch, key: key, identity: identity, installID: installID, hasFolder: true,
            lastSeen: try intMap(o["last_seen"], "last_seen"), peerDigests: try textMap(o["peer_digests"], "peer_digests"),
            membersEpoch: membersEpoch, members: try ids(o["members"], "members"), keyring: keyring,
            ownCounter: ownCounter, viewSigners: try textMap(o["view_signers"], "view_signers"),
            unackedMembers: try ids(o["unacked_members"], "unacked_members"),
            peerSyncedAt: try intMap(o["peer_synced_at"], "peer_synced_at"))
    }

    static func decodeMeta(_ v: JSONValue) throws -> SyncMeta {
        guard case .object(let o) = v, Set(o.keys) == metaFields, case .bool(let deleted)? = o["deleted"],
              case .object(let vvObject)? = o["vv"] else { throw bad("meta") }
        func textField(_ k: String) throws -> String? {
            switch o[k] {
            case .null?: return nil
            case .string(let s)?: return s
            default: throw bad("meta")
            }
        }
        func intField(_ k: String) throws -> Int64? {
            switch o[k] {
            case .null?: return nil
            case .int(let n)?: return n
            default: throw bad("meta")
            }
        }
        var vv: [String: Int64] = [:]
        for (d, x) in vvObject {
            guard case .int(let n) = x, (0...VersionVector.maxCounter).contains(n) else { throw bad("meta") }
            vv[d] = n
        }
        return SyncMeta(digest: try textField("digest"), body: try textField("body"),
                        updatedAt: try intField("updated_at"), vv: vv, deleted: deleted,
                        deletedAt: try intField("deleted_at"))
    }
}
