/// The Wi-Fi `features` message (sub-plan 07 Task 4; desktop `lan_sync`; Kotlin `LanFeatures`):
/// `{"type":"features","features":[...]}`. After a view exchange an initiator asks a peer what it reads; the peer
/// answers with its own list, or an older app answers `error` / `bad-message` (not capable). Personal collection
/// states go only to peers that listed `collections`. Vectors: `tests/vectors/share/collections/capability.json`.
///
/// `LanMessages` carries it as `.features`; the initiator asks with `LanClient.exchangeFeatures` (after the view
/// exchange, before the witness exchange) and keeps the answer in `SyncGroupState.collectionPeers` (`setPeer`); a
/// responder built with `collections` records the initiator the same way and answers with its own list, one without
/// answers `bad-message` like an older app.
public enum LanFeatures {
    public static let collections = "collections"
    public static let maxFeatures = 16
    public static let maxName = 32
    static let fields: Set<String> = ["type", "features"]
    /// What this version reads.
    public static let ours = [collections]
    /// Most peers kept in `SyncGroupState.collectionPeers` (desktop `MAX_LAN_PEERS`).
    public static let maxPeers = 16

    /// Canonical ASCII JSON of a `features` message listing `features`.
    public static func encode(_ features: [String]) throws -> [UInt8] {
        try CanonicalJSON.encode(.object(["type": .string("features"), "features": .array(features.map { .string($0) })]),
                                 dialect: .ascii)
    }

    /// The features a `features` message lists (desktop `parse_message`): `too-large` or `bad-message` otherwise.
    public static func parse(_ raw: [UInt8]) throws -> [String] {
        guard raw.count <= LanTransport.maxMessageBytes else { throw LanSyncError("too-large") }
        guard case .object(let o)? = try? CanonicalJSON.parse(raw), Set(o.keys) == fields,
              case .string(let type)? = o["type"], Array(type.utf8) == Array("features".utf8) else {
            throw LanSyncError("bad-message")
        }
        return try names(o["features"])
    }

    /// The `features` field: a list of at most 16 names of 1...32 code points, else `bad-message`.
    static func names(_ value: JSONValue?) throws -> [String] {
        guard case .array(let list)? = value, list.count <= maxFeatures else { throw LanSyncError("bad-message") }
        return try list.map { v in
            guard case .string(let s) = v, (1...maxName).contains(s.unicodeScalars.count) else {
                throw LanSyncError("bad-message")
            }
            return s
        }
    }

    /// Whether a peer's list names `collections` (compared as bytes).
    public static func readsCollections(_ features: [String]) -> Bool {
        features.contains { Array($0.utf8) == Array(collections.utf8) }
    }

    /// `collectionPeers` with `peer` added or removed (sorted, bounded); nil when nothing changes.
    public static func peers(_ current: [String], setting peer: String, capable: Bool) -> [String]? {
        var set = Set(current)
        if capable {
            guard !set.contains(peer), set.count < maxPeers, Identifier.isValid(peer) else { return nil }
            set.insert(peer)
        } else {
            guard set.remove(peer) != nil else { return nil }
        }
        return set.sorted()
    }

    /// Records a peer's answer in the group state (desktop `set_collection_peer`): one commit, only when the list
    /// changes. True: saved; false: nothing to change; nil: not saved (the store could not be read or written, or a
    /// new peer past `maxPeers`). A responder answers nil with `local-data`, so the initiator records nothing and asks
    /// again (desktop: the failed save raises inside `_serve`).
    @discardableResult
    public static func setPeer(_ peer: String, capable: Bool, store: any ItemStore) -> Bool? {
        guard let snap = try? store.load(), var state = snap.sync else { return nil }
        if capable && !state.collectionPeers.contains(peer)
            && (state.collectionPeers.count >= maxPeers || !Identifier.isValid(peer)) { return nil }
        guard let next = peers(state.collectionPeers, setting: peer, capable: capable) else { return false }
        state.collectionPeers = next
        do {
            try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: state))
        } catch {
            return nil
        }
        return true
    }
}
