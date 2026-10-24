/// Sealed item records (desktop `sync.group.seal_item` / `open_item`).
public enum SealedItem {
    public static let label = "lgk-sync-item-v1"
    static let nonceLength = 12
    static let tagLength = 16
    private static let fields: Set<String> = ["id", "vv", "deleted", "deleted_at", "ct"]

    static func isInt(_ v: JSONValue?) -> Bool {
        if case .int(let n)? = v { return (0...VersionVector.maxCounter).contains(n) }
        return false
    }

    static func aad(id: JSONValue, vv: JSONValue, deleted: Bool, deletedAt: JSONValue, epoch: Int64) throws -> [UInt8] {
        try CanonicalJSON.encode(.object(["label": .string(label), "id": id, "vv": vv, "deleted": .bool(deleted),
                                          "deleted_at": deletedAt, "epoch": .int(epoch)]), dialect: .utf8)
    }

    static func nonce(_ random: some RandomSource) throws -> [UInt8] {
        let n = random.bytes(count: nonceLength)
        guard n.count == nonceLength else {
            throw SyncFormatError("bad-nonce", "nonce source must return exactly \(nonceLength) bytes")
        }
        return n
    }

    /// Encrypts one state under the record key with the given nonce.
    public static func seal(_ key: GroupKey, _ state: ItemState, nonce: [UInt8]) throws -> JSONValue {
        let vv = JSONValue.object(state.vv.mapValues { .int($0) })
        let at: JSONValue = state.deletedAt.map { .int($0) } ?? .null
        let aad = try aad(id: .string(state.itemID), vv: vv, deleted: state.deleted, deletedAt: at, epoch: key.epoch)
        let plain = state.deleted ? [] : try CanonicalJSON.encode(state.item!, dialect: .utf8)
        let body = try CryptoBox.sealGCM(key: key.recordKey, nonce: nonce, plaintext: plain, aad: aad)
        return .object(["id": .string(state.itemID), "vv": vv, "deleted": .bool(state.deleted),
                        "deleted_at": at, "ct": .string(Base64.encode(nonce + body))])
    }

    /// Validates and decrypts a sealed record; reasons and their order follow the desktop.
    public static func open(_ key: GroupKey, _ sealed: JSONValue, recordKey: [UInt8]? = nil) throws -> ItemState {
        guard case .object(let o) = sealed, Set(o.keys) == fields else {
            throw SyncFormatError("bad-fields", "sealed item must have exactly id, vv, deleted, deleted_at, ct")
        }
        guard case .string(let itemID)? = o["id"], case .object(let vvRaw)? = o["vv"], case .bool(let deleted)? = o["deleted"] else {
            throw SyncFormatError("bad-fields", "id/vv/deleted types")
        }
        let deletedAtRaw = o["deleted_at"]!
        if deletedAtRaw != .null && !isInt(deletedAtRaw) { throw SyncFormatError("bad-fields", "deleted_at") }
        guard case .string(let ct)? = o["ct"] else { throw SyncFormatError("bad-fields", "ct must be a string") }
        var deletedAt: Int64?
        if case .int(let n) = deletedAtRaw { deletedAt = n }
        var vv: [String: Int64] = [:]
        for (k, v) in vvRaw {
            guard case .int(let n) = v else { throw SyncFormatError("invalid-state", "vv counter for \(k) must be an int") }
            vv[k] = n
        }
        do { _ = try ItemState(itemID: itemID, vv: vv, deleted: true, deletedAt: deletedAt, item: nil) } catch {
            throw SyncFormatError("invalid-state", "\(error)")
        }
        if ct.isEmpty { throw SyncFormatError("empty-ct", "every state needs authenticated ciphertext") }
        if !deleted && deletedAt != nil { throw SyncFormatError("invalid-state", "live item must not carry deleted_at") }
        guard let raw = try? Base64.decodeStrict(ct) else { throw SyncFormatError("bad-ct", "ciphertext is not canonical base64") }
        if raw.count < nonceLength + tagLength { throw SyncFormatError("bad-ct", "ciphertext too short") }
        let aad = try aad(id: .string(itemID), vv: .object(vvRaw), deleted: deleted, deletedAt: deletedAtRaw, epoch: key.epoch)
        let plain: [UInt8]
        do {
            plain = try CryptoBox.openGCM(key: recordKey ?? key.recordKey, nonce: Array(raw[..<nonceLength]),
                                          ciphertext: Array(raw[nonceLength...]), aad: aad)
        } catch { throw SyncFormatError("auth-failed", "item authentication failed") }
        if deleted {
            if !plain.isEmpty { throw SyncFormatError("bad-item", "tombstone plaintext must be empty") }
            return try ItemState(itemID: itemID, vv: vv, deleted: true, deletedAt: deletedAt, item: nil)
        }
        let item: JSONValue
        do { item = try CanonicalJSON.parse(plain) } catch let e as JSONError {
            // Python's json.loads accepts these; the desktop then fails them in ItemState.
            if e == .nonFinite || e == .intOutOfRange || e == .loneSurrogate {
                throw SyncFormatError("invalid-state", "item is not canonical-JSON safe")
            }
            throw SyncFormatError("bad-item", "item plaintext is not valid JSON")
        }
        guard case .object(let body) = item else { throw SyncFormatError("bad-item", "item plaintext must be an object") }
        if let id = body["id"] {
            if id != .string(itemID) { throw SyncFormatError("id-mismatch", "item id differs from sealed id") }
        } else if case .object(let record)? = body["record"], let rid = record["id"], rid != .string(itemID) {
            throw SyncFormatError("id-mismatch", "record id differs from sealed id")
        }
        do { return try ItemState(itemID: itemID, vv: vv, deleted: false, deletedAt: nil, item: item) } catch {
            throw SyncFormatError("invalid-state", "\(error)")
        }
    }
}
