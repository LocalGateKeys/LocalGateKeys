extension Keyring {
    static let topFields: Set<String> = ["format", "group_id", "epoch", "kdf", "password_wrap", "device_wraps",
                                         "members", "prev_mac", "mac"]
    static let kdfFields: Set<String> = ["name", "salt", "memory_kib", "iterations", "parallelism"]
    static let pwWrapFields: Set<String> = ["nonce", "ct"]
    static let devWrapFields: Set<String> = ["eph", "nonce", "ct"]
    static let memberFields: Set<String> = ["device_id", "name_ct", "exchange_public", "added_at"]

    /// Parse keyring bytes strictly (size, UTF-8, duplicate keys, non-finite numbers) and verify
    /// the structure (desktop `parse_keyring` followed by `verify_keyring_structure`).
    public static func parse(_ data: [UInt8]) throws -> JSONValue {
        guard data.count <= maxKeyringBytes else { throw KeyringError("too-large", "\(data.count) > \(maxKeyringBytes)") }
        let value: JSONValue
        do { value = try CanonicalJSON.parse(data) } catch { throw KeyringError("bad-json", "keyring is not valid JSON") }
        guard case .object = value else { throw KeyringError("bad-keyring", "keyring must be an object") }
        try verifyStructure(value)
        return value
    }

    static func fields(_ v: JSONValue?, _ expected: Set<String>, _ what: String) throws -> [String: JSONValue] {
        guard case .object(let o)? = v, Set(o.keys) == expected else { throw KeyringError("bad-fields", what) }
        return o
    }

    static func isInt(_ v: JSONValue?, min: Int64 = 0) -> Bool {
        guard let i = int(v) else { return false }
        return i >= min && i <= maxInt
    }

    /// Shape, bounds, KDF parameters and wrap/member sets; no authentication. Same check order as the desktop.
    static func verifyStructure(_ keyring: JSONValue) throws {
        let ring = try fields(keyring, topFields, "keyring fields")
        guard int(ring["format"]) == format else { throw KeyringError("bad-format", "unsupported keyring format") }
        guard let gid = str(ring["group_id"]), Identifier.isValid(gid) else { throw KeyringError("bad-group-id", "group_id") }
        guard isInt(ring["epoch"], min: 1), let epoch = int(ring["epoch"]) else { throw KeyringError("bad-epoch", "epoch") }

        let kdf = try fields(ring["kdf"], kdfFields, "kdf fields")
        guard str(kdf["name"]) == kdfName else { throw KeyringError("bad-kdf", "unsupported kdf") }
        for (name, want) in [("memory_kib", kdfMemoryKiB), ("iterations", kdfIterations), ("parallelism", kdfParallelism)] {
            guard int(kdf[name]) == want else { throw KeyringError("bad-kdf", "\(name) differs from the format parameters") }
        }
        _ = try b64(kdf["salt"], kdfSaltLen, "kdf salt")

        let pw = try fields(ring["password_wrap"], pwWrapFields, "password_wrap fields")
        _ = try b64(pw["nonce"], nonceLen, "password_wrap nonce")
        _ = try b64(pw["ct"], wrapCTLen, "password_wrap ct")

        guard case .array(let members)? = ring["members"], !members.isEmpty else {
            throw KeyringError("bad-members", "members must be a non-empty list")
        }
        guard members.count <= maxMembers else { throw KeyringError("too-many-members", "members must have at most 16 entries") }
        var ids = Set<String>()
        for m in members {
            let mo = try fields(m, memberFields, "member fields")
            guard let id = str(mo["device_id"]), Identifier.isValid(id) else { throw KeyringError("bad-device-id", "member device_id") }
            guard ids.insert(id).inserted else { throw KeyringError("duplicate-member", "member device ids must be unique") }
            guard (nameCTMin...nameCTMax).contains(try b64any(mo["name_ct"], "member name_ct").count) else {
                throw KeyringError("bad-name", "member name_ct must be 29..92 bytes")
            }
            guard isInt(mo["added_at"]) else { throw KeyringError("bad-fields", "member added_at") }
            _ = try b64(mo["exchange_public"], 32, "member exchange_public")
        }

        guard case .object(let wraps)? = ring["device_wraps"], Set(wraps.keys) == ids else {
            throw KeyringError("wrap-mismatch", "device_wraps must match members exactly")
        }
        for (_, wrap) in wraps.sorted(by: { $0.key < $1.key }) {
            let w = try fields(wrap, devWrapFields, "device wrap fields")
            _ = try b64(w["eph"], 32, "device wrap eph")
            _ = try b64(w["nonce"], nonceLen, "device wrap nonce")
            _ = try b64(w["ct"], wrapCTLen, "device wrap ct")
        }

        if epoch == 1 {
            guard ring["prev_mac"] == .null else { throw KeyringError("bad-fields", "prev_mac must be null at epoch 1") }
        } else if ring["prev_mac"] != .null {
            _ = try b64(ring["prev_mac"], macLen, "prev_mac")
        }
        _ = try b64(ring["mac"], macLen, "mac")
    }
}
