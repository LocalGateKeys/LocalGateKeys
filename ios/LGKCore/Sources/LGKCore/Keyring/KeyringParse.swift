extension Keyring {
    static let topFields: Set<String> = ["format", "group_id", "epoch", "kdf", "password_wrap", "device_wraps",
                                         "members", "prev_mac", "mac"]
    static let kdfFields: Set<String> = ["name", "salt", "memory_kib", "iterations", "parallelism"]
    static let pwWrapFields: Set<String> = ["nonce", "ct"]
    static let devWrapFields: Set<String> = ["eph", "nonce", "ct"]
    /// Member fields of format 1, and of format 2 (with the member's signing key and proof).
    static let memberFieldsV1: Set<String> = ["device_id", "name_ct", "exchange_public", "added_at"]
    static let memberFields: Set<String> = memberFieldsV1.union(["signing_public", "signing_proof"])
    /// The top-level fields only a share keyring has (sub-plan 07, desktop `_SHARE_TOP_FIELDS`).
    static let shareTopFields: Set<String> = ["metadata", "owner_sig"]

    /// Parse keyring bytes strictly (size, UTF-8, duplicate keys, non-finite numbers) and verify
    /// the structure (desktop `parse_keyring` followed by `verify_keyring_structure`). `share`: a share keyring
    /// (metadata and owner signature) is accepted; without it one is refused as `share-group` (a device-sync flow
    /// must never adopt a shared collection's keyring, desktop `join_folder_group`).
    public static func parse(_ data: [UInt8], share: Bool = false) throws -> JSONValue {
        guard data.count <= maxKeyringBytes else { throw KeyringError("too-large", "\(data.count) > \(maxKeyringBytes)") }
        let value: JSONValue
        do { value = try CanonicalJSON.parse(data) } catch { throw KeyringError("bad-json", "keyring is not valid JSON") }
        guard case .object = value else { throw KeyringError("bad-keyring", "keyring must be an object") }
        try verifyStructure(value, share: share)
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

    /// Whether `keyring` carries a share field (desktop: `_SHARE_TOP_FIELDS & set(keyring)`).
    static func isShare(_ keyring: JSONValue) -> Bool {
        guard case .object(let o) = keyring else { return false }
        return o.keys.contains { shareTopFields.contains($0) }
    }

    /// Shape, bounds, KDF parameters and wrap/member sets; no authentication. Same check order as the desktop.
    /// A share keyring (`share` true) also has its `metadata` checked and its `owner_sig` verified (the last step);
    /// with `share` false it is refused as `share-group` before anything else.
    static func verifyStructure(_ keyring: JSONValue, share: Bool = false) throws {
        // A later app version's keyring is said apart before anything else (desktop: the first check).
        if case .object(let top) = keyring, let f = int(top["format"]), f > newestFormat {
            throw KeyringError("newer-format", "this keyring needs a newer version of the app")
        }
        let shareRing = isShare(keyring)
        if shareRing && !share { throw KeyringError("share-group", "this keyring belongs to a shared collection") }
        // Format 3 (share v2) has one more top-level field, `content`.
        var v2 = false
        if case .object(let top) = keyring, int(top["format"]) == shareFormat { v2 = true }
        var expected = shareRing ? topFields.union(shareTopFields) : topFields
        if v2 { expected.insert("content") }
        let ring = try fields(keyring, expected, "keyring fields")
        guard let ringFormat = int(ring["format"]), readFormats.contains(ringFormat) else {
            throw KeyringError("bad-format", "unsupported keyring format")
        }
        if v2 && !shareRing { throw KeyringError("bad-fields", "a format-3 keyring is a share keyring") }
        if shareRing {
            guard ringFormat >= 2 else { throw KeyringError("bad-fields", "a format-1 keyring has no share fields") }
            _ = try ShareKeyring.checkMetadata(ring["metadata"])
        }
        let memberSet = ringFormat >= 2 ? memberFields : memberFieldsV1
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
            let mo = try fields(m, memberSet, "member fields")
            guard let id = str(mo["device_id"]), Identifier.isValid(id) else { throw KeyringError("bad-device-id", "member device_id") }
            guard ids.insert(id).inserted else { throw KeyringError("duplicate-member", "member device ids must be unique") }
            guard (nameCTMin...nameCTMax).contains(try b64any(mo["name_ct"], "member name_ct").count) else {
                throw KeyringError("bad-name", "member name_ct must be 29..92 bytes")
            }
            guard isInt(mo["added_at"]) else { throw KeyringError("bad-fields", "member added_at") }
            _ = try b64(mo["exchange_public"], 32, "member exchange_public")
            if ringFormat >= 2 { try checkMemberProof(groupID: gid, mo) }
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
        if v2 { try ShareKeyring.checkContentShape(ring["content"]) }
        if shareRing { try ShareKeyring.checkOwnerSig(keyring) }
    }
}
