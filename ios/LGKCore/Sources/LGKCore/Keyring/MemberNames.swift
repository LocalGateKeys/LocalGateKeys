extension Keyring {
    static func nameKey(_ gk: GroupKey) -> [UInt8] {
        CryptoBox.hkdf(ikm: gk.key, salt: Array(gk.groupID.utf8), info: nameInfo + epochBytes(gk.epoch), length: keyLen)
    }

    static func nameAAD(_ groupID: String, _ epoch: Int64, _ deviceID: String) -> [UInt8] {
        nameAAD + Array(groupID.utf8) + bar + epochBytes(epoch) + bar + Array(deviceID.utf8)
    }

    /// 1..64 UTF-8 bytes.
    static func checkName(_ name: String) throws -> String {
        guard (1...maxNameLen).contains(name.utf8.count) else {
            throw KeyringError("bad-name", "device name must be 1..64 UTF-8 bytes")
        }
        return name
    }

    /// Strict UTF-8 decode (rejects overlongs, surrogates, truncation), like Python's `bytes.decode("utf-8")`.
    static func strictUTF8(_ bytes: [UInt8]) -> String? {
        var it = bytes.makeIterator()
        var dec = UTF8()
        var out = String.UnicodeScalarView()
        while true {
            switch dec.decode(&it) {
            case .scalarValue(let s): out.append(s)
            case .emptyInput: return String(out)
            case .error: return nil
            }
        }
    }

    /// `name_ct` for `deviceID` at `gk`'s epoch. Draws the 12-byte nonce.
    static func sealName(_ gk: GroupKey, deviceID: String, name: String, random: RandomSource) throws -> String {
        let nonce = try draw(random, nonceLen)
        let ct = try CryptoBox.sealGCM(key: nameKey(gk), nonce: nonce, plaintext: Array(name.utf8),
                                       aad: nameAAD(gk.groupID, gk.epoch, deviceID))
        return Base64.encode(nonce + ct)
    }

    static func openName(key: [UInt8], gk: GroupKey, deviceID: JSONValue?, value: JSONValue?) -> String? {
        guard let id = str(deviceID), Identifier.isValid(id),
              let raw = try? b64any(value, "member name_ct"), (nameCTMin...nameCTMax).contains(raw.count),
              let plain = try? CryptoBox.openGCM(key: key, nonce: Array(raw[0..<nonceLen]),
                                                 ciphertext: Array(raw[nonceLen...]), aad: nameAAD(gk.groupID, gk.epoch, id)),
              let name = strictUTF8(plain)
        else { return nil }
        return try? checkName(name)
    }

    /// Decrypt every member's name: `[device_id: name]`, nil for a name that cannot be read.
    /// Call ONLY on a keyring already accepted under `key`; it does not authenticate the keyring.
    public static func memberNames(_ ring: JSONValue, key: GroupKey) -> [String: String?] {
        let k = nameKey(key)
        var out: [String: String?] = [:]
        for m in arr(obj(ring)["members"]) {
            let mo = obj(m)
            guard let id = str(mo["device_id"]) else { continue }
            out[id] = .some(openName(key: k, gk: key, deviceID: mo["device_id"], value: mo["name_ct"]))
        }
        return out
    }
}
