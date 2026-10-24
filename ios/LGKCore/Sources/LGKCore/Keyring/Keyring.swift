import Crypto

/// A keyring error; `reason` is the desktop `KeyringError.reason` string.
public struct KeyringError: Error, Equatable, Sendable, CustomStringConvertible {
    public let reason: String
    public let detail: String
    public init(_ reason: String, _ detail: String = "") { self.reason = reason; self.detail = detail }
    public var description: String { detail.isEmpty ? reason : "\(reason): \(detail)" }
}

/// Password- and device-wrapped group keyring (desktop `localvault.sync.keyring`, format 1).
/// Keyrings are handled as `JSONValue` so an untouched keyring re-encodes byte-identically.
public enum Keyring {
    static let format: Int64 = 1
    static let kdfName = "argon2id"
    static let kdfMemoryKiB: Int64 = 131072
    static let kdfIterations: Int64 = 4
    static let kdfParallelism: Int64 = 4
    static let kdfSaltLen = 16
    static let maxMembers = 16
    static let maxKeyringBytes = 256 * 1024
    static let maxNameLen = 64
    static let nonceLen = 12
    static let keyLen = 32
    static let wrapCTLen = 48
    static let macLen = 32
    static let nameCTMin = 12 + 1 + 16
    static let nameCTMax = 12 + 64 + 16
    static let maxInt: Int64 = (1 << 53) - 1

    static let passwordAAD = Array("lgk-keyring-password-wrap-v1|".utf8)
    static let deviceAAD = Array("lgk-keyring-device-wrap-v1|".utf8)
    static let deviceInfo = Array("localgatekeys|sync|device-wrap|v1|".utf8)
    static let macInfo = Array("localgatekeys|sync|keyring-mac|v1|".utf8)
    static let nameAAD = Array("lgk-keyring-member-name-v1|".utf8)
    static let nameInfo = Array("localgatekeys|sync|member-name|v1|".utf8)

    // MARK: JSON access (only on structurally verified keyrings unless noted)

    static func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
    static func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { return a }; return [] }
    static func str(_ v: JSONValue?) -> String? { if case .string(let s)? = v { return s }; return nil }
    static func int(_ v: JSONValue?) -> Int64? { if case .int(let i)? = v { return i }; return nil }

    // MARK: base64

    static func b64any(_ v: JSONValue?, _ what: String) throws -> [UInt8] {
        guard let s = str(v), let raw = try? Base64.decodeStrict(s) else { throw KeyringError("bad-base64", what) }
        return raw
    }

    static func b64(_ v: JSONValue?, _ length: Int, _ what: String) throws -> [UInt8] {
        let raw = try b64any(v, what)
        guard raw.count == length else { throw KeyringError("bad-length", what) }
        return raw
    }

    // MARK: derivations

    static func epochBytes(_ e: Int64) -> [UInt8] { Array(String(e).utf8) }
    static let bar: [UInt8] = [0x7C]

    static func passwordAAD(_ groupID: String, _ epoch: Int64) -> [UInt8] {
        passwordAAD + Array(groupID.utf8) + bar + epochBytes(epoch)
    }

    static func deviceAAD(_ groupID: String, _ epoch: Int64, _ deviceID: String) -> [UInt8] {
        deviceAAD + Array(groupID.utf8) + bar + epochBytes(epoch) + bar + Array(deviceID.utf8)
    }

    static func deviceKey(shared: [UInt8], groupID: String, deviceID: String) -> [UInt8] {
        CryptoBox.hkdf(ikm: shared, salt: Array(groupID.utf8), info: deviceInfo + Array(deviceID.utf8), length: keyLen)
    }

    static func macKey(_ gk: GroupKey) -> [UInt8] {
        CryptoBox.hkdf(ikm: gk.key, salt: Array(gk.groupID.utf8), info: macInfo + epochBytes(gk.epoch), length: keyLen)
    }

    static func hmac(_ key: [UInt8], _ message: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var d: UInt8 = 0
        for i in 0..<a.count { d |= a[i] ^ b[i] }
        return d == 0
    }

    /// HMAC over canonical JSON of the keyring without `mac`.
    static func mac(_ ring: [String: JSONValue], key gk: GroupKey) throws -> [UInt8] {
        var body = ring; body["mac"] = nil
        return hmac(macKey(gk), try CanonicalJSON.encode(.object(body), dialect: .utf8))
    }

    /// `prev_mac`: the old epoch's key commits to the new epoch's MAC key.
    static func chainMac(old: GroupKey, new: GroupKey) -> [UInt8] {
        let commitment = lowerHex(Array(SHA256.hash(data: macKey(new))))
        let message = Array("rotate|".utf8) + Array(new.groupID.utf8) + bar + epochBytes(new.epoch) + bar + Array(commitment.utf8)
        return hmac(macKey(old), message)
    }

    static func macOK(_ ring: JSONValue, key gk: GroupKey) -> Bool {
        let o = obj(ring)
        guard let given = try? b64(o["mac"], macLen, "mac"), let want = try? mac(o, key: gk) else { return false }
        return constantTimeEqual(given, want)
    }

    static func chainOK(_ value: JSONValue?, old: GroupKey, new: GroupKey) -> Bool {
        guard let given = try? b64(value, macLen, "prev_mac") else { return false }
        return constantTimeEqual(given, chainMac(old: old, new: new))
    }

    /// Body with `prev_mac` carried over and `mac` recomputed under `gk`.
    static func finish(_ body: [String: JSONValue], key gk: GroupKey) throws -> JSONValue {
        var out = body; out["mac"] = nil
        out["mac"] = .string(Base64.encode(try mac(out, key: gk)))
        return .object(out)
    }

    static func groupKey(_ groupID: String, _ epoch: Int64, _ key: [UInt8]) throws -> GroupKey {
        do { return try GroupKey(groupID: groupID, epoch: epoch, key: key) } catch {
            throw KeyringError("bad-group-key", "\(error)")
        }
    }

    // MARK: password wrap

    static func argon2(_ password: String, salt: [UInt8], kdf: [String: JSONValue]) throws -> [UInt8] {
        guard let mem = int(kdf["memory_kib"]), let its = int(kdf["iterations"]), let par = int(kdf["parallelism"]),
              let m = UInt32(exactly: mem), let i = UInt32(exactly: its), let p = UInt32(exactly: par)
        else { throw KeyringError("bad-kdf", "kdf parameters") }
        do {
            return try Argon2id.derive(password: Array(password.utf8), salt: salt, memoryKiB: m,
                                       iterations: i, parallelism: p, length: keyLen)
        } catch { throw KeyringError("bad-kdf", "argon2id failed") }
    }

    /// The Argon2id key for `password` with the keyring's salt and kdf parameters.
    static func passwordKey(_ ring: JSONValue, password: String) throws -> [UInt8] {
        let kdf = obj(obj(ring)["kdf"])
        return try argon2(password, salt: try b64(kdf["salt"], kdfSaltLen, "kdf salt"), kdf: kdf)
    }

    /// Open the password wrap with an already derived Argon2id key (structure must be verified).
    static func unwrap(_ ring: JSONValue, passwordKey key: [UInt8]) throws -> GroupKey {
        let o = obj(ring), pw = obj(o["password_wrap"])
        guard let gid = str(o["group_id"]), let epoch = int(o["epoch"]) else { throw KeyringError("bad-fields", "keyring") }
        let plain: [UInt8]
        do {
            plain = try CryptoBox.openGCM(key: key, nonce: try b64(pw["nonce"], nonceLen, "nonce"),
                                          ciphertext: try b64(pw["ct"], wrapCTLen, "ct"), aad: passwordAAD(gid, epoch))
        } catch let e as KeyringError { throw e } catch {
            throw KeyringError("password", "wrong sync password or damaged keyring")
        }
        return try groupKey(gid, epoch, plain)
    }

    /// Open the password wrap (Argon2id with the keyring's kdf block). Verifies structure first.
    public static func unwrapWithPassword(_ ring: JSONValue, password: String) throws -> GroupKey {
        try verifyStructure(ring)
        return try unwrap(ring, passwordKey: try passwordKey(ring, password: password))
    }

    // MARK: device wrap

    static func member(_ ring: JSONValue, _ identity: DeviceIdentity) throws -> [String: JSONValue] {
        for m in arr(obj(ring)["members"]) {
            let mo = obj(m)
            if str(mo["device_id"]) == identity.deviceID {
                guard str(mo["exchange_public"]) == Base64.encode(identity.exchangePublicKey) else {
                    throw KeyringError("key-mismatch", "device key differs from the registered member")
                }
                return mo
            }
        }
        throw KeyringError("not-member", "device is not a member of this keyring")
    }

    /// Open this device's wrap (structure must be verified): `not-member`, `key-mismatch`, `device-wrap`.
    static func unwrapDevice(_ ring: JSONValue, identity: DeviceIdentity) throws -> GroupKey {
        _ = try member(ring, identity)
        let o = obj(ring)
        let wrap = obj(obj(o["device_wraps"])[identity.deviceID])
        guard let gid = str(o["group_id"]), let epoch = int(o["epoch"]) else { throw KeyringError("bad-fields", "keyring") }
        let plain: [UInt8]
        do {
            let shared = try identity.exchange(with: try b64(wrap["eph"], 32, "eph"))
            plain = try CryptoBox.openGCM(key: deviceKey(shared: shared, groupID: gid, deviceID: identity.deviceID),
                                          nonce: try b64(wrap["nonce"], nonceLen, "nonce"),
                                          ciphertext: try b64(wrap["ct"], wrapCTLen, "ct"),
                                          aad: deviceAAD(gid, epoch, identity.deviceID))
        } catch let e as KeyringError { throw e } catch {
            throw KeyringError("device-wrap", "device wrap cannot be opened")
        }
        return try groupKey(gid, epoch, plain)
    }

    /// (eph, nonce, ct) wrap of `gk` to `exchangePublic`. Draws eph (32) then nonce (12).
    static func wrapDevice(_ gk: GroupKey, deviceID: String, exchangePublic: [UInt8], random: RandomSource) throws -> JSONValue {
        let ephRaw = try draw(random, 32)
        let ephPublic: [UInt8]
        let shared: [UInt8]
        do {
            let eph = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ephRaw)
            let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: exchangePublic)
            shared = try eph.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Array($0) }
            ephPublic = Array(eph.publicKey.rawRepresentation)
        } catch { throw KeyringError("bad-member-key", "exchange key unusable") }
        guard shared.contains(where: { $0 != 0 }) else { throw KeyringError("bad-member-key", "exchange key unusable") }
        let nonce = try draw(random, nonceLen)
        let ct = try CryptoBox.sealGCM(key: deviceKey(shared: shared, groupID: gk.groupID, deviceID: deviceID),
                                       nonce: nonce, plaintext: gk.key, aad: deviceAAD(gk.groupID, gk.epoch, deviceID))
        return .object(["eph": .string(Base64.encode(ephPublic)),
                        "nonce": .string(Base64.encode(nonce)), "ct": .string(Base64.encode(ct))])
    }

    static func draw(_ random: RandomSource, _ n: Int) throws -> [UInt8] {
        let raw = random.bytes(count: n)
        guard raw.count == n else { throw KeyringError("bad-random", "random source must return exactly \(n) bytes") }
        return raw
    }
}
