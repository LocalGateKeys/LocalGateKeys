import Crypto
import Foundation

/// A refused backup-key step (design `docs/design/backup-public-key-2026-10-31.md`, Windows `backup_key.py`).
/// Never carries a password, a private key or a phrase. Wrong passwords and failed unwraps are
/// `FullBackupError.wrongPasswordOrModified`, password lengths `.passwordLength` and KDF bounds
/// `.unsupportedEncryption`, as in full backup v2.
public struct BackupKeyError: Error, Equatable, Sendable, CustomStringConvertible {
    public let message: String
    /// The English reason of a damaged record or authority (pinned by the vectors), nil otherwise.
    public let reason: String?

    init(_ message: String, reason: String? = nil) { self.message = message; self.reason = reason }
    public var description: String { message }

    /// Section 3.3: the stored record is not one this code wrote. Scheduled backups skip; the page offers a new one.
    public static func damagedRecord(_ reason: String) -> BackupKeyError {
        BackupKeyError(String(localized: "The backup key record is damaged: \(reason)", bundle: .module), reason: reason)
    }

    public static func damagedAuthority(_ reason: String) -> BackupKeyError {
        BackupKeyError(String(localized: "The reset authority is damaged: \(reason)", bundle: .module), reason: reason)
    }

    /// Proof (a) failed: the typed password does not derive the record's public key (section 7.1).
    public static var notCurrentPassword: BackupKeyError {
        BackupKeyError(String(localized: "That is not the current backup password.", bundle: .module))
    }

    /// A wrap to a low-order or malformed public key (all-zero shared secret).
    public static var unusablePublicKey: BackupKeyError {
        BackupKeyError(String(localized: "The backup public key is not usable", bundle: .module))
    }
}

/// The `kdf` object of a backup key record and of a v3 header's recipient (section 3.2): Argon2id parameters plus a
/// 16-byte salt, exactly five keys `name`, `time_cost`, `memory_cost_kib`, `parallelism`, `salt`.
public struct BackupKeyKDF: Equatable, Sendable {
    /// Windows `BACKUP_KDF` for new keys (3 / 262144 KiB / 4). Readers accept `FullBackupV2.KDF` bounds.
    public static let defaultParameters = FullBackupV2.KDF(timeCost: 3, memoryKiB: 262_144, parallelism: 4)
    static let fields: Set<String> = ["name", "time_cost", "memory_cost_kib", "parallelism", "salt"]

    public let parameters: FullBackupV2.KDF
    public let salt: [UInt8]

    public init(parameters: FullBackupV2.KDF, salt: [UInt8]) throws {
        guard parameters.isAccepted, salt.count == 16 else { throw FullBackupError.unsupportedEncryption }
        self.parameters = parameters; self.salt = salt
    }

    /// A fresh salt (every set, change, reset and migration).
    public static func fresh(_ parameters: FullBackupV2.KDF = defaultParameters, random: any RandomSource) throws -> BackupKeyKDF {
        try BackupKeyKDF(parameters: parameters, salt: random.bytes(count: 16))
    }

    public var json: JSONValue {
        .object([
            "name": .string("argon2id"), "time_cost": .int(Int64(parameters.timeCost)),
            "memory_cost_kib": .int(Int64(parameters.memoryKiB)), "parallelism": .int(Int64(parameters.parallelism)),
            "salt": .string(Base64.encode(salt)),
        ])
    }

    /// Strict (`backup_key.parse_kdf`): exactly the five keys, ints within the bounds, canonical base64 salt of 16 bytes.
    public static func parse(_ value: JSONValue?) throws -> BackupKeyKDF {
        guard case .object(let o)? = value, Set(o.keys) == fields, case .string("argon2id")? = o["name"],
              case .int(let t)? = o["time_cost"], case .int(let m)? = o["memory_cost_kib"], case .int(let p)? = o["parallelism"],
              let t32 = UInt32(exactly: t), let m32 = UInt32(exactly: m), let p32 = UInt32(exactly: p),
              case .string(let text)? = o["salt"], let salt = try? Base64.decodeStrict(text), salt.count == 16 else {
            throw FullBackupError.unsupportedEncryption
        }
        return try BackupKeyKDF(parameters: FullBackupV2.KDF(timeCost: t32, memoryKiB: m32, parallelism: p32), salt: salt)
    }
}

/// A key pair derived from a backup password. `privateKey` is clamped; `wipe()` it when done.
public struct BackupKeyPair: Sendable {
    public private(set) var privateKey: [UInt8]
    public let publicKey: [UInt8]
    public let keyID: String
    public let kdf: BackupKeyKDF

    init(privateKey: [UInt8], publicKey: [UInt8], keyID: String, kdf: BackupKeyKDF) {
        self.privateKey = privateKey; self.publicKey = publicKey; self.keyID = keyID; self.kdf = kdf
    }

    public mutating func wipe() { for i in privateKey.indices { privateKey[i] = 0 } }
}

/// Sections 3.2 and 3.4 (one data key): the X25519 backup key from the backup password, its key id, and the wrap of
/// a data key to it with an ephemeral X25519 exchange, HKDF-SHA256 and AES-256-GCM. Byte-exact with Windows
/// `backup_key.py`; pinned by `tests/vectors/backup/v3`. No clock is read here.
public enum BackupKey {
    static let keyInfo = Array("localgatekeys|backup-key|x25519|v1".utf8)
    static let keyIDPrefix = Array("localgatekeys|backup-key-id|v1|".utf8)
    static let wrapInfo = Array("localgatekeys|backup-wrap|v1".utf8)
    static let wrapAADPrefix = Array("localgatekeys|backup-recipient|v1|".utf8)
    public static let scheme = "x25519-hkdf-sha256-aes-256-gcm-v1"
    /// An "absent" HKDF salt is 32 zero bytes (RFC 5869, Python `salt=None`), passed explicitly.
    static let zeroSalt = [UInt8](repeating: 0, count: 32)
    /// The KEK is unique per file (fresh ephemeral key), so the wrap nonce is fixed.
    static let wrapNonce = [UInt8](repeating: 0, count: 12)
    public static let keyBytes = 32
    public static let wrappedBytes = 48
    public static let passwordLengths = 12...4096

    /// Python `len(password)`: Unicode scalars, not grapheme clusters.
    public static func validLength(_ password: String) -> Bool { passwordLengths.contains(password.unicodeScalars.count) }

    /// RFC 7748 clamping, done explicitly so the vector value of a private key is the same everywhere.
    public static func clamp(_ raw: [UInt8]) throws -> [UInt8] {
        guard raw.count == keyBytes else { throw FullBackupError.invalid("An X25519 private key is 32 bytes") }
        var key = raw
        key[0] &= 0xF8
        key[31] &= 0x7F
        key[31] |= 0x40
        return key
    }

    static func publicKey(of privateKey: [UInt8]) throws -> [UInt8] {
        guard privateKey.count == keyBytes,
              let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey) else {
            throw FullBackupError.invalid("An X25519 private key is 32 bytes")
        }
        return Array(key.publicKey.rawRepresentation)
    }

    /// X25519; nil for a malformed key or an all-zero result (a low-order peer key).
    static func sharedSecret(_ privateKey: [UInt8], _ peerPublic: [UInt8]) -> [UInt8]? {
        guard privateKey.count == keyBytes, peerPublic.count == keyBytes,
              let priv = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey),
              let peer = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublic),
              let shared = try? priv.sharedSecretFromKeyAgreement(with: peer) else { return nil }
        var raw = shared.withUnsafeBytes { Array($0) }
        guard raw.count == keyBytes, raw.contains(where: { $0 != 0 }) else { wipe(&raw); return nil }
        return raw
    }

    /// `hex(SHA-256("localgatekeys|backup-key-id|v1|" || pk)[0:16])`: 32 lowercase hex characters.
    public static func keyID(_ publicKey: [UInt8]) throws -> String {
        guard publicKey.count == keyBytes else { throw BackupKeyError.unusablePublicKey }
        return lowerHex(Array(SHA256.hash(data: keyIDPrefix + publicKey)).prefix(16))
    }

    /// `^[0-9a-f]{32}$`.
    public static func isKeyID(_ text: String) -> Bool {
        let u = Array(text.utf8)
        return u.count == 32 && u.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    /// `(seed, sk_raw, sk)` of section 3.2 (the vectors pin all three). Callers wipe them.
    static func deriveParts(password: String, kdf: BackupKeyKDF) throws -> (seed: [UInt8], skRaw: [UInt8], sk: [UInt8]) {
        // 12-4096 scalars, UTF-8 as typed (no normalisation), the same check and Argon2id call as full backup v2.
        var seed = try FullBackupV2.derive(password, salt: kdf.salt, kdf: kdf.parameters)
        var skRaw = CryptoBox.hkdf(ikm: seed, salt: zeroSalt, info: keyInfo, length: keyBytes)
        do {
            return (seed, skRaw, try clamp(skRaw))
        } catch {
            wipe(&seed); wipe(&skRaw)
            throw error
        }
    }

    /// The key pair for `password` under `kdf` (a fresh one, a record's or a v3 header's).
    public static func derive(password: String, kdf: BackupKeyKDF) throws -> BackupKeyPair {
        var (seed, skRaw, sk) = try deriveParts(password: password, kdf: kdf)
        wipe(&seed); wipe(&skRaw)
        do {
            let pk = try publicKey(of: sk)
            return BackupKeyPair(privateKey: sk, publicKey: pk, keyID: try keyID(pk), kdf: kdf)
        } catch {
            wipe(&sk)
            throw error
        }
    }

    // MARK: wrap (3.4)

    /// `"localgatekeys|backup-recipient|v1|" || canon({"header": core, "recipient": rcpt_body})`: `core` is the v3
    /// header without `recipient`, `recipientBody` the recipient without `wrapped_key`.
    public static func wrapAAD(core: [String: JSONValue], recipientBody: [String: JSONValue]) throws -> [UInt8] {
        guard core["recipient"] == nil, recipientBody["wrapped_key"] == nil else {
            throw FullBackupError.invalid("The wrap AAD takes the header and recipient without the wrap")
        }
        return wrapAADPrefix + (try CanonicalJSON.encode(.object(["header": .object(core), "recipient": .object(recipientBody)]),
                                                         dialect: .utf8))
    }

    /// `esk` (clamped; wiped after the writer's self-verify, section 9.1) and `epk = X25519(esk, 9)`.
    public struct EphemeralKey: Sendable {
        public private(set) var secret: [UInt8]
        public let publicKey: [UInt8]
        init(secret: [UInt8], publicKey: [UInt8]) { self.secret = secret; self.publicKey = publicKey }
        public mutating func wipe() { BackupKey.wipe(&secret) }
    }

    /// `raw` (32 bytes) clamped as in 3.2.
    public static func ephemeral(raw: [UInt8]) throws -> EphemeralKey {
        let secret = try clamp(raw)
        return EphemeralKey(secret: secret, publicKey: try publicKey(of: secret))
    }

    /// 32 bytes drawn from `random`, clamped.
    public static func newEphemeral(random: any RandomSource) throws -> EphemeralKey {
        var raw = random.bytes(count: keyBytes)
        defer { wipe(&raw) }
        guard raw.count == keyBytes else { throw FullBackupError.invalid("The random source returned too few bytes") }
        return try ephemeral(raw: raw)
    }

    /// `kek = HKDF(ikm = ss, salt = epk || pk, info = "localgatekeys|backup-wrap|v1")`.
    static func kek(shared: [UInt8], ephemeralPublic: [UInt8], publicKey: [UInt8]) -> [UInt8] {
        CryptoBox.hkdf(ikm: shared, salt: ephemeralPublic + publicKey, info: wrapInfo, length: keyBytes)
    }

    /// `AES-256-GCM(kek, 12 zero bytes, dk, aad)`: 48 bytes. A low-order `publicKey` is refused (`unusablePublicKey`).
    public static func wrap(dataKey: [UInt8], publicKey: [UInt8], ephemeral: EphemeralKey, aad: [UInt8]) throws -> [UInt8] {
        guard dataKey.count == keyBytes else { throw FullBackupError.invalid("A backup data key is 32 bytes") }
        guard publicKey.count == keyBytes, var shared = sharedSecret(ephemeral.secret, publicKey) else {
            throw BackupKeyError.unusablePublicKey
        }
        var key = kek(shared: shared, ephemeralPublic: ephemeral.publicKey, publicKey: publicKey)
        defer { wipe(&shared); wipe(&key) }
        return try CryptoBox.sealGCM(key: key, nonce: wrapNonce, plaintext: dataKey, aad: aad)
    }

    /// Opens a wrap with the (clamped) private key. Every failure is `wrongPasswordOrModified`.
    public static func unwrap(privateKey: [UInt8], ephemeralPublic: [UInt8], wrapped: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        let wrong = FullBackupError.wrongPasswordOrModified
        guard privateKey.count == keyBytes, ephemeralPublic.count == keyBytes, wrapped.count == wrappedBytes,
              var shared = sharedSecret(privateKey, ephemeralPublic), let own = try? publicKey(of: privateKey) else { throw wrong }
        var key = kek(shared: shared, ephemeralPublic: ephemeralPublic, publicKey: own)
        defer { wipe(&shared); wipe(&key) }
        do { return try CryptoBox.openGCM(key: key, nonce: wrapNonce, ciphertext: wrapped, aad: aad) } catch { throw wrong }
    }

    /// The reader's order (3.4): Argon2 → key id check (no GCM attempt on a mismatch) → unwrap. A password outside
    /// 12-4096 characters is `passwordLength`, as v2.
    public static func unwrap(password: String, kdf: BackupKeyKDF, expectedKeyID: String, ephemeralPublic: [UInt8],
                              wrapped: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        var key = try derive(password: password, kdf: kdf)
        defer { key.wipe() }
        guard constantTimeEqual(Array(key.keyID.utf8), Array(expectedKeyID.utf8)) else { throw FullBackupError.wrongPasswordOrModified }
        return try unwrap(privateKey: key.privateKey, ephemeralPublic: ephemeralPublic, wrapped: wrapped, aad: aad)
    }

    static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var d: UInt8 = 0
        for i in 0..<a.count { d |= a[i] ^ b[i] }
        return d == 0
    }

    static func wipe(_ b: inout [UInt8]) { for i in b.indices { b[i] = 0 } }
}

/// Section 3.6: the proof, later, that a typed recovery phrase was the one active when the backup key was set.
/// Two kinds: `recovery-wrapper-v1` (Windows, a frozen copy of the vault's recovery wrapper) and
/// `recovery-key-mac-v1` (Mac, an HMAC under the phrase's vault key, bound to the record's key id). Both verify here.
public enum ResetAuthority {
    public static let wrapperKind = "recovery-wrapper-v1"
    public static let macKind = "recovery-key-mac-v1"
    static let macPrefix = Array("localgatekeys|backup-reset-authority|v1|".utf8)
    static let wrapperFields: Set<String> = ["kind", "salt", "nonce", "ciphertext", "aad"]
    static let macFields: Set<String> = ["kind", "salt", "mac"]
    static let maxAADBytes = 4096

    /// `K(s) = HKDF(ikm = entropy, salt = s, info = "localgatekeys|recovery-key|v1")` (`RecoveryWrapper.derive`).
    public static func phraseKey(entropy: [UInt8], salt: [UInt8]) throws -> [UInt8] {
        guard entropy.count == 32, salt.count == 16 else {
            throw FullBackupError.invalid("A recovery phrase key needs 32 bytes of entropy and a 16-byte salt")
        }
        return CryptoBox.hkdf(ikm: entropy, salt: salt, info: RecoveryWrapper.info, length: 32)
    }

    static func mac(_ key: [UInt8], keyID: String) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: macPrefix + Array(keyID.utf8), using: SymmetricKey(data: key)))
    }

    /// Mac: `{"kind", "salt": VaultKey.salt, "mac": HMAC-SHA256(VaultKey.key, prefix || key_id)}`.
    public static func captureMac(salt: [UInt8], recoveryKey: [UInt8], keyID: String) throws -> JSONValue {
        guard salt.count == 16, recoveryKey.count == 32, BackupKey.isKeyID(keyID) else {
            throw FullBackupError.invalid("A Mac reset authority needs the 16-byte salt, the 32-byte key and a key id")
        }
        return .object(["kind": .string(macKind), "salt": .string(Base64.encode(salt)),
                        "mac": .string(Base64.encode(mac(recoveryKey, keyID: keyID)))])
    }

    /// The current phrase's authority for `keyID` (nil without a phrase).
    public static func captureMac(_ vaultKey: RecoveryWrapper.VaultKey?, keyID: String) throws -> JSONValue? {
        guard let vaultKey else { return nil }
        return try captureMac(salt: vaultKey.salt, recoveryKey: vaultKey.key, keyID: keyID)
    }

    /// Strict shape check of either kind (`validate_authority`); `damagedAuthority` with the Windows reason.
    @discardableResult
    public static func validate(_ value: JSONValue?) throws -> [String: JSONValue] {
        guard case .object(let o)? = value else { throw BackupKeyError.damagedAuthority("not an object") }
        let fields: Set<String>
        let sizes: [(String, Int)]
        switch o["kind"] {
        case .string(wrapperKind)?: fields = wrapperFields; sizes = [("salt", 16), ("nonce", 12), ("ciphertext", 48)]
        case .string(macKind)?: fields = macFields; sizes = [("salt", 16), ("mac", 32)]
        default: throw BackupKeyError.damagedAuthority("unknown kind")
        }
        guard Set(o.keys) == fields else { throw BackupKeyError.damagedAuthority("unexpected or missing fields") }
        for (name, size) in sizes {
            guard case .string(let text)? = o[name], let bytes = try? Base64.decodeStrict(text), bytes.count == size else {
                throw BackupKeyError.damagedAuthority("bad \(name)")
            }
        }
        if fields == wrapperFields {
            guard case .string(let text)? = o["aad"], let aad = try? Base64.decodeStrict(text), (1...maxAADBytes).contains(aad.count) else {
                throw BackupKeyError.damagedAuthority("bad aad")
            }
        }
        return o
    }

    static func bytes(_ o: [String: JSONValue], _ name: String) -> [UInt8] {
        if case .string(let s)? = o[name], let b = try? Base64.decodeStrict(s) { return b }
        return []
    }

    /// Does the phrase with this `entropy` (`BIP39.entropy(from:)`) pass the authority? `keyID` is the key id of the
    /// record holding it (the Mac kind binds it). A damaged authority throws. A reset must use `verifyReset`.
    public static func verify(_ authority: JSONValue, entropy: [UInt8], keyID: String) throws -> Bool {
        let o = try validate(authority)
        var key = try phraseKey(entropy: entropy, salt: bytes(o, "salt"))
        defer { BackupKey.wipe(&key) }
        if case .string(wrapperKind)? = o["kind"] {
            guard var opened = try? CryptoBox.openGCM(key: key, nonce: bytes(o, "nonce"), ciphertext: bytes(o, "ciphertext"),
                                                      aad: bytes(o, "aad")) else { return false }
            BackupKey.wipe(&opened)   // that time's vault data key: never kept
            return true
        }
        guard BackupKey.isKeyID(keyID) else { return false }
        return BackupKey.constantTimeEqual(mac(key, keyID: keyID), bytes(o, "mac"))
    }

    /// Owner decision Q2 (strict, `verify_reset_phrase`): the phrase passes the record's bound authority **and** the
    /// authority of the current phrase (`current`, captured just before, same kind; nil without a phrase now).
    public static func verifyReset(record: BackupKeyRecord, entropy: [UInt8], current: JSONValue?) throws -> Bool {
        guard let bound = record.resetAuthority, let current else { return false }
        let b = try validate(bound), c = try validate(current)
        guard b["kind"] == c["kind"] else { return false }
        let isBound = try verify(bound, entropy: entropy, keyID: record.keyID)
        let isCurrent = try verify(current, entropy: entropy, keyID: record.keyID)
        return isBound && isCurrent
    }
}

/// Section 3.3: the public backup key record (stored in `scheduled-backup.bin` v2 on the Mac). Validated on read
/// exactly as Windows `validate_record`; `json` is the record as stored and `encoded()` its canonical bytes.
public struct BackupKeyRecord: Equatable, Sendable {
    public struct HistoryEntry: Equatable, Sendable {
        public let keyID: String
        public let setAt: Int64
        public let setBy: String
        public let replacedAt: Int64
    }

    public static let setByValues: Set<String> = ["set", "migrated", "changed", "reset"]
    public static let historyLimit = 16
    public static let maxTimestamp: Int64 = (1 << 53) - 1
    static let fields: Set<String> = ["v", "key_id", "public_key", "kdf", "set_at", "set_by", "reset_at", "reset_authority",
                                      "history"]
    static let historyFields: Set<String> = ["key_id", "set_at", "set_by", "replaced_at"]

    public let json: JSONValue
    public let keyID: String
    public let publicKey: [UInt8]
    public let kdf: BackupKeyKDF
    public let setAt: Int64
    public let setBy: String
    public let resetAt: Int64?
    public let resetAuthority: JSONValue?
    public let history: [HistoryEntry]

    static func timestamp(_ v: JSONValue?) -> Int64? {
        if case .int(let n)? = v, (0...maxTimestamp).contains(n) { return n }
        return nil
    }

    /// `validate_record`, in the Windows order; `damagedRecord(reason)` on the first problem.
    public init(validating value: JSONValue) throws {
        func damaged(_ reason: String) -> BackupKeyError { .damagedRecord(reason) }
        guard case .object(let o) = value else { throw damaged("not an object") }
        guard Set(o.keys) == Self.fields else { throw damaged("unexpected or missing fields") }
        guard o["v"] == .int(1) else { throw damaged("unsupported version") }
        guard case .string(let pkText)? = o["public_key"], let pk = try? Base64.decodeStrict(pkText), pk.count == 32 else {
            throw damaged("bad public key")
        }
        guard case .string(let id)? = o["key_id"], BackupKey.isKeyID(id) else { throw damaged("bad key id") }
        guard BackupKey.constantTimeEqual(Array(id.utf8), Array(try BackupKey.keyID(pk).utf8)) else {
            throw damaged("the key id does not match the public key")
        }
        let kdf: BackupKeyKDF
        do { kdf = try BackupKeyKDF.parse(o["kdf"]) } catch { throw damaged("bad key derivation parameters") }
        guard let setAt = Self.timestamp(o["set_at"]) else { throw damaged("bad set time") }
        guard case .string(let setBy)? = o["set_by"], Self.setByValues.contains(setBy) else { throw damaged("bad operation") }
        var resetAt: Int64?
        if setBy == "reset" {
            guard let r = Self.timestamp(o["reset_at"]) else { throw damaged("bad reset time") }
            resetAt = r
        } else if o["reset_at"] != .null {
            throw damaged("a reset time on a key that was not reset")
        }
        var authority: JSONValue?
        if let a = o["reset_authority"], a != .null {
            do { try ResetAuthority.validate(a) } catch let e as BackupKeyError {
                throw damaged("bad reset authority (\(e.reason ?? ""))")
            }
            authority = a
        }
        guard case .array(let rows)? = o["history"], rows.count <= Self.historyLimit else { throw damaged("bad history") }
        var history: [HistoryEntry] = []
        for row in rows {
            guard case .object(let e) = row, Set(e.keys) == Self.historyFields,
                  case .string(let hid)? = e["key_id"], BackupKey.isKeyID(hid),
                  let hSet = Self.timestamp(e["set_at"]), case .string(let hBy)? = e["set_by"], Self.setByValues.contains(hBy),
                  let replaced = Self.timestamp(e["replaced_at"]) else { throw damaged("bad history entry") }
            history.append(HistoryEntry(keyID: hid, setAt: hSet, setBy: hBy, replacedAt: replaced))
        }
        json = value; keyID = id; publicKey = pk; self.kdf = kdf; self.setAt = setAt; self.setBy = setBy
        self.resetAt = resetAt; resetAuthority = authority; self.history = history
    }

    /// From stored canonical bytes.
    public init(encoded: [UInt8]) throws {
        guard let value = try? CanonicalJSON.parse(encoded) else { throw BackupKeyError.damagedRecord("not an object") }
        try self.init(validating: value)
    }

    /// `canon(record)` (what the vectors pin).
    public func encoded() throws -> [UInt8] { try CanonicalJSON.encode(json, dialect: .utf8) }

    /// `build_record`: a new record for `key`, set at `now` (integer Unix seconds from the caller). `set` and
    /// `migrated` start a new history; `changed` and `reset` need `previous`, which goes to the front of `history`
    /// (`replaced_at = now`, at most 16 entries); `reset` sets `reset_at = now`. The proof is the caller's.
    public static func build(key: BackupKeyPair, now: Int64, setBy: String, resetAuthority: JSONValue?,
                             previous: BackupKeyRecord?) throws -> BackupKeyRecord {
        guard setByValues.contains(setBy) else { throw FullBackupError.invalid("Unknown backup key operation") }
        guard (0...maxTimestamp).contains(now) else { throw FullBackupError.invalid("A backup key time is integer Unix seconds") }
        guard (try? BackupKey.publicKey(of: key.privateKey)) == key.publicKey, (try? BackupKey.keyID(key.publicKey)) == key.keyID else {
            throw FullBackupError.invalid("The backup key pair does not match")
        }
        var history: [JSONValue] = []
        if setBy == "changed" || setBy == "reset" {
            guard let previous else { throw FullBackupError.invalid("A change or reset replaces an existing backup key record") }
            let first: JSONValue = .object(["key_id": .string(previous.keyID), "set_at": .int(previous.setAt),
                                            "set_by": .string(previous.setBy), "replaced_at": .int(now)])
            history = Array(([first] + previous.history.map(\.json)).prefix(historyLimit))
        } else if previous != nil {
            throw FullBackupError.invalid("A first set or a migration starts without a record")
        }
        let record: JSONValue = .object([
            "v": .int(1), "key_id": .string(key.keyID), "public_key": .string(Base64.encode(key.publicKey)),
            "kdf": key.kdf.json, "set_at": .int(now), "set_by": .string(setBy),
            "reset_at": setBy == "reset" ? .int(now) : .null, "reset_authority": resetAuthority ?? .null,
            "history": .array(history),
        ])
        return try BackupKeyRecord(validating: record)
    }

    /// Proof (a): re-derive with the record's salt and parameters, constant-time compare of `pk`.
    public func passwordMatches(_ password: String) -> Bool {
        guard var key = try? BackupKey.derive(password: password, kdf: kdf) else { return false }
        defer { key.wipe() }
        return BackupKey.constantTimeEqual(key.publicKey, publicKey)
    }

    /// Proof (a) that also hands back the key pair (a re-lock needs the old private key); nil when `password` is not
    /// this record's. The caller `wipe()`s the pair.
    public func matchingKeyPair(_ password: String) -> BackupKeyPair? {
        guard var key = try? BackupKey.derive(password: password, kdf: kdf) else { return nil }
        guard BackupKey.constantTimeEqual(key.publicKey, publicKey) else { key.wipe(); return nil }
        return key
    }

    /// The same record with another reset authority (owner decision Q2 re-bind). Every other field stays.
    func replacingAuthority(_ authority: JSONValue?) throws -> BackupKeyRecord {
        guard case .object(var o) = json else { throw BackupKeyError.damagedRecord("not an object") }
        if let authority { try ResetAuthority.validate(authority) }
        o["reset_authority"] = authority ?? .null
        return try BackupKeyRecord(validating: .object(o))
    }

    /// `rebind_record`: after the recovery phrase was replaced, bind the authority to the current phrase. Needs the
    /// current backup password (else `notCurrentPassword`); only `reset_authority` changes.
    public func rebound(password: String, resetAuthority: JSONValue?) throws -> BackupKeyRecord {
        guard passwordMatches(password) else { throw BackupKeyError.notCurrentPassword }
        return try replacingAuthority(resetAuthority)
    }

    /// The bound authority is the one `current` would give now (same phrase, same key id).
    public func isBound(to current: JSONValue?) -> Bool {
        switch (resetAuthority, current) {
        case (nil, nil): return true
        case (let a?, let c?):
            guard let ea = try? CanonicalJSON.encode(a, dialect: .utf8), let ec = try? CanonicalJSON.encode(c, dialect: .utf8) else { return false }
            return BackupKey.constantTimeEqual(ea, ec)
        default: return false
        }
    }
}

extension BackupKeyRecord.HistoryEntry {
    var json: JSONValue {
        .object(["key_id": .string(keyID), "set_at": .int(setAt), "set_by": .string(setBy), "replaced_at": .int(replacedAt)])
    }
}

extension DesktopVaultFile.PasswordKey {
    /// True when `password` derives this key (same salt and parameters), compared in constant time. Lets the Mac
    /// refuse a backup password equal to the master password without asking for the master password again.
    public func matches(_ password: String) -> Bool {
        guard (12...4096).contains(password.unicodeScalars.count), kdf.isAccepted, salt.count == 16,
              var derived = try? DesktopVaultFile.derive(password, kdf: kdf, salt: salt) else { return false }
        defer { BackupKey.wipe(&derived) }
        return BackupKey.constantTimeEqual(derived, key)
    }
}
