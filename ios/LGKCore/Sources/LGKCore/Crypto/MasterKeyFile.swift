/// The Mac vault's master-password key file: the local vault key sealed under an Argon2id-derived key.
public enum MasterKeyError: Error, Equatable { case wrongPassword, tooLong, empty, badParams, corrupt }

public struct MasterKeyFile: Codable, Equatable, Sendable {
    public struct KDFParams: Codable, Equatable, Sendable {
        public var timeCost: UInt32
        public var memoryKiB: UInt32
        public var parallelism: UInt32
        public init(timeCost: UInt32, memoryKiB: UInt32, parallelism: UInt32) {
            self.timeCost = timeCost; self.memoryKiB = memoryKiB; self.parallelism = parallelism
        }
        /// The desktop's DEFAULT_KDF (src/localvault/vault.py).
        enum CodingKeys: String, CodingKey {
            case timeCost = "time_cost", memoryKiB = "memory_kib", parallelism
        }
        public static let `default` = KDFParams(timeCost: 3, memoryKiB: 65536, parallelism: 4)
    }

    public var version: Int
    public var kdf: KDFParams
    public var salt: String
    public var nonce: String
    public var sealedKey: String
    /// The recovery-phrase wrapper of the same local key, when a phrase is enrolled (absent in older files).
    public var recovery: RecoveryWrapper? = nil

    /// True when `other` seals the local key under the same password (same salt, nonce and sealed key).
    public func samePasswordWrapper(as other: MasterKeyFile) -> Bool {
        version == other.version && kdf == other.kdf && salt == other.salt && nonce == other.nonce && sealedKey == other.sealedKey
    }

    /// Desktop MAX_MASTER_PASSWORD_LENGTH, counted in characters (Unicode scalars) like `SecretText.char_count`.
    enum CodingKeys: String, CodingKey {
        case version, kdf, salt, nonce, sealedKey = "sealed_key", recovery
    }

    static let maxPasswordLength = 4096
    static let minMemoryKiB: UInt32 = 8 * 1024
    static let maxMemoryKiB: UInt32 = 512 * 1024
    /// Binds version, KDF parameters and salt so tampering fails authentication.
    static func aad(_ k: KDFParams, salt: String) -> [UInt8] {
        Array("localgatekeys|mac-master|v1|t=\(k.timeCost)|m=\(k.memoryKiB)|p=\(k.parallelism)|salt=\(salt)".utf8)
    }

    static func validate(_ k: KDFParams) throws {
        guard (1...10).contains(k.timeCost), (1...16).contains(k.parallelism),
              (minMemoryKiB...maxMemoryKiB).contains(k.memoryKiB) else { throw MasterKeyError.badParams }
    }

    /// `params` other than `.default` is a test hook only (cheaper Argon2 in tests); still bounds-checked.
    public static func seal(localKey: [UInt8], password: String, params: KDFParams = .default,
                            random: any RandomSource) throws -> MasterKeyFile {
        try checkPassword(password)
        try validate(params)
        let salt = random.bytes(count: 16), nonce = random.bytes(count: 12)
        let saltText = Base64.encode(salt)
        var key = try derive(password, salt: salt, params: params)
        defer { wipe(&key) }
        let sealed = try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: localKey, aad: aad(params, salt: saltText))
        return MasterKeyFile(version: 1, kdf: params, salt: saltText,
                             nonce: Base64.encode(nonce), sealedKey: Base64.encode(sealed))
    }

    public func open(password: String) throws -> [UInt8] {
        try Self.checkPassword(password)
        try Self.validate(kdf)
        guard version == 1,
              let salt = try? Base64.decodeStrict(salt), salt.count == 16,
              let nonce = try? Base64.decodeStrict(nonce), nonce.count == 12,
              let sealed = try? Base64.decodeStrict(sealedKey) else { throw MasterKeyError.corrupt }
        var key = try Self.derive(password, salt: salt, params: kdf)
        defer { wipe(&key) }
        do { return try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: sealed, aad: Self.aad(kdf, salt: self.salt)) }
        catch { throw MasterKeyError.wrongPassword }
    }

    private static func checkPassword(_ password: String) throws {
        let n = password.unicodeScalars.count
        if n == 0 { throw MasterKeyError.empty }
        if n > maxPasswordLength { throw MasterKeyError.tooLong }
    }

    private static func derive(_ password: String, salt: [UInt8], params: KDFParams) throws -> [UInt8] {
        // The Swift String itself cannot be wiped; only this UTF-8 copy is. No Unicode normalisation.
        var pw = Array(password.utf8)
        defer { wipe(&pw) }
        return try Argon2id.derive(password: pw, salt: salt, memoryKiB: params.memoryKiB,
                                   iterations: params.timeCost, parallelism: params.parallelism, length: 32)
    }
}
