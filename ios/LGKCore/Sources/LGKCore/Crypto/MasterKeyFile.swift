/// The Mac vault's master-password key file: the local vault key sealed under an Argon2id-derived key.
///
/// Version 1 has no factors and is written exactly as before. Version 2 (docs/formats/COMPOSITE_KEY_V1.md §6, Mac
/// and iPhone) adds a `factors` list (key file and/or YubiKey); its key is the composite key (§4) and its AAD binds
/// the list. The recovery wrapper is the same in both.
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
    /// Version 2 only: the key-file / YubiKey factors (1-2, keyfile first). Absent (nil) in version 1, so a file
    /// without factors encodes exactly as before.
    public var factors: [FactorSpec]? = nil

    /// True when `other` seals the local key under the same password (same salt, nonce, sealed key and factors).
    public func samePasswordWrapper(as other: MasterKeyFile) -> Bool {
        version == other.version && kdf == other.kdf && salt == other.salt && nonce == other.nonce && sealedKey == other.sealedKey
            && factors == other.factors
    }

    /// The factor kinds this file asks for at unlock, in list order (empty for version 1).
    public var factorKinds: [FactorKind] { (factors ?? []).map(\.kind) }

    /// Desktop MAX_MASTER_PASSWORD_LENGTH, counted in characters (Unicode scalars) like `SecretText.char_count`.
    enum CodingKeys: String, CodingKey {
        case version, kdf, salt, nonce, sealedKey = "sealed_key", recovery, factors
    }

    static let maxPasswordLength = 4096
    static let minMemoryKiB: UInt32 = 8 * 1024
    static let maxMemoryKiB: UInt32 = 512 * 1024
    /// Binds version, KDF parameters and salt so tampering fails authentication.
    static func aad(_ k: KDFParams, salt: String) -> [UInt8] {
        Array("localgatekeys|mac-master|v1|t=\(k.timeCost)|m=\(k.memoryKiB)|p=\(k.parallelism)|salt=\(salt)".utf8)
    }

    /// Version 2 (§6): the v1 fields under `v2`, then the canonical JSON of the factor list.
    static func aad(_ k: KDFParams, salt: String, factors: [FactorSpec]) throws -> [UInt8] {
        let head = Array("localgatekeys|mac-master|v2|t=\(k.timeCost)|m=\(k.memoryKiB)|p=\(k.parallelism)|salt=\(salt)|factors=".utf8)
        return head + (try CompositeKey.info(factors))
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

    /// A file with key-file / YubiKey factors (version 2) sealed under `password` and the factors' `secrets` (in
    /// list order, from `CompositeKey.enrolKeyFile` / `enrolYubiKey` / `renewed`). With no factors this is `seal`
    /// (version 1). The caller carries the recovery wrapper (`recovery`) over.
    public static func seal(localKey: [UInt8], password: String, params: KDFParams = .default, random: any RandomSource,
                            factors: [FactorSpec], secrets: [[UInt8]]) throws -> MasterKeyFile {
        guard !factors.isEmpty else { return try seal(localKey: localKey, password: password, params: params, random: random) }
        try checkPassword(password)
        try validate(params)
        try CompositeKey.verify(factors, secrets: secrets)
        let salt = random.bytes(count: 16), nonce = random.bytes(count: 12)
        let saltText = Base64.encode(salt)
        var argonOut = try derive(password, salt: salt, params: params)
        defer { wipe(&argonOut) }
        var key = try CompositeKey.combine(argonOut: argonOut, specs: factors, secrets: secrets)
        defer { wipe(&key) }
        let sealed = try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: localKey,
                                           aad: try aad(params, salt: saltText, factors: factors))
        return MasterKeyFile(version: 2, kdf: params, salt: saltText, nonce: Base64.encode(nonce),
                             sealedKey: Base64.encode(sealed), factors: factors)
    }

    /// Version 1 only: a version-2 file throws `FactorError.required` (use `open(password:factors:)`).
    public func open(password: String) throws -> [UInt8] {
        try open(password: password, secrets: [])
    }

    /// The local key, with the factors' secrets in list order (none for version 1). The secrets are checked before
    /// Argon2id runs: missing ones throw `FactorError.required`, a wrong one `FactorError.mismatch` (neither is a
    /// wrong password).
    public func open(password: String, secrets: [[UInt8]]) throws -> [UInt8] {
        try open(password: password, secrets: secrets, derive: Self.derive)
    }

    /// `open(password:secrets:)` with the secrets taken from `factors` first (the key file's bytes; the YubiKey asked
    /// with each factor's padded challenge). Argon2id then runs on the calling task: callers run this detached.
    public func open(password: String, factors given: FactorSecrets) async throws -> [UInt8] {
        var secrets = try await CompositeKey.secrets(for: try factorsForUnlock(password: password), from: given)
        defer { for i in secrets.indices { wipe(&secrets[i]) } }
        return try open(password: password, secrets: secrets)
    }

    /// `derive` is a test hook (it counts Argon2id runs: a factor problem must fail before any).
    func open(password: String, secrets: [[UInt8]],
              derive: (String, [UInt8], KDFParams) throws -> [UInt8]) throws -> [UInt8] {
        try Self.checkPassword(password)
        try Self.validate(kdf)
        let specs = try checkedFactors()
        guard let salt = try? Base64.decodeStrict(salt), salt.count == 16,
              let nonce = try? Base64.decodeStrict(nonce), nonce.count == 12,
              let sealed = try? Base64.decodeStrict(sealedKey) else { throw MasterKeyError.corrupt }
        guard secrets.count == specs.count else { throw FactorError.required(specs.map(\.kind)) }
        try CompositeKey.verify(specs, secrets: secrets)
        var argonOut = try derive(password, salt, kdf)
        defer { wipe(&argonOut) }
        var key = try CompositeKey.combine(argonOut: argonOut, specs: specs, secrets: secrets)
        defer { wipe(&key) }
        let aad = try specs.isEmpty ? Self.aad(kdf, salt: self.salt) : Self.aad(kdf, salt: self.salt, factors: specs)
        do { return try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: sealed, aad: aad) }
        catch { throw MasterKeyError.wrongPassword }
    }

    /// Everything that can be checked before any factor is asked for (password length, KDF limits, version/factors
    /// consistency, the base64 fields), so a malformed file never triggers a YubiKey touch; returns the factor list.
    public func factorsForUnlock(password: String) throws -> [FactorSpec] {
        try Self.checkPassword(password)
        try Self.validate(kdf)
        let specs = try checkedFactors()
        guard let s = try? Base64.decodeStrict(salt), s.count == 16,
              let n = try? Base64.decodeStrict(nonce), n.count == 12,
              (try? Base64.decodeStrict(sealedKey)) != nil else { throw MasterKeyError.corrupt }
        return specs
    }

    /// The factor list for this version: none in version 1, 1-2 valid entries (keyfile first) in version 2.
    func checkedFactors() throws -> [FactorSpec] {
        switch version {
        case 1:
            guard factors == nil else { throw MasterKeyError.corrupt }
            return []
        case 2:
            guard let factors, (1...2).contains(factors.count), (try? CompositeKey.validate(factors)) != nil else {
                throw MasterKeyError.corrupt
            }
            return factors
        default:
            throw MasterKeyError.corrupt
        }
    }

    private static func checkPassword(_ password: String) throws {
        let n = password.unicodeScalars.count
        if n == 0 { throw MasterKeyError.empty }
        if n > maxPasswordLength { throw MasterKeyError.tooLong }
    }

    static func derive(_ password: String, salt: [UInt8], params: KDFParams) throws -> [UInt8] {
        // The Swift String itself cannot be wiped; only this UTF-8 copy is. No Unicode normalisation.
        var pw = Array(password.utf8)
        defer { wipe(&pw) }
        return try Argon2id.derive(password: pw, salt: salt, memoryKiB: params.memoryKiB,
                                   iterations: params.timeCost, parallelism: params.parallelism, length: 32)
    }
}
