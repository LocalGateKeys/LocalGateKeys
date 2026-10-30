import Foundation

/// A refused or failed Windows vault, with the message `vault.py` gives. Never carries a password or contents.
public struct DesktopVaultError: Error, Equatable, Sendable {
    public let message: String
    init(_ message: String) { self.message = message }
    static let wrongPassword = DesktopVaultError("Incorrect master password or modified vault")
}

/// The Windows `vault.json` envelope, format 3 (`vault.py` `FORMAT_VERSION`): a random 32-byte data key wrapped by
/// Argon2id(master password) (`wrappers.password`), and the catalog sealed with the data key:
///
/// * wrapper AAD = `localgatekeys|vault-key-wrapper|v3|` + canonical JSON of the identity (version, format, catalog,
///   catalog_version, vault_id, key_generation) plus `wrapper` and `metadata: {"kdf": header.kdf}`;
/// * catalog AAD = `localgatekeys|vault|v3|` + canonical JSON of the identity plus `generation`, `cipher.name` and
///   `throttle_binding` when present.
///
/// Formats 1 and 2 (the Argon2id output used directly as the catalog key, AAD binding the KDF) are opened too, as
/// `vault.py` does, because Windows backups copy `vault.json` as it is; writing is format 3 only.
///
/// The catalog's `entries` (website and desktop logins) and `items` (typed items) are the records Windows syncs.
/// A Mac full backup carries one of these, so a Windows PC restores it with its own code.
public enum DesktopVaultFile {
    static let formatVersion: Int64 = 3
    static let formatID = "localgatekeys-vault-v3"
    static let catalogFormat = "localgatekeys-catalog"
    static let legacyCatalog = "localgatekeys-credentials-v1"
    static let formatV2ID = "localgatekeys-vault-v2"
    static let aadV1 = Array("localvault-prototype|vault|v1|".utf8)
    static let aadV2 = Array("localgatekeys|vault|v2|".utf8)
    static let catalogAAD = Array("localgatekeys|vault|v3|".utf8)
    static let wrapperAAD = Array("localgatekeys|vault-key-wrapper|v3|".utf8)
    static let recoveryKind = "bip39-english-24"
    static let maxVaultBytes = 24 * 1024 * 1024
    static let maxWrappers = 4
    static let maxWrapperField = 512
    static let entryKinds: Set<String> = ["web", "desktop"]
    /// Keys `seal` sets itself; `settings` may not replace them.
    static let reserved: Set<String> = ["version", "catalog", "generation", "entries", "items", "created_at", "updated_at"]

    public typealias KDF = FullBackupV2.KDF

    /// A new vault holding `items` (logins of kind `web`/`desktop` go to `entries`, everything else to `items`).
    /// `settings` is an object of further catalog fields Windows keeps beside the records (for example `trash`,
    /// `license`, `sync_meta`), copied as given. `kdf` other than `.default` is for tests. `recovery` adds a
    /// `wrappers.recovery` (Windows `create_recovery_phrase`) so the Mac's recovery phrase opens the vault too.
    public static func seal(items: [JSONValue], settings: JSONValue, password: String, random: any RandomSource,
                            now: Int64? = nil, kdf: KDF = .default, recovery: RecoveryWrapper.VaultKey? = nil) throws -> Data {
        guard (12...4096).contains(password.unicodeScalars.count) else {
            throw DesktopVaultError("Use a master password between 12 and 4096 characters")
        }
        guard kdf.isAccepted else { throw DesktopVaultError("Invalid KDF parameters") }
        return try sealCore(items: items, settings: settings, random: random, now: now, kdf: kdf, recovery: recovery,
                            salt: { random.bytes(count: 16) }, kek: { try derive(password, kdf: kdf, salt: $0) })
    }

    /// The same vault sealed with a key derived earlier from the master password (`derivePasswordKey`), so a scheduled
    /// backup is written without the master password at hand. The result is the same format: it opens with the master
    /// password on any device.
    public static func seal(items: [JSONValue], settings: JSONValue, passwordKey: PasswordKey, random: any RandomSource,
                            now: Int64? = nil, recovery: RecoveryWrapper.VaultKey? = nil) throws -> Data {
        guard passwordKey.kdf.isAccepted, passwordKey.salt.count == 16, passwordKey.key.count == 32 else {
            throw DesktopVaultError("Invalid KDF parameters")
        }
        return try sealCore(items: items, settings: settings, random: random, now: now, kdf: passwordKey.kdf, recovery: recovery,
                            salt: { passwordKey.salt }, kek: { _ in passwordKey.key })
    }

    /// Argon2id(master password) over a new salt: the wrapper key a `vault.json` header with that salt and `kdf` opens with.
    /// Holds a password-equivalent key for vaults sealed with it; callers `wipe()` it after use.
    public struct PasswordKey: Sendable {
        public let kdf: KDF
        public let salt: [UInt8]
        public private(set) var key: [UInt8]

        public init(kdf: KDF, salt: [UInt8], key: [UInt8]) { self.kdf = kdf; self.salt = salt; self.key = key }

        public mutating func wipe() { for i in key.indices { key[i] = 0 } }

        /// Canonical JSON for storage (`{"key","memory_cost_kib","parallelism","salt","time_cost","v":1}`).
        public func encoded() throws -> [UInt8] {
            try CanonicalJSON.encode(.object([
                "v": .int(1), "time_cost": .int(Int64(kdf.timeCost)), "memory_cost_kib": .int(Int64(kdf.memoryKiB)),
                "parallelism": .int(Int64(kdf.parallelism)), "salt": .string(Base64.encode(salt)), "key": .string(Base64.encode(key)),
            ]), dialect: .utf8)
        }

        public init(encoded: [UInt8]) throws {
            let bad = DesktopVaultError("Invalid KDF parameters")
            guard case .object(let o)? = try? CanonicalJSON.parse(encoded), o["v"] == .int(1),
                  case .int(let t)? = o["time_cost"], case .int(let m)? = o["memory_cost_kib"], case .int(let p)? = o["parallelism"],
                  let t32 = UInt32(exactly: t), let m32 = UInt32(exactly: m), let p32 = UInt32(exactly: p),
                  case .string(let s)? = o["salt"], case .string(let k)? = o["key"],
                  let salt = try? Base64.decodeStrict(s), let key = try? Base64.decodeStrict(k),
                  salt.count == 16, key.count == 32 else { throw bad }
            let kdf = KDF(timeCost: t32, memoryKiB: m32, parallelism: p32)
            guard kdf.isAccepted else { throw bad }
            self.init(kdf: kdf, salt: salt, key: key)
        }
    }

    public static func derivePasswordKey(password: String, kdf: KDF = .default, random: any RandomSource) throws -> PasswordKey {
        guard (12...4096).contains(password.unicodeScalars.count) else {
            throw DesktopVaultError("Use a master password between 12 and 4096 characters")
        }
        guard kdf.isAccepted else { throw DesktopVaultError("Invalid KDF parameters") }
        let salt = random.bytes(count: 16)
        return PasswordKey(kdf: kdf, salt: salt, key: try derive(password, kdf: kdf, salt: salt))
    }

    private static func sealCore(items: [JSONValue], settings: JSONValue, random: any RandomSource, now: Int64?, kdf: KDF,
                                 recovery: RecoveryWrapper.VaultKey?, salt makeSalt: () -> [UInt8],
                                 kek makeKEK: ([UInt8]) throws -> [UInt8]) throws -> Data {
        guard case .object(let extra) = settings else { throw DesktopVaultError("Vault settings must be an object") }
        let time = now ?? SystemClock().now
        var entries: [JSONValue] = [], typed: [JSONValue] = []
        var ids = Set<String>()
        for item in items {
            guard case .object(let o) = item, case .string(let id)? = o["id"] else {
                throw DesktopVaultError("Vault entries are malformed")
            }
            guard ids.insert(id).inserted else { throw DesktopVaultError("Duplicate catalog item IDs") }
            if case .string(let kind)? = o["kind"], entryKinds.contains(kind) { entries.append(item) } else { typed.append(item) }
        }
        var payload: [String: JSONValue] = [
            "version": .int(2), "catalog": .string(catalogFormat), "created_at": .int(time), "updated_at": .int(time),
            "generation": .int(1), "entries": .array(entries), "items": .array(typed), "collections": .array([]),
            "templates": .array([]), "events": .array([]), "attachments": .array([]), "reminders": .array([]),
            "history": .array([]), "relationships": .array([]), "smart_views": .array([]), "ocr_derivatives": .array([]),
            "sync_protocol_state": .object(["next_counter": .int(1), "item_revisions": .object([:])]),
            "sync_receipts": .array([]),
        ]
        for (k, v) in extra where !reserved.contains(k) { payload[k] = v }

        let salt = makeSalt()
        var dataKey = random.bytes(count: 32)
        defer { FullBackupV2.wipe(&dataKey) }
        let vaultID = lowerHex(random.bytes(count: 16))
        let kdfValue: JSONValue = .object([
            "name": .string("argon2id"), "time_cost": .int(Int64(kdf.timeCost)), "memory_cost_kib": .int(Int64(kdf.memoryKiB)),
            "parallelism": .int(Int64(kdf.parallelism)), "hash_len": .int(32), "salt": .string(Base64.encode(salt)),
        ])
        var header: [String: JSONValue] = [
            "version": .int(formatVersion), "format": .string(formatID), "catalog": .string(catalogFormat),
            "catalog_version": .int(2), "vault_id": .string(vaultID), "generation": .int(1), "key_generation": .int(1),
            "kdf": kdfValue,
        ]
        var kek = try makeKEK(salt)
        defer { FullBackupV2.wipe(&kek) }
        let wrapperNonce = random.bytes(count: 12)
        let wrapped = try CryptoBox.sealGCM(key: kek, nonce: wrapperNonce, plaintext: dataKey,
                                            aad: try wrapperAADFor(header, kdf: kdfValue))
        var wrappers: [String: JSONValue] = ["password": .object(["nonce": .string(Base64.encode(wrapperNonce)),
                                                                  "ciphertext": .string(Base64.encode(wrapped))])]
        if let recovery {
            let metadata: [String: JSONValue] = ["kind": .string(recoveryKind), "salt": .string(Base64.encode(recovery.salt))]
            let recoveryNonce = random.bytes(count: 12)
            let sealedKey = try CryptoBox.sealGCM(key: recovery.key, nonce: recoveryNonce, plaintext: dataKey,
                                                  aad: try wrapperAADFor(header, name: "recovery", metadata: .object(metadata)))
            wrappers["recovery"] = .object(metadata.merging(["nonce": .string(Base64.encode(recoveryNonce)),
                                                             "ciphertext": .string(Base64.encode(sealedKey))]) { a, _ in a })
        }
        header["wrappers"] = .object(wrappers)
        header["cipher"] = .object(["name": .string("aes-256-gcm")])
        let plaintext = try CanonicalJSON.encode(.object(payload), dialect: .ascii)
        guard plaintext.count <= maxVaultBytes / 2 else { throw DesktopVaultError("Vault has exceeded the prototype size limit") }
        let nonce = random.bytes(count: 12)
        let ciphertext = try CryptoBox.sealGCM(key: dataKey, nonce: nonce, plaintext: plaintext, aad: try catalogAADFor(header))
        header["cipher"] = .object(["name": .string("aes-256-gcm"), "nonce": .string(Base64.encode(nonce)),
                                    "ciphertext": .string(Base64.encode(ciphertext))])
        return Data(try CanonicalJSON.encode(.object(header), dialect: .utf8))
    }

    /// The live records (`entries` then `items`) and whether a recovery phrase is enrolled.
    public static func open(_ data: Data, password: String) throws -> (items: [JSONValue], recoveryEnrolled: Bool) {
        let (payload, recovery) = try openPayload(data, password: password)
        var out: [JSONValue] = []
        for key in ["entries", "items"] {
            if case .array(let rows)? = payload[key] { out += rows }
        }
        return (out, recovery)
    }

    /// The live records of a format-3 vault opened with its recovery phrase (Windows `unlock_with_recovery_phrase`);
    /// a vault without one, or another phrase, throws `RecoveryPhraseError`.
    public static func open(_ data: Data, recoveryEntropy: Data) throws -> (items: [JSONValue], recoveryEnrolled: Bool) {
        let (payload, recovery) = try openPayload(data, unlock: .recovery(recoveryEntropy))
        var out: [JSONValue] = []
        for key in ["entries", "items"] {
            if case .array(let rows)? = payload[key] { out += rows }
        }
        return (out, recovery)
    }

    /// The whole decrypted catalog (also `trash`, `sync_meta`, `license` and the rest) and the recovery flag.
    public static func openPayload(_ data: Data, password: String) throws -> (payload: [String: JSONValue], recoveryEnrolled: Bool) {
        try openPayload(data, unlock: .password(password))
    }

    /// The catalog opened with a key from `derivePasswordKey` (its salt and KDF must be the header's).
    public static func openPayload(_ data: Data, passwordKey: PasswordKey) throws -> (payload: [String: JSONValue], recoveryEnrolled: Bool) {
        try openPayload(data, unlock: .passwordKey(passwordKey))
    }

    enum Unlock { case password(String), recovery(Data), passwordKey(PasswordKey) }

    static func openPayload(_ data: Data, unlock: Unlock) throws -> (payload: [String: JSONValue], recoveryEnrolled: Bool) {
        guard data.count <= maxVaultBytes else { throw DesktopVaultError("Vault exceeds the accepted size limit") }
        let parsed: JSONValue
        do { parsed = try CanonicalJSON.parse(Array(data)) } catch { throw DesktopVaultError("Unable to read vault") }
        guard case .object(let header) = parsed else { throw DesktopVaultError("Vault header must be an object") }
        guard case .int(let version)? = header["version"], [1, 2, 3].contains(version) else {
            throw DesktopVaultError("Unsupported vault format version")
        }
        guard case .object(let cipher)? = header["cipher"], cipher["name"] == .string("aes-256-gcm") else {
            throw DesktopVaultError("Unsupported vault cipher")
        }
        guard case .object(let kdf)? = header["kdf"] else { throw DesktopVaultError("Vault KDF metadata is missing") }
        if case .password(let password) = unlock {
            guard !password.isEmpty else { throw DesktopVaultError("Master password cannot be empty") }
            guard password.unicodeScalars.count <= 4096 else { throw DesktopVaultError("Master password is too long") }
        }
        let catalogVersion: Int64
        var recovery = false
        var dataKey: [UInt8]
        let catalogAADBytes: [UInt8]
        if version == formatVersion {
            catalogVersion = try validateHeader(header)
            guard case .object(let wrappers)? = header["wrappers"], case .object(let pw)? = wrappers["password"] else {
                throw DesktopVaultError("Vault has no master-password key wrapper")
            }
            if case .object? = wrappers["recovery"] { recovery = true }
            switch unlock {
            case .password(let password):
                let (params, salt) = try kdfParameters(kdf)
                let wrapperNonce = try field(pw, "nonce", 12), wrapped = try field(pw, "ciphertext", 48)
                var kek = try derive(password, kdf: params, salt: salt)
                defer { FullBackupV2.wipe(&kek) }
                do {
                    dataKey = try CryptoBox.openGCM(key: kek, nonce: wrapperNonce, ciphertext: wrapped,
                                                    aad: try wrapperAADFor(header, kdf: .object(kdf)))
                } catch { throw DesktopVaultError.wrongPassword }
            case .passwordKey(let given):
                let (params, salt) = try kdfParameters(kdf)
                let wrapperNonce = try field(pw, "nonce", 12), wrapped = try field(pw, "ciphertext", 48)
                guard params == given.kdf, salt == given.salt else { throw DesktopVaultError.wrongPassword }
                do {
                    dataKey = try CryptoBox.openGCM(key: given.key, nonce: wrapperNonce, ciphertext: wrapped,
                                                    aad: try wrapperAADFor(header, kdf: .object(kdf)))
                } catch { throw DesktopVaultError.wrongPassword }
            case .recovery(let entropy):
                guard case .object(let r)? = wrappers["recovery"], case .string(let saltText)? = r["salt"] else {
                    throw RecoveryPhraseError("This vault has no recovery phrase")
                }
                let salt = try field(r, "salt", 16), nonce = try field(r, "nonce", 12), wrapped = try field(r, "ciphertext", 48)
                var key = try RecoveryWrapper.derive(entropy, salt: salt)
                defer { FullBackupV2.wipe(&key) }
                let metadata: JSONValue = .object(["kind": .string(recoveryKind), "salt": .string(saltText)])
                do {
                    dataKey = try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: wrapped,
                                                    aad: try wrapperAADFor(header, name: "recovery", metadata: metadata))
                } catch { throw RecoveryPhraseError.notThisVault }
            }
            catalogAADBytes = try catalogAADFor(header)
        } else {
            // Formats 1 and 2: the Argon2id output is the catalog key and the AAD binds the KDF (`vault._aad`).
            if version == 2, header["format"] != .string(formatV2ID) || header["catalog"] != .string(catalogFormat) {
                throw DesktopVaultError("Unsupported vault format identifier")
            }
            catalogVersion = version
            guard case .password(let password) = unlock else { throw RecoveryPhraseError("This vault has no recovery phrase") }
            let (params, salt) = try kdfParameters(kdf)
            dataKey = try derive(password, kdf: params, salt: salt)
            catalogAADBytes = try legacyAAD(header, version: version)
        }
        defer { FullBackupV2.wipe(&dataKey) }
        let nonce: [UInt8], ciphertext: [UInt8]
        do {
            guard case .string(let n)? = cipher["nonce"], case .string(let c)? = cipher["ciphertext"] else { throw Base64Error.malformed }
            nonce = try Base64.decodeStrict(n); ciphertext = try Base64.decodeStrict(c)
        } catch { throw DesktopVaultError("Vault contains invalid base64 data") }
        guard nonce.count == 12 else { throw DesktopVaultError("Vault nonce has an invalid length") }
        let payloadValue: JSONValue
        do {
            let plain = try CryptoBox.openGCM(key: dataKey, nonce: nonce, ciphertext: ciphertext, aad: catalogAADBytes)
            payloadValue = try CanonicalJSON.parse(plain)
        } catch { throw DesktopVaultError.wrongPassword }
        guard case .object(let payload) = payloadValue, payload["version"] == .int(catalogVersion) else {
            throw DesktopVaultError("Unsupported decrypted vault payload")
        }
        if catalogVersion == 2, let c = payload["catalog"], c != .string(catalogFormat) {
            throw DesktopVaultError("Unsupported encrypted catalog format")
        }
        let generation: Int64
        if case .int(let g)? = payload["generation"] { generation = g } else { generation = 0 }
        guard version != formatVersion || header["generation"] == .int(generation) else {
            throw DesktopVaultError("Vault header generation does not match its encrypted catalog")
        }
        for key in ["entries", "items"] {
            if let v = payload[key] { guard case .array = v else { throw DesktopVaultError("Vault entries are malformed") } }
        }
        return (payload, recovery)
    }

    // MARK: - helpers

    /// `_validate_v3_header` (structural, before any crypto); returns the catalog version.
    static func validateHeader(_ h: [String: JSONValue]) throws -> Int64 {
        guard h["format"] == .string(formatID) else { throw DesktopVaultError("Unsupported vault format identifier") }
        let catalogVersion: Int64
        if let v = h["catalog_version"] {
            guard case .int(let n) = v else { throw DesktopVaultError("Vault catalog version is malformed") }
            catalogVersion = n
        } else { catalogVersion = 2 }
        guard catalogVersion == 1 || catalogVersion == 2 else { throw DesktopVaultError("Unsupported vault catalog version") }
        guard h["catalog"] == .string(catalogVersion == 2 ? catalogFormat : legacyCatalog) else {
            throw DesktopVaultError("Unsupported vault catalog identifier")
        }
        guard case .string(let id)? = h["vault_id"], id.unicodeScalars.count == 32,
              id.unicodeScalars.allSatisfy({ ("0"..."9").contains($0) || ("a"..."f").contains($0) }) else {
            throw DesktopVaultError("Vault identity is malformed")
        }
        for name in ["generation", "key_generation"] {
            guard case .int(let n)? = h[name], n >= 0 else { throw DesktopVaultError("Vault \(name) is malformed") }
        }
        guard case .object(let wrappers)? = h["wrappers"], !wrappers.isEmpty, wrappers.count <= maxWrappers else {
            throw DesktopVaultError("Vault key wrappers are malformed")
        }
        let malformed = DesktopVaultError("Vault key wrapper is malformed")
        for (name, value) in wrappers {
            guard name == "password" || name == "recovery", case .object(let w) = value, w.count <= 8 else { throw malformed }
            for (k, v) in w {
                guard k.count <= 32 else { throw malformed }
                switch v {
                case .string(let s): guard s.count <= maxWrapperField else { throw malformed }
                case .int: break
                default: throw malformed
                }
            }
            _ = try field(w, "nonce", 12)
            _ = try field(w, "ciphertext", 48)
        }
        guard wrappers["password"] != nil else { throw DesktopVaultError("Vault has no master-password key wrapper") }
        if case .object(let r)? = wrappers["recovery"] {
            guard r["kind"] == .string(recoveryKind) else { throw DesktopVaultError("Unsupported recovery wrapper") }
            _ = try field(r, "salt", 16)
        }
        if let binding = h["throttle_binding"] {
            guard case .object(let b) = binding, b.values.allSatisfy({ if case .string = $0 { return true }; return false }) else {
                throw DesktopVaultError("Vault unlock-throttle binding is malformed")
            }
        }
        return catalogVersion
    }

    static func field(_ w: [String: JSONValue], _ name: String, _ size: Int) throws -> [UInt8] {
        guard case .string(let s)? = w[name], s.count <= maxWrapperField,
              let bytes = try? Base64.decodeStrict(s), bytes.count == size else {
            throw DesktopVaultError("Vault key wrapper is malformed")
        }
        return bytes
    }

    static func kdfParameters(_ kdf: [String: JSONValue]) throws -> (KDF, [UInt8]) {
        guard kdf["name"] == .string("argon2id") else { throw DesktopVaultError("Unsupported KDF") }
        let salt: [UInt8]
        do {
            guard case .string(let s)? = kdf["salt"] else { throw Base64Error.malformed }
            salt = try Base64.decodeStrict(s)
        } catch { throw DesktopVaultError("Vault contains invalid base64 data") }
        guard salt.count >= 16 else { throw DesktopVaultError("Vault KDF salt is too short") }
        let invalid = DesktopVaultError("Invalid KDF parameters")
        guard case .int(let t)? = kdf["time_cost"], case .int(let m)? = kdf["memory_cost_kib"],
              case .int(let p)? = kdf["parallelism"], kdf["hash_len"] == .int(32),
              let t32 = UInt32(exactly: t), let m32 = UInt32(exactly: m), let p32 = UInt32(exactly: p) else { throw invalid }
        let params = KDF(timeCost: t32, memoryKiB: m32, parallelism: p32)
        guard params.isAccepted else { throw invalid }
        return (params, salt)
    }

    static func derive(_ password: String, kdf: KDF, salt: [UInt8]) throws -> [UInt8] {
        do {
            return try Argon2id.derive(password: Array(password.utf8), salt: salt, memoryKiB: kdf.memoryKiB,
                                       iterations: kdf.timeCost, parallelism: kdf.parallelism, length: 32)
        } catch { throw DesktopVaultError("Key derivation failed") }
    }

    static func identity(_ h: [String: JSONValue]) -> [String: JSONValue] {
        [
            "version": .int(formatVersion), "format": h["format"] ?? .string(formatID),
            "catalog": h["catalog"] ?? .string(catalogFormat), "catalog_version": h["catalog_version"] ?? .int(2),
            "vault_id": h["vault_id"] ?? .string(""), "key_generation": h["key_generation"] ?? .int(1),
        ]
    }

    static func wrapperAADFor(_ h: [String: JSONValue], kdf: JSONValue) throws -> [UInt8] {
        try wrapperAADFor(h, name: "password", metadata: .object(["kdf": kdf]))
    }

    /// `vault._wrapper_aad`: the identity plus the wrapper's name and public metadata.
    static func wrapperAADFor(_ h: [String: JSONValue], name: String, metadata: JSONValue) throws -> [UInt8] {
        var body = identity(h)
        body["wrapper"] = .string(name)
        body["metadata"] = metadata
        return wrapperAAD + (try CanonicalJSON.encode(.object(body), dialect: .ascii))
    }

    /// `vault._aad` for formats 1 and 2.
    static func legacyAAD(_ h: [String: JSONValue], version: Int64) throws -> [UInt8] {
        var body: [String: JSONValue] = ["version": .int(version), "kdf": h["kdf"] ?? .null,
                                         "cipher": .object(["name": .string("aes-256-gcm")])]
        if version == 2 {
            body["format"] = h["format"] ?? .string(formatV2ID)
            body["catalog"] = h["catalog"] ?? .string(catalogFormat)
        }
        return (version == 2 ? aadV2 : aadV1) + (try CanonicalJSON.encode(.object(body), dialect: .ascii))
    }

    static func catalogAADFor(_ h: [String: JSONValue]) throws -> [UInt8] {
        var body = identity(h)
        body["generation"] = h["generation"] ?? .int(0)
        body["cipher"] = .object(["name": .string("aes-256-gcm")])
        if let binding = h["throttle_binding"] { body["throttle_binding"] = binding }
        return catalogAAD + (try CanonicalJSON.encode(.object(body), dialect: .ascii))
    }
}
