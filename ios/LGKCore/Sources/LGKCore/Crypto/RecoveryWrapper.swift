import Foundation

/// The recovery-phrase wrapper of the Mac store's local key (`master-key.json` `recovery`), using the Windows
/// derivation (`vault.py` `_recovery_key`): key = HKDF-SHA256(entropy, salt, info `localgatekeys|recovery-key|v1`),
/// kind `bip39-english-24`, a 16-byte salt, a 12-byte nonce and AES-256-GCM over the 32-byte key.
///
/// The Mac AAD binds the kind and salt (`localgatekeys|mac-recovery|v1|kind=…|salt=…`). So that the same phrase also
/// opens a `vault.json` the Mac writes (Ruling 9), the wrapper keeps the derived key sealed under the local key
/// (`vault_key`): an unlocked Mac can add a Windows recovery wrapper with the same salt to a vault it seals, without
/// the phrase. Anyone able to read `vault_key` already holds the local key, so it opens nothing new.
public struct RecoveryWrapper: Codable, Equatable, Sendable {
    public static let kind = "bip39-english-24"
    static let info = Array("localgatekeys|recovery-key|v1".utf8)

    public var kind: String
    public var salt: String
    public var nonce: String
    public var ciphertext: String
    /// nonce (12 bytes) + AES-GCM of the derived key under the local key.
    public var vaultKey: String

    enum CodingKeys: String, CodingKey { case kind, salt, nonce, ciphertext, vaultKey = "vault_key" }

    /// The derived key and its salt, for `DesktopVaultFile.seal(recovery:)`; callers `wipe()` it after use.
    public struct VaultKey: Sendable {
        public let salt: [UInt8]
        public private(set) var key: [UInt8]
        public init(salt: [UInt8], key: [UInt8]) { self.salt = salt; self.key = key }
        public mutating func wipe() { for i in key.indices { key[i] = 0 } }
    }

    static func aad(salt: String) -> [UInt8] { Array("localgatekeys|mac-recovery|v1|kind=\(kind)|salt=\(salt)".utf8) }
    static func vaultKeyAAD(salt: String) -> [UInt8] { Array("localgatekeys|mac-recovery-vault-key|v1|salt=\(salt)".utf8) }

    static func derive(_ entropy: Data, salt: [UInt8]) throws -> [UInt8] {
        guard entropy.count == 32, salt.count == 16 else { throw RecoveryPhraseError("Recovery entropy must be 256 bits") }
        var ikm = [UInt8](entropy)
        defer { for i in ikm.indices { ikm[i] = 0 } }
        return CryptoBox.hkdf(ikm: ikm, salt: salt, info: info, length: 32)
    }

    public static func seal(localKey: [UInt8], entropy: Data, random: any RandomSource) throws -> RecoveryWrapper {
        guard localKey.count == 32 else { throw RecoveryPhraseError("Invalid key-wrapping parameters") }
        let salt = random.bytes(count: 16), nonce = random.bytes(count: 12), keyNonce = random.bytes(count: 12)
        let saltText = Base64.encode(salt)
        var key = try derive(entropy, salt: salt)
        defer { for i in key.indices { key[i] = 0 } }
        let sealed = try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: localKey, aad: aad(salt: saltText))
        let sealedKey = try CryptoBox.sealGCM(key: localKey, nonce: keyNonce, plaintext: key, aad: vaultKeyAAD(salt: saltText))
        return RecoveryWrapper(kind: kind, salt: saltText, nonce: Base64.encode(nonce), ciphertext: Base64.encode(sealed),
                               vaultKey: Base64.encode(keyNonce + sealedKey))
    }

    /// The local key; a wrong phrase (or a tampered wrapper) throws `RecoveryPhraseError.notThisVault`.
    public static func open(_ wrapper: RecoveryWrapper, entropy: Data) throws -> [UInt8] {
        let (salt, nonce, sealed) = try wrapper.fields()
        var key = try derive(entropy, salt: salt)
        defer { for i in key.indices { key[i] = 0 } }
        do { return try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: sealed, aad: aad(salt: wrapper.salt)) }
        catch { throw RecoveryPhraseError.notThisVault }
    }

    /// The derived key from the phrase (tests; recovery).
    public static func vaultKey(for wrapper: RecoveryWrapper, entropy: Data) throws -> VaultKey {
        let (salt, _, _) = try wrapper.fields()
        return VaultKey(salt: salt, key: try derive(entropy, salt: salt))
    }

    /// The derived key from the local key (an unlocked Mac sealing a `vault.json`).
    public static func vaultKey(for wrapper: RecoveryWrapper, localKey: [UInt8]) throws -> VaultKey {
        let (salt, _, _) = try wrapper.fields()
        guard let blob = try? Base64.decodeStrict(wrapper.vaultKey), blob.count == 12 + 48 else { throw MasterKeyError.corrupt }
        do {
            let key = try CryptoBox.openGCM(key: localKey, nonce: Array(blob[0..<12]), ciphertext: Array(blob[12...]),
                                            aad: vaultKeyAAD(salt: wrapper.salt))
            return VaultKey(salt: salt, key: key)
        } catch { throw MasterKeyError.corrupt }
    }

    /// The same phrase (same salt and derived key) wrapping `newLocalKey`: a local key rotation that keeps the phrase
    /// (Windows `_rotate_data_key` with the recovery key). The derived key comes from `vault_key` under the old key.
    public static func reseal(_ wrapper: RecoveryWrapper, oldLocalKey: [UInt8], newLocalKey: [UInt8],
                              random: any RandomSource) throws -> RecoveryWrapper {
        var derived = try vaultKey(for: wrapper, localKey: oldLocalKey)
        defer { derived.wipe() }
        let nonce = random.bytes(count: 12), keyNonce = random.bytes(count: 12)
        let sealed = try CryptoBox.sealGCM(key: derived.key, nonce: nonce, plaintext: newLocalKey, aad: aad(salt: wrapper.salt))
        let sealedKey = try CryptoBox.sealGCM(key: newLocalKey, nonce: keyNonce, plaintext: derived.key,
                                              aad: vaultKeyAAD(salt: wrapper.salt))
        return RecoveryWrapper(kind: kind, salt: wrapper.salt, nonce: Base64.encode(nonce), ciphertext: Base64.encode(sealed),
                               vaultKey: Base64.encode(keyNonce + sealedKey))
    }

    private func fields() throws -> (salt: [UInt8], nonce: [UInt8], sealed: [UInt8]) {
        guard kind == Self.kind, let salt = try? Base64.decodeStrict(salt), salt.count == 16,
              let nonce = try? Base64.decodeStrict(nonce), nonce.count == 12,
              let sealed = try? Base64.decodeStrict(ciphertext), sealed.count == 48 else { throw MasterKeyError.corrupt }
        return (salt, nonce, sealed)
    }
}
