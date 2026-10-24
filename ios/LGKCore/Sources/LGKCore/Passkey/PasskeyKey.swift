import Crypto

public enum PasskeyKeyError: Error, Equatable { case badClientDataHash }

/// An ES256 passkey private key, stored as unpadded base64url PKCS#8 DER (desktop `create_credential`).
public struct PasskeyKey: Sendable {
    private let key: P256.Signing.PrivateKey

    /// nil where desktop `_load_private_key` returns None (bad base64url, not a P-256 key).
    /// The base64url string is key material: callers should keep its lifetime short (read it from the item,
    /// build the key, drop the string) and never log it.
    public init?(pkcs8B64URL: String) {
        guard var der = decodeBase64URL(pkcs8B64URL, maxBytes: 4096) else { return nil }
        defer { for i in der.indices { der[i] = 0 } }
        guard let k = try? P256.Signing.PrivateKey(derRepresentation: der) else { return nil }
        key = k
    }

    private init(key: P256.Signing.PrivateKey) { self.key = key }

    public static func generate() -> PasskeyKey { PasskeyKey(key: P256.Signing.PrivateKey()) }

    public var pkcs8B64URL: String { base64URLNoPad(Array(key.derRepresentation)) }

    public var publicKey: P256.Signing.PublicKey { key.publicKey }

    /// DER ECDSA-SHA256 over `authData ‖ clientDataHash`. Throws `badClientDataHash` unless the hash is
    /// 32 bytes (SHA-256 of clientDataJSON).
    public func sign(authData: [UInt8], clientDataHash: [UInt8]) throws -> [UInt8] {
        guard clientDataHash.count == 32 else { throw PasskeyKeyError.badClientDataHash }
        return Array(try key.signature(for: authData + clientDataHash).derRepresentation)
    }
}
