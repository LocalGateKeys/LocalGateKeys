import Crypto

/// Long-lived device keys (desktop `sync.pairing.DeviceIdentity`): an Ed25519 signing key and an
/// X25519 exchange key, held as raw 32-byte private keys. Task 8 adds signing helpers.
public struct DeviceIdentity: Sendable, Equatable {
    public enum Error: Swift.Error, Equatable { case malformed }

    public let deviceID: String
    public let signingPrivateKey: [UInt8]
    public let exchangePrivateKey: [UInt8]
    public let signingPublicKey: [UInt8]
    public let exchangePublicKey: [UInt8]

    /// From raw private keys (desktop `from_protected_dict`).
    public init(deviceID: String, signingPrivate: [UInt8], exchangePrivate: [UInt8]) throws {
        guard Identifier.isValid(deviceID), signingPrivate.count == 32, exchangePrivate.count == 32,
              let s = try? Curve25519.Signing.PrivateKey(rawRepresentation: signingPrivate),
              let x = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: exchangePrivate)
        else { throw Error.malformed }
        self.deviceID = deviceID
        signingPrivateKey = signingPrivate
        exchangePrivateKey = exchangePrivate
        signingPublicKey = Array(s.publicKey.rawRepresentation)
        exchangePublicKey = Array(x.publicKey.rawRepresentation)
    }

    /// A new identity; the device id defaults to a random UUID4 (lowercase, hyphenated).
    public static func generate(deviceID: String? = nil, random: RandomSource) throws -> DeviceIdentity {
        let id: String
        if let deviceID { id = deviceID } else {
            var u = random.bytes(count: 16)
            guard u.count == 16 else { throw Error.malformed }
            u[6] = (u[6] & 0x0F) | 0x40; u[8] = (u[8] & 0x3F) | 0x80
            let c = Array(lowerHex(u))
            id = String(c[0..<8]) + "-" + String(c[8..<12]) + "-" + String(c[12..<16]) + "-" + String(c[16..<20]) + "-" + String(c[20..<32])
        }
        return try DeviceIdentity(deviceID: id, signingPrivate: random.bytes(count: 32), exchangePrivate: random.bytes(count: 32))
    }

    /// Lowercase hex SHA-256 of the raw Ed25519 public key.
    public var fingerprint: String {
        lowerHex(Array(SHA256.hash(data: signingPublicKey)))
    }

    /// Raw X25519 shared secret with `peerPublic`; throws on a malformed or low-order peer key.
    func exchange(with peerPublic: [UInt8]) throws -> [UInt8] {
        guard peerPublic.count == 32,
              let priv = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: exchangePrivateKey),
              let pub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublic),
              let shared = try? priv.sharedSecretFromKeyAgreement(with: pub)
        else { throw Error.malformed }
        let raw = shared.withUnsafeBytes { Array($0) }
        guard raw.contains(where: { $0 != 0 }) else { throw Error.malformed }
        return raw
    }

    /// Ed25519 signature of `message`. CryptoKit signs with hedged randomness, so the bytes differ
    /// from the desktop's deterministic RFC 8032 signature; any valid signature verifies on both.
    public func sign(_ message: [UInt8]) throws -> [UInt8] {
        guard let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: signingPrivateKey),
              let sig = try? key.signature(for: message) else { throw Error.malformed }
        return Array(sig)
    }

    /// True when `signature` is a valid Ed25519 signature of `message` by the raw `publicKey`.
    public static func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool {
        guard publicKey.count == 32, signature.count == 64,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return key.isValidSignature(signature, for: message)
    }

    /// Raw X25519 shared secret of a raw private key and a raw peer public key.
    static func x25519(privateKey: [UInt8], peerPublic: [UInt8]) throws -> (shared: [UInt8], ownPublic: [UInt8]) {
        guard privateKey.count == 32, peerPublic.count == 32,
              let priv = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey),
              let pub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublic),
              let shared = try? priv.sharedSecretFromKeyAgreement(with: pub)
        else { throw Error.malformed }
        let raw = shared.withUnsafeBytes { Array($0) }
        guard raw.contains(where: { $0 != 0 }) else { throw Error.malformed }
        return (raw, Array(priv.publicKey.rawRepresentation))
    }
}

