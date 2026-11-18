import Crypto
import Foundation

/// `reason`: `malformed`, `unsupported` (another version) or `bad-signature` (desktop `envelope.EnvelopeError`).
public struct EnvelopeError: Error, Equatable, Sendable {
    public let reason: String
    public init(_ reason: String) { self.reason = reason }
}

/// One verified signed envelope: the signer's public key and the parsed, canonical payload.
public struct SignedEnvelope: Sendable {
    public let format: String
    public let version: Int64
    public let id: String
    public let sender: String
    public let signer: [UInt8]
    public let payload: [String: JSONValue]
}

/// The signed envelope of `.lgkheir` and the heir folder files: port of `src/localvault/envelope.py` and Android
/// `SignedEnvelope.kt` (byte rules in `docs/formats/LGKHEIR_V1.md`). One canonical JSON object
/// `{format, version, id, sender, signer, payload, sig}`; `payload` is base64 of the payload's exact canonical bytes;
/// the Ed25519 signature covers `signContext` followed by the canonical JSON of every field but `sig`. The signature
/// is checked before the payload is parsed.
///
/// Apple's Ed25519 signatures are randomized (any valid signature verifies everywhere); `seal` takes an optional
/// `sign` so the tests can pin the desktop's deterministic signature and compare bytes.
public enum Envelope {
    public static let signContext: [UInt8] = Array("LocalGateKeys signed envelope v1\n".utf8)
    public static let senderLimit = 64
    static let signedFields = ["format", "version", "id", "sender", "signer", "payload"]

    /// A signer for `seal`: the message in, the 64-byte signature out.
    public typealias Signer = @Sendable ([UInt8]) throws -> [UInt8]

    /// Sorted keys (by code point), no spaces, UTF-8 (desktop `canonical`).
    public static func canonical(_ value: JSONValue) throws -> [UInt8] {
        do { return try CanonicalJSON.encode(value, dialect: .utf8) } catch { throw EnvelopeError("malformed") }
    }

    public static func b64e(_ value: [UInt8]) -> String { Base64.encode(value) }

    /// Strict standard base64 (padding required, exact round trip); `size` pins the decoded length.
    public static func b64d(_ value: JSONValue?, size: Int? = nil) throws -> [UInt8] {
        guard case .string(let s)? = value, let out = try? Base64.decodeStrict(s) else { throw EnvelopeError("malformed") }
        if let size, out.count != size { throw EnvelopeError("malformed") }
        return out
    }

    /// At most `limit` bytes of UTF-8 JSON that must be an object (duplicate keys refused).
    public static func loadObject(_ data: [UInt8], limit: Int) throws -> [String: JSONValue] {
        guard data.count <= limit, let value = try? CanonicalJSON.parse(data), case .object(let o) = value else {
            throw EnvelopeError("malformed")
        }
        return o
    }

    /// A lower-case canonical UUID string, else `malformed`.
    public static func checkedID(_ value: JSONValue?) throws -> String {
        guard case .string(let s)? = value, isID(s) else { throw EnvelopeError("malformed") }
        return s
    }

    /// `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`.
    public static func isID(_ s: String) -> Bool {
        let b = Array(s.utf8)
        guard b.count == 36 else { return false }
        for (i, c) in b.enumerated() {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                if c != 0x2D { return false }
            } else if !((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66)) {
                return false
            }
        }
        return true
    }

    /// Python `len(str)`: code points.
    static func length(_ s: String) -> Int { s.unicodeScalars.count }

    static func message(_ header: [String: JSONValue]) throws -> [UInt8] {
        var fields: [String: JSONValue] = [:]
        for k in signedFields { fields[k] = header[k] }
        return signContext + (try canonical(.object(fields)))
    }

    /// Ed25519 public key of a 32-byte seed.
    public static func publicKey(seed: [UInt8]) throws -> [UInt8] {
        guard let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else { throw EnvelopeError("malformed") }
        return Array(key.publicKey.rawRepresentation)
    }

    static func verify(_ signature: [UInt8], _ message: [UInt8], _ publicKey: [UInt8]) -> Bool {
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return key.isValidSignature(signature, for: message)
    }

    /// The canonical bytes of one signed envelope, signed with the Ed25519 `seed` (or `sign`, for vectors).
    public static func seal(format: String, version: Int64, packageID: String, sender: String,
                            payload: [String: JSONValue], seed: [UInt8], sign: Signer? = nil) throws -> [UInt8] {
        let name = Normalise.pyStrip(sender)
        guard length(name) <= senderLimit, isID(packageID) else { throw EnvelopeError("malformed") }
        var header: [String: JSONValue] = [
            "format": .string(format), "version": .int(version), "id": .string(packageID), "sender": .string(name),
            "signer": .string(b64e(try publicKey(seed: seed))), "payload": .string(b64e(try canonical(.object(payload)))),
        ]
        let msg = try message(header)
        let signature: [UInt8]
        if let sign {
            signature = try sign(msg)
        } else {
            guard let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed),
                  let sig = try? key.signature(for: msg) else { throw EnvelopeError("malformed") }
            signature = Array(sig)
        }
        header["sig"] = .string(b64e(signature))
        return try canonical(.object(header))
    }

    /// Parses and verifies one signed envelope (signature first, then the payload must be canonical).
    public static func open(_ data: [UInt8], format: String, version: Int64, limit: Int) throws -> SignedEnvelope {
        let outer = try loadObject(data, limit: limit)
        guard outer["format"] == .string(format) else { throw EnvelopeError("malformed") }
        guard outer["version"] == .int(version) else { throw EnvelopeError("unsupported") }
        guard Set(outer.keys) == Set(signedFields + ["sig"]) else { throw EnvelopeError("malformed") }
        let id = try checkedID(outer["id"])
        guard case .string(let sender)? = outer["sender"], length(sender) <= senderLimit else { throw EnvelopeError("malformed") }
        let signer = try b64d(outer["signer"], size: 32)
        let signature = try b64d(outer["sig"], size: 64)
        let rawPayload = try b64d(outer["payload"])
        guard verify(signature, try message(outer), signer) else { throw EnvelopeError("bad-signature") }
        let payload = try loadObject(rawPayload, limit: limit)
        guard try canonical(.object(payload)) == rawPayload else { throw EnvelopeError("malformed") }
        return SignedEnvelope(format: format, version: version, id: id, sender: sender, signer: signer, payload: payload)
    }

    /// Constant-time equality of two byte strings (the length is public).
    public static func same(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var d: UInt8 = 0
        for i in a.indices { d |= a[i] ^ b[i] }
        return d == 0
    }
}
