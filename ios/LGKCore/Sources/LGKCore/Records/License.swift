import Crypto

/// Licence bundle verification (desktop `licensing.verify_bundle`, `newer_format`, `sync_state_id`).
public struct LicenseError: Error, Equatable, Sendable {
    /// `license-shape`, `bad-alg`, `unknown-key` or `bad-signature`.
    public let reason: String
    public init(_ reason: String) { self.reason = reason }
}

public struct LicenseInfo: Equatable, Sendable {
    public let licenseID: String
    public let edition: String
    public let name: String
    public let email: String
    /// ISO dates `YYYY-MM-DD`.
    public let issuedAt: String
    public let updatesUntil: String
}

public enum License {
    public static let idPrefix = "lic:"
    static let bundleFields: Set<String> = ["license", "signature"]
    static let licenseFields: Set<String> = ["format", "license_id", "edition", "name", "email", "issued_at", "updates_until"]
    static let signatureFields: Set<String> = ["alg", "key_id", "signature"]

    /// `"lic:"` + the first 32 lowercase hex digits of SHA-256 of the UTF-8 licence id.
    public static func stateID(licenseID: String) -> String {
        idPrefix + hex(Array(SHA256.hash(data: Array(licenseID.utf8)))).prefix(32)
    }

    static func hex(_ b: [UInt8]) -> String { lowerHex(b) }

    /// `keys`: key id -> raw 32-byte Ed25519 public key.
    public static func verify(bundle: JSONValue, keys: [String: [UInt8]]) throws -> LicenseInfo {
        guard case .object(let b) = bundle, Set(b.keys) == bundleFields,
              case .object(let lic)? = b["license"], Set(lic.keys) == licenseFields,
              case .object(let sig)? = b["signature"], Set(sig.keys) == signatureFields else {
            throw LicenseError("license-shape")
        }
        try checkSignature(lic, sig, keys)
        // Python: `format != 1` (so 1.0 passes) and not a bool.
        guard lic["format"] == .int(1) || lic["format"] == .float(1), lic["edition"] == .string("pro") else {
            throw LicenseError("license-shape")
        }
        var text: [String: String] = [:]
        for f in ["license_id", "name", "email"] {
            guard case .string(let s)? = lic[f], !s.isEmpty else { throw LicenseError("license-shape") }
            text[f] = s
        }
        return LicenseInfo(licenseID: text["license_id"]!, edition: "pro", name: text["name"]!, email: text["email"]!,
                           issuedAt: try date(lic["issued_at"]), updatesUntil: try date(lic["updates_until"]))
    }

    /// True for a correctly signed bundle whose licence `format` is an int above 1.
    public static func newerFormat(bundle: JSONValue, keys: [String: [UInt8]]) -> Bool {
        guard case .object(let b) = bundle, Set(b.keys) == bundleFields,
              case .object(let lic)? = b["license"], case .object(let sig)? = b["signature"],
              Set(sig.keys) == signatureFields, case .int(let fmt)? = lic["format"], fmt > 1 else { return false }
        return (try? checkSignature(lic, sig, keys)) != nil
    }

    static func checkSignature(_ lic: [String: JSONValue], _ sig: [String: JSONValue], _ keys: [String: [UInt8]]) throws {
        guard sig["alg"] == .string("Ed25519") else { throw LicenseError("bad-alg") }
        guard case .string(let keyID)? = sig["key_id"], keyID.utf8.count == 16,
              keyID.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }) else {
            throw LicenseError("license-shape")
        }
        guard let raw = keys[keyID], raw.count == 32,
              hex(Array(SHA256.hash(data: raw).prefix(8))) == keyID,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw) else {
            throw LicenseError("unknown-key")
        }
        guard case .string(let encoded)? = sig["signature"], let rawSig = try? Base64.decodeStrict(encoded), rawSig.count == 64,
              let message = try? CanonicalJSON.encode(.object(lic), dialect: .utf8),
              key.isValidSignature(rawSig, for: message) else {
            throw LicenseError("bad-signature")
        }
    }

    static func date(_ v: JSONValue?) throws -> String {
        guard case .string(let s)? = v, s.utf8.count == 10 else { throw LicenseError("license-shape") }
        let u = Array(s.utf8)
        let digitsOK = [0, 1, 2, 3, 5, 6, 8, 9].allSatisfy { u[$0] >= 0x30 && u[$0] <= 0x39 }
        guard digitsOK, u[4] == 0x2D, u[7] == 0x2D, let y = Int(s.prefix(4)), let m = Int(s.dropFirst(5).prefix(2)),
              let d = Int(s.suffix(2)), y >= 1, (1...12).contains(m) else { throw LicenseError("license-shape") }
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        let days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]
        guard (1...days).contains(d) else { throw LicenseError("license-shape") }
        return s
    }
}
