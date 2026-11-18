import Foundation
import Crypto

/// The privacy proof file (feature pack contract §5): `LocalGateKeys-privacy-proof-YYYY-MM-DD.json`, signed with the
/// sync device identity's Ed25519 key, or unsigned (`"signature": null`) when sync is off. No item content, no paths,
/// no site hosts, ever. Apple platforms list no connections (`network.available: false`) until their guard test exists.
public enum PrivacyProof {
    public static let format = "lgk-privacy-proof"
    /// Version 2 (2026-11-15): the signature also covers `signature.alg`, `device_id` and `public_key`. Version-1
    /// files (device id not signed) verify `invalid`.
    public static let version: Int64 = 2
    public static let domainPrefix = Array("localgatekeys|privacy-proof|v2|".utf8)

    public enum ProofError: Error, Equatable { case noSignatureObject }
    static let topKeys: Set<String> = ["format", "version", "generated_at", "app", "facts", "claims", "network", "signature"]

    /// Claims this build may make on Apple platforms: only the breach-check one, which `BreachCheckTests` covers
    /// (the request carries a 5-character prefix). `connections_listed` / `no_item_content_sent` need a network guard.
    public static let appleClaims = ["breach_prefix_only"]

    public enum SyncMode: String, Sendable { case off, folder, wifi, both }

    public struct Facts: Equatable, Sendable {
        public var sync: SyncMode
        public var devices: Int64
        public var shares: Int64
        public var items: Int64
        public var breachChecks: Bool
        public var strictOffline: Bool
        public var updateCheck: Bool
        public init(sync: SyncMode, devices: Int64, shares: Int64, items: Int64, breachChecks: Bool, strictOffline: Bool,
                    updateCheck: Bool) {
            self.sync = sync; self.devices = devices; self.shares = shares; self.items = items
            self.breachChecks = breachChecks; self.strictOffline = strictOffline; self.updateCheck = updateCheck
        }
        var json: JSONValue {
            .object(["sync": .string(sync.rawValue), "devices": .int(devices), "shares": .int(shares), "items": .int(items),
                     "breach_checks": .bool(breachChecks), "strict_offline": .bool(strictOffline),
                     "update_check": .bool(updateCheck)])
        }
    }

    /// The document without its signature. `generatedAt` is `YYYY-MM-DDTHH:MM:SSZ`.
    public static func document(platform: String, appVersion: String, generatedAt: String, facts: Facts,
                                claims: [String] = appleClaims) -> [String: JSONValue] {
        [
            "format": .string(format), "version": .int(version), "generated_at": .string(generatedAt),
            "app": .object(["platform": .string(platform), "version": .string(appVersion)]),
            "facts": facts.json,
            "claims": .array(claims.map(JSONValue.string)),
            "network": .object(["available": .bool(false), "since": .null, "entries": .array([]), "counts": .object([:])]),
        ]
    }

    /// The signed bytes: the domain prefix + `canon(D)`, where D is the whole document with only `signature.value`
    /// removed (so `alg`, `device_id` and `public_key` are signed). Only a document whose `signature` is an object has
    /// signed bytes.
    public static func signedBytes(_ document: [String: JSONValue]) throws -> [UInt8] {
        guard case .object(var s)? = document["signature"] else { throw ProofError.noSignatureObject }
        s["value"] = nil
        var d = document
        d["signature"] = .object(s)
        return domainPrefix + (try RecordDigest.canon(.object(d)))
    }

    /// The document with its `signature`: signed by `identity`, or `null` when there is none (sync off). The
    /// signature object `{alg, device_id, public_key}` is set first and signed with the rest, then `value` is added.
    public static func signed(_ document: [String: JSONValue], identity: DeviceIdentity?) throws -> [String: JSONValue] {
        var d = document
        d["signature"] = nil
        guard let identity else {
            d["signature"] = .null
            return d
        }
        var s: [String: JSONValue] = ["alg": .string("Ed25519"), "device_id": .string(identity.deviceID),
                                      "public_key": .string(Base64.encode(identity.signingPublicKey))]
        d["signature"] = .object(s)
        let sig = try identity.sign(try signedBytes(d))
        s["value"] = .string(Base64.encode(sig))
        d["signature"] = .object(s)
        return d
    }

    /// The file's bytes (canonical JSON, UTF-8).
    public static func fileBytes(_ document: [String: JSONValue]) throws -> [UInt8] { try RecordDigest.canon(.object(document)) }

    public static func fileName(date: String) -> String { "LocalGateKeys-privacy-proof-\(date).json" }

    /// 16 hex digits: the first 8 bytes of SHA-256 of the raw public key.
    public static func fingerprint(publicKey: [UInt8]) -> String { String(lowerHex(Array(SHA256.hash(data: publicKey))).prefix(16)) }

    public enum Verdict: String, Equatable, Sendable { case valid, unsigned, invalid }

    public struct Verification: Equatable, Sendable {
        public let verdict: Verdict
        public let deviceID: String?
        public let fingerprint: String?
    }

    /// `lgk proof verify`: strict parse (duplicate keys refused), exact top-level keys, format and version 2 (a
    /// version-1 file, whose device id is not signed, is `invalid`), then the signature over the signed bytes.
    public static func verify(_ bytes: [UInt8]) -> Verification {
        let bad = Verification(verdict: .invalid, deviceID: nil, fingerprint: nil)
        guard bytes.count <= maxFileBytes, case .object(let d)? = try? CanonicalJSON.parse(bytes), shapeIsValid(d)
        else { return bad }
        guard let sig = d["signature"] else { return bad }
        if sig == .null { return Verification(verdict: .unsigned, deviceID: nil, fingerprint: nil) }
        guard case .object(let s) = sig, Set(s.keys) == ["alg", "device_id", "public_key", "value"],
              s["alg"] == .string("Ed25519"), case .string(let device)? = s["device_id"],
              case .string(let pk)? = s["public_key"], case .string(let value)? = s["value"],
              let key = try? Base64.decodeStrict(pk), let signature = try? Base64.decodeStrict(value),
              let message = try? signedBytes(d), strictEd25519(publicKey: key, signature: signature),
              DeviceIdentity.verify(signature: signature, message: message, publicKey: key) else { return bad }
        return Verification(verdict: .valid, deviceID: device, fingerprint: fingerprint(publicKey: key))
    }

    // MARK: shape (Windows `privacy_proof.check_shape`, scan 2026-11-15 S-L5)

    static let maxFileBytes = 1024 * 1024
    static let platforms: Set<String> = ["windows", "mac", "ios", "android"]
    static let knownClaims: Set<String> = ["connections_listed", "no_item_content_sent", "breach_prefix_only"]
    static let intFacts = ["devices", "shares", "items"]
    static let boolFacts = ["breach_checks", "strict_offline", "update_check"]

    /// True when `d` has exactly the version-2 shape Windows accepts: every field present with the right type, known
    /// platform, sync mode and claims (no repeats), times as `YYYY-MM-DDTHH:MM:SSZ`, at most 1000 network entries,
    /// and a device id of 1 to 128 characters. Lengths count Unicode scalars, as Python counts code points.
    static func shapeIsValid(_ d: [String: JSONValue]) -> Bool {
        guard Set(d.keys) == topKeys, d["format"] == .string(format), d["version"] == .int(version),
              case .string(let generated)? = d["generated_at"], isTime(generated) else { return false }
        guard case .object(let app)? = d["app"], Set(app.keys) == ["platform", "version"],
              case .string(let platform)? = app["platform"], platforms.contains(platform),
              case .string(let appVersion)? = app["version"], appVersion.unicodeScalars.count <= 64 else { return false }
        guard case .object(let facts)? = d["facts"],
              Set(facts.keys) == Set(["sync"] + intFacts + boolFacts),
              case .string(let sync)? = facts["sync"], SyncMode(rawValue: sync) != nil,
              intFacts.allSatisfy({ isCount(facts[$0]) }),
              boolFacts.allSatisfy({ if case .bool? = facts[$0] { return true }; return false }) else { return false }
        guard case .array(let claims)? = d["claims"] else { return false }
        var seen = Set<String>()
        for claim in claims {
            guard case .string(let c) = claim, knownClaims.contains(c), seen.insert(c).inserted else { return false }
        }
        guard case .object(let network)? = d["network"], Set(network.keys) == ["available", "since", "entries", "counts"],
              case .bool? = network["available"], case .array(let entries)? = network["entries"], entries.count <= 1000,
              case .object(let counts)? = network["counts"] else { return false }
        switch network["since"] {
        case .null?: break
        case .string(let since)? where isTime(since): break
        default: return false
        }
        for row in entries {
            guard case .object(let r) = row, Set(r.keys) == ["purpose", "host", "result", "at"],
                  r.values.allSatisfy({ if case .string(let s) = $0 { return s.unicodeScalars.count <= 300 }; return false })
            else { return false }
        }
        for (key, value) in counts where key.unicodeScalars.count > 64 || !isCount(value) { return false }
        switch d["signature"] {
        case .null?: return true
        case .object(let s)?:
            guard Set(s.keys) == ["alg", "device_id", "public_key", "value"], s["alg"] == .string("Ed25519"),
                  case .string(let device)? = s["device_id"] else { return false }
            return (1...128).contains(device.unicodeScalars.count)
        default: return false
        }
    }

    /// A whole number from 0 to 2^53 (Windows `_int`).
    static func isCount(_ v: JSONValue?) -> Bool {
        guard case .int(let n)? = v else { return false }
        return n >= 0 && n <= 1 << 53
    }

    /// `YYYY-MM-DDTHH:MM:SSZ` with ASCII digits (the shape only, as Windows checks it).
    static func isTime(_ s: String) -> Bool {
        let b = Array(s.utf8)
        guard b.count == 20 else { return false }
        for (i, c) in b.enumerated() {
            switch i {
            case 4, 7: if c != UInt8(ascii: "-") { return false }
            case 10: if c != UInt8(ascii: "T") { return false }
            case 13, 16: if c != UInt8(ascii: ":") { return false }
            case 19: if c != UInt8(ascii: "Z") { return false }
            default: if c < UInt8(ascii: "0") || c > UInt8(ascii: "9") { return false }
            }
        }
        return true
    }

    // MARK: strict Ed25519 (contract §5, `privacy_proof._strict_parts`)

    /// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
    static let groupOrder: [UInt8] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ]

    /// The canonical encodings of the 8 points of small order (orders 1, 2, 4, 4, 8, 8, 8, 8).
    static let smallOrderPoints: Set<[UInt8]> = Set([
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    ].map { PrivacyProof.hexBytes($0) })

    private static func hexBytes(_ s: String) -> [UInt8] {
        let digits = Array(s.utf8)
        return stride(from: 0, to: digits.count, by: 2).map { UInt8(String(decoding: digits[$0..<$0 + 2], as: UTF8.self), radix: 16)! }
    }

    /// The strict checks the Windows verifier runs before the signature equation (CryptoKit's `isValidSignature`
    /// alone accepts some of these): a 32-byte key and 64-byte signature, S < L, A and R canonical (y < p, and x = 0
    /// only with the sign bit clear), and neither A nor R one of the small-order points. Pure byte checks; a y with
    /// no point on the curve is left to CryptoKit, which refuses it.
    static func strictEd25519(publicKey: [UInt8], signature: [UInt8]) -> Bool {
        guard publicKey.count == 32, signature.count == 64 else { return false }
        let r = Array(signature[0..<32]), s = Array(signature[32..<64])
        return scalarBelowL(s) && canonicalPoint(publicKey) && canonicalPoint(r)
            && !smallOrderPoints.contains(publicKey) && !smallOrderPoints.contains(r)
    }

    /// `s` (32 bytes, little-endian) < L.
    static func scalarBelowL(_ s: [UInt8]) -> Bool {
        for i in stride(from: 31, through: 0, by: -1) where s[i] != groupOrder[i] { return s[i] < groupOrder[i] }
        return false
    }

    /// A 32-byte point encoding whose y (the low 255 bits) is below p = 2^255 - 19, and whose sign bit is clear when
    /// x = 0 (y = 1 or y = p - 1).
    static func canonicalPoint(_ e: [UInt8]) -> Bool {
        guard e.count == 32 else { return false }
        var y = e
        y[31] &= 0x7f
        if y[31] == 0x7f && y[1..<31].allSatisfy({ $0 == 0xff }) && y[0] >= 0xed { return false }   // y >= p
        guard e[31] & 0x80 != 0 else { return true }
        let one: [UInt8] = [0x01] + [UInt8](repeating: 0, count: 31)
        let pMinusOne: [UInt8] = [0xec] + [UInt8](repeating: 0xff, count: 30) + [0x7f]
        return y != one && y != pMinusOne
    }

    /// `generated_at` for `date` (UTC, whole seconds).
    public static func timestamp(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        return f.string(from: date)
    }
}
