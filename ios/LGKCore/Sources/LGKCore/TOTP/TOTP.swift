import Foundation
import Crypto

/// Thrown exactly where `src/localvault/totp.py` raises `TotpError` for code generation.
public enum TOTPError: Error, Equatable {
    case invalidSecretLength, emptySecret, invalidBase32, secretTooShort, secretTooLong
    case unsupportedDigits, unsupportedPeriod, unsupportedAlgorithm, invalidTimestamp
    /// `parse_otpauth_uri`: "Expected an otpauth://totp URI", duplicate or invalid parameters, label/issuer too long.
    case notOtpauthURI, duplicateParameter, invalidParameter, labelTooLong
}

/// The stored `totp` dict shape the desktop writes (`feature_ui` `config()`): secret, algorithm, digits, period.
public struct TOTPConfig: Equatable, Sendable {
    public var secret: String
    public var algorithm: String
    public var digits: Int
    public var period: Int
    public init(secret: String, algorithm: String = "SHA1", digits: Int = 6, period: Int = 30) {
        self.secret = secret; self.algorithm = algorithm; self.digits = digits; self.period = period
    }
}

/// RFC 6238 TOTP. Secret handling mirrors `totp.py` `_compact_secret` / `_decode_base32`.
public enum TOTP {
    static let minSecretBytes = 10
    static let maxSecretBytes = 128

    /// Python `str.split()` whitespace (Unicode White_Space plus U+001C...U+001F).
    private static func isPyWhitespace(_ s: Unicode.Scalar) -> Bool {
        switch s.value {
        case 0x09...0x0D, 0x1C...0x20, 0x85, 0xA0, 0x1680, 0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000: return true
        default: return false
        }
    }

    /// Desktop: reject > 4096 code points; drop "-" and whitespace; uppercase; reject empty.
    static func compactSecret(_ value: String) throws -> String {
        let scalars = value.unicodeScalars
        if scalars.count > 4096 { throw TOTPError.invalidSecretLength }
        var kept = String.UnicodeScalarView()
        for s in scalars where s != "-" && !isPyWhitespace(s) { kept.append(s) }
        let compact = String(kept).uppercased()
        if compact.isEmpty { throw TOTPError.emptySecret }
        return compact
    }

    /// Mirrors `base64.b32decode(compact + "=" * ((8 - len % 8) % 8), casefold=True)`:
    /// literal "=" in the input is NOT stripped, so it only passes when the padded total is valid.
    static func decodeBase32(_ compact: String) throws -> [UInt8] {
        var chars = Array(compact.unicodeScalars)
        chars += Array(repeating: "=", count: (8 - chars.count % 8) % 8)
        var end = chars.count
        while end > 0 && chars[end - 1] == "=" { end -= 1 }
        let pad = chars.count - end
        guard [0, 1, 3, 4, 6].contains(pad) else { throw TOTPError.invalidBase32 }
        var out = [UInt8](); var acc = 0, bits = 0
        for s in chars[..<end] {
            let v: Int
            switch s.value {
            case 0x41...0x5A: v = Int(s.value) - 0x41
            case 0x32...0x37: v = Int(s.value) - 0x32 + 26
            default: throw TOTPError.invalidBase32
            }
            acc = (acc << 5) | v; bits += 5
            if bits >= 8 { bits -= 8; out.append(UInt8((acc >> bits) & 0xFF)); acc &= (1 << bits) - 1 }
        }
        if out.count < minSecretBytes { throw TOTPError.secretTooShort }
        if out.count > maxSecretBytes { throw TOTPError.secretTooLong }
        return out
    }

    public static func code(secret: String, algorithm: String, digits: Int, period: Int, at: Int64) throws -> String {
        guard (6...8).contains(digits) else { throw TOTPError.unsupportedDigits }
        guard (15...120).contains(period) else { throw TOTPError.unsupportedPeriod }
        let alg = algorithm.uppercased()
        guard alg == "SHA1" || alg == "SHA256" || alg == "SHA512" else { throw TOTPError.unsupportedAlgorithm }
        guard at >= 0 else { throw TOTPError.invalidTimestamp }
        let key = SymmetricKey(data: try decodeBase32(compactSecret(secret)))
        var counter = UInt64(at / Int64(period)).bigEndian
        let msg = withUnsafeBytes(of: &counter) { Array($0) }
        let digest: [UInt8]
        switch alg {
        case "SHA1": digest = Array(HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: key))
        case "SHA256": digest = Array(HMAC<SHA256>.authenticationCode(for: msg, using: key))
        default: digest = Array(HMAC<SHA512>.authenticationCode(for: msg, using: key))
        }
        let o = Int(digest[digest.count - 1] & 0x0F)
        let bin = (UInt32(digest[o] & 0x7F) << 24) | (UInt32(digest[o + 1]) << 16) | (UInt32(digest[o + 2]) << 8) | UInt32(digest[o + 3])
        var modulus: UInt32 = 1
        for _ in 0..<digits { modulus *= 10 }
        let s = String(bin % modulus)
        return String(repeating: "0", count: digits - s.count) + s
    }

    /// `totp.normalize_secret`: the compact upper-case secret, after checking it decodes to 10...128 bytes.
    public static func normalizeSecret(_ value: String) throws -> String {
        let compact = try compactSecret(value)
        _ = try decodeBase32(compact)
        return compact
    }

    static let maxURILength = 16 * 1024

    /// `totp.parse_otpauth_uri`, keeping the keys the desktop stores (secret, algorithm, digits, period).
    public static func parseOtpauthURI(_ uri: String) throws -> TOTPConfig {
        guard uri.unicodeScalars.count <= maxURILength else { throw TOTPError.notOtpauthURI }
        let scalars = Array(uri.unicodeScalars)
        var lo = 0, hi = scalars.count
        while lo < hi && isPyWhitespace(scalars[lo]) { lo += 1 }
        while hi > lo && isPyWhitespace(scalars[hi - 1]) { hi -= 1 }
        // urlsplit drops embedded tab, CR and LF.
        var u = String(String.UnicodeScalarView(scalars[lo..<hi].filter { $0 != "\t" && $0 != "\r" && $0 != "\n" }))
        if let hash = u.firstIndex(of: "#") { u = String(u[..<hash]) }
        guard let sep = u.range(of: "://"), u[..<sep.lowerBound].lowercased() == "otpauth" else { throw TOTPError.notOtpauthURI }
        let rest = u[sep.upperBound...]
        let netEnd = rest.firstIndex(where: { $0 == "/" || $0 == "?" }) ?? rest.endIndex
        guard rest[..<netEnd].lowercased() == "totp" else { throw TOTPError.notOtpauthURI }
        let afterNet = rest[netEnd...]
        let qStart = afterNet.firstIndex(of: "?")
        let path = qStart.map { afterNet[..<$0] } ?? afterNet
        let queryText = qStart.map { String(afterNet[afterNet.index(after: $0)...]) } ?? ""
        var query: [String: [String]] = [:]
        var fields = 0
        for pair in queryText.split(separator: "&", omittingEmptySubsequences: true) {
            fields += 1
            if fields > 64 { throw TOTPError.notOtpauthURI }
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            func dec(_ s: Substring) -> String { pyUnquote(s.replacingOccurrences(of: "+", with: " ")) }
            // parse_qs(keep_blank_values=True): a bare "name" is kept with the value "".
            query[dec(parts[0]), default: []].append(parts.count == 2 ? dec(parts[1]) : "")
        }
        func single(_ name: String, _ def: String) throws -> String {
            guard let v = query[name] else { return def }
            guard v.count == 1 else { throw TOTPError.duplicateParameter }
            return v[0]
        }
        func intParam(_ name: String, _ def: Int) throws -> Int {
            let v = try single(name, "")
            guard query[name] != nil else { return def }
            guard !v.isEmpty, v.count <= 6, v.unicodeScalars.allSatisfy({ (0x30...0x39).contains($0.value) }), let n = Int(v) else {
                throw TOTPError.invalidParameter
            }
            return n
        }
        let secret = try normalizeSecret(try single("secret", ""))
        let digits = try intParam("digits", 6)
        let period = try intParam("period", 30)
        let algorithm = try single("algorithm", "SHA1").uppercased()
        guard (6...8).contains(digits) else { throw TOTPError.unsupportedDigits }
        guard (15...120).contains(period) else { throw TOTPError.unsupportedPeriod }
        guard ["SHA1", "SHA256", "SHA512"].contains(algorithm) else { throw TOTPError.unsupportedAlgorithm }
        let issuer = try single("issuer", "")
        if issuer.unicodeScalars.count > 256 || path.unicodeScalars.count > 1024 { throw TOTPError.labelTooLong }
        return TOTPConfig(secret: secret, algorithm: algorithm, digits: digits, period: period)
    }

    /// A base32 secret or an `otpauth://totp` URI, the way the desktop editor's `config()` reads its field.
    /// `defaults` supplies algorithm/digits/period for a bare secret. Returns nil for an empty field.
    public static func parseField(_ text: String, defaults: TOTPConfig? = nil) throws -> TOTPConfig? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return nil }
        if trimmed.hasPrefix("otpauth://") { return try parseOtpauthURI(trimmed) }
        let d = defaults ?? TOTPConfig(secret: "")
        return TOTPConfig(secret: try normalizeSecret(trimmed), algorithm: d.algorithm, digits: d.digits, period: d.period)
    }

    /// Python `urllib.parse.unquote`: each valid %XX becomes a byte, malformed escapes stay literal, and the
    /// bytes decode as UTF-8 with invalid sequences replaced by U+FFFD.
    static func pyUnquote(_ s: String) -> String {
        guard s.contains("%") else { return s }
        let u = Array(s.utf8)
        func hex(_ b: UInt8) -> UInt8? {
            switch b {
            case 0x30...0x39: b - 0x30
            case 0x41...0x46: b - 0x41 + 10
            case 0x61...0x66: b - 0x61 + 10
            default: nil
            }
        }
        var out = [UInt8](); var i = 0
        while i < u.count {
            if u[i] == 0x25, i + 2 < u.count, let h = hex(u[i + 1]), let l = hex(u[i + 2]) {
                out.append(h << 4 | l); i += 3
            } else { out.append(u[i]); i += 1 }
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Short user-facing text for a parse error.
    public static func message(for error: TOTPError) -> String {
        switch error {
        case .emptySecret: String(localized: "The 2FA secret is empty.", bundle: .module)
        case .invalidBase32, .invalidSecretLength: String(localized: "The 2FA secret is not valid Base32.", bundle: .module)
        case .secretTooShort: String(localized: "The 2FA secret is too short.", bundle: .module)
        case .secretTooLong: String(localized: "The 2FA secret is too long.", bundle: .module)
        case .unsupportedDigits: String(localized: "This 2FA setup uses an unsupported digit count.", bundle: .module)
        case .unsupportedPeriod: String(localized: "This 2FA setup uses an unsupported period.", bundle: .module)
        case .unsupportedAlgorithm: String(localized: "This 2FA setup uses an unsupported algorithm.", bundle: .module)
        case .notOtpauthURI: String(localized: "Enter a Base32 secret or an otpauth://totp link.", bundle: .module)
        case .duplicateParameter, .invalidParameter: String(localized: "The otpauth link has an invalid parameter.", bundle: .module)
        case .labelTooLong: String(localized: "The otpauth link's label or issuer is too long.", bundle: .module)
        case .invalidTimestamp: String(localized: "The 2FA secret is not valid.", bundle: .module)
        }
    }
}
