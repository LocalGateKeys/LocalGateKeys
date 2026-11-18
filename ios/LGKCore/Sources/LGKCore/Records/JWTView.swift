/// Decoded JWT parts. Times are seconds since the epoch; only JSON integers count, so numeric strings stay nil.
public struct JWTInfo: Equatable, Sendable {
    public let header: JSONValue
    public let claims: JSONValue
    public let alg: String?
    public let issued: Int64?
    public let notBefore: Int64?
    public let expires: Int64?

    public func expired(now: Int64) -> Bool {
        guard let expires else { return false }
        return expires <= now
    }
}

/// Read-only JWT decode for API-key items; the signature is never checked.
/// Mirror of Python `jwt_view.decode_jwt` and Kotlin `JwtView`; vectors in `tests/vectors/jwt/cases.json`.
public enum JWTView {
    public static let maxChars = 16 * 1024
    private static let maxTimestamp: Int64 = 32_503_680_000   // 3000-01-01T00:00:00Z; later values are ignored

    /// Decodes `header.payload.signature` (base64url, no padding); nil when `value` is not a JWT.
    public static func decode(_ value: String) -> JWTInfo? {
        guard value.utf8.count <= maxChars else { return nil }
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, !parts[0].isEmpty, !parts[1].isEmpty else { return nil }
        for byte in value.utf8 where byte != 0x2E && !isURLSafe(byte) { return nil }
        guard let header = object(String(parts[0])), let claims = object(String(parts[1])) else { return nil }
        var alg: String?
        if case .string(let a)? = header["alg"] { alg = a }
        func time(_ name: String) -> Int64? {
            guard case .int(let n)? = claims[name], n >= 0, n <= maxTimestamp else { return nil }
            return n
        }
        return JWTInfo(header: .object(header), claims: .object(claims), alg: alg,
                       issued: time("iat"), notBefore: time("nbf"), expires: time("exp"))
    }

    private static func isURLSafe(_ b: UInt8) -> Bool {
        (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39) || b == 0x2D || b == 0x5F
    }

    private static func object(_ part: String) -> [String: JSONValue]? {
        guard let bytes = decodeBase64URL(part, maxBytes: maxChars),
              case .object(let o)? = try? CanonicalJSON.parse(bytes) else { return nil }
        return o
    }
}
