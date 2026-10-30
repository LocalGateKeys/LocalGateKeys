import Foundation

/// Licence text as people paste it, and `localgatekeys://install-licence/` links (desktop
/// `licensing.parse_license_text`, `encode_paste` and `licence_link.key_from_link`).
/// Errors are `LicenseError` with the desktop reasons: `not-json`, `duplicate-field`, `bad-encoding`,
/// `license-shape`, and `bad-link` for a link that is not an install link.
public enum LicenceText {
    public static let pastePrefix = "LGK1-"
    public static let scheme = "localgatekeys"
    public static let installPrefix = "localgatekeys://install-licence/"
    /// A licence key is well under 2 KB; anything far larger is not one.
    public static let maxLinkChars = 16_384

    /// An `LGK1-` paste string (wrapping and spaces tolerated) or the JSON file text, as a bundle object.
    /// The result still has to pass `License.verify`.
    public static func parse(_ text: String) throws -> JSONValue {
        var stripped = trim(text)
        while stripped.unicodeScalars.first == "\u{FEFF}" { stripped = String(stripped.unicodeScalars.dropFirst()) }
        stripped = trim(stripped)
        let value: JSONValue
        if stripped.hasPrefix(pastePrefix) {
            let body = String(stripped.dropFirst(pastePrefix.count).unicodeScalars.filter { !isSpace($0) })
            let trimmedBody = dropTrailing(dropTrailing(body, "."), "=")
            // Python `urlsafe_b64decode` also takes the standard alphabet's `+` and `/`.
            let urlSafe = trimmedBody.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            guard let raw = decodeBase64URL(urlSafe, maxBytes: maxLinkChars),
                  let decoded = String(bytes: raw, encoding: .utf8) else {
                throw LicenseError("bad-encoding")
            }
            value = try loads(decoded)
        } else {
            value = try loads(dropTrailing(stripped, "."))
        }
        guard case .object = value else { throw LicenseError("license-shape") }
        return value
    }

    /// `LGK1-` + unpadded base64url of the bundle's canonical JSON.
    public static func encodePaste(_ bundle: JSONValue) throws -> String {
        pastePrefix + Base64URL.encodeNoPad(try CanonicalJSON.encode(bundle, dialect: .utf8))
    }

    /// The `LGK1-` key in an install link; `bad-link` for anything else.
    public static func key(fromLink link: String) throws -> String {
        let bad = LicenseError("bad-link")
        guard link.unicodeScalars.count <= maxLinkChars, link.lowercased().hasPrefix(installPrefix) else { throw bad }
        let tail = String(link.unicodeScalars.dropFirst(installPrefix.unicodeScalars.count))
        let key = dropTrailing(trim(tail.removingPercentEncoding ?? tail), "/")
        guard key.hasPrefix(pastePrefix) else { throw bad }
        return key
    }

    /// "Name (email)", or the email alone when the name is the email (desktop `licence_link._holder`).
    public static func holder(name: String, email: String) -> String {
        name == email ? email : "\(name) (\(email))"
    }

    static func loads(_ text: String) throws -> JSONValue {
        do { return try CanonicalJSON.parse(Array(text.utf8)) } catch JSONError.duplicateKey {
            throw LicenseError("duplicate-field")
        } catch {
            throw LicenseError("not-json")
        }
    }

    static func isSpace(_ s: Unicode.Scalar) -> Bool { s.properties.isWhitespace || (0x1C...0x1F).contains(s.value) }

    static func trim(_ s: String) -> String {
        var u = Substring.UnicodeScalarView(s.unicodeScalars)
        while let f = u.first, isSpace(f) { u.removeFirst() }
        while let l = u.last, isSpace(l) { u.removeLast() }
        return String(u)
    }

    static func dropTrailing(_ s: String, _ c: Character) -> String {
        var s = s
        while s.last == c { s.removeLast() }
        return s
    }
}
