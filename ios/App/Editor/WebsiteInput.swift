import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

enum WebsiteInputError: Error, Equatable {
    /// Desktop web logins always have an origin (`Normalise.entry` refuses an empty one).
    case required
    case invalid(String)
    case needsPunycode
}

/// The editor's Website field. People type `github.com` or paste a full address; the record stores the
/// exact origin (`scheme://host[:port]`) that LGKCore `Origin.canonicalize` accepts. Before canonicalising:
/// trim, add `https://` when no scheme is given, and drop any path, query or fragment.
enum WebsiteInput {
    static let requiredMessage = String(localized: "Website is required")
    static let invalidMessage = String(localized: "Enter a website like github.com")
    static let httpMessage = String(localized: "Use https:// for this website. Plain http:// works only for localhost.")

    /// ASCII characters that may appear in what is typed for the host and port.
    private static let hostChars = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._:[]@%~".unicodeScalars)

    static func origin(_ text: String) throws(WebsiteInputError) -> String {
        var t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { throw .required }
        if t.unicodeScalars.contains(where: { $0.properties.isWhitespace || $0.value < 0x20 || $0.value == 0x7F }) {
            throw .invalid(invalidMessage)
        }
        if t.range(of: "://") == nil { t = "https://" + (t.hasPrefix("//") ? String(t.dropFirst(2)) : t) }
        guard let sep = t.range(of: "://") else { throw .invalid(invalidMessage) }
        let rest = t[sep.upperBound...]
        let authority = rest.prefix { $0 != "/" && $0 != "?" && $0 != "#" }
        if authority.unicodeScalars.contains(where: { $0.isASCII && !hostChars.contains($0) }) { throw .invalid(invalidMessage) }
        let candidate = String(t[..<sep.upperBound]) + authority
        do {
            return try Origin.canonicalize(candidate)
        } catch OriginError.needsPunycode {
            throw .needsPunycode
        } catch OriginError.invalid(let detail) {
            // canonicalize's own wording for http on a public host; every other refusal gets the plain hint.
            throw .invalid(detail.hasPrefix("Plain HTTP") ? httpMessage : invalidMessage)
        } catch {
            throw .invalid(invalidMessage)
        }
    }
}
