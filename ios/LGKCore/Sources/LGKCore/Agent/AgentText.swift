import Foundation

/// The Local Agent Gate's text and site helpers (Windows `agent_gate.py`: `clean_text`, `registrable_domain`,
/// `site_host`, `origin_domain`, `agents_may_use`, `site_passkeys`). Pinned by `tests/vectors/agent/text.json`
/// (`AgentVectorsTests`), which the Windows build writes.
public enum AgentText {
    /// `MAX_SITE`: the longest site an agent may name (plus 16 for a scheme and path).
    public static let maxSite = 253
    /// `AGENT_SCOPE_KEY`: the per-login opt-in in the login's `scope` ("AI agents may use this login"). It syncs
    /// as an ordinary scope key; transfers and shares drop it.
    public static let scopeKey = "ai_agents"

    /// `clean_text`: plain, single-line text. Tab, CR and LF become spaces; other control, format, surrogate,
    /// private-use and unassigned code points are removed; runs of white space become one space, none at either
    /// end; at most `limit` code points.
    public static func clean(_ value: String?, limit: Int) -> String {
        guard let value else { return "" }
        var kept: [Unicode.Scalar] = []
        for scalar in value.unicodeScalars {
            if scalar == "\t" || scalar == "\r" || scalar == "\n" {
                kept.append(" ")
                continue
            }
            switch scalar.properties.generalCategory {
            case .control, .format, .surrogate, .privateUse, .unassigned: continue
            default: kept.append(scalar)
            }
        }
        // Python `" ".join(text.split())`: what is left of Python's white space is Zs, Zl and Zp.
        var words: [[Unicode.Scalar]] = []
        var word: [Unicode.Scalar] = []
        for scalar in kept {
            if isSpace(scalar) {
                if !word.isEmpty { words.append(word); word = [] }
            } else {
                word.append(scalar)
            }
        }
        if !word.isEmpty { words.append(word) }
        let joined = words.map { String(String.UnicodeScalarView($0)) }.joined(separator: " ")
        return String(String.UnicodeScalarView(joined.unicodeScalars.prefix(max(0, limit))))
    }

    static func isSpace(_ scalar: Unicode.Scalar) -> Bool {
        if Origin.isPySpace(scalar) { return true }
        switch scalar.properties.generalCategory {
        case .spaceSeparator, .lineSeparator, .paragraphSeparator: return true
        default: return false
        }
    }

    /// Python `text[:limit]` (code points).
    static func prefix(_ text: String, _ limit: Int) -> String {
        String(String.UnicodeScalarView(text.unicodeScalars.prefix(max(0, limit))))
    }

    /// Python `needle in haystack` (code points; Swift's `contains` compares characters).
    static func pyContains(_ haystack: String, _ needle: String) -> Bool {
        let h = Array(haystack.unicodeScalars), n = Array(needle.unicodeScalars)
        if n.isEmpty { return true }
        guard n.count <= h.count else { return false }
        for start in 0...(h.count - n.count) where Array(h[start..<start + n.count]) == n { return true }
        return false
    }

    /// Python string equality (code points; Swift's `==` treats canonically equivalent strings as equal).
    static func pyEqual(_ a: String, _ b: String) -> Bool { Array(a.unicodeScalars) == Array(b.unicodeScalars) }

    /// The site text as a URL: stripped, `https://` added when it has no scheme; nil when empty or too long.
    private static func asURL(_ site: String?) -> String? {
        guard let site, Normalise.len(site) <= maxSite + 16 else { return nil }
        let text = Normalise.pyStrip(site)
        guard !text.isEmpty else { return nil }
        return asciiNetloc(text.contains("://") ? text : "https://" + text)
    }

    /// The desktop's `host_of` IDNA-encodes a non-ASCII host (`bücher.example` -> `xn--bcher-kva.example`). The
    /// phone has no UTS-46 tables; NFC plus lower-casing plus Punycode gives the same A-label for ordinary names.
    /// nil when a label cannot be encoded.
    private static func asciiNetloc(_ url: String) -> String? {
        guard let schemeEnd = url.range(of: "://") else { return url }
        let rest = url[schemeEnd.upperBound...]
        let netEnd = rest.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) ?? rest.endIndex
        let netloc = rest[..<netEnd]
        guard !netloc.unicodeScalars.allSatisfy(\.isASCII) else { return url }
        let userEnd = netloc.lastIndex(of: "@").map { netloc.index(after: $0) } ?? netloc.startIndex
        let hostPort = netloc[userEnd...]
        guard !hostPort.hasPrefix("[") else { return url }
        let hostEnd = hostPort.firstIndex(of: ":") ?? hostPort.endIndex
        let host = hostPort[..<hostEnd].precomposedStringWithCanonicalMapping
        var labels: [String] = []
        for label in host.split(separator: ".", omittingEmptySubsequences: false) {
            if label.unicodeScalars.allSatisfy(\.isASCII) { labels.append(String(label)); continue }
            guard let a = Punycode.idnaLabel(Array(label.unicodeScalars)) else { return nil }
            labels.append(String(String.UnicodeScalarView(a)))
        }
        return String(url[..<schemeEnd.upperBound]) + netloc[..<userEnd] + labels.joined(separator: ".")
            + hostPort[hostEnd...] + rest[netEnd...]
    }

    /// `registrable_domain`: `paypal.com` for `paypal.com`, `https://www.paypal.com/x` or `login.paypal.com`; nil
    /// when the site does not parse or has no registrable domain with a dot.
    public static func registrableDomain(_ site: String?, matcher: URLMatcher) -> String? {
        guard let text = asURL(site), let host = try? URLMatcher.hostOf(text),
              let domain = try? matcher.baseDomain(host), !domain.isEmpty,
              domain.contains(".") || Origin.isLoopback(domain) else { return nil }
        return domain
    }

    /// `site_host`: the lower-case host an agent named (`login.paypal.com` for `https://login.paypal.com/x`).
    public static func siteHost(_ site: String?) -> String? {
        guard let text = asURL(site), let host = try? URLMatcher.hostOf(text) else { return nil }
        var scalars = Array(host.lowercased().unicodeScalars)
        while scalars.last == "." { scalars.removeLast() }
        return scalars.isEmpty ? nil : String(String.UnicodeScalarView(scalars))
    }

    /// `origin_domain`: the registrable domain of a page origin; https, or plain http on a loopback host.
    public static func originDomain(_ origin: String, matcher: URLMatcher) -> String? {
        guard let canonical = try? Origin.canonicalize(origin) else { return nil }
        if !canonical.hasPrefix("https://") {
            // Plain http only on loopback, like the extension's own fill (`canonicalize_origin`).
            guard canonical.hasPrefix("http://"), let host = siteHost(canonical),
                  Origin.isLoopback(host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))) else { return nil }
        }
        return registrableDomain(canonical, matcher: matcher)
    }

    /// `agents_may_use`: true only when the owner turned on "AI agents may use this login" (`scope.ai_agents` is
    /// exactly `true`); missing or malformed is off.
    public static func agentsMayUse(_ record: [String: JSONValue]) -> Bool {
        guard case .object(let scope)? = record["scope"] else { return false }
        return scope[scopeKey] == .bool(true)
    }

    /// WebAuthn's rule: a passkey for `rpID` signs in on `rpID` and its subdomains, inside one site.
    static func rpCovers(_ rpID: String, host: String, domain: String, matcher: URLMatcher) -> Bool {
        var scalars = Array(Normalise.pyStrip(rpID).lowercased().unicodeScalars)
        while scalars.last == "." { scalars.removeLast() }
        let rp = String(String.UnicodeScalarView(scalars))
        guard !rp.isEmpty, registrableDomain(rp, matcher: matcher) == domain else { return false }
        return host == rp || host.hasSuffix("." + rp)
    }

    /// `site_passkeys`: the credential ids of the saved passkeys a login has for these sign-in hosts. A passkey
    /// belongs to the site when its relying party covers one of the hosts; when some of them name the login's user
    /// name only those count, otherwise every passkey for the site counts (a doubtful match prefers the passkey).
    public static func sitePasskeys(username: String, hosts: [String], domain: String, passkeys: [AgentPasskey],
                                    matcher: URLMatcher) -> Set<String> {
        let hosts = hosts.filter { !$0.isEmpty }
        let site = passkeys.filter { passkey in
            !passkey.credentialID.isEmpty
                && hosts.contains(where: { rpCovers(passkey.rpID, host: $0, domain: domain, matcher: matcher) })
        }
        let name = Casefold.fold(Normalise.pyStrip(username))
        let same = name.isEmpty ? [] : site.filter { pyEqual(Casefold.fold(Normalise.pyStrip($0.userName)), name) }
        return Set((same.isEmpty ? site : same).map(\.credentialID))
    }
}

/// Names and credential ids of one saved passkey (`passkey_metadata`: never key material).
public struct AgentPasskey: Equatable, Sendable {
    public let credentialID: String
    public let rpID: String
    public let userName: String
    public init(credentialID: String, rpID: String, userName: String) {
        self.credentialID = credentialID; self.rpID = rpID; self.userName = userName
    }

    /// From a passkey item's record (`payload.credential_id`, `relying_party_id`, `user_name`); nil for other kinds.
    public init?(record: [String: JSONValue]) {
        guard record["kind"] == .string("passkey"), case .object(let payload)? = record["payload"] else { return nil }
        func text(_ key: String) -> String { if case .string(let s)? = payload[key] { return s }; return "" }
        self.init(credentialID: text("credential_id"), rpID: text("relying_party_id"), userName: text("user_name"))
    }
}
