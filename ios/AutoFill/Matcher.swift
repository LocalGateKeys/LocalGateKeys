import Foundation
import AuthenticationServices
import AppShared

/// A web login the extension can fill.
struct AutoFillLogin: Equatable, Sendable {
    let id: String
    let title: String
    let username: String
    let password: String
    /// `totp` of the record, when it has a secret.
    let totp: TOTPSpec?

    struct TOTPSpec: Equatable, Sendable {
        let secret: String, algorithm: String, digits: Int, period: Int
    }
}

/// Matches AutoFill service identifiers against the vault with the desktop's rules (`URLMatcher`, a port
/// of `localvault.origin`): exact origin first, then the `scope.urls` modes, then most recently updated.
struct AutoFillMatcher: Sendable {
    let matcher: URLMatcher

    /// The desktop's Public Suffix List snapshot, bundled from `src/localvault/assets/` by project.yml.
    /// Missing or truncated: `base_domain` matches the exact host only, as on the desktop.
    static func bundled(_ bundle: Bundle = .main) -> AutoFillMatcher {
        let rules = bundle.url(forResource: "public_suffix_list", withExtension: "dat")
            .flatMap { try? String(contentsOf: $0, encoding: .utf8) }
            .flatMap(PublicSuffixRules.load(listText:))
        return AutoFillMatcher(matcher: URLMatcher(rules: rules))
    }

    /// The candidate page URL for one service identifier. A `.domain` identifier (a native app's
    /// associated domain) is the HTTPS origin of that host.
    static func candidateURL(_ identifier: String, isDomain: Bool) -> String {
        isDomain ? "https://" + identifier + "/" : identifier
    }

    static func candidateURLs(_ ids: [ASCredentialServiceIdentifier]) -> [String] {
        ids.map { candidateURL($0.identifier, isDomain: $0.type == .domain) }
    }

    /// Live web logins of a snapshot: not deleted, entry namespace, decodable.
    static func logins(_ snapshot: StoreSnapshot) -> [(record: [String: JSONValue], login: AutoFillLogin)] {
        snapshot.records.keys.sorted(by: Scalars.less).compactMap { id in
            if snapshot.meta[id]?.deleted == true { return nil }
            guard case .object(let w)? = snapshot.records[id], case .string(let ns)? = w["ns"],
                  Scalars.equal(ns, Namespace.entry.rawValue), case .object(let r)? = w["record"],
                  case .string(let kind)? = r["kind"], Scalars.equal(kind, "web") else { return nil }
            return (r, login(id: id, record: r))
        }
    }

    static func login(id: String, record r: [String: JSONValue]) -> AutoFillLogin {
        func str(_ k: String) -> String { if case .string(let s)? = r[k] { return s }; return "" }
        var totp: AutoFillLogin.TOTPSpec?
        if case .object(let t)? = r["totp"], case .string(let secret)? = t["secret"] {
            func int(_ k: String, _ d: Int) -> Int { if case .int(let n)? = t[k] { return Int(n) }; return d }
            var alg = "SHA1"
            if case .string(let a)? = t["algorithm"] { alg = a }
            totp = .init(secret: secret, algorithm: alg, digits: int("digits", 6), period: int("period", 30))
        }
        var title = str("title")
        if title.isEmpty { title = str("label") }
        if title.isEmpty, case .object(let scope)? = r["scope"], case .string(let o)? = scope["origin"] { title = o }
        return AutoFillLogin(id: id, title: title, username: str("username"), password: str("password"), totp: totp)
    }

    /// The page URLs a login may be offered on, as the desktop broker does before matching: only those whose
    /// origin `Origin.canonicalize` accepts (HTTPS, or plain HTTP on loopback). A plain-HTTP page (anyone on
    /// the same Wi-Fi can serve one) must not be offered an HTTPS login whose `host`/`base_domain` row
    /// ignores the scheme (audit 2026-10-24 M-4).
    static func secureURLs(_ urls: [String]) -> [String] {
        urls.filter { url in
            guard let origin = try? Origin.originOf(url) else { return false }
            return (try? Origin.canonicalize(origin)) != nil
        }
    }

    /// Matching logins, best first. Insecure page URLs are dropped first (`secureURLs`).
    func matches(_ snapshot: StoreSnapshot, urls: [String]) -> [AutoFillLogin] {
        let pages = Self.secureURLs(urls)
        guard !pages.isEmpty else { return [] }
        let all = Self.logins(snapshot)
        return matcher.candidates(all.map(\.record), urls: pages).map { all[$0].login }
    }

    /// For the trace: why an id is not a fillable login (absent, deleted, other namespace or kind). Never content.
    static func traceKind(id: String, in snapshot: StoreSnapshot) -> TraceMessage {
        guard let key = snapshot.records.keys.first(where: { Scalars.equal($0, id) }) else {
            return "present=false records=\(snapshot.records.count)"
        }
        let deleted = snapshot.meta[key]?.deleted == true
        var nsIsEntry = false, kindIsWeb = false, hasRecord = false
        if case .object(let w)? = snapshot.records[key] {
            if case .string(let ns)? = w["ns"] { nsIsEntry = Scalars.equal(ns, Namespace.entry.rawValue) }
            if case .object(let r)? = w["record"] {
                hasRecord = true
                if case .string(let k)? = r["kind"] { kindIsWeb = Scalars.equal(k, "web") }
            }
        }
        return "present=true deleted=\(deleted) nsIsEntry=\(nsIsEntry) hasRecord=\(hasRecord) kindIsWeb=\(kindIsWeb)"
    }

    /// The login an identity names (its record identifier is the item id), if it is still live.
    func login(id: String, in snapshot: StoreSnapshot) -> AutoFillLogin? {
        Self.logins(snapshot).first { Scalars.equal($0.login.id, id) }?.login
    }
}
