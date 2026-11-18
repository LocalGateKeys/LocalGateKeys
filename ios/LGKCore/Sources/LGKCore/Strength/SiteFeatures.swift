import Foundation

/// Which sites offer two-factor codes (TOTP) or passkeys, from the bundled `site_features.json` (desktop
/// `site_features.SiteFeatures`). Keys of the data file are registrable domains; `supports` reduces any host the same
/// way (`URLMatcher.baseDomain`, Public Suffix List) before looking it up, so `login.github.com` finds `github.com`.
public struct SiteFeatures: Sendable {
    public static let features: Set<String> = ["passkey", "totp"]
    /// No data: no 2FA or passkey hints.
    public static let empty = SiteFeatures(sites: [:], matcher: URLMatcher(rules: nil))

    private let sites: [String: Set<String>]
    private let matcher: URLMatcher

    public init(sites: [String: Set<String>], matcher: URLMatcher) {
        var clean: [String: Set<String>] = [:]
        for (domain, list) in sites { clean[domain.lowercased()] = list.intersection(Self.features) }
        self.sites = clean
        self.matcher = matcher
    }

    /// A missing or malformed file gives an empty map (no hints).
    public init(json: Data, matcher: URLMatcher = URLMatcher(rules: nil)) {
        var sites: [String: Set<String>] = [:]
        if let root = try? JSONSerialization.jsonObject(with: json) as? [String: Any],
           let raw = root["sites"] as? [String: Any] {
            for (domain, list) in raw {
                if let names = list as? [String] { sites[domain] = Set(names) }
            }
        }
        self.init(sites: sites, matcher: matcher)
    }

    /// The bundled `site_features.json` and `public_suffix_list.dat` (both listed in project.yml); empty if missing.
    public static func bundled(_ bundle: Bundle = .main) -> SiteFeatures {
        let rules = bundle.url(forResource: "public_suffix_list", withExtension: "dat")
            .flatMap { try? String(contentsOf: $0, encoding: .utf8) }
            .flatMap(PublicSuffixRules.load(listText:))
        guard let url = bundle.url(forResource: "site_features", withExtension: "json"),
              let data = try? Data(contentsOf: url) else { return .empty }
        return SiteFeatures(json: data, matcher: URLMatcher(rules: rules))
    }

    /// Registrable domains that already have a passkey item, from the items' `payload.relying_party_id` values.
    public func passkeyDomains(relyingPartyIDs: [String]) -> Set<String> {
        Set(relyingPartyIDs.filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            .compactMap { registrableDomain(of: $0) })
    }

    public var isEmpty: Bool { sites.isEmpty }

    /// The registrable domain of `host`, nil when it does not parse (desktop `base_domain`).
    public func registrableDomain(of host: String) -> String? {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return try? matcher.baseDomain(trimmed)
    }

    public func supports(host: String, feature: String) -> Bool {
        guard let domain = registrableDomain(of: host) else { return false }
        return sites[domain]?.contains(feature) == true
    }
}

extension URLMatcher {
    /// The hosts of a login's saved URLs, and whether any is plain HTTP on a non-loopback host (desktop `_web_hosts`).
    /// A URL that does not parse as http(s) adds nothing.
    public static func webHosts(_ urls: [String]) -> (hosts: [String], insecure: Bool) {
        var hosts: [String] = [], insecure = false
        for url in urls {
            guard let parts = try? Origin.splitURL(url) else { continue }
            hosts.append(parts.1)
            if parts.0 == "http" && !Origin.isLoopback(parts.1) { insecure = true }
        }
        return (hosts, insecure)
    }
}
