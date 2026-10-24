import Foundation

/// The short name a website login gets from its origin (desktop `vault.py` `friendly_origin_label`): the host
/// without its port and without one common login subdomain. Shared by the vault list and the Safari import.
public enum OriginLabel {
    public static let loginSubdomains = ["www.", "app.", "login.", "accounts.", "account.", "auth.", "signin.", "secure.", "my.", "id."]

    /// "https://accounts.example.com:8443" -> "example.com". An IPv6 host or an empty one gives the origin back.
    public static func friendly(_ origin: String) -> String {
        var host = origin
        if let r = origin.range(of: "://") {
            host = String(origin[r.upperBound...].split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
            if let colon = host.lastIndex(of: ":") { host = String(host[..<colon]) }
        }
        if host.hasPrefix("[") { return origin }
        for p in loginSubdomains where host.hasPrefix(p) && host.filter({ $0 == "." }).count >= 2 {
            host = String(host.dropFirst(p.count)); break
        }
        return host.isEmpty ? origin : host
    }
}
