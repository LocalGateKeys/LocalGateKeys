import Foundation
import CryptoKit
import LGKCore

/// The saved sites for the Safari extension's site check (phishing shield, sub-plan 09).
///
/// Ruling T5b: `<SafariSave>/sites.bin` holds only the **registrable domains** of the saved web logins' URL rows
/// (`example.com` for `https://login.example.com/path`): no paths, no usernames, no full URLs. It is sealed
/// (AES-GCM, `SealedBlob`) under a subkey of the device-only Safari index key and written with the index after each
/// commit and unlock. It keeps working while the app is locked (the guard is most useful then), so the extension
/// process can read the list of saved domains while the device is unlocked (SECURITY.md). It classifies the page
/// origin in its own process (`SafariSaveService.siteVerdict`) and answers only the verdict, the imitated domain and
/// an opaque pair id: the list never reaches the extension's pages or storage. A deleted login's domain stays in
/// it until the next commit or unlock. The app itself classifies against the full URL rows (`urlRows`).
public enum SafariSites {
    public static let fileName = "sites.bin"
    static let version: Int64 = 1
    static let sealInfo = Array("localgatekeys|safari-sites|v1".utf8)
    static let pairInfo = Array("localgatekeys|site-pair|v1".utf8)
    static let aad = "localgatekeys/safari-sites/v1"

    public static func url(in directory: URL) -> URL {
        directory.appendingPathComponent(fileName, isDirectory: false)
    }

    /// Every URL row of every web login in `records` (a snapshot's id -> wrapper; deleted items are not in it),
    /// without duplicates, in item id order (the classifier gives ties to the earliest). In the app only.
    public static func urlRows(records: [String: JSONValue]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for id in records.keys.sorted() {
            guard case .object(let w)? = records[id], w["ns"] == .string(Namespace.entry.rawValue),
                  case .object(let rec)? = w["record"], rec["kind"] == .string("web") else { continue }
            for row in URLMatcher.entryURLs(rec) where seen.insert(row.url).inserted { out.append(row.url) }
        }
        return out
    }

    /// What `sites.bin` holds (Ruling T5b): the registrable domain of each URL row (by `matcher`'s Public Suffix
    /// List; without one, the host), once each, in `urlRows` order. A row whose host cannot be read is left out.
    public static func domains(records: [String: JSONValue], matcher: URLMatcher) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for url in urlRows(records: records) {
            guard var domain = try? matcher.baseDomainOf(url), !domain.isEmpty else { continue }
            if domain.contains(":") { domain = "[\(domain)]" }  // an IPv6 address, as a host
            if seen.insert(domain).inserted { out.append(domain) }
        }
        return out
    }

    static func sealKey(_ indexKey: [UInt8]) -> [UInt8] {
        CryptoBox.hkdf(ikm: indexKey, salt: [], info: sealInfo, length: 32)
    }

    /// `{"domains":[...],"version":1}` as canonical JSON, sealed.
    public static func seal(_ domains: [String], indexKey: [UInt8], random: any RandomSource) throws -> [UInt8] {
        let plain = try CanonicalJSON.encode(.object(["version": .int(version), "domains": .array(domains.map { .string($0) })]),
                                             dialect: .utf8)
        return try SealedBlob.seal(plain, key: sealKey(indexKey), aad: aad, random: random)
    }

    /// The domains in a `seal` blob; nil when it does not open under this key or is not version 1.
    public static func open(_ blob: [UInt8], indexKey: [UInt8]) -> [String]? {
        guard let plain = try? SealedBlob.open(blob, key: sealKey(indexKey), aad: aad),
              case .object(let o)? = try? CanonicalJSON.parse(plain), Set(o.keys) == ["version", "domains"],
              o["version"] == .int(version), case .array(let rows)? = o["domains"] else { return nil }
        var out: [String] = []
        out.reserveCapacity(rows.count)
        for row in rows {
            guard case .string(let s) = row else { return nil }
            out.append(s)
        }
        return out
    }

    /// Opaque id of a (page origin, saved origin) pair, for the extension's remembered "Same account" answers: the
    /// first 32 hex digits of HMAC-SHA256, under a subkey of the device-only index key, over `page origin \n saved
    /// origin` (desktop `site_pair_id`, Kotlin `SiteCheck.pairId`). Keyed, so whoever reads the extension's
    /// storage cannot test a list of popular sites against it.
    public static func pairID(indexKey: [UInt8], origin: String, saved: String) -> String {
        let sub = CryptoBox.hkdf(ikm: indexKey, salt: [], info: pairInfo, length: 32)
        let mac = HMAC<SHA256>.authenticationCode(for: Array("\(origin)\n\(saved)".utf8), using: SymmetricKey(data: sub))
        return Array(mac).prefix(16).map { String(format: "%02x", $0) }.joined()
    }
}
