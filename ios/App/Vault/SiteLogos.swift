import Foundation
import SwiftUI
import AppShared

/// The bundled site logos (desktop `src/localvault/assets/site_logos.json`, built by
/// `scripts/build_site_logos.mjs`): when no website icon was downloaded (`SiteIcons.swift`), a web login
/// whose origin matches a listed domain shows the brand's glyph (`SiteLogos.xcassets`, "logo-<slug>") on the
/// brand colour instead of the kind symbol (`ItemAvatar`). Same matching as the desktop
/// (`webui/src/lib/siteLogos.js`).
struct SiteLogo: Equatable, Sendable {
    let slug: String
    let title: String
    /// 0xRRGGBB.
    let rgb: UInt32

    var imageName: String { "logo-" + slug }
    var color: Color {
        Color(red: Double((rgb >> 16) & 0xFF) / 255, green: Double((rgb >> 8) & 0xFF) / 255, blue: Double(rgb & 0xFF) / 255)
    }
    /// A light brand colour gets a dark glyph.
    var isLight: Bool {
        let r = Double((rgb >> 16) & 0xFF), g = Double((rgb >> 8) & 0xFF), b = Double(rgb & 0xFF)
        return (0.299 * r + 0.587 * g + 0.114 * b) / 255 > 0.7
    }
}

enum SiteLogos {
    struct Table: Sendable {
        let logos: [String: SiteLogo]
        let domains: [String: String]
    }

    static let shared: Table = load(Bundle.main.url(forResource: "site_logos", withExtension: "json").flatMap { try? Data(contentsOf: $0) })

    /// Parses the JSON; a missing or broken file gives an empty table (every row keeps its kind symbol).
    static func load(_ data: Data?) -> Table {
        guard let data, let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let logos = root["logos"] as? [String: [String: Any]], let domains = root["domains"] as? [String: String]
        else { return Table(logos: [:], domains: [:]) }
        var parsed: [String: SiteLogo] = [:]
        for (slug, entry) in logos {
            guard let hex = entry["hex"] as? String, hex.count == 7, hex.hasPrefix("#"),
                  let rgb = UInt32(hex.dropFirst(), radix: 16) else { continue }
            parsed[slug] = SiteLogo(slug: slug, title: entry["title"] as? String ?? slug, rgb: rgb)
        }
        return Table(logos: parsed, domains: domains)
    }

    /// The logo for an origin, or nil. A host matches a listed domain or any subdomain of it, never a
    /// lookalike (google.com.example.net has no logo).
    static func logo(for origin: String, in table: Table = shared) -> SiteLogo? {
        guard var host = URLComponents(string: origin)?.host?.lowercased(), !host.isEmpty else { return nil }
        if host.hasSuffix(".") { host.removeLast() }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return nil }
        for i in 0..<(labels.count - 1) {
            let domain = labels[i...].joined(separator: ".")
            if let slug = table.domains[domain], let logo = table.logos[slug] { return logo }
        }
        return nil
    }
}

extension VaultItem {
    /// The bundled logo for a web login's origin.
    var siteLogo: SiteLogo? {
        guard kind == "web", let origin = record["scope"]?.objectValue?["origin"]?.stringValue else { return nil }
        return SiteLogos.logo(for: origin)
    }
}
