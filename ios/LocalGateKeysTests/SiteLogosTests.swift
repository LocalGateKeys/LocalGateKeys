import XCTest
import UIKit
import AppShared
@testable import LocalGateKeys

/// The bundled site logos on web rows: same matching as the desktop (webui/src/lib/siteLogos.test.js).
final class SiteLogosTests: XCTestCase {
    func test_the_bundled_table_loads_and_every_logo_has_its_image() {
        let table = SiteLogos.shared
        XCTAssertGreaterThan(table.logos.count, 100, "site_logos.json is missing from the app bundle")
        for logo in table.logos.values {
            XCTAssertNotNil(UIImage(named: logo.imageName), "SiteLogos.xcassets has no \(logo.imageName)")
        }
        for (domain, slug) in table.domains { XCTAssertNotNil(table.logos[slug], domain) }
    }

    func test_a_domain_and_its_subdomains_match() {
        XCTAssertEqual(SiteLogos.logo(for: "https://github.com")?.slug, "github")
        XCTAssertEqual(SiteLogos.logo(for: "https://accounts.google.com")?.slug, "google")
        XCTAssertEqual(SiteLogos.logo(for: "https://www.netflix.com:443/")?.slug, "netflix")
        XCTAssertEqual(SiteLogos.logo(for: "https://mail.google.com")?.slug, "gmail", "the most specific domain wins")
    }

    func test_lookalikes_and_junk_get_no_logo() {
        XCTAssertNil(SiteLogos.logo(for: "https://google.com.example.net"))
        XCTAssertNil(SiteLogos.logo(for: "https://evilgoogle.com"))
        XCTAssertNil(SiteLogos.logo(for: "https://192.168.1.1"))
        XCTAssertNil(SiteLogos.logo(for: "not a url"))
        XCTAssertNil(SiteLogos.logo(for: ""))
    }

    func test_a_broken_file_gives_an_empty_table() {
        XCTAssertTrue(SiteLogos.load(nil).logos.isEmpty)
        XCTAssertTrue(SiteLogos.load(Data("{".utf8)).domains.isEmpty)
    }

    func test_light_brand_colours_get_a_dark_glyph() {
        XCTAssertTrue(SiteLogo(slug: "snapchat", title: "Snapchat", rgb: 0xFFFC00).isLight)
        XCTAssertFalse(SiteLogo(slug: "github", title: "GitHub", rgb: 0x181717).isLight)
    }

    func test_only_web_rows_use_a_logo() {
        let web = VaultItem(id: "w", record: ["kind": .string("web"), "title": .string("GitHub"),
                                              "scope": .object(["origin": .string("https://github.com")])])
        XCTAssertEqual(web?.siteLogo?.slug, "github")
        let note = VaultItem(id: "n", record: ["kind": .string("note"), "title": .string("github.com")])
        XCTAssertNil(note?.siteLogo)
    }
}
