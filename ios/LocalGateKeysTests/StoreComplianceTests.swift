import XCTest
import AppShared
@testable import LocalGateKeys

/// Plan 2026-10-29-appstore-licence Task 10 (App Store 3.1.1 / 3.1.3(b)): nothing the iPhone, Mac or extension
/// sources show or open leads to buying outside the App Store. Scans the string literals of the source folders
/// for shop pages, shop names, `$` prices and website paths outside the allow-list (the in-app legal pages and
/// the backup device namespace). Subdomains (the licence Worker) are services, not pages, and are not matched.
@MainActor
final class StoreComplianceTests: XCTestCase {
    private static let ios = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    private static let folders = ["App", "Mac", "AppShared", "AutoFill", "AutoFillMac", "SafariSave", "SafariMac"]
    /// The passphrase word list: its words ("paddle") are not wording about buying.
    private static let skipped: Set<String> = ["FallbackWordlist.swift"]

    private func regex(_ pattern: String, _ options: NSRegularExpression.Options = []) -> NSRegularExpression {
        // The patterns are constants; a typo fails every test here.
        try! NSRegularExpression(pattern: pattern, options: options)
    }

    /// Shop pages, shop names and `$` prices.
    private var shopWording: NSRegularExpression {
        regex(#"(?<![\w.-])localgatekeys\.app/(?!legal/app/|ios/backup-device)|buy\.html|pricing|paddle|lemon ?squeezy|\$\d"#,
              [.caseInsensitive])
    }

    /// Owner 2026-10-29: "In the App Store there is no mention of another vendor": payment providers and other
    /// stores or platforms, other cloud drives as selling points. "Windows" (the PC app) and the import sources the user picks (Bitwarden, Chrome CSV...)
    /// are allowed; the passphrase word list ("paddle", "stripe") is skipped.
    private var vendorWording: NSRegularExpression {
        regex(#"\b(paddle|lemon ?squeezy|stripe|google play|play store|android|microsoft|windows store|onedrive|google drive)\b"#, [.caseInsensitive])
    }

    /// Every string literal (and every line inside a `"""` literal) that matches a forbidden pattern.
    private func hits(in text: String, file: String, forbidden given: NSRegularExpression? = nil) -> [String] {
        let forbidden = given ?? shopWording
        let literal = regex(#""(?:[^"\\\n]|\\.)*""#)
        // Interpolations are code, not text (`\($0)` is no price); two levels of parentheses are enough here.
        let interpolation = regex(#"\\\((?:[^()]|\([^()]*\))*\)"#)
        func whole(_ s: String) -> NSRange { NSRange(s.startIndex..., in: s) }
        var out: [String] = []
        var inMultiline = false
        for (n, raw) in text.components(separatedBy: "\n").enumerated() {
            let line = interpolation.stringByReplacingMatches(in: raw, range: whole(raw), withTemplate: "")
            let triples = line.components(separatedBy: "\"\"\"").count - 1
            let pieces: [String] = inMultiline && triples == 0
                ? [line]
                : literal.matches(in: line, range: whole(line)).compactMap { Range($0.range, in: line).map { String(line[$0]) } }
            if triples % 2 == 1 { inMultiline.toggle() }
            for piece in pieces where forbidden.firstMatch(in: piece, range: whole(piece)) != nil {
                out.append("\(file):\(n + 1): \(piece)")
            }
        }
        return out
    }

    func test_sources_have_no_shop_links_names_or_prices() throws {
        var found: [String] = []
        var scanned = 0
        for folder in Self.folders {
            let dir = Self.ios.appendingPathComponent(folder)
            guard let walk = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: nil) else { continue }
            for case let url as URL in walk where url.pathExtension == "swift" && !Self.skipped.contains(url.lastPathComponent) {
                let text = try String(contentsOf: url, encoding: .utf8)
                found += hits(in: text, file: "\(folder)/\(url.lastPathComponent)")
                scanned += 1
            }
        }
        XCTAssertGreaterThan(scanned, 100, "the sources were found")
        XCTAssertEqual(found, [])
    }

    /// The Swift sources (string literals) and every Info.plist, .strings and .stringsdict file (whole lines).
    private func vendorHits() throws -> (found: [String], scanned: Int) {
        var found: [String] = []
        var scanned = 0
        for folder in Self.folders + ["Watch"] {
            let dir = Self.ios.appendingPathComponent(folder)
            guard let walk = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: nil) else { continue }
            for case let url as URL in walk where !Self.skipped.contains(url.lastPathComponent) {
                let name = "\(folder)/\(url.lastPathComponent)"
                let ext = url.pathExtension
                guard ["swift", "plist", "strings", "stringsdict"].contains(ext) else { continue }
                let text = try String(contentsOf: url, encoding: .utf8)
                found += ext == "swift" ? hits(in: text, file: name, forbidden: vendorWording) : lineHits(in: text, file: name)
                scanned += 1
            }
        }
        // The display names and usage strings XcodeGen writes into the Info.plists (comments are not shown).
        let project = try String(contentsOf: Self.ios.appendingPathComponent("project.yml"), encoding: .utf8)
        let shown = project.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces).hasPrefix("#") ? "" : $0 }
        found += lineHits(in: shown.joined(separator: "\n"), file: "project.yml")
        return (found, scanned)
    }

    private func lineHits(in text: String, file: String) -> [String] {
        text.components(separatedBy: "\n").enumerated().compactMap { n, line in
            vendorWording.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) == nil ? nil : "\(file):\(n + 1): \(line)"
        }
    }

    func test_sources_name_no_other_vendor() throws {
        let (found, scanned) = try vendorHits()
        XCTAssertGreaterThan(scanned, 100, "the sources were found")
        XCTAssertEqual(found, [])
    }

    func test_scanner_catches_vendor_names() {
        let v = vendorWording
        XCTAssertFalse(hits(in: #"Text("Restore a backup from your Android phone")"#, file: "x", forbidden: v).isEmpty)
        XCTAssertFalse(hits(in: #"Text("Also on Google Play and the Microsoft Store")"#, file: "x", forbidden: v).isEmpty)
        XCTAssertFalse(hits(in: #"Text("Payments by Stripe")"#, file: "x", forbidden: v).isEmpty)
        XCTAssertFalse(lineHits(in: "<string>Works with Android</string>", file: "x").isEmpty)
        XCTAssertTrue(hits(in: #"Text("Sync with the Windows app")"#, file: "x", forbidden: v).isEmpty)
        XCTAssertTrue(hits(in: #"Text("Bitwarden JSON")"#, file: "x", forbidden: v).isEmpty, "import sources stay")
        XCTAssertTrue(hits(in: "// Android `HostDiscovery.kt`", file: "x", forbidden: v).isEmpty, "comments are not text")
        XCTAssertTrue(hits(in: #"Text("pinstripe")"#, file: "x", forbidden: v).isEmpty)
    }

    func test_scanner_catches_shop_wording() {
        XCTAssertFalse(hits(in: #"let u = "https://localgatekeys.app/buy.html""#, file: "x").isEmpty)
        XCTAssertFalse(hits(in: #"let u = "https://localgatekeys.app/legal/privacy.html""#, file: "x").isEmpty)
        XCTAssertFalse(hits(in: #"Text("Only $4.99 on our website")"#, file: "x").isEmpty)
        XCTAssertFalse(hits(in: #"Text("Paid with Paddle")"#, file: "x").isEmpty)
        XCTAssertFalse(hits(in: "let s = \"\"\"\nSee our pricing page\n\"\"\"", file: "x").isEmpty)
        XCTAssertTrue(hits(in: #"let u = "https://localgatekeys.app/legal/app/eula.html""#, file: "x").isEmpty)
        XCTAssertTrue(hits(in: #"let u = "https://licenses.localgatekeys.app/appstore/claim""#, file: "x").isEmpty)
        XCTAssertTrue(hits(in: #"Text("Buy Pro – \(price.map { $0 } ?? "")")"#, file: "x").isEmpty)
        XCTAssertTrue(hits(in: #"items.map { $0.title }"#, file: "x").isEmpty, "code outside literals is not text")
    }

    func test_legal_links_open_the_in_app_pages() {
        XCTAssertEqual(SettingsView.privacyPolicyURL.absoluteString, "https://localgatekeys.app/legal/app/privacy.html")
        XCTAssertEqual(SettingsView.licenceAgreementURL.absoluteString, "https://localgatekeys.app/legal/app/eula.html")
        // The backup device namespace is a UUID5 name, never opened: it must stay as it is (device ids depend on it).
        XCTAssertEqual(VaultExporter.deviceNamespace, UUID5.make(namespace: UUID5.namespaceURL, name: "https://localgatekeys.app/ios/backup-device"))
    }
}
