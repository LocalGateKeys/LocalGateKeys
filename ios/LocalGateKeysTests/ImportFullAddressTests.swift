import XCTest
import AppShared
@testable import LocalGateKeys

/// Imported logins keep the full page address (tester report 2026-10-29): `https://www.abcdef.com/interface/login.aspx`
/// was saved as `https://www.abcdef.com`. Same cases as Windows `tests/test_import_full_url.py` and Android
/// `ImportFullAddressTest`.
@MainActor
final class ImportFullAddressTests: XCTestCase {
    private func row(_ url: String, _ match: String) -> JSONValue { .object(["url": .string(url), "match": .string(match)]) }

    func testFullAddressIsAStartsWithRowAfterTheExactOrigins() {
        let urls = ["https://www.abcdef.com/interface/login.aspx"]
        let (web, _, _) = ImportReviewModel.webRows(urls)
        XCTAssertEqual(web, ["https://www.abcdef.com"])
        XCTAssertEqual(ImportReviewModel.urlRows(web, pages: ImportReviewModel.webPages(urls, origins: web)),
                       .array([row("https://www.abcdef.com", "exact_origin"),
                               row("https://www.abcdef.com/interface/login.aspx", "starts_with")]))
    }

    func testBareSitesUpgradesAndLoopbackMatchWindows() {
        let urls = ["https://x.example.com/", "abc.example.com", "http://old.example.com/a?b=1#frag", "http://localhost:8080/p"]
        let (web, _, upgraded) = ImportReviewModel.webRows(urls)
        XCTAssertTrue(upgraded)
        XCTAssertEqual(ImportReviewModel.webPages(urls, origins: web), ["https://old.example.com/a?b=1", "http://localhost:8080/p"])
    }

    func testOpenWebsiteUsesThePageOnTheSameOrigin() {
        let scope: [String: JSONValue] = ["origin": .string("https://www.abcdef.com"),
                                          "urls": .array([row("https://www.abcdef.com", "exact_origin"),
                                                          row("https://www.abcdef.com/interface/login.aspx", "starts_with")])]
        XCTAssertEqual(VaultItem.pageAddress(scope), "https://www.abcdef.com/interface/login.aspx")
        let other: [String: JSONValue] = ["origin": .string("https://a.example"),
                                          "urls": .array([row("https://a.example", "exact_origin"),
                                                          row("https://b.example/x", "starts_with")])]
        XCTAssertEqual(VaultItem.pageAddress(other), "https://a.example")
        XCTAssertNil(VaultItem.pageAddress(nil))
    }

    func testChangingTheWebsiteMovesTheRowsOfTheOldSite() {
        let rows = [row("https://www.abcdef.com", "exact_origin"), row("https://sso.example.com", "exact_origin"),
                    row("https://www.abcdef.com/interface/login.aspx", "starts_with")]
        XCTAssertEqual(EditorModel.movedRows(rows, from: "https://www.abcdef.com", to: "https://new.example.com"),
                       .array([row("https://new.example.com", "exact_origin"), row("https://sso.example.com", "exact_origin")]))
    }
}
