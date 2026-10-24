import XCTest
import AppShared
@testable import LocalGateKeys

/// The editor's Website field: what people type, reduced to the origin the desktop stores.
@MainActor
final class WebsiteInputTests: XCTestCase {
    let clock = TestClock(1_800_000_000)

    func test_bare_domain_gets_https() throws {
        XCTAssertEqual(try WebsiteInput.origin("github.com"), "https://github.com")
        XCTAssertEqual(try WebsiteInput.origin("  GitHub.com \n"), "https://github.com")
        XCTAssertEqual(try WebsiteInput.origin("localhost:3000"), "https://localhost:3000")
    }

    func test_url_with_path_query_or_fragment_is_reduced_to_its_origin() throws {
        XCTAssertEqual(try WebsiteInput.origin("https://github.com/login?x=1"), "https://github.com")
        XCTAssertEqual(try WebsiteInput.origin("github.com/login#top"), "https://github.com")
        XCTAssertEqual(try WebsiteInput.origin("https://github.com:443/"), "https://github.com")
        XCTAssertEqual(try WebsiteInput.origin("https://shop.example:8443/a/b"), "https://shop.example:8443")
        XCTAssertEqual(try WebsiteInput.origin("http://localhost:8080/admin"), "http://localhost:8080")
    }

    func test_plain_http_for_a_public_host_follows_canonicalize() {
        // Origin.canonicalize allows plain HTTP only for loopback hosts.
        XCTAssertThrowsError(try WebsiteInput.origin("HTTP://Example.COM:8080/a")) { e in
            XCTAssertEqual(e as? WebsiteInputError, .invalid(WebsiteInput.httpMessage))
        }
        XCTAssertEqual(try WebsiteInput.origin("HTTPS://Example.COM:8080/a"), "https://example.com:8080")
    }

    func test_not_a_site_has_a_friendly_error() {
        for bad in ["not a site", "https://", "user@github.com", "ftp://github.com", "git hub.com/x", "github.com:99999"] {
            XCTAssertThrowsError(try WebsiteInput.origin(bad), bad) { e in
                XCTAssertEqual(e as? WebsiteInputError, .invalid(WebsiteInput.invalidMessage), bad)
            }
        }
        XCTAssertEqual(WebsiteInput.invalidMessage, "Enter a website like github.com")
    }

    func test_empty_website_is_required() {
        for empty in ["", "   "] {
            XCTAssertThrowsError(try WebsiteInput.origin(empty)) { e in XCTAssertEqual(e as? WebsiteInputError, .required) }
        }
    }

    func test_non_ascii_host_still_asks_for_punycode() {
        XCTAssertThrowsError(try WebsiteInput.origin("bücher.example/x")) { e in
            XCTAssertEqual(e as? WebsiteInputError, .needsPunycode)
        }
    }

    // MARK: through the editor

    func editor(_ store: MemoryStore, item: VaultItem? = nil) -> EditorModel {
        EditorModel(store: store, pro: ProModel(purchases: FakePurchases(), licenseKeys: [:]), editing: item, kind: .web,
                    clock: clock, random: CountingRandom(), background: FakeBackgroundTasks())
    }

    func storedOrigin(_ store: MemoryStore) -> JSONValue? {
        guard case .object(let w)? = store.snapshot.records.values.first, case .object(let r)? = w["record"],
              case .object(let scope)? = r["scope"] else { return nil }
        return scope["origin"]
    }

    func test_editor_saves_a_typed_domain_as_its_origin() {
        let store = MemoryStore()
        let e = editor(store)
        e.set("label", "GitHub"); e.set("username", "me"); e.set("password", "pw")
        e.set("origin", "github.com/login?return_to=x")
        XCTAssertEqual(e.save(), .saved, e.error ?? "")
        XCTAssertEqual(storedOrigin(store), .string("https://github.com"))
        XCTAssertNil(e.websiteError)
    }

    func test_editor_shows_friendly_inline_errors_and_writes_nothing() {
        let store = MemoryStore()
        let e = editor(store)
        e.set("label", "Site")
        XCTAssertEqual(e.save(), .invalid)
        XCTAssertEqual(e.websiteError, WebsiteInput.requiredMessage)
        XCTAssertEqual(WebsiteInput.requiredMessage, "Website is required")
        e.set("origin", "not a site")
        XCTAssertNil(e.websiteError, "editing the field clears its error")
        XCTAssertEqual(e.save(), .invalid)
        XCTAssertEqual(e.websiteError, "Enter a website like github.com")
        XCTAssertFalse(e.error?.contains("Origin") ?? false, "never the raw normaliser text")
        XCTAssertEqual(store.commits, 0)
    }

    func test_existing_login_still_saves_unchanged() {
        let store = MemoryStore(snapshot([webLogin]))
        let e = editor(store, item: VaultItem.items(from: store.snapshot)[0])
        XCTAssertEqual(e.save(), .unchanged)
        XCTAssertEqual(store.commits, 0)
    }
}
