import XCTest
@testable import AppShared

final class WhatsNewTests: XCTestCase {
    func test_shows_once_after_an_update() {
        XCTAssertTrue(WhatsNew.shouldShow(seen: "", itemCount: 3, setupPagesOpen: false))
        XCTAssertTrue(WhatsNew.shouldShow(seen: "1.0.1", itemCount: 3, setupPagesOpen: false))
        XCTAssertFalse(WhatsNew.shouldShow(seen: WhatsNew.version, itemCount: 3, setupPagesOpen: false))
    }

    func test_waits_for_the_setup_pages() {
        XCTAssertFalse(WhatsNew.shouldShow(seen: "", itemCount: 3, setupPagesOpen: true))
    }

    func test_a_new_vault_skips_it() {
        XCTAssertFalse(WhatsNew.shouldShow(seen: "", itemCount: 0, setupPagesOpen: false))
        XCTAssertTrue(WhatsNew.skipsForever(seen: "", itemCount: 0))
        XCTAssertFalse(WhatsNew.skipsForever(seen: "", itemCount: 1))
    }

    func test_the_setting_round_trips() {
        let settings = AppSettings(defaults: UserDefaults(suiteName: "wn-\(UUID().uuidString)")!)
        XCTAssertEqual(settings.whatsNewSeen, "")
        settings.whatsNewSeen = WhatsNew.version
        XCTAssertEqual(settings.whatsNewSeen, WhatsNew.version)
    }

    func test_every_item_has_text() {
        XCTAssertFalse(WhatsNew.items.isEmpty)
        for item in WhatsNew.items { XCTAssertFalse(item.title.isEmpty || item.detail.isEmpty || item.symbol.isEmpty) }
    }
}
