import XCTest
@testable import AppShared

/// UX plan workstream 4 (Android `OnboardingTest`, Windows `test_onboarding.py`): skip all → card shows; finish all →
/// card gone; hide → stays hidden; Show setup again reopens; progress lives in this device's settings only.
@MainActor
final class OnboardingTests: XCTestCase {
    private func settings() -> AppSettings {
        let name = "onboarding-\(UUID().uuidString)"
        let d = UserDefaults(suiteName: name)!
        d.removePersistentDomain(forName: name)
        return AppSettings(defaults: d)
    }

    func test_five_steps_in_order() {
        XCTAssertEqual(SetupStep.allCases.map(\.rawValue), ["vault", "unlock", "import", "phrase", "autofill"])
        XCTAssertEqual(Onboarding.pageCount(.importItems), "Step 3 of 5")
        XCTAssertEqual(Onboarding.cardText(done: 3, total: 5), "Finish setting up · 3 of 5")
        XCTAssertEqual(Onboarding.skip, "Skip")
        XCTAssertEqual(Onboarding.skipSetup, "Skip setup")
        XCTAssertEqual(Onboarding.hide, "Hide")
        XCTAssertEqual(Onboarding.showAgainTitle, "Show setup again")
    }

    func test_first_run_opens_the_pages_at_the_first_open_step() {
        let o = Onboarding(settings: settings())
        XCTAssertTrue(o.pagesOpen)
        XCTAssertEqual(o.done, [.vault])
        XCTAssertEqual(o.firstPage(), .unlock)
        XCTAssertNil(o.cardText)   // never while the pages show
    }

    func test_skip_setup_leaves_the_card_with_the_steps_left() {
        let s = settings()
        let o = Onboarding(settings: s)
        o.closePages()
        XCTAssertEqual(o.cardText, "Finish setting up · 1 of 5")
        XCTAssertEqual(o.remaining, [.unlock, .importItems, .phrase, .autofill])
        XCTAssertFalse(Onboarding(settings: s).pagesOpen)   // the pages do not open again by themselves
    }

    func test_finishing_every_step_removes_the_card() {
        let o = Onboarding(settings: settings())
        o.complete(.unlock)
        XCTAssertEqual(o.next(after: .vault), .importItems)
        o.complete(.importItems); o.complete(.phrase)
        o.closePages()
        XCTAssertEqual(o.cardText, "Finish setting up · 4 of 5")
        XCTAssertNil(o.next(after: .autofill))
        o.detected([.autofill])
        XCTAssertNil(o.cardText)
        XCTAssertEqual(o.firstPage(), .vault)
    }

    func test_hide_stays_hidden_until_show_setup_again() {
        let s = settings()
        let o = Onboarding(settings: s)
        o.closePages()
        o.hideCard()
        XCTAssertNil(o.cardText)
        XCTAssertNil(Onboarding(settings: s).cardText)   // after a relaunch too
        o.showAgain()
        XCTAssertTrue(o.pagesOpen)
        o.closePages()
        XCTAssertEqual(o.cardText, "Finish setting up · 1 of 5")
    }

    func test_progress_is_local_settings_only() {
        let s = settings()
        let o = Onboarding(settings: s)
        o.complete(.phrase); o.complete(.vault)
        XCTAssertEqual(s.setupDone, ["phrase"])   // the vault step is implied, never stored
        s.setupDone = ["phrase", "unknown"]
        XCTAssertEqual(Onboarding(settings: s).done, [.vault, .phrase])
        for key in [AppSettings.Key.setupDone, AppSettings.Key.setupSeen, AppSettings.Key.setupCardHidden] {
            XCTAssertTrue(AppSettings.Key.all.contains(key))
        }
    }
}
