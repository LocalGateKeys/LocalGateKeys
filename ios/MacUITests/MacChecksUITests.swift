import XCTest

/// Hands-on Mac checks from docs/PENDING.md, driven on the app's demo preview (`LGK_MAC_SHELL_PREVIEW=1`: a demo
/// vault in a temporary folder with an in-memory Keychain, no master password). Run them through
/// `scripts/mac_ui_checks.sh`, which builds with a separate bundle prefix so the app under test never shares the
/// installed app's container or Keychain.
final class MacChecksUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_MAC_UI_CHECKS"] == "1", "run through scripts/mac_ui_checks.sh")
    }

    @MainActor
    private func launch(_ environment: [String: String] = [:], arguments: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment.merge(environment) { $1 }
        app.launchArguments += arguments
        app.launchEnvironment["LGK_MAC_ALLOW_CAPTURE"] = "1"
        app.launchEnvironment["LGK_MAC_SHELL_PREVIEW"] = "1"
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20), "the main window opened")
        let skip = app.buttons["Skip setup"]
        if skip.waitForExistence(timeout: 3) { skip.click() }
        return app
    }

    @MainActor
    private func shot(_ app: XCUIApplication, _ name: String) {
        let a = XCTAttachment(screenshot: app.screenshot()); a.name = name; a.lifetime = .keepAlways
        add(a)
    }

    @MainActor
    private func texts(_ app: XCUIApplication) -> [String] {
        guard let snap = try? app.windows.firstMatch.snapshot() else { return [] }
        var out: [String] = []
        func walk(_ s: XCUIElementSnapshot) {
            for t in [s.label, s.title, (s.value as? String) ?? ""] where !t.isEmpty { out.append(t) }
            s.children.forEach(walk)
        }
        walk(snap)
        return out
    }

    @MainActor
    func testOneTimeCodesFoldIsKeptAfterARelaunch() throws {
        var app = launch()
        let collapse = app.buttons["Collapse one-time codes"]
        let codes = app.buttons["Copy 2FA code for github.com"]
        // A previous run may have left the section folded: start unfolded.
        let unfold = app.buttons["Expand one-time codes"]
        if unfold.waitForExistence(timeout: 3) { unfold.click() }
        XCTAssertTrue(collapse.waitForExistence(timeout: 5))
        XCTAssertTrue(codes.exists, "codes shown at first")
        collapse.click()
        XCTAssertTrue(codes.waitForNonExistence(timeout: 3), "folding hides the codes")
        shot(app, "codes-folded")
        app.terminate()
        app = launch()
        XCTAssertFalse(app.buttons["Copy 2FA code for github.com"].waitForExistence(timeout: 3), "still folded after a relaunch")
        let expand = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Expand' OR label BEGINSWITH 'Show'")).firstMatch
        XCTAssertTrue(expand.exists, "an unfold button is offered")
        expand.click()
        XCTAssertTrue(app.buttons["Copy 2FA code for github.com"].waitForExistence(timeout: 3), "unfolding shows the codes")
        // Keyboard: the button folds again from the keyboard (focus it, Space).
        app.buttons["Collapse one-time codes"].firstMatch.click()
        app.typeKey(" ", modifierFlags: [])
        shot(app, "codes-after-keyboard")
        XCTAssertTrue(app.buttons["Copy 2FA code for github.com"].waitForNonExistence(timeout: 3), "Space on the button folds too")
    }

    @MainActor
    func testLicencePageShowsTheFreePlanAndBuyPro() throws {
        let app = launch()
        // Since the UX refresh the Licence page opens from Settings > Plan > Licence > Open.
        app.buttons["Settings"].firstMatch.click()
        let plan = app.descendants(matching: .any).matching(NSPredicate(format: "label == 'Plan'")).firstMatch
        XCTAssertTrue(plan.waitForExistence(timeout: 5), "Settings shows the Plan tab")
        plan.click()
        let open = app.buttons["Open"].firstMatch
        XCTAssertTrue(open.waitForExistence(timeout: 5), "the Licence row's Open button")
        open.click()
        sleep(2)
        shot(app, "licence")
        let page = texts(app)
        XCTAssertTrue(page.contains("Pro unlocks unlimited items, 2FA codes and Wi-Fi sync hosting. Buy it on the App Store, or pair this Mac with a device that has Pro."))
        XCTAssertTrue(page.contains("Free plan: up to 7 items. Upgrade to Pro to add more."), "the free plan shows the 7-item limit")
        XCTAssertTrue(app.buttons["Buy Pro"].exists)
        // The upgrade sheet's price and "One payment. Every update, forever, free." need the store, which these UI
        // tests do not load ("Pro isn't available yet"): that sheet stays a manual check.
    }

    /// The Pro sheet (`LGK_MAC_UPGRADE=1` opens it) carries the lifetime wording, in English and in German.
    @MainActor
    func testUpgradeSheetSaysOnePaymentEveryUpdate() throws {
        for (language, line) in [("en", "One payment. Every update, forever, free. No subscription."),
                                 ("de", "Eine Zahlung. Jedes Update, für immer, kostenlos. Kein Abonnement.")] {
            let app = launch(["LGK_MAC_UPGRADE": "1"], arguments: ["-AppleLanguages", "(\(language))"])
            let text = app.staticTexts.matching(NSPredicate(format: "label == %@ OR value == %@", line, line)).firstMatch
            let found = text.waitForExistence(timeout: 10)
            shot(app, "upgrade-sheet-\(language)")
            if !found { print("MAC-CHECK sheet texts:", texts(app).filter { $0.count > 20 }.prefix(20)) }
            XCTAssertTrue(found, "the Pro sheet shows the lifetime line in \(language)")
            app.terminate()
        }
    }
}
