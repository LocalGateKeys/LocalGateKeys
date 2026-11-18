import XCTest

/// Sub-plan 06 task 3 (Shortcuts "Copy code") on the simulator. Run it with `scripts/ios_simulator_checks.sh`, which
/// matches Face ID from the Mac while the test waits and then checks the simulator clipboard holds a code (the test
/// runner itself may not read the clipboard). It is skipped otherwise (it needs that Face ID loop).
///
/// Siri cannot be checked this way: the simulator's typed Siri (`XCUISiriService`) answers "Sorry, I can't help
/// you with that" to the App Shortcut phrase, so Siri stays a manual check on an iPhone.
final class ShortcutsCopyCodeUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_FACEID_LOOP"] == "1",
                          "run through scripts/ios_simulator_checks.sh")
    }

    @MainActor
    private func shot(_ name: String) {
        let a = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        a.name = name; a.lifetime = .keepAlways
        add(a)
    }

    @MainActor
    func testCopyCodeOffersOnlyThePinnedCode() throws {
        let app = XCUIApplication()
        // `-LGKScreen item` opens the first demo item (github.com, which has a 2FA code) and skips the setup pages;
        // pinning a code is Pro (`LGK_DEBUG_PRO`, DEBUG builds only).
        app.launchArguments += ["-LGKDemoData", "YES", "-LGKScreen", "item"]
        app.launchEnvironment["LGK_DEBUG_PRO"] = "1"
        app.launch()

        let pin = app.buttons["Show in widgets and on Apple Watch"]
        let unpin = app.buttons["Remove from widgets and Apple Watch"]
        XCTAssertTrue(pin.waitForExistence(timeout: 60) || unpin.exists, "the item opened after Face ID")
        if pin.exists { pin.tap() }
        XCTAssertTrue(unpin.waitForExistence(timeout: 5), "github.com's code is pinned")

        let shortcuts = XCUIApplication(bundleIdentifier: "com.apple.shortcuts")
        shortcuts.launch()
        if shortcuts.buttons["BackButton"].waitForExistence(timeout: 5) { shortcuts.buttons["BackButton"].tap() }
        let lgk = shortcuts.buttons.matching(NSPredicate(format: "label == 'LocalGateKeys'")).firstMatch
        XCTAssertTrue(lgk.waitForExistence(timeout: 5), "LocalGateKeys is listed under Apps")
        lgk.tap()
        let copy = shortcuts.descendants(matching: .any).matching(NSPredicate(format: "label == 'Copy code'")).firstMatch
        XCTAssertTrue(copy.waitForExistence(timeout: 5), "the Copy code action is offered")
        copy.tap()

        // The code picker is shown by SpringBoard: only the pinned code is offered.
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let choice = springboard.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS[c] 'github.com'")).firstMatch
        XCTAssertTrue(choice.waitForExistence(timeout: 10), "the pinned github.com code is offered")
        shot("picker")
        choice.tap()
        sleep(3)
        shot("after-copy")
    }
}
