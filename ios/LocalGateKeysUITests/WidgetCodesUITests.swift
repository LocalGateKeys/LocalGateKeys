import XCTest

/// Sub-plan 06 task 2 (codes widget) on the simulator: pins github.com's demo code, adds the "Pinned codes" widget
/// to the home screen (once), and checks the widget shows the same code as the app and a new one 30 seconds later.
/// Run it with `scripts/ios_simulator_checks.sh` (Face ID is matched from the Mac); skipped otherwise.
final class WidgetCodesUITests: XCTestCase {
    @MainActor private var springboard: XCUIApplication { XCUIApplication(bundleIdentifier: "com.apple.springboard") }

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

    /// Every label in `root`, read from one accessibility snapshot (the screen keeps changing while it is read).
    @MainActor
    private func labels(_ root: XCUIElement) -> [String] {
        guard let snap = try? root.snapshot() else { return [] }
        var out: [String] = []
        func walk(_ s: XCUIElementSnapshot) { if !s.label.isEmpty { out.append(s.label) }; s.children.forEach(walk) }
        walk(snap)
        return out
    }

    private func isCode(_ label: String) -> Bool {
        (6...8).contains(label.filter(\.isNumber).count) && label.allSatisfy { $0.isNumber || $0 == " " }
    }

    /// The first 6-8 digit code shown in `root`, as digits only.
    @MainActor
    private func code(in root: XCUIElement) -> String? {
        labels(root).first(where: isCode)?.filter(\.isNumber)
    }

    /// The code the widget shows: the first code after its "github.com" label on the home screen.
    @MainActor
    private func widgetCode() -> String? {
        let all = labels(springboard)
        guard let i = all.firstIndex(of: "github.com") else { return nil }
        return all[(i + 1)...].prefix(4).first(where: isCode)?.filter(\.isNumber)
    }

    @MainActor
    private func openItemAndPin() -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments += ["-LGKDemoData", "YES", "-LGKScreen", "item"]
        app.launchEnvironment["LGK_DEBUG_PRO"] = "1"
        app.launch()
        let pin = app.buttons["Show in widgets and on Apple Watch"]
        let unpin = app.buttons["Remove from widgets and Apple Watch"]
        XCTAssertTrue(pin.waitForExistence(timeout: 60) || unpin.exists, "the item opened after Face ID")
        if pin.exists { pin.tap() }
        XCTAssertTrue(unpin.waitForExistence(timeout: 5), "github.com's code is pinned")
        return app
    }

    @MainActor
    private func addWidgetIfMissing() {
        XCUIDevice.shared.press(.home)
        if springboard.buttons["Done"].waitForExistence(timeout: 1) { springboard.buttons["Done"].tap() }
        XCUIDevice.shared.press(.home)
        if springboard.staticTexts["github.com"].waitForExistence(timeout: 3) { return }
        springboard.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.75)).press(forDuration: 1.5)
        XCTAssertTrue(springboard.buttons["Edit"].waitForExistence(timeout: 5), "home screen edit mode")
        springboard.buttons["Edit"].tap()
        let addMenu = springboard.buttons.matching(NSPredicate(format: "label CONTAINS[c] 'Widget'")).firstMatch
        XCTAssertTrue(addMenu.waitForExistence(timeout: 3))
        addMenu.tap()
        let search = springboard.searchFields.firstMatch
        XCTAssertTrue(search.waitForExistence(timeout: 5), "widget gallery")
        search.tap()
        search.typeText("LocalGateKeys\n")
        let app = springboard.descendants(matching: .any).matching(NSPredicate(format: "label == 'LocalGateKeys'")).element(boundBy: 1)
        if app.waitForExistence(timeout: 3), app.isHittable { app.tap() } else {
            springboard.coordinate(withNormalizedOffset: CGVector(dx: 0.35, dy: 0.282)).tap()
        }
        XCTAssertTrue(springboard.staticTexts["Pinned codes"].waitForExistence(timeout: 5), "the Pinned codes widget is offered")
        let add = springboard.buttons.matching(NSPredicate(format: "label CONTAINS 'Add Widget'")).firstMatch
        XCTAssertTrue(add.waitForExistence(timeout: 3))
        add.tap()
        if springboard.buttons["Done"].waitForExistence(timeout: 3) { springboard.buttons["Done"].tap() }
        XCTAssertTrue(springboard.staticTexts["github.com"].waitForExistence(timeout: 10), "the widget is on the home screen")
    }

    @MainActor
    func testWidgetShowsThePinnedCodeAndRefreshes() throws {
        _ = openItemAndPin()
        addWidgetIfMissing()
        shot("widget")

        // Same code as the app, read within one 30-second period (retried once across a boundary).
        var matched = false
        for _ in 0..<2 where !matched {
            let app = XCUIApplication()
            app.activate()
            sleep(2)   // the app may ask Face ID again after the home screen
            let inApp = code(in: app)
            XCUIDevice.shared.press(.home)
            let onWidget = widgetCode()
            print("WIDGET-CHECK app \(inApp == nil ? "none" : "code") widget \(onWidget == nil ? "none" : "code") same \(inApp == onWidget)")
            matched = inApp != nil && inApp == onWidget
            if !matched { sleep(3) }
        }
        XCTAssertTrue(matched, "the widget shows the app's code")

        let first = try XCTUnwrap(widgetCode())
        sleep(31)
        let second = try XCTUnwrap(widgetCode())
        shot("widget-30s-later")
        XCTAssertNotEqual(first, second, "the widget's code changed after 30 seconds")
    }
}
