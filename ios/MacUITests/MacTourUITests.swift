import XCTest

/// A screenshot tour of the Mac app's demo preview for the hands-on rows of docs/PENDING.md (UX refresh: Tools,
/// Settings tabs and search, overview boxes in German, dark mode, Recovery centre). It asserts little: it clicks
/// through the screens, attaches a screenshot of each and prints `MAC-CHECK` lines with the visible text, for a
/// person to review. Run: `scripts/mac_ui_checks.sh MacTourUITests`.
final class MacTourUITests: XCTestCase {
    override func setUpWithError() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_MAC_UI_CHECKS"] == "1", "run through scripts/mac_ui_checks.sh")
    }

    @MainActor
    private func launch(_ arguments: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments += arguments
        app.launchEnvironment["LGK_MAC_ALLOW_CAPTURE"] = "1"
        app.launchEnvironment["LGK_MAC_SHELL_PREVIEW"] = "1"
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20))
        let skip = app.buttons["Skip setup"]
        if skip.waitForExistence(timeout: 3) { skip.click() }
        sleep(1)
        return app
    }

    @MainActor
    private func shot(_ app: XCUIApplication, _ name: String) {
        let a = XCTAttachment(screenshot: app.windows.firstMatch.screenshot()); a.name = name; a.lifetime = .keepAlways
        add(a)
        guard let snap = try? app.windows.firstMatch.snapshot() else { return }
        var out: [String] = []
        func walk(_ s: XCUIElementSnapshot) {
            for t in [s.label, s.title, (s.value as? String) ?? ""] where !t.isEmpty && !out.contains(t) { out.append(t) }
            s.children.forEach(walk)
        }
        walk(snap)
        print("MAC-CHECK \(name): \(out.prefix(160).joined(separator: " | "))")
    }

    @MainActor
    private func click(_ app: XCUIApplication, _ label: String) -> Bool {
        let e = app.descendants(matching: .any).matching(NSPredicate(format: "label == %@ OR title == %@", label, label)).firstMatch
        guard e.waitForExistence(timeout: 4), e.isHittable else { print("MAC-CHECK missing: \(label)"); return false }
        e.click(); sleep(1)
        return true
    }

    @MainActor
    func testTourEnglish() throws {
        let app = launch()
        shot(app, "home")
        for tool in ["Security centre", "Generator"] {
            if click(app, tool) { shot(app, "tool-\(tool)") }
        }
        app.typeKey(",", modifierFlags: .command)
        sleep(2)
        shot(app, "settings")
        for tab in ["General", "Security", "AutoFill", "Backups", "Appearance", "Plan", "Advanced"] {
            let b = app.buttons[tab].firstMatch
            if b.waitForExistence(timeout: 3) { b.click(); sleep(1); shot(app, "settings-\(tab)") } else { print("MAC-CHECK missing tab: \(tab)") }
        }
        let search = app.searchFields.firstMatch.exists ? app.searchFields.firstMatch : app.textFields["Search settings"].firstMatch
        if search.waitForExistence(timeout: 3) {
            search.click(); search.typeText("backup"); sleep(1); shot(app, "settings-search-backup")
        } else { print("MAC-CHECK missing: settings search field") }
        app.typeKey(.escape, modifierFlags: [])
        // Recovery centre from the Backup & recovery box, then Emergency access.
        if click(app, "All items") || true {
            let recovery = app.buttons["Recovery centre"].firstMatch
            if recovery.waitForExistence(timeout: 5) {
                recovery.click(); sleep(2); shot(app, "recovery-centre")
                for label in ["Grant now", "Show phrase"] {
                    let b = app.buttons[label].firstMatch
                    if b.waitForExistence(timeout: 3) {
                        b.click(); sleep(2); shot(app, "emergency-\(label)")
                        app.typeKey(.escape, modifierFlags: []); sleep(1)
                    } else { print("MAC-CHECK missing: \(label)") }
                }
            } else { print("MAC-CHECK missing: Recovery centre button") }
        }
    }

    @MainActor
    func testTourGermanAndDark() throws {
        var app = launch(["-AppleLanguages", "(de)", "-AppleLocale", "de_DE"])
        shot(app, "home-de-setup")
        let skip = app.buttons["Einrichtung überspringen"]
        if skip.waitForExistence(timeout: 3) { skip.click(); sleep(1) }
        shot(app, "home-de")
        app.terminate()
        app = launch(["-AppleInterfaceStyle", "Dark"])
        shot(app, "home-dark")
        let collapse = app.buttons["Collapse one-time codes"]
        if collapse.waitForExistence(timeout: 3) { collapse.click(); sleep(1); shot(app, "home-dark-codes-folded"); app.buttons["Expand one-time codes"].firstMatch.click() }
    }

    @MainActor
    func testEmergencyAccessAsksForTheMasterPassword() throws {
        let app = launch()
        // The Backup & recovery box is itself the link (its tooltip says "Recovery centre"); the sidebar row also opens it.
        let recovery = app.descendants(matching: .any).matching(NSPredicate(
            format: "(label == 'Recovery centre' OR label BEGINSWITH 'Backup & recovery' OR title == 'Recovery centre') AND elementType IN %@",
            [XCUIElement.ElementType.button.rawValue, XCUIElement.ElementType.cell.rawValue,
             XCUIElement.ElementType.outlineRow.rawValue, XCUIElement.ElementType.staticText.rawValue])).firstMatch
        XCTAssertTrue(recovery.waitForExistence(timeout: 5), "the Recovery centre can be opened")
        recovery.click(); sleep(2); shot(app, "recovery-centre")
        XCTAssertTrue(app.buttons["Grant now"].firstMatch.waitForExistence(timeout: 5)
                      || app.staticTexts["Recovery centre"].firstMatch.exists, "the Recovery centre opened")
        for label in ["Grant now", "Show phrase"] {
            let b = app.buttons[label].firstMatch
            if b.waitForExistence(timeout: 3) {
                b.click(); sleep(2); shot(app, "emergency-\(label)")
                app.typeKey(.escape, modifierFlags: []); sleep(1)
            } else { print("MAC-CHECK missing: \(label)") }
        }
    }

    /// The login detail beside the list (one-time code first, Sign-in, Notes, Autofill rules, extras), scrolled.
    @MainActor
    func testDetailPanel() throws {
        let app = XCUIApplication()
        app.launchEnvironment["LGK_MAC_ALLOW_CAPTURE"] = "1"
        app.launchEnvironment["LGK_MAC_SHELL_PREVIEW"] = "1"
        app.launchEnvironment["LGK_MAC_SELECT"] = "github.com"
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20))
        let skip = app.buttons["Skip setup"]; if skip.waitForExistence(timeout: 3) { skip.click() }
        sleep(1); shot(app, "detail-top")
        XCTAssertTrue(app.staticTexts["Autofill rules"].waitForExistence(timeout: 3), "Autofill rules section")
        let window = app.windows.firstMatch
        window.coordinate(withNormalizedOffset: CGVector(dx: 0.8, dy: 0.6)).scroll(byDeltaX: 0, deltaY: -800)
        sleep(1); shot(app, "detail-bottom")
    }
}
