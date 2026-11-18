import XCTest

/// docs/PENDING.md "Mac Settings parity" and "Mac six new settings", on a real vault made per test
/// (MacRealVaultUITestCase). Settings live in the uitest build's own app group defaults; each test puts back what it
/// changed.
final class MacSettingsUITests: MacRealVaultUITestCase {
    private let tabs = ["General", "Security", "AutoFill", "Backups", "Appearance", "Plan", "Advanced"]

    /// The ⌘, window: the one with a Search settings field that is not the main window.
    @MainActor
    private func settingsWindow(_ app: XCUIApplication) -> XCUIElement {
        app.typeKey(",", modifierFlags: .command)
        var w = app.windows.firstMatch
        let deadline = Date().addingTimeInterval(10)
        repeat {
            if let found = app.windows.allElementsBoundByIndex.first(where: { $0.exists && $0.frame.width < 700 && $0.frame.width > 300 }) { w = found; break }
            usleep(300_000)
        } while Date() < deadline
        XCTAssertTrue(w.frame.width < 700, "the ⌘, window opened")
        return w
    }

    @MainActor
    private func strings(in element: XCUIElement) -> Set<String> {
        guard let snap = try? element.snapshot() else { return [] }
        var out = Set<String>()
        func walk(_ s: XCUIElementSnapshot) {
            for t in [s.label, s.title, (s.value as? String) ?? ""] where !t.isEmpty { out.insert(t) }
            s.children.forEach(walk)
        }
        walk(snap)
        return out
    }

    /// Every tab's strings in `window` (the tab buttons are clicked in turn).
    @MainActor
    private func allTabStrings(_ window: XCUIElement) -> Set<String> {
        var out = Set<String>()
        for tab in tabs {
            let b = window.buttons[tab].firstMatch
            XCTAssertTrue(b.waitForExistence(timeout: 5), "tab \(tab)")
            b.click()
            usleep(600_000)
            out.formUnion(strings(in: window))
        }
        return out
    }

    @MainActor
    private func search(_ window: XCUIElement, _ text: String) {
        let field = window.textFields["Search settings"].firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.click()
        field.typeKey("a", modifierFlags: .command)
        field.typeKey(.delete, modifierFlags: [])
        if !text.isEmpty { field.typeText(text) }
        usleep(700_000)
    }

    @MainActor
    private func mainWindow(_ app: XCUIApplication) -> XCUIElement { app.windows["LocalGateKeys"].firstMatch }

    // MARK: Parity

    /// The main window's Settings and the ⌘, window show the same rows, tab by tab.
    @MainActor
    func testMainWindowAndCommandCommaShowTheSameRows() throws {
        let app = launch()
        createVault(app)
        app.buttons["Settings"].firstMatch.click()
        let main = mainWindow(app)
        XCTAssertTrue(main.textFields["Search settings"].waitForExistence(timeout: 5))
        // The main window's own chrome (sidebar, status line) is not part of Settings: take it out by diffing
        // against the window before Settings was opened is unreliable, so compare the ⌘, side into the main side.
        let mainStrings = allTabStrings(main)
        let window = settingsWindow(app)
        let standalone = allTabStrings(window)
        let missingInMain = standalone.subtracting(mainStrings)
        let rows = ["Auto-lock after inactivity", "Count activity from", "Ask before releasing 2FA codes",
                    "Open documents in other apps", "Automatic backups to keep", "Quick access shortcut",
                    "Recovery centre", "Licence", "Duress password", "Keyboard shortcuts", "Privacy policy",
                    "Licence agreement", "Devices & connections", "Set up LocalGateKeys"]
        print("MAC-CHECK only in ⌘,:", missingInMain.sorted())
        XCTAssertEqual(missingInMain.filter { !$0.hasPrefix("_XCUI") && $0 != window.title }, [], "rows only in the ⌘, window")
        for r in rows {
            XCTAssertTrue(mainStrings.contains(r), "main window Settings has \(r)")
            XCTAssertTrue(standalone.contains(r), "⌘, window has \(r)")
        }
        // Settings › Backups: the schedule and the weekly restore test.
        let backups = window.buttons["Backups"].firstMatch
        backups.click(); usleep(600_000)
        let b = strings(in: window)
        print("MAC-CHECK backups tab:", b.sorted().joined(separator: " | "))
        XCTAssertTrue(b.contains { $0.hasPrefix("Each week, prove that a scheduled backup restores") }, "weekly restore test row")
        XCTAssertTrue(b.contains { $0.localizedCaseInsensitiveContains("Scheduled backups") || $0.localizedCaseInsensitiveContains("schedule") },
                      "backup schedule section")
        shot(app, "settings-backups")
    }

    /// From ⌘,: Recovery centre, Licence and Show setup again open the main window's page, also from the lock screen
    /// (after the unlock).
    @MainActor
    func testCommandCommaOpensMainWindowPages() throws {
        let app = launch()
        createVault(app)
        let main = mainWindow(app)
        let pages: [(tab: String, search: String, button: String, expect: String)] = [
            ("Backups", "Recovery centre", "Open", "Recovery centre"),
            ("Plan", "licence key", "Open", "Pro unlocks unlimited items, 2FA codes and Wi-Fi sync hosting."),
            ("General", "Set up LocalGateKeys", "Show setup again", "Set up LocalGateKeys"),
        ]
        for p in pages {
            let window = settingsWindow(app)
            search(window, p.search)
            let b = window.buttons[p.button].firstMatch
            XCTAssertTrue(b.waitForExistence(timeout: 5), "\(p.search) › \(p.button)")
            b.click()
            sleep(2)
            let shown = strings(in: main)
            shot(app, "from-cmd-comma-\(p.search)")
            let found = shown.contains { $0 == p.expect || $0.hasPrefix(p.expect) }
            if !found { print("MAC-CHECK \(p.search) page:", shown.sorted().prefix(80)) }
            // The Pro debug flag shows "You have Pro" instead of the free plan line.
            XCTAssertTrue(found, "\(p.search) opened in the main window")
            app.typeKey(.escape, modifierFlags: [])
            dismissSheets(app)
        }
        // Locked: the request waits for the unlock.
        app.typeKey("l", modifierFlags: .command)
        XCTAssertTrue(app.buttons["Unlock"].waitForExistence(timeout: 10))
        let window = settingsWindow(app)
        search(window, "Recovery centre")
        let open = window.buttons["Open"].firstMatch
        if open.waitForExistence(timeout: 5), open.isEnabled { open.click() }
        let field = app.secureTextFields["Master password"].firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 10), "the lock screen")
        print("MAC-CHECK windows after Open while locked:", app.windows.allElementsBoundByIndex.map { "\($0.title) \($0.frame)" })
        if window.exists { window.buttons[XCUIIdentifierCloseWindow].firstMatch.click() }
        field.click(); field.typeText(Self.master)
        app.buttons["Unlock"].click()
        sleep(3)
        let after = strings(in: main)
        shot(app, "recovery-after-unlock")
        XCTAssertTrue(after.contains { $0.hasPrefix("Before each restore, a copy of the vault") || $0 == "Recovery centre" },
                      "Recovery centre shown after the unlock")
    }

    // MARK: Persistence of the six new settings (and an older one)

    @MainActor
    private func popUp(_ window: XCUIElement) -> XCUIElement { window.popUpButtons.firstMatch }

    @MainActor
    private func choose(_ window: XCUIElement, search text: String, option: String) {
        search(window, text)
        let p = popUp(window)
        XCTAssertTrue(p.waitForExistence(timeout: 5), "picker for \(text)")
        p.click()
        let item = window.menuItems[option].firstMatch
        XCTAssertTrue(item.waitForExistence(timeout: 5), "option \(option)")
        item.click()
    }

    @MainActor
    private func setSwitch(_ window: XCUIElement, search text: String, on: Bool) {
        search(window, text)
        let s = toggle(window)
        XCTAssertTrue(s.waitForExistence(timeout: 5), "switch for \(text)")
        if switchValue(s) != on { s.click() }
        XCTAssertEqual(switchValue(s), on, text)
    }

    /// A SwiftUI switch with a hidden label shows up as a switch or a checkbox, depending on the macOS version.
    @MainActor
    private func toggle(_ window: XCUIElement) -> XCUIElement {
        let sw = window.switches.firstMatch
        if sw.waitForExistence(timeout: 2) { return sw }
        return window.checkBoxes.firstMatch
    }

    private func switchValue(_ s: XCUIElement) -> Bool {
        if let n = s.value as? NSNumber { return n.boolValue }
        return (s.value as? String) == "1"
    }

    @MainActor
    func testSettingsPersistAcrossRelaunch() throws {
        continueAfterFailure = true
        var app = launch()
        createVault(app)
        var window = settingsWindow(app)
        choose(window, search: "Count activity from", option: "Vault activity")
        setSwitch(window, search: "Ask before releasing 2FA codes", on: true)
        setSwitch(window, search: "Open documents in other apps", on: false)
        choose(window, search: "Automatic backups to keep", option: "3 backups")
        setSwitch(window, search: "Lock when the Mac sleeps", on: false)
        shot(app, "settings-changed")
        // A fresh ⌘, window (new model, read from the defaults) before the relaunch.
        window.buttons[XCUIIdentifierCloseWindow].firstMatch.click()
        window = settingsWindow(app)
        search(window, "Count activity from")
        print("MAC-CHECK idle source before relaunch, new window:", (popUp(window).value as? String) ?? "?")
        app.typeKey("q", modifierFlags: .command)   // quit as a person would
        if !app.wait(for: .notRunning, timeout: 10) { app.terminate() }

        app = launch()
        let field = app.secureTextFields["Master password"].firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 15))
        field.click(); field.typeText(Self.master)
        app.buttons["Unlock"].click()
        XCTAssertTrue(app.buttons["Settings"].firstMatch.waitForExistence(timeout: 30))
        window = settingsWindow(app)
        func check(_ text: String, _ expected: String) {
            search(window, text)
            let p = popUp(window)
            XCTAssertTrue(p.waitForExistence(timeout: 5))
            XCTAssertEqual((p.value as? String) ?? p.title, expected, "\(text) kept after a relaunch")
        }
        func checkSwitch(_ text: String, _ expected: Bool) {
            search(window, text)
            let s = toggle(window)
            XCTAssertTrue(s.waitForExistence(timeout: 5))
            XCTAssertEqual(switchValue(s), expected, "\(text) kept after a relaunch")
        }
        check("Count activity from", "Vault activity")
        checkSwitch("Ask before releasing 2FA codes", true)
        checkSwitch("Open documents in other apps", false)
        check("Automatic backups to keep", "3 backups")
        checkSwitch("Lock when the Mac sleeps", false)
        shot(app, "settings-after-relaunch")
        // Put the defaults back (the uitest build's app group defaults outlive the test).
        choose(window, search: "Count activity from", option: "Computer activity")
        setSwitch(window, search: "Ask before releasing 2FA codes", on: false)
        setSwitch(window, search: "Open documents in other apps", on: true)
        choose(window, search: "Automatic backups to keep", option: "5 backups")
        setSwitch(window, search: "Lock when the Mac sleeps", on: true)
    }

    // MARK: Six new settings, behaviour

    /// Automatic backups to keep = 3: each save makes a copy, only the newest 3 stay; the Recovery centre text
    /// still says "the newest 5".
    @MainActor
    func testAutomaticBackupCountKeepsTheNewestCopies() throws {
        let app = launch()
        createVault(app)
        let window = settingsWindow(app)
        choose(window, search: "Automatic backups to keep", option: "3 backups")
        window.buttons[XCUIIdentifierCloseWindow].firstMatch.click()
        func automatic() -> [String] {
            ((try? FileManager.default.contentsOfDirectory(atPath: vaultDir.appendingPathComponent("Backups").path)) ?? [])
                .filter { $0.hasPrefix("automatic-") }.sorted()
        }
        var counts: [Int] = []
        var times: [TimeInterval] = []
        for n in 1...5 {
            app.buttons["New item"].firstMatch.click()
            let kind = app.buttons.matching(NSPredicate(format: "label CONTAINS 'Secure note'")).firstMatch
            if !kind.waitForExistence(timeout: 5) { dump(app, "new item") }
            XCTAssertTrue(kind.exists, "New item › Secure note")
            kind.click()
            let title = app.textFields["Title"].firstMatch
            XCTAssertTrue(title.waitForExistence(timeout: 5), "editor title field")
            title.click(); title.typeText("Note \(n)")
            let start = Date()
            app.buttons["Save"].firstMatch.click()
            XCTAssertTrue(app.buttons["Save"].firstMatch.waitForNonExistence(timeout: 10), "saved")
            times.append(Date().timeIntervalSince(start))
            sleep(1)
            counts.append(automatic().count)
        }
        print("MAC-CHECK automatic copies after each save: \(counts); save seconds \(times)")
        XCTAssertEqual(counts.first, 1, "a copy after the first save")
        XCTAssertEqual(counts.last, 3, "only the newest 3 kept")
        XCTAssertLessThan(times.max() ?? 0, 5, "saves stay quick")
        // Recovery centre: the safety text still says the newest 5 (before-restore copies).
        let w2 = settingsWindow(app)
        search(w2, "Recovery centre")
        w2.buttons["Open"].firstMatch.click()
        sleep(2)
        let page = strings(in: mainWindow(app))
        shot(app, "recovery-centre")
        XCTAssertTrue(page.contains { $0.contains("the newest 5") }, "Recovery centre still says the newest 5")
        let w3 = settingsWindow(app)
        choose(w3, search: "Automatic backups to keep", option: "5 backups")
    }

    /// Quick access shortcut: record ⌃⌥J, then Reset brings back ⌃⌥K.
    @MainActor
    func testCustomShortcutRecordsAndResets() throws {
        let app = launch()
        createVault(app)
        let window = settingsWindow(app)
        search(window, "Quick access shortcut")
        let recorder = window.buttons["Quick access shortcut"].firstMatch
        XCTAssertTrue(recorder.waitForExistence(timeout: 5))
        let before = (recorder.value as? String) ?? recorder.title
        recorder.click()
        app.typeKey("j", modifierFlags: [.control, .option])
        sleep(1)
        let after = strings(in: window)
        shot(app, "shortcut-recorded")
        print("MAC-CHECK shortcut before=\(before) after=", after.filter { $0.contains("⌃") || $0.contains("⌥") })
        XCTAssertTrue(after.contains { $0.contains("⌃⌥J") }, "the new shortcut is shown")
        window.buttons["Reset"].firstMatch.click()
        sleep(1)
        XCTAssertTrue(strings(in: window).contains { $0.contains("⌃⌥K") }, "Reset brings back ⌃⌥K")
    }

    /// Help & diagnostics: Keyboard shortcuts › View and Devices & connections › Open open the main window's pages;
    /// the two website rows have Open buttons (the browser is not driven here).
    @MainActor
    func testHelpAndDiagnosticsLinks() throws {
        let app = launch()
        createVault(app)
        var window = settingsWindow(app)
        search(window, "Keyboard shortcuts")
        window.buttons["View"].firstMatch.click()
        sleep(2)
        var shown = strings(in: mainWindow(app))
        shot(app, "help-shortcuts")
        XCTAssertTrue(shown.contains { $0.localizedCaseInsensitiveContains("shortcut") }, "the shortcuts sheet")
        app.typeKey(.escape, modifierFlags: [])
        window = settingsWindow(app)
        search(window, "Devices & connections")
        window.buttons["Open"].firstMatch.click()
        sleep(2)
        shown = strings(in: mainWindow(app))
        shot(app, "help-connections")
        XCTAssertTrue(shown.contains { $0.localizedCaseInsensitiveContains("Browser extension") || $0.contains("Devices & connections") },
                      "the Devices & connections page")
        window = settingsWindow(app)
        for row in ["Privacy policy", "Licence agreement"] {
            search(window, row)
            XCTAssertTrue(window.buttons["Open"].firstMatch.waitForExistence(timeout: 5), "\(row) › Open")
        }
    }

    /// Seconds left on the status line's "Auto-lock in m:ss".
    @MainActor
    private func autoLockSeconds(_ app: XCUIApplication) -> Int? {
        let t = app.staticTexts.matching(NSPredicate(format: "value CONTAINS 'Auto-lock in' OR label CONTAINS 'Auto-lock in'")).firstMatch
        guard t.waitForExistence(timeout: 5) else { return nil }
        let text = (t.value as? String) ?? t.label
        guard let r = text.range(of: #"\d+:\d\d"#, options: .regularExpression) else { return nil }
        let parts = text[r].split(separator: ":").compactMap { Int($0) }
        return parts[0] * 60 + parts[1]
    }

    /// Input in another app for ~20 s (Finder), then back to LocalGateKeys without input; returns the countdown
    /// before and after.
    @MainActor
    private func countdownAcrossOtherAppActivity(_ app: XCUIApplication) -> (Int, Int) {
        let before = autoLockSeconds(app) ?? -1
        let finder = XCUIApplication(bundleIdentifier: "com.apple.finder")
        finder.activate()
        for _ in 0..<10 {
            finder.typeKey(.shift, modifierFlags: [])
            sleep(2)
        }
        app.activate()
        sleep(1)
        return (before, autoLockSeconds(app) ?? -1)
    }

    /// Count activity from: Vault activity ignores input in other apps (the countdown runs on); Computer activity
    /// counts it (the countdown starts again).
    @MainActor
    func testIdleSourceVaultIgnoresOtherAppsComputerCountsThem() throws {
        let app = launch()
        createVault(app)
        var window = settingsWindow(app)
        choose(window, search: "Count activity from", option: "Vault activity")
        window.buttons[XCUIIdentifierCloseWindow].firstMatch.click()
        let (v0, v1) = countdownAcrossOtherAppActivity(app)
        window = settingsWindow(app)
        choose(window, search: "Count activity from", option: "Computer activity")
        window.buttons[XCUIIdentifierCloseWindow].firstMatch.click()
        let (c0, c1) = countdownAcrossOtherAppActivity(app)
        print("MAC-CHECK idle countdown vault \(v0)->\(v1), computer \(c0)->\(c1)")
        XCTAssertGreaterThan(v0, 0); XCTAssertGreaterThan(c0, 0)
        XCTAssertLessThanOrEqual(v1, v0 - 15, "Vault activity: typing in Finder does not keep the vault open")
        XCTAssertGreaterThanOrEqual(c1, c0 - 6, "Computer activity: typing in Finder keeps the vault open")
    }

    /// Ask before releasing 2FA codes: on, a copy from the codes strip asks first and Cancel copies nothing.
    /// Runs on the demo preview (its github.com login has a code).
    @MainActor
    func testTOTPConfirmAsksBeforeCopying() throws {
        let app = XCUIApplication()
        app.launchEnvironment["LGK_MAC_ALLOW_CAPTURE"] = "1"
        app.launchEnvironment["LGK_MAC_SHELL_PREVIEW"] = "1"
        app.launchEnvironment["LGK_MAC_HIDE_SETUP"] = "1"
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20))
        let unfold = app.buttons["Expand one-time codes"]
        if unfold.waitForExistence(timeout: 3) { unfold.click() }
        // The preview's ⌘, window has no unlocked vault behind it: use the main window's Settings.
        app.buttons["Settings"].firstMatch.click()
        setSwitch(mainWindow(app), search: "Ask before releasing 2FA codes", on: true)
        app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'All items'")).firstMatch.click()
        sleep(1)
        let copy = app.buttons["Copy 2FA code for github.com"].firstMatch
        if !copy.waitForExistence(timeout: 5) { dump(app, "no code button") }
        copy.click()
        let ask = app.staticTexts["Copy the 2FA code?"].firstMatch
        XCTAssertTrue(ask.waitForExistence(timeout: 5), "asks before copying")
        shot(app, "totp-confirm")
        app.buttons["Cancel"].firstMatch.click()
        XCTAssertTrue(ask.waitForNonExistence(timeout: 5))
        app.buttons["Settings"].firstMatch.click()
        setSwitch(mainWindow(app), search: "Ask before releasing 2FA codes", on: false)
    }

    // MARK: Sidebar and Home

    /// At the smallest window (680 pt, below the 900 pt of the check) only the item groups scroll; Tools and
    /// Settings stay visible.
    @MainActor
    func testSidebarToolsStayVisibleInAShortWindow() throws {
        let app = XCUIApplication()
        app.launchEnvironment["LGK_MAC_ALLOW_CAPTURE"] = "1"
        app.launchEnvironment["LGK_MAC_SHELL_PREVIEW"] = "1"
        app.launchEnvironment["LGK_MAC_HIDE_SETUP"] = "1"
        app.launchEnvironment["LGK_MAC_WINDOW_SIZE"] = "1180x680"
        app.launch()
        let window = app.windows.firstMatch
        XCTAssertTrue(window.waitForExistence(timeout: 20))
        sleep(2)
        print("MAC-CHECK window frame:", window.frame)
        shot(app, "sidebar-680")
        for name in ["Security centre", "Generator", "Sync & devices", "Import & export", "Trash", "Settings"] {
            let b = app.buttons[name].firstMatch
            XCTAssertTrue(b.exists, name)
            XCTAssertTrue(window.frame.contains(b.frame), "\(name) inside the window")
            XCTAssertFalse(app.scrollViews.buttons[name].exists, "\(name) is not in the scrolling part")
        }
        XCTAssertTrue(app.scrollViews.buttons.matching(NSPredicate(format: "label BEGINSWITH 'All items'")).firstMatch.exists,
                      "the item groups scroll")
    }

    /// Home › One-time codes folds and unfolds in light mode.
    @MainActor
    func testOneTimeCodesCollapseInLightMode() throws {
        let app = XCUIApplication()
        app.launchEnvironment["LGK_MAC_ALLOW_CAPTURE"] = "1"
        app.launchEnvironment["LGK_MAC_SHELL_PREVIEW"] = "1"
        app.launchEnvironment["LGK_MAC_HIDE_SETUP"] = "1"
        app.launchEnvironment["LGK_MAC_APPEARANCE"] = "light"
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20))
        let unfold = app.buttons["Expand one-time codes"]
        if unfold.waitForExistence(timeout: 3) { unfold.click() }
        let collapse = app.buttons["Collapse one-time codes"]
        let code = app.buttons["Copy 2FA code for github.com"]
        XCTAssertTrue(collapse.waitForExistence(timeout: 5))
        XCTAssertTrue(collapse.isHittable, "the fold button is visible in light mode")
        XCTAssertTrue(code.exists)
        shot(app, "codes-light-open")
        collapse.click()
        XCTAssertTrue(code.waitForNonExistence(timeout: 3), "folding hides the codes in light mode")
        shot(app, "codes-light-folded")
        XCTAssertTrue(unfold.waitForExistence(timeout: 3) && unfold.isHittable, "the unfold button is visible")
        unfold.click()
        XCTAssertTrue(code.waitForExistence(timeout: 3), "unfolding shows them again")
    }
}
