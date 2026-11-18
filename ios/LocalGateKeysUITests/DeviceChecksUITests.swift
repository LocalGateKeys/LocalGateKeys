import XCTest

/// PENDING "UX refresh" checks for iPhone and iPad on the simulator, with demo data. Needs Face ID matched in a loop:
/// run it with `scripts/ios_simulator_checks.sh <udid> DeviceChecksUITests`.
final class DeviceChecksUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = true
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_FACEID_LOOP"] == "1",
                          "run through scripts/ios_simulator_checks.sh")
    }

    @MainActor private func shot(_ name: String) {
        let a = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        a.name = name; a.lifetime = .keepAlways
        add(a)
        if let dir = ProcessInfo.processInfo.environment["LGK_SHOTS"] {
            try? XCUIScreen.main.screenshot().pngRepresentation.write(to: URL(fileURLWithPath: "\(dir)/\(name).png"))
        }
    }

    @MainActor private func dump(_ app: XCUIApplication, _ tag: String) {
        print("DUMP-\(tag)-BEGIN\n\(app.debugDescription)\nDUMP-\(tag)-END")
    }

    @MainActor private func launch(_ extra: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments += ["-LGKDemoData", "YES"] + extra
        app.launchEnvironment["LGK_DEBUG_PRO"] = "1"
        app.launch()
        for name in ["Skip setup", "Einrichtung überspringen", "セットアップをスキップ"] where app.buttons[name].waitForExistence(timeout: name == "Skip setup" ? 45 : 1) {
            app.buttons[name].tap(); sleep(1); break
        }
        for name in ["Continue", "Weiter", "続ける"] where app.buttons[name].waitForExistence(timeout: name == "Continue" ? 4 : 1) {
            app.buttons[name].tap(); sleep(1); break
        }
        return app
    }

    @MainActor private func exists(_ app: XCUIApplication, _ label: String, _ t: TimeInterval = 3) -> Bool {
        app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@", label)).firstMatch.waitForExistence(timeout: t)
    }

    @MainActor private func sidebar(_ app: XCUIApplication, _ name: String) {
        let row = app.staticTexts.matching(NSPredicate(format: "label == %@", name)).firstMatch
        if !row.exists || !row.isHittable {
            app.staticTexts.matching(NSPredicate(format: "label == 'Vault'")).firstMatch.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 10)).press(forDuration: 0.05, thenDragTo: app.staticTexts.matching(NSPredicate(format: "label == 'Vault'")).firstMatch.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 1)))
            sleep(1)
        }
        row.tap()
        sleep(1)
    }

    @MainActor
    func testIPad() throws {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .pad, "iPad only")
        XCUIDevice.shared.orientation = .landscapeLeft
        var app = launch()
        XCTAssertTrue(exists(app, "All items", 60), "vault open")
        sleep(2)
        sidebar(app, "Favorites")
        shot("ipad-favorites"); dump(app, "fav")
        XCTAssertTrue(exists(app, "github.com, alex@example.com"), "favourite shown")
        XCTAssertFalse(exists(app, "amazon.com, alex@example.com", 1), "non-favourite hidden")
        sidebar(app, "Note")
        shot("ipad-notes")
        XCTAssertTrue(exists(app, "Wi-Fi at home"), "note shown")
        XCTAssertFalse(exists(app, "amazon.com, alex@example.com", 1), "login hidden under Note")
        sidebar(app, "Sync"); shot("ipad-sync"); dump(app, "sync")
        sidebar(app, "Security"); shot("ipad-security"); dump(app, "security")
        sidebar(app, "Settings"); shot("ipad-settings"); dump(app, "settings")
        app.terminate()
        app = launch()
        XCTAssertTrue(exists(app, "All items", 60), "vault open again")
        sleep(2)
        let search = app.searchFields["Search"]
        XCTAssertTrue(search.waitForExistence(timeout: 3))
        search.tap(); search.typeText("amazon")
        sleep(1); shot("ipad-search"); dump(app, "search")
        XCTAssertTrue(exists(app, "amazon.com"), "search hit")
        XCTAssertFalse(exists(app, "netflix.com", 1), "search filters")
        if app.buttons["Cancel"].exists { app.buttons["Cancel"].tap() } else { search.buttons["Clear text"].tap() }
        app.navigationBars.buttons["New item"].firstMatch.tap()
        sleep(1); shot("ipad-plus"); dump(app, "plus")
        app.typeKey(XCUIKeyboardKey.escape, modifierFlags: [])
        sleep(1)
        app.typeKey("n", modifierFlags: .command); sleep(2); shot("ipad-cmd-n"); dump(app, "cmdn")
        app.typeKey(XCUIKeyboardKey.escape, modifierFlags: []); sleep(1)
        if app.buttons["Cancel"].exists { app.buttons["Cancel"].tap(); sleep(1) }
        app.typeKey("f", modifierFlags: .command); sleep(1)
        print("CMDF-focus \(app.searchFields["Search"].value(forKey: "hasKeyboardFocus") as? Bool ?? false)")
        shot("ipad-cmd-f")
        app.typeKey(XCUIKeyboardKey.escape, modifierFlags: []); sleep(1)
        if app.buttons["Cancel"].exists { app.buttons["Cancel"].tap(); sleep(1) }
        app.staticTexts["amazon.com, alex@example.com"].firstMatch.tap(); sleep(1)
        UIPasteboard.general.string = "x"
        app.typeKey("c", modifierFlags: [.command, .shift]); sleep(1)
        shot("ipad-shift-cmd-c"); dump(app, "copy")
        print("COPY-result changed=\(UIPasteboard.general.string != "x") toast=\(exists(app, "Password copied", 1))")
        app.typeKey("l", modifierFlags: .command); sleep(2)
        shot("ipad-cmd-l"); dump(app, "lock")
        print("LOCK-result vaultGone=\(!app.searchFields["Search"].exists)")
    }

    /// PENDING iPad "Split View at 1/3 width falls back to tabs": `-LGKCompactWidth YES` gives the app the compact
    /// size class Split View gives it (UI tests cannot resize the window).
    @MainActor
    func testIPadCompactWidthUsesTabs() throws {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .pad, "iPad only")
        XCUIDevice.shared.orientation = .portrait
        let app = launch(["-LGKCompactWidth", "YES"])
        XCTAssertTrue(app.tabBars.firstMatch.waitForExistence(timeout: 60) || app.buttons["Settings"].waitForExistence(timeout: 5),
                      "tabs shown at compact width")
        sleep(2); shot("ipad-compact-tabs"); dump(app, "compact")
        XCTAssertFalse(exists(app, "Favorites", 1) && app.staticTexts["Collections"].exists, "no sidebar")
        app.buttons["Settings"].firstMatch.tap(); sleep(1); shot("ipad-compact-settings")
    }

    /// PENDING iPhone "Export to a CXF file asks Face ID (declined: no share sheet, no file)". The runner script
    /// answers Face ID with a match until this test writes `$LGK_SHOTS/nomatch.flag`, then with no match.
    @MainActor
    func testCXFExportDeclinedFaceIDShowsNoShareSheet() throws {
        let dir = try XCTUnwrap(ProcessInfo.processInfo.environment["LGK_SHOTS"], "needs LGK_SHOTS")
        let flag = URL(fileURLWithPath: dir).appendingPathComponent("nomatch.flag")
        try? FileManager.default.removeItem(at: flag)
        defer { try? FileManager.default.removeItem(at: flag) }
        let app = launch(["-LGKScreen", "settings"])
        // iPhone: Import & Export is a row of Settings; iPad: under Sync & data.
        let row = app.buttons["Import & Export"].firstMatch
        let data = app.buttons["Sync & data"].firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 60) || data.exists, "Settings open")
        if !row.exists && data.exists { data.tap(); sleep(1) }
        for _ in 0..<4 where !row.isHittable { app.swipeUp() }
        row.tap()
        sleep(1)
        var export = app.buttons["Export to a CXF file…"].firstMatch
        for _ in 0..<4 where !export.isHittable { app.swipeUp(); export = app.buttons["Export to a CXF file…"].firstMatch }
        export.tap(); sleep(2)
        shot("cxf-sheet"); dump(app, "cxf")
        let all = app.buttons.matching(NSPredicate(format: "label IN %@", ["Select all", "Select All"])).firstMatch
        if all.exists { all.tap() } else { app.cells.element(boundBy: 0).tap(); app.cells.element(boundBy: 1).tap() }
        try Data().write(to: flag)
        sleep(3)   // the loop now answers no match
        app.buttons.matching(NSPredicate(format: "label == 'Export'")).firstMatch.tap()
        sleep(8); shot("cxf-face-not-recognized")
        // "Face Not Recognized": Cancel declines the check (Face ID's own sheet, in SpringBoard or the app).
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        for host in [springboard, app] where host.buttons["Cancel"].firstMatch.exists {
            host.buttons["Cancel"].firstMatch.tap(); break
        }
        sleep(4); shot("cxf-declined"); dump(app, "cxf-declined")
        XCTAssertFalse(app.otherElements["ActivityListView"].exists, "no share sheet")
        XCTAssertFalse(app.buttons["Copy"].exists || app.buttons["Save to Files"].exists, "no share sheet")
        // The message must be on screen without scrolling (it was a footer below every item before 2026-11-15).
        let message = app.descendants(matching: .any)["cxf-export-message"].firstMatch
        XCTAssertTrue(message.waitForExistence(timeout: 3), "declined message")
        XCTAssertTrue(message.isHittable, "declined message is on screen")
        XCTAssertTrue(message.label.contains("did not succeed"), message.label)
        shot("cxf-declined-message")
    }

    /// PENDING "iPad wording": no text says "iPhone" on the iPad's lock screen, setup pages, Sync and Settings.
    @MainActor private func noIPhone(_ app: XCUIApplication, _ screen: String) {
        sleep(1)
        let hits = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS 'iPhone'")).allElementsBoundByIndex.map(\.label)
        XCTAssertEqual(hits, [], "\(screen) names the iPhone")
    }

    /// Run on a fresh install with Face ID matched: the setup pages, then Sync, Settings and Security.
    @MainActor
    func testIPadWording() throws {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .pad, "iPad only")
        XCUIDevice.shared.orientation = .landscapeLeft
        let app = XCUIApplication()
        app.launchArguments += ["-LGKDemoData", "YES"]
        app.launchEnvironment["LGK_DEBUG_PRO"] = "1"
        app.launch()
        XCTAssertTrue(app.buttons["Skip setup"].waitForExistence(timeout: 45), "setup pages")
        for page in 1...5 {
            shot("ipad-wording-setup-\(page)"); dump(app, "setup\(page)")
            noIPhone(app, "setup page \(page)")
            let skip = app.buttons["onboarding-skip"]
            guard skip.waitForExistence(timeout: 2) else { break }
            skip.tap()
        }
    }

    /// After `testIPadWording` (setup done), with Face ID matched: Sync, Settings and Security, one launch each.
    @MainActor
    func testIPadWordingScreens() throws {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .pad, "iPad only")
        XCUIDevice.shared.orientation = .landscapeLeft
        for screen in ["sync", "settings", "security"] {
            let app = launch(["-LGKScreen", screen])
            sleep(5)
            shot("ipad-wording-\(screen)"); dump(app, screen)
            noIPhone(app, screen)
            app.terminate()
        }
    }

    /// Run without Face ID matched (`LGK_FACEID_LOOP=1` but no match loop): the app stays on the lock screen.
    @MainActor
    func testIPadWordingLock() throws {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .pad, "iPad only")
        XCUIDevice.shared.orientation = .landscapeLeft
        let app = XCUIApplication()
        app.launchArguments += ["-LGKDemoData", "YES"]
        app.launch()
        sleep(10)
        shot("ipad-wording-lock"); dump(app, "lock")
        noIPhone(app, "lock screen")
    }

    @MainActor
    func testIPhoneRows() throws {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .phone, "iPhone only")
        let app = launch()
        let copy = app.buttons["Copy password"].firstMatch
        XCTAssertTrue(copy.waitForExistence(timeout: 60), "row copy button")
        shot("iphone-list"); dump(app, "phonelist")
        UIPasteboard.general.string = "x"
        copy.tap()
        shot("iphone-copied")   // the toast is hidden from accessibility (announced instead): checked on the shot
        print("PHONECOPY changed=\(UIPasteboard.general.string != "x")")
    }

    /// Collections screens in English, German or Japanese (`TEST_RUNNER_LGK_LANG=de|ja`): screenshots for clipping.
    @MainActor
    func testIPhoneCollections() throws {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .phone, "iPhone only")
        let lang = ProcessInfo.processInfo.environment["LGK_LANG"] ?? "en"
        let w: [String: [String]] = ["en": ["More", "Collections", "Manage collections", "Add starter collections"],
                                     "de": ["Mehr", "Sammlungen", "Sammlungen verwalten", "Startsammlungen hinzufügen"],
                                     "ja": ["その他", "コレクション", "コレクションを管理", "初期コレクションを追加"]]
        let t = try XCTUnwrap(w[lang])
        let app = launch(["-AppleLanguages", "(\(lang))", "-AppleLocale", lang])
        let more = app.buttons[t[0]].firstMatch
        XCTAssertTrue(more.waitForExistence(timeout: 60), "vault open")
        more.tap()
        app.buttons[t[1]].firstMatch.tap(); sleep(1)
        shot("coll-\(lang)-menu")
        app.buttons[t[2]].firstMatch.tap(); sleep(2)
        shot("coll-\(lang)-screen")
        let starters = app.buttons[t[3]].firstMatch
        if starters.exists { starters.tap(); sleep(2); shot("coll-\(lang)-starters") }
        dump(app, "coll-\(lang)")
        let raw = labels(app).filter { $0.range(of: #"^[a-z]+(\.[a-zA-Z_]+)+$"#, options: .regularExpression) != nil }
        XCTAssertTrue(raw.isEmpty, "raw keys: \(raw)")
        let row = app.cells.firstMatch
        if row.exists { row.swipeLeft(); sleep(1); shot("coll-\(lang)-swipe"); row.swipeRight() }
        // Share sheet of the first collection, if reachable from the row's context menu.
        if row.exists { row.press(forDuration: 1.2); sleep(1); shot("coll-\(lang)-context") }
    }

    @MainActor private func labels(_ root: XCUIElement) -> [String] {
        guard let snap = try? root.snapshot() else { return [] }
        var out: [String] = []
        func walk(_ s: XCUIElementSnapshot) { if !s.label.isEmpty { out.append(s.label) }; s.children.forEach(walk) }
        walk(snap)
        return out
    }

    @MainActor
    func disabled_testExplore() throws {
        let app = launch()
        sleep(12)
        shot("start")
        dump(app, "start")
    }
}
