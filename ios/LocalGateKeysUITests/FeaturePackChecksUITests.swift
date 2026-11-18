import XCTest

/// PENDING iPhone checks (feature pack, access rules, travel mode, clean-up, collections, power-user pack) on the
/// simulator with demo data and Pro. Needs Face ID answered in a loop from the Mac: a match every 2 s, a no-match while
/// `$LGK_SHOTS/nomatch.flag` exists (see `testCXFExportDeclinedFaceIDShowsNoShareSheet`). Run with
/// `TEST_RUNNER_LGK_FACEID_LOOP=1 TEST_RUNNER_LGK_SHOTS=<dir>`.
final class FeaturePackChecksUITests: XCTestCase {
    private var shots: String { ProcessInfo.processInfo.environment["LGK_SHOTS"] ?? NSTemporaryDirectory() }

    override func setUpWithError() throws {
        continueAfterFailure = true
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_FACEID_LOOP"] == "1", "needs the Face ID loop")
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .phone, "iPhone only")
        faceID(match: true)
    }

    override func tearDown() { faceID(match: true) }

    // MARK: - Helpers

    @MainActor private func shot(_ name: String) {
        let a = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        a.name = name; a.lifetime = .keepAlways
        add(a)
        try? XCUIScreen.main.screenshot().pngRepresentation.write(to: URL(fileURLWithPath: "\(shots)/\(name).png"))
    }

    @MainActor private func dump(_ app: XCUIApplication, _ tag: String) {
        try? app.debugDescription.write(toFile: "\(shots)/\(tag).txt", atomically: true, encoding: .utf8)
    }

    /// The Face ID loop answers with a match, or with no match while the flag file exists.
    private func faceID(match: Bool) {
        let flag = URL(fileURLWithPath: shots).appendingPathComponent("nomatch.flag")
        if match { try? FileManager.default.removeItem(at: flag) } else { try? Data().write(to: flag) }
    }

    @MainActor private func launch(_ extra: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments += ["-LGKDemoData", "YES"] + extra
        app.launchEnvironment["LGK_DEBUG_PRO"] = "1"
        app.launch()
        if app.buttons["Skip setup"].waitForExistence(timeout: 30) { app.buttons["Skip setup"].tap(); sleep(1) }
        if app.buttons["Continue"].waitForExistence(timeout: 3) { app.buttons["Continue"].tap(); sleep(1) }
        // A StoreKit restore can leave the system "Sign in to Apple Account" alert up: Cancel it (never type in it).
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        for _ in 0..<12 where !app.tabBars.buttons["Vault"].waitForExistence(timeout: 10) {
            let alert = springboard.alerts.firstMatch
            if alert.exists, alert.staticTexts["Sign in to Apple Account"].exists || alert.label.contains("Apple Account") {
                alert.buttons["Cancel"].tap(); sleep(2)
            }
            if app.buttons["Use Face ID"].exists { app.buttons["Use Face ID"].tap() }
            else if app.buttons["Unlock"].exists && !app.secureTextFields["App password"].exists { app.buttons["Unlock"].tap() }
        }
        XCTAssertTrue(app.tabBars.buttons["Vault"].waitForExistence(timeout: 90), "vault open")
        return app
    }

    @MainActor private func any(_ app: XCUIApplication, _ label: String, exact: Bool = false) -> XCUIElement {
        app.descendants(matching: .any)
            .matching(NSPredicate(format: exact ? "label == %@" : "label BEGINSWITH %@", label)).firstMatch
    }

    @MainActor private func exists(_ app: XCUIApplication, _ label: String, _ t: TimeInterval = 3) -> Bool {
        any(app, label).waitForExistence(timeout: t)
    }

    @MainActor private func contains(_ app: XCUIApplication, _ text: String, _ t: TimeInterval = 3) -> Bool {
        app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", text)).firstMatch
            .waitForExistence(timeout: t)
    }

    /// Taps the first element labelled `label` (exact first, then prefix), scrolling up to find it.
    @MainActor @discardableResult
    private func tap(_ app: XCUIApplication, _ label: String, in type: XCUIElement.ElementType? = nil,
                     scrolls: Int = 6, wait: UInt32 = 1) -> Bool {
        func find() -> XCUIElement {
            let q = type.map { app.descendants(matching: $0) } ?? app.descendants(matching: .any)
            let exact = q.matching(NSPredicate(format: "label == %@", label)).firstMatch
            return exact.exists ? exact : q.matching(NSPredicate(format: "label BEGINSWITH %@", label)).firstMatch
        }
        var e = find()
        if !e.waitForExistence(timeout: 3) { e = find() }
        var n = 0
        while (!e.exists || !e.isHittable) && n < scrolls { app.swipeUp(velocity: .slow); n += 1; e = find() }
        guard e.exists else { XCTFail("no \(label)"); return false }
        e.tap(); sleep(wait)
        return true
    }

    @MainActor private func toggle(_ app: XCUIApplication, _ label: String, on: Bool, retry: Bool = true) {
        let s = app.switches.matching(NSPredicate(format: "label BEGINSWITH %@", label)).firstMatch
        var n = 0
        while (!s.exists || !s.isHittable) && n < 4 { app.swipeUp(velocity: .slow); n += 1 }
        guard s.exists else { XCTFail("no switch \(label)"); return }
        // The switch itself, not the label (a tap on the row's middle can miss it); taps get lost under load, so
        // check and try again.
        for attempt in 0..<(retry ? 4 : 1) where (s.value as? String == "1") != on {
            let inner = s.switches.firstMatch
            if attempt % 2 == 1, inner.exists { inner.tap() } else {
                s.coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap()
            }
            // The value can lag behind the tap under load: wait before tapping again (a second tap flips it back).
            for _ in 0..<8 where (s.value as? String == "1") != on { sleep(1) }
        }
        if retry { XCTAssertEqual(s.value as? String == "1", on, "switch \(label)") }
    }

    /// Opens a login from the Vault list through search (the list has several rows per site).
    @MainActor private func openLogin(_ app: XCUIApplication, _ site: String, _ user: String) {
        app.tabBars.buttons["Vault"].tap()
        let search = app.searchFields.firstMatch
        if !search.waitForExistence(timeout: 3) { any(app, "Search").tap() }
        search.tap(); search.typeText(site)
        sleep(2)
        let row = app.descendants(matching: .any)
            .matching(NSPredicate(format: "label CONTAINS %@ AND label CONTAINS %@", site, user)).firstMatch
        if row.waitForExistence(timeout: 4) { row.tap() } else {
            app.staticTexts.matching(NSPredicate(format: "label == %@", user)).firstMatch.tap()
        }
        sleep(2)
    }

    /// Waits (up to `timeout`) while the system Face ID prompt is on screen: a match through the loop is slow under load.
    @MainActor private func awaitFaceID(timeout: TimeInterval = 40) {
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        sleep(2)
        let start = Date()
        while Date().timeIntervalSince(start) < timeout,
              springboard.staticTexts["Face ID"].exists || springboard.otherElements["Face ID"].exists {
            sleep(1)
        }
        sleep(1)
    }

    /// The system Face ID / passcode sheet's Cancel (SpringBoard's or the app's).
    @MainActor private func cancelSystemSheet(_ app: XCUIApplication) {
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        for host in [springboard, app] where host.buttons["Cancel"].firstMatch.exists {
            host.buttons["Cancel"].firstMatch.tap(); sleep(2); return
        }
    }

    // MARK: - Access rules (feature pack §4)

    /// Item › Access rules: sets the switches named in `on` (and clears those in `off`), then Save. Loosening asks
    /// the owner (the Face ID loop matches).
    @MainActor private func setRules(_ app: XCUIApplication, on: [String] = [], off: [String] = []) {
        tap(app, "Access rules", in: .button)
        XCTAssertTrue(app.navigationBars["Access rules"].waitForExistence(timeout: 5), "Access rules screen")
        for s in on { toggle(app, s, on: true) }
        for s in off { toggle(app, s, on: false) }
        shot("rules-\(name.count)-\(on.count)-\(off.count)"); dump(app, "rules-last")
        app.navigationBars["Access rules"].buttons["Save"].tap()
        awaitFaceID()   // the owner check when loosening
        if app.navigationBars["Access rules"].exists { cancelSystemSheet(app) }
    }

    @MainActor private func sixDigits(_ app: XCUIApplication) -> Bool {
        app.staticTexts.matching(NSPredicate(format: "label MATCHES '^[0-9]{6}$'")).count > 0
    }

    /// The pasteboard as the Mac reads it (`simctl pbpaste` into `$LGK_SHOTS/pb.txt` every second: the test runner
    /// is not allowed to read what the app copied). The mirror lags a few seconds.
    @MainActor private func pasteboardText() -> String? {
        try? String(contentsOfFile: "\(shots)/pb.txt", encoding: .utf8)
    }

    /// Waits up to `timeout` for the pasteboard to hold `text`.
    @MainActor private func pasteboardBecomes(_ text: String, timeout: TimeInterval = 12) -> Bool {
        let start = Date()
        while Date().timeIntervalSince(start) < timeout {
            if pasteboardText() == text { return true }
            usleep(500_000)
        }
        return false
    }

    /// Scrolls the item screen back to its top (the access banner is the first section).
    @MainActor private func scrollTop(_ app: XCUIApplication) {
        for _ in 0..<3 { app.swipeDown(velocity: .fast) }
        sleep(1)
    }

    /// Waits up to `timeout` for a 6-digit code on screen (a Face ID match through the loop can take a while).
    @MainActor private func codeAppears(_ app: XCUIApplication, timeout: TimeInterval = 25) -> Bool {
        let start = Date()
        while Date().timeIntervalSince(start) < timeout {
            if sixDigits(app) { return true }
            sleep(1)
        }
        return false
    }

    /// "Confirm it's me" (ask again): the code and the password stay masked, a declined Face ID reveals nothing, a
    /// match reveals; copying asks too.
    @MainActor
    func testAccessRulesAskAgain() throws {
        let app = launch()
        openLogin(app, "github.com", "alex@example.com")
        setRules(app, on: ["Confirm it's me"])
        scrollTop(app)
        shot("ask-banner"); dump(app, "ask-detail")
        XCTAssertTrue(exists(app, "This login has access rules."), "banner")
        XCTAssertTrue(contains(app, "Asks to confirm it's you"), "banner names the rule")
        XCTAssertFalse(sixDigits(app), "2FA code masked on a restricted login")
        // Declined Face ID: nothing is revealed.
        faceID(match: false); sleep(3)
        app.buttons.matching(NSPredicate(format: "label == 'Reveal'")).firstMatch.tap()
        sleep(8); shot("ask-reveal-nomatch")
        cancelSystemSheet(app)
        sleep(2); shot("ask-reveal-declined")
        XCTAssertFalse(sixDigits(app), "declined: code stays masked")
        // Declined copy: nothing copied.
        tap(app, "Copy Password", in: .button, wait: 0); sleep(8); shot("ask-copy-nomatch")
        cancelSystemSheet(app)
        XCTAssertFalse(pasteboardBecomes("demo-Pass-1-orbit", timeout: 8), "declined copy copies nothing")
        // Face ID matched: revealed and copied.
        faceID(match: true); sleep(3)
        app.buttons.matching(NSPredicate(format: "label == 'Reveal'")).firstMatch.tap()
        XCTAssertTrue(codeAppears(app), "matched: code shown")
        shot("ask-reveal-match")
        tap(app, "Copy Password", in: .button, wait: 0)
        XCTAssertTrue(pasteboardBecomes("demo-Pass-1-orbit", timeout: 30), "matched copy")
        setRules(app, off: ["Confirm it's me"])
        scrollTop(app)
        XCTAssertFalse(exists(app, "This login has access rules.", 2), "rule removed")
        XCTAssertTrue(sixDigits(app), "code shown again")
    }

    /// Copy once: the first password copy needs nothing, a username copy does not use it up, the second password
    /// copy asks (declined: nothing copied), and the copy clears after 10 s.
    @MainActor
    func testAccessRulesCopyOnce() throws {
        let app = launch()
        openLogin(app, "proton.me", "alex.demo")
        setRules(app, on: ["Copy once per unlock"])
        scrollTop(app); shot("once-banner"); dump(app, "once-detail")
        XCTAssertTrue(contains(app, "Copy once per unlock, then confirm again"), "banner")
        faceID(match: false); sleep(3)   // any owner check from here on fails
        tap(app, "Copy Password", in: .button, wait: 0)
        XCTAssertTrue(pasteboardBecomes("demo-Pass-2-orbit"), "first copy needs no check")
        tap(app, "Copy Username", in: .button, wait: 0)
        XCTAssertTrue(pasteboardBecomes("alex.demo"), "a username copy needs no check")
        tap(app, "Copy Password", in: .button, wait: 0); sleep(8); shot("once-second-copy-nomatch")
        cancelSystemSheet(app)
        XCTAssertFalse(pasteboardBecomes("demo-Pass-2-orbit", timeout: 8), "second password copy refused without the owner")
        faceID(match: true); sleep(3)
        tap(app, "Copy Password", in: .button, wait: 0)
        XCTAssertTrue(pasteboardBecomes("demo-Pass-2-orbit", timeout: 30), "second copy after Face ID")
        let seen = Date()
        var cleared: TimeInterval?
        while Date().timeIntervalSince(seen) < 40 {
            if pasteboardText() != "demo-Pass-2-orbit" { cleared = Date().timeIntervalSince(seen); break }
            usleep(500_000)
        }
        print("ONCE-cleared-after-seen=\(cleared.map { String($0) } ?? "never")")
        XCTAssertNotNil(cleared, "copy once clears")
        XCTAssertLessThan(cleared ?? 99, 14, "cleared about 10 s after the copy, not 60 s")
        setRules(app, off: ["Copy once per unlock"])
    }

    /// View only on phones: no Share, no copy of the password, the code masked until Face ID.
    @MainActor
    func testAccessRulesViewOnly() throws {
        let app = launch()
        openLogin(app, "google.com", "alex.demo@example.com")
        XCTAssertTrue(app.buttons["Share"].exists, "Share before the rule")
        setRules(app, on: ["View only on phones"])
        scrollTop(app); shot("view-banner"); dump(app, "view-detail")
        XCTAssertTrue(contains(app, "View only on phones"), "banner")
        XCTAssertFalse(app.buttons["Share"].exists, "no Share on a view-only login")
        XCTAssertFalse(sixDigits(app), "code masked")
        tap(app, "Copy Password", in: .button, wait: 0); sleep(1); shot("view-copy-refused")
        XCTAssertFalse(pasteboardBecomes("demo-Pass-4-orbit", timeout: 8), "view only: not copied")
        setRules(app, off: ["View only on phones"])
        XCTAssertTrue(app.buttons["Share"].waitForExistence(timeout: 3), "Share back after removing the rule")
    }

    /// Access expires: a date in the past shows the expired banner; Offer in AutoFill off says so.
    @MainActor
    func testAccessRulesExpiredAndNeverFill() throws {
        let app = launch()
        openLogin(app, "bank.example", "alex.p")
        tap(app, "Access rules", in: .button)
        toggle(app, "Access expires", on: true)
        toggle(app, "Offer in AutoFill", on: false)
        sleep(1); shot("exp-picker"); dump(app, "exp-picker")
        // The compact date picker: open it and pick the 1st of the shown month (before today, the 16th).
        let picker = app.datePickers.firstMatch
        if picker.exists { picker.buttons.firstMatch.tap() } else { any(app, "Expires on").tap() }
        sleep(2); shot("exp-calendar"); dump(app, "exp-calendar")
        let first = app.buttons.matching(NSPredicate(format: "label CONTAINS[c] 'November 1' OR label CONTAINS '1 November'")).firstMatch
        if first.exists { first.tap() } else { XCTFail("no 1 November in the calendar") }
        sleep(1)
        app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.08)).tap(); sleep(1)   // close the popover
        shot("exp-picked")
        app.navigationBars["Access rules"].buttons["Save"].tap(); sleep(3)
        scrollTop(app); shot("exp-banner"); dump(app, "exp-detail")
        XCTAssertTrue(contains(app, "Access expired on"), "expired banner")
        XCTAssertTrue(contains(app, "Not offered by AutoFill"), "never fill in the banner")
        XCTAssertFalse(app.staticTexts["demo-Pass-3-orbit"].exists)
    }

    // MARK: - Collections and travel mode

    @MainActor private func vaultRoot(_ app: XCUIApplication) {
        if app.keyboards.firstMatch.exists, app.buttons["Cancel"].exists { app.buttons["Cancel"].tap(); sleep(1) }
        app.tabBars.buttons["Vault"].tap(); sleep(1)
        // The search screen (pushed on the Vault tab) closes with its Close button.
        if app.navigationBars["Search"].buttons["Close"].exists { app.navigationBars["Search"].buttons["Close"].tap(); sleep(1) }
        for _ in 0..<4 where app.navigationBars.buttons["BackButton"].exists {
            app.navigationBars.buttons["BackButton"].tap(); sleep(1)
        }
        if app.buttons["Cancel"].exists { app.buttons["Cancel"].tap(); sleep(1) }
        if app.navigationBars["Search"].buttons["Close"].exists { app.navigationBars["Search"].buttons["Close"].tap(); sleep(1) }
    }

    @MainActor private func openNote(_ app: XCUIApplication, _ title: String) {
        vaultRoot(app)
        let search = app.searchFields.firstMatch
        if !search.waitForExistence(timeout: 3) { any(app, "Search").tap() }
        search.tap(); search.typeText(title); sleep(2)
        app.staticTexts.matching(NSPredicate(format: "label == %@", title)).firstMatch.tap(); sleep(2)
    }

    /// Edit › Collections › `name` › Save.
    @MainActor private func addToCollection(_ app: XCUIApplication, _ name: String) {
        app.navigationBars.buttons["Edit"].tap(); sleep(2)
        tap(app, "Collections", in: .button)
        shot("picker-\(name)"); dump(app, "picker")
        let row = app.buttons.matching(NSPredicate(format: "label == %@", name)).firstMatch
        if !(row.exists && row.isSelected) { tap(app, name, in: .button, scrolls: 2) }   // a tap on a member removes it
        app.navigationBars.buttons.element(boundBy: 0).tap(); sleep(1)
        app.navigationBars.buttons["Save"].tap(); sleep(2)
    }

    @MainActor private func moreMenu(_ app: XCUIApplication, _ path: [String]) {
        vaultRoot(app)
        let more = app.buttons["More"].firstMatch
        if !more.waitForExistence(timeout: 5) {
            dump(app, "more-missing"); shot("more-missing")
            if app.buttons["Cancel"].exists { app.buttons["Cancel"].tap(); sleep(1) }
            vaultRoot(app)
        }
        more.tap(); sleep(1)
        for p in path { tap(app, p, in: .button, scrolls: 0) }
    }

    @MainActor private func searchFinds(_ app: XCUIApplication, _ text: String) -> Bool {
        vaultRoot(app)
        let search = app.searchFields.firstMatch
        if !search.waitForExistence(timeout: 3) { any(app, "Search").tap() }
        search.tap(); search.typeText(text); sleep(2)
        let found = app.staticTexts.matching(NSPredicate(format: "label == %@", text)).firstMatch.exists
        shot("search-\(text.replacingOccurrences(of: " ", with: "_"))-\(found)")
        return found
    }

    @MainActor private func settingsPage(_ app: XCUIApplication, _ category: String) {
        app.tabBars.buttons["Settings"].tap(); sleep(1)
        for _ in 0..<4 where app.navigationBars.buttons["BackButton"].exists {
            app.navigationBars.buttons["BackButton"].tap(); sleep(1)
        }
        tap(app, category, in: .button)
    }

    /// PENDING "Collections: add a note to Family from the editor, filter by Family, delete Family (the note stays)",
    /// with travel mode hiding Family in between (list, search, Collections, Security check, Recently deleted; off
    /// needs Face ID).
    @MainActor
    func testCollectionsAndTravelMode() throws {
        let app = launch()
        moreMenu(app, ["Collections", "Manage collections"])
        shot("coll-manage"); dump(app, "coll-manage")
        // The starters are Personal, Work, Travel and Emergency: Family is made here.
        if !app.staticTexts["Family"].exists && !app.buttons["Family"].exists {
            app.buttons["New collection"].tap(); sleep(2)
            let name = app.alerts.textFields.firstMatch
            XCTAssertTrue(name.waitForExistence(timeout: 5), "new collection name")
            name.typeText("Family")
            app.alerts.buttons["Create"].tap(); sleep(2)
        }
        shot("coll-family-made"); dump(app, "coll-family-made")
        XCTAssertTrue(exists(app, "Family"), "Family collection")
        // Two notes in Family from the editor; one goes to Recently deleted.
        openNote(app, "Door code"); addToCollection(app, "Family")
        if !app.navigationBars["Door code"].exists { openNote(app, "Door code") }
        shot("coll-door-saved"); dump(app, "coll-door-saved")
        XCTAssertTrue(exists(app, "Family"), "the note shows its collection")
        openNote(app, "Wi-Fi at home"); addToCollection(app, "Family")
        if !app.navigationBars["Wi-Fi at home"].exists { openNote(app, "Wi-Fi at home") }
        app.navigationBars.buttons["Edit"].tap(); sleep(2)
        tap(app, "Delete item", in: .button)
        app.buttons.matching(NSPredicate(format: "label == 'Delete'")).firstMatch.tap(); sleep(2)
        // Filter by Family.
        moreMenu(app, ["Collections", "Family"])
        sleep(1); shot("coll-filter-family"); dump(app, "coll-filter")
        XCTAssertTrue(app.staticTexts["Door code"].exists, "Door code under Family")
        XCTAssertFalse(app.staticTexts["bank.example"].exists, "others filtered out")
        if app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Collection: '")).firstMatch.exists {
            app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Collection: '")).firstMatch.tap(); sleep(1)
        }
        // Travel mode hides Family.
        settingsPage(app, "Sync & data")
        tap(app, "Travel mode", in: .button)
        toggle(app, "Family", on: true)
        toggle(app, "Travel mode", on: true)
        sleep(2); shot("travel-on"); dump(app, "travel-on")
        XCTAssertTrue(contains(app, "items are hidden on this device"), "travel on")
        vaultRoot(app); shot("travel-list")
        XCTAssertFalse(app.staticTexts["Door code"].exists, "hidden in the list")
        XCTAssertFalse(searchFinds(app, "Door code"), "hidden in search")
        moreMenu(app, ["Collections"]); shot("travel-collections-menu"); dump(app, "travel-coll-menu")
        if app.buttons["Family"].exists {
            app.buttons["Family"].tap(); sleep(1); shot("travel-family-filter")
            XCTAssertFalse(app.staticTexts["Door code"].exists, "hidden under Family")
        } else { app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.9)).tap() }
        app.tabBars.buttons["Security"].tap(); sleep(2); shot("travel-security"); dump(app, "travel-security")
        settingsPage(app, "Sync & data")
        tap(app, "Recently deleted", in: .button); sleep(1)
        shot("travel-trash"); dump(app, "travel-trash")
        XCTAssertFalse(app.staticTexts["Wi-Fi at home"].exists, "hidden in Recently deleted")
        // Off needs Face ID: declined stays on.
        app.navigationBars.buttons["BackButton"].tap(); sleep(1)
        tap(app, "Travel mode", in: .button)
        faceID(match: false); sleep(3)
        toggle(app, "Travel mode", on: false, retry: false)
        sleep(6); shot("travel-off-nomatch")
        cancelSystemSheet(app); sleep(2)
        shot("travel-off-declined")
        XCTAssertTrue(contains(app, "items are hidden on this device"), "declined: still on")
        faceID(match: true); sleep(3)
        toggle(app, "Travel mode", on: false, retry: false)
        sleep(6); shot("travel-off")
        XCTAssertFalse(contains(app, "items are hidden on this device", 1), "off after Face ID")
        vaultRoot(app)
        XCTAssertTrue(searchFinds(app, "Door code"), "shown again")
        // Delete Family: the note stays.
        moreMenu(app, ["Collections", "Manage collections"])
        let family = app.cells.containing(NSPredicate(format: "label BEGINSWITH 'Family'")).firstMatch
        if family.exists { family.swipeLeft() } else { any(app, "Family").swipeLeft() }
        sleep(1); shot("coll-family-swipe")
        app.buttons["Delete"].firstMatch.tap(); sleep(1); shot("coll-family-confirm"); dump(app, "coll-delete-confirm")
        app.buttons.matching(NSPredicate(format: "label == 'Delete'")).firstMatch.tap(); sleep(2)
        shot("coll-family-deleted")
        XCTAssertFalse(app.staticTexts["Family"].exists, "Family deleted")
        XCTAssertTrue(searchFinds(app, "Door code"), "the note stays")
    }

    // MARK: - CSV import and clean-up

    /// Import & Export › Import from a file › On My iPhone › `file` (put there by the runner).
    @MainActor private func importFile(_ app: XCUIApplication, _ file: String) {
        settingsPage(app, "Sync & data")
        tap(app, "Import & Export", in: .button)
        tap(app, "Import from a file", in: .button, wait: 3)
        shot("picker-open"); dump(app, "picker-open")
        let entry = app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@", file)).firstMatch
        if !entry.waitForExistence(timeout: 5) {
            if app.buttons["Browse"].exists { app.buttons["Browse"].tap(); sleep(2) }
            let mine = app.descendants(matching: .any).matching(NSPredicate(format: "label == 'On My iPhone'")).firstMatch
            if mine.waitForExistence(timeout: 5) { mine.tap(); sleep(2) }
            shot("picker-browse"); dump(app, "picker-browse")
        }
        if entry.waitForExistence(timeout: 8) { entry.tap() } else { XCTFail("no \(file) in the picker") }
        sleep(4)
    }

    /// PENDING "Import a CSV, read the report, Undo" then "Clean-up: review and merge (both website addresses kept),
    /// swipe delete, Select > Delete / Merge all, Undo".
    @MainActor
    func testCSVImportAndCleanUp() throws {
        let app = launch()
        importFile(app, "lgk-test-import")
        shot("csv-review"); dump(app, "csv-review")
        XCTAssertTrue(app.navigationBars["Review import"].waitForExistence(timeout: 10), "review")
        if app.buttons["Keep both for duplicates"].exists { app.buttons["Keep both for duplicates"].tap(); sleep(1) }
        app.navigationBars["Review import"].buttons["Import"].tap(); sleep(5)
        shot("csv-report"); dump(app, "csv-report")
        XCTAssertTrue(exists(app, "Undo this import", 10), "report with Undo")
        tap(app, "Undo this import", in: .button)
        shot("csv-undo-confirm")
        app.buttons.matching(NSPredicate(format: "label == 'Undo this import'")).element(boundBy: 1).tap(); sleep(3)
        shot("csv-undone"); dump(app, "csv-undone")
        if app.buttons["Done"].exists { app.buttons["Done"].tap(); sleep(1) }
        XCTAssertFalse(searchFinds(app, "Imported site"), "undo removed the import")
        // Import again and keep it, for the clean-up.
        importFile(app, "lgk-test-import")
        if app.buttons["Keep both for duplicates"].exists { app.buttons["Keep both for duplicates"].tap(); sleep(1) }
        app.navigationBars["Review import"].buttons["Import"].tap(); sleep(5)
        if app.buttons["Done"].waitForExistence(timeout: 5) { app.buttons["Done"].tap(); sleep(1) }
        XCTAssertTrue(searchFinds(app, "Imported site"), "imported")
        // Clean-up.
        app.tabBars.buttons["Security"].tap(); sleep(2)
        tap(app, "Clean-up", in: .button, wait: 2)
        shot("clean-1"); dump(app, "clean-1")
        for i in 2...4 { app.swipeUp(); shot("clean-\(i)") }
        dump(app, "clean-end")
    }

    // MARK: - Power-user pack

    /// PENDING "Restore test row with Test now, the printable health report, Estate pack in emergency access, share
    /// sheet Expires in and One use only, the Wi-Fi QR does not expire line".
    @MainActor
    func testPowerUserPack() throws {
        let app = launch()
        // Wi-Fi QR.
        openNote(app, "Home Wi-Fi")
        tap(app, "Show QR", in: .button, wait: 2)
        shot("pu-wifi-qr"); dump(app, "pu-wifi-qr")
        XCTAssertTrue(contains(app, "This code does not expire"), "Wi-Fi QR line")
        if app.buttons["Done"].exists { app.buttons["Done"].tap() } else { app.swipeDown(velocity: .fast) }
        sleep(1)
        // Share sheet options.
        openLogin(app, "amazon.com", "alex@example.com")
        app.buttons["Share"].tap(); sleep(3)
        shot("pu-share"); dump(app, "pu-share")
        XCTAssertTrue(contains(app, "Expires in"), "Expires in")
        XCTAssertTrue(contains(app, "One use only"), "One use only")
        if app.navigationBars["Share item"].buttons["Done"].exists { app.navigationBars["Share item"].buttons["Done"].tap() }
        else { app.swipeDown(velocity: .fast) }
        sleep(2)
        // Restore test and health report.
        settingsPage(app, "Lock & security")
        shot("pu-lock-1"); dump(app, "pu-lock-1")
        let testNow = app.buttons["Test now"].firstMatch
        for _ in 0..<6 where !testNow.isHittable { app.swipeUp(velocity: .slow) }
        shot("pu-restore-test"); dump(app, "pu-restore-test")
        XCTAssertTrue(testNow.exists, "Test now")
        XCTAssertTrue(contains(app, "Last backup restore test") || contains(app, "restore test"), "Restore test row")
        tap(app, "Print vault health report", in: .button, wait: 4)
        shot("pu-print"); dump(app, "pu-print")
        if app.buttons["Cancel"].exists { app.buttons["Cancel"].tap(); sleep(1) }
        // Emergency access › Estate pack.
        for _ in 0..<6 where !app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Emergency'")).firstMatch.isHittable {
            app.swipeUp(velocity: .slow)
        }
        app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Emergency'")).firstMatch.tap(); sleep(2)
        shot("pu-emergency-1"); dump(app, "pu-emergency-1")
        for i in 2...4 { app.swipeUp(velocity: .slow); shot("pu-emergency-\(i)") }
        dump(app, "pu-emergency-end")
        XCTAssertTrue(contains(app, "Estate pack"), "Estate pack section")
    }

    // MARK: - Item history, privacy proof, passkey check

    /// PENDING "Item history after an edit (masked diff, restore one field)".
    @MainActor
    func testItemHistoryAfterAnEdit() throws {
        let app = launch()
        openLogin(app, "dropbox.com", "alex@example.com")
        app.navigationBars.buttons["Edit"].tap(); sleep(2)
        app.buttons["Generate password"].firstMatch.tap(); sleep(2)
        shot("hist-generate"); dump(app, "hist-generate")
        for name in ["Use password", "Use", "Use This Password", "Done"] where app.buttons[name].exists {
            app.buttons[name].firstMatch.tap(); sleep(1); break
        }
        let notes = app.textViews["Notes"].exists ? app.textViews["Notes"]
            : (app.textFields["Notes"].exists ? app.textFields["Notes"] : app.textViews.firstMatch)
        for _ in 0..<4 where !notes.isHittable { app.swipeUp(velocity: .slow) }
        notes.tap(); notes.typeText("history check note")
        app.navigationBars.buttons["Save"].tap(); sleep(3)
        shot("hist-saved")
        if app.alerts.firstMatch.exists { dump(app, "hist-alert"); app.alerts.buttons.firstMatch.tap(); sleep(1) }
        if !app.navigationBars["dropbox.com"].exists { openLogin(app, "dropbox.com", "alex@example.com") }
        tap(app, "Item history", in: .button, wait: 2)
        shot("hist-list"); dump(app, "hist-list")
        tap(app, "Edited", wait: 2)
        shot("hist-version"); dump(app, "hist-version")
        XCTAssertFalse(app.staticTexts["demo-Shared-orbit-77"].exists, "earlier password masked")
        XCTAssertTrue(contains(app, "Notes"), "notes change listed")
        if app.navigationBars.buttons["Reveal"].exists {
            app.navigationBars.buttons["Reveal"].tap(); awaitFaceID()
            shot("hist-revealed")
            XCTAssertTrue(contains(app, "demo-Shared-orbit-77"), "revealed after Face ID")
        } else { XCTFail("no Reveal on the earlier version") }
        let restore = app.buttons.matching(NSPredicate(format: "label == 'Restore Password'")).firstMatch
        if restore.exists { restore.tap() } else { tap(app, "Restore this field", in: .button) }
        sleep(1); shot("hist-restore-alert")
        app.alerts.buttons["Restore"].firstMatch.tap(); sleep(3)
        shot("hist-restored"); dump(app, "hist-restored")
        app.navigationBars.buttons.element(boundBy: 0).tap(); sleep(1)
        app.navigationBars.buttons.element(boundBy: 0).tap(); sleep(2)
        shot("hist-detail-after"); dump(app, "hist-detail-after")
        app.buttons.matching(NSPredicate(format: "label == 'Reveal'")).firstMatch.tap(); sleep(3)
        XCTAssertTrue(app.staticTexts["demo-Shared-orbit-77"].exists, "the password is back, the note kept")
        XCTAssertTrue(contains(app, "history check note"), "the notes change stays")
        shot("hist-detail-revealed")
    }

    /// PENDING "Privacy proof export" (sync off: not signed) and "Passkey check": the file is saved to On My iPhone
    /// for `lgk proof verify`.
    @MainActor
    func testPrivacyProofAndPasskeyCheck() throws {
        let app = launch()
        settingsPage(app, "AutoFill")
        tap(app, "Passkey check", in: .button, wait: 2)
        shot("passkey-check"); dump(app, "passkey-check")
        XCTAssertTrue(app.navigationBars["Passkey check"].exists, "Passkey check screen")
        settingsPage(app, "Sync & data")
        tap(app, "Privacy proof", in: .button, wait: 3)
        shot("proof-1"); dump(app, "proof-1")
        XCTAssertTrue(app.buttons["Export privacy proof"].exists, "Export privacy proof")
        // The file is written to the app's tmp folder while this screen is open: the runner copies it from the
        // simulator's container for `lgk proof verify` (the share sheet is out of process).
        let sync = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Sync, '")).firstMatch.label
        print("PROOF-sync=\(sync) unsigned-note=\(contains(app, "so the file is not signed", 1))")
        try? Data().write(to: URL(fileURLWithPath: "\(shots)/proof-open.flag"))
        sleep(20)
        tap(app, "Export privacy proof", in: .button, wait: 10)
        shot("proof-share")
    }

    // MARK: - Face ID lockout (review fixes 2026-11-15)

    /// Fails Face ID until it locks out, then Reveal, Export and Share each show a clear message. The runner
    /// re-enrolls Face ID afterwards to end the lockout.
    @MainActor
    func testFaceIDLockoutMessages() throws {
        let app = launch()
        openLogin(app, "github.com", "alex@example.com")
        setRules(app, on: ["Confirm it's me"])
        faceID(match: false); sleep(3)
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        var locked = false
        for round in 1...8 where !locked {
            app.buttons.matching(NSPredicate(format: "label == 'Reveal'")).firstMatch.tap()
            sleep(7)
            shot("lock-round-\(round)"); dump(springboard, "lock-sb-\(round)"); dump(app, "lock-app-\(round)")
            if contains(app, "Face ID is locked", 1) || contains(springboard, "Face ID is locked", 1) { locked = true; break }
            for host in [springboard, app] {
                let again = host.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Try Face ID Again' OR label == 'Try Again'")).firstMatch
                if again.exists { again.tap(); sleep(5) }
            }
            if contains(app, "Face ID is locked", 1) { locked = true; break }
            cancelSystemSheet(app); sleep(2)
            if app.alerts.firstMatch.exists {
                shot("lock-alert-\(round)"); dump(app, "lock-alert-\(round)")
                if contains(app, "Face ID is locked", 1) { locked = true }
                app.alerts.buttons.firstMatch.tap(); sleep(1)
            }
        }
        print("LOCKOUT reached=\(locked)")
        XCTAssertTrue(locked, "Reveal shows the lockout message")
        if app.alerts.firstMatch.exists { app.alerts.buttons.firstMatch.tap(); sleep(1) }
        cancelSystemSheet(app)
        // Share.
        if app.buttons["Share"].exists {
            app.buttons["Share"].tap(); sleep(6); shot("lock-share"); dump(app, "lock-share")
            print("LOCKOUT share-message=\(contains(app, "Face ID is locked", 1))")
            if app.alerts.firstMatch.exists { app.alerts.buttons.firstMatch.tap(); sleep(1) }
            cancelSystemSheet(app)
            if app.buttons["Cancel"].exists { app.buttons["Cancel"].tap(); sleep(1) } else { app.swipeDown(velocity: .fast); sleep(1) }
        }
        // Export.
        startCSVExport(app); sleep(7)
        shot("lock-export"); dump(app, "lock-export")
        XCTAssertTrue(contains(app, "Face ID is locked", 2), "Export shows the lockout message")
        if app.alerts.firstMatch.exists { app.alerts.buttons.firstMatch.tap(); sleep(1) }
        cancelSystemSheet(app)
        XCTAssertFalse(shareSheetShown(app), "nothing exported")
    }

    // MARK: - App password on (audit 2026-11-10)

    static let appPassword = "Test-Orbit-Lantern-4821"   // made up for the simulator

    @MainActor private func turnOnAppPassword(_ app: XCUIApplication) {
        settingsPage(app, "Lock & security")
        let sw = app.switches["Use an app password"]
        XCTAssertTrue(sw.waitForExistence(timeout: 5), "app password switch")
        if sw.value as? String == "1" { return }
        toggle(app, "Use an app password", on: true, retry: false)
        let field = app.secureTextFields["App password"]
        XCTAssertTrue(field.waitForExistence(timeout: 5), "setup sheet")
        field.tap(); field.typeText(Self.appPassword)
        app.secureTextFields["Confirm app password"].tap(); app.secureTextFields["Confirm app password"].typeText(Self.appPassword)
        app.buttons["Continue"].tap()
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH '1. '")).firstMatch
                        .waitForExistence(timeout: 90), "phrase shown")
        shot("ap-phrase")
        // The list loads its rows as they scroll in: read the words while scrolling to the button.
        var words: [Int: String] = [:]
        for _ in 0..<10 {
            for t in app.staticTexts.allElementsBoundByIndex {
                let parts = t.label.split(separator: " ")
                if parts.count == 2, parts[0].hasSuffix("."), let n = Int(parts[0].dropLast()) { words[n] = String(parts[1]) }
            }
            if app.buttons["I wrote them down"].exists && app.buttons["I wrote them down"].isHittable { break }
            app.swipeUp(velocity: .slow)
        }
        XCTAssertEqual(words.count, 24, "24 words read")
        app.buttons["I wrote them down"].tap(); sleep(1)
        for f in app.textFields.allElementsBoundByIndex where f.placeholderValue?.hasPrefix("Word ") == true || f.label.hasPrefix("Word ") {
            let name = f.placeholderValue?.hasPrefix("Word ") == true ? f.placeholderValue! : f.label
            guard let n = Int(name.dropFirst(5)), let w = words[n] else { XCTFail("word \(name)"); continue }
            f.tap(); f.typeText(w)
        }
        app.buttons["Turn on app password"].tap()
        sleep(15); shot("ap-on"); dump(app, "ap-on")
        XCTAssertEqual(app.switches["Use an app password"].value as? String, "1", "app password on")
    }

    @MainActor private func shareSheetShown(_ app: XCUIApplication) -> Bool {
        app.otherElements["ActivityListView"].waitForExistence(timeout: 4) || app.buttons["Save to Files"].exists
            || app.cells["Save to Files"].exists || app.buttons["Copy"].exists
    }

    @MainActor private func closeShareSheet(_ app: XCUIApplication) {
        for name in ["Close", "Cancel"] where app.buttons[name].exists { app.buttons[name].firstMatch.tap(); sleep(2); return }
        app.swipeDown(velocity: .fast); sleep(2)
    }

    /// Import & Export › Export as CSV › Export.
    @MainActor private func startCSVExport(_ app: XCUIApplication) {
        settingsPage(app, "Sync & data")
        tap(app, "Import & Export", in: .button)
        tap(app, "Export as CSV", in: .button)
        shot("csv-export-dialog")
        app.buttons.matching(NSPredicate(format: "label == 'Export'")).firstMatch.tap()
    }

    /// PENDING audit 2026-11-10 with the app password on, on CSV and CXF export: Face ID passes, Cancel refuses, the
    /// passcode is never offered, a wrong password shows the message and counts toward the delay.
    @MainActor
    func testAppPasswordOwnerChecks() throws {
        let app = launch()
        turnOnAppPassword(app)
        // Face ID matched: the share sheet.
        startCSVExport(app); sleep(8); shot("ap-csv-match")
        XCTAssertTrue(shareSheetShown(app), "Face ID match: CSV share sheet")
        closeShareSheet(app)
        // Face ID not recognised, Cancel: nothing.
        faceID(match: false); sleep(3)
        startCSVExport(app); sleep(8)
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        shot("ap-csv-nomatch"); dump(springboard, "ap-sb-nomatch"); dump(app, "ap-app-nomatch")
        XCTAssertFalse(springboard.buttons.matching(NSPredicate(format: "label CONTAINS[c] 'Passcode'")).firstMatch.exists
                       || app.buttons.matching(NSPredicate(format: "label CONTAINS[c] 'Passcode'")).firstMatch.exists,
                       "the device passcode is never offered")
        cancelSystemSheet(app); sleep(3); shot("ap-csv-cancelled")
        XCTAssertFalse(shareSheetShown(app), "Cancel refuses")
        if app.alerts.firstMatch.exists { dump(app, "ap-csv-cancel-alert"); app.alerts.buttons.firstMatch.tap() }
        // Use App Password, wrong twice: the message, then the delay.
        startCSVExport(app); sleep(8)
        let fallback = [springboard, app].lazy.map { $0.buttons["Use App Password"].firstMatch }.first { $0.exists }
        if let fallback { fallback.tap() } else { XCTFail("no Use App Password on the failed Face ID sheet") }
        sleep(3); shot("ap-password-alert"); dump(app, "ap-password-alert")
        for i in 1...3 {
            let f = app.alerts.secureTextFields.firstMatch
            guard f.waitForExistence(timeout: 5) else { XCTFail("password alert \(i)"); break }
            f.tap(); f.typeText("wrong-password-\(i)")
            app.alerts.buttons["Confirm"].tap(); sleep(3)
            shot("ap-wrong-\(i)"); dump(app, "ap-wrong-\(i)")
            if i == 1 { XCTAssertTrue(contains(app, "That app password is not right."), "wrong password message") }
        }
        print("AP-delay=\(contains(app, "Too many wrong tries", 1))")
        if app.alerts.buttons["Cancel"].exists { app.alerts.buttons["Cancel"].tap(); sleep(2) }
        XCTAssertFalse(shareSheetShown(app), "no export after wrong passwords")
        faceID(match: true); sleep(3)
        // CXF export with Face ID matched.
        app.navigationBars.buttons["BackButton"].firstMatch.tap(); sleep(1)
        tap(app, "Import & Export", in: .button)
        tap(app, "Export to a CXF file", in: .button, wait: 2)
        let all = app.buttons.matching(NSPredicate(format: "label IN %@", ["Select all", "Select All"])).firstMatch
        if all.exists { all.tap() }
        app.buttons.matching(NSPredicate(format: "label == 'Export'")).firstMatch.tap(); sleep(10)
        shot("ap-cxf-match")
        XCTAssertTrue(shareSheetShown(app), "CXF share sheet after Face ID")
        closeShareSheet(app)
    }

    // MARK: - Duress password

    static let duressPassword = "Duress-Maple-Quartz-93"   // made up for the simulator

    /// Locks, keeps Face ID from matching, cancels its prompt and types `password` on the unlock screen.
    @MainActor private func lockAndUnlock(_ app: XCUIApplication, with password: String, tag: String) {
        faceID(match: false); sleep(3)
        settingsPage(app, "Lock & security")
        tap(app, "Lock now", in: .button, wait: 3)
        sleep(6); cancelSystemSheet(app)
        let field = app.secureTextFields["App password"]
        XCTAssertTrue(field.waitForExistence(timeout: 20), "unlock screen")
        shot("\(tag)-locked")
        field.tap(); field.typeText(password)
        app.buttons["Unlock"].tap()
        sleep(12); shot("\(tag)-after-unlock"); dump(app, "\(tag)-after-unlock")
    }

    /// PENDING "Duress: set up (1 hour); the duress password opens the sample vault with no sync…; Face ID and the
    /// real password are refused until the hour ends", and the audit's "repeat in a duress session" for CSV export.
    /// Run after `testAppPasswordOwnerChecks` (the app password is on). Leaves the real vault held for an hour.
    @MainActor
    func testDuressSession() throws {
        let app = launch()
        settingsPage(app, "Lock & security")
        let setUp = app.buttons.matching(NSPredicate(format: "label == 'Set up'")).firstMatch
        for _ in 0..<6 where !setUp.isHittable { app.swipeUp(velocity: .slow) }
        setUp.tap(); sleep(2)
        app.secureTextFields["Current app password"].tap(); app.secureTextFields["Current app password"].typeText(Self.appPassword)
        app.secureTextFields["Duress password"].tap(); app.secureTextFields["Duress password"].typeText(Self.duressPassword)
        app.secureTextFields["Repeat duress password"].tap(); app.secureTextFields["Repeat duress password"].typeText(Self.duressPassword)
        tap(app, "Hours to refuse the app password", wait: 2)
        shot("duress-hours"); dump(app, "duress-hours")
        app.buttons.matching(NSPredicate(format: "label == '1'")).firstMatch.tap(); sleep(1)
        shot("duress-form")
        app.buttons.matching(NSPredicate(format: "label == 'Set up'")).element(boundBy: app.buttons.matching(NSPredicate(format: "label == 'Set up'")).count - 1).tap()
        sleep(20); shot("duress-set-up"); dump(app, "duress-set-up")
        XCTAssertTrue(contains(app, "Remove duress password", 5), "duress on")
        // The duress password opens the sample vault.
        lockAndUnlock(app, with: Self.duressPassword, tag: "duress")
        app.tabBars.buttons["Vault"].tap(); sleep(2)
        shot("duress-vault"); dump(app, "duress-vault")
        XCTAssertFalse(app.staticTexts["github.com"].exists, "not the real vault")
        app.tabBars.buttons["Sync"].tap(); sleep(2); shot("duress-sync"); dump(app, "duress-sync")
        settingsPage(app, "Sync & data"); shot("duress-data"); dump(app, "duress-data")
        XCTAssertFalse(app.buttons["Travel mode"].exists, "no travel mode in the duress vault")
        // Repeat the audit in the duress session: CSV export asks the app password (no Face ID shortcut).
        faceID(match: true); sleep(3)
        startCSVExport(app); sleep(8); shot("duress-csv"); dump(app, "duress-csv")
        let f = app.alerts.secureTextFields.firstMatch
        if f.waitForExistence(timeout: 5) {
            f.tap(); f.typeText("wrong-password-9"); app.alerts.buttons["Confirm"].tap(); sleep(3)
            shot("duress-csv-wrong"); dump(app, "duress-csv-wrong")
            XCTAssertTrue(contains(app, "That app password is not right."), "duress: wrong password message")
            let g = app.alerts.secureTextFields.firstMatch
            if g.exists { g.tap(); g.typeText(Self.duressPassword); app.alerts.buttons["Confirm"].tap(); sleep(8) }
            shot("duress-csv-ok")
            XCTAssertTrue(shareSheetShown(app), "duress: export with the duress password")
            closeShareSheet(app)
        } else {
            print("DURESS-csv no password alert; share=\(shareSheetShown(app))")
            closeShareSheet(app)
        }
        // Face ID and the real password are refused during the hold.
        lockAndUnlock(app, with: Self.appPassword, tag: "held-real")
        XCTAssertTrue(app.secureTextFields["App password"].exists, "real password refused during the hold")
        faceID(match: true); sleep(2)
        if app.buttons["Use Face ID"].exists { app.buttons["Use Face ID"].tap() }
        sleep(12); shot("held-faceid"); dump(app, "held-faceid")
        XCTAssertTrue(app.secureTextFields["App password"].exists, "Face ID refused during the hold")
    }

    /// The health report on a US-region phone prints on Letter (A4 elsewhere, `testPowerUserPack`).
    @MainActor
    func testHealthReportLetter() throws {
        let app = launch(["-AppleLocale", "en_US"])
        settingsPage(app, "Lock & security")
        tap(app, "Print vault health report", in: .button, wait: 6)
        shot("pu-print-letter"); dump(app, "pu-print-letter")
        XCTAssertTrue(app.staticTexts["Letter"].waitForExistence(timeout: 10) || contains(app, "Letter"), "Letter paper")
        if app.buttons["Cancel"].exists { app.buttons["Cancel"].tap() }
    }

    /// Cancels the system "Sign in to Apple Account" alert a StoreKit restore can leave on screen (never types in it).
    @MainActor
    func testZCancelAppleAccountAlert() throws {
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        for _ in 0..<3 {
            let alert = springboard.alerts.firstMatch
            guard alert.waitForExistence(timeout: 5) else { break }
            shot("signin-alert"); dump(springboard, "signin-alert")
            guard alert.label.contains("Apple Account") || alert.staticTexts["Sign in to Apple Account"].exists else { break }
            alert.buttons["Cancel"].tap(); sleep(2)
        }
    }

    // MARK: - Exploration

    @MainActor
    func testExplore() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_EXPLORE"] == "1")
        let app = launch()
        shot("x-list"); dump(app, "x-list")
        openLogin(app, "github.com", "alex@example.com")
        shot("x-github"); dump(app, "x-github")
        app.swipeUp(); shot("x-github2"); dump(app, "x-github2")
        tap(app, "Access rules")
        shot("x-rules"); dump(app, "x-rules")
        app.navigationBars.buttons.firstMatch.tap(); sleep(1)
        app.tabBars.buttons["Settings"].tap(); sleep(2)
        dump(app, "x-settings1"); shot("x-settings1")
        for i in 2...6 { app.swipeUp(); shot("x-settings\(i)") }
        dump(app, "x-settings-end")
        app.tabBars.buttons["Security"].tap(); sleep(2)
        shot("x-security"); dump(app, "x-security")
        app.tabBars.buttons["Vault"].tap(); sleep(1)
        any(app, "More", exact: true).tap(); sleep(1)
        shot("x-more"); dump(app, "x-more")
    }
}
