import XCTest

/// Shared launch setup for the checks that need a REAL vault: a fresh temporary vault folder per test
/// (`LGK_MAC_VAULT_DIR`), created through the app's own create screen. Run through `scripts/mac_ui_checks.sh`, which
/// builds with a separate bundle prefix (own container and Keychain), so the installed app's vault is never touched.
class MacRealVaultUITestCase: XCTestCase {
    static let master = "correct horse battery staple 42"
    /// The vault folder's name, relative: the app puts it in its own temporary folder (the runner is sandboxed too).
    var vaultName: String!
    /// Where that folder is, for reading its files from the runner (nil reads mean the runner may not look).
    var vaultDir: URL {
        let home = String(cString: getpwuid(getuid())!.pointee.pw_dir)
        return URL(fileURLWithPath: home).appendingPathComponent("Library/Containers/app.localgatekeys.uitest.app/Data/tmp/\(vaultName!)")
    }

    override func setUpWithError() throws {
        continueAfterFailure = false
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_MAC_UI_CHECKS"] == "1", "run through scripts/mac_ui_checks.sh")
        vaultName = "lgk-uitest-\(UUID().uuidString)"
    }

    /// The vault folder's files, recursively (relative paths); nil when the runner cannot read the folder.
    func vaultFiles() -> [String]? {
        guard let e = FileManager.default.enumerator(atPath: vaultDir.path) else { return nil }
        return (e.allObjects as? [String])?.sorted()
    }

    @MainActor
    func launch(_ environment: [String: String] = [:], arguments: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment["LGK_MAC_ALLOW_CAPTURE"] = "1"
        app.launchEnvironment["LGK_MAC_VAULT_DIR"] = vaultName
        app.launchEnvironment["LGK_MAC_HIDE_SETUP"] = "1"
        app.launchEnvironment["LGK_DEBUG_PRO"] = "1"
        app.launchEnvironment.merge(environment) { $1 }
        app.launchArguments += arguments
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20), "the main window opened")
        return app
    }

    /// Creates the vault on the create screen and waits for the unlocked window.
    @MainActor
    func createVault(_ app: XCUIApplication) {
        let field = app.secureTextFields["Master password"]
        XCTAssertTrue(field.waitForExistence(timeout: 10), "create screen shown")
        field.click(); field.typeText(Self.master)
        let confirm = app.secureTextFields["Confirm master password"]
        confirm.click(); confirm.typeText(Self.master)
        app.buttons["Create vault"].click()
        dismissSheets(app)
        XCTAssertTrue(app.buttons["Settings"].firstMatch.waitForExistence(timeout: 30), "unlocked window after create")
        dismissSheets(app)
    }

    /// Closes the recovery-phrase / setup sheets that may follow vault creation.
    @MainActor
    func dismissSheets(_ app: XCUIApplication) {
        sleep(2)
        for _ in 0..<4 {
            var acted = false
            for name in ["Skip setup", "I've saved it", "I have saved it", "Done", "Not now", "Later", "Skip"] {
                let b = app.buttons[name].firstMatch
                if b.exists, b.isHittable { b.click(); acted = true }
            }
            if !acted { return }
        }
    }

    @MainActor
    func shot(_ app: XCUIApplication, _ name: String) {
        let a = XCTAttachment(screenshot: app.screenshot()); a.name = name; a.lifetime = .keepAlways
        add(a)
    }

    @MainActor
    func texts(_ app: XCUIApplication) -> [String] {
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
    func dump(_ app: XCUIApplication, _ tag: String) {
        print("MAC-CHECK \(tag):", texts(app).prefix(120).joined(separator: " | "))
    }
}

extension MacRealVaultUITestCase {
    /// Opens Settings in the main window and filters it to `search` (rows below the fold need no scrolling).
    @MainActor
    func openSettings(_ app: XCUIApplication, search: String) {
        app.buttons["Settings"].firstMatch.click()
        let field = app.textFields["Search settings"].firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 5), "Settings search field")
        field.click()
        field.typeKey("a", modifierFlags: .command)
        field.typeText(search)
        sleep(1)
    }

    @MainActor
    func type(_ app: XCUIApplication, secure label: String, _ text: String, in scope: XCUIElement? = nil) {
        let f = (scope ?? app).secureTextFields[label].firstMatch
        XCTAssertTrue(f.waitForExistence(timeout: 5), "field \(label)")
        f.click()
        f.typeKey("a", modifierFlags: .command)
        f.typeKey(.delete, modifierFlags: [])
        f.typeText(text)
    }

    @MainActor
    func lock(_ app: XCUIApplication) {
        // ⌘L (the Lock button is not shown on the Settings page).
        app.typeKey("l", modifierFlags: .command)
        XCTAssertTrue(app.buttons["Unlock"].waitForExistence(timeout: 10), "locked")
    }

    /// Types a password on the lock screen, presses Unlock and returns the seconds until `done` exists.
    @MainActor
    func timedUnlock(_ app: XCUIApplication, _ password: String, until done: XCUIElement) -> TimeInterval {
        type(app, secure: "Master password", password)
        let start = Date()
        app.buttons["Unlock"].click()
        while !done.exists {
            if Date().timeIntervalSince(start) > 60 { XCTFail("no result after 60 s"); break }
            usleep(20_000)
        }
        return Date().timeIntervalSince(start)
    }

    func text(_ app: XCUIApplication, _ value: String) -> XCUIElement {
        app.staticTexts.matching(NSPredicate(format: "label == %@ OR value == %@", value, value)).firstMatch
    }

    func text(_ app: XCUIApplication, beginningWith prefix: String) -> XCUIElement {
        app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@ OR value BEGINSWITH %@", prefix, prefix)).firstMatch
    }
}

/// docs/reports/2026-11-14-mac-duress.md: set up, removal, equal unlock times, and the hold.
final class MacDuressUITests: MacRealVaultUITestCase {
    static let duress = "purple monkey dishwasher 7"
    static let wrong = "this is not the password 9"

    @MainActor
    private func setUpDuress(_ app: XCUIApplication) {
        openSettings(app, search: "Duress")
        let setUp = app.buttons["Set up"].firstMatch
        XCTAssertTrue(setUp.waitForExistence(timeout: 5), "Duress password row's Set up")
        setUp.click()
        let sheet = app.sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 5), "set-up sheet")
        type(app, secure: "Master password", Self.master, in: sheet)
        type(app, secure: "Duress password", Self.duress, in: sheet)
        type(app, secure: "Repeat duress password", Self.duress, in: sheet)
        sheet.buttons["Set up"].click()
        let done = text(app, beginningWith: "Set up. After the duress password is used")
        let ok = done.waitForExistence(timeout: 30)
        shot(app, "duress-set-up")
        if !ok { dump(app, "duress-setup") }
        XCTAssertTrue(ok, "Settings shows the duress password as set up")
    }

    /// Creates a recovery phrase through Settings and returns its words.
    @MainActor
    private func createRecoveryPhrase(_ app: XCUIApplication) -> [String] {
        openSettings(app, search: "Recovery phrase")
        let create = app.buttons["Create…"].firstMatch
        XCTAssertTrue(create.waitForExistence(timeout: 5), "Recovery phrase › Create…")
        create.click()
        let sheet = app.sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 5))
        type(app, secure: "Master password", Self.master, in: sheet)
        sheet.buttons["Continue"].click()
        XCTAssertTrue(sheet.buttons["I've written it down"].waitForExistence(timeout: 30), "the words are shown")
        let all = sheet.staticTexts.allElementsBoundByIndex.map { $0.label.isEmpty ? (($0.value as? String) ?? "") : $0.label }
        var words: [String] = []
        for (i, t) in all.enumerated() where t.range(of: #"^\d+\.$"#, options: .regularExpression) != nil && i + 1 < all.count {
            words.append(all[i + 1])
        }
        XCTAssertGreaterThanOrEqual(words.count, 12, "read the phrase: \(all)")
        sheet.buttons["I've written it down"].click()
        // The confirmation asks for some words by position ("Word N").
        sleep(1)
        for field in sheet.textFields.allElementsBoundByIndex {
            let label = field.placeholderValue ?? field.label
            guard let n = Int(label.replacingOccurrences(of: "Word ", with: "")), n >= 1, n <= words.count else { continue }
            field.click(); field.typeText(words[n - 1])
        }
        sheet.buttons["Confirm"].click()
        let done = sheet.buttons["Done"]
        if done.waitForExistence(timeout: 10) { done.click() }
        XCTAssertTrue(sheet.waitForNonExistence(timeout: 10), "phrase confirmed")
        // The "Recovery phrase confirmed" notice (and any other) waits for OK.
        for _ in 0..<3 {
            let ok = app.buttons["OK"].firstMatch
            if ok.waitForExistence(timeout: 2) { print("MAC-CHECK notice:", texts(app).filter { $0.count > 30 }.prefix(3)); ok.click() } else { break }
        }
        return words
    }

    /// Set up, then Remove: every duress file goes from the vault folder.
    @MainActor
    func testSetUpAndRemovalLeaveNoDuressFiles() throws {
        let app = launch()
        createVault(app)
        let before = try XCTUnwrap(vaultFiles(), "the runner can read the app's vault folder")
        setUpDuress(app)
        let during = try XCTUnwrap(vaultFiles())
        print("MAC-CHECK duress files:", during.filter { !before.contains($0) })
        XCTAssertTrue(during.contains(".lgk-d"), "the second vault folder exists")
        XCTAssertTrue(during.contains("duress.bin"), "duress.bin exists")
        XCTAssertTrue(during.contains(".lgk-d/app-password.json"))
        openSettings(app, search: "Duress")
        app.buttons["Remove…"].firstMatch.click()
        let confirm = app.buttons["Remove duress password"].firstMatch
        XCTAssertTrue(confirm.waitForExistence(timeout: 5), "removal asks first")
        confirm.click()
        XCTAssertTrue(text(app, "Not set up.").waitForExistence(timeout: 15), "status back to Not set up")
        let after = try XCTUnwrap(vaultFiles())
        let left = after.filter { $0.hasPrefix(".lgk-d") || $0 == "duress.bin" || $0 == "vault.hold.json" }
        XCTAssertEqual(left, [], "no duress file is left")
        shot(app, "duress-removed")
    }

    /// Real, wrong and duress unlocks take about the same time; after the duress unlock the hold refuses the real
    /// master password and the recovery phrase.
    @MainActor
    func testUnlockTimesMatchAndTheHoldRefusesRealPasswordAndPhrase() throws {
        let app = launch()
        createVault(app)
        let words = createRecoveryPhrase(app)
        setUpDuress(app)
        let unlocked = app.buttons["Settings"].firstMatch
        let wrongLine = text(app, beginningWith: "That password isn't right.")
        var real: [TimeInterval] = [], wrong: [TimeInterval] = [], duress: [TimeInterval] = []
        // A warm-up round first (the first unlocked window is built from scratch), then three of each.
        lock(app)
        _ = timedUnlock(app, Self.wrong, until: wrongLine)
        _ = timedUnlock(app, Self.master, until: unlocked)
        for _ in 0..<3 {
            lock(app)
            wrong.append(timedUnlock(app, Self.wrong, until: wrongLine))
            real.append(timedUnlock(app, Self.master, until: unlocked))
        }
        // The duress password opens the second vault each time (the hold starts with the first).
        for _ in 0..<3 {
            lock(app)
            duress.append(timedUnlock(app, Self.duress, until: unlocked))
        }
        shot(app, "duress-session")
        func median(_ a: [TimeInterval]) -> TimeInterval { a.sorted()[a.count / 2] }
        print("MAC-CHECK unlock seconds real=\(real) wrong=\(wrong) duress=\(duress)")
        let medians = [median(real), median(wrong), median(duress)]
        print("MAC-CHECK unlock medians real/wrong/duress=\(medians)")
        // Measured to what the screen shows: an opened vault also builds its window (the real one with more to
        // load), so the bounds are UI-level. Real and duress both open a window and must not be told apart; a
        // wrong password must not take longer than an unlock (both Argon2 checks run every time).
        XCTAssertLessThan(abs(medians[0] - medians[2]), max(0.75, medians[0] * 0.4), "real vs duress: \(medians)")
        XCTAssertLessThan(medians[1], max(medians[0], medians[2]) + 0.3, "wrong vs unlocks: \(medians)")
        XCTAssertGreaterThan(medians[1], min(medians[0], medians[2]) * 0.5, "a wrong password runs the same checks: \(medians)")
        // The decoy is open: Settings says Not set up.
        openSettings(app, search: "Duress")
        XCTAssertTrue(text(app, "Not set up.").waitForExistence(timeout: 5), "the second session shows Not set up")
        // The hold: the real master password is refused (and costs the same time).
        lock(app)
        let held = timedUnlock(app, Self.master, until: wrongLine)
        print("MAC-CHECK held real-password seconds=\(held)")
        XCTAssertFalse(unlocked.exists, "the real master password is refused during the hold")
        // The recovery phrase is refused too.
        let forgot = app.descendants(matching: .any).matching(NSPredicate(format: "label == 'Forgot your master password?' OR title == 'Forgot your master password?' OR value == 'Forgot your master password?'")).firstMatch
        if !forgot.waitForExistence(timeout: 5) { dump(app, "lock screen") }
        forgot.click()
        let sheet = app.sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 5))
        let phrase = sheet.textViews["Recovery phrase"].firstMatch
        XCTAssertTrue(phrase.waitForExistence(timeout: 5))
        phrase.click(); phrase.typeText(words.joined(separator: " "))
        type(app, secure: "New master password", "a brand new master password 1", in: sheet)
        type(app, secure: "Repeat new master password", "a brand new master password 1", in: sheet)
        sheet.buttons["Recover"].click()
        let refused = text(app, beginningWith: "This recovery phrase does not belong")
        let ok = refused.waitForExistence(timeout: 30)
        shot(app, "held-recovery")
        if !ok { dump(app, "held-recovery") }
        XCTAssertTrue(ok, "the recovery phrase is refused during the hold")
        XCTAssertFalse(unlocked.exists)
    }
}
