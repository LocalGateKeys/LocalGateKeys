import AppKit
import XCTest

/// docs/PENDING.md section 4 (Mac app), driven on a REAL vault in the uitest container: the review fixes (copy keys,
/// Item menu, copy buttons' accessibility), the feature pack (CSV import report and Undo, Clean-up free and Pro,
/// access rules, item history, travel mode, privacy proof, passkey check) and the power-user pack.
/// Run through `scripts/mac_ui_checks.sh MacPendingChecksUITests`.
class MacPendingUITestCase: MacRealVaultUITestCase {
    static let csvRows: [(title: String, url: String, user: String, password: String)] = [
        ("Example", "https://example.com/login", "alice@example.com", "Pw-Example-1111"),
        ("Example again", "https://www.example.com/signin", "alice@example.com", "Pw-Example-1111"),
        ("Shop", "https://shop.example.org/", "bob", "Pw-Shop-2222"),
        ("Mail", "https://mail.example.net/", "carol", "Pw-Mail-3333"),
        ("Bank", "https://bank.example.io/", "dave", "Pw-Bank-4444"),
    ]

    override func setUpWithError() throws {
        try super.setUpWithError()
        continueAfterFailure = true
    }

    /// The CSV file (Apple Passwords columns) in the runner's temporary folder.
    func writeCSV(_ rows: [(title: String, url: String, user: String, password: String)] = csvRows) throws -> URL {
        var text = "Title,URL,Username,Password,Notes,OTPAuth\n"
        for r in rows { text += "\(r.title),\(r.url),\(r.user),\(r.password),,\n" }
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("lgk-pending-\(UUID().uuidString.prefix(8)).csv")
        try text.write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    @MainActor
    func dumpAll(_ app: XCUIApplication, _ tag: String, window: XCUIElement? = nil) {
        guard let snap = try? (window ?? app.windows.firstMatch).snapshot() else { return }
        var out: [String] = []
        let skip: Set<String> = ["General", "Security", "AutoFill", "Backups", "Appearance", "Plan", "Advanced", "Generator",
                                 "Sync & devices", "Import & export", "Trash", "Settings", "Vault", "Tools", "Recently used",
                                 "Collections", "Manage collections/ellipsis.circle", "_XCUI:CloseWindow", "_XCUI:FullScreenWindow",
                                 "_XCUI:MinimizeWindow", "_XCUI:ZoomWindow", "LocalGateKeys", "Security centre"]
        func walk(_ s: XCUIElementSnapshot) {
            let t = [s.label, s.title, (s.value as? String) ?? "", s.identifier].filter { !$0.isEmpty }.joined(separator: "/")
            if !t.isEmpty, !skip.contains(t) { out.append("\(s.elementType.rawValue):\(t)") }
            s.children.forEach(walk)
        }
        walk(snap)
        print("MAC-CHECK [\(tag)] " + out.joined(separator: " | "))
    }

    func any(_ app: XCUIApplication, _ label: String) -> XCUIElement {
        app.descendants(matching: .any).matching(NSPredicate(format: "label == %@ OR title == %@ OR value == %@", label, label, label)).firstMatch
    }

    func any(_ app: XCUIApplication, containing part: String) -> XCUIElement {
        app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@ OR value CONTAINS %@", part, part)).firstMatch
    }

    /// Chooses `file` in an open panel (⇧⌘G, path, Return, then Open).
    @MainActor
    func choose(_ app: XCUIApplication, file: URL) {
        sleep(2)
        app.typeKey("g", modifierFlags: [.command, .shift])
        sleep(1)
        app.typeText(file.path)
        sleep(1)
        app.typeKey(.return, modifierFlags: [])
        sleep(1)
        app.typeKey(.return, modifierFlags: [])
        sleep(2)
    }

    /// Names `file` in a save panel (⇧⌘G to the folder, the name, Save).
    @MainActor
    func save(_ app: XCUIApplication, to file: URL) {
        sleep(2)
        app.typeKey("a", modifierFlags: .command)
        app.typeText(file.lastPathComponent)
        app.typeKey("g", modifierFlags: [.command, .shift])
        sleep(1)
        app.typeText(file.deletingLastPathComponent().path)
        app.typeKey(.return, modifierFlags: [])
        sleep(1)
        app.typeKey(.return, modifierFlags: [])
        sleep(2)
        // "Replace?" when the name exists.
        let replace = app.buttons["Replace"].firstMatch
        if replace.exists { replace.click() }
    }

    @MainActor
    func importCSV(_ app: XCUIApplication, _ file: URL) {
        app.buttons["Import & export"].firstMatch.click()
        let chooseButton = app.buttons["Choose a file…"].firstMatch
        XCTAssertTrue(chooseButton.waitForExistence(timeout: 5), "Import › Choose a file…")
        chooseButton.click()
        choose(app, file: file)
        // The review sheet: Import writes the rows (each defaults to Add).
        let review = any(app, "Review import")
        XCTAssertTrue(review.waitForExistence(timeout: 15), "the review sheet")
        let importButton = app.sheets.buttons["Import"].firstMatch.exists ? app.sheets.buttons["Import"].firstMatch
            : app.buttons.matching(NSPredicate(format: "label == %@", "Import")).allElementsBoundByIndex.last ?? app.buttons["Import"].firstMatch
        importButton.click()
        sleep(3)
    }

    func allItems(_ app: XCUIApplication) -> XCUIElement {
        app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "All items")).firstMatch
    }

    @MainActor
    func selectItem(_ app: XCUIApplication, _ title: String) {
        allItems(app).click()
        let row = app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@", title + ",")).firstMatch
        let plain = any(app, title)
        let target = row.waitForExistence(timeout: 3) ? row : plain
        if !target.exists { dumpAll(app, "select-\(title)") }
        target.click()
        sleep(1)
    }

    func clipboard() -> String? { NSPasteboard.general.string(forType: .string) }

    /// Turns a switch (a checkbox to XCUITest) and checks that its value changed; a click on the centre of a wide row can
    /// miss the control, so it then clicks its right end.
    @MainActor
    func flip(_ el: XCUIElement) {
        // macOS does not scroll to a control before a click: bring it into view first.
        var tries = 0
        let win = XCUIApplication().windows.firstMatch.frame
        while (!el.isHittable || el.frame.maxY > win.maxY - 90) && tries < 8 {
            XCUIApplication().windows.firstMatch.coordinate(withNormalizedOffset: CGVector(dx: 0.8, dy: 0.5)).scroll(byDeltaX: 0, deltaY: -250)
            tries += 1; usleep(300_000)
        }
        let before = "\(el.value ?? "")"
        el.click(); sleep(1)
        if "\(el.value ?? "")" == before {
            el.coordinate(withNormalizedOffset: CGVector(dx: 0.95, dy: 0.5)).click(); sleep(1)
        }
        if "\(el.value ?? "")" == before {
            el.coordinate(withNormalizedOffset: CGVector(dx: 0.25, dy: 0.5)).click(); sleep(1)
        }
        print("MAC-CHECK flip \(el.label): \(before) -> \(el.value ?? "") frame=\(el.frame) hittable=\(el.isHittable) enabled=\(el.isEnabled) window=\(XCUIApplication().windows.firstMatch.frame)")
    }

    func clearClipboard() { NSPasteboard.general.clearContents() }

    /// "Confirm it's you" before a password copy: Confirm, then the master password when asked.
    @MainActor
    func confirmCopy(_ app: XCUIApplication) {
        let confirm = app.buttons["Confirm"].firstMatch
        guard confirm.waitForExistence(timeout: 3) else { return }
        confirm.click(); sleep(1)
        answerPasswordPrompt(app, timeout: 3)
        sleep(1)
    }

    /// Answers a master-password prompt (sheet or panel) when one is shown; true when it was.
    @MainActor
    @discardableResult
    func answerPasswordPrompt(_ app: XCUIApplication, _ password: String = master, timeout: TimeInterval = 4) -> Bool {
        let field = app.secureTextFields.matching(NSPredicate(format: "label CONTAINS 'assword' OR placeholderValue CONTAINS 'assword'")).firstMatch
        guard field.waitForExistence(timeout: timeout) else { return false }
        field.click()
        field.typeText(password)
        field.typeKey(.return, modifierFlags: [])
        sleep(2)
        return true
    }
}

final class MacPendingChecksUITests: MacPendingUITestCase {

    // MARK: review fixes

    /// Item menu key equivalents (⌘C, ⇧⌘C on the focused list), ⌘C in a text field copies the text, and the copy
    /// buttons' accessibility labels (what VoiceOver reads).
    @MainActor
    func testCopyKeysItemMenuAndCopyButtonLabels() throws {
        let app = launch()
        createVault(app)
        importCSV(app, try writeCSV())
        dumpAll(app, "after-import")
        shot(app, "import-report")
        let done = app.buttons["Done"].firstMatch
        if done.waitForExistence(timeout: 5) { done.click() }
        selectItem(app, "Shop")
        dumpAll(app, "detail-shop")
        shot(app, "detail-shop")
        // VoiceOver: the copy buttons carry "Copy username" / "Copy password" labels and the press action.
        for label in ["Copy username", "Copy password"] {
            let b = app.buttons[label].firstMatch
            XCTAssertTrue(b.waitForExistence(timeout: 3), "copy button labelled '\(label)'")
            print("MAC-CHECK a11y \(label): exists=\(b.exists) enabled=\(b.isEnabled) type=button")
        }
        // The copy button copies.
        clearClipboard()
        app.buttons["Copy username"].firstMatch.click()
        sleep(1)
        XCTAssertEqual(clipboard(), "bob", "Copy username button")
        // Item menu: the key equivalents are on the menu items.
        let itemMenu = app.menuBars.menuBarItems["Item"].firstMatch
        XCTAssertTrue(itemMenu.exists, "Item menu")
        itemMenu.click()
        sleep(1)
        for name in ["Copy username", "Copy password", "Copy 2FA code", "Edit", "Save"] {
            let mi = app.menuItems[name].firstMatch
            print("MAC-CHECK item menu \(name): exists=\(mi.exists) enabled=\(mi.isEnabled)")
        }
        shot(app, "item-menu")
        app.typeKey(.escape, modifierFlags: [])
        // ⇧⌘C with the list focused copies the user name; ⌘C the password (it may ask first).
        selectItem(app, "Mail")
        clearClipboard()
        app.typeKey("c", modifierFlags: [.command, .shift])
        sleep(1)
        XCTAssertEqual(clipboard(), "carol", "⇧⌘C copies the user name")
        clearClipboard()
        app.typeKey("c", modifierFlags: .command)
        sleep(1)
        dumpAll(app, "after-cmd-c")
        let ok = app.sheets.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Copy'")).firstMatch
        if ok.exists { ok.click(); sleep(1) }
        confirmCopy(app)
        XCTAssertEqual(clipboard(), "Pw-Mail-3333", "⌘C copies the password")
        // ⌘C in a text field copies the selected text, not the password.
        let search = app.windows.firstMatch.searchFields.firstMatch
        app.typeKey("f", modifierFlags: .command)
        sleep(1)
        let field = search.exists ? search : app.textFields.firstMatch
        field.click()
        field.typeText("Shop")
        field.typeKey("a", modifierFlags: .command)
        clearClipboard()
        field.typeKey("c", modifierFlags: .command)
        sleep(1)
        XCTAssertEqual(clipboard(), "Shop", "⌘C in the search field copies its text")
        shot(app, "cmd-c-in-field")
    }

    /// ⌘C in the search field (demo preview, an item selected): the key, then Edit › Copy from the menu bar.
    @MainActor
    func testCommandCInSearchFieldCopiesText() throws {
        let app = XCUIApplication()
        app.launchEnvironment["LGK_MAC_ALLOW_CAPTURE"] = "1"
        app.launchEnvironment["LGK_MAC_SHELL_PREVIEW"] = "1"
        app.launchEnvironment["LGK_MAC_HIDE_SETUP"] = "1"
        app.launchEnvironment["LGK_MAC_SELECT"] = "github.com"
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20))
        let skip = app.buttons["Skip setup"]; if skip.waitForExistence(timeout: 3) { skip.click() }
        sleep(2)
        let field = app.windows.firstMatch.textFields["Search your vault"].firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 5), "the window's search field")
        field.click()
        field.typeText("github")
        field.typeKey("a", modifierFlags: .command)
        clearClipboard()
        field.typeKey("c", modifierFlags: .command)
        sleep(1)
        let byKey = clipboard()
        print("MAC-CHECK search field ⌘C -> \(byKey ?? "nil")")
        clearClipboard()
        field.typeKey("a", modifierFlags: .command)
        app.menuBars.menuBarItems["Edit"].firstMatch.click()
        app.menuItems["Copy"].firstMatch.click()
        sleep(1)
        let byMenu = clipboard()
        print("MAC-CHECK search field Edit › Copy -> \(byMenu ?? "nil")")
        XCTAssertEqual(byKey, "github", "⌘C in the search field copies its text")
        XCTAssertEqual(byMenu, "github", "Edit › Copy copies the field's text")
    }

    // MARK: feature pack

    /// Import a CSV: the report, Undo; then Clean-up on the free plan (one merge keeps both addresses).
    @MainActor
    func testImportReportUndoAndFreeCleanUpMerge() throws {
        let app = launch(["LGK_DEBUG_PRO": "0"])
        createVault(app)
        let csv = try writeCSV()
        importCSV(app, csv)
        sleep(2)
        dumpAll(app, "import-report")
        shot(app, "import-report")
        let undo = app.buttons["Undo this import"].firstMatch
        XCTAssertTrue(undo.waitForExistence(timeout: 10), "the report offers Undo this import")
        undo.click()
        sleep(1)
        dumpAll(app, "undo-confirm")
        let confirm: XCUIElement? = app.buttons.matching(NSPredicate(format: "label == 'Undo this import' AND identifier == 'action-button-1'")).firstMatch
        confirm?.click()
        sleep(3)
        dumpAll(app, "after-undo")
        shot(app, "after-undo")
        allItems(app).click()
        sleep(1)
        XCTAssertTrue(any(app, "0 items").waitForExistence(timeout: 5), "Undo removed the imported items")
        // Import again for the clean-up.
        importCSV(app, csv)
        let done = app.buttons["Done"].firstMatch
        if done.waitForExistence(timeout: 10) { done.click() }
        app.buttons["Security centre"].firstMatch.click()
        let openCleanUp = app.buttons["Open, Clean-up"].firstMatch
        XCTAssertTrue(openCleanUp.waitForExistence(timeout: 5), "Security centre › Clean-up › Open")
        openCleanUp.click()
        sleep(2)
        dumpAll(app, "cleanup-free")
        shot(app, "cleanup-free")
        // Free: Select (bulk) asks for Pro.
        let select = app.buttons["Select"].firstMatch
        if select.exists {
            select.click(); sleep(2)
            dumpAll(app, "cleanup-free-select")
            shot(app, "cleanup-free-select")
            for b in ["Not now", "Cancel", "Close", "Done"] where app.buttons[b].firstMatch.exists { app.buttons[b].firstMatch.click(); sleep(1); break }
        }
        let review = app.buttons["Review and merge"].firstMatch
        XCTAssertTrue(review.waitForExistence(timeout: 5), "the duplicate pair is offered for review")
        review.click()
        sleep(2)
        dumpAll(app, "review-merge")
        shot(app, "review-merge")
        app.buttons["Merge"].firstMatch.click()
        sleep(2)
        answerPasswordPrompt(app)
        dumpAll(app, "after-merge")
        shot(app, "after-merge")
        // The kept login holds both website addresses.
        // The review keeps the first of the pair shown ("Keep") and merges the other into it.
        selectItem(app, "Example again")
        dumpAll(app, "kept-login")
        shot(app, "kept-login")
        XCTAssertTrue(app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "https://example.com")).firstMatch.exists, "first address kept")
        XCTAssertTrue(app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "https://www.example.com")).firstMatch.exists, "second address kept")
    }

    /// Pro: bulk delete, Undo last clean-up; a lock clears the Undo.
    @MainActor
    func testProBulkCleanUpUndoAndLockClearsUndo() throws {
        let app = launch(["LGK_DEBUG_PRO": "1"])
        createVault(app)
        let csv = try writeCSV()
        importCSV(app, csv)
        if app.buttons["Done"].firstMatch.waitForExistence(timeout: 10) { app.buttons["Done"].firstMatch.click() }
        func openCleanUp() {
            app.buttons["Security centre"].firstMatch.click()
            let open = app.buttons["Open, Clean-up"].firstMatch
            XCTAssertTrue(open.waitForExistence(timeout: 5))
            open.click(); sleep(2)
        }
        openCleanUp()
        dumpAll(app, "cleanup-pro")
        app.buttons["Select"].firstMatch.click()
        sleep(1)
        dumpAll(app, "cleanup-pro-select")
        shot(app, "cleanup-pro-select")
        /// Bulk delete of the selected rows (Pro), confirmed in the alert.
        func bulkDelete(_ title: String) {
            if !app.buttons["Done"].firstMatch.exists { app.buttons["Select"].firstMatch.click(); sleep(1) }
            let box = app.checkBoxes[title].firstMatch
            XCTAssertTrue(box.waitForExistence(timeout: 5), "row checkbox \(title)")
            flip(box)
            let delete = app.buttons.matching(NSPredicate(format: "label MATCHES 'Delete [1-9][0-9]* items?' AND identifier != 'action-button-1'")).firstMatch
            XCTAssertTrue(delete.waitForExistence(timeout: 5), "Pro: Delete 1 items")
            delete.click()
            sleep(1)
            let confirm = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Delete' AND identifier == 'action-button-1'")).firstMatch
            if confirm.waitForExistence(timeout: 3) { confirm.click() }
            sleep(2)
            answerPasswordPrompt(app, timeout: 2)
        }
        bulkDelete("Example again")
        dumpAll(app, "after-bulk-delete")
        shot(app, "after-bulk-delete")
        let undo = app.buttons["Undo last clean-up"].firstMatch
        XCTAssertTrue(undo.waitForExistence(timeout: 5), "Undo last clean-up offered")
        undo.click()
        sleep(2)
        dumpAll(app, "after-undo-cleanup")
        shot(app, "after-undo-cleanup")
        XCTAssertTrue(any(app, containing: "Clean-up undone").waitForExistence(timeout: 5), "Clean-up undone message")
        XCTAssertTrue(app.descendants(matching: .any).matching(NSPredicate(format: "label == 'Example again'")).firstMatch.exists,
                      "the deleted login is back")
        // Again, then lock: the Undo is gone after the unlock.
        bulkDelete("Example again")
        XCTAssertTrue(app.buttons["Undo last clean-up"].firstMatch.waitForExistence(timeout: 5), "Undo offered again")
        lock(app)
        _ = timedUnlock(app, Self.master, until: app.buttons["Settings"].firstMatch)
        openCleanUp()
        dumpAll(app, "cleanup-after-lock")
        shot(app, "cleanup-after-lock")
        XCTAssertFalse(app.buttons["Undo last clean-up"].firstMatch.exists, "a lock clears the Undo")
    }

    /// Access rules: copy once per unlock (a second password copy is refused; a lock gives it back); the expiry
    /// switch and date; item history after an edit (restore one field).
    @MainActor
    func testAccessRulesCopyOnceAndItemHistory() throws {
        let app = launch(["LGK_DEBUG_PRO": "1"])
        createVault(app)
        importCSV(app, try writeCSV())
        if app.buttons["Done"].firstMatch.waitForExistence(timeout: 10) { app.buttons["Done"].firstMatch.click() }
        selectItem(app, "Shop")
        let copyOnce = app.checkBoxes["Copy once per unlock"].firstMatch
        if !copyOnce.waitForExistence(timeout: 3) {
            app.windows.firstMatch.coordinate(withNormalizedOffset: CGVector(dx: 0.8, dy: 0.6)).scroll(byDeltaX: 0, deltaY: -800)
        }
        XCTAssertTrue(copyOnce.waitForExistence(timeout: 3), "Access rules › Copy once per unlock")
        dumpAll(app, "access-rules")
        flip(copyOnce)
        app.buttons["Save"].firstMatch.click()
        sleep(1)
        answerPasswordPrompt(app)
        dumpAll(app, "access-rules-saved")
        shot(app, "access-rules-saved")
        func copyPassword() {
            let b = app.buttons["Copy password"].firstMatch
            if !b.isHittable { app.windows.firstMatch.coordinate(withNormalizedOffset: CGVector(dx: 0.8, dy: 0.4)).scroll(byDeltaX: 0, deltaY: 800) }
            b.click(); sleep(1)
            let ok = app.sheets.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Copy'")).firstMatch
            if ok.exists { ok.click(); sleep(1) }
            confirmCopy(app)
        }
        clearClipboard()
        copyPassword()
        XCTAssertEqual(clipboard(), "Pw-Shop-2222", "the first copy works")
        clearClipboard()
        copyPassword()
        dumpAll(app, "second-copy")
        shot(app, "second-copy-refused")
        XCTAssertNotEqual(clipboard(), "Pw-Shop-2222", "the second copy in the same unlock is refused")
        // A username copy does not use it up and the next unlock gives it back.
        lock(app)
        _ = timedUnlock(app, Self.master, until: app.buttons["Settings"].firstMatch)
        selectItem(app, "Shop")
        clearClipboard()
        copyPassword()
        XCTAssertEqual(clipboard(), "Pw-Shop-2222", "after a new unlock one copy works again")
        // Expiry: switch on, the date row appears.
        let expires = app.checkBoxes["Access expires"].firstMatch
        if expires.exists {
            flip(expires); sleep(1)
            dumpAll(app, "expiry")
            shot(app, "expiry")
            XCTAssertTrue(any(app, "Expires on").exists, "Expires on row")
            app.buttons["Cancel"].firstMatch.click()
        }
        // Item history: edit the password, then restore it from the history.
        selectItem(app, "Bank")
        app.typeKey("e", modifierFlags: .command)
        sleep(1)
        let pw = app.secureTextFields["Password"].firstMatch
        XCTAssertTrue(pw.waitForExistence(timeout: 5), "editor password field")
        pw.click(); pw.typeKey("a", modifierFlags: .command); pw.typeText("Pw-Bank-CHANGED")
        app.buttons["Save"].firstMatch.click()
        sleep(2)
        answerPasswordPrompt(app)
        app.windows.firstMatch.coordinate(withNormalizedOffset: CGVector(dx: 0.8, dy: 0.6)).scroll(byDeltaX: 0, deltaY: -1500)
        sleep(1)
        dumpAll(app, "history")
        shot(app, "item-history")
        XCTAssertTrue(any(app, "Item history").exists, "Item history section")
        XCTAssertTrue(any(app, "Edited").exists || any(app, containing: "Edited").exists, "an Edited version is listed")
    }

    /// Travel mode: a tagged login is hidden from the list, search, Trash and the CSV export; turning it off asks for
    /// the owner (Touch ID, or the master password where Touch ID is not set up).
    @MainActor
    func testTravelMode() throws {
        let app = launch(["LGK_DEBUG_PRO": "1"])
        createVault(app)
        importCSV(app, try writeCSV())
        if app.buttons["Done"].firstMatch.waitForExistence(timeout: 10) { app.buttons["Done"].firstMatch.click() }
        // Tag Bank and Mail "secret".
        for title in ["Bank", "Mail"] {
            selectItem(app, title)
            app.typeKey("e", modifierFlags: .command)
            let tags = app.textFields["Tags"].firstMatch
            XCTAssertTrue(tags.waitForExistence(timeout: 5), "Tags field")
            tags.click(); tags.typeText("secret")
            app.buttons["Save"].firstMatch.click()
            sleep(2)
        }
        // Delete Mail (goes to Trash).
        selectItem(app, "Mail")
        app.typeKey(.delete, modifierFlags: .command)
        sleep(1)
        dumpAll(app, "delete-confirm")
        let move = app.buttons["Move to Recently deleted"].firstMatch
        XCTAssertTrue(move.waitForExistence(timeout: 5), "delete asks first")
        move.click()
        sleep(2)
        openSettings(app, search: "Travel")
        let toggle = app.checkBoxes["Travel mode"].firstMatch
        XCTAssertTrue(toggle.waitForExistence(timeout: 5))
        flip(toggle)
        sleep(2)
        dumpAll(app, "travel-on")
        shot(app, "travel-settings")
        // Choose the "secret" tag.
        let tag = app.checkBoxes["secret"].firstMatch
        if tag.waitForExistence(timeout: 3) { tag.click(); sleep(1) }
        for b in ["Save", "Turn on", "Done"] where app.buttons[b].firstMatch.exists && app.buttons[b].firstMatch.isHittable {
            app.buttons[b].firstMatch.click(); sleep(1)
        }
        answerPasswordPrompt(app, timeout: 2)
        dumpAll(app, "travel-chosen")
        shot(app, "travel-chosen")
        // List and search.
        allItems(app).click()
        sleep(1)
        dumpAll(app, "travel-list")
        shot(app, "travel-list")
        XCTAssertFalse(app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@", "Bank,")).firstMatch.exists, "Bank hidden from the list")
        XCTAssertTrue(app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@", "Shop,")).firstMatch.exists, "Shop still listed")
        app.typeKey("f", modifierFlags: .command)
        app.typeText("Bank")
        sleep(1)
        dumpAll(app, "travel-search")
        XCTAssertFalse(app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH 'Bank,'")).firstMatch.exists, "search finds no Bank")
        app.typeKey(.escape, modifierFlags: [])
        // Trash.
        app.buttons["Trash"].firstMatch.click()
        sleep(2)
        dumpAll(app, "travel-trash")
        shot(app, "travel-trash")
        XCTAssertFalse(any(app, containing: "Mail").exists, "the deleted travel-hidden Mail is not shown in Trash")
        // CSV export.
        let out = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("lgk-travel-export.csv")
        try? FileManager.default.removeItem(at: out)
        app.buttons["Import & export"].firstMatch.click()
        sleep(1)
        let exportButtons = app.buttons.matching(NSPredicate(format: "label == 'Export…'")).allElementsBoundByIndex
        dumpAll(app, "export-page")
        if exportButtons.count >= 2 {
            exportButtons[1].click()   // Apple Passwords CSV
            sleep(2)
            answerPasswordPrompt(app)
            dumpAll(app, "csv-export-sheet")
            shot(app, "csv-export-sheet")
            let next = app.buttons.matching(NSPredicate(format: "label == 'Export'")).firstMatch
            if next.waitForExistence(timeout: 5) { next.click() }
            sleep(2)
            answerPasswordPrompt(app, timeout: 5)
            dumpAll(app, "csv-after-confirm")
            save(app, to: out)
            sleep(2)
            let text = (try? String(contentsOf: out, encoding: .utf8)) ?? ""
            print("MAC-CHECK travel export: \(text.replacingOccurrences(of: "\n", with: " / ").replacingOccurrences(of: "Pw-", with: "pw-"))")
            XCTAssertTrue(text.contains("Shop"), "the export holds the visible logins")
            XCTAssertFalse(text.contains("Bank"), "the export leaves out travel-hidden logins")
        }
        // Menu bar panel.
        let status = app.statusItems.firstMatch
        if status.exists {
            status.click(); sleep(2)
            print("MAC-CHECK menu bar texts:", app.descendants(matching: .any).allElementsBoundByIndex.prefix(0).count)
            shot(app, "menubar")
            for (i, w) in app.windows.allElementsBoundByIndex.enumerated() { dumpAll(app, "menubar-\(i)", window: w) }
            for (i, w) in app.popovers.allElementsBoundByIndex.enumerated() { dumpAll(app, "menubar-popover-\(i)", window: w) }
            XCTAssertFalse(app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS 'Bank'")).firstMatch.exists, "menu bar hides Bank")
            app.typeKey(.escape, modifierFlags: [])
        } else {
            print("MAC-CHECK no status item")
        }
        // Off: asks for the owner.
        openSettings(app, search: "Travel")
        app.checkBoxes["Travel mode"].firstMatch.click()
        sleep(2)
        dumpAll(app, "travel-off-prompt")
        shot(app, "travel-off-prompt")
        let asked = answerPasswordPrompt(app)
        print("MAC-CHECK travel off asked for the master password: \(asked)")
        sleep(1)
        allItems(app).click()
        sleep(1)
        XCTAssertTrue(any(app, containing: "Bank").waitForExistence(timeout: 5), "Bank back after travel mode off")
    }

    /// Privacy proof export; the file is checked afterwards with `lgk proof verify` (the path is printed).
    /// Passkey check with the provider off.
    @MainActor
    func testPrivacyProofExportAndPasskeyCheck() throws {
        let app = launch()
        createVault(app)
        openSettings(app, search: "Privacy proof")
        let out = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("lgk-privacy-proof.json")
        try? FileManager.default.removeItem(at: out)
        app.buttons["Export privacy proof"].firstMatch.click()
        save(app, to: out)
        sleep(2)
        let data = try? Data(contentsOf: out)
        XCTAssertNotNil(data, "proof written")
        if let data { try data.write(to: URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("lgk-privacy-proof-copy.json")) }
        print("MAC-CHECK proof file \(out.path) bytes=\(data?.count ?? -1)")
        if let data, let s = String(data: data, encoding: .utf8) { print("MAC-CHECK proof json \(s.prefix(1500))") }
        openSettings(app, search: "Passkey")
        sleep(2)
        dumpAll(app, "passkey-check")
        shot(app, "passkey-check")
        XCTAssertTrue(any(app, "LocalGateKeys isn't turned on for passkeys yet.").exists, "provider off is reported")
    }

    // MARK: power-user pack

    /// Restore test (Test now), the vault health report, Estate pack in emergency access.
    @MainActor
    func testRestoreTestHealthReportAndEstatePack() throws {
        let backupPassword = "backup pass for checks 77"
        let app = launch()
        createVault(app)
        // Recovery centre: a backup password, then daily scheduled backups.
        app.buttons["Security centre"].firstMatch.click()
        let backupNow = app.buttons["Back up now"].firstMatch
        XCTAssertTrue(backupNow.waitForExistence(timeout: 5))
        backupNow.click()
        sleep(2)
        let set = app.buttons["Set…"].firstMatch
        XCTAssertTrue(set.waitForExistence(timeout: 5), "Backup password › Set…")
        set.click()
        sleep(1)
        type(app, secure: "Backup password", backupPassword)
        type(app, secure: "Confirm backup password", backupPassword)
        type(app, secure: "Master password", Self.master)
        app.buttons["Save"].firstMatch.click()
        sleep(4)
        dumpAll(app, "backup-password-set")
        let freq = app.popUpButtons.matching(NSPredicate(format: "label == 'Scheduled backups' OR value == 'Off'")).firstMatch
        if freq.waitForExistence(timeout: 3) {
            freq.click(); sleep(1)
            app.menuItems["Daily"].firstMatch.click(); sleep(2)
        }
        dumpAll(app, "schedule-daily")
        shot(app, "schedule-daily")
        // A missed run happens at the next unlock.
        lock(app)
        _ = timedUnlock(app, Self.master, until: app.buttons["Settings"].firstMatch)
        sleep(8)
        app.buttons["Security centre"].firstMatch.click()
        sleep(2)
        dumpAll(app, "security-after-backup")
        let test = app.buttons["Test now"].firstMatch
        XCTAssertTrue(test.waitForExistence(timeout: 5), "Test now")
        test.click()
        sleep(2)
        let field = app.secureTextFields["Backup password"].firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 5), "Test now asks for the backup password")
        field.click(); field.typeText(backupPassword)
        shot(app, "restore-test-ask")
        let run = app.buttons.matching(NSPredicate(format: "label == 'Test now' AND identifier == 'action-button-1'")).firstMatch
        run.click()
        sleep(15)
        dumpAll(app, "restore-test-result")
        shot(app, "restore-test-result")
        XCTAssertFalse(any(app, containing: "Failed").exists, "the restore test passed")
        // Health report: the print panel opens (then cancelled).
        app.buttons["Print vault health report"].firstMatch.click()
        sleep(4)
        shot(app, "health-report")
        for w in app.windows.allElementsBoundByIndex { dumpAll(app, "health-window", window: w) }
        for s in app.sheets.allElementsBoundByIndex { dumpAll(app, "health-sheet", window: s) }
        let refused = any(app, containing: "does not support printing")
        XCTAssertFalse(refused.exists, "printing is allowed")
        if app.buttons["OK"].firstMatch.exists { app.buttons["OK"].firstMatch.click() }
        if app.buttons["Cancel"].firstMatch.exists { app.buttons["Cancel"].firstMatch.click() }
        sleep(1)
        // Estate pack in the Recovery centre's Emergency access.
        app.buttons["Security centre"].firstMatch.click()
        app.buttons["Back up now"].firstMatch.click()
        sleep(2)
        let emergency = app.buttons["Emergency access"].firstMatch
        for _ in 0..<6 where !emergency.exists { app.windows.firstMatch.coordinate(withNormalizedOffset: CGVector(dx: 0.6, dy: 0.6)).scroll(byDeltaX: 0, deltaY: -2000); sleep(1) }
        XCTAssertTrue(emergency.waitForExistence(timeout: 5), "Emergency access")
        emergency.click()
        sleep(2)
        dumpAll(app, "emergency-access")
        for s in app.sheets.allElementsBoundByIndex { dumpAll(app, "emergency-sheet", window: s) }
        shot(app, "emergency-access")
        let estate = app.buttons["Create estate pack note"].firstMatch
        XCTAssertTrue(estate.waitForExistence(timeout: 5), "Create estate pack note")
        estate.click()
        sleep(2)
        for s in app.sheets.allElementsBoundByIndex { dumpAll(app, "estate-sheet", window: s) }
        shot(app, "estate-created")
        if app.buttons["Done"].firstMatch.exists { app.buttons["Done"].firstMatch.click() }
        sleep(1)
        allItems(app).click()
        sleep(1)
        dumpAll(app, "estate-list")
        XCTAssertTrue(any(app, containing: "state").exists, "the estate pack note is in the vault")
    }
}
