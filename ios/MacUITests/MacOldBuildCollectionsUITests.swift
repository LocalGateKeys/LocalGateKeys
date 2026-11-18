import XCTest

/// docs/PENDING.md section 4, "Collections from an older build": a build from before the collections moved into the
/// item store (`6eb84563^`, collections in the Mac's local data) makes a vault with collections and memberships, one
/// member in Recently deleted; then this build opens the same vault folder. The older build is made separately with
/// the same `app.localgatekeys.uitest` prefix (same container) and passed as `TEST_RUNNER_LGK_OLD_APP=<path to .app>`;
/// without it the tests are skipped. Run `testA…` then `testB…` (the vault folder name is fixed).
final class MacOldBuildCollectionsUITests: MacRealVaultUITestCase {
    static let folder = ProcessInfo.processInfo.environment["LGK_OLD_FOLDER"] ?? "lgk-uitest-oldbuild-collections"

    override func setUpWithError() throws {
        try super.setUpWithError()
        vaultName = Self.folder
    }

    @MainActor
    func dumpAll(_ app: XCUIApplication, _ tag: String) {
        guard let snap = try? app.windows.firstMatch.snapshot() else { return }
        var out: [String] = []
        func walk(_ s: XCUIElementSnapshot) {
            let t = [s.label, s.title, (s.value as? String) ?? "", s.identifier].filter { !$0.isEmpty }.joined(separator: "/")
            if !t.isEmpty { out.append("\(s.elementType.rawValue):\(t)") }
            s.children.forEach(walk)
        }
        walk(snap)
        print("MAC-CHECK [\(tag)] " + out.joined(separator: " | "))
    }

    @MainActor
    func oldApp() throws -> XCUIApplication {
        let path = try XCTUnwrap(ProcessInfo.processInfo.environment["LGK_OLD_APP"], "TEST_RUNNER_LGK_OLD_APP not set")
        let app = XCUIApplication(url: URL(fileURLWithPath: path))
        app.launchEnvironment["LGK_MAC_ALLOW_CAPTURE"] = "1"
        // The older build takes the path as given (no relative-to-temporary rule): pass the absolute folder.
        app.launchEnvironment["LGK_MAC_VAULT_DIR"] = vaultDir.path
        app.launchEnvironment["LGK_MAC_HIDE_SETUP"] = "1"
        app.launchEnvironment["LGK_DEBUG_PRO"] = "1"
        return app
    }

    @MainActor
    func testA0ProbeOldBuild() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_OLD_APP"] != nil, "no older build given")
        try? FileManager.default.removeItem(at: vaultDir)
        let app = try oldApp()
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20))
        createVault(app)
        dumpAll(app, "old-home")
        shot(app, "old-home")
        app.buttons["Manage collections"].firstMatch.click()
        sleep(2)
        dumpAll(app, "old-manage")
        shot(app, "old-manage")
        app.typeKey(.escape, modifierFlags: [])
        sleep(1)
        app.buttons["New item"].firstMatch.click()
        let kind = app.buttons.matching(NSPredicate(format: "label CONTAINS 'Website login'")).firstMatch
        if kind.waitForExistence(timeout: 5) { kind.click() }
        sleep(1)
        dumpAll(app, "old-editor")
        shot(app, "old-editor")
        app.terminate()
    }

    /// Notes and the collections each one is put in (the older build shows the collection checkboxes for every kind
    /// but website logins). "Note D" is deleted afterwards.
    static let plan: [(String, [String])] = [("Note A", ["Personal", "Office"]), ("Note B", ["Travel"]),
                                             ("Note C", ["Family", "Personal"]), ("Note D", ["Family", "Emergency"])]

    /// Older build: a custom collection (Family), a renamed starter (Work → Office), four notes in collections, one deleted.
    @MainActor
    func testA1OlderBuildMakesCollections() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_OLD_APP"] != nil, "no older build given")
        continueAfterFailure = true
        let app = try oldApp()
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 20))
        if app.buttons["Unlock"].waitForExistence(timeout: 3) {
            // A vault from an earlier run: start again.
            app.terminate()
            try? FileManager.default.removeItem(at: vaultDir)
            app.launch()
        }
        createVault(app)
        app.buttons["Manage collections"].firstMatch.click()
        let newName = app.textFields["New collection"].firstMatch
        XCTAssertTrue(newName.waitForExistence(timeout: 5), "Manage collections › New collection")
        newName.click(); newName.typeText("Family")
        app.buttons["Create"].firstMatch.click()
        sleep(1)
        // Rename Work → Office: the Rename buttons follow the collections in order (Emergency, Family, Personal, Travel, Work).
        let rows = app.buttons.matching(identifier: "Rename").allElementsBoundByIndex
        let renames = app.buttons.matching(NSPredicate(format: "label == 'Rename'")).allElementsBoundByIndex
        print("MAC-CHECK rename buttons \(rows.count)/\(renames.count)")
        renames.last?.click()
        sleep(1)
        let nameField = app.textFields["Name"].firstMatch
        if nameField.waitForExistence(timeout: 3) {
            nameField.click(); nameField.typeKey("a", modifierFlags: .command); nameField.typeText("Office\r")
        }
        sleep(1)
        dumpAll(app, "old-manage-after")
        shot(app, "old-manage-after")
        app.buttons["Done"].firstMatch.click()
        sleep(1)
        for (title, names) in Self.plan {
            app.buttons["New item"].firstMatch.click()
            let kind = app.buttons.matching(NSPredicate(format: "label CONTAINS 'Secure note'")).firstMatch
            XCTAssertTrue(kind.waitForExistence(timeout: 5))
            kind.click()
            let t = app.textFields["Title"].firstMatch
            XCTAssertTrue(t.waitForExistence(timeout: 5))
            t.click(); t.typeText(title)
            for n in names {
                let box = app.checkBoxes[n].firstMatch
                if !box.exists { dumpAll(app, "old-note-editor") }
                XCTAssertTrue(box.exists, "checkbox \(n)")
                box.click()
            }
            shot(app, "old-editor-\(title)")
            app.buttons["Save"].firstMatch.click()
            XCTAssertTrue(app.buttons["Save"].firstMatch.waitForNonExistence(timeout: 10), "saved \(title)")
            sleep(1)
        }
        // Delete Note D.
        let row = app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH 'Note D'")).firstMatch
        row.click()
        app.typeKey(.delete, modifierFlags: .command)
        sleep(1)
        dumpAll(app, "old-delete")
        let move = app.buttons["Move to Recently deleted"].firstMatch
        XCTAssertTrue(move.waitForExistence(timeout: 5), "delete asks first")
        move.click()
        sleep(2)
        dumpAll(app, "old-final")
        shot(app, "old-final")
        app.terminate()
    }

    /// This build over the same vault folder: every collection, name and membership is there; restoring Note D brings
    /// its collections back; the access log of the older local data (no event chain) reads as verified.
    @MainActor
    func testB1CurrentBuildKeepsCollections() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_OLD_APP"] != nil, "no older build given")
        continueAfterFailure = true
        let app = launch()
        _ = timedUnlock(app, Self.master, until: app.buttons["Settings"].firstMatch)
        sleep(2)
        dumpAll(app, "new-home")
        shot(app, "new-home")
        func count(_ name: String) -> String? {
            let b = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", name + ",")).firstMatch
            return b.exists ? b.label : nil
        }
        for (name, want) in [("Personal", 2), ("Office", 1), ("Travel", 1), ("Family", 1), ("Emergency", 0)] {
            print("MAC-CHECK collection \(name): \(count(name) ?? "missing")")
            XCTAssertEqual(count(name), "\(name), \(want)", "\(name) kept with its members")
        }
        XCTAssertNil(count("Work"), "the renamed Work stays Office")
        // Members.
        for (name, notes) in [("Personal", ["Note A", "Note C"]), ("Office", ["Note A"]), ("Family", ["Note C"])] {
            app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", name + ",")).firstMatch.click()
            sleep(1)
            for n in notes {
                XCTAssertTrue(app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@", n)).firstMatch.exists,
                              "\(n) listed in \(name)")
            }
        }
        // Restore Note D from Trash.
        app.buttons["Trash"].firstMatch.click()
        sleep(2)
        dumpAll(app, "new-trash")
        let pick = app.checkBoxes["Select Note D"].firstMatch
        XCTAssertTrue(pick.waitForExistence(timeout: 5), "Note D in Trash")
        pick.click()
        app.buttons["Restore selected"].firstMatch.click()
        sleep(2)
        dumpAll(app, "new-restored")
        shot(app, "new-restored")
        XCTAssertEqual(count("Family"), "Family, 2", "Note D back in Family")
        XCTAssertEqual(count("Emergency"), "Emergency, 1", "Note D back in Emergency")
        // The older local data's access log.
        app.buttons["Security centre"].firstMatch.click()
        sleep(2)
        let verified = app.staticTexts["Access log verified"].firstMatch
        shot(app, "new-security-centre")
        XCTAssertTrue(verified.waitForExistence(timeout: 5), "Access log verified with the older local data")
        if !verified.exists { dumpAll(app, "new-security") }
        // A relaunch changes nothing.
        app.terminate()
        let again = launch()
        _ = timedUnlock(again, Self.master, until: again.buttons["Settings"].firstMatch)
        sleep(2)
        for (name, want) in [("Personal", 2), ("Office", 1), ("Travel", 1), ("Family", 2), ("Emergency", 1)] {
            let b = again.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", name + ",")).firstMatch
            XCTAssertEqual(b.exists ? b.label : nil, "\(name), \(want)", "after a relaunch: \(name)")
        }
    }
}
