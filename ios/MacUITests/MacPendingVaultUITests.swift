import XCTest

/// docs/PENDING.md section 4: the unlock throttle mark outside the vault folder, and the power-user pack's profile
/// checks (the upgrade sheet for a second profile on the free plan, the greyed "Vault: <name>" with two profiles).
final class MacPendingVaultUITests: MacPendingUITestCase {
    static let wrong = "this is not the password 9"

    /// Wrong passwords until the wait reaches 8 s (failures 6, 7, 8 each start a wait), counting each one.
    @MainActor
    private func failUntil(_ app: XCUIApplication, failures want: Int) {
        var failed = 0
        let wrongLine = text(app, beginningWith: "That password isn't right.")
        let tooMany = text(app, beginningWith: "Too many attempts.")
        var rounds = 0
        while failed < want && rounds < 40 {
            rounds += 1
            type(app, secure: "Master password", Self.wrong)
            app.buttons["Unlock"].click()
            let start = Date()
            var outcome = ""
            while Date().timeIntervalSince(start) < 20 {
                if tooMany.exists { outcome = tooMany.label.isEmpty ? ((tooMany.value as? String) ?? "") : tooMany.label; break }
                if wrongLine.exists { outcome = "wrong"; break }
                usleep(100_000)
            }
            print("MAC-CHECK attempt \(rounds): \(outcome)")
            if outcome.hasPrefix("Too many") {
                // Was this attempt counted? The message is shown before checking, so it was refused: wait it out.
                let secs = Int(outcome.components(separatedBy: CharacterSet.decimalDigits.inverted).joined()) ?? 2
                sleep(UInt32(secs + 1))
                // The next attempt may show the same line again; it was this run's failure count that started it.
                continue
            }
            if outcome == "wrong" { failed += 1 }
            // Let the line clear before the next attempt.
            sleep(1)
        }
        print("MAC-CHECK counted wrong passwords: \(failed)")
    }

    @MainActor
    func testUnlockThrottleSurvivesPuttingBackAVaultCopy() throws {
        let fm = FileManager.default
        var app = launch()
        createVault(app)
        lock(app)
        app.terminate()
        let copy = vaultDir.deletingLastPathComponent().appendingPathComponent(vaultName + "-copy")
        do {
            try? fm.removeItem(at: copy)
            try fm.copyItem(at: vaultDir, to: copy)
        } catch {
            throw XCTSkip("the runner cannot copy the app's vault folder: \(error)")
        }
        print("MAC-CHECK copied: \(vaultFiles() ?? [])")
        app = launch()
        XCTAssertTrue(app.buttons["Unlock"].waitForExistence(timeout: 10))
        failUntil(app, failures: 8)
        // One more try shows the wait.
        type(app, secure: "Master password", Self.wrong)
        app.buttons["Unlock"].click()
        sleep(1)
        shot(app, "throttle-before-copy")
        print("MAC-CHECK throttle.json present: \(fm.fileExists(atPath: vaultDir.appendingPathComponent("throttle.json").path))")
        app.terminate()
        // Put back the copy from before the failures (no throttle.json).
        try fm.removeItem(at: vaultDir)
        try fm.moveItem(at: copy, to: vaultDir)
        print("MAC-CHECK put back: \(vaultFiles() ?? [])")
        app = launch()
        XCTAssertTrue(app.buttons["Unlock"].waitForExistence(timeout: 10))
        type(app, secure: "Master password", Self.master)
        app.buttons["Unlock"].click()
        let tooMany = text(app, beginningWith: "Too many attempts.")
        let waited = tooMany.waitForExistence(timeout: 10)
        shot(app, "throttle-after-copy")
        let line = tooMany.exists ? (tooMany.label.isEmpty ? ((tooMany.value as? String) ?? "") : tooMany.label) : "none"
        print("MAC-CHECK after putting back the copy: \(line); unlocked=\(app.buttons["Settings"].firstMatch.exists)")
        XCTAssertTrue(waited, "the wait still applies after the vault folder copy is put back")
        XCTAssertFalse(app.buttons["Settings"].firstMatch.exists, "the right password waits too")
        // After the wait the right password opens and clears it.
        sleep(20)
        _ = timedUnlock(app, Self.master, until: app.buttons["Settings"].firstMatch)
        XCTAssertTrue(app.buttons["Settings"].firstMatch.waitForExistence(timeout: 30), "the right password opens after the wait")
        lock(app)
        // Cleared: five wrong passwords are free again.
        failUntil(app, failures: 5)
        _ = timedUnlock(app, Self.master, until: app.buttons["Settings"].firstMatch)
        let opened = app.buttons["Settings"].firstMatch.waitForExistence(timeout: 30)
        shot(app, "throttle-cleared")
        XCTAssertTrue(opened, "after the success, 5 wrong passwords start no wait")
    }

    /// Free plan: adding a second profile opens the upgrade sheet. Pro: a second profile, then the app menu shows the
    /// greyed "Vault: <name>".
    @MainActor
    func testSecondProfileUpgradeSheetAndVaultMenuLabel() throws {
        let root = vaultDir.deletingLastPathComponent().appendingPathComponent("profiles-\(UUID().uuidString.prefix(8))").path
        var app = launch(["LGK_DEBUG_PRO": "0", "LGK_MAC_VAULT_DIR": "", "LGK_MAC_PROFILES_ROOT": root])
        createVault(app)
        func chooser() {
            app.menuBars.menuBarItems["LocalGateKeys"].firstMatch.click()
            let sw = app.menuItems["Switch Profile…"].firstMatch
            XCTAssertTrue(sw.waitForExistence(timeout: 5), "Switch Profile… in the app menu")
            sw.click()
            sleep(2)
        }
        chooser()
        dumpAll(app, "profiles-chooser")
        let field = app.textFields["New profile name"].firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 5), "New profile name")
        field.click(); field.typeText("Work")
        app.buttons["Add profile"].firstMatch.click()
        sleep(2)
        dumpAll(app, "profiles-free-add")
        shot(app, "profiles-upgrade-sheet")
        XCTAssertTrue(any(app, containing: "Pro").exists, "the upgrade sheet is shown")
        app.typeKey(.escape, modifierFlags: [])
        app.terminate()
        // Pro.
        app = launch(["LGK_DEBUG_PRO": "1", "LGK_MAC_VAULT_DIR": "", "LGK_MAC_PROFILES_ROOT": root])
        _ = timedUnlock(app, Self.master, until: app.buttons["Settings"].firstMatch)
        chooser()
        let field2 = app.textFields["New profile name"].firstMatch
        XCTAssertTrue(field2.waitForExistence(timeout: 5))
        field2.click(); field2.typeText("Work")
        app.buttons["Add profile"].firstMatch.click()
        sleep(2)
        // The new profile opens on its create screen.
        createVault(app)
        app.menuBars.menuBarItems["LocalGateKeys"].firstMatch.click()
        sleep(1)
        let label = app.menuItems["Vault: Work"].firstMatch
        let shown = label.waitForExistence(timeout: 3)
        print("MAC-CHECK Vault: Work menu item exists=\(shown) enabled=\(shown ? label.isEnabled : false)")
        shot(app, "app-menu-two-profiles")
        XCTAssertTrue(shown, "the app menu names the open vault")
        XCTAssertFalse(label.isEnabled, "and it is greyed (a label)")
        app.typeKey(.escape, modifierFlags: [])
    }
}
