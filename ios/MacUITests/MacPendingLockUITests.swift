import XCTest

/// docs/PENDING.md section 4, review fixes 2026-11-15: the vault locks when the screensaver starts and when the display
/// sleeps. The screensaver and display sleep are started from outside the runner: a driver follows the test log for
/// the "MAC-CHECK flag" lines, starts the screensaver or sleeps the display, and ends it within seconds. Without the
/// driver (`TEST_RUNNER_LGK_MAC_LOCK_DRIVER=1` in the script's environment) the test is skipped.
final class MacPendingLockUITests: MacRealVaultUITestCase {
    private func flag(_ name: String) {
        print("MAC-CHECK flag \(name)")
        fflush(stdout)
    }

    @MainActor
    func testScreensaverAndDisplaySleepLockTheVault() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_MAC_LOCK_DRIVER"] == "1", "no lock driver running")
        continueAfterFailure = true
        let app = launch()
        createVault(app)
        XCTAssertTrue(app.buttons["Settings"].firstMatch.exists, "unlocked before the screensaver")
        flag("lgk-ready-screensaver")
        let unlock = app.buttons["Unlock"]
        let lockedBySaver = unlock.waitForExistence(timeout: 60)
        print("MAC-CHECK locked by screensaver: \(lockedBySaver)")
        // The driver ends the screensaver within about 10 s; give the screen a moment.
        sleep(15)
        shot(app, "locked-after-screensaver")
        XCTAssertTrue(lockedBySaver, "the screensaver start locked the vault")
        _ = timedUnlock(app, Self.master, until: app.buttons["Settings"].firstMatch)
        XCTAssertTrue(app.buttons["Settings"].firstMatch.waitForExistence(timeout: 30), "unlocked again")
        flag("lgk-ready-displaysleep")
        let lockedBySleep = unlock.waitForExistence(timeout: 60)
        print("MAC-CHECK locked by display sleep: \(lockedBySleep)")
        sleep(15)
        shot(app, "locked-after-display-sleep")
        XCTAssertTrue(lockedBySleep, "display sleep locked the vault")
        flag("lgk-done")
    }
}
