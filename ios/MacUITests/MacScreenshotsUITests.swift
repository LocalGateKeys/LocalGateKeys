import XCTest

/// The four Mac screenshots for the website showcase (`website/src/static/screenshots/platforms/mac-0N-*.webp`: items and edit, sync, security, settings), in
/// English, from the demo preview at 1180×760 (the largest window a 1280×800-point screen fits). A trimmed demo vault (four item types) keeps every Tools row in view,
/// the one-time codes are unfolded and the setup chip hidden. Run: `scripts/mac_ui_checks.sh MacScreenshotsUITests`,
/// then export the attachments (`xcrun xcresulttool export attachments`).
final class MacScreenshotsUITests: XCTestCase {
    /// Demo items moved out of the vault so the sidebar lists four types and every Tools row fits.
    static let trimmed = "Driving licence,Everyday account,Music,Home Wi-Fi,Photo editor,Weather API,Docs"

    override func setUpWithError() throws {
        continueAfterFailure = false
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_MAC_UI_CHECKS"] == "1", "run through scripts/mac_ui_checks.sh")
    }

    @MainActor
    private func capture(_ name: String, _ env: [String: String], unfold: Bool = true, tidy: Bool = true, prepare: (XCUIApplication) -> Void = { _ in }) {
        let app = XCUIApplication()
        app.launchArguments += ["-AppleLanguages", "(en)", "-AppleLocale", "en_US", "-ApplePersistenceIgnoreState", "YES"]
        app.launchEnvironment["LGK_MAC_ALLOW_CAPTURE"] = "1"
        app.launchEnvironment["LGK_MAC_SHELL_PREVIEW"] = "1"
        app.launchEnvironment["LGK_MAC_TRASH"] = Self.trimmed
        app.launchEnvironment.merge(env) { $1 }
        app.launch()
        let window = app.windows.firstMatch
        XCTAssertTrue(window.waitForExistence(timeout: 20))
        guard tidy else {
            let skipSetup = app.buttons["Skip setup"]
            if skipSetup.waitForExistence(timeout: 4) { skipSetup.click() }
            prepare(app); sleep(2)
            let a = XCTAttachment(screenshot: window.screenshot()); a.name = name; a.lifetime = .keepAlways
            add(a); app.terminate(); return
        }
        let skip = app.buttons["Skip setup"]
        if skip.waitForExistence(timeout: 3) { skip.click() }
        let hide = app.buttons["Hide"].firstMatch
        if hide.waitForExistence(timeout: 2) { hide.click() }
        if unfold {
            let expand = app.buttons["Expand one-time codes"].firstMatch
            if expand.waitForExistence(timeout: 2) { expand.click() }
        }
        prepare(app)
        sleep(2)
        let a = XCTAttachment(screenshot: app.windows.firstMatch.screenshot()); a.name = name; a.lifetime = .keepAlways
        add(a)
        app.terminate()
    }

    @MainActor
    func testScreenshots() throws {
        capture("mac-01-edit", ["LGK_MAC_SELECT": "github.com", "LGK_MAC_EDIT": "1", "LGK_MAC_APPEARANCE": "dark"])
        capture("mac-02-sync", ["LGK_MAC_TOOL": "sync", "LGK_MAC_SYNC_PREVIEW": "page", "LGK_MAC_APPEARANCE": "light"])
        capture("mac-03-security", ["LGK_MAC_TOOL": "security", "LGK_MAC_APPEARANCE": "dark"])
        capture("mac-04-settings", ["LGK_MAC_TOOL": "settings", "LGK_MAC_APPEARANCE": "light"])
    }

    /// A clean five-shot set (store and press use), light and dark alternating.
    @MainActor
    func testCleanSet() throws {
        capture("clean-mac-1-vault", ["LGK_MAC_SELECT": "github.com", "LGK_MAC_APPEARANCE": "light"])
        capture("clean-mac-2-edit", ["LGK_MAC_SELECT": "github.com", "LGK_MAC_EDIT": "1", "LGK_MAC_APPEARANCE": "dark"])
        capture("clean-mac-3-sync", ["LGK_MAC_TOOL": "sync", "LGK_MAC_SYNC_PREVIEW": "page", "LGK_MAC_APPEARANCE": "light"])
        capture("clean-mac-4-security", ["LGK_MAC_TOOL": "security", "LGK_MAC_APPEARANCE": "dark"])
        capture("clean-mac-5-settings", ["LGK_MAC_TOOL": "settings", "LGK_MAC_APPEARANCE": "light"])
    }
}
