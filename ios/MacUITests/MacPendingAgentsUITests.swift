import AppKit
import XCTest

/// docs/PENDING.md section 4, AI agents: the switch, the copied `claude mcp add` command, and the approval panel for
/// `lgk mcp` requests (Deny, Approve once, the 2-minute timeout, "Require Touch ID for each approval"). The MCP client
/// is a driver outside the runner (it follows the test log for "MAC-CHECK flag mcp-…" lines and runs `lgk mcp` from
/// the built app over stdio); it also checks that another program on `fill.sock` gets nothing. Without the driver
/// (`TEST_RUNNER_LGK_MCP_DRIVER=1`) the test is skipped.
final class MacPendingAgentsUITests: MacPendingUITestCase {
    private func flag(_ name: String) {
        print("MAC-CHECK flag \(name)")
        fflush(stdout)
    }

    /// The switch on the same row as `title` (the settings rows' switches have no label of their own).
    @MainActor
    func switchBeside(_ app: XCUIElement, _ title: String) -> XCUIElement? {
        let text = app.staticTexts[title].firstMatch
        guard text.waitForExistence(timeout: 5) else { return nil }
        // The switch is centred on the row (title and its detail): the first switch to the right, from the title's
        // top to a little below.
        let top = text.frame.minY
        let all = app.checkBoxes.allElementsBoundByIndex
        print("MAC-CHECK switches near '\(title)' at \(text.frame): \(all.map { "\($0.frame)" })")
        return all
            .filter { $0.frame.minX > text.frame.minX && $0.frame.midY > top - 12 && $0.frame.midY < top + 160 }
            .min { $0.frame.midY < $1.frame.midY }
    }

    @MainActor
    func panelButton(_ app: XCUIApplication, _ name: String, timeout: TimeInterval = 30) -> XCUIElement? {
        let b = app.buttons[name].firstMatch
        return b.waitForExistence(timeout: timeout) ? b : nil
    }

    @MainActor
    func testAIAgentsApprovalPanel() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_MCP_DRIVER"] == "1", "no MCP driver running")
        let app = launch(["LGK_DEBUG_PRO": "1"])
        createVault(app)
        importCSV(app, try writeCSV())
        if app.buttons["Done"].firstMatch.waitForExistence(timeout: 10) { app.buttons["Done"].firstMatch.click() }
        // "AI agents may use this login" on Example.
        selectItem(app, "Example")
        app.windows.firstMatch.coordinate(withNormalizedOffset: CGVector(dx: 0.8, dy: 0.6)).scroll(byDeltaX: 0, deltaY: -1500)
        sleep(1)
        let mayUse = switchBeside(app, "AI agents may use this login")
        XCTAssertNotNil(mayUse, "the login's AI agents switch")
        mayUse?.click()
        sleep(1)
        answerPasswordPrompt(app, timeout: 2)
        shot(app, "login-ai-agents-on")
        // Settings › Developer › Allow AI agents.
        openSettings(app, search: "Developer")
        let allow = switchBeside(app, "Allow AI agents to use LocalGateKeys")
        XCTAssertNotNil(allow, "Allow AI agents switch")
        allow?.click()
        sleep(2)
        dumpAll(app, "developer-agents-on")
        shot(app, "developer-agents-on")
        // The command: the Copy button under its title.
        let title = app.staticTexts["Add LocalGateKeys to Claude Code (Terminal)"].firstMatch
        XCTAssertTrue(title.waitForExistence(timeout: 5), "the command row")
        let copy = app.buttons.matching(NSPredicate(format: "label == 'Copy'")).allElementsBoundByIndex
            .filter { $0.frame.minY >= title.frame.minY }.min { $0.frame.minY < $1.frame.minY }
        clearClipboard()
        copy?.click()
        sleep(1)
        let command = clipboard() ?? ""
        print("MAC-CHECK copied command: \(command)")
        XCTAssertTrue(command.hasPrefix("claude mcp add localgatekeys -- \""), "claude mcp add command")
        XCTAssertTrue(command.hasSuffix("/Contents/MacOS/lgk\" mcp"), "points at the bundled lgk")

        // 1. list_sites, Deny.
        flag("mcp-deny")
        let deny = panelButton(app, "Deny")
        XCTAssertNotNil(deny, "list_sites shows the approval panel")
        sleep(1)
        shot(app, "panel-list-sites")
        if let w = app.windows.allElementsBoundByIndex.first(where: { $0.buttons["Deny"].exists }) { dumpAll(app, "panel", window: w) }
        deny?.click()
        sleep(3)
        // 2. list_sites, Approve once.
        flag("mcp-approve")
        let approve = panelButton(app, "Approve once")
        XCTAssertNotNil(approve, "the second list_sites shows the panel")
        approve?.click()
        sleep(3)
        // 3. request_login, no answer: refused after 120 s.
        flag("mcp-timeout")
        let pending = panelButton(app, "Approve once")
        XCTAssertNotNil(pending, "request_login shows the panel")
        shot(app, "panel-request-login")
        if let w = app.windows.allElementsBoundByIndex.first(where: { $0.buttons["Deny"].exists }) { dumpAll(app, "panel-login", window: w) }
        let gone = app.buttons["Approve once"].firstMatch.waitForNonExistence(timeout: 135)
        print("MAC-CHECK panel closed by the timeout: \(gone)")
        XCTAssertTrue(gone, "the panel closes after 2 minutes without an answer")
        sleep(3)
        // 4. Require Touch ID for each approval: Approve once asks for Touch ID, or the master password when Touch ID
        // is not set up (as in this test vault).
        openSettings(app, search: "Developer")
        let touch = switchBeside(app, "Require Touch ID for each approval")
        XCTAssertNotNil(touch, "Require Touch ID switch")
        touch?.click()
        sleep(1)
        flag("mcp-touchid")
        let approve2 = panelButton(app, "Approve once")
        XCTAssertNotNil(approve2)
        approve2?.click()
        sleep(2)
        shot(app, "panel-verify")
        if let w = app.windows.allElementsBoundByIndex.first(where: { $0.buttons["Deny"].exists }) { dumpAll(app, "panel-verify", window: w) }
        let pw = app.secureTextFields["Master password"].firstMatch
        let asked = pw.waitForExistence(timeout: 10)
        print("MAC-CHECK approval asked for verification (master password field): \(asked)")
        XCTAssertTrue(asked, "with Require Touch ID on, Approve once asks again (master password: no Touch ID here)")
        if asked {
            // A wrong password first.
            pw.click(); pw.typeText("not the password 1\r")
            sleep(3)
            shot(app, "panel-wrong-password")
            if let w = app.windows.allElementsBoundByIndex.first(where: { $0.buttons["Deny"].exists }) { dumpAll(app, "panel-wrong", window: w) }
            pw.click(); pw.typeKey("a", modifierFlags: .command); pw.typeText(Self.master + "\r")
            sleep(3)
        }
        // 5. fill.sock from another program, then the end (fill_login waits up to 60 s for Safari).
        flag("mcp-fill")
        sleep(70)
        flag("mcp-end")
        sleep(5)
    }
}
