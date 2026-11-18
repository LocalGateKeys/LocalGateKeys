import XCTest

/// The Safari "just filled" marker (`SafariFillMarker`) end to end on the iPhone simulator, against the local page
/// `scripts/ios_simulator_checks.sh` serves. The demo vault saves `tester@example.com` for
/// `https://loginlab.localhost:<port>` (`LGK_DEMO_LOCAL_SITE`).
/// - A saved login typed by hand gets the "Save / update?" prompt (the extension works, and nothing was filled).
/// - The same login filled by LocalGateKeys AutoFill and signed in gets no prompt.
/// - After the marker's 20 seconds, the login typed by hand gets the prompt again.
final class SafariFillMarkerUITests: SafariExtensionUITestCase {
    static let user = "tester@example.com"

    @MainActor
    func testALoginFilledByAutoFillIsNotOfferedAndATypedOneIs() throws {
        unlockAppRetrying()
        // AutoFill first: Settings may reopen on that page, whose "LocalGateKeys" row `allowExtension` would take for
        // the extension's; it walks back to the top from there.
        allowAutoFill()
        allowExtension()

        // Typed by hand: the vault has this site and username, so the extension asks.
        dismissSafariFirstRun()
        open(page())
        typeAndSignIn(Self.user, "typed-by-hand-1")
        XCTAssertTrue(promptAppears(), "a saved login typed by hand gets the prompt")
        shot("typed-prompt")
        dismissPrompt()

        // Filled by AutoFill: no prompt.
        open(page())
        fillWithAutoFill()
        shot("filled-before-sign-in")
        element(safari, "label == 'Sign in' AND elementType == %d", XCUIElement.ElementType.button.rawValue).tap()
        XCTAssertTrue(element(safari, "label == 'Signed in'").waitForExistence(timeout: 10), "signed in")
        let asked = promptAppears(timeout: 8)
        shot("filled-after-sign-in")
        if asked { print("SF-LABELS", labels(safari)) }
        XCTAssertFalse(asked, "a login AutoFill just filled gets no prompt")

        // The marker is used up 20 seconds after its first match: typed by hand again, the prompt is back.
        sleep(25)
        open(page())
        typeAndSignIn(Self.user, "typed-by-hand-2")
        XCTAssertTrue(promptAppears(), "after the marker's time a typed login gets the prompt again")
        shot("typed-prompt-again")
        dismissPrompt()
    }

    /// `unlockApp`, tapping Unlock again when a Face ID match from the Mac landed badly ("Could not unlock", seen on
    /// a simulator whose enrolment had just been set).
    @MainActor
    func unlockAppRetrying() {
        let app = XCUIApplication()
        app.launchArguments += ["-LGKDemoData", "YES", "-LGKScreen", "item"]
        app.launchEnvironment["LGK_DEBUG_PRO"] = "1"
        app.launchEnvironment["LGK_DEMO_LOCAL_SITE"] = "1"
        app.launchEnvironment["LGK_DEMO_LOCAL_PORT"] = String(port)
        app.launch()
        let unlocked = element(app, "label == 'Username' OR (elementType == %d AND identifier == 'Save from Safari?')",
                               XCUIElement.ElementType.navigationBar.rawValue)
        let retry = app.buttons["Unlock"]
        for _ in 0..<12 where !unlocked.waitForExistence(timeout: 5) {
            if retry.exists, retry.isHittable { retry.tap() }
        }
        if !unlocked.exists { print("APP-LABELS", labels(app)) }
        XCTAssertTrue(unlocked.exists, "unlocked (Face ID from the Mac)")
    }

    /// Types one key at a time and checks the field after each: with AutoFill on, the simulator's keyboard drops keys
    /// while the QuickType bar changes (seen on iOS 27). `count` reads how many characters the field holds.
    @MainActor
    func typeChecked(_ field: XCUIElement, _ text: String, secure: Bool = false) {
        field.tap()
        let chars = Array(text)
        func current() -> String { let v = (field.value as? String) ?? ""; return v == field.placeholderValue ? "" : v }
        for _ in 0..<(chars.count * 4) {
            let now = current()
            let good = secure ? now.count <= chars.count : text.hasPrefix(now)
            if good, now.count == chars.count { break }
            if good { field.typeText(String(chars[now.count])) } else { field.typeText(XCUIKeyboardKey.delete.rawValue) }
        }
        if secure { XCTAssertEqual(current().count, chars.count, "the password typed in full") }
        else { XCTAssertEqual(current(), text, "typed in full") }
    }

    @MainActor
    func typeAndSignIn(_ user: String, _ password: String) {
        let email = safari.textFields["Email"].firstMatch
        XCTAssertTrue(email.waitForExistence(timeout: 5))
        typeChecked(email, user)
        typeChecked(safari.secureTextFields["Password"].firstMatch, password, secure: true)
        element(safari, "label == 'Sign in' AND elementType == %d", XCUIElement.ElementType.button.rawValue).tap()
    }

    /// A simulator whose Safari never ran shows a first-run sheet over the start page ("Include topics from other
    /// devices": Not Now / Turn On), and a link opened meanwhile does not load.
    @MainActor
    func dismissSafariFirstRun() {
        safari.launch()
        let notNow = safari.buttons["Not Now"]
        for _ in 0..<3 where notNow.waitForExistence(timeout: 3) { notNow.tap() }
    }

    /// Waits for the extension's prompt. Safari's own "Save Password?" sheet (the Passwords app is an AutoFill
    /// source too, and offers to keep a typed password) covers the page: it is answered Not Now on the way.
    @MainActor
    func promptAppears(timeout: Int = 12) -> Bool {
        for _ in 0..<timeout {
            if savePrompt.exists { return true }
            if element(safari, "label == 'Save Password?'").exists, safari.buttons["Not Now"].exists { safari.buttons["Not Now"].tap() }
            sleep(1)
        }
        return savePrompt.exists
    }

    @MainActor
    func dismissPrompt() {
        let later = element(safari, "label == 'Not now'")
        if later.waitForExistence(timeout: 3) { later.tap() }
    }

    /// Settings › General › AutoFill & Passwords › LocalGateKeys on.
    @MainActor
    func allowAutoFill() {
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.terminate()
        settings.launch()
        // The row reads "LocalGateKeys, Off" (a cell on iOS 27) or is a switch named LocalGateKeys; it only counts on
        // the AutoFill & Passwords page.
        let onPage = settings.navigationBars["AutoFill & Passwords"]
        let toggle = element(settings, "label BEGINSWITH 'LocalGateKeys' AND (elementType == %d OR elementType == %d)",
                             XCUIElement.ElementType.switch.rawValue, XCUIElement.ElementType.cell.rawValue)
        func isOn() -> Bool { (toggle.value as? String) == "1" || toggle.label.hasSuffix(", On") }
        for name in ["General", "AutoFill & Passwords"] where !onPage.waitForExistence(timeout: 1) {
            let row = element(settings, "label == %@ AND (elementType == %d OR elementType == %d)", name,
                              XCUIElement.ElementType.cell.rawValue, XCUIElement.ElementType.button.rawValue)
            if !row.exists, name == "General" {
                for _ in 0..<5 where settings.navigationBars.buttons.firstMatch.exists { settings.navigationBars.buttons.firstMatch.tap() }
            }
            func reachable() -> Bool { row.exists && row.isHittable && row.frame.maxY < settings.frame.height * 0.78 }
            for _ in 0..<8 where !reachable() {
                let from = settings.coordinate(withNormalizedOffset: CGVector(dx: 0.02, dy: 0.8))
                from.press(forDuration: 0.05, thenDragTo: settings.coordinate(withNormalizedOffset: CGVector(dx: 0.02, dy: 0.35)))
            }
            XCTAssertTrue(row.exists, "Settings row \(name)")
            let before = settings.navigationBars.firstMatch.exists ? settings.navigationBars.firstMatch.identifier : ""
            func title() -> String { settings.navigationBars.firstMatch.exists ? settings.navigationBars.firstMatch.identifier : "" }
            for _ in 0..<3 where title() == before {
                row.tap()
                for _ in 0..<6 where title() == before { usleep(500_000) }
            }
        }
        if !(onPage.waitForExistence(timeout: 5) && toggle.waitForExistence(timeout: 5)) { print("SETTINGS-LABELS", labels(settings)) }
        XCTAssertTrue(onPage.exists && toggle.exists, "the LocalGateKeys AutoFill switch")
        for attempt in 0..<3 where !isOn() {
            // A bare switch is tapped in its middle; a whole row at its right end, where the switch sits.
            let wide = toggle.frame.width > 140
            toggle.coordinate(withNormalizedOffset: CGVector(dx: wide ? (attempt == 0 ? 0.9 : 0.86) : 0.5, dy: 0.5)).tap()
            // iOS may ask to confirm.
            let confirm = element(settings, "elementType == %d AND (label == 'Turn On' OR label == 'Continue' OR label == 'OK')",
                                  XCUIElement.ElementType.button.rawValue)
            if confirm.waitForExistence(timeout: 2) { confirm.tap() }
            for _ in 0..<4 where !isOn() { usleep(500_000) }
        }
        if !isOn() { print("SETTINGS-TOGGLE", toggle.elementType.rawValue, toggle.frame, String(describing: toggle.value)); print("SETTINGS-LABELS", labels(settings)) }
        XCTAssertTrue(isOn(), "LocalGateKeys AutoFill is on")
    }

    /// Taps the email field and picks the LocalGateKeys suggestion (the QuickType bar, else the list behind the
    /// keyboard's Passwords key). Face ID is matched from the Mac. Returns once the password field is filled.
    @MainActor
    func fillWithAutoFill() {
        let email = safari.textFields["Email"].firstMatch
        XCTAssertTrue(email.waitForExistence(timeout: 5))
        email.tap()
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let pw = safari.secureTextFields["Password"].firstMatch
        func filled() -> Bool { ((pw.value as? String) ?? "").contains("•") }
        var picked = false
        for app in [safari, springboard] where !picked {
            let suggestion = app.descendants(matching: .any)
                .matching(NSPredicate(format: "label CONTAINS %@ AND (elementType == %d OR elementType == %d OR elementType == %d)",
                                      Self.user, XCUIElement.ElementType.button.rawValue,
                                      XCUIElement.ElementType.key.rawValue, XCUIElement.ElementType.other.rawValue)).firstMatch
            if suggestion.waitForExistence(timeout: 5) { suggestion.tap(); picked = true; print("FILL-PATH quicktype") }
        }
        if !picked {
            // The list: the keyboard's Passwords key, then LocalGateKeys, then the row.
            let key = element(safari, "label == 'Passwords' OR label == 'AutoFill Password' OR label == 'Passwords…'")
            if !key.waitForExistence(timeout: 3) { print("SF-LABELS", labels(safari)); print("SB-LABELS", labels(springboard)) }
            XCTAssertTrue(key.exists, "an AutoFill suggestion or the Passwords key")
            key.tap()
            let provider = element(safari, "label BEGINSWITH 'LocalGateKeys'")
            if provider.waitForExistence(timeout: 3) { provider.tap() }
            print("FILL-PATH list")
        }
        // The extension's own list (several matches, or the list path): pick the row.
        let row = element(safari, "label CONTAINS %@ AND elementType == %d", Self.user, XCUIElement.ElementType.cell.rawValue)
        // The list is drawn by the extension's own process: Safari's hierarchy does not hold its rows (seen on iOS 27),
        // so the only row (the one saved login for this page) is tapped by position, at most every 3 seconds.
        for i in 0..<40 where !filled() {
            if row.exists, row.isHittable { row.tap() }
            else if !picked, i % 6 == 4, !email.isHittable || !safari.keyboards.firstMatch.exists {
                safari.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.197)).tap()
            }
            usleep(500_000)
        }
        if !filled() { shot("not-filled"); print("SF-LABELS", labels(safari)); print("SB-LABELS", labels(springboard)) }
        XCTAssertTrue(filled(), "AutoFill filled the password")
    }
}
