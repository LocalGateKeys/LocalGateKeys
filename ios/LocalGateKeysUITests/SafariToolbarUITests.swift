import XCTest

/// The Safari extension's toolbar button and popup on the iPhone (manifest `action`, `popup-safari.html`), end to
/// end on the local test page (`SafariExtensionUITestCase`). After a login is saved from Safari, the popup shows the
/// site, the "Fill this sign-in" hint, "1 login waiting to review" and the per-site switch "Offer to save logins on
/// this site" (on), and no "Open LocalGateKeys" button (Mac only). Off, a sign-in gets no save prompt; on again, it
/// does. The app's unlock then asks "Save from Safari?"; "Decide later" keeps the login waiting, so the popup
/// still counts it.
final class SafariToolbarUITests: SafariExtensionUITestCase {
    private let popupHint = "Fill this sign-in"
    private let switchLabel = "Offer to save logins on this site"

    /// Opens the popup from the Page Menu (Safari on iPhone has no toolbar of extension buttons), granting the
    /// site when Safari asks first, and waits for its content.
    @MainActor
    private func openPopup(_ step: String) {
        openPageMenu()
        let ext = element(safari, "label == 'LocalGateKeys'")
        XCTAssertTrue(ext.waitForExistence(timeout: 5), "LocalGateKeys in the Page Menu")
        ext.tap()
        let always = element(safari, "label BEGINSWITH 'Always Allow'")
        if always.waitForExistence(timeout: 2) {
            always.tap()
            let site = element(safari, "label CONTAINS[c] 'This Website'")
            if site.waitForExistence(timeout: 3) { site.tap() }
        }
        // The hint, or the switch once the background page answers (the popup may show a loading state first).
        let hint = element(safari, "label == %@ OR label CONTAINS %@", popupHint, switchLabel)
        if !hint.waitForExistence(timeout: 10) {
            shot("\(step)-no-popup")
            print("SF-LABELS", labels(safari))
            XCTFail("the toolbar popup opened (\(step))")
        }
        sleep(1)                                        // the count and the switch come from the background page
    }

    /// The popup's `<input role="switch">`: a switch (or checkbox) named by its row's label, else the only switch on
    /// screen (the page itself has none).
    @MainActor private var offerSwitch: XCUIElement {
        let named = element(safari, "label CONTAINS %@ AND (elementType == %d OR elementType == %d)", switchLabel,
                            XCUIElement.ElementType.switch.rawValue, XCUIElement.ElementType.checkBox.rawValue)
        return named.exists ? named : safari.switches.firstMatch
    }

    private func isOn(_ value: Any?) -> Bool {
        if let n = value as? NSNumber { return n.boolValue }
        return ["1", "on", "true", "checked"].contains(((value as? String) ?? "").lowercased())
    }

    @MainActor
    private func switchIsOn() -> Bool? {
        let s = offerSwitch
        guard s.waitForExistence(timeout: 30) else { print("SF-NO-SWITCH", labels(safari)); return nil }
        return isOn(s.value)
    }

    /// The popup as it shows now: the site, the hint, the count, the switch, and no Mac-only button.
    @MainActor
    private func checkPopup(waiting: Int, switchOn: Bool, _ step: String) {
        shot(step)
        print("SF-POPUP", step, labels(safari))
        XCTAssertTrue(element(safari, "label == 'loginlab.localhost'").exists, "the popup names the tab's site")
        XCTAssertTrue(element(safari, "label == %@", popupHint).exists, "the fill hint")
        // "1 login waiting to review", "N logins waiting to review": matched by its words and its leading number,
        // so wording around it (a loading state) may change.
        let row = element(safari, "label CONTAINS[c] 'waiting to review'")
        if waiting == 0 {
            XCTAssertFalse(row.waitForExistence(timeout: 3), "no waiting row with an empty inbox")
        } else {
            var shown: Int?
            for _ in 0..<10 {
                if row.exists, let n = Int(row.label.prefix(while: \.isNumber)) { shown = n; if n == waiting { break } }
                usleep(500_000)
            }
            XCTAssertEqual(shown, waiting, "the waiting row counts \(waiting)")
        }
        XCTAssertFalse(element(safari, "label == 'Open LocalGateKeys'").exists, "no Open LocalGateKeys button on iPhone")
        XCTAssertEqual(switchIsOn(), switchOn, "the per-site switch")
    }

    @MainActor
    private func setSwitch(_ on: Bool) {
        let s = offerSwitch
        XCTAssertTrue(s.waitForExistence(timeout: 5))
        // By coordinate: the sheet can still be settling, and XCUITest then calls the switch not hittable.
        if isOn(s.value) != on { sleep(1); offerSwitch.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap() }
        for _ in 0..<10 where isOn(offerSwitch.value) != on { usleep(500_000) }
        XCTAssertEqual(isOn(offerSwitch.value), on, "the switch turned \(on ? "on" : "off")")
    }

    /// The app's "Save from Safari?" sheet, answered: `later` keeps the logins waiting, otherwise all are
    /// deselected and deleted (a clean inbox before the test). False when the sheet did not show.
    @MainActor @discardableResult
    private func answerReview(_ app: XCUIApplication, later: Bool, timeout: TimeInterval) -> Bool {
        let title = app.navigationBars["Save from Safari?"]
        guard title.waitForExistence(timeout: timeout) else { return false }
        shot(later ? "app-review-sheet" : "app-review-sheet-before-test")
        if later {
            title.buttons["Decide later"].tap()
        } else {
            // Every row starts selected and the confirm button reads "Save N"; with none selected it reads
            // "Delete all". Each row is one button whose label joins site, username and "New login · <origin>"
            // (the selection shows only as a "Selected" child, not as the button's selected state): tap each row
            // once (the list scrolls to it), then check the button reads "Delete all".
            let confirm = title.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Save ' OR label == 'Delete all'")).firstMatch
            XCTAssertTrue(confirm.waitForExistence(timeout: 3), "the review sheet's confirm button")
            let rows = app.buttons.matching(NSPredicate(format: "label CONTAINS ' · '"))
            let total = Int(confirm.label.dropFirst("Save ".count)) ?? 0
            for i in 0..<min(total, 60) where confirm.label != "Delete all" {
                let row = rows.element(boundBy: i)
                guard row.exists else { break }
                row.tap()
            }
            print("SF-REVIEW-CLEANUP", confirm.label)
            if confirm.label == "Delete all" {
                confirm.tap()
            } else {
                print("SF-REVIEW-LABELS", labels(app))
                XCTFail("could not deselect every login in Save from Safari? (\(confirm.label))")
                title.buttons["Decide later"].tap()
            }
        }
        XCTAssertTrue(title.waitForNonExistence(timeout: 5), "the review sheet closed")
        return true
    }

    @MainActor
    func testToolbarPopupCountsWaitingLoginsAndTurnsSavingOffPerSite() throws {
        let stamp = Int(Date().timeIntervalSince1970) % 1_000_000
        // A clean inbox: what earlier runs left is deleted at this unlock.
        let app = unlockApp(slim: true)
        answerReview(app, later: false, timeout: 5)
        allowExtension()

        // 1. A new login, saved from the prompt.
        open(page())
        signIn("tb\(stamp)@example.com", "demo-Toolbar-orbit-1")
        XCTAssertTrue(savePrompt.waitForExistence(timeout: 20), "the save prompt for a new login")
        shot("1-save-prompt")
        // The in-page prompt's buttons: "Save login", "Not now", "Never on this site".
        // Only "Save login": Safari's own "Save Password?" sheet can show at the same time and has a plain "Save"
        // button that saves to Passwords instead (seen on iOS 27). That sheet is answered "Not Now" first.
        dismissSafariSavePassword()
        let save = element(safari, "label == 'Save login' AND elementType == %d", XCUIElement.ElementType.button.rawValue)
        XCTAssertTrue(save.waitForExistence(timeout: 5), "the prompt's Save login button")
        save.tap()
        XCTAssertTrue(element(safari, "label BEGINSWITH 'Saved' OR label CONTAINS 'next time you open it'").waitForExistence(timeout: 10),
                      "the saved notice")
        shot("1-saved-notice")

        // 2. The popup: site, hint, 1 waiting, switch on, no Open button.
        openPopup("2-popup")
        checkPopup(waiting: 1, switchOn: true, "2-popup-one-waiting")

        // 3. Off for this site: a sign-in gets no prompt.
        setSwitch(false)
        shot("3-popup-switch-off")
        closePopup()
        open(page(), grant: false)
        signIn("tb.off\(stamp)@example.com", "demo-Toolbar-orbit-2")
        XCTAssertTrue(element(safari, "label == 'Signed in'").waitForExistence(timeout: 5), "the page signed in")
        XCTAssertFalse(savePrompt.waitForExistence(timeout: 15), "no save prompt while saving is off for the site")
        shot("3-no-prompt-when-off")
        // With LocalGateKeys silent, Safari's own "Save Password?" sheet is left on screen; while it shows, Safari
        // never reports its animations complete and every later step waits 60 s (seen on iOS 27).
        dismissSafariSavePassword()

        // 4. On again: still on after reopening, and the prompt is back ("Not now", so 1 stays waiting).
        openPopup("4-popup")
        XCTAssertEqual(switchIsOn(), false, "the switch stayed off")
        setSwitch(true)
        closePopup()
        openPopup("4-popup-reopened")
        checkPopup(waiting: 1, switchOn: true, "4-popup-switch-on-again")
        closePopup()
        open(page(), grant: false)
        signIn("tb.on\(stamp)@example.com", "demo-Toolbar-orbit-3")
        XCTAssertTrue(savePrompt.waitForExistence(timeout: 20), "the save prompt is back")
        shot("4-prompt-back")
        dismissSafariSavePassword()                     // its "Not Now" differs from the prompt's "Not now" by case only
        let notNow = element(safari, "label == 'Not now' AND elementType == %d", XCUIElement.ElementType.button.rawValue)
        if notNow.waitForExistence(timeout: 3) { notNow.tap() } else { print("SF-NO-NOTNOW", labels(safari)) }

        // 5. The app asks at its unlock; "Decide later" keeps the login waiting.
        let again = unlockApp(slim: true)
        XCTAssertTrue(answerReview(again, later: true, timeout: 15), "the app asks Save from Safari?")
        XCUIDevice.shared.system.open(URL(string: page())!)
        XCTAssertTrue(safari.wait(for: .runningForeground, timeout: 10))
        XCTAssertTrue(element(safari, "label == 'Login lab'").waitForExistence(timeout: 15))
        openPopup("5-popup")
        checkPopup(waiting: 1, switchOn: true, "5-popup-after-decide-later")
        closePopup()
    }
}
