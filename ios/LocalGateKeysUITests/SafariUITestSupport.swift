import XCTest

/// Shared by the Safari Web Extension UI tests (`SafariShieldUITests`, `SafariToolbarUITests`), run through
/// `scripts/ios_simulator_checks.sh`: it matches Face ID from the Mac while they wait and serves
/// `scripts/safari_test_page/` over HTTPS (a throwaway CA only the simulator trusts) on 127.0.0.1, port
/// `LGK_SAFARI_PORT` (default 8765). The app is unlocked on the demo vault, which then also saves a login for
/// `https://loginlab.localhost:<port>` (`LGK_DEMO_LOCAL_SITE`, `LGK_DEMO_LOCAL_PORT`).
class SafariExtensionUITestCase: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LGK_FACEID_LOOP"] == "1",
                          "run through scripts/ios_simulator_checks.sh")
    }

    /// The port the script serves the test page on.
    var port: Int {
        Int(ProcessInfo.processInfo.environment["LGK_SAFARI_PORT"] ?? "").flatMap { (1...65535).contains($0) ? $0 : nil } ?? 8765
    }

    /// `https://<host>:<port>/login.html`.
    func page(_ host: String = "loginlab.localhost") -> String { "https://\(host):\(port)/login.html" }

    @MainActor var safari: XCUIApplication { XCUIApplication(bundleIdentifier: "com.apple.mobilesafari") }

    @MainActor
    func shot(_ name: String) {
        let a = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        a.name = name; a.lifetime = .keepAlways
        add(a)
    }

    @MainActor
    func element(_ app: XCUIApplication, _ format: String, _ args: Any...) -> XCUIElement {
        app.descendants(matching: .any).matching(NSPredicate(format: format, argumentArray: args)).firstMatch
    }

    /// Every non-empty label under `app`, for a failure's log.
    @MainActor
    func labels(_ app: XCUIApplication) -> [String] {
        guard let s = try? app.snapshot() else { return [] }
        var out: [String] = []
        func walk(_ e: XCUIElementSnapshot) {
            if !e.label.isEmpty { out.append("\(e.elementType.rawValue):\(e.label)") }
            e.children.forEach(walk)
        }
        walk(s)
        return out
    }

    /// Launches the app on the demo vault with the local test login and waits for the unlock (Face ID from the
    /// Mac), so it publishes the Safari site list. Returns the app.
    /// `slim`: a vault under the free limit (`LGK_DEMO_SLIM`): the extension never sees `LGK_DEBUG_PRO`, so in the
    /// full demo vault a new login gets the "full" prompt, which has no Save button.
    @MainActor @discardableResult
    func unlockApp(slim: Bool = false) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments += ["-LGKDemoData", "YES", "-LGKScreen", "item"]
        app.launchEnvironment["LGK_DEBUG_PRO"] = "1"        // the demo vault is over the free limit
        if slim { app.launchEnvironment["LGK_DEMO_SLIM"] = "1" }
        app.launchEnvironment["LGK_DEMO_LOCAL_SITE"] = "1"
        app.launchEnvironment["LGK_DEMO_LOCAL_PORT"] = String(port)
        app.launch()
        // Unlocked: the demo item, or the "Save from Safari?" sheet over it when Safari saved logins meanwhile.
        XCTAssertTrue(element(app, "label == 'Username' OR (elementType == %d AND identifier == 'Save from Safari?')",
                              XCUIElement.ElementType.navigationBar.rawValue).waitForExistence(timeout: 60),
                      "unlocked (Face ID from the Mac)")
        return app
    }

    /// Settings › Apps › Safari › Extensions › LocalGateKeys › Allow Extension.
    @MainActor
    func allowExtension() {
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.terminate()
        settings.launch()
        let toggle = settings.switches["Allow Extension"]
        // Settings may reopen where it was left; walk the rows only until the switch shows.
        for name in ["Apps", "Safari", "Extensions", "LocalGateKeys"] where !toggle.waitForExistence(timeout: 1) {
            // The extension's row reads "LocalGateKeys, On" or "LocalGateKeys, Off".
            let row = element(settings, "(label == %@ OR label BEGINSWITH %@) AND (elementType == %d OR elementType == %d)",
                              name, name + ", ",
                              XCUIElement.ElementType.cell.rawValue, XCUIElement.ElementType.button.rawValue)
            if !row.exists, settings.navigationBars.buttons.firstMatch.exists, name == "Apps" {
                // Somewhere else in Settings: go back to the top first.
                for _ in 0..<5 where settings.navigationBars.buttons.firstMatch.exists { settings.navigationBars.buttons.firstMatch.tap() }
            }
            // Scrolled from the left margin, outside the rows: a swipe over a row can land as a tap on it while
            // Settings is busy (seen on iOS 27: Safari › Search Engine opened instead).
            // iOS 27's floating "Search Apps" bar covers the bottom of the list: a row is only tapped above it.
            // By frame, not isHittable, which fails the test outright while the page still slides in.
            func reachable() -> Bool {
                guard row.exists else { return false }
                let f = row.frame, h = settings.frame.height
                return !f.isEmpty && f.minY > h * 0.1 && f.maxY < h * 0.78
            }
            for _ in 0..<8 where !reachable() {
                let from = settings.coordinate(withNormalizedOffset: CGVector(dx: 0.02, dy: 0.8))
                from.press(forDuration: 0.05, thenDragTo: settings.coordinate(withNormalizedOffset: CGVector(dx: 0.02, dy: 0.35)))
            }
            XCTAssertTrue(row.exists, "Settings row \(name)")
            // A tap while the list still glides after the scroll can be lost: tap again until the row's page opens.
            // (The page's title changes; the row itself may live on as the next page's back button.)
            func title() -> String { let bar = settings.navigationBars.firstMatch; return bar.exists ? bar.identifier : "" }
            let page = title()
            for _ in 0..<3 where title() == page {
                usleep(700_000)                         // let the list and any page slide settle
                row.tap()
                for _ in 0..<6 where title() == page { usleep(500_000) }
            }
        }
        XCTAssertTrue(toggle.waitForExistence(timeout: 5))
        // A tap right after the page slides in can be lost (seen on iOS 27): try again, on the switch itself.
        for attempt in 0..<3 where (toggle.value as? String) != "1" {
            if attempt == 0 { toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.92, dy: 0.5)).tap() } else { toggle.switches.firstMatch.exists ? toggle.switches.firstMatch.tap() : toggle.tap() }
            for _ in 0..<4 where (toggle.value as? String) != "1" { usleep(500_000) }
        }
        XCTAssertEqual(toggle.value as? String, "1", "the extension is allowed")
    }

    /// Safari's Page Menu, opened (the "≡" button of the compact bar).
    @MainActor
    func openPageMenu() {
        let menu = element(safari, "label == 'Page Menu'")
        if !menu.exists { dismissSafariFillPassword() }
        if !menu.exists, safari.keyboards.firstMatch.exists { element(safari, "label == 'Login lab'").tap() }
        XCTAssertTrue(menu.waitForExistence(timeout: 5), "Safari's Page Menu button")
        menu.tap()
    }

    /// Opens `url` in Safari and (with `grant`) gives the extension access to that site when Safari asks. When access
    /// was already given, the Page Menu's LocalGateKeys item opens the toolbar popup instead; it is closed again.
    /// Without `grant` the page is only loaded (afresh: a reload when it is already open).
    @MainActor
    func open(_ url: String, grant: Bool = true) {
        XCUIDevice.shared.system.open(URL(string: url)!)
        XCTAssertTrue(safari.wait(for: .runningForeground, timeout: 10))
        let title = element(safari, "label == 'Login lab'")
        if !title.waitForExistence(timeout: 15) {
            // Safari freshly launched can stay blank for a while (seen on iOS 27): ask for the page once more.
            XCUIDevice.shared.system.open(URL(string: url)!)
        }
        XCTAssertTrue(title.waitForExistence(timeout: 30), "the test page loaded: \(url)")
        guard grant else { reload(url); return }
        openPageMenu()
        let ext = element(safari, "label == 'LocalGateKeys'")
        XCTAssertTrue(ext.waitForExistence(timeout: 5), "LocalGateKeys in the Page Menu")
        ext.tap()
        let always = element(safari, "label BEGINSWITH 'Always Allow'")
        if always.waitForExistence(timeout: 3) {
            always.tap()
            let site = element(safari, "label CONTAINS[c] 'This Website' OR label CONTAINS[c] 'Every Website'")
            if site.waitForExistence(timeout: 3) { site.tap() }
            // The content script starts on the next load. iOS 27's Safari has no "Reload" identifier on its compact
            // bar: a reload button by label, else the same address opened again.
            reload(url)
        } else {
            // Already allowed: the toolbar popup opened instead. Saving must be on for the site: a run that stopped
            // with the popup's switch off (SafariToolbarUITests step 3) leaves the origin in the extension's
            // automatic_save_blocked_origins, and every later run on that port then gets no capture at all.
            ensureSavingOn()
            closePopup()
            reload(url)
        }
    }

    /// In the open toolbar popup: turns "Offer to save logins on this site" on if it is off. The switch shows only
    /// once the background page answers, which after a cold Safari launch can take half a minute on the simulator.
    @MainActor
    func ensureSavingOn() {
        let label = "Offer to save logins on this site"
        func toggle() -> XCUIElement {
            let named = element(safari, "label CONTAINS %@ AND (elementType == %d OR elementType == %d)", label,
                                XCUIElement.ElementType.switch.rawValue, XCUIElement.ElementType.checkBox.rawValue)
            return named.exists ? named : safari.switches.firstMatch
        }
        func on() -> Bool? {
            let s = toggle()
            guard s.exists else { return nil }
            if let n = s.value as? NSNumber { return n.boolValue }
            return ["1", "on", "true", "checked"].contains(((s.value as? String) ?? "").lowercased())
        }
        guard toggle().waitForExistence(timeout: 30) else { print("SF-NO-SWITCH", labels(safari)); return }
        guard on() == false else { return }
        print("SF-SAVING-WAS-OFF: turning saving back on for the site")
        sleep(1)                                        // the sheet can still be settling
        toggle().coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
        for _ in 0..<10 where on() != true { usleep(500_000) }
        XCTAssertEqual(on(), true, "saving turned back on for the site")
    }

    /// Loads the page afresh, so the content script starts on a clean page with its form. iOS 27's Safari has no
    /// "Reload" identifier on its compact bar: a reload button by label, else the same address opened again.
    @MainActor
    func reload(_ url: String) {
        let reload = safari.buttons.matching(NSPredicate(format: "identifier == 'Reload' OR label BEGINSWITH[c] 'Reload'")).firstMatch
        if reload.waitForExistence(timeout: 2) { reload.tap() } else { XCUIDevice.shared.system.open(URL(string: url)!) }
        XCTAssertTrue(element(safari, "label == 'Login lab'").waitForExistence(timeout: 15), "the page loaded again")
        XCTAssertTrue(safari.textFields["Email"].firstMatch.waitForExistence(timeout: 10), "the sign-in form")
        sleep(1)                                        // the content script starts after the load
    }

    /// Closes the extension's toolbar popup (a sheet on iPhone) or any other extension sheet, if one is open.
    /// Waits until it is gone, its dimming layer (`PopoverDismissRegion`) included: a tap on the page while that layer
    /// is still there only closes it, and the form never submits.
    @MainActor
    func closePopup() {
        let done = safari.buttons["Done"]
        let dismiss = safari.descendants(matching: .any).matching(identifier: "PopoverDismissRegion").firstMatch
        if done.waitForExistence(timeout: 2) {
            done.tap()
        } else if safari.buttons["Close"].exists {
            safari.buttons["Close"].tap()
        } else if dismiss.exists {
            dismiss.tap()
        }
        if !dismiss.waitForNonExistence(timeout: 5), dismiss.exists { dismiss.tap() }
        XCTAssertTrue(dismiss.waitForNonExistence(timeout: 5), "the extension sheet closed")
        XCTAssertTrue(done.waitForNonExistence(timeout: 2), "the extension sheet closed")
    }

    @MainActor
    func signIn(_ user: String, _ password: String) {
        let email = safari.textFields["Email"].firstMatch
        XCTAssertTrue(email.waitForExistence(timeout: 5))
        // A few keys at a time: the simulator's keyboard drops keys of a long typeText while Safari is busy (seen on
        // iOS 27: "tool" left of a whole address). Typed again when the field still does not read the address.
        func typeSlowly(_ text: String) {
            var rest = Substring(text)
            while !rest.isEmpty { email.typeText(String(rest.prefix(3))); rest = rest.dropFirst(3) }
        }
        email.tap()
        if element(safari, "label == 'Fill Password'").exists { dismissSafariFillPassword(); email.tap() }
        typeSlowly(user)
        for _ in 0..<2 where (email.value as? String) != user {
            let typed = (email.value as? String) ?? ""
            email.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: typed.count + 2))
            typeSlowly(user)
        }
        XCTAssertEqual(email.value as? String, user, "the email typed in full")
        let pw = safari.secureTextFields["Password"].firstMatch
        pw.tap(); pw.typeText(password)
        element(safari, "label == 'Sign in' AND elementType == %d", XCUIElement.ElementType.button.rawValue).tap()
    }

    /// Safari's own "Save Password?" sheet (iOS Passwords, not LocalGateKeys), answered "Not Now" when it shows, so it
    /// neither covers the extension's prompt nor gets tapped in its place.
    @MainActor
    func dismissSafariSavePassword() {
        let sheet = element(safari, "label == 'Save Password?'")
        guard sheet.waitForExistence(timeout: 2) else { return }
        print("SF-SAFARI-SAVE-PASSWORD-SHEET")
        shot("safari-save-password-sheet")
        let notNow = safari.buttons.matching(NSPredicate(format: "label == 'Not Now'")).firstMatch
        if notNow.exists { notNow.tap() }
        _ = sheet.waitForNonExistence(timeout: 5)
    }

    /// Safari's own "Sign In ... Fill Password" sheet (a login saved in iOS Passwords for the test site, e.g. by a
    /// run that tapped "Save" on the "Save Password?" sheet), closed when it shows: it covers the compact bar and
    /// its Page Menu button.
    @MainActor
    func dismissSafariFillPassword() {
        let fill = element(safari, "label == 'Fill Password'")
        guard fill.waitForExistence(timeout: 2) else { return }
        print("SF-SAFARI-FILL-PASSWORD-SHEET")
        shot("safari-fill-password-sheet")
        let close = safari.buttons.matching(NSPredicate(format: "label IN {'Close', 'Dismiss', 'Cancel', 'Not Now'} OR identifier IN {'Close', 'close'}")).firstMatch
        if close.exists { close.tap() } else { print("SF-FILL-SHEET-LABELS", labels(safari)) }
        _ = fill.waitForNonExistence(timeout: 5)
    }

    /// The extension's save prompt ("Save this login?", or the update wording).
    @MainActor
    var savePrompt: XCUIElement {
        element(safari, "label CONTAINS 'Save this login?' OR label CONTAINS 'Save / update in LocalGateKeys?'")
    }
}
