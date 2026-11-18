import XCTest

/// Sub-plan 09 task 5b (Safari phishing shield) on the iPhone simulator, against the local page in
/// `scripts/safari_test_page/` that `scripts/ios_simulator_checks.sh` serves on 127.0.0.1 (port `LGK_SAFARI_PORT`,
/// default 8765). The demo vault saves a login for `https://loginlab.localhost:<port>` (`LGK_DEMO_LOCAL_SITE`); `1oginlab.localhost` is a lookalike
/// of it (1 for l). On the iPhone the extension shows no field icons (`features:{fill:false}`), so the shield shows in
/// the submit path: the saved site gets the save prompt, the lookalike the "Is this the right site?" guard first.
final class SafariShieldUITests: SafariExtensionUITestCase {
    @MainActor
    func testSavedSiteGetsTheSavePromptAndALookalikeIsGuarded() throws {
        unlockApp()
        allowExtension()

        open(page())
        signIn("new.tester@example.com", "demo-Lab-orbit-1")
        let saveTitle = savePrompt
        let prompted = saveTitle.waitForExistence(timeout: 10)
        if !prompted {
            shot("no-save-prompt")
            print("SF-LABELS", labels(safari))
        }
        XCTAssertTrue(prompted, "the saved site gets the save prompt")
        XCTAssertFalse(element(safari, "label == 'Is this the right site?'").exists, "no guard on the saved site")
        shot("saved-site-save-prompt")

        open(page("1oginlab.localhost"))
        signIn("tester@example.com", "demo-Lab-orbit-2")
        let guardTitle = element(safari, "label CONTAINS 'Is this the right site?'")
        if !guardTitle.waitForExistence(timeout: 10) {
            // The first tap can land before the content script has started on this load: submit once more.
            element(safari, "label == 'Sign in' AND elementType == %d", XCUIElement.ElementType.button.rawValue).tap()
        }
        XCTAssertTrue(guardTitle.waitForExistence(timeout: 10), "the lookalike gets the guard")
        XCTAssertTrue(element(safari, "label == 'Go back'").exists, "Go back is offered")
        // The saved site is named only inside the extension's own frame; a panel drawn in the page shows "•••"
        // instead, so the page cannot read which sites are saved (audit fix dc6e93dc2).
        XCTAssertTrue(element(safari, "label CONTAINS 'loginlab.localhost' OR label CONTAINS 'looks like •••'").exists,
                      "the guard names the saved site, or masks it when drawn in the page")
        shot("lookalike-guard")
    }
}
