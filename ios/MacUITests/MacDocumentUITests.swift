import XCTest
import AppKit

/// docs/PENDING.md "open a document in Preview from the sandbox; the copy is deleted at lock and at quit", on a real
/// throwaway vault with a seeded PDF document (`LGK_MAC_SEED_DOCUMENT`, Debug builds only). Preview is closed after;
/// when Preview was already running (the person's own documents), the test is skipped rather than touching it.
final class MacDocumentUITests: MacRealVaultUITestCase {
    private let fileName = "lgk-uitest-doc.pdf"
    private var title: String { (fileName as NSString).deletingPathExtension }
    private let previewID = "com.apple.Preview"

    /// `MacDocumentOpen.directory` inside the app's container.
    private var copiesDir: URL {
        vaultDir.deletingLastPathComponent().appendingPathComponent("LocalGateKeys opened documents", isDirectory: true)
    }

    /// The opened copies (`<random>/<name>`), nil when the runner cannot read the folder.
    private func copies() -> [String] {
        guard let e = FileManager.default.enumerator(atPath: copiesDir.path) else { return [] }
        return ((e.allObjects as? [String]) ?? []).filter { $0.hasSuffix(fileName) }
    }

    private func previewRunning() -> Bool { !NSRunningApplication.runningApplications(withBundleIdentifier: previewID).isEmpty }

    private func closePreview() {
        let preview = XCUIApplication(bundleIdentifier: previewID)
        if preview.state != .notRunning { preview.terminate() }
    }

    override func setUpWithError() throws {
        try super.setUpWithError()
        try XCTSkipIf(previewRunning(), "Preview is already open: quit it first (the test closes Preview afterwards)")
    }

    override func tearDown() {
        closePreview()
        super.tearDown()
    }

    /// Opens the seeded document from its detail panel: the warning, the copy, Preview.
    @MainActor
    private func openDocument(_ app: XCUIApplication) {
        let row = app.descendants(matching: .any).matching(NSPredicate(format: "label == %@ OR value == %@", title, title)).firstMatch
        if !row.waitForExistence(timeout: 10) { print("MAC-CHECK window texts:", texts(app)) }
        XCTAssertTrue(row.exists, "seeded document in the list")
        row.click()
        let open = app.buttons["Open"].firstMatch
        XCTAssertTrue(open.waitForExistence(timeout: 10), "Open button in the detail panel")
        open.click()
        // The setting may be off (left so by an earlier run): turn it on from the alert.
        let turnOn = app.buttons["Turn on and open"].firstMatch
        if turnOn.waitForExistence(timeout: 3) { turnOn.click() }
        // First copy: the one-time warning (an alert with its own Open button).
        // (Its default button is Open: Return answers it.)
        if app.staticTexts["Open a decrypted copy?"].firstMatch.waitForExistence(timeout: 6) {
            app.typeKey(.return, modifierFlags: [])
        }
        // The routine gate, when the unlock's grace has passed: the master password.
        let gate = app.secureTextFields.firstMatch
        if gate.waitForExistence(timeout: 2), gate.isHittable {
            gate.click(); gate.typeText(Self.master + "\r")
        }
    }

    @MainActor
    private func waitFor(_ what: String, timeout: TimeInterval = 15, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline { if condition() { return true }; usleep(300_000) }
        print("MAC-CHECK timed out waiting for", what)
        return condition()
    }

    @MainActor
    func testOpenedCopyGoesAtLockAndAtQuit() throws {
        let env = ["LGK_MAC_SEED_DOCUMENT": fileName, "LGK_MAC_SELECT": title]
        let app = launch(env)
        createVault(app)
        continueAfterFailure = true
        openDocument(app)
        XCTAssertTrue(waitFor("Preview") { previewRunning() }, "Preview launched")
        if !previewRunning() { print("MAC-CHECK texts after Open:", texts(app)); shot(app, "after-open") }
        XCTAssertTrue(waitFor("the copy") { !copies().isEmpty }, "the decrypted copy exists in the app's temporary folder")
        print("MAC-CHECK copies dir:", copiesDir.path, "readable:", FileManager.default.isReadableFile(atPath: copiesDir.deletingLastPathComponent().path),
              "copies:", copies())
        let preview = XCUIApplication(bundleIdentifier: previewID)
        XCTAssertTrue(waitFor("Preview window") { preview.windows.allElementsBoundByIndex.contains { $0.title.contains(title) } },
                      "Preview shows \(fileName)")
        shot(app, "document-opened")

        // Lock: the copy goes.
        app.activate()
        app.typeKey("l", modifierFlags: .command)
        XCTAssertTrue(app.secureTextFields["Master password"].waitForExistence(timeout: 10), "locked")
        XCTAssertTrue(waitFor("lock sweep") { copies().isEmpty }, "the copy is deleted when the vault locks")
        closePreview()

        // Quit: unlock, open again, ⌘Q; the copy goes.
        let field = app.secureTextFields["Master password"].firstMatch
        field.click(); field.typeText(Self.master)
        app.buttons["Unlock"].click()
        XCTAssertTrue(app.buttons["Settings"].firstMatch.waitForExistence(timeout: 30))
        openDocument(app)
        XCTAssertTrue(waitFor("the copy again") { !copies().isEmpty }, "a new copy exists")
        XCTAssertTrue(waitFor("Preview again") { previewRunning() }, "Preview launched again")
        app.activate()
        app.typeKey("q", modifierFlags: .command)
        XCTAssertTrue(app.wait(for: .notRunning, timeout: 15), "the app quit")
        XCTAssertTrue(waitFor("quit sweep") { copies().isEmpty }, "the copy is deleted when the app quits")
        closePreview()
    }
}
