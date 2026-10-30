import XCTest
import AppKit
import LGKCore
@testable import AppSharedMac

/// A clock the test moves by hand.
private final class StepClock: UnixClock, @unchecked Sendable {
    var now: Int64 = 1_000
}

@MainActor
final class MacClipboardTests: XCTestCase {
    private var pasteboard: NSPasteboard!

    override func setUp() async throws {
        // A private named pasteboard: the tests never touch the general one.
        pasteboard = NSPasteboard(name: NSPasteboard.Name("app.localgatekeys.tests.\(UUID().uuidString)"))
    }

    override func tearDown() async throws {
        pasteboard.releaseGlobally()
    }

    func testCopyMarksConcealed() {
        let clip = MacClipboard(pasteboard: pasteboard, clock: StepClock(), clearAfter: 30)
        clip.copy("hunter2-secret", concealed: true)
        XCTAssertEqual(pasteboard.string(forType: .string), "hunter2-secret")
        XCTAssertTrue(pasteboard.types?.contains(MacClipboard.concealedType) == true)

        clip.copy("alex@example.com", concealed: false)
        XCTAssertEqual(pasteboard.string(forType: .string), "alex@example.com")
        XCTAssertFalse(pasteboard.types?.contains(MacClipboard.concealedType) == true)
    }

    func testClearsOnlyOwnCopy() {
        let clip = MacClipboard(pasteboard: pasteboard, clock: StepClock(), clearAfter: 30)
        clip.copy("hunter2-secret", concealed: true)
        // The person copies something else: locking must leave it alone.
        pasteboard.clearContents()
        pasteboard.setString("their own text", forType: .string)
        clip.clearIfOurs()
        XCTAssertEqual(pasteboard.string(forType: .string), "their own text")

        // Still ours: cleared.
        clip.copy("hunter2-secret", concealed: true)
        clip.clearIfOurs()
        XCTAssertNil(pasteboard.string(forType: .string))
    }

    func testClearAfterTimeout() {
        let clock = StepClock()
        let clip = MacClipboard(pasteboard: pasteboard, clock: clock, clearAfter: 30)
        clip.copy("hunter2-secret", concealed: true)
        clock.now += 29
        clip.clearIfExpired()
        XCTAssertEqual(pasteboard.string(forType: .string), "hunter2-secret", "not before the delay")
        clock.now += 1
        clip.clearIfExpired()
        XCTAssertNil(pasteboard.string(forType: .string))

        // Expired, but replaced by someone else in the meantime: untouched.
        clip.copy("hunter2-secret", concealed: true)
        pasteboard.clearContents()
        pasteboard.setString("later copy", forType: .string)
        clock.now += 60
        clip.clearIfExpired()
        XCTAssertEqual(pasteboard.string(forType: .string), "later copy")
    }

    func testTimerClearsForReal() async throws {
        let clip = MacClipboard(pasteboard: pasteboard, clock: SystemClock(), clearAfter: 0.2)
        clip.copy("hunter2-secret", concealed: true)
        try await Task.sleep(for: .milliseconds(600))
        XCTAssertNil(pasteboard.string(forType: .string))
    }
}
