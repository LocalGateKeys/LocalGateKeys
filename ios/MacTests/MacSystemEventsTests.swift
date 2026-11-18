import AppKit
import XCTest
import LGKCore
@testable import AppSharedMac

/// docs/PENDING.md section 4 (review fixes 2026-11-15), the parts that cannot be run by automation on this Mac: fast
/// user switching needs a second account, and a Greek input source would change the owner's keyboard settings. These
/// drive the real `MacSystemEvents` with the notifications macOS posts, and the real key path with Greek key events.
@MainActor
final class MacSystemEventsTests: XCTestCase {
    private var dir: URL!
    private var suite: String!
    private var settings: AppSettings!
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-events-\(UUID().uuidString)", isDirectory: true)
        suite = "lgk-events-tests-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        UserDefaults().removePersistentDomain(forName: suite)
    }

    private func unlocked(_ events: MacSystemEvents) async -> MacLockModel {
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(), kdfParams: cheap)
        let m = MacLockModel(vault: vault, settings: settings, events: events, startTimer: false)
        await m.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertEqual(m.state, .unlocked)
        return m
    }

    private func waitForLock(_ m: MacLockModel) async {
        for _ in 0..<200 where m.state != .locked { try? await Task.sleep(for: .milliseconds(10)) }
    }

    /// Fast user switching: macOS posts `sessionDidResignActiveNotification` on the workspace centre when this
    /// session is switched away from.
    func testFastUserSwitchLocks() async {
        let events = MacSystemEvents()
        let m = await unlocked(events)
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.sessionDidResignActiveNotification, object: NSWorkspace.shared)
        await waitForLock(m)
        XCTAssertEqual(m.state, .locked)
    }

    func testDisplaySleepLocks() async {
        let events = MacSystemEvents()
        let m = await unlocked(events)
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.screensDidSleepNotification, object: NSWorkspace.shared)
        await waitForLock(m)
        XCTAssertEqual(m.state, .locked)
    }

    /// The same events with "Lock when the screen locks" off leave the vault open.
    func testSwitchAndDisplaySleepIgnoredWhenSettingOff() async {
        settings.lockOnScreenLock = false
        let events = MacSystemEvents()
        let m = await unlocked(events)
        for name in [NSWorkspace.sessionDidResignActiveNotification, NSWorkspace.screensDidSleepNotification] {
            NSWorkspace.shared.notificationCenter.post(name: name, object: NSWorkspace.shared)
        }
        try? await Task.sleep(for: .milliseconds(300))
        XCTAssertEqual(m.state, .unlocked)
    }

    /// ⌘C, ⇧⌘C and ⌘T as a Greek layout delivers them: the characters are Greek letters, the key codes are the
    /// physical C (8) and T (17) keys. The window's key monitor reads exactly these two properties.
    func testGreekKeyEventsMapToTheCopyShortcuts() throws {
        func event(_ chars: String, _ code: UInt16, _ flags: NSEvent.ModifierFlags) throws -> NSEvent {
            try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: flags, timestamp: 0, windowNumber: 0,
                                           context: nil, characters: chars, charactersIgnoringModifiers: chars,
                                           isARepeat: false, keyCode: code))
        }
        let cases: [(NSEvent, String)] = [
            (try event("ψ", 8, .command), "c"),
            (try event("Ψ", 8, [.command, .shift]), "c"),
            (try event("τ", 17, .command), "t"),
        ]
        for (e, want) in cases {
            XCTAssertEqual(MainWindow.shortcutKey(characters: e.charactersIgnoringModifiers, keyCode: e.keyCode), want)
        }
        // In a text field the system keeps ⌘C (copies the selected text) on a Greek layout too.
        XCTAssertFalse(CopyShortcutPolicy.intercepts(key: "c", shift: false, responder: .text, listShown: true))
        XCTAssertTrue(CopyShortcutPolicy.intercepts(key: "c", shift: true, responder: .itemList, listShown: true))
    }
}
