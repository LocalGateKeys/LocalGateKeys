import AppKit
import XCTest
@testable import AppSharedMac

/// Windows stay out of screenshots and screen sharing unless Settings › Privacy turns it off.
@MainActor
final class CaptureProtectionTests: XCTestCase {
    private var saved: Any?

    override func setUp() async throws {
        saved = UserDefaults.standard.object(forKey: CaptureProtection.key)
    }

    override func tearDown() async throws {
        if let saved { UserDefaults.standard.set(saved, forKey: CaptureProtection.key) }
        else { UserDefaults.standard.removeObject(forKey: CaptureProtection.key) }
    }

    private func window() -> NSWindow {
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 100, height: 100), styleMask: [.titled],
                         backing: .buffered, defer: true)
        w.isReleasedWhenClosed = false
        w.orderBack(nil)
        addTeardownBlock { @MainActor in w.close() }
        return w
    }

    func testOnByDefault() {
        UserDefaults.standard.removeObject(forKey: CaptureProtection.key)
        XCTAssertTrue(CaptureProtection.isOn)
        let w = window()
        CaptureProtection.shared.apply()
        XCTAssertEqual(w.sharingType, .none)
    }

    /// Off: windows opened from then on can be captured. macOS keeps a window that was shown with `.none` that way,
    /// so the windows already open stay hidden until the app restarts (Settings says so).
    func testTurningItOffAllowsCaptureForNewWindows() {
        UserDefaults.standard.set(false, forKey: CaptureProtection.key)
        XCTAssertFalse(CaptureProtection.isOn)
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 100, height: 100), styleMask: [.titled],
                         backing: .buffered, defer: true)
        w.isReleasedWhenClosed = false
        w.sharingType = .none
        CaptureProtection.shared.apply()
        XCTAssertEqual(w.sharingType, .readOnly)
    }

    /// A launch argument (argument domain) naming the key never wins over the stored value (scan APL-L1).
    func testLaunchArgumentCannotOverrideStoredValue() {
        let key = CaptureProtection.key
        let fromArgs = PersistentDefaults.resolve(key: key, merged: "NO", arguments: [key: "NO"], persistent: { [:] })
        XCTAssertTrue(CaptureProtection.value(fromArgs))
        let stored = PersistentDefaults.resolve(key: key, merged: "NO", arguments: [key: "NO"],
                                                persistent: { [key: true] })
        XCTAssertTrue(CaptureProtection.value(stored))
        let storedOff = PersistentDefaults.resolve(key: key, merged: true, arguments: [key: "YES"],
                                                   persistent: { [key: false] })
        XCTAssertFalse(CaptureProtection.value(storedOff))
        XCTAssertEqual(PersistentDefaults.resolve(key: key, merged: false, arguments: [:], persistent: { nil }) as? Bool,
                       false)
        XCTAssertFalse(CaptureProtection.value("NO"))
        XCTAssertTrue(CaptureProtection.value(nil))
    }

    func testAWindowOpenedLaterIsCovered() async {
        UserDefaults.standard.set(true, forKey: CaptureProtection.key)
        CaptureProtection.shared.start()
        let w = window()
        w.sharingType = .readOnly
        // The next pass of the event loop applies the setting.
        NSApplication.shared.updateWindows()
        for _ in 0..<50 where w.sharingType != .none { try? await Task.sleep(for: .milliseconds(20)) }
        XCTAssertEqual(w.sharingType, .none)
    }
}
