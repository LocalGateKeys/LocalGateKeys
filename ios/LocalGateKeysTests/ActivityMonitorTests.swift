import XCTest
import UIKit
import SwiftUI
import AppShared
@testable import LocalGateKeys

@MainActor
final class ActivityMonitorTests: XCTestCase {
    func test_text_change_notifications_count_as_activity() {
        let center = NotificationCenter()
        var count = 0
        let monitor = ActivityMonitor(center: center) { count += 1 }
        center.post(name: UITextField.textDidChangeNotification, object: UITextField())
        center.post(name: UITextView.textDidChangeNotification, object: UITextView())
        XCTAssertEqual(count, 2)
        withExtendedLifetime(monitor) {}
    }

    func test_unrelated_notifications_are_ignored() {
        let center = NotificationCenter()
        var count = 0
        let monitor = ActivityMonitor(center: center) { count += 1 }
        center.post(name: UIApplication.didBecomeActiveNotification, object: nil)
        XCTAssertEqual(count, 0)
        withExtendedLifetime(monitor) {}
    }

    func test_touch_began_in_the_window_counts_and_never_claims_the_touch() {
        var count = 0
        let monitor = ActivityMonitor(center: NotificationCenter()) { count += 1 }
        let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 100, height: 100))
        monitor.attach(to: window)
        monitor.attach(to: window)   // idempotent: SwiftUI may move the reader view
        let recognizers = (window.gestureRecognizers ?? []).compactMap { $0 as? ActivityTouchRecognizer }
        XCTAssertEqual(recognizers.count, 1)
        let r = try! XCTUnwrap(recognizers.first)
        XCTAssertFalse(r.cancelsTouchesInView); XCTAssertFalse(r.delaysTouchesBegan); XCTAssertFalse(r.delaysTouchesEnded)
        XCTAssertTrue(r.delegate?.gestureRecognizer?(r, shouldRecognizeSimultaneouslyWith: UITapGestureRecognizer()) ?? false)
        XCTAssertFalse(r.canPrevent(UITapGestureRecognizer()))
        r.touchesBegan([], with: UIEvent())
        XCTAssertEqual(count, 1)
        XCTAssertFalse([.began, .recognized, .changed].contains(r.state), "never recognises, so no button or list row loses its tap")
    }

    /// The old `.simultaneousGesture(TapGesture())` on UnlockedRoot swallowed List-row button taps.
    func test_unlocked_root_attaches_no_gesture() {
        let lock = AppLockModel(unlocker: FakeUnlocker(), clock: TestClock(0), scheduler: ManualScheduler(clock: TestClock(0)),
                                settings: AppSettings(defaults: UserDefaults(suiteName: "root-\(UUID().uuidString)")!),
                                clipboard: nil, eraser: FakeEraser())
        let root = UnlockedRoot(store: MemoryStore(), keychain: InMemoryKeychainVault(), pro: ProModel(purchases: FakePurchases()), lock: lock,
                                safariImport: SafariImportModel(background: FakeBackgroundTasks()))
        let bodyType = String(reflecting: type(of: root.body))
        XCTAssertFalse(bodyType.contains("Gesture"), bodyType)
    }
}
