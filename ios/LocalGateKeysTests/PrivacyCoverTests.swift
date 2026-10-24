import XCTest
import SwiftUI
import UIKit
@testable import LocalGateKeys

@MainActor
final class PrivacyCoverTests: XCTestCase {
    final class FakeWindow: PrivacyCoverWindow { var isHidden = true; var isOnCurrentScene = true }

    func test_cover_shows_when_not_active_and_hides_on_active() {
        let w = FakeWindow()
        var made = 0
        let c = PrivacyCoverController { made += 1; return w }
        c.sceneChanged(.active)
        XCTAssertEqual(made, 0, "no window until the first time the app leaves active")
        XCTAssertTrue(w.isHidden)
        c.sceneChanged(.inactive)
        XCTAssertFalse(w.isHidden); XCTAssertTrue(c.isCovering)
        c.sceneChanged(.background)
        XCTAssertFalse(w.isHidden)
        c.sceneChanged(.active)
        XCTAssertTrue(w.isHidden); XCTAssertFalse(c.isCovering)
        c.sceneChanged(.inactive)
        XCTAssertFalse(w.isHidden)
        XCTAssertEqual(made, 1, "one window, reused")
    }

    func test_window_is_rebuilt_when_its_scene_is_gone_or_replaced() {
        var made: [FakeWindow] = []
        let c = PrivacyCoverController { let w = FakeWindow(); made.append(w); return w }
        c.sceneChanged(.inactive)
        XCTAssertEqual(made.count, 1)
        c.sceneChanged(.active)
        made[0].isOnCurrentScene = false   // the scene was disconnected and a new one connected
        c.sceneChanged(.background)
        XCTAssertEqual(made.count, 2, "a new window on the current scene")
        XCTAssertTrue(made[0].isHidden, "the stale window is hidden")
        XCTAssertFalse(made[1].isHidden)
        XCTAssertTrue(c.isCovering)
    }

    func test_no_scene_means_no_cover_and_no_crash() {
        let c = PrivacyCoverController { nil }
        c.sceneChanged(.background)
        XCTAssertFalse(c.isCovering)
        c.sceneChanged(.active)
    }

    func test_cover_window_sits_above_alerts_and_sheets() {
        let w = UIWindow(frame: CGRect(x: 0, y: 0, width: 100, height: 100))
        PrivacyCoverController.configure(w)
        XCTAssertGreaterThan(w.windowLevel, .alert)
        XCTAssertGreaterThan(w.windowLevel, .normal)
        XCTAssertTrue(w.rootViewController is UIHostingController<PrivacyCover>)
        XCTAssertTrue(w.isHidden)
        XCTAssertFalse(w.isKeyWindow)
    }
}
