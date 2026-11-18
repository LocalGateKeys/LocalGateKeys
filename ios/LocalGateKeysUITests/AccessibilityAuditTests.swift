import XCTest

/// UX plan workstream 13: Xcode's accessibility audit (labels, contrast, hit regions, Dynamic Type, clipped
/// text) on the screens a UI test can reach without Face ID: the unlock screen, at the default and the
/// largest accessibility text size, in light and dark. The vault screens are covered by the manual
/// VoiceOver / AX5 row in RELEASE.md (unlocking needs a real face or passcode).
final class AccessibilityAuditTests: XCTestCase {
    override func setUp() { continueAfterFailure = true }

    @MainActor
    private func launch(_ extra: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments += extra
        app.launch()
        // The Face ID permission alert (first launch) or the Face ID prompt sits in front of the app, and the audit
        // service then refuses the app with -902: dismiss it so the unlock screen itself is audited.
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        for _ in 0..<3 {
            let alert = springboard.alerts.firstMatch
            guard alert.waitForExistence(timeout: 4) else { break }
            let button = ["Don’t Allow", "Don't Allow", "Cancel", "OK"].lazy
                .map { alert.buttons[$0].firstMatch }.first { $0.exists } ?? alert.buttons.firstMatch
            button.tap()
        }
        return app
    }

    /// Xcode 27.1's audit service refuses every app on the iOS 27.0 and 27.1 simulators with -902 "Invalid target
    /// app", Apple's Settings included (checked 2026-11-15): that one error skips. On a device the audits run once the
    /// Face ID alert in front of the app is dismissed (checked on iOS 27.2.1, 2026-11-16).
    @MainActor
    private func audit(_ app: XCUIApplication, for types: XCUIAccessibilityAuditType = .all) throws {
        do { try app.performAccessibilityAudit(for: types) } catch let e as NSError
            where e.domain == "com.apple.accessibilityAudit" && e.code == -902 {
            throw XCTSkip("The accessibility audit service refused the app (-902), as Xcode 27.1's simulators do for every app.")
        }
    }

    @MainActor
    func testUnlockScreenPassesTheAudit() throws {
        let app = launch()
        try audit(app)
    }

    @MainActor
    func testUnlockScreenAtTheLargestTextSize() throws {
        let app = launch(["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"])
        try audit(app, for: [.dynamicType, .textClipped, .hitRegion, .sufficientElementDescription])
    }

    @MainActor
    func testUnlockScreenInDarkModeHasContrast() throws {
        let app = launch(["-AppleInterfaceStyle", "Dark"])
        try audit(app, for: [.contrast])
    }
}
