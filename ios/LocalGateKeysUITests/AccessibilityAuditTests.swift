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
        return app
    }

    @MainActor
    func testUnlockScreenPassesTheAudit() throws {
        let app = launch()
        try app.performAccessibilityAudit()
    }

    @MainActor
    func testUnlockScreenAtTheLargestTextSize() throws {
        let app = launch(["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"])
        try app.performAccessibilityAudit(for: [.dynamicType, .textClipped, .hitRegion, .sufficientElementDescription])
    }

    @MainActor
    func testUnlockScreenInDarkModeHasContrast() throws {
        let app = launch(["-AppleInterfaceStyle", "Dark"])
        try app.performAccessibilityAudit(for: [.contrast])
    }
}
