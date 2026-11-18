import XCTest

/// The Mac app's sandbox entitlements (ios/Mac/Mac.entitlements, generated from project.yml).
final class MacEntitlementsTests: XCTestCase {
    private func entitlements() throws -> [String: Any] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Mac/Mac.entitlements")
        let data = try Data(contentsOf: url)
        return try XCTUnwrap(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    }

    /// Found by MacPendingChecksUITests 2026-11-16: "Print vault health report" showed "This application does not
    /// support printing." The sandbox refuses NSPrintOperation without `com.apple.security.print`, which also stopped
    /// the emergency kit and the recovery kit from printing.
    func testSandboxAllowsPrinting() throws {
        let e = try entitlements()
        XCTAssertEqual(e["com.apple.security.app-sandbox"] as? Bool, true)
        XCTAssertEqual(e["com.apple.security.print"] as? Bool, true, "printing needs com.apple.security.print in the sandbox")
    }
}
