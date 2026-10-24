import XCTest
@testable import LocalGateKeys

/// project.yml packaging choices, read from the built app's Info.plist (the test host).
final class PackagingTests: XCTestCase {
    func test_export_compliance_is_answered_in_app_store_connect() {
        // Answered per build in App Store Connect (RELEASE.md): a true key without a compliance code fails upload.
        XCTAssertNil(Bundle.main.object(forInfoDictionaryKey: "ITSAppUsesNonExemptEncryption"))
    }

    func test_iphone_only() {
        XCTAssertEqual(Bundle.main.object(forInfoDictionaryKey: "UIDeviceFamily") as? [Int], [1])
    }
}
