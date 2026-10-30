import XCTest

/// TestBundleSetup: String(localized:) reads the app's catalog, so the English plurals are checked here too.
final class TestBundleSetupTests: XCTestCase {
    func testMainBundleCarriesTheCatalog() {
        XCTAssertEqual(String(localized: "\(1) free slots left on the free plan"), "1 free slot left on the free plan")
        XCTAssertEqual(String(localized: "\(2) free slots left on the free plan"), "2 free slots left on the free plan")
    }
}
