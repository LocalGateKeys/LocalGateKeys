import XCTest
@testable import LGKCore

/// `tests/vectors/wifi_qr/cases.json`: the Wi-Fi QR text. Every platform returns exactly the vector's text.
/// Mirror of Kotlin `WifiQrTest`.
final class WifiQRTests: XCTestCase {
    struct Case: Decodable {
        let name: String
        let ssid: String
        let password: String
        let security: String
        let hidden: Bool
        let text: String?
    }

    func testVectors() throws {
        let data = try Data(contentsOf: Vectors.shared("wifi_qr/cases.json"))
        let cases = try JSONDecoder().decode([Case].self, from: data)
        XCTAssertGreaterThanOrEqual(cases.count, 9)
        for c in cases {
            XCTAssertEqual(WifiQR.text(ssid: c.ssid, password: c.password, security: c.security, hidden: c.hidden),
                           c.text, "vector \(c.name)")
        }
    }

    func testUnknownSecurityHasNoQR() {
        XCTAssertNil(WifiQR.text(ssid: "a", password: "b", security: "bogus", hidden: false))
    }
}
