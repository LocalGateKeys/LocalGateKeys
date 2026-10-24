import XCTest
import AppShared
@testable import LocalGateKeys

/// The phone's licence keys must equal the desktop's `licensing.LICENSE_KEYS`, or a synced desktop licence
/// stops unlocking Pro on the phone.
final class LicenseKeysTests: XCTestCase {
    func test_license_keys_match_desktop() throws {
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(contentsOf: repo.appendingPathComponent("src/localvault/licensing.py"), encoding: .utf8)
        let line = try XCTUnwrap(source.split(separator: "\n").first { $0.hasPrefix("LICENSE_KEYS: dict[str, str] = ") })
        let pairs = try NSRegularExpression(pattern: #""([0-9a-f]{16})":\s*"([A-Za-z0-9+/=]+)""#)
        let text = String(line)
        var desktop: [String: [UInt8]] = [:]
        for m in pairs.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
            let id = String(text[Range(m.range(at: 1), in: text)!])
            let key = try XCTUnwrap(Data(base64Encoded: String(text[Range(m.range(at: 2), in: text)!])))
            desktop[id] = [UInt8](key)
        }
        XCTAssertFalse(desktop.isEmpty)
        XCTAssertEqual(LicenseKeys.production, desktop)
    }
}
