import XCTest
@testable import LGKCore

/// `.lgkshare` v1.1 (sub-plan 12) against `tests/vectors/share/v1_1.json`: an earlier embedded expiry wins,
/// a later one is capped at the 24 h lifetime, and `one_use` is accepted.
final class ShareExpiryTests: XCTestCase {
    private func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
    private func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { return a }; return [] }
    private func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }
    private func int(_ v: JSONValue?) -> Int64 { if case .int(let i)? = v { return i }; return -1 }

    func testV11VectorsOpenUntilTheirExpiry() throws {
        let opens = arr(obj(try CanonicalJSON.parse(Array(try Vectors.data("../share/v1_1.json"))))["opens"])
        XCTAssertEqual(opens.count, 2)
        for v in opens {
            let c = obj(v)
            let data = Array(str(c["package"]).utf8)
            let opened = try Share.open(data, code: str(c["code"]), now: int(c["now"]))
            XCTAssertEqual(opened.expiresAt, int(c["expires_at"]), str(c["name"]))
            XCTAssertEqual(opened.item, obj(c["item"]))
            XCTAssertThrowsError(try Share.open(data, code: str(c["code"]), now: opened.expiresAt)) {
                XCTAssertEqual(($0 as? ShareError)?.reason, "expired")
            }
        }
    }
}
