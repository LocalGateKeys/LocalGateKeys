import XCTest
@testable import LGKCore

/// `tests/vectors/jwt/cases.json`: the JWT decode. Every platform returns the vector's result, or nothing.
/// Mirror of Kotlin `JwtViewTest`.
final class JWTViewTests: XCTestCase {
    private func cases() throws -> [[String: JSONValue]] {
        let data = try Data(contentsOf: Vectors.shared("jwt/cases.json"))
        guard case .array(let rows) = try CanonicalJSON.parse(Array(data)) else { throw CocoaError(.fileReadCorruptFile) }
        return rows.compactMap { if case .object(let o) = $0 { return o } else { return nil } }
    }

    private func string(_ v: JSONValue?) -> String? { if case .string(let s)? = v { return s } else { return nil } }
    private func int(_ v: JSONValue?) -> Int64? { if case .int(let n)? = v { return n } else { return nil } }

    func testVectors() throws {
        let all = try cases()
        XCTAssertGreaterThanOrEqual(all.count, 40)
        for c in all {
            let name = string(c["name"]) ?? "?"
            let info = JWTView.decode(string(c["value"]) ?? "")
            guard case .object(let expected)? = c["result"] else {
                XCTAssertNil(info, "vector \(name)")
                continue
            }
            let got = try XCTUnwrap(info, "vector \(name)")
            XCTAssertEqual(got.header, expected["header"], "header \(name)")
            XCTAssertEqual(got.claims, expected["claims"], "claims \(name)")
            XCTAssertEqual(got.alg, string(expected["alg"]), "alg \(name)")
            XCTAssertEqual(got.issued, int(expected["issued"]), "issued \(name)")
            XCTAssertEqual(got.notBefore, int(expected["not_before"]), "not_before \(name)")
            XCTAssertEqual(got.expires, int(expected["expires"]), "expires \(name)")
            if let now = int(c["now"]), case .bool(let flag)? = c["expired"] {
                XCTAssertEqual(got.expired(now: now), flag, "expired \(name)")
            }
        }
    }

    private func goodToken() throws -> String {
        let row = try XCTUnwrap(try cases().first { string($0["name"]) == "hs256_basic" })
        return try XCTUnwrap(string(row["value"]))
    }

    func testOversizedValueIsNotDecoded() throws {
        let good = try goodToken()
        XCTAssertNotNil(JWTView.decode(good))
        XCTAssertNil(JWTView.decode(good + String(repeating: "A", count: JWTView.maxChars)))
    }

    func testExpiredBoundary() throws {
        let info = try XCTUnwrap(JWTView.decode(try goodToken()))
        XCTAssertTrue(info.expired(now: 1_800_000_000))
        XCTAssertFalse(info.expired(now: 1_799_999_999))
    }
}
