import XCTest
@testable import LGKCore

final class CanonicalJSONTests: XCTestCase {
    private func vectors() throws -> [String: Any] { try Vectors.json("canonical_json.json") }

    private func roundTrip(_ key: String, _ dialect: Dialect) throws {
        let rows = try XCTUnwrap(try vectors()[key] as? [[String: String]])
        XCTAssertFalse(rows.isEmpty)
        for r in rows {
            let v = try CanonicalJSON.parse(Array(r["value_json"]!.utf8))
            let out = try CanonicalJSON.encode(v, dialect: dialect)
            XCTAssertEqual(Vectors.hexString(out), r["canonical_hex"], r["value_json"]!)
        }
    }

    func test_utf8_vectors() throws { try roundTrip("utf8", .utf8) }
    func test_ascii_vectors() throws { try roundTrip("ascii", .ascii) }

    func test_rejected_vectors() throws {
        let rows = try XCTUnwrap(try vectors()["rejected"] as? [[String: Any]])
        let expected: [String: JSONError] = [
            #"{"n":9223372036854775808}"#: .intOutOfRange,
            #"{"x":NaN}"#: .nonFinite,
            #"{"x":Infinity}"#: .nonFinite,
            #"{"a":1,"a":2}"#: .duplicateKey,
            #"{"s":"\ud800"}"#: .loneSurrogate,
        ]
        XCTAssertEqual(rows.count, expected.count)
        for r in rows {
            let text = r["text"] as! String
            XCTAssertThrowsError(try CanonicalJSON.parse(Array(text.utf8)), text) {
                XCTAssertEqual($0 as? JSONError, expected[text], text)
            }
        }
    }

    func test_more_rejections() {
        for (t, e) in [("-Infinity", JSONError.nonFinite), ("1e999", .nonFinite), ("-9223372036854775808", .intOutOfRange),
                       (#""\udc00""#, .loneSurrogate), (#""\ud83dx""#, .loneSurrogate), ("01", .syntax), ("[1,]", .syntax),
                       ("{} x", .syntax), (#""a"#, .syntax)] {
            XCTAssertThrowsError(try CanonicalJSON.parse(Array(t.utf8)), t) { XCTAssertEqual($0 as? JSONError, e, t) }
        }
        XCTAssertThrowsError(try CanonicalJSON.parse([0x22, 0xC0, 0x80, 0x22])) { XCTAssertEqual($0 as? JSONError, .syntax) }
        XCTAssertThrowsError(try CanonicalJSON.encode(.float(.nan), dialect: .utf8)) { XCTAssertEqual($0 as? JSONError, .nonFinite) }
    }

    func test_keys_sorted_by_code_point() throws {
        // U+FF5A sorts before U+1F511 by code point, after it by UTF-16.
        let v = JSONValue.object(["\u{1F511}": .int(4), "\u{FF5A}": .int(3), "\u{E9}": .int(2), "a": .int(1)])
        let s = String(decoding: try CanonicalJSON.encode(v, dialect: .utf8), as: UTF8.self)
        XCTAssertEqual(s, "{\"a\":1,\"\u{E9}\":2,\"\u{FF5A}\":3,\"\u{1F511}\":4}")
    }

    func test_float_formatting_matches_python_repr() throws {
        let cases: [(Double, String)] = [(0.1, "0.1"), (1e-07, "1e-07"), (1e15, "1000000000000000.0"), (1e16, "1e+16"),
                                         (100.0, "100.0"), (-0.0, "-0.0"), (1.5e+300, "1.5e+300"), (1.5, "1.5"),
                                         (0.0001, "0.0001"), (0.00001, "1e-05"), (123456789012345.6, "123456789012345.6"),
                                         (1.2345e20, "1.2345e+20"), (-2.5e-10, "-2.5e-10"), (5e-324, "5e-324")]
        for (d, s) in cases { XCTAssertEqual(PythonFloat.repr(d), s) }
    }

    func test_int_float_distinction_survives() throws {
        let t = "[100.0,100,1e+16,-0.0,4611686018427387904]"
        let out = try CanonicalJSON.encode(try CanonicalJSON.parse(Array(t.utf8)), dialect: .utf8)
        XCTAssertEqual(String(decoding: out, as: UTF8.self), "[100.0,100,1e+16,-0.0,4611686018427387904]")
    }
}
