import XCTest
import Foundation
@testable import LGKCore

/// normalise/entries.json and items.json (README "Normalisation tables").
final class NormaliseTests: XCTestCase {
    static let phoneKinds: Set<String> = Normalise.phoneEntryKinds.union(Normalise.phoneItemKinds).subtracting(["passkey"])
    /// Kinds the desktop does not know at all: the phone rejects them like the desktop does.
    static let unknownKinds: Set<String> = ["spaceship"]

    func cases(_ file: String) throws -> [[String: JSONValue]] {
        guard case .object(let o) = try CanonicalJSON.parse(Array(Vectors.data(file))),
              case .array(let rows)? = o["cases"] else { throw JSONError.syntax }
        XCTAssertFalse(rows.isEmpty, file)
        return rows.map { MergeVectors.obj($0) }
    }

    func canonical(_ v: JSONValue) throws -> String {
        String(decoding: try CanonicalJSON.encode(v, dialect: .utf8), as: UTF8.self)
    }

    func run(_ file: String) throws -> Int {
        var checked = 0
        for c in try cases(file) {
            let name = MergeVectors.str(c["name"])!
            let ns = Namespace(rawValue: MergeVectors.str(c["ns"])!)!
            let input = c["input"]!
            let kind = MergeVectors.str(MergeVectors.obj(input)["kind"]) ?? ""
            let result = Result { try Normalise.normalForm(ns: ns, record: input) }
            if !Self.phoneKinds.contains(kind) && !Self.unknownKinds.contains(kind) {
                // Never normalised on the phone: refused so the caller passes the record through.
                XCTAssertThrowsError(try result.get(), name) { XCTAssertEqual($0 as? NormaliseError, .notPhoneKind, name) }
                continue
            }
            checked += 1
            if name.contains("idna") {
                XCTAssertThrowsError(try result.get(), name) { XCTAssertEqual($0 as? NormaliseError, .needsPunycode, name) }
                continue
            }
            if c["error"] == .string("rejected") {
                XCTAssertThrowsError(try result.get(), name) { e in
                    guard case .rejected? = e as? NormaliseError else { return XCTFail("\(name): \(e)") }
                }
                continue
            }
            XCTAssertEqual(c["error"], .null, name)
            do {
                let got = try result.get()
                XCTAssertEqual(try canonical(got), try canonical(c["output"]!), name)
                if c["already_normal"] == .bool(true) {
                    XCTAssertEqual(try canonical(got), try canonical(input), name)
                }
                // Normal form is a fixed point.
                XCTAssertEqual(try canonical(Normalise.normalForm(ns: ns, record: got)), try canonical(got), name)
            } catch {
                XCTFail("\(name): \(error)")
            }
        }
        return checked
    }

    func test_entries_vectors() throws {
        XCTAssertGreaterThanOrEqual(try run("normalise/entries.json"), 50)
    }

    func test_items_vectors() throws {
        XCTAssertGreaterThanOrEqual(try run("normalise/items.json"), 10)
    }

    func test_origin_canonicalize() throws {
        XCTAssertEqual(try Origin.canonicalize("HTTPS://Example.COM:443/"), "https://example.com")
        XCTAssertEqual(try Origin.canonicalize("https://[2001:DB8::1]:8443"), "https://[2001:db8::1]:8443")
        XCTAssertEqual(try Origin.canonicalize("http://127.0.0.1:3000"), "http://127.0.0.1:3000")
        XCTAssertEqual(try Origin.canonicalize("http://[::1]"), "http://[::1]")
        XCTAssertEqual(try Origin.canonicalize("https://a.example.com."), "https://a.example.com")
        XCTAssertThrowsError(try Origin.canonicalize("https://bücher.example")) { XCTAssertEqual($0 as? OriginError, .needsPunycode) }
        for bad in ["", "ftp://example.com", "https://user@example.com", "https://example.com?q", "https://example.com#f",
                    "https://example.com/x", "http://example.com", "https://", "https://a..b.com", "https://example.com:99999",
                    "https://example.com:8x", "https://[example.com]", "https://[::1", String(repeating: "a", count: 2049),
                    "https://" + String(repeating: "a", count: 64) + ".com",
                    // Audit 2026-10-24: forbidden host code points, whitespace, bracket tricks, zone ids, mapped addresses.
                    "https://a.example.com..", "https://paypal.com\\.evil.com", "https://a%2fb.com", "https://a^b.com",
                    "https://example.com ", " https://example.com", "https://evil.com[::1]", "https://[::1].:8443",
                    "https://[v1.abc]", "https://[::1%25eth0]", "https://[::ffff:127.0.0.1]"] {
            XCTAssertThrowsError(try Origin.canonicalize(bad), bad) { e in
                guard case .invalid? = e as? OriginError else { return XCTFail("\(bad): \(e)") }
            }
        }
    }

    func test_card_payload_normalises() throws {
        let rec: JSONValue = .object([
            "id": .string("88888888-AAAA-4000-8000-000000000008"), "kind": .string("card"), "title": .string("Visa"),
            "created_at": .int(1), "updated_at": .int(2), "tags": .array([.string(" Work "), .string("work")]),
            "payload": .object(["number": .string("4111 1111-1111 1111"), "expiry": .string("3/2031"),
                                "cvv": .string(" 123 "), "template_id": .null]),
        ])
        let out = try Normalise.normalForm(ns: .item, record: rec)
        let p = MergeVectors.obj(MergeVectors.obj(out)["payload"])
        XCTAssertEqual(p["number"], .string("4111111111111111"))
        XCTAssertEqual(p["brand"], .string("visa"))
        XCTAssertEqual(p["last4"], .string("1111"))
        XCTAssertEqual(p["expiry"], .string("03/31"))
        XCTAssertEqual(p["cvv"], .string("123"))
        XCTAssertEqual(MergeVectors.obj(out)["tags"], .array([.string("Work")]))
        var bad = MergeVectors.obj(rec)
        // NFC and NFD spellings are different tags (Python compares code points).
        var twin = MergeVectors.obj(rec)
        twin["tags"] = .array([.string("\u{E9}"), .string("e\u{301}"), .string("\u{C9}")])
        let tw = try Normalise.normalForm(ns: .item, record: .object(twin))
        XCTAssertEqual(MergeVectors.obj(tw)["tags"].map { try! CanonicalJSON.encode($0, dialect: .utf8) },
                       try CanonicalJSON.encode(.array([.string("\u{E9}"), .string("e\u{301}")]), dialect: .utf8))
        // Web URL rows that differ only by normalisation form are both kept.
        let rows = try Normalise.webURLs(.array([.object(["url": .string("https://a.example/\u{E9}"), "match": .string("starts_with")]),
                                                 .object(["url": .string("https://a.example/e\u{301}"), "match": .string("starts_with")])]))
        guard case .array(let kept) = rows else { return XCTFail() }
        XCTAssertEqual(kept.count, 2)
        bad["payload"] = .object(["number": .string("4111111111111112")])
        XCTAssertThrowsError(try Normalise.normalForm(ns: .item, record: .object(bad)))
    }
}
