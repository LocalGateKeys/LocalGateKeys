import XCTest
@testable import LGKCore

/// `tests/vectors/lookalike/cases.json`: the same cases `src/localvault/lookalike.py`, `browser-extension/lookalike.js`
/// and Kotlin `LookalikeTest` pass. Kind, matched (the saved origin exactly as given) and reason must be identical.
final class LookalikeTests: XCTestCase {
    static let fileURL = Vectors.shared("lookalike/cases.json")

    private func cases() throws -> [[String: Any]] {
        let data = try Data(contentsOf: Self.fileURL)
        let doc = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        return try XCTUnwrap(doc["cases"] as? [[String: Any]])
    }

    private var lookalike: Lookalike { Lookalike(rules: URLMatchTests.rules) }

    func test_every_shared_vector_matches() throws {
        XCTAssertNotNil(URLMatchTests.rules, "public suffix list missing at \(URLMatchTests.pslURL.path)")
        let all = try cases()
        XCTAssertGreaterThanOrEqual(all.count, 92)
        let l = lookalike
        var failures: [String] = []
        for c in all {
            let name = c["name"] as? String ?? "?"
            let origin = try XCTUnwrap(c["origin"] as? String)
            let saved = try XCTUnwrap(c["saved"] as? [String])
            let expected = LookalikeVerdict(kind: try XCTUnwrap(c["kind"] as? String), matched: c["matched"] as? String,
                                            reason: try XCTUnwrap(c["reason"] as? String))
            let got = l.classify(origin, saved: saved)
            if got != expected { failures.append("\(name): expected \(expected), got \(got)") }
        }
        XCTAssertEqual(failures, [])
    }

    /// `tests/vectors/lookalike/crosscheck.json`: about 5,800 origin/saved pairs Python and the extension agree on.
    func test_the_crosscheck_corpus_matches() throws {
        let data = try Data(contentsOf: Vectors.shared("lookalike/crosscheck.json"))
        let doc = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let origins = try XCTUnwrap(doc["origins"] as? [String])
        let saved = try XCTUnwrap(doc["saved"] as? [String])
        let pairs = try XCTUnwrap(doc["pairs"] as? [[Any]])
        let lists = try XCTUnwrap(doc["lists"] as? [[Any]])
        XCTAssertGreaterThanOrEqual(pairs.count, 5000)
        func verdict(_ row: [Any], _ at: Int) throws -> LookalikeVerdict {
            let matched = try XCTUnwrap(row[at + 1] as? Int)
            return LookalikeVerdict(kind: try XCTUnwrap(row[at] as? String), matched: matched < 0 ? nil : saved[matched],
                                    reason: try XCTUnwrap(row[at + 2] as? String))
        }
        let l = lookalike
        var failures: [String] = []
        for row in pairs {
            let origin = origins[try XCTUnwrap(row[0] as? Int)]
            let one = saved[try XCTUnwrap(row[1] as? Int)]
            let expected = try verdict(row, 2)
            let got = l.classify(origin, saved: [one])
            if got != expected { failures.append("\(origin) vs \(one): expected \(expected), got \(got)") }
        }
        for row in lists {
            let origin = origins[try XCTUnwrap(row[0] as? Int)]
            let expected = try verdict(row, 1)
            let got = l.classify(origin, saved: saved)
            if got != expected { failures.append("\(origin) vs all: expected \(expected), got \(got)") }
        }
        XCTAssertEqual(failures, [])
    }

    /// Design decision 2026-11-12: the phishing shield (`shield`, desktop `lookalike.classify`) keeps "related" for
    /// the same host or its `www.` twin; `crosscheck.json` `shield_pairs` (pairs that differ from `classify`) and
    /// `shield_lists`.
    func test_the_shield_corpus_matches() throws {
        let data = try Data(contentsOf: Vectors.shared("lookalike/crosscheck.json"))
        let doc = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let origins = try XCTUnwrap(doc["origins"] as? [String])
        let saved = try XCTUnwrap(doc["saved"] as? [String])
        let pairs = try XCTUnwrap(doc["pairs"] as? [[Any]])
        let shieldPairs = try XCTUnwrap(doc["shield_pairs"] as? [[Any]])
        let shieldLists = try XCTUnwrap(doc["shield_lists"] as? [[Any]])
        func verdict(_ row: [Any], _ at: Int) throws -> LookalikeVerdict {
            let matched = try XCTUnwrap(row[at + 1] as? Int)
            return LookalikeVerdict(kind: try XCTUnwrap(row[at] as? String), matched: matched < 0 ? nil : saved[matched],
                                    reason: try XCTUnwrap(row[at + 2] as? String))
        }
        var overrides: [String: LookalikeVerdict] = [:]
        for row in shieldPairs {
            overrides["\(try XCTUnwrap(row[0] as? Int)),\(try XCTUnwrap(row[1] as? Int))"] = try verdict(row, 2)
        }
        XCTAssertGreaterThanOrEqual(overrides.count, 20)
        let l = lookalike
        var failures: [String] = []
        for row in pairs {
            let o = try XCTUnwrap(row[0] as? Int), s = try XCTUnwrap(row[1] as? Int)
            let expected = try overrides["\(o),\(s)"] ?? verdict(row, 2)
            let got = l.shield(origins[o], saved: [saved[s]])
            if got != expected { failures.append("\(origins[o]) vs \(saved[s]): expected \(expected), got \(got)") }
        }
        for row in shieldLists {
            let origin = origins[try XCTUnwrap(row[0] as? Int)]
            let expected = try verdict(row, 1)
            let got = l.shield(origin, saved: saved)
            if got != expected { failures.append("\(origin) vs all: expected \(expected), got \(got)") }
        }
        XCTAssertEqual(failures, [])
        XCTAssertEqual(l.shield("https://sites.google.com", saved: ["https://accounts.google.com"]),
                       LookalikeVerdict(kind: "unknown", matched: "https://accounts.google.com", reason: "same-site"))
    }

    func test_without_rules_only_hosts_and_mixed_script_count() {
        let bare = Lookalike(rules: nil)
        XCTAssertEqual(bare.classify("https://example.com", saved: ["https://example.com"]),
                       LookalikeVerdict(kind: "exact", matched: "https://example.com", reason: "same-origin"))
        XCTAssertEqual(bare.classify("https://paypa1.com", saved: ["https://paypal.com"]),
                       LookalikeVerdict(kind: "unknown", matched: nil, reason: "no-match"))
        XCTAssertEqual(bare.classify("https://xn--pple-43d.com", saved: ["https://example.com"]),
                       LookalikeVerdict(kind: "lookalike", matched: nil, reason: "mixed-script"))
    }

    func test_the_tables_are_the_reference_text() throws {
        var repo = Vectors.root
        for _ in 0..<3 { repo.deleteLastPathComponent() }
        let py = try String(contentsOf: repo.appendingPathComponent("src/localvault/lookalike.py"), encoding: .utf8)
        for table in [Lookalike.confusablesTable, Lookalike.visualPairsTable, Lookalike.scriptTable] {
            // The Python source splits long tables over several string literals; every entry must be there in order.
            var from = py.startIndex
            for word in table.split(separator: " ") {
                let found = py.range(of: String(word), range: from..<py.endIndex)
                XCTAssertNotNil(found, "entry \(word) missing from lookalike.py")
                if let found { from = found.upperBound }
            }
        }
    }

    func test_punycode_decode_round_trips_and_refuses_junk() {
        XCTAssertEqual(Punycode.decode(Array("bcher-kva".unicodeScalars)), Array("bücher".unicodeScalars).map(\.value))
        // Digits are case-insensitive; basic code points keep their case.
        XCTAssertEqual(Punycode.decode(Array("bcher-KVA".unicodeScalars)), Array("bücher".unicodeScalars).map(\.value))
        XCTAssertNil(Punycode.decode(Array("bcher-kv!".unicodeScalars)))
        XCTAssertNil(Punycode.decode(Array("bcher-k".unicodeScalars)), "truncated")
    }

    func test_junk_saved_entries_and_odd_inputs_never_crash() {
        let junk = ["", " ", "://", "https://", "https://[::1", "https://a:99999", "xn--", "https://xn--.com", "https://\u{0}.com",
                    "https://" + String(repeating: "a", count: 5000), "https://0x" + String(repeating: "f", count: 40) + ".1"]
        let l = lookalike
        for s in junk {
            _ = l.classify(s, saved: junk)
            _ = l.classify("https://example.com", saved: [s])
        }
    }
}
