import XCTest
@testable import LGKCore

/// `tests/vectors/origin/url_cases.json`: the desktop's `canonicalize_origin`, `normalize_url`, `origin_of`,
/// `host_of` and `match_rank` on forbidden host code points, whitespace, brackets, zone ids, IPv4-mapped
/// addresses, trailing dots, ports in `host` mode and plain-HTTP candidates (audit 2026-10-24 L-27, L-28, L-29,
/// I-13, I-22, M-4). Values and error messages must be identical. Mirror of Kotlin `OriginVectorsTest`.
final class URLOriginVectorsTests: XCTestCase {
    static let fileURL: URL = Vectors.root.deletingLastPathComponent().appendingPathComponent("origin/url_cases.json")

    func doc() throws -> [String: Any] {
        let data = try Data(contentsOf: Self.fileURL)
        guard let o = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CocoaError(.fileReadCorruptFile)
        }
        return o
    }

    private func run(_ fn: (String) throws -> String, _ input: String) -> [String: String] {
        do {
            return ["ok": try fn(input)]
        } catch OriginError.invalid(let message) {
            return ["error": message]
        } catch {
            return ["unexpected": "\(error)"]
        }
    }

    func test_functions_match_the_desktop() throws {
        let functions: [(String, (String) throws -> String)] = [
            ("canonicalize", Origin.canonicalize),
            ("normalize_url", Origin.normalizeURL),
            ("origin_of", Origin.originOf),
            ("host_of", URLMatcher.hostOf),
        ]
        let cases = try XCTUnwrap(try doc()["cases"] as? [[String: Any]])
        XCTAssertGreaterThanOrEqual(cases.count, 50)
        for c in cases {
            let input = try XCTUnwrap(c["input"] as? String)
            for (name, fn) in functions {
                let want = try XCTUnwrap(c[name] as? [String: String])
                XCTAssertEqual(run(fn, input), want, "\(name)(\(input.debugDescription))")
            }
        }
    }

    func test_match_rank_matches_the_desktop() throws {
        let matcher = URLMatcher(rules: URLMatchTests.rules)
        let cases = try XCTUnwrap(try doc()["match"] as? [[String: Any]])
        XCTAssertGreaterThanOrEqual(cases.count, 30)
        for c in cases {
            let rawRows = try XCTUnwrap(c["rows"] as? [[String]])
            let rows = try rawRows.map { URLRow(url: $0[0], mode: try XCTUnwrap(URLMatchMode(stored: $0[1]))) }
            let candidate = try XCTUnwrap(c["candidate"] as? String)
            let want = c["rank"] as? Int
            XCTAssertEqual(matcher.matchRank(rows, candidate: candidate), want, "\(rawRows) vs \(candidate.debugDescription)")
        }
    }
}
