import XCTest
import Crypto
@testable import LGKCore

/// Desktop `localvault.origin` parity. Expected values were produced by the desktop's own functions
/// (`match_rank`, `entry_urls`, `base_domain`) with the `idna` package installed; see the task 16 report.
final class URLMatchTests: XCTestCase {
    static let pslURL: URL = {
        var u = Vectors.root
        for _ in 0..<3 { u.deleteLastPathComponent() }   // tests/vectors/sync -> repo
        return u.appendingPathComponent("src/localvault/assets/public_suffix_list.dat")
    }()

    static let rules: PublicSuffixRules? = {
        guard let text = try? String(contentsOf: pslURL, encoding: .utf8) else { return nil }
        return PublicSuffixRules.load(listText: text)
    }()

    var matcher: URLMatcher { URLMatcher(rules: Self.rules) }

    func test_suffix_rules_equal_desktop_parse() throws {
        let rules = try XCTUnwrap(Self.rules, "public suffix list missing at \(Self.pslURL.path)")
        func digest(_ s: Set<[Unicode.Scalar]>) -> String {
            let sorted = s.sorted { $0.lexicographicallyPrecedes($1, by: { $0.value < $1.value }) }
            let text = sorted.map { String(String.UnicodeScalarView($0)) }.joined(separator: "\n")
            return SHA256.hash(data: Array(text.utf8)).map { String(format: "%02x", $0) }.joined()
        }
        // Desktop: suffix_rules() -> 10018 normal, 311 wildcard, 8 exception (IDNA rules as A-labels).
        XCTAssertEqual(rules.normal.count, 10018)
        XCTAssertEqual(rules.wildcard.count, 311)
        XCTAssertEqual(rules.exception.count, 8)
        XCTAssertEqual(digest(rules.normal), "e7b252fd28770493bb4c535d99cd5b5231f9da115fe817a64a281f02b15e9e7b")
        XCTAssertEqual(digest(rules.wildcard), "ed512b85712c945aa1b889e3be8c831f60d152e7deb31025ae096d506d4aef5e")
        XCTAssertEqual(digest(rules.exception), "dfbf3e07d8e99b5b9d71971eebf7a926d2d23d02d7c5ae1841d02968244bc958")
    }

    func test_truncated_list_fails_closed() throws {
        XCTAssertNil(PublicSuffixRules.load(listText: "com\nco.uk\n"))
        let closed = URLMatcher(rules: nil)
        XCTAssertEqual(try closed.baseDomain("login.example.co.uk"), "login.example.co.uk")
        XCTAssertNil(closed.matchRank([URLRow(url: "https://a.example.com/", mode: .baseDomain)], candidate: "https://b.example.com/"))
    }

    func test_base_domain_matches_desktop() throws {
        XCTAssertNotNil(Self.rules)
        for (host, expected) in Self.baseDomains {
            XCTAssertTrue(Scalars.equal(try matcher.baseDomain(host), expected), host)
        }
    }

    /// The URL rows of `normalise/entries.json`: each accepted web case's normalised record is the stored
    /// login, matched against a fixed candidate list.
    func test_matcher_table_from_normalise_vectors() throws {
        let raw = try CanonicalJSON.parse(Array(try Vectors.data("normalise/entries.json")))
        guard case .object(let top) = raw, case .array(let cases)? = top["cases"] else { return XCTFail("shape") }
        var seen = Set<String>()
        for case .object(let c) in cases {
            guard case .string(let name)? = c["name"], let expected = Self.vectorExpected[name] else { continue }
            guard case .object(let record)? = c["output"] else { return XCTFail(name) }
            seen.insert(name)
            let rows = URLMatcher.entryURLs(record)
            for (i, candidate) in Self.vectorCandidates.enumerated() {
                var want = expected[i]
                // Known divergence: the phone has no UTS-46, so a non-ASCII candidate host fails closed
                // (the desktop encodes it). Browsers and AutoFill hand the extension A-label hosts.
                if candidate.unicodeScalars.contains(where: { !$0.isASCII }) { want = nil }
                XCTAssertEqual(matcher.matchRank(rows, candidate: candidate), want, "\(name) vs \(candidate)")
            }
        }
        XCTAssertEqual(seen, Set(Self.vectorExpected.keys), "every URL case must be in the vectors")
    }

    func test_each_mode_extra_rows() {
        for (rows, candidate, rank) in Self.extraRows {
            let record: [String: JSONValue] = ["kind": .string("web"), "scope": .object(["urls": .array(rows.map {
                .object(["url": .string($0.0), "match": .string($0.1)])
            })])]
            XCTAssertEqual(matcher.matchRank(URLMatcher.entryURLs(record), candidate: candidate), rank, "\(rows) vs \(candidate)")
        }
    }

    func test_starts_with_compares_code_points() {
        // "é" precomposed vs "e" + combining acute are canonically equivalent as Swift Strings.
        XCTAssertTrue("caf\u{E9}" == "cafe\u{301}")
        XCTAssertFalse(URLMatcher.startsWith(stored: "https://x.com/caf\u{E9}", candidate: "https://x.com/cafe\u{301}/a"))
        XCTAssertFalse(Scalars.equal("caf\u{E9}", "cafe\u{301}"))
        XCTAssertNil(URLMatchMode(stored: "host\u{301}"))
    }

    func test_candidates_rank_exact_origin_first_then_updated_then_id() {
        func login(_ id: String, _ updated: Int64, _ rows: [(String, String)], kind: String = "web") -> [String: JSONValue] {
            ["id": .string(id), "kind": .string(kind), "updated_at": .int(updated),
             "scope": .object(["origin": .string("https://unused.example"),
                               "urls": .array(rows.map { .object(["url": .string($0.0), "match": .string($0.1)]) })])]
        }
        let records = [
            login("d", 9, [("https://example.com/", "base_domain")]),
            login("c", 1, [("https://login.example.com", "exact_origin")]),
            login("b", 5, [("https://login.example.com/", "host")]),
            login("a", 1, [("https://login.example.com", "exact_origin")]),
            login("e", 99, [("https://login.example.com", "exact_origin")], kind: "desktop"),
            login("f", 99, [("https://other.org", "exact_origin")]),
            ["id": .string("g"), "kind": .string("web"), "updated_at": .int(2), "scope": .object(["origin": .string("https://login.example.com")])],
        ]
        let order = matcher.candidates(records, urls: ["https://login.example.com/signin"]).map { records[$0]["id"]! }
        XCTAssertEqual(order, [.string("g"), .string("a"), .string("c"), .string("b"), .string("d")])
        // Several service identifiers: best rank across them.
        let both = matcher.candidates(records, urls: ["https://other.org/", "https://login.example.com/"]).map { records[$0]["id"]! }
        XCTAssertEqual(both.first, .string("f"))
    }

    func test_punycode_rfc3492_samples() {
        func p(_ s: String) -> String? { Punycode.idnaLabel(Array(s.unicodeScalars)).map { String(String.UnicodeScalarView($0)) } }
        XCTAssertEqual(p("bücher"), "xn--bcher-kva")
        XCTAssertEqual(p("例え"), "xn--r8jz45g")
        XCTAssertEqual(p("テスト"), "xn--zckzah")
        XCTAssertEqual(p("faß"), "xn--fa-hia")
    }
}

extension URLMatchTests {
    static let vectorCandidates: [String] = ["https://example.com", "https://example.com/login?x=1", "https://www.example.com/", "http://example.com", "https://example.com:8443/", "https://app.example.com/a", "https://a.example.com", "https://a.example.com:444/", "https://b.example.com/x", "https://zz.b.example.com/", "https://c.example.com/", "https://other.c.example.com/p", "https://d.example.com/", "https://d.example.com/deep/path", "https://evil-example.com/", "https://xn--bcher-kva.example/login", "https://xn--fa-hia.de/", "https://xn--r8jz45g.xn--zckzah/", "https://[2001:db8::1]:8443/", "https://[2001:db8::1]/", "http://localhost:8080/x", "http://localhost/", "not a url", "https://bücher.example/"]
    /// case name -> expected rank per candidate (desktop `match_rank`, nil = no match).
    static let vectorExpected: [String: [Int?]] = [
        "plain_web_login": [0, 0, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil],
        "origin_upper_case_scheme_and_host": [0, 0, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil],
        "origin_default_https_port": [0, 0, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil],
        "origin_trailing_dot": [0, 0, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil],
        "origin_ipv6_upper_case_with_port": [nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, 0, nil, nil, nil, nil, nil],
        "origin_localhost_http_with_port": [nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, 0, nil, nil, nil],
        "origin_idna_umlaut": [nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, 0, nil, nil, nil, nil, nil, nil, nil, 0],
        "origin_idna_sharp_s_non_transitional": [nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, 0, nil, nil, nil, nil, nil, nil, nil],
        "origin_idna_japanese": [nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, 0, nil, nil, nil, nil, nil, nil],
        "urls_bare_string_row": [nil, nil, nil, nil, nil, 0, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil],
        "urls_each_match_mode": [2, 2, 2, nil, 2, 2, 0, 2, 1, 2, 2, 2, 2, 2, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil],
        "urls_duplicate_row_dropped": [nil, nil, nil, nil, nil, 0, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil],
    ]
    static let extraRows: [(rows: [(String, String)], candidate: String, rank: Int?)] = [
        ([("https://example.com", "exact_origin")], "https://example.com:443/x", 0),
        ([("https://example.com", "exact_origin")], "https://www.example.com/", nil),
        // M-4: a plain-HTTP candidate on a non-loopback host never matches. I-13: host mode compares the port.
        ([("https://login.example.com/", "host")], "http://login.example.com:9/q", nil),
        ([("https://login.example.com/", "host")], "https://login.example.com:9/q", nil),
        ([("https://login.example.com/", "host")], "https://login.example.com:443/q", 1),
        ([("https://login.example.com/", "host")], "https://example.com/", nil),
        ([("https://login.example.co.uk/", "base_domain")], "https://shop.example.co.uk/", 2),
        ([("https://login.example.co.uk/", "base_domain")], "https://other.co.uk/", nil),
        ([("https://a.github.io/", "base_domain")], "https://b.github.io/", nil),
        ([("https://a.github.io/", "base_domain")], "https://a.github.io/x", 2),
        ([("https://www.ck/", "base_domain")], "https://x.www.ck/", 2),
        ([("https://foo.bar.ck/", "base_domain")], "https://baz.bar.ck/", nil),
        ([("https://foo.bar.ck/", "base_domain")], "https://x.foo.bar.ck/", 2),
        ([("https://acct.z13.web.core.windows.net/", "base_domain")], "https://other.z13.web.core.windows.net/", nil),
        ([("https://192.168.1.10/", "base_domain")], "https://192.168.1.10:8443/", 2),
        ([("https://localhost/", "base_domain")], "https://localhost/", 2),
        ([("https://co.uk/", "base_domain")], "https://x.co.uk/", nil),
        ([("https://a.xn--r8jz45g.xn--zckzah/", "base_domain")], "https://b.xn--r8jz45g.xn--zckzah/", 2),
        ([("https://a.b.xn--zckzah/", "base_domain")], "https://c.b.xn--zckzah/", 2),
        ([("https://example.com/app", "starts_with")], "https://example.com/app/login", 3),
        ([("https://example.com/app", "starts_with")], "https://example.com/application", nil),
        ([("https://example.com/app", "starts_with")], "https://example.com/app?next=1", 3),
        ([("https://example.com/app", "starts_with")], "https://example.com/app", 3),
        ([("https://example.com/app/", "starts_with")], "https://example.com/app/x", 3),
        ([("https://example.com/café", "starts_with")], "https://example.com/café/x", nil),
        ([("https://example.com/café", "starts_with")], "https://example.com/café/x", 3),
        ([("https://EXAMPLE.com:443/A", "starts_with")], "https://example.com/A/b", 3),
        ([("https://example.com/A", "starts_with")], "https://example.com/a/b", nil),
        ([("https://example.com", "starts_with"), ("https://example.com", "host"), ("https://example.com", "exact_origin")], "https://example.com/z", 0),
        ([("https://sub.example.com", "exact_origin"), ("https://x.example.com", "base_domain")], "https://sub.example.com/", 0),
        ([("not a url", "host"), ("https://example.com", "host")], "https://example.com/", 1),
        ([("https://example.com", "regex")], "https://example.com/", 0),
    ]
    static let baseDomains: [(String, String)] = [
        ("login.example.co.uk", "example.co.uk"),
        ("example.co.uk", "example.co.uk"),
        ("co.uk", "co.uk"),
        ("a.b.github.io", "b.github.io"),
        ("github.io", "github.io"),
        ("x.www.ck", "www.ck"),
        ("www.ck", "www.ck"),
        ("a.b.c.ck", "b.c.ck"),
        ("localhost", "localhost"),
        ("192.168.0.1", "192.168.0.1"),
        ("::1", "::1"),
        ("a.b.kawasaki.jp", "a.b.kawasaki.jp"),
        ("city.kawasaki.jp", "city.kawasaki.jp"),
        ("x.city.kawasaki.jp", "city.kawasaki.jp"),
        ("acct.z1.web.core.windows.net", "acct.z1.web.core.windows.net"),
        ("foo.unknowntld", "foo.unknowntld"),
        ("a.xn--r8jz45g.xn--zckzah", "xn--r8jz45g.xn--zckzah"),
        ("xn--zckzah", "xn--zckzah"),
        ("b.a.xn--55qx5d.cn", "a.xn--55qx5d.cn"),
        ("EXAMPLE.COM.", "example.com"),
        ("q.blogspot.com", "q.blogspot.com"),
    ]
}
