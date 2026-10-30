import XCTest
@testable import LGKCore

/// `mac/licence_text.json` (scripts/gen_licence_text_vectors.py): desktop `parse_license_text`,
/// `verify_bundle` and `licence_link.key_from_link` outcomes.
final class LicenceTextTests: XCTestCase {
    func vector() throws -> [String: JSONValue] {
        guard case .object(let o) = try CanonicalJSON.parse(Array(Vectors.data("mac/licence_text.json"))) else {
            throw JSONError.syntax
        }
        return o
    }

    func keys(_ o: [String: JSONValue]) throws -> [String: [UInt8]] {
        [MergeVectors.str(o["key_id"])!: try Base64.decodeStrict(MergeVectors.str(o["public_key_b64"])!)]
    }

    /// The parse reason, then the verify reason (or the licence id when it verifies).
    func outcome(_ text: String, _ keys: [String: [UInt8]]) -> (String, String?) {
        let bundle: JSONValue
        do { bundle = try LicenceText.parse(text) } catch { return ((error as? LicenseError)?.reason ?? "\(error)", nil) }
        do { return ("ok", try License.verify(bundle: bundle, keys: keys).licenseID) } catch {
            return ("ok", (error as? LicenseError)?.reason ?? "\(error)")
        }
    }

    func test_texts_match_the_desktop() throws {
        let o = try vector(), k = try keys(o)
        let rows = MergeVectors.arr(o["texts"])
        XCTAssertGreaterThanOrEqual(rows.count, 15)
        for row in rows {
            let c = MergeVectors.obj(row), name = MergeVectors.str(c["name"])!
            let got = outcome(MergeVectors.str(c["text"])!, k)
            XCTAssertEqual(got.0, MergeVectors.str(c["parse"]), name)
            if got.0 == "ok" {
                let want = MergeVectors.str(c["verify"]) == "ok" ? MergeVectors.str(c["license_id"]) : MergeVectors.str(c["verify"])
                XCTAssertEqual(got.1, want, name)
            }
        }
    }

    func test_links_match_the_desktop() throws {
        let o = try vector(), k = try keys(o)
        XCTAssertEqual(o["max_link_chars"], .int(Int64(LicenceText.maxLinkChars)))
        for row in MergeVectors.arr(o["links"]) {
            let c = MergeVectors.obj(row), name = MergeVectors.str(c["name"])!
            let link = MergeVectors.str(c["link"])!
            if case .string(let want)? = c["key"] {
                XCTAssertEqual(try LicenceText.key(fromLink: link), want, name)
                let got = outcome(want, k)
                XCTAssertEqual(got.0, MergeVectors.str(c["parse"]), name)
            } else {
                XCTAssertThrowsError(try LicenceText.key(fromLink: link), name) {
                    XCTAssertEqual(($0 as? LicenseError)?.reason, "bad-link", name)
                }
            }
        }
    }

    func test_encode_paste_round_trips_and_matches_the_vector() throws {
        let o = try vector()
        let paste = MergeVectors.str(MergeVectors.obj(MergeVectors.arr(o["texts"])[0])["text"])!
        let bundle = try LicenceText.parse(paste)
        XCTAssertEqual(try LicenceText.encodePaste(bundle), paste)
    }

    func test_holder_line() {
        XCTAssertEqual(LicenceText.holder(name: "Ada Lovelace", email: "ada@example.com"), "Ada Lovelace (ada@example.com)")
        XCTAssertEqual(LicenceText.holder(name: "ada@example.com", email: "ada@example.com"), "ada@example.com")
    }
}
