import XCTest
@testable import LGKCore

/// `tests/vectors/markdown/cases.json`: the Markdown subset for notes. Every platform parser returns exactly
/// the vector's nodes. Mirror of Kotlin `NoteMarkdownTest`.
final class NoteMarkdownTests: XCTestCase {
    struct Case: Decodable {
        let name: String
        let input: String
        let nodes: [MDNode]
    }

    func testVectors() throws {
        let data = try Data(contentsOf: Vectors.shared("markdown/cases.json"))
        let cases = try JSONDecoder().decode([Case].self, from: data)
        XCTAssertGreaterThanOrEqual(cases.count, 35)
        for c in cases {
            XCTAssertEqual(NoteMarkdown.parse(c.input), c.nodes, "vector \(c.name)")
        }
    }

    func testEmptyInputGivesNoNodes() {
        XCTAssertEqual(NoteMarkdown.parse(""), [])
    }

    /// Every unclosed `*` used to rescan to the end; the skip and closer tables keep it linear.
    func testUnclosedStarsParseInLinearTime() {
        let text = String(repeating: "*a ", count: 6666)
        let start = Date()
        let nodes = NoteMarkdown.parse(text)
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertEqual(nodes, [.paragraph([.text(text)])])
        XCTAssertLessThan(elapsed, 1)
    }
}
