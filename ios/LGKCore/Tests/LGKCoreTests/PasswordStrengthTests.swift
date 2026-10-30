import Foundation
import XCTest
@testable import LGKCore

/// Pins `PasswordStrength` to the desktop's `password_tools.estimate_strength`
/// (tests/vectors/strength/vectors.json, written by scripts/gen_strength_vectors.py).
final class PasswordStrengthTests: XCTestCase {

    private struct Vector: Decodable {
        let password: String
        let score: Int
        let guesses_log10: Double
    }

    private func vectors() throws -> [Vector] {
        var u = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { u.deleteLastPathComponent() }
        let file = u.appendingPathComponent("tests/vectors/strength/vectors.json")
        return try JSONDecoder().decode([Vector].self, from: Data(contentsOf: file))
    }

    func testMatchesPythonVectors() throws {
        let all = try vectors()
        XCTAssertGreaterThanOrEqual(all.count, 300)
        var failures = 0
        for v in all {
            let got = PasswordStrength.estimate(v.password)
            let log = log10(got.guesses)
            if got.score != v.score || abs(log - v.guesses_log10) > 0.01 {
                failures += 1
                XCTFail("\(v.password.debugDescription): score \(got.score) vs \(v.score), log10 \(log) vs \(v.guesses_log10)")
            }
        }
        XCTAssertEqual(failures, 0)
    }

    func testKnownScores() {
        XCTAssertEqual(PasswordStrength.estimate("password").score, 0)
        XCTAssertEqual(PasswordStrength.estimate("abc123").score, 0)
        XCTAssertEqual(PasswordStrength.estimate("Summer2024!").score, 2)
        XCTAssertEqual(PasswordStrength.estimate("Tr0ub4dor&3").score, 4)
        XCTAssertEqual(PasswordStrength.estimate("correct horse battery staple").score, 4)
        XCTAssertEqual(PasswordStrength.estimate("").guesses, 1)
    }

    func testListsMatchDesktopSizes() {
        XCTAssertEqual(StrengthLists.common.count, 640)
        XCTAssertEqual(StrengthLists.common.first, "123456")
        XCTAssertEqual(StrengthLists.wordRank, 5017)
    }
}
