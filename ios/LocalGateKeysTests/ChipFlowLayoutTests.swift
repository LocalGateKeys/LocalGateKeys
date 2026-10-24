import XCTest
import SwiftUI
@testable import LocalGateKeys

/// The generator's separator chips wrap instead of being clipped at the card edge.
final class ChipFlowLayoutTests: XCTestCase {
    func inside(_ r: (origins: [CGPoint], size: CGSize), _ sizes: [CGSize], width: CGFloat) -> Bool {
        zip(r.origins, sizes).allSatisfy { o, s in o.x >= 0 && o.x + s.width <= width + 0.001 }
    }

    func test_five_chips_fit_on_one_row_when_there_is_room() {
        let sizes = [60, 70, 50, 100, 60].map { CGSize(width: $0, height: 34) }
        let r = ChipFlowLayout.arrange(sizes, width: 400, spacing: 8)
        XCTAssertTrue(r.origins.allSatisfy { $0.y == 0 })
        XCTAssertEqual(r.size.height, 34)
        XCTAssertTrue(inside(r, sizes, width: 400))
    }

    func test_narrow_card_wraps_and_none_is_fully_visible() {
        // About the default text size on an iPhone card (≈ 320 pt of content).
        let sizes = [64, 76, 54, 108, 62].map { CGSize(width: $0, height: 34) }
        let r = ChipFlowLayout.arrange(sizes, width: 320, spacing: 8)
        XCTAssertTrue(inside(r, sizes, width: 320), "no chip crosses the card edge")
        XCTAssertGreaterThan(r.origins[4].y, 0, "None moves to the next row")
        XCTAssertEqual(r.size.height, 34 + 8 + 34)
    }

    func test_accessibility_text_sizes_stack_rows_and_never_overflow() {
        let sizes = [150, 170, 120, 250, 140].map { CGSize(width: $0, height: 60) }
        let r = ChipFlowLayout.arrange(sizes, width: 300, spacing: 8)
        XCTAssertTrue(inside(r, sizes, width: 300))
        XCTAssertEqual(Set(r.origins.map(\.y)).count, 4)   // rows: 150 | 170 120 | 250 | 140
        XCTAssertEqual(r.size.height, CGFloat(Set(r.origins.map(\.y)).count) * 60 + CGFloat(Set(r.origins.map(\.y)).count - 1) * 8)
    }

    func test_empty() {
        XCTAssertEqual(ChipFlowLayout.arrange([], width: 300, spacing: 8).size, .zero)
    }
}
