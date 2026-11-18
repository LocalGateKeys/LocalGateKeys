import XCTest
import LGKCore
#if os(iOS)
import PDFKit
@testable import LocalGateKeys
#endif

/// The vault health report (sub-plan 12, compiled into the iPhone and Mac test bundles): the KDF memory in MiB and
/// every row are there, and nothing that names an item.
@MainActor
final class HealthReportTests: XCTestCase {
    private let input = HealthReport.Input(
        kdfMemoryKiB: 65_536, factors: ["Master password", "Touch ID"],
        lastBackup: Date(timeIntervalSince1970: 1_790_000_000), restoreTest: "Passed on 1 Nov 2026, 12 items",
        pairedDevices: 2, lastSync: Date(timeIntervalSince1970: 1_790_050_000), accessLog: nil,
        breachFilterUpdated: nil, build: "1.4.0", isPro: true, now: Date(timeIntervalSince1970: 1_790_100_000))

    private func text(_ blocks: [EmergencyKitDocument.Block]) -> String {
        blocks.compactMap { block -> String? in
            switch block {
            case .title(let t), .paragraph(let t), .heading(let t), .warning(let t), .blankLine(let t): return t
            case .fact(let label, let values): return ([label] + values).joined(separator: "\n")
            case .steps(let items): return items.joined(separator: "\n")
            case .phraseBoxes: return nil
            }
        }.joined(separator: "\n")
    }

    func testKDFMemoryInMiB() {
        let rows = HealthReport.rows(input)
        XCTAssertEqual(rows.count, 10)
        XCTAssertTrue(rows[0].value.contains("64"), rows[0].value)
        XCTAssertTrue(rows[0].value.contains("MiB"), rows[0].value)
        XCTAssertEqual(rows[2].value, "1")   // days since the last backup
        XCTAssertEqual(rows[4].value, "2")   // paired devices
        XCTAssertTrue(rows.contains { $0.value == "1.4.0" })
        XCTAssertTrue(rows.contains { $0.value == "Pro" })
    }

    func testNoTitleOrSecret() {
        let blocks = HealthReport.blocks(input)
        let all = text(blocks)
        for leak in ["Bank login", "hunter2", "alice@example.com", "example.com"] {
            XCTAssertFalse(all.contains(leak), leak)
        }
        XCTAssertFalse(blocks.contains { if case .phraseBoxes = $0 { return true }; return false })
        if case .title(let t)? = blocks.first { XCTAssertEqual(t, HealthReport.title) } else { XCTFail("no title block") }
    }

    #if os(iOS)
    func testOnePagePDF() throws {
        let document = try XCTUnwrap(PDFDocument(data: EmergencyKitDocument.pdf(HealthReport.blocks(input))))
        XCTAssertEqual(document.pageCount, 1)
    }
    #endif
}
