import XCTest
#if os(iOS)
import PDFKit
@testable import LocalGateKeys
#endif

/// The printable emergency kit shared by the iPhone and the Mac (compiled into both test bundles): blank boxes without
/// a phrase, the 24 words only in the boxes with one, and no password value anywhere.
@MainActor
final class EmergencyKitDocumentTests: XCTestCase {
    private let phone = EmergencyKitDocument.Facts(kind: .phone, date: "3 November 2026", appVersion: "1.1")
    private let mac = EmergencyKitDocument.Facts(
        kind: .mac(machine: "Test Mac", vaultFolder: "/Users/test/Vault", backupFolders: ["/Users/test/Backups/Scheduled", "/Volumes/Cloud/Mirror"]),
        date: "3 November 2026", appVersion: "1.1")
    /// Not English words, so a hit in the fixed text would be a leak.
    private let words = (1...24).map { String(format: "qzx%02dword", $0) }

    private func boxes(_ blocks: [EmergencyKitDocument.Block]) -> [EmergencyKitDocument.Box] {
        blocks.flatMap { block -> [EmergencyKitDocument.Box] in
            if case .phraseBoxes(let boxes) = block { return boxes }
            return []
        }
    }

    /// Every piece of text outside the phrase boxes.
    private func fixedText(_ blocks: [EmergencyKitDocument.Block]) -> String {
        blocks.compactMap { block -> String? in
            switch block {
            case .title(let t), .paragraph(let t), .heading(let t), .warning(let t), .blankLine(let t): return t
            case .fact(let label, let values): return ([label] + values).joined(separator: "\n")
            case .steps(let items): return items.joined(separator: "\n")
            case .phraseBoxes: return nil
            }
        }.joined(separator: "\n")
    }

    func testKitWithoutPhraseHasBlankBoxes() {
        for facts in [phone, mac] {
            let blocks = EmergencyKitDocument.build(facts, words: nil)
            let kit = boxes(blocks)
            XCTAssertEqual(kit.map(\.number), Array(1...24))
            XCTAssertTrue(kit.allSatisfy { $0.word.isEmpty })
            let text = EmergencyKitDocument.attributedText(blocks).string
            XCTAssertFalse(text.contains("qzx"))
            XCTAssertTrue(text.contains(String(repeating: "_", count: 14)))
        }
    }

    func testKitWithPhraseHas24Words() {
        for facts in [phone, mac] {
            let blocks = EmergencyKitDocument.build(facts, words: words)
            XCTAssertEqual(boxes(blocks).map(\.word), words)
            let text = EmergencyKitDocument.attributedText(blocks).string
            for word in words { XCTAssertTrue(text.contains(word)) }
        }
        // A shorter list leaves the rest blank; extra words are ignored.
        XCTAssertEqual(boxes(EmergencyKitDocument.build(phone, words: Array(words.prefix(3)))).filter { !$0.word.isEmpty }.count, 3)
        XCTAssertEqual(boxes(EmergencyKitDocument.build(phone, words: words + ["qzxextra"])).count, 24)
    }

    func testKitHasNoPasswordValue() {
        for facts in [phone, mac] {
            let blocks = EmergencyKitDocument.build(facts, words: words)
            // The words are only in the boxes; the password line is a label with a blank line to write on.
            let fixed = fixedText(blocks)
            for word in words { XCTAssertFalse(fixed.contains(word)) }
            XCTAssertEqual(blocks.filter { if case .blankLine = $0 { return true } else { return false } }.count, 1)
            // A box never prints its word in a log line.
            let logged = "\(boxes(blocks)[0]) \(String(reflecting: boxes(blocks)[0]))"
            XCTAssertFalse(logged.contains("qzx01word"))
        }
    }

    func testMacKitListsVaultAndBackupFolders() {
        let text = fixedText(EmergencyKitDocument.build(mac, words: nil))
        XCTAssertTrue(text.contains("/Users/test/Vault"))
        XCTAssertTrue(text.contains("/Users/test/Backups/Scheduled"))
        XCTAssertTrue(text.contains("/Volumes/Cloud/Mirror"))
        // No folders yet: the kit says so instead of leaving the line empty.
        let none = EmergencyKitDocument.Facts(kind: .mac(machine: "Mac", vaultFolder: "/v", backupFolders: []), date: "d", appVersion: "1")
        let said = EmergencyKitDocument.build(none, words: nil).contains { block in
            if case .fact(_, let values) = block { return values == [String(localized: "None yet")] }
            return false
        }
        XCTAssertTrue(said)
    }

    #if os(iOS)
    func testPDFIsPaginatedAndNeverOverflows() throws {
        let data = EmergencyKitDocument.pdf(EmergencyKitDocument.build(phone, words: words))
        let document = try XCTUnwrap(PDFDocument(data: data))
        XCTAssertGreaterThanOrEqual(document.pageCount, 1)
        XCTAssertTrue((document.string ?? "").contains("qzx24word"))
        // Many long folders push text onto more pages; every word is still printed.
        let folders = (0..<80).map { "/Users/test/Backups/a-rather-long-folder-name-number-\($0)/Scheduled" }
        let long = EmergencyKitDocument.Facts(kind: .mac(machine: "Mac", vaultFolder: "/v", backupFolders: folders), date: "d", appVersion: "1")
        let many = try XCTUnwrap(PDFDocument(data: EmergencyKitDocument.pdf(EmergencyKitDocument.build(long, words: words))))
        XCTAssertGreaterThan(many.pageCount, 1)
        XCTAssertTrue((many.string ?? "").contains("qzx24word"))
    }
    #endif
}
