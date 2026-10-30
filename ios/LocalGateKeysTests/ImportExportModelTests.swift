import XCTest
import UniformTypeIdentifiers
import AppShared
@testable import LocalGateKeys

/// The iPhone Import & Export page: every format the Mac reads is detected and opens the review; encrypted
/// files ask for their password, a generic CSV asks for its columns; nothing is written before Import.
@MainActor
final class ImportExportModelTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    /// The repo root: LocalGateKeysTests -> ios -> repo (the simulator reads the host's files).
    private static let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()

    func model(_ store: MemoryStore, isPro: Bool = true, afterCommit: @escaping () -> Void = {}) -> ImportExportModel {
        ImportExportModel(importer: VaultImporter(store: store, isPro: { isPro }, now: { [now] in now },
                                                  random: SystemRandomSource(), afterCommit: afterCommit))
    }

    func tempFile(_ text: String, name: String = UUID().uuidString + ".csv") throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        try Data(text.utf8).write(to: url)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }

    private func fixture(_ path: String) -> URL { Self.repo.appendingPathComponent(path) }

    func testAppleCSVOpensReviewThenImports() async throws {
        let store = MemoryStore()
        var committed = 0
        let m = model(store, afterCommit: { committed += 1 })
        let url = try tempFile("Title,URL,Username,Password,Notes,OTPAuth\nExample,https://example.com,ada,pw,,\n")
        await m.importFile(url: url)
        let review = try XCTUnwrap(m.review)
        XCTAssertEqual(m.reviewSource, ImportReviewModel.formatLabel(.appleCSV))
        XCTAssertEqual(review.rows.count, 1)
        XCTAssertEqual(store.commits, 0, "nothing is written before the review is accepted")
        XCTAssertTrue(m.hasImportStep)
        let out = await m.commitReview()
        XCTAssertEqual(out?.created, 1)
        XCTAssertNil(m.review)
        XCTAssertFalse(m.hasImportStep)
        XCTAssertEqual(store.commits, 1)
        XCTAssertEqual(committed, 1, "the sync is told about the import")
        XCTAssertEqual(m.message, "1 record(s) written. Added 1, updated 0, skipped 0.")
    }

    /// One fixture per format the Mac imports (the LGKCore vectors' inputs), through the iPhone path into review rows.
    func testEveryFormatFixtureOpensReview() async throws {
        let cases: [(path: String, format: ImportFormat, password: String?)] = [
            ("tests/fixtures/imports/safari.csv", .appleCSV, nil),
            ("tests/fixtures/imports/chrome.csv", .chrome, nil),
            ("tests/fixtures/imports/firefox.csv", .firefox, nil),
            ("tests/fixtures/imports/bitwarden.json", .bitwarden, nil),
            ("tests/fixtures/imports/bitwarden.csv", .bitwarden, nil),
            ("tests/fixtures/imports/bitwarden_protected.json", .bitwardenEncrypted, "fixture export password"),
            ("tests/vectors/import/_inputs/onepassword.1pux", .onePassword1PUX, nil),
            ("tests/fixtures/imports/onepassword.csv", .onePasswordCSV, nil),
            ("tests/fixtures/imports/lastpass.csv", .lastPass, nil),
            ("tests/vectors/import/_inputs/dashlane_export.zip", .dashlane, nil),
            ("tests/vectors/import/_inputs/kdbx4_chacha_argon2id.kdbx", .keePassKDBX, "kdbx fixture password"),
            ("tests/vectors/import/_inputs/kdbx3_keepass.kdbx", .keePassKDBX, "kdbx fixture password"),
            ("tests/fixtures/imports/keepass.xml", .keePassXML, nil),
            ("tests/fixtures/imports/keepassxc.csv", .keePassCSV, nil),
            ("tests/fixtures/imports/protonpass/Proton Pass/data.json", .protonPass, nil),
            ("tests/vectors/import/_inputs/protonpass_export.zip", .protonPass, nil),
        ]
        for c in cases {
            let store = MemoryStore()
            let m = model(store)
            await m.importFile(url: fixture(c.path))
            if let password = c.password {
                let request = try XCTUnwrap(m.passwordRequest, c.path)
                XCTAssertEqual(request.prompt, ImportReviewModel.passwordPrompt(for: c.format), c.path)
                XCTAssertNil(m.review, c.path)
                await m.submitPassword(password)
            }
            XCTAssertNil(m.passwordRequest, c.path)
            let review = try XCTUnwrap(m.review, "\(c.path): \(m.message ?? "no review")")
            XCTAssertEqual(m.reviewSource, ImportReviewModel.formatLabel(c.format), c.path)
            XCTAssertFalse(review.rows.isEmpty, c.path)
            XCTAssertEqual(store.commits, 0, c.path)
            let out = await m.commitReview()
            XCTAssertGreaterThan(out?.created ?? 0, 0, "\(c.path): \(m.message ?? "")")
        }
    }

    func testSameFileTwiceAddsNothing() async throws {
        let store = MemoryStore()
        let m = model(store)
        await m.importFile(url: fixture("tests/fixtures/imports/bitwarden.json"))
        _ = await m.commitReview()
        let commits = store.commits
        await m.importFile(url: fixture("tests/fixtures/imports/bitwarden.json"))
        let review = try XCTUnwrap(m.review)
        XCTAssertFalse(review.rows.contains { $0.decision != .skip }, "every row is already here and defaults to Skip")
        XCTAssertEqual(store.commits, commits)
    }

    func testWrongPasswordAsksAgain() async throws {
        let m = model(MemoryStore())
        await m.importFile(url: fixture("tests/vectors/import/_inputs/bitwarden_pbkdf2.json"))
        XCTAssertNotNil(m.passwordRequest)
        await m.submitPassword("not the password")
        XCTAssertNotNil(m.passwordRequest, "a wrong password asks again")
        XCTAssertEqual(m.passwordRequest?.error, ImportError.wrongPassword.message)
        XCTAssertNil(m.review)
        await m.submitPassword("fixture export password")
        XCTAssertNil(m.passwordRequest)
        XCTAssertNotNil(m.review)
    }

    func testKDBXWrongPasswordAsksAgain() async throws {
        let m = model(MemoryStore())
        await m.importFile(url: fixture("tests/vectors/import/_inputs/kdbx4_chacha_argon2id.kdbx"))
        XCTAssertEqual(m.passwordRequest?.prompt, ImportReviewModel.passwordPrompt(for: .keePassKDBX))
        await m.submitPassword("wrong kdbx password")
        XCTAssertNotNil(m.passwordRequest?.error)
        XCTAssertNil(m.review)
    }

    func testCancelDropsThePendingFile() async throws {
        let m = model(MemoryStore())
        await m.importFile(url: fixture("tests/fixtures/imports/bitwarden_protected.json"))
        XCTAssertTrue(m.hasImportStep)
        m.reset()
        XCTAssertFalse(m.hasImportStep)
        await m.submitPassword("fixture export password")
        XCTAssertNil(m.review, "nothing is held after Cancel")
    }

    func testGenericCSVAsksForColumns() async throws {
        let m = model(MemoryStore())
        await m.importFile(url: try tempFile("Site,Login,Secret\nhttps://shop.example,ada,pw\n"))
        XCTAssertNil(m.review)
        let request = try XCTUnwrap(m.mappingRequest)
        XCTAssertEqual(request.header, ["Site", "Login", "Secret"])
        XCTAssertEqual(request.mapping.password, 2)
        await m.applyMapping(request.mapping)
        XCTAssertNil(m.mappingRequest)
        XCTAssertEqual(m.review?.rows.count, 1)
        XCTAssertEqual(m.reviewSource, ImportReviewModel.formatLabel(.generic))
    }

    func testUnknownFileMessage() async throws {
        let m = model(MemoryStore())
        await m.importFile(url: try tempFile("-----BEGIN PGP MESSAGE-----\nabc\n", name: UUID().uuidString + ".txt"))
        XCTAssertNil(m.review)
        XCTAssertFalse(m.hasImportStep)
        XCTAssertEqual(m.message, ImportExportModel.unknownFormatMessage)
        XCTAssertFalse(ImportExportModel.unknownFormatMessage.contains("desktop app"))
    }

    func testFreePlanLimitsRows() async throws {
        let m = model(MemoryStore(), isPro: false)
        await m.importFile(url: fixture("tests/fixtures/imports/bitwarden.json"))
        let review = try XCTUnwrap(m.review)
        XCTAssertEqual(review.freeSlots, ItemLimit.freeItems)
        if review.rows.filter({ $0.decision != .skip }).count > ItemLimit.freeItems {
            XCTAssertTrue(review.rows.contains(where: \.limited))
        }
    }

    func testOversizeFileRefused() async throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".csv")
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let h = try FileHandle(forWritingTo: url)
        try h.truncate(atOffset: UInt64(ImportExportModel.maxFileBytes + 1))
        try h.close()
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        let m = model(MemoryStore())
        await m.importFile(url: url)
        XCTAssertNil(m.review)
        XCTAssertEqual(m.message, ImportError.tooLarge.message)
    }

    func testPickerAllowsEveryExportType() {
        let types = ImportExportModel.importTypes
        for ext in ["csv", "json", "xml", "zip", "1pux", "kdbx"] {
            let t = UTType(filenameExtension: ext)
            XCTAssertTrue(types.contains { t?.conforms(to: $0) ?? false }, ext)
        }
    }
}
