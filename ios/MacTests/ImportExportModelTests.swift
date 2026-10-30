import XCTest
import LGKCore
@testable import AppSharedMac

/// Applies changes like LocalStore (a stale base is refused) and counts the commits.
private final class ExportMemoryStore: ItemStore, @unchecked Sendable {
    var snapshot = StoreSnapshot()
    private(set) var commits = 0
    func load() throws -> StoreSnapshot { snapshot }
    func commit(_ change: StoreChange) throws {
        guard change.baseRevision == snapshot.revision else {
            throw LocalStoreError.stale(expected: change.baseRevision, actual: snapshot.revision)
        }
        snapshot = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: snapshot.revision + 1)
        commits += 1
    }
}

@MainActor
private final class ExportFakeVault: MasterPasswordService {
    let right = "correct horse"
    var hasVault = true
    var isUnlocked = true
    var touchIDAvailable = true
    func verifyPassword(_ password: String) async throws {
        guard password == right else { throw MacVaultError.wrongPassword(retryAfter: nil) }
    }
    func changePassword(old: String, new: String) async throws {}
    func setTouchID(_ on: Bool, password: String) async throws {}
}

/// The Mac Import & export page: detection opens the review, encrypted files ask for their password, a generic
/// CSV asks for its columns, `.lgkm` and CSV export (CSV only after the plain-text warning and the master
/// password), phone backup restore through the review sheet (merge, never wipe), Apple Passwords on macOS 26.
@MainActor
final class ImportExportModelTests: XCTestCase {
    private static let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../..").standardized
    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-import-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    private func file(_ name: String, _ text: String) throws -> URL {
        let url = dir.appendingPathComponent(name)
        try Data(text.utf8).write(to: url)
        return url
    }

    private func model(_ store: ExportMemoryStore, isPro: Bool = true, vault: ExportFakeVault = ExportFakeVault(),
                       installID: String = "mac-install-1",
                       local: InMemoryLocalData? = nil,
                       blobs: (any AttachmentBlobStore)? = nil) -> (ImportExportModel, StrictItemGate) {
        let gate = StrictItemGate(passwords: vault)
        let m = ImportExportModel(store: store, isPro: { isPro }, gate: gate, fallbackDeviceID: { installID },
                                  appVersion: "1.0.0", licenseKeys: [:], local: local, blobs: blobs)
        return (m, gate)
    }

    private static let appleCSV = "Title,URL,Username,Password,Notes,OTPAuth\n"
        + "Example,https://example.com,ada,pw-one,,\nOther,https://other.example,bob,pw-two,,\n"

    func testDetectsFormatAndOpensReview() async throws {
        let store = ExportMemoryStore()
        let (m, _) = model(store)
        await m.importFile(url: try file("Passwords.csv", Self.appleCSV))
        let review = try XCTUnwrap(m.review)
        XCTAssertEqual(m.reviewSource, "Safari passwords CSV")
        XCTAssertEqual(review.rows.count, 2)
        XCTAssertEqual(store.commits, 0, "nothing is written before the review is accepted")
        let outcome = await m.commitReview()
        XCTAssertEqual(outcome?.created, 2)
        XCTAssertNil(m.review)
        XCTAssertEqual(store.snapshot.records.count, 2)
        XCTAssertNotNil(m.message)
    }

    func testUnknownFileIsRefused() async throws {
        let (m, _) = model(ExportMemoryStore())
        await m.importFile(url: try file("export.pgp", "-----BEGIN PGP MESSAGE-----\nabc\n"))
        XCTAssertNil(m.review)
        XCTAssertEqual(m.message, ImportError.unknownFormat.message)
    }

    func testEncryptedFileAsksPassword() async throws {
        let (m, _) = model(ExportMemoryStore())
        let url = Self.repo.appendingPathComponent("tests/vectors/import/_inputs/bitwarden_pbkdf2.json")
        await m.importFile(url: url)
        XCTAssertNil(m.review)
        let request = try XCTUnwrap(m.passwordRequest)
        XCTAssertEqual(request.prompt, ImportReviewModel.passwordPrompt(for: .bitwardenEncrypted))
        await m.submitPassword("not the password")
        XCTAssertNotNil(m.passwordRequest, "a wrong password asks again")
        XCTAssertEqual(m.passwordRequest?.error, ImportError.wrongPassword.message)
        await m.submitPassword("fixture export password")
        XCTAssertNil(m.passwordRequest)
        XCTAssertNotNil(m.review)
    }

    func testGenericCSVShowsMapping() async throws {
        let (m, _) = model(ExportMemoryStore())
        await m.importFile(url: try file("custom.csv", "Site,Login,Secret\nhttps://shop.example,ada,pw\n"))
        XCTAssertNil(m.review)
        let mapping = try XCTUnwrap(m.mappingRequest)
        XCTAssertEqual(mapping.header, ["Site", "Login", "Secret"])
        XCTAssertEqual(mapping.mapping.url, 0)
        XCTAssertEqual(mapping.mapping.username, 1)
        XCTAssertEqual(mapping.mapping.password, 2)
        await m.applyMapping(mapping.mapping)
        XCTAssertNil(m.mappingRequest)
        XCTAssertEqual(m.review?.rows.count, 1)
    }

    func testExportLGKMReadableByPhoneBackupOpen() async throws {
        let store = ExportMemoryStore()
        let (m, _) = model(store)
        await m.importFile(url: try file("Passwords.csv", Self.appleCSV))
        _ = await m.commitReview()
        let out = dir.appendingPathComponent("LocalGateKeys.lgkm")
        let short = await m.exportEncrypted(to: out, password: "short")
        XCTAssertFalse(short)
        XCTAssertFalse(FileManager.default.fileExists(atPath: out.path))
        // Not without the master password (the model enforces the gate itself).
        let ungated = await m.exportEncrypted(to: out, password: "a long backup password")
        XCTAssertFalse(ungated)
        XCTAssertFalse(FileManager.default.fileExists(atPath: out.path))
        let (m2, gate) = model(store)
        XCTAssertTrue(m2.requestEncryptedExport(password: "a long backup password",
                                                confirmation: "a long backup password", choose: { out }))
        // A second request while the prompt is open is refused with a message, not dropped silently.
        XCTAssertFalse(m2.requestEncryptedExport(password: "a long backup password",
                                                 confirmation: "a long backup password", choose: { out }))
        XCTAssertEqual(m2.exportMessage, ImportExportModel.promptBusyMessage)
        await gate.submit("correct horse")
        let ok = await m2.exportTask?.value ?? false
        XCTAssertTrue(ok)
        let backup = try PhoneBackup.open(Data(contentsOf: out), password: "a long backup password")
        XCTAssertEqual(Set(backup.states.map(\.id)), Set(store.snapshot.records.keys))
        XCTAssertEqual(backup.platform, "ios")
        // A backup made on this Mac restores nothing here (it is this Mac's own data).
        _ = await m2.restorePhoneBackup(url: out, password: "a long backup password")
        XCTAssertNil(m.restore)
        XCTAssertEqual(m2.message, ImportExportModel.sameDeviceMessage)
    }

    func testCSVExportNeedsConfirmation() async throws {
        let store = ExportMemoryStore()
        let (m, gate) = model(store)
        await m.importFile(url: try file("Passwords.csv", Self.appleCSV))
        _ = await m.commitReview()
        let out = dir.appendingPathComponent("export.csv")
        // Not without the plain-text warning and the master password.
        let direct = await m.exportCSV(to: out)
        XCTAssertFalse(direct)
        XCTAssertFalse(FileManager.default.fileExists(atPath: out.path))
        m.requestCSVExport()
        XCTAssertTrue(m.confirmingCSV)
        XCTAssertTrue(ImportExportModel.csvWarning.contains("plain text"))
        m.acceptCSVWarning(choose: { out })
        let request = try XCTUnwrap(gate.pending, "the master password is asked")
        XCTAssertFalse(request.offersTouchID)
        XCTAssertEqual(request.level, .strict)
        await gate.submit("wrong")
        XCTAssertFalse(FileManager.default.fileExists(atPath: out.path))
        await gate.submit("correct horse")
        _ = await m.exportTask?.value
        let text = try String(contentsOf: out, encoding: .utf8)
        XCTAssertTrue(text.hasPrefix("Title,URL,Username,Password,Notes,OTPAuth"))
        XCTAssertTrue(text.contains("pw-one"))
        // The confirmation is used once.
        try FileManager.default.removeItem(at: out)
        let again = await m.exportCSV(to: out)
        XCTAssertFalse(again)
    }

    func testRestoreIOSAndAndroidVectors() async throws {
        let store = ExportMemoryStore()
        let (m, _) = model(store)
        for dir in ["from_ios", "from_android"] {
            let url = Self.repo.appendingPathComponent("tests/vectors/backup/\(dir)/backup.lgkm")
            let wrong = await m.restorePhoneBackup(url: url, password: "wrong")
            XCTAssertNil(wrong)
            XCTAssertEqual(m.passwordRequest?.error, ImportExportModel.wrongBackupPassword)
            let planned = await m.restorePhoneBackup(url: url, password: "correct horse battery staple 42")
            XCTAssertNotNil(planned, dir)
            let preview = try XCTUnwrap(m.restore, dir)
            XCTAssertFalse(preview.lines.isEmpty)
            XCTAssertEqual(store.commits, dir == "from_ios" ? 0 : 1, "nothing is written before Restore")
            let before = Set(store.snapshot.records.keys)
            let done = await m.commitRestore()
            XCTAssertNotNil(done, dir)
            XCTAssertNil(m.restore)
            XCTAssertTrue(before.isSubset(of: Set(store.snapshot.records.keys)), "a restore never wipes")
        }
        XCTAssertTrue(store.snapshot.meta.values.contains(where: \.deleted), "tombstones are kept")
    }

    func testRestoreMovesPhoneDeletionsToRecentlyDeleted() async throws {
        let store = ExportMemoryStore()
        let id = "44444444-aaaa-4000-8000-000000000004"   // tombstoned in the vectors with vv {A: 1, C: 1}
        let note: JSONValue = .object(["ns": .string("item"), "schema": .int(1), "updated_at": .int(1_789_000_000),
                                       "record": .object(["id": .string(id), "kind": .string("note"), "title": .string("Old note"),
                                                          "favorite": .bool(false), "tags": .array([]),
                                                          "created_at": .int(1_789_000_000), "updated_at": .int(1_789_000_000),
                                                          "payload": .object(["body": .string("x"), "fields": .array([]),
                                                                              "template_id": .null])])])
        // Held on this Mac at the phone's older version (device A, counter 1), so the phone's delete wins.
        let view = try SyncMeta.localView(records: [id: note], meta: [:], device: "a1111111-0000-4000-8000-00000000000a",
                                          now: 1_789_000_000)
        store.snapshot = StoreSnapshot(records: [id: note], meta: view.meta, revision: 1)
        let local = InMemoryLocalData()
        let (m, _) = model(store, local: local)
        let url = Self.repo.appendingPathComponent("tests/vectors/backup/from_ios/backup.lgkm")
        _ = await m.restorePhoneBackup(url: url, password: "correct horse battery staple 42")
        XCTAssertTrue(m.restore?.lines.contains("1 items moved to Recently deleted (deleted on the phone)") ?? false,
                      "\(m.restore?.lines ?? [])")
        let done = await m.commitRestore()
        XCTAssertNotNil(done)
        XCTAssertNil(store.snapshot.records[id], "deleted in the vault, as the phone did")
        let trash = try XCTUnwrap(local.localData?.trash)
        XCTAssertEqual(trash.count, 1, "kept in Recently deleted, not purged")
        XCTAssertEqual((try trash[0].record()).objectValue?["id"], .string(id))
    }

    func testRestoreFormat2StoresTheDocumentFile() async throws {
        let store = ExportMemoryStore()
        let blobs = BlobFolder(root: dir)
        let (m, _) = model(store, blobs: blobs)
        let url = Self.repo.appendingPathComponent("tests/vectors/backup/format2/backup.lgkm")
        let planned = await m.restorePhoneBackup(url: url, password: "correct horse battery staple 42")
        XCTAssertNotNil(planned)
        let lines = try XCTUnwrap(m.restore?.lines)
        XCTAssertTrue(lines.contains("1 document files from the backup"), "\(lines)")
        XCTAssertTrue(blobs.ids().isEmpty, "the preview stores nothing")
        let done = await m.commitRestore()
        XCTAssertNotNil(done)
        XCTAssertEqual(blobs.ids(), ["ed412dc40eb91d245ba4f0a9332e5e97c0802388ed585c73f3ee2cc51275aaa2"])
        let doc = try XCTUnwrap(store.snapshot.records["88888888-aaaa-4000-8000-000000000008"])
        XCTAssertEqual(try AttachmentDocuments.open(doc, blobs: blobs).data.count, 24)   // the "small" attachment vector
        XCTAssertTrue(m.message?.contains("1 document files restored.") ?? false, m.message ?? "")
    }

    func testRestoreWithoutAttachmentStoreLeavesDocumentOut() async throws {
        let store = ExportMemoryStore()
        let (m, _) = model(store)
        let url = Self.repo.appendingPathComponent("tests/vectors/backup/format2/backup.lgkm")
        _ = await m.restorePhoneBackup(url: url, password: "correct horse battery staple 42")
        _ = await m.commitRestore()
        XCTAssertNil(store.snapshot.records["88888888-aaaa-4000-8000-000000000008"])
        XCTAssertTrue(m.message?.contains("1 document was not restored: its file is not in this backup.") ?? false,
                      m.message ?? "")
    }

    func testPreviewLinesCountMissingFiles() {
        XCTAssertEqual(ImportExportModel.missingFilesLine(2, future: true),
                       "2 documents will not be restored: their files are not in this backup")
        XCTAssertEqual(ImportExportModel.fileLines(stored: 1, refused: 1, missing: 0),
                       " 1 document files restored. 1 document files were damaged and not restored.")
    }

    func testCXFHiddenBelowMacOS26() {
        XCTAssertFalse(ImportExportModel.showsApplePasswords(OperatingSystemVersion(majorVersion: 15, minorVersion: 7, patchVersion: 0)))
        XCTAssertFalse(ImportExportModel.showsApplePasswords(OperatingSystemVersion(majorVersion: 14, minorVersion: 0, patchVersion: 0)))
        XCTAssertTrue(ImportExportModel.showsApplePasswords(OperatingSystemVersion(majorVersion: 26, minorVersion: 0, patchVersion: 0)))
    }
}
