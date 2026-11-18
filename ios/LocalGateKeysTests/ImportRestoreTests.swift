import XCTest
import AppShared
@testable import LocalGateKeys

/// Restoring an encrypted phone backup (`.lgkm`) on the iPhone, as the Mac's `ImportExportModelTests` restore
/// tests: iPhone and Android vectors, preview before Restore, merge (never a wipe), deletions to Recently deleted,
/// document files (format 2), the same-device rule (refused into a vault with data, restored into an empty one)
/// and the free-plan limit.
@MainActor
final class ImportRestoreTests: XCTestCase {
    private static let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
    private static let password = "correct horse battery staple 42"
    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-restore-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    private func vector(_ name: String) -> URL { Self.repo.appendingPathComponent("tests/vectors/backup/\(name)/backup.lgkm") }

    private func model(_ store: MemoryStore, isPro: Bool = true, installID: String = "iphone-install-1",
                       local: InMemoryPhoneLocal? = nil, blobs: (any AttachmentBlobStore)? = nil,
                       afterCommit: @escaping () -> Void = {}) -> ImportExportModel {
        ImportExportModel(importer: VaultImporter(store: store, isPro: { isPro }, now: { Date(timeIntervalSince1970: 1_800_000_000) },
                                                  random: SystemRandomSource(), afterCommit: afterCommit),
                          fallbackDeviceID: { installID }, local: local, blobs: blobs, licenseKeys: [:])
    }

    func testRestoreIOSAndAndroidVectors() async throws {
        let store = MemoryStore()
        var notified = 0
        let m = model(store, afterCommit: { notified += 1 })
        for name in ["from_ios", "from_android"] {
            let wrong = await m.restorePhoneBackup(url: vector(name), password: "wrong")
            XCTAssertNil(wrong)
            XCTAssertEqual(m.passwordRequest?.error, ImportExportModel.wrongBackupPassword)
            let planned = await m.restorePhoneBackup(url: vector(name), password: Self.password)
            XCTAssertNotNil(planned, name)
            let preview = try XCTUnwrap(m.restore, name)
            XCTAssertFalse(preview.lines.isEmpty)
            XCTAssertTrue(m.hasImportStep, "the preview is on screen")
            XCTAssertEqual(store.commits, name == "from_ios" ? 0 : 1, "nothing is written before Restore")
            let before = Set(store.snapshot.records.keys)
            let done = await m.commitRestore()
            XCTAssertNotNil(done, name)
            XCTAssertNil(m.restore)
            XCTAssertTrue(m.message?.hasPrefix(ImportExportModel.restoredMessage) ?? false, m.message ?? "")
            XCTAssertTrue(before.isSubset(of: Set(store.snapshot.records.keys)), "a restore never wipes")
        }
        XCTAssertTrue(store.snapshot.meta.values.contains(where: \.deleted), "tombstones are kept")
        XCTAssertGreaterThan(notified, 0, "the sync is told about the restore")
    }

    func testImportFileDetectsBackupByExtensionAndContent() async throws {
        let m = model(MemoryStore())
        await m.importFile(url: vector("from_android"))
        XCTAssertEqual(m.passwordRequest?.isPhoneBackup, true)
        XCTAssertEqual(m.passwordRequest?.prompt, ImportExportModel.backupPasswordPrompt)
        await m.submitPassword(Self.password)
        XCTAssertNil(m.passwordRequest)
        XCTAssertNotNil(m.restore)
        m.cancelRestore()
        XCTAssertNil(m.restore)

        // Renamed (no .lgkm extension): found by its content.
        let renamed = dir.appendingPathComponent("backup.bin")
        try FileManager.default.copyItem(at: vector("from_ios"), to: renamed)
        await m.importFile(url: renamed)
        XCTAssertEqual(m.passwordRequest?.isPhoneBackup, true)
        await m.submitPassword("wrong")
        XCTAssertEqual(m.passwordRequest?.error, ImportExportModel.wrongBackupPassword, "a wrong password asks again")
    }

    func testRestoreMovesBackupDeletionsToRecentlyDeleted() async throws {
        let store = MemoryStore()
        let id = "44444444-aaaa-4000-8000-000000000004"   // tombstoned in the vectors with vv {A: 1, C: 1}
        let note: JSONValue = .object(["ns": .string("item"), "schema": .int(1), "updated_at": .int(1_789_000_000),
                                       "record": .object(["id": .string(id), "kind": .string("note"), "title": .string("Old note"),
                                                          "favorite": .bool(false), "tags": .array([]),
                                                          "created_at": .int(1_789_000_000), "updated_at": .int(1_789_000_000),
                                                          "payload": .object(["body": .string("x"), "fields": .array([]),
                                                                              "template_id": .null])])])
        // Held here at the phone's older version (device A, counter 1), so the backup's delete wins.
        let view = try SyncMeta.localView(records: [id: note], meta: [:], device: "a1111111-0000-4000-8000-00000000000a",
                                          now: 1_789_000_000)
        store.snapshot = StoreSnapshot(records: [id: note], meta: view.meta, revision: 1)
        let local = InMemoryPhoneLocal()
        let m = model(store, local: local)
        _ = await m.restorePhoneBackup(url: vector("from_ios"), password: Self.password)
        XCTAssertTrue(m.restore?.lines.contains("1 items moved to Recently deleted (deleted on the phone)") ?? false,
                      "\(m.restore?.lines ?? [])")
        let done = await m.commitRestore()
        XCTAssertNotNil(done)
        XCTAssertNil(store.snapshot.records[id], "deleted in the vault, as the backup did")
        let trash = try XCTUnwrap(local.localData?.trash)
        XCTAssertEqual(trash.count, 1, "kept in Recently deleted, not purged")
        XCTAssertEqual((try trash[0].record()).objectValue?["id"], .string(id))
    }

    func testRestoreWithoutRecentlyDeletedDeletesNothing() async throws {
        let store = MemoryStore()
        let id = "44444444-aaaa-4000-8000-000000000004"
        let note: JSONValue = .object(["ns": .string("item"), "schema": .int(1), "updated_at": .int(1_789_000_000),
                                       "record": .object(["id": .string(id), "kind": .string("note"), "title": .string("Old note"),
                                                          "favorite": .bool(false), "tags": .array([]),
                                                          "created_at": .int(1_789_000_000), "updated_at": .int(1_789_000_000),
                                                          "payload": .object(["body": .string("x"), "fields": .array([]),
                                                                              "template_id": .null])])])
        let view = try SyncMeta.localView(records: [id: note], meta: [:], device: "a1111111-0000-4000-8000-00000000000a",
                                          now: 1_789_000_000)
        store.snapshot = StoreSnapshot(records: [id: note], meta: view.meta, revision: 1)
        let m = model(store)
        _ = await m.restorePhoneBackup(url: vector("from_ios"), password: Self.password)
        let done = await m.commitRestore()
        XCTAssertNil(done)
        XCTAssertEqual(m.message, "Nothing was restored: Recently deleted couldn't be updated.")
        XCTAssertNotNil(store.snapshot.records[id], "the item is never lost from both")
    }

    func testRestoreFormat2StoresTheDocumentFile() async throws {
        let store = MemoryStore()
        let blobs = BlobFolder(root: dir)
        let m = model(store, blobs: blobs)
        let planned = await m.restorePhoneBackup(url: vector("format2"), password: Self.password)
        XCTAssertNotNil(planned)
        let lines = try XCTUnwrap(m.restore?.lines)
        XCTAssertTrue(lines.contains("1 document files from the backup"), "\(lines)")
        XCTAssertTrue(blobs.ids().isEmpty, "the preview stores nothing")
        let done = await m.commitRestore()
        XCTAssertNotNil(done)
        XCTAssertEqual(blobs.ids(), ["ed412dc40eb91d245ba4f0a9332e5e97c0802388ed585c73f3ee2cc51275aaa2"])
        let doc = try XCTUnwrap(store.snapshot.records["88888888-aaaa-4000-8000-000000000008"])
        XCTAssertEqual(try AttachmentDocuments.open(doc, blobs: blobs).data.count, 24)
        XCTAssertTrue(m.message?.contains("1 document files restored.") ?? false, m.message ?? "")
    }

    func testRestoreWithoutAttachmentStoreLeavesDocumentOut() async throws {
        let store = MemoryStore()
        let m = model(store)
        _ = await m.restorePhoneBackup(url: vector("format2"), password: Self.password)
        _ = await m.commitRestore()
        XCTAssertNil(store.snapshot.records["88888888-aaaa-4000-8000-000000000008"])
        XCTAssertTrue(m.message?.contains("1 document was not restored: its file is not in this backup.") ?? false,
                      m.message ?? "")
    }

    func testFreePlanHoldsBackItemsPastTheLimit() async throws {
        let store = MemoryStore()
        let m = model(store, isPro: false)
        let result = await m.restorePhoneBackup(url: vector("from_android"), password: Self.password)
        let planned = try XCTUnwrap(result)
        XCTAssertLessThanOrEqual(planned.created, ItemLimit.freeItems)
        if planned.limited > 0 {
            XCTAssertTrue(m.restore?.lines.contains { $0.contains("held back by the free plan") } ?? false)
        }
        let done = await m.commitRestore()
        XCTAssertEqual(done?.limited, planned.limited)
    }

    /// A backup this iPhone made: nothing to restore into a vault with data (the Mac and Android message);
    /// restored into an empty vault (the app reinstalled, the keychain install id kept).
    func testSameDeviceBackupRefusedWithDataRestoredWhenEmpty() async throws {
        let store = MemoryStore()
        let importer = model(store)
        let csv = dir.appendingPathComponent("Passwords.csv")
        try Data("Title,URL,Username,Password,Notes,OTPAuth\nExample,https://example.com,ada,pw-one,,\n".utf8).write(to: csv)
        await importer.importFile(url: csv)
        _ = await importer.commitReview()
        XCTAssertEqual(store.snapshot.records.count, 1)
        let exporter = VaultExporter(store: store, isPro: { true }, appVersion: "1.0.0", fallbackDeviceID: { "iphone-install-1" },
                                     now: { Date(timeIntervalSince1970: 1_800_000_000) }, random: SystemRandomSource())
        let data = try await exporter.encryptedBackupData(password: "a long backup password", confirmation: "a long backup password")
        let url = dir.appendingPathComponent("LocalGateKeys-Backup.lgkm")
        try data.write(to: url)

        let same = model(store)
        let refused = await same.restorePhoneBackup(url: url, password: "a long backup password")
        XCTAssertNil(refused)
        XCTAssertNil(same.restore)
        XCTAssertEqual(same.message, ImportExportModel.sameDeviceMessage)

        let fresh = MemoryStore()
        let reinstalled = model(fresh)
        let planned = await reinstalled.restorePhoneBackup(url: url, password: "a long backup password")
        XCTAssertEqual(planned?.created, 1)
        _ = await reinstalled.commitRestore()
        XCTAssertEqual(Set(fresh.snapshot.records.keys), Set(store.snapshot.records.keys))
    }

    /// "Test now" on a backup this iPhone exported: passes with the backup password (device report: "can't be read").
    @MainActor
    func testRestoreTestPassesOnAnExportedBackup() async throws {
        let store = MemoryStore()
        let csv = dir.appendingPathComponent("one.csv")
        try Data("Title,URL,Username,Password,Notes,OTPAuth\nExample,https://example.com,ada,pw-one,,\n".utf8).write(to: csv)
        let importer = model(store)
        await importer.importFile(url: csv)
        _ = await importer.commitReview()
        let exporter = VaultExporter(store: store, isPro: { true }, appVersion: "1.0.0", fallbackDeviceID: { "iphone-install-1" },
                                     now: { Date(timeIntervalSince1970: 1_800_000_000) }, random: SystemRandomSource())
        let url = try await exporter.encryptedBackup(password: "a long backup password", confirmation: "a long backup password")
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "restore-test-\(UUID().uuidString)"))
        let restoreTest = RestoreTestModel(folder: dir.appendingPathComponent("state"), defaults: defaults)
        let result = await restoreTest.run(backup: url, restore: RestoreTest.phoneBackup(password: "a long backup password"))
        XCTAssertTrue(result.ok, "reason: \(result.reason)")
        XCTAssertEqual(result.items, 1)
    }
}
