import Foundation
import XCTest
@testable import LGKCore

/// The restore side of `LGKMBAK1` (desktop `sync/phone_restore.py`): the backup's states merge as one peer view,
/// so version vectors and tombstones are kept, nothing newer is overwritten and the vault is never wiped.
final class PhoneBackupRestoreTests: XCTestCase {
    static let device = "d4444444-0000-4000-8000-00000000000d"
    static let now: Int64 = 1_790_100_000
    nonisolated(unsafe) static var cache: [String: BackupPayload] = [:]

    func payload(_ dir: String) throws -> BackupPayload {
        if let p = Self.cache[dir] { return p }
        let url = PhoneBackupTests.root.appendingPathComponent("\(dir)/backup.lgkm")
        let p = try PhoneBackup.open(Data(contentsOf: url), password: PhoneBackupTests.password)
        Self.cache[dir] = p
        return p
    }

    private func o(_ v: JSONValue?) -> [String: JSONValue]? { if case .object(let x)? = v { return x }; return nil }
    private func a(_ v: JSONValue?) -> [JSONValue]? { if case .array(let x)? = v { return x }; return nil }

    /// Live logins and typed items (not tombstones or licence states).
    private func contentCount(_ b: BackupPayload) -> Int {
        b.states.filter { !$0.deleted && ["entry", "item"].contains(o($0.item)?["ns"].flatMap { if case .string(let n) = $0 { n } else { nil } } ?? "") }.count
    }

    private func commit(_ plan: PhoneRestorePlan, over snap: StoreSnapshot) -> StoreSnapshot {
        StoreSnapshot(records: plan.records, meta: plan.meta, sync: snap.sync, revision: snap.revision + 1)
    }

    func testRestoreIOSAndAndroidVectors() throws {
        for dir in ["from_ios", "from_android"] {
            let backup = try payload(dir)
            let plan = try PhoneBackup.restoreStates(backup, into: StoreSnapshot(), device: Self.device, now: Self.now)
            XCTAssertGreaterThanOrEqual(contentCount(backup), 8, dir)
            XCTAssertEqual(plan.new, contentCount(backup), dir)
            XCTAssertEqual(plan.updated, 0, dir)
            XCTAssertEqual(plan.deleted, 0, dir)
            XCTAssertEqual(plan.heldBack, 0, dir)
            XCTAssertTrue(plan.changes, dir)
            // Every live content state lands under its own id with the backup's version vector.
            for s in backup.states where !s.deleted && o(s.item)?["ns"] != .string("license") {
                XCTAssertNotNil(plan.records[s.id], "\(dir) \(s.id)")
                XCTAssertEqual(plan.meta[s.id]?.vv, s.vv, "\(dir) \(s.id)")
            }
            // The tombstone is kept, so a later sync does not bring the item back.
            let tomb = try XCTUnwrap(backup.states.first(where: \.deleted))
            XCTAssertNil(plan.records[tomb.id])
            XCTAssertEqual(plan.meta[tomb.id]?.deleted, true, dir)
            XCTAssertEqual(plan.meta[tomb.id]?.vv, tomb.vv, dir)

            // Restoring the same backup again changes nothing.
            let after = commit(plan, over: StoreSnapshot())
            let again = try PhoneBackup.restoreStates(backup, into: after, device: Self.device, now: Self.now)
            XCTAssertEqual(again.new, 0, dir)
            XCTAssertEqual(again.updated, 0, dir)
            XCTAssertEqual(again.unchanged, contentCount(backup), dir)
            XCTAssertFalse(again.changes, dir)
        }
    }

    func testRestoreMergesAndNeverWipes() throws {
        let backup = try payload("from_ios")
        // An item only on this Mac stays; an item this Mac holds at a newer version is not overwritten.
        let first = try PhoneBackup.restoreStates(backup, into: StoreSnapshot(), device: Self.device, now: Self.now)
        var snap = commit(first, over: StoreSnapshot())
        let id = "22222222-aaaa-4000-8000-000000000002"
        guard case .object(var w)? = snap.records[id], case .object(var r)? = w["record"] else { return XCTFail() }
        r["title"] = .string("Edited on the Mac"); r["updated_at"] = .int(Self.now)
        w["record"] = .object(r); w["updated_at"] = .int(Self.now)
        snap.records[id] = .object(w)
        let local: JSONValue = .object(["ns": .string("item"), "schema": .int(1), "updated_at": .int(Self.now),
                                        "record": .object(["id": .string("mac-only-1"), "kind": .string("note"),
                                                           "title": .string("Mac only"), "favorite": .bool(false),
                                                           "tags": .array([]), "created_at": .int(Self.now),
                                                           "updated_at": .int(Self.now),
                                                           "payload": .object(["body": .string("x"), "fields": .array([]),
                                                                               "template_id": .null])])])
        snap.records["mac-only-1"] = local
        let view = try SyncMeta.localView(records: snap.records, meta: snap.meta, device: Self.device, now: Self.now)
        snap.meta = view.meta
        let plan = try PhoneBackup.restoreStates(backup, into: snap, device: Self.device, now: Self.now)
        XCTAssertEqual(plan.new, 0)
        XCTAssertEqual(plan.updated, 0)
        XCTAssertNotNil(plan.records["mac-only-1"])
        XCTAssertEqual(o(o(plan.records[id])?["record"])?["title"], .string("Edited on the Mac"))
    }

    func testFreePlanHoldsBackNewItems() throws {
        let backup = try payload("from_android")
        let plan = try PhoneBackup.restoreStates(backup, into: StoreSnapshot(), device: Self.device, now: Self.now,
                                                 freeSlots: 3)
        XCTAssertEqual(plan.new, 3)
        XCTAssertEqual(plan.heldBack, contentCount(backup) - 3)
        let live = plan.records.filter { plan.meta[$0.key]?.deleted != true }
        XCTAssertEqual(live.count, 3)
        // The free plan keeps a new two-factor key as a hidden field.
        let full = try PhoneBackup.restoreStates(backup, into: StoreSnapshot(), device: Self.device, now: Self.now,
                                                 freeSlots: 20, totpAllowed: false)
        let rec = o(o(full.records["11111111-aaaa-4000-8000-000000000001"])?["record"])
        XCTAssertEqual(rec?["totp"] ?? .null, .null)
        let field = o(a(rec?["custom_fields"])?.last)
        XCTAssertEqual(field?["name"], .string("Two-factor key (needs Pro)"))
        XCTAssertEqual(field?["hidden"], .bool(true))
        XCTAssertEqual(full.totpAsField, 1)
    }

    // MARK: format 2 (document files)

    static let documentID = "88888888-aaaa-4000-8000-000000000008"

    func testFormat2RestoresDocumentWithItsFile() throws {
        let backup = try payload("format2")
        let blobs = AttachmentSyncTests.MemoryBlobs()
        let plan = try PhoneBackup.restoreStates(backup, into: StoreSnapshot(), device: Self.device, now: Self.now,
                                                 blobs: blobs)
        XCTAssertNotNil(plan.records[Self.documentID])
        XCTAssertEqual(plan.files, backup.files)
        XCTAssertEqual(plan.filesMissing, 0)
        XCTAssertEqual(plan.new, contentCount(backup))
        XCTAssertTrue(blobs.blobs.isEmpty, "the preview stores nothing")

        let stored = PhoneBackup.storeFiles(plan, into: blobs)
        XCTAssertEqual(stored.stored, 1)
        XCTAssertEqual(stored.refused, [])
        XCTAssertEqual(Set(blobs.blobs.keys), Set(backup.files.keys))
        // On commit the plan is made again against the stored files: the document needs nothing more.
        var noFiles = backup
        noFiles.files = [:]
        let again = try PhoneBackup.restoreStates(noFiles, into: StoreSnapshot(), device: Self.device, now: Self.now,
                                                  blobs: blobs)
        XCTAssertNotNil(again.records[Self.documentID])
        XCTAssertEqual(again.files, [:])
        XCTAssertEqual(again.filesMissing, 0)
        let doc = try AttachmentDocuments.open(again.records[Self.documentID], blobs: blobs)
        XCTAssertEqual(doc.data.count, doc.ref.size)
    }

    func testDocumentWithoutItsFileIsLeftOutAndCounted() throws {
        var backup = try payload("format2")
        backup.files = [:]   // a format-1 backup of the same states
        let plan = try PhoneBackup.restoreStates(backup, into: StoreSnapshot(), device: Self.device, now: Self.now,
                                                 blobs: AttachmentSyncTests.MemoryBlobs())
        XCTAssertNil(plan.records[Self.documentID])
        XCTAssertEqual(plan.filesMissing, 1)
        XCTAssertEqual(plan.new, contentCount(backup) - 1)
        XCTAssertEqual(plan.skipped, 0)
    }

    /// Windows and Android count a document that is both unreadable and file-less as skipped; so does the Mac.
    func testUnreadableDocumentWithoutItsFileIsSkippedNotMissing() throws {
        var backup = try payload("format2")
        backup.files = [:]
        let i = try XCTUnwrap(backup.states.firstIndex { $0.id == Self.documentID })
        backup.states[i].vv["ffffffff-0000-4000-8000-00000000ffff"] = Int64.max / 2   // implausible counter
        let plan = try PhoneBackup.restoreStates(backup, into: StoreSnapshot(), device: Self.device, now: Self.now,
                                                 blobs: AttachmentSyncTests.MemoryBlobs())
        XCTAssertNil(plan.records[Self.documentID])
        XCTAssertEqual(plan.filesMissing, 0)
        XCTAssertEqual(plan.skipped, 1)
    }

    func testDamagedBackupFileIsRefusedAndStoresNothing() throws {
        let backup = try payload("format2")
        let blobs = AttachmentSyncTests.MemoryBlobs()
        var plan = try PhoneBackup.restoreStates(backup, into: StoreSnapshot(), device: Self.device, now: Self.now,
                                                 blobs: blobs)
        let blob = try XCTUnwrap(plan.files.keys.first)
        plan.files[blob]?[40] ^= 1
        let stored = PhoneBackup.storeFiles(plan, into: blobs)
        XCTAssertEqual(stored.stored, 0)
        XCTAssertEqual(stored.refused, [blob])
        XCTAssertTrue(blobs.blobs.isEmpty)
        var noFiles = backup
        noFiles.files = [:]
        let again = try PhoneBackup.restoreStates(noFiles, into: StoreSnapshot(), device: Self.device, now: Self.now,
                                                  blobs: blobs)
        XCTAssertNil(again.records[Self.documentID])
        XCTAssertEqual(again.filesMissing, 1)
    }

    func testBackupFromThisDeviceIsRefused() throws {
        let backup = try payload("from_ios")
        XCTAssertThrowsError(try PhoneBackup.restoreStates(backup, into: StoreSnapshot(), device: backup.deviceID,
                                                           now: Self.now)) {
            XCTAssertEqual($0 as? PhoneBackup.RestoreError, .sameDevice)
        }
    }
}
