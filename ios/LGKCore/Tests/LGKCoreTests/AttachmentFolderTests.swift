import XCTest
import Foundation
@testable import LGKCore

/// In-memory folder that also knows sizes and modification times (attachment keep and sweep).
final class TimedFolder: FolderAccess, @unchecked Sendable {
    var files: [String: [UInt8]] = [:]
    var times: [String: Int64] = [:]
    var now: Int64 = 0
    func list(_ dir: String) throws -> [String] {
        let prefix = dir + "/"
        let names = files.keys.filter { $0.hasPrefix(prefix) }.map { String($0.dropFirst(prefix.count)) }.filter { !$0.contains("/") }
        if names.isEmpty { throw FolderAccessError.notFound(dir) }
        return names
    }
    func read(_ path: String, limit: Int) throws -> [UInt8] {
        guard let d = files[path] else { throw FolderAccessError.notFound(path) }
        return Array(d.prefix(limit))
    }
    func writeAtomic(_ path: String, _ data: [UInt8]) throws { files[path] = data; times[path] = now }
    func remove(_ path: String) throws {
        guard files.removeValue(forKey: path) != nil else { throw FolderAccessError.notFound(path) }
        times[path] = nil
    }
    func exists(_ path: String) -> Bool { files[path] != nil || files.keys.contains { $0.hasPrefix(path + "/") } }
    func fileAttributes(_ path: String) -> (size: Int, modified: Int64)? {
        guard let d = files[path], let t = times[path] else { return nil }
        return (d.count, t)
    }
    func touch(_ path: String, modified: Int64) throws {
        guard files[path] != nil else { throw FolderAccessError.notFound(path) }
        times[path] = modified
    }
}

final class AttachmentFolderTests: XCTestCase {
    typealias V = MergeVectors
    typealias Blobs = AttachmentSyncTests.MemoryBlobs
    let day: Int64 = 86400

    func doc(_ blobs: Blobs, _ text: String = "synthetic passport scan\n") throws -> (id: String, wrapper: JSONValue, ref: AttachmentRef) {
        try AttachmentDocuments.make(data: Array(text.utf8), fileName: "scan.pdf", mimeType: "application/pdf", title: "",
                                     now: EngineTests.T0, random: DetRand("attach|\(text)"), blobs: blobs)
    }

    func state(_ d: (id: String, wrapper: JSONValue, ref: AttachmentRef)) throws -> ItemState {
        try ItemState(itemID: d.id, vv: [EngineTests.A: 1], deleted: false, deletedAt: nil, item: d.wrapper)
    }

    // MARK: capability files

    func test_capability_file_counts_only_signed_by_the_trusted_key_and_for_its_device() throws {
        let folder = MemoryFolder()
        let blobs = FolderBlobs(access: folder)
        let gk = try FolderSyncTests.epoch1()
        let a = try KeyringTests.identity("A"), b = try KeyringTests.identity("B")
        let aKey = Base64.encode(a.signingPublicKey), bKey = Base64.encode(b.signingPublicKey)
        XCTAssertFalse(blobs.capable(gk, deviceID: a.deviceID, signer: aKey))
        XCTAssertTrue(try blobs.writeCapability(gk, identity: a, clock: FixedClock(now: EngineTests.T0), random: DetRand("cap")))
        XCTAssertFalse(try blobs.writeCapability(gk, identity: a, clock: FixedClock(now: EngineTests.T0), random: DetRand("cap")))
        XCTAssertTrue(blobs.capable(gk, deviceID: a.deviceID, signer: aKey))
        XCTAssertFalse(blobs.capable(gk, deviceID: a.deviceID, signer: bKey))   // not the key trusted for A
        XCTAssertFalse(blobs.capable(gk, deviceID: a.deviceID, signer: nil))
        // A's files copied as B's: the view names A, so they do not count for B.
        let dir = FolderBlobs.dir
        folder.files["\(dir)/\(b.deviceID).lgkcap"] = folder.files["\(dir)/\(a.deviceID).lgkcap"]
        folder.files["\(dir)/\(b.deviceID).lgkcap.lgksig"] = folder.files["\(dir)/\(a.deviceID).lgkcap.lgksig"]
        XCTAssertFalse(blobs.capable(gk, deviceID: b.deviceID, signer: aKey))
        XCTAssertFalse(blobs.capable(gk, deviceID: b.deviceID, signer: bKey))
        // Unsigned or another epoch: not capable.
        folder.files["\(dir)/\(a.deviceID).lgkcap.lgksig"] = nil
        XCTAssertFalse(blobs.capable(gk, deviceID: a.deviceID, signer: aKey))
        XCTAssertTrue(try blobs.writeCapability(gk, identity: a, clock: FixedClock(now: EngineTests.T0), random: DetRand("cap2")))
        let epoch2 = try GroupKey(groupID: gk.groupID, epoch: gk.epoch + 1, key: Array(repeating: 3, count: 32))
        XCTAssertFalse(blobs.capable(epoch2, deviceID: a.deviceID, signer: aKey))
    }

    // MARK: blobs in the folder

    func test_import_publish_keep_and_sweep() throws {
        let folder = TimedFolder()
        folder.now = EngineTests.T0
        let blobs = FolderBlobs(access: folder)
        let mine = Blobs()
        let d = try doc(mine)
        // Publish: written once, then kept.
        XCTAssertEqual(blobs.publishOwn([try state(d)], from: mine, now: EngineTests.T0), [])
        XCTAssertEqual(blobs.ids(), [d.ref.blob])
        XCTAssertEqual(blobs.read(d.ref.blob), mine.read(d.ref.blob))
        // Four days on, keep refreshes the time, so a sweep at day 8 keeps it even unreferenced.
        XCTAssertEqual(blobs.publishOwn([try state(d)], from: mine, now: EngineTests.T0 + 4 * day), [])
        XCTAssertEqual(folder.times[try FolderBlobs.path(d.ref.blob)], EngineTests.T0 + 4 * day)
        XCTAssertEqual(blobs.sweep(referenced: [], now: EngineTests.T0 + 8 * day), [])
        // A truncated copy is rewritten.
        folder.files[try FolderBlobs.path(d.ref.blob)] = Array(mine.read(d.ref.blob)!.prefix(100))
        folder.now = EngineTests.T0 + 5 * day
        XCTAssertFalse(blobs.keep(d.ref.blob, size: d.ref.blobSize, now: EngineTests.T0 + 5 * day))
        XCTAssertEqual(blobs.publishOwn([try state(d)], from: mine, now: EngineTests.T0 + 5 * day), [])
        XCTAssertEqual(blobs.read(d.ref.blob), mine.read(d.ref.blob))
        // A document whose own file is gone: reported, nothing written.
        let lost = try doc(Blobs(), "lost")
        XCTAssertEqual(blobs.publishOwn([try state(lost)], from: mine, now: EngineTests.T0).map(\.kind), ["attachment-missing"])
        // Import on another device: verified and stored; a tampered copy is refused and not stored.
        let other = Blobs()
        XCTAssertEqual(blobs.importMissing([try state(d)], into: other), [])
        XCTAssertTrue(other.has(d.ref.blob))
        let bad = try doc(Blobs(), "other file")
        var tampered = try XCTUnwrap(mine.read(d.ref.blob))
        tampered[40] ^= 1
        folder.files[try FolderBlobs.path(bad.ref.blob)] = tampered
        folder.times[try FolderBlobs.path(bad.ref.blob)] = EngineTests.T0
        XCTAssertEqual(blobs.importMissing([try state(bad)], into: other), [])   // name does not match content: not read
        XCTAssertFalse(other.has(bad.ref.blob))
        // Sweep: referenced and young blobs stay, an old unreferenced one goes.
        XCTAssertEqual(blobs.sweep(referenced: [d.ref.blob], now: EngineTests.T0 + 30 * day), [bad.ref.blob])
        XCTAssertEqual(blobs.sweep(referenced: [], now: EngineTests.T0 + 5 * day + 6 * day), [])
        XCTAssertEqual(blobs.sweep(referenced: [], now: EngineTests.T0 + 5 * day + 7 * day), [d.ref.blob])
    }

    func test_folder_without_times_never_sweeps() throws {
        let folder = MemoryFolder()
        let blobs = FolderBlobs(access: folder)
        let mine = Blobs()
        let d = try doc(mine)
        XCTAssertEqual(blobs.publishOwn([try state(d)], from: mine, now: EngineTests.T0), [])
        XCTAssertTrue(blobs.keep(d.ref.blob, size: d.ref.blobSize, now: EngineTests.T0))
        XCTAssertEqual(blobs.sweep(referenced: [], now: EngineTests.T0 + 400 * day), [])
    }

    // MARK: folder run

    func test_folder_run_publishes_documents_only_when_every_member_is_capable() throws {
        let (folder, store, _, _) = try FolderSyncTests().joined("attach")
        let mine = Blobs()
        let d = try doc(mine)
        store.snapshot.records[d.id] = d.wrapper
        let phone = try XCTUnwrap(store.snapshot.sync).deviceID
        let fs = try FolderSync(access: folder, installID: FolderSyncTests.install, attachmentBlobs: mine)
        let gk = try FolderSyncTests.epoch1()
        func ownView() throws -> [ItemState] {
            try ViewFile.decode(try XCTUnwrap(folder.files[FolderSyncTests.devPath(phone)]), key: gk, expectedDeviceID: phone).states
        }
        _ = fs.runOnce(store: store, random: DetRand("run1"), clock: FixedClock(now: EngineTests.T0 + 2000))
        XCTAssertFalse(try ownView().contains { $0.itemID == d.id })          // A, B and C have no capability file
        XCTAssertNotNil(folder.files["\(FolderBlobs.dir)/\(phone).lgkcap"])  // this device declared it reads documents
        XCTAssertTrue(FolderBlobs(access: folder).ids().isEmpty)
        for who in ["A", "B", "C"] {
            try FolderBlobs(access: folder).writeCapability(gk, identity: try KeyringTests.identity(who),
                                                            clock: FixedClock(now: EngineTests.T0), random: DetRand("cap|\(who)"))
        }
        let r = fs.runOnce(store: store, random: DetRand("run2"), clock: FixedClock(now: EngineTests.T0 + 3000))
        XCTAssertFalse(r.issues.contains { $0.kind == "write-failed" })
        XCTAssertTrue(try ownView().contains { $0.itemID == d.id })
        XCTAssertEqual(FolderBlobs(access: folder).ids(), [d.ref.blob])   // the blob went in before the view
        // Another member that reads the view imports the file and applies the document.
        let other = Blobs()
        XCTAssertEqual(FolderBlobs(access: folder).importMissing(try ownView(), into: other), [])
        let run = SyncRunner.run(store: StoreSnapshot(), views: [PeerView(deviceID: phone, states: try ownView())],
                                 device: EngineTests.A, now: EngineTests.T0 + 3000, blobs: other)
        XCTAssertEqual(run.records?[d.id], d.wrapper)
    }

    // MARK: attachment peers

    func test_attachment_peers_list_and_store() throws {
        XCTAssertEqual(AttachmentDocuments.peers([], setting: EngineTests.A, capable: true), [EngineTests.A])
        XCTAssertNil(AttachmentDocuments.peers([EngineTests.A], setting: EngineTests.A, capable: true))
        XCTAssertEqual(AttachmentDocuments.peers([EngineTests.A, EngineTests.B], setting: EngineTests.A, capable: false), [EngineTests.B])
        XCTAssertNil(AttachmentDocuments.peers([], setting: EngineTests.A, capable: false))
        let (_, store, _, _) = try FolderSyncTests().joined("peers")
        XCTAssertTrue(AttachmentDocuments.setPeer(EngineTests.B, capable: true, store: store))
        XCTAssertEqual(store.snapshot.sync?.attachmentPeers, [EngineTests.B])
        XCTAssertFalse(AttachmentDocuments.setPeer(EngineTests.B, capable: true, store: store))   // no commit when unchanged
        XCTAssertTrue(AttachmentDocuments.setPeer(EngineTests.B, capable: false, store: store))
        XCTAssertEqual(store.snapshot.sync?.attachmentPeers, [])
    }

    // MARK: backups

    func test_sidecar_matches_the_windows_layout_and_round_trips() throws {
        let vector = Array(try Data(contentsOf: Vectors.root.deletingLastPathComponent()
            .appendingPathComponent("backup/v2/inputs/0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d.blob")))
        let id = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", store = "7c6b5a49-3827-4615-a4b3-c2d1e0f9a8b7"
        let key = Array(repeating: UInt8(9), count: 32), data = Array("hello sidecar".utf8)
        let sidecar = try DesktopAttachmentSidecar.seal(id: id, data: data, storeID: store, key: key, random: DetRand("side"))
        // Same magic, length prefix and header bytes as a Windows sidecar.
        let headerEnd = 12 + Int(vector[11]) + Int(vector[10]) << 8
        XCTAssertEqual(Array(sidecar[0..<headerEnd]), Array(vector[0..<headerEnd]))
        XCTAssertEqual(sidecar.count, headerEnd + 12 + data.count + 16)
        XCTAssertEqual(try DesktopAttachmentSidecar.open(sidecar, id: id, storeID: store, key: key), data)
        XCTAssertThrowsError(try DesktopAttachmentSidecar.open(sidecar, id: id, storeID: store, key: Array(repeating: 1, count: 32)))
        XCTAssertEqual(try FullBackupManifest.sidecarSize(Data(sidecar), expectedID: id), data.count)
    }

    func test_backup_rows_and_restore_give_back_the_same_document() throws {
        let mine = Blobs()
        let d = try doc(mine)
        let record = V.obj(d.wrapper)["record"]!
        let storeID = "7c6b5a49-3827-4615-a4b3-c2d1e0f9a8b7"
        let made = DesktopAttachmentSidecar.backupRows(documents: [(record, d.wrapper)], existing: [], storeID: storeID,
                                                       blobs: mine, random: DetRand("rows"))
        XCTAssertEqual(made.skipped, [])
        XCTAssertEqual(made.rows, [.object(["id": .string(d.ref.attachmentID), "name": .string("scan.pdf"),
                                            "mime_type": .string("application/pdf"), "size": .int(Int64(d.ref.size)),
                                            "sha256": .string(d.ref.sha256), "key": .string(Base64.encode(d.ref.key))])])
        XCTAssertEqual(made.sidecars.map(\.id), [d.ref.attachmentID])
        // A row already kept from Windows is not duplicated; a document without its file is skipped.
        XCTAssertTrue(DesktopAttachmentSidecar.backupRows(documents: [(record, d.wrapper)], existing: [d.ref.attachmentID],
                                                          storeID: storeID, blobs: mine, random: DetRand("rows")).rows.isEmpty)
        XCTAssertEqual(DesktopAttachmentSidecar.backupRows(documents: [(record, d.wrapper)], existing: [], storeID: storeID,
                                                           blobs: Blobs(), random: DetRand("rows")).skipped, [d.id])
        // Restore on a new device: the same wrapper (deterministic blob) and the blob stored.
        let restored = Blobs()
        let back = DesktopAttachmentSidecar.restoredDocument(record: record, catalog: made.rows,
                                                             sidecars: Dictionary(uniqueKeysWithValues: made.sidecars.map { ($0.id, $0.data) }),
                                                             storeID: storeID, blobs: restored)
        XCTAssertEqual(back, d.wrapper)
        XCTAssertTrue(restored.has(d.ref.blob))
        XCTAssertNil(DesktopAttachmentSidecar.restoredDocument(record: record, catalog: made.rows, sidecars: [:],
                                                               storeID: storeID, blobs: restored))
    }

    // MARK: Recently deleted

    func test_trash_keeps_the_reference_and_garbage_collection_spares_trash() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-gc-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let folder = BlobFolder(root: root)
        let d = try AttachmentDocuments.make(data: Array("x".utf8), fileName: "x.txt", mimeType: "text/plain", title: "",
                                             now: EngineTests.T0, random: DetRand("gc"), blobs: folder)
        let row = try XCTUnwrap(AttachmentDocuments.trashRecord(d.wrapper))
        XCTAssertEqual(AttachmentDocuments.restoredWrapper(row, ns: .item), d.wrapper)
        XCTAssertEqual(AttachmentDocuments.trashBlobs([row]), [d.ref.blob])
        let store = MemoryStore()   // the item was deleted: only the trash row references the file
        XCTAssertEqual(AttachmentDocuments.collectGarbage(store: store, trash: [row], blobs: folder), [])
        XCTAssertTrue(folder.has(d.ref.blob))
        XCTAssertEqual(AttachmentDocuments.collectGarbage(store: store, trash: [], blobs: folder), [d.ref.blob])
        XCTAssertFalse(folder.has(d.ref.blob))
        // An ordinary record goes through untouched.
        let note: JSONValue = .object(["id": .string(EngineTests.NOTE), "kind": .string("note"), "title": .string("n")])
        XCTAssertEqual(AttachmentDocuments.restoredWrapper(note, ns: .item), Wrapper.make(ns: .item, record: note))
    }
}
