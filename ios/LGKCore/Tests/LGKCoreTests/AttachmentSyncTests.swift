import XCTest
import Foundation
@testable import LGKCore

/// Attachment sync format 1 against `tests/vectors/sync/attachments/vectors.json`
/// (`scripts/make_attachment_sync_vectors.py`), byte for byte, plus the document wrapper rules.
final class AttachmentSyncTests: XCTestCase {
    typealias V = MergeVectors

    static func vectors() throws -> [String: JSONValue] {
        guard case .object(let o) = try CanonicalJSON.parse(Array(Vectors.data("attachments/vectors.json"))) else {
            throw JSONError.syntax
        }
        return o
    }

    static func int(_ v: JSONValue?) -> Int { if case .int(let n)? = v { return Int(n) }; return -1 }
    static func b64(_ v: JSONValue?) throws -> [UInt8] { try Base64.decodeStrict(V.str(v)!) }

    func test_constants() throws {
        let c = V.obj(try Self.vectors()["constants"])
        XCTAssertEqual(Self.int(try Self.vectors()["format"]), AttachmentSync.format)
        XCTAssertEqual(V.str(c["blob_magic"]), String(decoding: AttachmentSync.blobMagic, as: UTF8.self))
        XCTAssertEqual(V.str(c["blob_aad"]), String(decoding: AttachmentSync.blobAAD, as: UTF8.self))
        XCTAssertEqual(V.str(c["nonce_label"]), String(decoding: AttachmentSync.nonceLabel, as: UTF8.self))
        XCTAssertEqual(Self.int(c["pad_block"]), AttachmentSync.padBlock)
        XCTAssertEqual(Self.int(c["max_file_bytes"]), AttachmentSync.maxFileBytes)
        XCTAssertEqual(Self.int(c["max_blob_bytes"]), AttachmentSync.maxBlobBytes)
        XCTAssertEqual(Self.int(c["max_attachments"]), AttachmentSync.maxAttachments)
        XCTAssertEqual(Self.int(c["chunk_bytes"]), AttachmentSync.chunkBytes)
        XCTAssertEqual(Self.int(c["sweep_min_age_seconds"]), Int(AttachmentSync.sweepMinAgeSeconds))
        XCTAssertEqual(V.str(c["folder"]), "\(AttachmentSync.blobsDirName)/<blob_id>\(AttachmentSync.blobSuffix)")
    }

    func test_blobs_are_reproduced_byte_for_byte_and_open() throws {
        let blobs = V.arr(try Self.vectors()["blobs"]).map(V.obj)
        XCTAssertEqual(blobs.count, 5)
        for b in blobs {
            let name = V.str(b["name"])!
            let key = try Self.b64(b["key"]), data = try Self.b64(b["plaintext"]), id = V.str(b["attachment_id"])!
            let want = try Self.b64(b["blob"])
            XCTAssertEqual(Vectors.hexString(try AttachmentSync.blobNonce(key: key, attachmentID: id, data: data)), V.str(b["nonce"]), name)
            XCTAssertEqual(AttachmentSync.paddedLength(data.count), Self.int(b["padded_length"]), name)
            let sealed = try AttachmentSync.sealBlob(key: key, attachmentID: id, data: data)
            XCTAssertEqual(sealed, want, name)
            XCTAssertEqual(AttachmentSync.blobID(sealed), V.str(b["blob_id"]), name)
            XCTAssertEqual(sealed.count, Self.int(b["blob_size"]), name)
            XCTAssertEqual(Vectors.hexString(AttachmentSync.sha256(data)), V.str(b["plaintext_sha256"]), name)
            let ref = try AttachmentRef(json: b["ref"])
            XCTAssertEqual(ref.json, b["ref"], name)
            XCTAssertEqual(try CanonicalJSON.encode(ref.json, dialect: .utf8), Array(V.str(b["ref_canonical"])!.utf8), name)
            let opened = try AttachmentSync.openBlob(want, ref: ref)
            XCTAssertEqual(opened, data, name)
            let made = try AttachmentRef.forBlob(sealed, attachmentID: id, name: ref.name, mimeType: ref.mimeType, data: data, key: key)
            XCTAssertEqual(made, ref, name)
        }
    }

    func test_refused_blobs_give_the_vector_reason() throws {
        let cases = V.arr(try Self.vectors()["refused_blobs"]).map(V.obj)
        XCTAssertEqual(cases.count, 7)
        for c in cases {
            let ref = try AttachmentRef(json: c["ref"])
            XCTAssertThrowsError(try AttachmentSync.openBlob(try Self.b64(c["blob"]), ref: ref), V.str(c["name"])!) { error in
                XCTAssertEqual((error as? AttachmentSyncError)?.reason, V.str(c["reason"]), V.str(c["name"])!)
            }
        }
    }

    func test_refused_refs() throws {
        let cases = V.arr(try Self.vectors()["refused_refs"])
        XCTAssertEqual(cases.count, 9)
        for (i, c) in cases.enumerated() {
            XCTAssertThrowsError(try AttachmentRef(json: c), "case \(i)")
        }
    }

    func test_lan_messages_byte_for_byte() throws {
        let v = try Self.vectors()
        let two = V.obj(V.arr(v["blobs"])[3])
        let blob = try Self.b64(two["blob"])
        let lan = V.obj(v["lan"])
        let get = Array(V.str(lan["blob_get"])!.utf8)
        XCTAssertEqual(try LanMessages.encode(.blobGet(blob: AttachmentSync.blobID(blob), seq: 0)), get)
        XCTAssertEqual(try LanMessages.parse(get), .blobGet(blob: AttachmentSync.blobID(blob), seq: 0))
        let chunks = V.arr(lan["chunks"]).map { Array(V.str($0)!.utf8) }
        XCTAssertEqual(chunks.count, (blob.count + AttachmentSync.chunkBytes - 1) / AttachmentSync.chunkBytes)
        var download = BlobDownload(ref: try AttachmentRef(json: two["ref"]))
        var whole: [UInt8]?
        for (seq, raw) in chunks.enumerated() {
            let message = try AttachmentSync.chunk(blob, seq: seq)
            XCTAssertEqual(try LanMessages.encode(message), raw)
            let parsed = try LanMessages.parse(raw)
            XCTAssertEqual(parsed, message)
            whole = try download.add(parsed)
        }
        XCTAssertEqual(whole, blob)
    }

    func test_download_refuses_out_of_order_or_foreign_chunks() throws {
        let v = try Self.vectors()
        let two = V.obj(V.arr(v["blobs"])[3])
        let blob = try Self.b64(two["blob"])
        let ref = try AttachmentRef(json: two["ref"])
        var d = BlobDownload(ref: ref)
        XCTAssertThrowsError(try d.add(try AttachmentSync.chunk(blob, seq: 1)))
        let other = try Self.b64(V.obj(V.arr(v["blobs"])[0])["blob"])
        var e = BlobDownload(ref: ref)
        XCTAssertThrowsError(try e.add(try AttachmentSync.chunk(other, seq: 0)))
        XCTAssertThrowsError(try LanMessages.parse(Array(#"{"blob":"ABC","seq":0,"type":"blob-get"}"#.utf8)))
    }

    func test_blob_folder_write_read_ids_and_sweep() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-attach-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let folder = BlobFolder(root: root)
        let blob = try Self.b64(V.obj(V.arr(try Self.vectors()["blobs"])[1])["blob"])
        let id = try folder.write(blob)
        XCTAssertEqual(id, AttachmentSync.blobID(blob))
        XCTAssertEqual(try folder.write(blob), id)   // kept, never rewritten
        XCTAssertEqual(folder.ids(), [id])
        XCTAssertEqual(folder.read(id), blob)
        // A file whose name does not match its content is not returned; other names are ignored.
        let wrong = String(repeating: "a", count: 64)
        try Data(blob).write(to: try folder.path(wrong))
        try Data([1]).write(to: folder.dir.appendingPathComponent("notes.txt"))
        XCTAssertNil(folder.read(wrong))
        XCTAssertEqual(folder.ids(), [id, wrong])
        // Sweep: young files stay, old unreferenced ones go, referenced ones stay.
        XCTAssertEqual(folder.sweep(referenced: [id], now: Date()), [])
        XCTAssertEqual(folder.sweep(referenced: [id], now: Date().addingTimeInterval(8 * 86400)), [wrong])
        XCTAssertEqual(folder.ids(), [id])
        XCTAssertThrowsError(try folder.path("../x"))
    }

    func test_blob_folder_keep_refreshes_and_rewrites_short_files() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-keep-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let folder = BlobFolder(root: root)
        let blob = try Self.b64(V.obj(V.arr(try Self.vectors()["blobs"])[1])["blob"])
        let id = AttachmentSync.blobID(blob)
        XCTAssertFalse(folder.keep(id, size: blob.count, now: Date()))
        XCTAssertTrue(folder.publish(blob, now: Date()))
        // Four days later the date is refreshed, so a sweep three days after that keeps it.
        let later = Date().addingTimeInterval(4 * 86400)
        XCTAssertTrue(folder.keep(id, size: blob.count, now: later))
        XCTAssertEqual(folder.sweep(referenced: [], now: later.addingTimeInterval(3 * 86400)), [])
        // A truncated copy is not kept, and publishing rewrites it.
        try Data(blob.prefix(100)).write(to: try folder.path(id))
        XCTAssertFalse(folder.keep(id, size: blob.count, now: Date()))
        XCTAssertTrue(folder.publish(blob, now: Date()))
        XCTAssertEqual(folder.read(id), blob)
    }

    // MARK: documents

    final class MemoryBlobs: AttachmentBlobStore, @unchecked Sendable {
        var blobs: [String: [UInt8]] = [:]
        func has(_ blobID: String) -> Bool { blobs[blobID] != nil }
        func read(_ blobID: String) -> [UInt8]? { blobs[blobID] }
        @discardableResult func write(_ blob: [UInt8]) throws -> String {
            let id = AttachmentSync.blobID(try AttachmentSync.checkBlobShape(blob)); blobs[id] = blob; return id
        }
        func ids() -> Set<String> { Set(blobs.keys) }
    }

    struct CountingRandom: RandomSource {
        func bytes(count: Int) -> [UInt8] { (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 11) } }
    }

    func document(blobs: MemoryBlobs) throws -> (id: String, wrapper: JSONValue, ref: AttachmentRef) {
        try AttachmentDocuments.make(data: Array("synthetic passport scan\n".utf8), fileName: "passport.pdf",
                                     mimeType: "application/pdf", title: "", now: EngineTests.T0, random: CountingRandom(), blobs: blobs)
    }

    func test_new_document_wrapper_unwraps_and_opens() throws {
        let blobs = MemoryBlobs()
        let doc = try document(blobs: blobs)
        XCTAssertTrue(blobs.has(doc.ref.blob))
        XCTAssertEqual(AttachmentDocuments.ref(of: doc.wrapper), doc.ref)
        let state = try ItemState(itemID: doc.id, vv: [EngineTests.A: 1], deleted: false, deletedAt: nil, item: doc.wrapper)
        let (ns, record) = try Wrapper.unwrap(state, isCopy: false)
        XCTAssertEqual(ns, .item)
        XCTAssertEqual(V.obj(record)["title"], .string("passport.pdf"))
        XCTAssertEqual(try AttachmentDocuments.open(doc.wrapper, blobs: blobs).data, Array("synthetic passport scan\n".utf8))
        // Rename changes the title only.
        let renamed = AttachmentDocuments.renamed(doc.wrapper, title: "Passport", now: EngineTests.T0 + 5)!
        XCTAssertEqual(AttachmentDocuments.ref(of: renamed), doc.ref)
        XCTAssertEqual(V.obj(V.obj(renamed)["record"])["title"], .string("Passport"))
        XCTAssertEqual(V.obj(renamed)["updated_at"], .int(EngineTests.T0 + 5))
    }

    func test_document_wrapper_rules() throws {
        let doc = try document(blobs: MemoryBlobs())
        func state(_ w: JSONValue) throws -> ItemState {
            try ItemState(itemID: doc.id, vv: [EngineTests.A: 1], deleted: false, deletedAt: nil, item: w)
        }
        // Without its reference a document is still a kind that does not sync.
        var bare = V.obj(doc.wrapper); bare["attachment"] = nil
        XCTAssertThrowsError(try Wrapper.unwrap(try state(.object(bare)), isCopy: false))
        // A reference naming another attachment is refused.
        var other = V.obj(doc.wrapper), record = V.obj(other["record"]), payload = V.obj(record["payload"])
        payload["attachment_id"] = .string("00000000-0000-4000-8000-000000000009")
        record["payload"] = .object(payload); other["record"] = .object(record)
        XCTAssertThrowsError(try Wrapper.unwrap(try state(.object(other)), isCopy: false))
        // An `attachment` key on another kind is refused.
        var note = V.obj(doc.wrapper), noteRecord = V.obj(note["record"])
        noteRecord["kind"] = .string("note"); noteRecord["payload"] = .object(["body": .string("x")])
        note["record"] = .object(noteRecord)
        XCTAssertThrowsError(try Wrapper.unwrap(try state(.object(note)), isCopy: false))
    }

    func test_runner_waits_for_the_file_then_applies() throws {
        let sender = MemoryBlobs()
        let doc = try document(blobs: sender)
        let view = PeerView(deviceID: EngineTests.A,
                            states: [try ItemState(itemID: doc.id, vv: [EngineTests.A: 1], deleted: false, deletedAt: nil, item: doc.wrapper)])
        let device = RunnerTests.phone, now = EngineTests.T0 + 1000
        let receiver = MemoryBlobs()
        let waiting = SyncRunner.run(store: StoreSnapshot(), views: [view], device: device, now: now, blobs: receiver)
        XCTAssertEqual(waiting.issues, [SyncIssue("attachment-missing", "\(EngineTests.A):\(doc.id)")])
        XCTAssertNil(waiting.records?[doc.id])
        try receiver.write(sender.read(doc.ref.blob)!)
        let applied = SyncRunner.run(store: StoreSnapshot(), views: [view], device: device, now: now, blobs: receiver)
        XCTAssertEqual(applied.issues, [])
        XCTAssertEqual(applied.records?[doc.id], doc.wrapper)
        XCTAssertEqual(applied.applied, 1)
    }

    func test_publishable_and_own_blob() throws {
        let blobs = MemoryBlobs()
        let doc = try document(blobs: blobs)
        let live = try ItemState(itemID: doc.id, vv: [EngineTests.A: 1], deleted: false, deletedAt: nil, item: doc.wrapper)
        let tomb = try ItemState(itemID: EngineTests.NOTE, vv: [EngineTests.A: 2], deleted: true, deletedAt: EngineTests.T0, item: nil)
        XCTAssertEqual(AttachmentDocuments.publishable([live, tomb], documents: false), [tomb])
        XCTAssertEqual(AttachmentDocuments.publishable([live, tomb], documents: true), [live, tomb])
        XCTAssertEqual(AttachmentDocuments.refs([live, tomb]), [doc.ref])
        let snap = StoreSnapshot(records: [doc.id: doc.wrapper])
        // The responder serves only blobs of its own live documents; the probe id never matches.
        XCTAssertEqual(AttachmentDocuments.ownBlob(doc.ref.blob, snapshot: snap, blobs: blobs), blobs.read(doc.ref.blob))
        XCTAssertNil(AttachmentDocuments.ownBlob(AttachmentSync.probeBlob, snapshot: snap, blobs: blobs))
        XCTAssertNil(AttachmentDocuments.ownBlob(doc.ref.blob, snapshot: StoreSnapshot(), blobs: blobs))
        XCTAssertNil(AttachmentDocuments.ownBlob(doc.ref.blob, snapshot: StoreSnapshot(records: [doc.id: doc.wrapper],
            meta: [doc.id: SyncMeta.tomb(vv: [EngineTests.A: 2], deletedAt: EngineTests.T0)]), blobs: blobs))
    }

    func test_wanted_and_check_refs() throws {
        let doc = try document(blobs: MemoryBlobs())
        XCTAssertEqual(try AttachmentSync.wanted([doc.ref, doc.ref], presentBlobs: []), [doc.ref])
        XCTAssertEqual(try AttachmentSync.wanted([doc.ref], presentBlobs: [doc.ref.blob]), [])
        let clash = try AttachmentRef(attachmentID: doc.ref.attachmentID, blob: doc.ref.blob, blobSize: doc.ref.blobSize,
                                      name: "other.pdf", mimeType: doc.ref.mimeType, size: doc.ref.size, sha256: doc.ref.sha256,
                                      key: doc.ref.key)
        XCTAssertThrowsError(try AttachmentSync.checkRefs([doc.ref, clash]))
    }
}
