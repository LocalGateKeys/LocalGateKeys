import Foundation
import XCTest
@testable import LGKCore

/// `LGKMBAK1` against tests/vectors/backup. `LGK_WRITE_FROM_IOS=1` rewrites
/// tests/vectors/backup/from_ios/backup.lgkm; otherwise the written bytes must equal the committed file.
/// The desktop restores it in tests/test_phone_backup_vectors.py.
final class PhoneBackupTests: XCTestCase {
    static let root: URL = {
        var u = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { u.deleteLastPathComponent() }
        return u.appendingPathComponent("tests/vectors/backup", isDirectory: true)
    }()
    static let password = "correct horse battery staple 42"

    struct FixedRandom: RandomSource {
        let salt: [UInt8], nonce: [UInt8]
        func bytes(count: Int) -> [UInt8] { count == 16 ? salt : count == 12 ? nonce : [UInt8](repeating: 7, count: count) }
    }

    func expected() throws -> [String: JSONValue] {
        let data = try Data(contentsOf: Self.root.appendingPathComponent("expected.json"))
        guard case .object(let o) = try CanonicalJSON.parse(Array(data)) else { throw JSONError.syntax }
        return o
    }

    func expectedStates(_ e: [String: JSONValue]) throws -> [BackupState] {
        guard case .array(let a)? = e["states"] else { throw JSONError.syntax }
        return a.map { j in
            let o = MergeVectors.obj(j)
            var vv: [String: Int64] = [:]
            for (k, v) in MergeVectors.obj(o["vv"]) { if case .int(let n) = v { vv[k] = n } }
            var at: Int64?
            if case .int(let n)? = o["deleted_at"] { at = n }
            return BackupState(id: MergeVectors.str(o["id"])!, deleted: o["deleted"] == .bool(true), deletedAt: at,
                               item: o["item"] == .null ? nil : o["item"], vv: vv)
        }
    }

    func fixedRandom(_ e: [String: JSONValue]) throws -> FixedRandom {
        FixedRandom(salt: try Base64.decodeStrict(MergeVectors.str(e["salt_b64"])!),
                    nonce: try Base64.decodeStrict(MergeVectors.str(e["nonce_b64"])!))
    }

    func testOpensDesktopVector() throws {
        let e = try expected()
        let p = try PhoneBackup.open(Data(contentsOf: Self.root.appendingPathComponent("backup.lgkm")), password: Self.password)
        XCTAssertEqual(p.states, try expectedStates(e))
        XCTAssertEqual(p.deviceID, MergeVectors.str(e["device_id"]))
        XCTAssertEqual(p.appVersion, MergeVectors.str(e["app_version"]))
        XCTAssertEqual(.bool(p.proHint), e["pro_hint"])
        XCTAssertEqual(p.platform, "android")
        XCTAssertEqual(.int(p.createdAt), e["created_at"])
    }

    func testSealThenOpenRoundTrip() throws {
        let e = try expected()
        let states = try expectedStates(e)
        let file = try PhoneBackup.seal(states: states.reversed(), password: "pässwörd", appVersion: "1.2.3",
                                        deviceID: "dev-1", proHint: true, now: Date(timeIntervalSince1970: 1_800_000_000.7),
                                        random: SystemRandomSource())
        let p = try PhoneBackup.open(file, password: "pässwörd")
        XCTAssertEqual(p.states, states)
        XCTAssertEqual(p.platform, "ios")
        XCTAssertEqual(p.createdAt, 1_800_000_000)
        XCTAssertEqual(p.appVersion, "1.2.3")
        XCTAssertEqual(p.deviceID, "dev-1")
        XCTAssertTrue(p.proHint)
    }

    func testSealIsByteExactWithFixedRandom() throws {
        let e = try expected()
        guard case .int(let created)? = e["created_at"] else { throw JSONError.syntax }
        let file = try PhoneBackup.seal(states: try expectedStates(e), password: Self.password,
                                        appVersion: MergeVectors.str(e["app_version"])!,
                                        deviceID: MergeVectors.str(e["device_id"])!, proHint: false,
                                        now: Date(timeIntervalSince1970: TimeInterval(created)),
                                        random: try fixedRandom(e))
        let url = Self.root.appendingPathComponent("from_ios/backup.lgkm")
        if ProcessInfo.processInfo.environment["LGK_WRITE_FROM_IOS"] == "1" {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try file.write(to: url)
        }
        XCTAssertEqual(file, try Data(contentsOf: url))
        // The same inputs as backup.lgkm except the platform: identical up to the header (AAD) and tag.
        let desktop = try String(contentsOf: Self.root.appendingPathComponent("backup.lgkm"), encoding: .utf8)
        XCTAssertTrue(desktop.contains("\"platform\":\"android\""))
        XCTAssertTrue(String(decoding: file, as: UTF8.self).contains("\"platform\":\"ios\""))
    }

    func testWrongPasswordThrows() throws {
        let file = try Data(contentsOf: Self.root.appendingPathComponent("backup.lgkm"))
        XCTAssertThrowsError(try PhoneBackup.open(file, password: "wrong")) {
            XCTAssertEqual($0 as? PhoneBackup.Error, .wrongPassword)
        }
    }

    // MARK: format 2 (document files)

    func expectedFormat2() throws -> [String: JSONValue] {
        let data = try Data(contentsOf: Self.root.appendingPathComponent("format2/expected.json"))
        guard case .object(let o) = try CanonicalJSON.parse(Array(data)) else { throw JSONError.syntax }
        return o
    }

    func testOpensFormat2Vector() throws {
        let e = try expectedFormat2()
        let p = try PhoneBackup.open(Data(contentsOf: Self.root.appendingPathComponent("format2/backup.lgkm")),
                                     password: MergeVectors.str(e["password"])!)
        XCTAssertEqual(p.states, try expectedStates(e))
        XCTAssertEqual(p.deviceID, MergeVectors.str(e["device_id"]))
        XCTAssertEqual(p.platform, "android")
        guard case .array(let files)? = e["files"] else { throw JSONError.syntax }
        XCTAssertEqual(p.files.count, files.count)
        for f in files {
            let spec = MergeVectors.obj(f)
            let blob = try XCTUnwrap(p.files[MergeVectors.str(spec["blob"])!])
            XCTAssertEqual(.int(Int64(blob.count)), spec["blob_size"])
            XCTAssertEqual(AttachmentSync.blobID(blob), MergeVectors.str(spec["blob_sha256"]))
        }
        // The document names the file, and the file opens against its reference to the attachment vector's
        // plaintext (`file_size` / `file_sha256` describe the .lgkm file itself, as in format 1).
        let doc = try XCTUnwrap(p.states.first { $0.id == MergeVectors.str(e["document_id"]) })
        let ref = try XCTUnwrap(AttachmentDocuments.ref(of: doc.item))
        let data = try AttachmentSync.openBlob(try XCTUnwrap(p.files[ref.blob]), ref: ref)
        guard case .object(let av) = try CanonicalJSON.parse(Array(Vectors.data("attachments/vectors.json"))),
              case .array(let blobs)? = av["blobs"],
              let small = blobs.map(MergeVectors.obj).first(where: { MergeVectors.str($0["name"]) == "small" })
        else { throw JSONError.syntax }
        XCTAssertEqual(lowerHex(AttachmentSync.sha256(data)), MergeVectors.str(small["plaintext_sha256"]))
    }

    func testSealFormat2IsByteExactWithFixedRandom() throws {
        let e = try expectedFormat2()
        let url = Self.root.appendingPathComponent("format2/backup.lgkm")
        let desktop = try Data(contentsOf: url)
        let p = try PhoneBackup.open(desktop, password: Self.password)
        let header = MergeVectors.obj(e["header"])
        guard case .int(let created)? = header["created_at"] else { throw JSONError.syntax }
        let random = FixedRandom(salt: try Base64.decodeStrict(MergeVectors.str(header["salt"])!),
                                 nonce: try Base64.decodeStrict(MergeVectors.str(header["nonce"])!))
        let file = try PhoneBackup.seal(states: p.states, password: Self.password, appVersion: p.appVersion,
                                        deviceID: p.deviceID, proHint: p.proHint,
                                        now: Date(timeIntervalSince1970: TimeInterval(created)), random: random,
                                        files: p.files, writerPlatform: "android")
        XCTAssertEqual(file, desktop)
        // Without files the writer stays on version 1; the public writer says "ios".
        let v1 = try PhoneBackup.seal(states: p.states, password: Self.password, appVersion: p.appVersion,
                                      deviceID: p.deviceID, proHint: p.proHint, now: Date(), random: SystemRandomSource())
        XCTAssertTrue(String(decoding: v1, as: UTF8.self).contains("\"version\":1"))
        XCTAssertTrue(try PhoneBackup.open(v1, password: Self.password).files.isEmpty)
    }

    func testSealRefusesFilesNoDocumentNames() throws {
        let p = try PhoneBackup.open(Data(contentsOf: Self.root.appendingPathComponent("format2/backup.lgkm")),
                                     password: Self.password)
        let noDocs = p.states.filter { AttachmentDocuments.ref(of: $0.item) == nil }
        XCTAssertThrowsError(try PhoneBackup.seal(states: noDocs, password: Self.password, appVersion: p.appVersion,
                                                  deviceID: p.deviceID, proHint: false, now: Date(),
                                                  random: SystemRandomSource(), files: p.files)) {
            XCTAssertEqual($0 as? PhoneBackup.Error, .badPayload)
        }
    }

    func testSelectFilesKeepsStateOrderWithinBudget() throws {
        let p = try PhoneBackup.open(Data(contentsOf: Self.root.appendingPathComponent("format2/backup.lgkm")),
                                     password: Self.password)
        let ref = try XCTUnwrap(AttachmentDocuments.refs(p.states.compactMap {
            try? ItemState(itemID: $0.id, vv: $0.vv, deleted: $0.deleted, deletedAt: $0.deletedAt, item: $0.item)
        }).first)
        let all = PhoneBackup.selectFiles(p.states) { p.files[$0.blob] }
        XCTAssertEqual(all.files, p.files)
        XCTAssertEqual(all.leftOut, [])
        let tight = PhoneBackup.selectFiles(p.states, budget: ref.blobSize - 1) { p.files[$0.blob] }
        XCTAssertEqual(tight.files, [:])
        XCTAssertEqual(tight.leftOut, [ref.attachmentID])
        let missing = PhoneBackup.selectFiles(p.states) { _ in nil }
        XCTAssertEqual(missing.leftOut, [ref.attachmentID])
    }

    func testFormat2RejectedVectorsFail() throws {
        let rejected = MergeVectors.obj(try expectedFormat2()["rejected"])
        let dir = Self.root.appendingPathComponent("format2/rejected")
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".lgkm") }
        XCTAssertEqual(Set(files), Set(rejected.keys))
        for name in files.sorted() {
            let spec = MergeVectors.obj(rejected[name])
            XCTAssertEqual(MergeVectors.str(spec["reason"]), "bad-payload", name)
            XCTAssertThrowsError(try PhoneBackup.open(Data(contentsOf: dir.appendingPathComponent(name)),
                                                      password: MergeVectors.str(spec["password"])!), name) {
                XCTAssertEqual($0 as? PhoneBackup.Error, .badPayload, name)
            }
        }
    }

    func testRejectedVectorsFail() throws {
        let reasons: [String: PhoneBackup.Error] = [
            "wrong-password-or-damaged": .wrongPassword, "not-a-backup": .notABackup,
            "unsupported-version": .unsupportedVersion, "bad-kdf": .badKDF, "bad-payload": .badPayload,
            "too-large": .tooLarge,
        ]
        let rejected = MergeVectors.obj(try expected()["rejected"])
        let dir = Self.root.appendingPathComponent("rejected")
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".lgkm") }
        XCTAssertEqual(Set(files), Set(rejected.keys))
        for name in files.sorted() {
            let spec = MergeVectors.obj(rejected[name])
            let want = reasons[MergeVectors.str(spec["reason"])!]
            XCTAssertThrowsError(try PhoneBackup.open(Data(contentsOf: dir.appendingPathComponent(name)),
                                                      password: MergeVectors.str(spec["password"])!), name) {
                XCTAssertEqual($0 as? PhoneBackup.Error, want, name)
            }
        }
    }
}
