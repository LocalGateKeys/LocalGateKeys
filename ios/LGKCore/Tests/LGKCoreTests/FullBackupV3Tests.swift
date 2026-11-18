import Crypto
import Foundation
import XCTest
@testable import LGKCore

/// Full backup v3 (scheduled backups to a public key, design section 3.4): writer, reader, self-verify (9.1), re-lock
/// (7.2) and the v2/v3 dispatcher. Uses the v2 fixture profile (`tests/vectors/backup/v2/inputs`) and the records of
/// `tests/vectors/backup/v3/record.json`. `from_mac_v3.lgkfull` is written here for `tests/test_backup_v3_vectors.py`;
/// the Windows container vectors (`full.lgkfull`, `relocked.lgkfull`, `rejected/`) are checked when present.
final class FullBackupV3Tests: XCTestCase {
    static let v2 = BackupKeyTests.dir.deletingLastPathComponent().appendingPathComponent("v2", isDirectory: true)
    private static let v3 = BackupKeyTests.dir

    static func v2Expected() throws -> [String: JSONValue] {
        try BackupKeyTests.obj(CanonicalJSON.parse(Array(Data(contentsOf: v2.appendingPathComponent("expected.json")))))
    }
    private static func input(_ name: String) throws -> Data { try Data(contentsOf: v2.appendingPathComponent("inputs/\(name)")) }
    private static func attachments() throws -> [(id: String, data: Data)] {
        try BackupKeyTests.arr(v2Expected()["attachment_ids"]).map { v in
            let id = try BackupKeyTests.str(v)
            return (id: id, data: try input("\(id).blob"))
        }
    }

    /// `record.json` records with their passwords.
    private static func record(_ name: String) throws -> (record: BackupKeyRecord, password: String) {
        let records = try BackupKeyTests.obj(BackupKeyTests.load("record.json")["records"])
        let entry = try BackupKeyTests.obj(records[name])
        return (try BackupKeyTests.record(entry["record"]),
                try BackupKeyTests.str(BackupKeyTests.obj(entry["inputs"])["password"]))
    }

    private static func write(_ record: BackupKeyRecord, seed: String, createdAt: Int64 = 1_793_100_000) throws -> FullBackupV3.Written {
        try FullBackupV3.write(vault: input("vault.json"), settings: input("settings.json"), attachments: attachments(),
                               record: record, random: FullBackupV2Tests.Replay(Array(seed.utf8)),
                               progress: { _, _, _ in }, cancel: { false }, generation: input("generation.json"),
                               profileName: BackupKeyTests.str(v2Expected()["profile_name"]), createdAt: createdAt)
    }

    /// Every member of a stored zip, in order.
    private static func members(_ data: Data) throws -> [(name: String, data: Data)] {
        let reader = try ZipReader(data: data, maxBytes: FullBackupV2.maxBackupBytes, maxEntries: FullBackupV2.maxEntries + 2)
        return try reader.entries().map { (name: $0.name, data: try reader.read($0, limit: FullBackupV2.maxBackupBytes)) }
    }

    /// The same zip with `header.json` edited (or replaced).
    private static func rezip(_ data: Data, header edit: (inout [String: JSONValue]) throws -> Void) throws -> Data {
        var zip = ZipWriter()
        for m in try members(data) {
            var bytes = m.data
            if m.name == "header.json" {
                var h = try BackupKeyTests.obj(CanonicalJSON.parse(Array(bytes)))
                try edit(&h)
                bytes = Data(try CanonicalJSON.encode(.object(h), dialect: .utf8))
            }
            try zip.addStored(name: m.name, data: bytes)
        }
        return try zip.finish()
    }

    private static func header(_ data: Data) throws -> [String: JSONValue] {
        try BackupKeyTests.obj(CanonicalJSON.parse(Array(XCTUnwrap(members(data).first { $0.name == "header.json" }).data)))
    }

    private func assertSameContents(_ c: FullBackupContents, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(c.vault, try Self.input("vault.json"), file: file, line: line)
        XCTAssertEqual(c.settings, try Self.input("settings.json"), file: file, line: line)
        XCTAssertEqual(c.generation, try Self.input("generation.json"), file: file, line: line)
        XCTAssertEqual(c.attachments.map(\.id), try Self.attachments().map(\.id), file: file, line: line)
        XCTAssertEqual(c.attachments.map(\.data), try Self.attachments().map(\.data), file: file, line: line)
        XCTAssertEqual(c.profileName, try BackupKeyTests.str(Self.v2Expected()["profile_name"]), file: file, line: line)
    }

    // MARK: write, read, inspect

    func testRoundTripOpensWithTheBackupPasswordOnly() throws {
        let (record, password) = try Self.record("set")
        var written = try Self.write(record, seed: "v3-round-trip")
        defer { written.wipe() }
        let data = written.data

        // The public header: v3, the record's key id, set time and KDF; no public key anywhere in the file.
        guard case .v3(let info) = try FullBackup.inspect(data) else { return XCTFail("not v3") }
        XCTAssertEqual(info.entryCount, 5)
        XCTAssertEqual(info.recipient.keyID, record.keyID)
        XCTAssertEqual(info.recipient.keySetAt, record.setAt)
        XCTAssertEqual(info.recipient.kdf, record.kdf)
        XCTAssertEqual(FullBackup.headerVersion(data), 3)
        XCTAssertNil(data.range(of: Data(record.publicKey)))
        XCTAssertNil(data.range(of: Data(Base64.encode(record.publicKey).utf8)))
        let h = try Self.header(data)
        XCTAssertEqual(Set(h.keys), FullBackupV3.headerFields)
        XCTAssertEqual(Set(try BackupKeyTests.obj(h["recipient"]).keys), FullBackupV3.recipientFields)

        let contents = try FullBackup.open(data, password: password)
        try assertSameContents(contents)
        XCTAssertEqual(contents.createdAt, 1_793_100_000)
        // The inner vault still opens with the master password of the fixture.
        let master = try BackupKeyTests.str(Self.v2Expected()["master_password"])
        XCTAssertNoThrow(try DesktopVaultFile.open(contents.vault, password: master))

        for wrong in ["second fixture backup password", try BackupKeyTests.str(Self.v2Expected()["backup_password"])] {
            XCTAssertThrowsError(try FullBackupV3.open(data, password: wrong)) {
                XCTAssertEqual(BackupKeyTests.message($0), "Wrong backup password or modified full backup")
            }
        }
        XCTAssertThrowsError(try FullBackupV3.open(data, password: "short")) {
            XCTAssertEqual(BackupKeyTests.message($0), "Backup password must contain at least 12 characters")
        }
        XCTAssertThrowsError(try FullBackupV3.open(data, password: password, cancel: { true })) {
            XCTAssertEqual(BackupKeyTests.message($0), "Backup operation was cancelled")
        }
        // The same inputs and random stream give the same bytes.
        XCTAssertEqual(try Self.write(record, seed: "v3-round-trip").data, data)
    }

    func testOldFormatStillGoesToTheV2Reader() throws {
        let file = try Data(contentsOf: Self.v2.appendingPathComponent("full.lgkfull"))
        let password = try BackupKeyTests.str(Self.v2Expected()["backup_password"])
        XCTAssertEqual(FullBackup.headerVersion(file), 2)
        guard case .v2(let info) = try FullBackup.inspect(file) else { return XCTFail("not v2") }
        XCTAssertEqual(info, try FullBackupV2.inspect(file))
        XCTAssertEqual(try FullBackup.open(file, password: password), try FullBackupV2.open(file, password: password))
        XCTAssertThrowsError(try FullBackupV3.inspect(file)) {
            XCTAssertEqual(BackupKeyTests.message($0), "Unsupported full backup format")
        }
        // Not a backup at all: the v2 reader's message, as before.
        XCTAssertNil(FullBackup.headerVersion(Data("nope".utf8)))
        XCTAssertThrowsError(try FullBackup.open(Data("nope".utf8), password: password)) {
            XCTAssertEqual(BackupKeyTests.message($0), "Could not read full backup")
        }
    }

    // MARK: self-verify (9.1)

    func testVerifyWrittenNeedsNoPasswordAndCatchesTampering() throws {
        let (record, _) = try Self.record("set")
        let (other, _) = try Self.record("changed")
        var written = try Self.write(record, seed: "v3-verify")
        defer { written.wipe() }
        try assertSameContents(FullBackupV3.verifyWritten(written.data, dataKey: written.dataKey,
                                                          ephemeralSecret: written.ephemeralSecret, record: record))
        func refused(_ data: Data, record r: BackupKeyRecord = record, dataKey: [UInt8]? = nil, esk: [UInt8]? = nil,
                     _ why: String) {
            XCTAssertThrowsError(try FullBackupV3.verifyWritten(data, dataKey: dataKey ?? written.dataKey,
                                                               ephemeralSecret: esk ?? written.ephemeralSecret, record: r), why)
        }
        // A record public key swapped between make and verify.
        refused(written.data, record: other, "other record")
        refused(written.data, dataKey: [UInt8](repeating: 7, count: 32), "other data key")
        refused(written.data, esk: [UInt8](repeating: 7, count: 32), "other ephemeral key")
        // Any member changed after writing.
        let members = try Self.members(written.data)
        for index in members.indices {
            var edited = members
            var bytes = [UInt8](edited[index].data)
            bytes[bytes.count / 2] ^= 0x01
            edited[index].data = Data(bytes)
            var zip = ZipWriter()
            for m in edited { try zip.addStored(name: m.name, data: m.data) }
            refused(try zip.finish(), "member \(members[index].name)")
        }
        // The header: the set time and the entry count are authenticated.
        refused(try Self.rezip(written.data) { h in
            guard case .object(var r)? = h["recipient"], case .int(let n)? = r["key_set_at"] else { return }
            r["key_set_at"] = .int(n + 1); h["recipient"] = .object(r)
        }, "key_set_at")
        refused(try Self.rezip(written.data) { h in
            if case .int(let n)? = h["entry_count"] { h["entry_count"] = .int(n + 1) }
        }, "entry_count")
    }

    // MARK: re-lock (7.2)

    func testRelockReplacesOnlyTheHeader() throws {
        let (old, oldPassword) = try Self.record("set")
        let (new, newPassword) = try Self.record("changed")
        let original = try Self.write(old, seed: "v3-relock").data
        var oldKey = try BackupKey.derive(password: oldPassword, kdf: old.kdf)
        defer { oldKey.wipe() }
        var relocked = try FullBackupV3.relock(original, oldKey: oldKey, newRecord: new, random: FullBackupV2Tests.Replay(Array("relock".utf8)))
        defer { relocked.wipe() }
        try assertSameContents(FullBackupV3.verifyWritten(relocked.data, dataKey: relocked.dataKey,
                                                          ephemeralSecret: relocked.ephemeralSecret, record: new))
        let before = try Self.members(original), after = try Self.members(relocked.data)
        XCTAssertEqual(before.map(\.name), after.map(\.name))
        for (a, b) in zip(before, after) where a.name != "header.json" { XCTAssertEqual(a.data, b.data, a.name) }
        XCTAssertNotEqual(before.first?.data, after.first?.data)
        // Same core, new recipient.
        var ho = try Self.header(original), hn = try Self.header(relocked.data)
        let ro = try BackupKeyTests.obj(ho.removeValue(forKey: "recipient")), rn = try BackupKeyTests.obj(hn.removeValue(forKey: "recipient"))
        XCTAssertEqual(ho, hn)
        XCTAssertEqual(rn["key_id"], .string(new.keyID))
        XCTAssertEqual(rn["key_set_at"], .int(new.setAt))
        XCTAssertEqual(rn["kdf"], new.kdf.json)
        XCTAssertNotEqual(rn["ephemeral_public_key"], ro["ephemeral_public_key"])

        try assertSameContents(FullBackupV3.open(relocked.data, password: newPassword))
        XCTAssertThrowsError(try FullBackupV3.open(relocked.data, password: oldPassword))
        XCTAssertNoThrow(try FullBackupV3.open(original, password: oldPassword))

        // A file under another key is refused without touching anything; so is a wrong old key.
        var wrongKey = try BackupKey.derive(password: newPassword, kdf: new.kdf)
        defer { wrongKey.wipe() }
        XCTAssertThrowsError(try FullBackupV3.relock(original, oldKey: wrongKey, newRecord: old, random: SystemRandomSource()))
        // An old-format file is not a v3 file: refused by the header check (the app skips it before reading more).
        let v2File = try Data(contentsOf: Self.v2.appendingPathComponent("full.lgkfull"))
        XCTAssertThrowsError(try FullBackupV3.relock(v2File, oldKey: oldKey, newRecord: new, random: SystemRandomSource())) {
            XCTAssertEqual(BackupKeyTests.message($0), "Unsupported full backup format")
        }
    }

    // MARK: refused headers (the Windows messages are pinned by `rejected/` when present)

    func testRefusedHeaders() throws {
        let (record, password) = try Self.record("set")
        let (other, _) = try Self.record("changed")
        let good = try Self.write(record, seed: "v3-rejected").data
        // Another file under the same key: its recipient is a valid wrap of another data key.
        let otherFile = try Self.write(record, seed: "v3-rejected-other").data
        let wrong = "Wrong backup password or modified full backup"
        func recipient(_ edit: @escaping (inout [String: JSONValue]) -> Void) throws -> Data {
            try Self.rezip(good) { h in
                guard case .object(var r)? = h["recipient"] else { return }
                edit(&r); h["recipient"] = .object(r)
            }
        }
        let cases: [(String, Data, String)] = [
            ("unknown scheme", try recipient { $0["scheme"] = .string("x25519-hkdf-sha256-aes-256-gcm-v2") },
             FullBackupV3.Messages.unsupportedCipher.message),
            ("extra recipient key", try recipient { $0["public_key"] = .string(Base64.encode(record.publicKey)) },
             "Unsupported full backup format"),
            ("extra header key", try Self.rezip(good) { $0["kdf"] = record.kdf.json }, "Unsupported full backup format"),
            ("salt not canonical", try recipient {
                guard case .object(var k)? = $0["kdf"] else { return }
                k["salt"] = .string("AAAAAAAAAAAAAAAAAAAAAA"); $0["kdf"] = .object(k)
            }, "Malformed full backup KDF salt"),
            ("kdf out of range", try recipient {
                guard case .object(var k)? = $0["kdf"] else { return }
                k["time_cost"] = .int(11); $0["kdf"] = .object(k)
            }, "Unsupported backup encryption parameters"),
            ("wrapped short", try recipient { $0["wrapped_key"] = .string(Base64.encode([UInt8](repeating: 1, count: 47))) },
             FullBackupV3.Messages.malformedRecipient.message),
            ("epk low order", try recipient { $0["ephemeral_public_key"] = .string(Base64.encode([UInt8](repeating: 0, count: 32))) }, wrong),
            ("key id mismatch", try recipient { $0["key_id"] = .string(other.keyID) }, wrong),
            ("tampered recipient kdf (salt)", try recipient { $0["kdf"] = other.kdf.json }, wrong),
            ("tampered core entry count", try Self.rezip(good) { h in
                if case .int(let n)? = h["entry_count"] { h["entry_count"] = .int(n + 1) }
            }, wrong),
            ("version 4", try Self.rezip(good) { $0["version"] = .int(4) }, "Unsupported full backup format"),
            ("recipient from another file", try Self.rezip(good) { h in h["recipient"] = try Self.header(otherFile)["recipient"] }, wrong),
        ]
        for (name, data, message) in cases {
            XCTAssertThrowsError(try FullBackupV3.open(data, password: password), name) {
                XCTAssertEqual(BackupKeyTests.message($0), message, name)
            }
        }
        XCTAssertNoThrow(try FullBackupV3.open(otherFile, password: password))
    }

    // MARK: cross-platform vectors

    /// Writes `from_mac_v3.lgkfull` (the v2 fixture profile to `expected.json` `record`, password
    /// `expected.backup_password`, created 1793100000) for `pytest tests/test_backup_v3.py`.
    func testMacV3BackupForPython() throws {
        let expected = try Self.v3Expected()
        let record = try BackupKeyTests.record(expected["record"])
        let password = try BackupKeyTests.str(expected["backup_password"])
        var written = try Self.write(record, seed: "from-mac-backup-v3")
        defer { written.wipe() }
        let url = Self.v3.appendingPathComponent("from_mac_v3.lgkfull")
        // The tracked copy is rewritten only on request (`LGK_WRITE_FROM_MAC=1`): its bytes differ every run.
        if ProcessInfo.processInfo.environment["LGK_WRITE_FROM_MAC"] == "1", (try? Data(contentsOf: url)) != written.data { try written.data.write(to: url) }
        try assertSameContents(FullBackupV3.open(written.data, password: password))
    }

    /// The Windows container vectors (`full.lgkfull`, `relocked.lgkfull`, `rejected/*.lgkfull`, `expected.json`;
    /// `SCHEMA.md` "full.lgkfull, relocked.lgkfull, expected.json, rejected/"): byte equality of the writer and the
    /// re-lock from the recorded random streams, the reader, and every refused file with the Windows message.
    func testWindowsContainerVectors() throws {
        let expected = try Self.v3Expected()
        let full = try Data(contentsOf: Self.v3.appendingPathComponent("full.lgkfull"))
        let password = try BackupKeyTests.str(expected["backup_password"])
        let record = try BackupKeyTests.record(expected["record"])
        XCTAssertEqual(lowerHex(SHA256.hash(data: full)), try BackupKeyTests.str(expected["full_sha256"]))
        XCTAssertEqual(try FullBackupV3Tests.header(full), try BackupKeyTests.obj(expected["header"]))

        // The writer, from the recorded stream (dk, esk, then the nonces).
        var rebuilt = try FullBackupV3.write(
            vault: Self.input("vault.json"), settings: Self.input("settings.json"), attachments: Self.attachments(),
            record: record, random: FullBackupV2Tests.Replay(BackupKeyTests.hex(expected["random_hex"])), progress: { _, _, _ in },
            cancel: { false }, generation: Self.input("generation.json"),
            profileName: BackupKeyTests.str(expected["profile_name"]), createdAt: BackupKeyTests.int(expected["created_at"]))
        defer { rebuilt.wipe() }
        XCTAssertEqual(rebuilt.data, full)
        XCTAssertEqual(rebuilt.dataKey, try BackupKeyTests.hex(expected["data_key"]))
        XCTAssertNoThrow(try FullBackupV3.verifyWritten(full, dataKey: rebuilt.dataKey, ephemeralSecret: rebuilt.ephemeralSecret,
                                                        record: record))

        // The reader.
        let contents = try FullBackup.open(full, password: password)
        try assertSameContents(contents)
        XCTAssertEqual(contents.createdAt, try BackupKeyTests.int(expected["created_at"]))
        let master = try BackupKeyTests.str(expected["master_password"])
        XCTAssertNoThrow(try DesktopVaultFile.open(contents.vault, password: master))
        guard case .v3(let info) = try FullBackup.inspect(full) else { return XCTFail("not v3") }
        XCTAssertEqual(info.recipient.keyID, record.keyID)
        XCTAssertEqual(info.recipient.keySetAt, record.setAt)

        // The re-lock, from the recorded ephemeral key: only header.json differs.
        let relocked = try Data(contentsOf: Self.v3.appendingPathComponent("relocked.lgkfull"))
        let second = try BackupKeyTests.str(expected["second_password"])
        let newRecord = try BackupKeyTests.record(expected["relock_record"])
        var oldKey = try BackupKey.derive(password: password, kdf: record.kdf)
        defer { oldKey.wipe() }
        var mine = try FullBackupV3.relock(full, oldKey: oldKey, newRecord: newRecord,
                                           random: FullBackupV2Tests.Replay(BackupKeyTests.hex(expected["relock_esk_random"])))
        defer { mine.wipe() }
        XCTAssertEqual(mine.data, relocked)
        XCTAssertEqual(lowerHex(SHA256.hash(data: relocked)), try BackupKeyTests.str(expected["relocked_sha256"]))
        XCTAssertEqual(try FullBackupV3Tests.header(relocked), try BackupKeyTests.obj(expected["relocked_header"]))
        let before = try Self.members(full), after = try Self.members(relocked)
        XCTAssertEqual(before.map(\.name), after.map(\.name))
        for (a, b) in zip(before, after) where a.name != "header.json" { XCTAssertEqual(a.data, b.data, a.name) }
        try assertSameContents(FullBackupV3.open(relocked, password: second))

        // Every refused file, with the Windows message.
        let rejected = try BackupKeyTests.obj(expected["rejected"])
        var checked = 0
        for (name, value) in rejected {
            let message = try BackupKeyTests.str(value)
            let file: Data, pw: String
            switch name {
            case "full.lgkfull with a wrong password": (file, pw) = (full, "not the backup password")
            case "relocked.lgkfull with the first password": (file, pw) = (relocked, password)
            default: (file, pw) = (try Data(contentsOf: Self.v3.appendingPathComponent("rejected/\(name).lgkfull")), password)
            }
            XCTAssertThrowsError(try FullBackup.open(file, password: pw), name) {
                XCTAssertEqual(BackupKeyTests.message($0), message, name)
            }
            checked += 1
        }
        XCTAssertGreaterThanOrEqual(checked, 16)
    }

    private static func v3Expected() throws -> [String: JSONValue] {
        try BackupKeyTests.obj(CanonicalJSON.parse(Array(Data(contentsOf: v3.appendingPathComponent("expected.json")))))
    }

    private static func string(_ v: JSONValue?) -> String? { if case .string(let s)? = v { return s }; return nil }
}
