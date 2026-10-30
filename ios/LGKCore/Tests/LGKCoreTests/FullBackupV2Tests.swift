import Foundation
import XCTest
@testable import LGKCore

/// Full backup v2 (`backup.py` `export_full_backup`) and the Windows `vault.json` envelope, pinned to
/// `tests/vectors/backup/v2` (written by `scripts/gen_mac_backup_vectors.py backup`). `from_mac.lgkfull` is written
/// here and opened by Windows in `tests/test_mac_backup_vectors.py`.
final class FullBackupV2Tests: XCTestCase {
    private static let repo: URL = Vectors.root.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    private static let dir = repo.appendingPathComponent("tests/vectors/backup/v2", isDirectory: true)

    /// Replays a fixed byte stream (the bytes Python's `os.urandom` handed out), then a seeded counter stream.
    final class Replay: RandomSource, @unchecked Sendable {
        private var bytes: [UInt8]
        private var position = 0
        private let lock = NSLock()
        init(_ bytes: [UInt8]) { self.bytes = bytes }
        func bytes(count: Int) -> [UInt8] {
            lock.lock(); defer { lock.unlock() }
            while position + count > bytes.count {
                bytes += Array(CryptoBox.hkdf(ikm: [UInt8(truncatingIfNeeded: bytes.count)], salt: [], info: Array("replay".utf8), length: 32))
            }
            defer { position += count }
            return Array(bytes[position..<(position + count)])
        }
    }

    private static func expected() throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Data(contentsOf: dir.appendingPathComponent("expected.json"))) as! [String: Any]
    }
    private static func input(_ name: String) throws -> Data { try Data(contentsOf: dir.appendingPathComponent("inputs/\(name)")) }
    /// The cheap Argon2id parameters the vectors use (`CHEAP_KDF` in the generator).
    private static let cheap = FullBackupV2.KDF(timeCost: 1, memoryKiB: 8192, parallelism: 1)
    private static func attachments() throws -> [(id: String, data: Data)] {
        let ids = try expected()["attachment_ids"] as! [String]
        return try ids.map { (id: $0, data: try input("\($0).blob")) }
    }
    private static func records() throws -> [JSONValue] {
        let e = try CanonicalJSON.parse(Array(Data(contentsOf: dir.appendingPathComponent("expected.json"))))
        guard case .object(let o) = e, case .array(let r)? = o["records"] else { throw XCTSkip("no records") }
        return r
    }
    private static func string(_ key: String) throws -> String { try expected()[key] as! String }

    func testWriteMatchesPythonBytes() throws {
        let e = try Self.expected()
        var events: [(String, Int, Int)] = []
        let data = try FullBackupV2.write(
            vault: Self.input("vault.json"), settings: Self.input("settings.json"), attachments: Self.attachments(),
            password: Self.string("backup_password"), random: Replay(KDBXHex.hex(e["random_hex"] as! String)),
            progress: { events.append(($0, $1, $2)) }, cancel: { false },
            generation: Self.input("generation.json"), profileName: Self.string("profile_name"),
            createdAt: Int64(e["created_at"] as! Int), kdf: Self.cheap)
        XCTAssertEqual(data, try Data(contentsOf: Self.dir.appendingPathComponent("full.lgkfull")))
        XCTAssertEqual(events.last?.0, "export")
        XCTAssertEqual(events.last?.1, 5)
        XCTAssertEqual(events.last?.2, 5)
    }

    func testOpenPythonBackup() throws {
        let file = try Data(contentsOf: Self.dir.appendingPathComponent("full.lgkfull"))
        let info = try FullBackupV2.inspect(file)
        XCTAssertEqual(info.entryCount, 5)
        XCTAssertEqual(info.kdf, Self.cheap)
        let c = try FullBackupV2.open(file, password: Self.string("backup_password"))
        XCTAssertEqual(c.profileName, try Self.string("profile_name"))
        XCTAssertEqual(c.createdAt, 1_793_000_000)
        XCTAssertEqual(c.vault, try Self.input("vault.json"))
        XCTAssertEqual(c.settings, try Self.input("settings.json"))
        XCTAssertEqual(c.generation, try Self.input("generation.json"))
        XCTAssertEqual(c.attachments.map(\.id), try Self.attachments().map(\.id))
        XCTAssertEqual(c.attachments.map(\.data), try Self.attachments().map(\.data))

        // The Windows vault inside opens with the master password to the records Windows wrote.
        let opened = try DesktopVaultFile.open(c.vault, password: Self.string("master_password"))
        XCTAssertFalse(opened.recoveryEnrolled)
        XCTAssertEqual(Self.sortedByID(opened.items), Self.sortedByID(try Self.records()))
        XCTAssertThrowsError(try DesktopVaultFile.open(c.vault, password: "not the master password")) {
            XCTAssertEqual(($0 as? DesktopVaultError)?.message, "Incorrect master password or modified vault")
        }
    }

    private static func sortedByID(_ v: [JSONValue]) -> [JSONValue] {
        func id(_ x: JSONValue) -> String { if case .object(let o) = x, case .string(let s)? = o["id"] { return s }; return "" }
        return v.sorted { id($0) < id($1) }
    }

    /// Writes `from_mac.lgkfull` (a Mac backup: a Mac-sealed Windows vault, Windows settings and two sidecars) for
    /// `pytest tests/test_mac_backup_vectors.py`, which opens and restores it with Windows code.
    func testMacBackupOpensInPython() throws {
        let random = Replay(Array("from-mac-backup-v2".utf8))
        let master = try Self.string("master_password")
        let vault = try DesktopVaultFile.seal(items: Self.records(), settings: .object([:]), password: master, random: random,
                                              now: 1_793_100_000, kdf: Self.cheap)
        let reopened = try DesktopVaultFile.open(vault, password: master)
        XCTAssertEqual(Self.sortedByID(reopened.items), Self.sortedByID(try Self.records()))
        let data = try FullBackupV2.write(
            vault: vault, settings: Self.input("settings.json"), attachments: Self.attachments(),
            password: Self.string("backup_password"), random: random, progress: { _, _, _ in }, cancel: { false },
            profileName: Self.string("profile_name"), createdAt: 1_793_100_000, kdf: Self.cheap)
        let url = Self.dir.appendingPathComponent("from_mac.lgkfull")
        if (try? Data(contentsOf: url)) != data { try data.write(to: url) }
        let back = try FullBackupV2.open(data, password: Self.string("backup_password"))
        XCTAssertEqual(back.vault, vault)
        XCTAssertNil(back.generation)
    }

    func testEachRejectedVectorRefused() throws {
        let rejected = try Self.expected()["rejected"] as! [String: String]
        let password = try Self.string("backup_password")
        for (name, message) in rejected where name.hasSuffix(".lgkfull") {
            let data = try Data(contentsOf: Self.dir.appendingPathComponent("rejected/\(name)"))
            XCTAssertThrowsError(try FullBackupV2.open(data, password: password), name) {
                XCTAssertEqual(($0 as? FullBackupError)?.message, message, name)
            }
        }
        let good = try Data(contentsOf: Self.dir.appendingPathComponent("full.lgkfull"))
        XCTAssertThrowsError(try FullBackupV2.open(good, password: "not the backup password")) {
            XCTAssertEqual(($0 as? FullBackupError)?.message, rejected["full.lgkfull with a wrong password"])
        }
        XCTAssertGreaterThanOrEqual(rejected.count, 12)
    }

    func testLimitsEnforced() throws {
        let password = try Self.string("backup_password")
        let good = try Data(contentsOf: Self.dir.appendingPathComponent("full.lgkfull"))
        // zip64 is refused (classic zip only).
        var zip64 = [UInt8](good)
        let eocd = zip64.count - 22
        zip64[eocd + 16] = 0xFF; zip64[eocd + 17] = 0xFF; zip64[eocd + 18] = 0xFF; zip64[eocd + 19] = 0xFF
        XCTAssertThrowsError(try FullBackupV2.open(Data(zip64), password: password)) {
            XCTAssertEqual(($0 as? FullBackupError)?.message, "Could not read full backup")
        }
        // Short and over-long backup passwords, as Windows.
        XCTAssertThrowsError(try FullBackupV2.open(good, password: "short")) {
            XCTAssertEqual(($0 as? FullBackupError)?.message, "Backup password must contain at least 12 characters")
        }
        let tooLong = String(repeating: "a", count: 4097)
        XCTAssertThrowsError(try FullBackupV2.open(good, password: tooLong))
        // KDF bounds: memory below the vault range.
        XCTAssertThrowsError(try FullBackupV2.write(
            vault: Data("{}".utf8), settings: Data("{}".utf8), attachments: [], password: password,
            random: Replay([1]), progress: { _, _, _ in }, cancel: { false },
            profileName: "Test", kdf: FullBackupV2.KDF(timeCost: 1, memoryKiB: 1024, parallelism: 1))) {
            XCTAssertEqual(($0 as? FullBackupError)?.message, "Unsupported backup encryption parameters")
        }
        // Settings over 1 MiB, an invalid attachment id, a vault that is not a JSON object.
        let big = Data("{\"a\":\"".utf8) + Data(repeating: 0x61, count: FullBackupV2.maxSettingsBytes) + Data("\"}".utf8)
        XCTAssertThrowsError(try FullBackupV2.write(
            vault: Data("{}".utf8), settings: big, attachments: [], password: password, random: Replay([1]),
            progress: { _, _, _ in }, cancel: { false }, profileName: "Test", kdf: Self.cheap)) {
            XCTAssertEqual(($0 as? FullBackupError)?.message, "Profile settings are too large")
        }
        XCTAssertThrowsError(try FullBackupV2.write(
            vault: Data("[]".utf8), settings: Data("{}".utf8), attachments: [], password: password, random: Replay([1]),
            progress: { _, _, _ in }, cancel: { false }, profileName: "Test", kdf: Self.cheap)) {
            XCTAssertEqual(($0 as? FullBackupError)?.message, "Vault must be a JSON object")
        }
        XCTAssertThrowsError(try FullBackupV2.write(
            vault: Data("{}".utf8), settings: Data("{}".utf8), attachments: [(id: "../x", data: Data([1]))],
            password: password, random: Replay([1]), progress: { _, _, _ in }, cancel: { false }, profileName: "Test", kdf: Self.cheap)) {
            XCTAssertEqual(($0 as? FullBackupError)?.message, "Attachment sidecar ID is malformed")
        }
        XCTAssertThrowsError(try FullBackupV2.inspect(Data(count: FullBackupV2.maxBackupBytes + 1))) {
            XCTAssertEqual(($0 as? FullBackupError)?.message, "Full backup is too large")
        }
        XCTAssertEqual(FullBackupV2.maxEntries, 20_005)
        XCTAssertEqual(FullBackupV2.maxMemberBytes, 32 * 1024 * 1024)
        XCTAssertEqual(FullBackupV2.KDF.default, FullBackupV2.KDF(timeCost: 3, memoryKiB: 65536, parallelism: 4))
        // A vault KDF outside the accepted range is refused before any derivation.
        var header = try XCTUnwrap(JSONSerialization.jsonObject(with: Self.input("vault.json")) as? [String: Any])
        var kdf = header["kdf"] as! [String: Any]
        kdf["time_cost"] = 11
        header["kdf"] = kdf
        let edited = try JSONSerialization.data(withJSONObject: header)
        XCTAssertThrowsError(try DesktopVaultFile.open(edited, password: Self.string("master_password"))) {
            XCTAssertEqual(($0 as? DesktopVaultError)?.message, "Invalid KDF parameters")
        }
    }

    func testCancelLeavesNoOutput() throws {
        var calls = 0
        var result: Data?
        XCTAssertThrowsError(result = try FullBackupV2.write(
            vault: Self.input("vault.json"), settings: Self.input("settings.json"), attachments: Self.attachments(),
            password: Self.string("backup_password"), random: Replay([1]), progress: { _, _, _ in },
            cancel: { calls += 1; return calls > 3 }, profileName: "Test", kdf: Self.cheap)) {
            XCTAssertEqual(($0 as? FullBackupError)?.message, "Backup operation was cancelled")
        }
        XCTAssertNil(result)
        let file = try Data(contentsOf: Self.dir.appendingPathComponent("full.lgkfull"))
        XCTAssertThrowsError(try FullBackupV2.open(file, password: Self.string("backup_password"), cancel: { true })) {
            XCTAssertEqual(($0 as? FullBackupError)?.message, "Backup operation was cancelled")
        }
    }

    /// Formats 1 and 2 (the Argon2id output is the catalog key) still sit in Windows backups: open them as
    /// `vault.py` does, directly and from inside a full backup.
    func testOpenLegacyVaultFormats() throws {
        let master = try Self.string("master_password")
        let ids = try Self.expected()["legacy_vault_ids"] as! [String: [String]]
        for name in ["vault_v1.json", "vault_v2.json"] {
            let vault = try Self.input(name)
            func idsOf(_ items: [JSONValue]) -> [String] {
                items.compactMap { if case .object(let o) = $0, case .string(let s)? = o["id"] { return s }; return nil }.sorted()
            }
            let opened = try DesktopVaultFile.open(vault, password: master)
            XCTAssertEqual(idsOf(opened.items), ids[name], name)
            XCTAssertFalse(opened.recoveryEnrolled)
            XCTAssertThrowsError(try DesktopVaultFile.open(vault, password: "not the master password")) {
                XCTAssertEqual(($0 as? DesktopVaultError)?.message, "Incorrect master password or modified vault")
            }
            let backup = try FullBackupV2.write(
                vault: vault, settings: Self.input("settings.json"), attachments: [], password: Self.string("backup_password"),
                random: Replay([9]), progress: { _, _, _ in }, cancel: { false }, profileName: "Legacy", kdf: Self.cheap)
            let back = try FullBackupV2.open(backup, password: Self.string("backup_password"))
            XCTAssertEqual(idsOf(try DesktopVaultFile.open(back.vault, password: master).items), ids[name], name)
        }
        // A tampered legacy header (the KDF is in the AAD) fails like a wrong password.
        var header = try XCTUnwrap(JSONSerialization.jsonObject(with: Self.input("vault_v2.json")) as? [String: Any])
        header["format"] = "localgatekeys-vault-v9"
        XCTAssertThrowsError(try DesktopVaultFile.open(try JSONSerialization.data(withJSONObject: header), password: master)) {
            XCTAssertEqual(($0 as? DesktopVaultError)?.message, "Unsupported vault format identifier")
        }
    }

    func testDesktopVaultRecoveryFlagAndPayload() throws {
        let master = "a master password long enough"
        let vault = try DesktopVaultFile.seal(items: [], settings: .object(["trash": .array([])]), password: master,
                                              random: Replay([7]), now: 1_800_000_000, kdf: Self.cheap)
        var header = try XCTUnwrap(JSONSerialization.jsonObject(with: vault) as? [String: Any])
        XCTAssertEqual(header["version"] as? Int, 3)
        XCTAssertFalse(try DesktopVaultFile.open(vault, password: master).recoveryEnrolled)
        // A recovery wrapper (outside the catalog AAD) is reported without being opened.
        var wrappers = header["wrappers"] as! [String: Any]
        wrappers["recovery"] = ["kind": "bip39-english-24", "salt": Base64.encode([UInt8](repeating: 1, count: 16)),
                                "nonce": Base64.encode([UInt8](repeating: 2, count: 12)),
                                "ciphertext": Base64.encode([UInt8](repeating: 3, count: 48))]
        header["wrappers"] = wrappers
        let enrolled = try JSONSerialization.data(withJSONObject: header)
        XCTAssertTrue(try DesktopVaultFile.open(enrolled, password: master).recoveryEnrolled)
        XCTAssertThrowsError(try DesktopVaultFile.seal(items: [], settings: .object([:]), password: "short", random: Replay([7])))
    }
}
