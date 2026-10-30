import XCTest
@testable import LGKCore

/// Windows `backup_schedule.py`, pinned by `tests/vectors/backup/schedule/schedule.json`
/// (`scripts/gen_mac_backup_vectors.py schedule`). Python works in naive local time; the vectors are read in UTC.
final class BackupScheduleTests: XCTestCase {
    static let root: URL = {
        var u = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { u.deleteLastPathComponent() }
        return u.appendingPathComponent("tests/vectors/backup/schedule", isDirectory: true)
    }()

    var calendar: Calendar = {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        return c
    }()

    var vectors: [String: Any] = [:]
    var dir: URL!

    override func setUpWithError() throws {
        let data = try Data(contentsOf: Self.root.appendingPathComponent("schedule.json"))
        vectors = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-schedule-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() { try? FileManager.default.removeItem(at: dir) }

    func date(_ text: Any?) -> Date? {
        guard let text = text as? String else { return nil }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.calendar = calendar
        f.timeZone = calendar.timeZone
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
        return f.date(from: text)
    }

    func rows(_ key: String) -> [[String: Any]] { vectors[key] as? [[String: Any]] ?? [] }

    func testConstantsMatchPython() throws {
        let c = try XCTUnwrap(vectors["constants"] as? [String: Any])
        XCTAssertEqual(c["frequencies"] as? [String], BackupSchedule.frequencies)
        XCTAssertEqual(c["keep_choices"] as? [Int], BackupSchedule.keepChoices)
        XCTAssertEqual(c["default_time"] as? String, BackupSchedule.defaultTime)
        XCTAssertEqual(c["weekdays"] as? [String], BackupSchedule.weekdays)
        XCTAssertEqual(c["scheduled_dir"] as? String, BackupSchedule.scheduledDirName)
        XCTAssertEqual(c["state_file"] as? String, BackupSchedule.stateFilename)
        XCTAssertEqual(c["min_password"] as? Int, BackupSchedule.minBackupPasswordLength)
        XCTAssertEqual(c["retry_after_seconds"] as? Int, Int(BackupSchedule.retryAfter))
    }

    func testLatestSlotMatchesPython() throws {
        let cases = rows("slots")
        XCTAssertGreaterThan(cases.count, 100)
        for row in cases {
            let now = try XCTUnwrap(date(row["now"]))
            let slot = BackupSchedule.latestSlot(now: now, frequency: row["frequency"] as! String, time: row["time"] as! String,
                                                 weekday: row["weekday"] as! Int, calendar: calendar)
            XCTAssertEqual(slot, date(row["slot"]), "\(row)")
        }
    }

    func testIsDueMatchesPython() throws {
        let cases = rows("due")
        XCTAssertGreaterThan(cases.count, 500)
        for row in cases {
            let now = try XCTUnwrap(date(row["now"]))
            let due = BackupSchedule.isDue(now: now, lastSuccess: date(row["last_success"]), frequency: row["frequency"] as! String,
                                           time: row["time"] as! String, weekday: row["weekday"] as! Int, calendar: calendar)
            XCTAssertEqual(due, row["due"] as? Bool, "\(row)")
        }
    }

    func testValidatedTimeMatchesPython() {
        for row in rows("times") {
            XCTAssertEqual(BackupSchedule.validatedTime(row["value"] as? String), row["validated"] as? String, "\(row)")
        }
    }

    func testFilenameAndTagMatchPython() throws {
        for row in rows("tags") {
            XCTAssertEqual(BackupSchedule.profileTag(row["profile_id"] as! String), row["tag"] as? String)
        }
        for row in rows("filenames") {
            let name = try BackupSchedule.scheduledFilename(tag: row["tag"] as! String, when: XCTUnwrap(date(row["when"])),
                                                            counter: row["counter"] as! Int, calendar: calendar)
            XCTAssertEqual(name, row["filename"] as? String)
        }
        for row in rows("bad_tags") {
            XCTAssertThrowsError(try BackupSchedule.scheduledFilename(tag: row["tag"] as! String, when: Date(), calendar: calendar)) {
                XCTAssertEqual(($0 as? BackupScheduleError)?.message, row["error"] as? String)
            }
        }
    }

    /// Writes the vector listing (one name is a folder, like Python's fixture).
    func makeListing(in folder: URL) throws -> [String: Any] {
        let listing = try XCTUnwrap(vectors["listing"] as? [String: Any])
        let directory = listing["directory"] as! String
        for name in listing["names"] as! [String] {
            let u = folder.appendingPathComponent(name)
            if name == directory { try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true) }
            else { try Data("x".utf8).write(to: u) }
        }
        return listing
    }

    func testOwnedBackupsMatchPython() throws {
        let listing = try makeListing(in: dir)
        let tag = listing["tag"] as! String
        XCTAssertEqual(BackupSchedule.ownedBackups(in: dir, tag: tag).map(\.lastPathComponent), listing["owned"] as? [String])
        // A symbolic link with an owned name is never one of them.
        let link = dir.appendingPathComponent("LocalGateKeys-scheduled-\(tag)-20991231-235959.lgk")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: dir.appendingPathComponent("vault-20261026.json"))
        XCTAssertEqual(BackupSchedule.ownedBackups(in: dir, tag: tag).map(\.lastPathComponent), listing["owned"] as? [String])
    }

    func testPruneKeepsNewestAndProtected() throws {
        for row in rows("prune") {
            let folder = dir.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let listing = try makeListing(in: folder)
            let protect = (row["protect"] as? String).map { folder.appendingPathComponent($0) }
            let removed = BackupSchedule.prune(in: folder, tag: listing["tag"] as! String, keep: row["keep"] as! Int, protect: protect)
            XCTAssertEqual(removed.map(\.lastPathComponent).sorted(), row["removed"] as? [String], "\(row)")
            let left = try FileManager.default.contentsOfDirectory(atPath: folder.path).sorted()
            XCTAssertEqual(left, row["left"] as? [String], "\(row)")
        }
    }

    func testPruneRemovesEachPrunedBackupsChecksumFile() throws {
        let tag = BackupSchedule.profileTag("mac")
        let names = ["20261020-120000", "20261021-120000", "20261022-120000"].map { "LocalGateKeys-scheduled-\(tag)-\($0).lgk" }
        for n in names {
            try Data("x".utf8).write(to: dir.appendingPathComponent(n))
            try Data("{}".utf8).write(to: dir.appendingPathComponent(n + ".sha256.json"))
        }
        let removed = BackupSchedule.prune(in: dir, tag: tag, keep: 1, protect: dir.appendingPathComponent(names[2]))
        XCTAssertEqual(removed.map(\.lastPathComponent).sorted(), Array(names.prefix(2)))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted(), [names[2], names[2] + ".sha256.json"])
    }

    func testLastSuccessStateRoundTrips() throws {
        XCTAssertNil(BackupSchedule.readLastSuccess(dir))
        let when = Date(timeIntervalSince1970: 1_793_016_000.5)
        try BackupSchedule.writeLastSuccess(dir, when)
        XCTAssertEqual(BackupSchedule.readLastSuccess(dir), when)
        let text = try String(contentsOf: dir.appendingPathComponent(BackupSchedule.stateFilename), encoding: .utf8)
        XCTAssertEqual(text, #"{"version": 1, "last_success": 1793016000.5}"#)   // Python json.dumps
        // Python's reader: a bool or a non-number is no state.
        for bad in [#"{"last_success": true}"#, #"{"last_success": "1"}"#, "[]", "nope"] {
            try Data(bad.utf8).write(to: dir.appendingPathComponent(BackupSchedule.stateFilename))
            XCTAssertNil(BackupSchedule.readLastSuccess(dir), bad)
        }
        try Data(#"{"version": 1, "last_success": 1793016000}"#.utf8).write(to: dir.appendingPathComponent(BackupSchedule.stateFilename))
        XCTAssertEqual(BackupSchedule.readLastSuccess(dir), Date(timeIntervalSince1970: 1_793_016_000))
    }

    /// A vault sealed with a key derived earlier (scheduled backups run without the master password) opens
    /// with the master password like any other, and a key for another password opens nothing.
    func testPasswordKeySealOpensWithThePassword() throws {
        let kdf = FullBackupV2.KDF(timeCost: 1, memoryKiB: 8192, parallelism: 1)
        let random = SystemRandomSource()
        var key = try DesktopVaultFile.derivePasswordKey(password: "master password 2026", kdf: kdf, random: random)
        defer { key.wipe() }
        let item: JSONValue = .object(["id": .string("a1"), "kind": .string("web"), "title": .string("Mail")])
        let sealed = try DesktopVaultFile.seal(items: [item], settings: .object([:]), passwordKey: key, random: random, now: 1)
        let opened = try DesktopVaultFile.open(sealed, password: "master password 2026")
        XCTAssertEqual(opened.items, [item])
        XCTAssertEqual(try DesktopVaultFile.openPayload(sealed, passwordKey: key).payload["entries"], .array([item]))
        XCTAssertThrowsError(try DesktopVaultFile.open(sealed, password: "another password 2026"))
        var other = try DesktopVaultFile.derivePasswordKey(password: "another password 2026", kdf: kdf, random: random)
        defer { other.wipe() }
        XCTAssertThrowsError(try DesktopVaultFile.openPayload(sealed, passwordKey: other))
        // Two seals with one key: each has its own data key and vault id.
        let again = try DesktopVaultFile.seal(items: [item], settings: .object([:]), passwordKey: key, random: random, now: 1)
        XCTAssertNotEqual(again, sealed)
        // Round trip through its stored form.
        let restored = try DesktopVaultFile.PasswordKey(encoded: key.encoded())
        XCTAssertEqual(try DesktopVaultFile.open(DesktopVaultFile.seal(items: [item], settings: .object([:]), passwordKey: restored,
                                                                      random: random), password: "master password 2026").items, [item])
    }
}
