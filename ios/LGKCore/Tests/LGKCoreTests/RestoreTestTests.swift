import Foundation
import XCTest
@testable import LGKCore

/// The backup restore test (sub-plan 12, Windows `tests/test_restore_test.py`): a good backup passes with its item
/// count, a damaged one is `unreadable`, a changed password is `old_password`, and the scratch folder never stays.
final class RestoreTestTests: XCTestCase {
    static let now: Int64 = 1_790_100_000
    private var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("restore-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    private var scratchRoot: URL { root.appendingPathComponent(RestoreTest.scratchName, isDirectory: true) }
    private var vector: URL { PhoneBackupTests.root.appendingPathComponent("from_ios/backup.lgkm") }

    /// Nothing is left under the scratch root (it may exist, empty).
    private func assertScratchRemoved(file: StaticString = #filePath, line: UInt = #line) {
        let left = (try? FileManager.default.contentsOfDirectory(atPath: scratchRoot.path)) ?? []
        XCTAssertEqual(left, [], "scratch folder left behind", file: file, line: line)
    }

    func testGoodBackupPassesWithItemCount() throws {
        let result = RestoreTest.run(backup: vector, scratchRoot: scratchRoot, now: Self.now,
                                     restore: RestoreTest.phoneBackup(password: PhoneBackupTests.password))
        XCTAssertTrue(result.ok)
        XCTAssertNil(result.failure)
        XCTAssertEqual(result.reason, "")
        XCTAssertGreaterThanOrEqual(result.items, 8)
        let payload = try PhoneBackup.open(Data(contentsOf: vector), password: PhoneBackupTests.password)
        XCTAssertEqual(result.items, RestoreTest.liveItems(payload.states))
        XCTAssertEqual(result.backupAge, max(0, Self.now - payload.createdAt))
        XCTAssertEqual(result.testedAt, Self.now)
        assertScratchRemoved()
    }

    func testCorruptedBackupIsUnreadable() throws {
        let bad = root.appendingPathComponent("damaged.lgkm")
        var bytes = try Data(contentsOf: vector)
        bytes.replaceSubrange(0..<min(64, bytes.count), with: Data(repeating: 0x41, count: min(64, bytes.count)))
        try bytes.write(to: bad)
        let result = RestoreTest.run(backup: bad, scratchRoot: scratchRoot, now: Self.now,
                                     restore: RestoreTest.phoneBackup(password: PhoneBackupTests.password))
        XCTAssertFalse(result.ok)
        XCTAssertEqual(result.failure, .unreadable)
        XCTAssertEqual(result.items, 0)
        assertScratchRemoved()
    }

    func testOldPasswordIsReported() {
        let result = RestoreTest.run(backup: vector, scratchRoot: scratchRoot, now: Self.now,
                                     restore: RestoreTest.phoneBackup(password: "the password before the change"))
        XCTAssertFalse(result.ok)
        XCTAssertEqual(result.failure, .oldPassword)
        XCTAssertEqual(result.reason, "old_password")
        assertScratchRemoved()
    }

    func testNoBackup() {
        for missing in [nil, root.appendingPathComponent("missing.lgkm"), root] {
            let result = RestoreTest.run(backup: missing, scratchRoot: scratchRoot, now: Self.now) { _, _ in
                XCTFail("restorer must not run"); return RestoreTest.Restored(items: 0, exportedAt: 0)
            }
            XCTAssertEqual(result.failure, .noBackup)
        }
    }

    func testScratchRemovedEvenWhenTheRestorerThrows() throws {
        var seen: URL?
        let result = RestoreTest.run(backup: vector, scratchRoot: scratchRoot, now: Self.now) { _, scratch in
            seen = scratch
            XCTAssertTrue(scratch.path.hasPrefix(self.scratchRoot.path))
            try Data("restored".utf8).write(to: scratch.appendingPathComponent("vault.json"))
            struct Boom: Error {}
            throw Boom()
        }
        XCTAssertEqual(result.failure, .unreadable)
        let scratch = try XCTUnwrap(seen)
        XCTAssertFalse(FileManager.default.fileExists(atPath: scratch.path))
        assertScratchRemoved()
    }

    func testFullBackupRestorerRefusesGarbage() throws {
        let bad = root.appendingPathComponent("garbage.lgk")
        try Data("not a backup".utf8).write(to: bad)
        let key = DesktopVaultFile.PasswordKey(kdf: .init(timeCost: 1, memoryKiB: 8192, parallelism: 1),
                                               salt: [UInt8](repeating: 2, count: 16), key: [UInt8](repeating: 1, count: 32))
        let result = RestoreTest.run(backup: bad, scratchRoot: scratchRoot, now: Self.now,
                                     restore: RestoreTest.fullBackup(password: "a long enough backup password", passwordKey: key))
        XCTAssertEqual(result.failure, .unreadable)
        assertScratchRemoved()
    }

    func testWeeklyDueRule() {
        let passed = RestoreTest.Result(ok: true, backupPath: "/b.lgkm", backupAge: 0, items: 3, reason: nil, testedAt: Self.now)
        XCTAssertTrue(RestoreTest.due(last: nil, now: Self.now, enabled: true))
        XCTAssertFalse(RestoreTest.due(last: nil, now: Self.now, enabled: false))
        XCTAssertFalse(RestoreTest.due(last: passed, now: Self.now + RestoreTest.week - 1, enabled: true))
        XCTAssertTrue(RestoreTest.due(last: passed, now: Self.now + RestoreTest.week, enabled: true))
    }

    func testResultFileUsesWindowsKeys() throws {
        let url = root.appendingPathComponent(RestoreTest.stateFile)
        let failed = RestoreTest.Result(ok: false, backupPath: "/b.lgkm", backupAge: 0, items: 0, reason: .oldPassword, testedAt: Self.now)
        try RestoreTest.save(failed, to: url)
        let text = try String(contentsOf: url, encoding: .utf8)
        for key in ["\"backup_path\"", "\"backup_age\"", "\"tested_at\"", "\"old_password\""] { XCTAssertTrue(text.contains(key), key) }
        XCTAssertEqual(RestoreTest.load(from: url), failed)
        try Data(#"{"ok":false,"backup_path":"","backup_age":0,"items":0,"reason":"bogus"}"#.utf8).write(to: url)
        XCTAssertNil(RestoreTest.load(from: url))
    }

    /// A Windows full backup tested on a phone: backup password plus that computer's master password.
    func testComputerBackupOnAPhone() throws {
        let file = FullBackupV3Tests.v2.appendingPathComponent("full.lgkfull")
        let expected = try FullBackupV3Tests.v2Expected()
        let backupPassword = try BackupKeyTests.str(expected["backup_password"])
        let master = try BackupKeyTests.str(expected["master_password"])
        XCTAssertTrue(RestoreTest.isComputerBackup(file))
        XCTAssertFalse(RestoreTest.isComputerBackup(vector))
        let good = RestoreTest.run(backup: file, scratchRoot: scratchRoot, now: Self.now,
                                   restore: RestoreTest.computerBackup(password: backupPassword, masterPassword: master))
        XCTAssertTrue(good.ok, good.reason)
        XCTAssertGreaterThan(good.items, 0)
        let wrongMaster = RestoreTest.run(backup: file, scratchRoot: scratchRoot, now: Self.now,
                                          restore: RestoreTest.computerBackup(password: backupPassword, masterPassword: "not the master password"))
        XCTAssertEqual(wrongMaster.failure, .oldPassword)
        let wrongBackup = RestoreTest.run(backup: file, scratchRoot: scratchRoot, now: Self.now,
                                          restore: RestoreTest.computerBackup(password: "not the backup password", masterPassword: master))
        XCTAssertEqual(wrongBackup.failure, .oldPassword)
        assertScratchRemoved()
    }
}
