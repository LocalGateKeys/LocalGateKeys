import XCTest
import LGKCore
@testable import AppSharedMac

/// The unlock throttle's high-water mark outside the vault folder (PENDING 2026-11-15, Windows `outside_marks`):
/// putting back an earlier copy of the folder does not reset the failure count.
final class UnlockThrottleMarkTests: XCTestCase {
    final class MemoryMarks: ThrottleMarkStoring, @unchecked Sendable {
        private let lock = NSLock()
        var values: [String: Data] = [:]
        var failReads = false, failWrites = false
        func read(_ name: String) throws -> Data? {
            try lock.withLock {
                if failReads { throw CocoaError(.fileReadUnknown) }
                return values[name]
            }
        }
        func write(_ name: String, _ data: Data) throws {
            try lock.withLock {
                if failWrites { throw CocoaError(.fileWriteUnknown) }
                values[name] = data
            }
        }
        func delete(_ name: String) throws { lock.withLock { values[name] = nil } }
    }

    private var dir: URL!
    private var marks: MemoryMarks!
    private let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-mark-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        marks = MemoryMarks()
        UnlockThrottle.markStore = marks
    }

    override func tearDown() {
        UnlockThrottle.markStore = nil
        try? FileManager.default.removeItem(at: dir)
    }

    private func fail(_ n: Int, at date: Date) {
        for _ in 0..<n { UnlockThrottle.update(in: dir, now: date) { $0.recordFailure(at: date) } }
    }

    private var file: URL { dir.appendingPathComponent(UnlockThrottle.fileName) }

    func test_restoring_the_folder_keeps_the_failures() throws {
        fail(7, at: t0)
        XCTAssertEqual(UnlockThrottle.current(in: dir, now: t0).failures, 7)
        // An attacker puts back the folder as it was before guessing (no throttle file).
        try FileManager.default.removeItem(at: file)
        let after = UnlockThrottle.current(in: dir, now: t0)
        XCTAssertEqual(after.failures, 7)
        XCTAssertNotNil(after.waitUntil())
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path), "the file is written back from the mark")
    }

    func test_an_older_file_copy_never_lowers_the_count() throws {
        fail(2, at: t0)
        let early = try Data(contentsOf: file)
        fail(6, at: t0.addingTimeInterval(5))
        try early.write(to: file)
        XCTAssertEqual(UnlockThrottle.current(in: dir, now: t0.addingTimeInterval(6)).failures, 8)
    }

    func test_success_clears_the_mark() {
        fail(6, at: t0)
        XCTAssertFalse(marks.values.isEmpty)
        MasterPasswordUnlock.recordSuccess(directory: dir, now: t0)
        XCTAssertTrue(marks.values.isEmpty)
        XCTAssertEqual(UnlockThrottle.current(in: dir, now: t0), UnlockThrottle())
    }

    func test_reset_clears_the_mark() {
        fail(3, at: t0)
        MasterPasswordUnlock.resetThrottle(directory: dir, now: t0)
        XCTAssertTrue(marks.values.isEmpty)
    }

    func test_unreadable_mark_falls_back_to_the_file() {
        fail(3, at: t0)
        marks.failReads = true
        XCTAssertEqual(UnlockThrottle.current(in: dir, now: t0).failures, 3, "never a lock-out, never lower")
    }

    func test_unwritable_mark_still_counts_in_the_file() {
        marks.failWrites = true
        fail(6, at: t0)
        XCTAssertEqual(UnlockThrottle.current(in: dir, now: t0).failures, 6)
    }

    func test_malformed_mark_fails_closed_and_keeps_its_time() {
        marks.values[UnlockThrottle.markName(for: dir)] = Data("{broken".utf8)
        let first = UnlockThrottle.current(in: dir, now: t0)
        XCTAssertEqual(first.failures, UnlockThrottle.failClosedFailures)
        let later = UnlockThrottle.current(in: dir, now: t0.addingTimeInterval(30))
        XCTAssertEqual(later.lastFailure, t0, "the wait does not slide forward")
    }

    func test_marks_are_per_folder_and_name_no_path() {
        let other = dir.appendingPathComponent("other", isDirectory: true)
        XCTAssertNotEqual(UnlockThrottle.markName(for: dir), UnlockThrottle.markName(for: other))
        XCTAssertFalse(UnlockThrottle.markName(for: dir).contains("lgk-mark"))
        XCTAssertEqual(UnlockThrottle.markName(for: dir), UnlockThrottle.markName(for: dir.appendingPathComponent(".")))
    }

    func test_without_a_store_the_file_alone_decides() throws {
        UnlockThrottle.markStore = nil
        fail(6, at: t0)
        try FileManager.default.removeItem(at: file)
        XCTAssertEqual(UnlockThrottle.current(in: dir, now: t0).failures, 0)
    }
}
