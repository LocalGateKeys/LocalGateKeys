import XCTest
import LGKCore
@testable import AppShared

/// A clock the test moves by hand.
final class InboxClock: @unchecked Sendable {
    private var value: Int64
    private let lock = NSLock()
    init(_ value: Int64) { self.value = value }
    var now: Int64 {
        get { lock.withLock { value } }
        set { lock.withLock { value = newValue } }
    }
}

final class SafariInboxTests: XCTestCase {
    var dir: URL!
    let key = Array(repeating: UInt8(7), count: 32)
    let otherKey = Array(repeating: UInt8(8), count: 32)
    let clock = InboxClock(1000)
    let random = FixedRandom()

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-inbox-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    func makeInbox(key: [UInt8]? = nil, directory: URL? = nil) -> SafariInbox {
        SafariInbox(directory: directory ?? dir!, key: key ?? self.key, now: { [clock = self.clock] in clock.now },
                    random: random)
    }

    /// The `.blob` files in the inbox directory.
    func blobs() throws -> [URL] {
        try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "blob" }
    }

    func onlyBlob() throws -> URL {
        let all = try blobs()
        XCTAssertEqual(all.count, 1)
        return try XCTUnwrap(all.first)
    }

    func blobID(_ url: URL) -> String { url.deletingPathExtension().lastPathComponent }

    func assertThrows(_ expected: SafariInboxError, _ body: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            XCTAssertEqual($0 as? SafariInboxError, expected, file: file, line: line)
        }
    }

    // MARK: sealing

    func test_seal_open_round_trip() throws {
        let inbox = makeInbox()
        try inbox.add(origin: "https://example.com", username: "alex", password: "pw1")

        let blob = try onlyBlob()
        let id = blobID(blob)
        XCTAssertEqual(id, id.lowercased())
        XCTAssertNotNil(UUID(uuidString: id))

        let read = inbox.entries()
        XCTAssertEqual(read.entries, [SafariInboxEntry(id: id, origin: "https://example.com", username: "alex",
                                                       password: "pw1", capturedAt: 1000)])
        XCTAssertEqual(read.damaged, [])

        // The file is nonce(12) || AES-256-GCM under the inbox key, AAD bound to the uuid, over canonical JSON.
        let bytes = Array(try Data(contentsOf: blob))
        let plain = try CryptoBox.openGCM(key: key, nonce: Array(bytes[0..<12]), ciphertext: Array(bytes[12...]),
                                          aad: Array("localgatekeys|safari-inbox|v1|\(id)".utf8))
        XCTAssertEqual(String(decoding: plain, as: UTF8.self),
                       #"{"captured_at":1000,"origin":"https://example.com","password":"pw1","username":"alex"}"#)
        XCTAssertFalse(String(decoding: bytes, as: UTF8.self).contains("pw1"))
    }

    func test_tampered_blob_is_reported_damaged() throws {
        let inbox = makeInbox()
        try inbox.add(origin: "https://example.com", username: "alex", password: "pw1")
        let blob = try onlyBlob()
        var bytes = Array(try Data(contentsOf: blob))
        bytes[bytes.count - 1] ^= 0x01
        try Data(bytes).write(to: blob)

        let read = inbox.entries()
        XCTAssertEqual(read.entries, [])
        XCTAssertEqual(read.damaged, [blobID(blob)])
    }

    func test_blob_renamed_to_other_uuid_fails_aad() throws {
        let inbox = makeInbox()
        try inbox.add(origin: "https://example.com", username: "alex", password: "pw1")
        let blob = try onlyBlob()
        let otherID = UUID().uuidString.lowercased()
        try FileManager.default.moveItem(at: blob, to: dir.appendingPathComponent("\(otherID).blob"))

        let read = inbox.entries()
        XCTAssertEqual(read.entries, [])
        XCTAssertEqual(read.damaged, [otherID])
    }

    func test_wrong_key_reports_damaged() throws {
        try makeInbox().add(origin: "https://example.com", username: "alex", password: "pw1")
        let blob = try onlyBlob()

        let read = makeInbox(key: otherKey).entries()
        XCTAssertEqual(read.entries, [])
        XCTAssertEqual(read.damaged, [blobID(blob)])
    }

    // MARK: cap and de-duplication

    func test_cap_50_throws_full() throws {
        let inbox = makeInbox()
        for i in 0..<50 { try inbox.add(origin: "https://example.com", username: "user\(i)", password: "pw") }
        XCTAssertEqual(inbox.entries().entries.count, 50)

        assertThrows(.full) { try inbox.add(origin: "https://example.com", username: "user50", password: "pw") }
        XCTAssertEqual(try blobs().count, 50)

        // An identical capture is de-duplicated before the cap is checked: no error, nothing written.
        try inbox.add(origin: "https://example.com", username: "user0", password: "pw")
        XCTAssertEqual(try blobs().count, 50)

        // Expiry runs first, so once the old entries are past 7 days there is room again.
        clock.now = 1000 + 604_801
        try inbox.add(origin: "https://example.com", username: "user50", password: "pw")
        XCTAssertEqual(inbox.entries().entries.map(\.username), ["user50"])
    }

    func test_identical_add_is_deduplicated() throws {
        let inbox = makeInbox()
        try inbox.add(origin: "https://example.com", username: "alex", password: "pw1")
        clock.now = 2000
        try inbox.add(origin: "https://example.com", username: "alex", password: "pw1")
        XCTAssertEqual(try blobs().count, 1)
        XCTAssertEqual(inbox.entries().entries.map(\.capturedAt), [1000])

        // Another password for the same login is a separate entry.
        try inbox.add(origin: "https://example.com", username: "alex", password: "pw2")
        XCTAssertEqual(inbox.entries().entries.map(\.password), ["pw1", "pw2"])
    }

    func test_empty_username_or_password_is_invalid() throws {
        let inbox = makeInbox()
        assertThrows(.invalid) { try inbox.add(origin: "https://example.com", username: "", password: "pw1") }
        assertThrows(.invalid) { try inbox.add(origin: "https://example.com", username: "alex", password: "") }
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path))
    }

    func test_unwritable_directory_is_unavailable() throws {
        // The inbox directory's parent is a regular file, so the inbox cannot be created.
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("plain-file")
        try Data("x".utf8).write(to: file)
        let inbox = makeInbox(directory: file.appendingPathComponent("inbox", isDirectory: true))
        assertThrows(.unavailable) { try inbox.add(origin: "https://example.com", username: "alex", password: "pw1") }
        XCTAssertEqual(inbox.entries().entries, [])
    }

    // MARK: expiry

    func test_expire_after_7_days() throws {
        let inbox = makeInbox()
        try inbox.add(origin: "https://example.com", username: "alex", password: "pw1")

        clock.now = 1000 + 604_800
        inbox.expire()
        XCTAssertEqual(inbox.entries().entries.count, 1, "exactly 7 days old is kept")

        clock.now = 1000 + 604_801
        inbox.expire()
        XCTAssertEqual(inbox.entries().entries, [])
        XCTAssertEqual(try blobs(), [])
    }

    func test_future_captured_at_is_kept() throws {
        clock.now = 5000
        let inbox = makeInbox()
        try inbox.add(origin: "https://example.com", username: "alex", password: "pw1")

        // The phone clock moved back: the entry is in the future and is kept.
        clock.now = 1000
        inbox.expire()
        XCTAssertEqual(inbox.entries().entries.map(\.capturedAt), [5000])

        // It expires 7 days after that future time.
        clock.now = 5000 + 604_800
        inbox.expire()
        XCTAssertEqual(inbox.entries().entries.count, 1)
        clock.now = 5000 + 604_801
        inbox.expire()
        XCTAssertEqual(inbox.entries().entries, [])
    }

    // MARK: listing and removal

    func test_entries_sorted_oldest_first() throws {
        let inbox = makeInbox()
        clock.now = 3000
        try inbox.add(origin: "https://example.com", username: "c", password: "pw")
        clock.now = 1000
        try inbox.add(origin: "https://example.com", username: "a", password: "pw")
        try inbox.add(origin: "https://example.com", username: "b", password: "pw")

        let read = inbox.entries().entries
        XCTAssertEqual(read.map(\.capturedAt), [1000, 1000, 3000])
        XCTAssertEqual(Set(read.prefix(2).map(\.username)), ["a", "b"])
        XCTAssertLessThan(read[0].id, read[1].id, "equal times are ordered by id")
        XCTAssertEqual(read[2].username, "c")
    }

    func test_other_files_are_ignored() throws {
        let inbox = makeInbox()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let id = UUID().uuidString.lowercased()
        try Data("x".utf8).write(to: dir.appendingPathComponent("notes.txt"))
        try Data("x".utf8).write(to: dir.appendingPathComponent(".\(id).blob.\(UUID().uuidString).tmp"))
        try Data("x".utf8).write(to: dir.appendingPathComponent("not-a-uuid.blob"))
        try Data("x".utf8).write(to: dir.appendingPathComponent("\(id.uppercased()).blob"))

        let read = inbox.entries()
        XCTAssertEqual(read.entries, [])
        XCTAssertEqual(read.damaged, [])
    }

    func test_missing_directory_is_empty() {
        let read = makeInbox().entries()
        XCTAssertEqual(read.entries, [])
        XCTAssertEqual(read.damaged, [])
    }

    func test_remove_deletes_only_named_entries() throws {
        let inbox = makeInbox()
        try inbox.add(origin: "https://example.com", username: "alex", password: "pw1")
        try inbox.add(origin: "https://example.com", username: "sam", password: "pw2")
        let all = inbox.entries().entries
        XCTAssertEqual(all.count, 2)

        inbox.remove(ids: [all[0].id, "../escape", "not-a-uuid"])
        XCTAssertEqual(inbox.entries().entries, [all[1]])

        // Damaged entries are removed by id too.
        let blob = try onlyBlob()
        try Data("garbage".utf8).write(to: blob)
        XCTAssertEqual(inbox.entries().damaged, [all[1].id])
        inbox.remove(ids: [all[1].id])
        XCTAssertEqual(try blobs(), [])
    }
}
