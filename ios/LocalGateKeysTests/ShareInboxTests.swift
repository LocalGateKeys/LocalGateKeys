import XCTest
import AppShared
@testable import LocalGateKeys

/// Secure sharing (UX workstream 9): the sender's temporary file and the receiver's inbox rules.
@MainActor
final class ShareInboxTests: XCTestCase {
    let code = "maple river onion seven lamp quote"
    let now: Int64 = 1_800_000_000
    var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-share-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDown() async throws { try? FileManager.default.removeItem(at: dir) }

    func note(_ title: String = "Shared note") -> [String: JSONValue] {
        ["id": .string("6f8a9a52-4d0b-4b87-8f3c-0a4f9d7b2c10"), "kind": .string("note"), "title": .string(title),
         "created_at": .int(1_799_000_000), "updated_at": .int(1_799_000_000), "favorite": .bool(true), "tags": .array([]),
         "payload": .object(["body": .string("hello"), "fields": .array([]), "template_id": .null])]
    }

    func package(_ item: [String: JSONValue]? = nil) throws -> String {
        String(decoding: try Share.seal(item: item ?? note(), code: code, sender: "Desk PC", now: now), as: UTF8.self)
    }

    func inbox() -> ShareInbox {
        ShareInbox(directory: dir.appendingPathComponent("in"), clock: TestClock(now + 10), ownedFolders: [])
    }

    func test_outbox_writes_one_file_without_the_title_and_removes_it() throws {
        let item = try XCTUnwrap(VaultItem(id: "x", record: note("Bank PIN")))
        let out = try ShareOutbox.make(item: item, sender: "iPhone", now: now, directory: dir.appendingPathComponent("out"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: out.fileURL.path))
        XCTAssertFalse(out.fileURL.lastPathComponent.contains("Bank"))
        XCTAssertEqual(out.codeWords.count, 6)
        XCTAssertNotNil(out.packageQRText)   // a note fits one QR
        let opened = try Share.open(Array(try Data(contentsOf: out.fileURL)), code: out.code, now: now + 1)
        XCTAssertEqual(opened.item["title"], .string("Bank PIN"))
        XCTAssertNil(opened.item["favorite"])   // local-only keys never travel
        ShareOutbox.remove(out)
        XCTAssertFalse(FileManager.default.fileExists(atPath: out.fileURL.path))
    }

    func test_open_preview_save_adds_a_new_item_and_deletes_the_package() throws {
        let box = inbox()
        let text = try package()
        XCTAssertTrue(box.deliver(text: text))
        let pending = try XCTUnwrap(box.pending)
        XCTAssertEqual(pending.sender, "Desk PC")
        XCTAssertTrue(FileManager.default.fileExists(atPath: pending.file.path))
        XCTAssertTrue(box.open(code: "Maple-River-Onion-Seven-Lamp-Quote"))
        XCTAssertEqual(box.preview?.item["title"], .string("Shared note"))
        let store = LockedStore()
        XCTAssertEqual(box.save(store: store, isPro: false, random: FixedRandom()), .saved)
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), 1)
        XCTAssertNil(store.snapshot.records["6f8a9a52-4d0b-4b87-8f3c-0a4f9d7b2c10"])   // a new id, never the sender's
        XCTAssertNil(box.pending)
        XCTAssertFalse(FileManager.default.fileExists(atPath: pending.file.path))
        // Open once: the same package is refused afterwards.
        XCTAssertFalse(box.deliver(text: text))
        XCTAssertNil(box.pending)
    }

    func test_same_package_is_refused_after_it_was_opened() throws {
        let box = inbox()
        let text = try package()
        box.deliver(text: text)
        XCTAssertTrue(box.open(code: code))
        box.reject()
        box.deliver(text: text)
        XCTAssertNil(box.pending)
        XCTAssertEqual(box.message, "This shared item was already opened on this device.")
    }

    func test_three_wrong_codes_delete_the_package() throws {
        let box = inbox()
        let text = try package()   // seal draws a new id each time: keep this one to deliver again
        box.deliver(text: text)
        let file = try XCTUnwrap(box.pending).file
        let wrong = "maple river onion seven lamp quick"
        XCTAssertFalse(box.open(code: wrong))
        XCTAssertEqual(box.message, ShareText.wrongCode(left: 2))
        XCTAssertFalse(box.open(code: "not six words"))   // not counted
        XCTAssertNotNil(box.pending)
        XCTAssertFalse(box.open(code: wrong))
        XCTAssertFalse(box.open(code: wrong))
        XCTAssertNil(box.pending)
        XCTAssertEqual(box.message, ShareText.threeWrong)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        // Burned: delivering the same package again does not reset the count.
        XCTAssertFalse(box.deliver(text: text))
        XCTAssertEqual(box.message, "This shared item was already opened on this device.")
    }

    func test_free_plan_limit_applies_to_a_received_item() throws {
        var records: [String: JSONValue] = [:]
        for i in 1...ItemLimit.freeItems { let (id, w) = noteRecord(i); records[id] = w }
        let store = LockedStore(StoreSnapshot(records: records))
        let box = inbox()
        box.deliver(text: try package())
        XCTAssertTrue(box.open(code: code))
        XCTAssertEqual(box.save(store: store, isPro: false, random: FixedRandom()), .needsPro)
        XCTAssertNotNil(box.pending)   // kept: the person can upgrade and add it
        XCTAssertEqual(box.save(store: store, isPro: true, random: FixedRandom()), .saved)
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), ItemLimit.freeItems + 1)
    }

    /// Every platform's packages (`tests/vectors/share/v1.json`: stored shape for each kind, plus the display shape
    /// early builds sent) save; a desktop login is refused before the preview.
    func test_every_vector_item_saves() throws {
        let raw = try SyncVectors.data("../share/v1.json")
        guard case .object(let root) = try CanonicalJSON.parse(Array(raw)), case .array(let opens)? = root["opens"],
              case .array(let legacy)? = root["legacy"] else {
            return XCTFail("vectors")
        }
        for v in opens + legacy {
            guard case .object(let c) = v, case .string(let pkg)? = c["package"], case .string(let words)? = c["code"] else {
                return XCTFail("vector")
            }
            let box = inbox()
            XCTAssertTrue(box.deliver(text: pkg))
            if c["phone_saves"] == .bool(false) {
                XCTAssertFalse(box.open(code: words))
                XCTAssertEqual(box.message, Share.cannotSaveHere.message)
                continue
            }
            XCTAssertTrue(box.open(code: words), box.message ?? "")
            let store = LockedStore()
            XCTAssertEqual(box.save(store: store, isPro: true, random: FixedRandom()), .saved, box.message ?? "")
            XCTAssertEqual(VaultItem.items(from: store.snapshot).count, 1)
        }
    }

    func test_junk_and_other_files_are_not_accepted() throws {
        let box = inbox()
        XCTAssertFalse(box.deliver(text: "lgk-pair:abc"))
        XCTAssertFalse(box.deliver(fileURL: URL(fileURLWithPath: "/tmp/x.txt")))
        XCTAssertFalse(box.deliver(text: "{\"format\":\"something-else\"}"))
        XCTAssertNil(box.pending)
    }
}
