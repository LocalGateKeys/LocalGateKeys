import XCTest
import AppShared
@testable import LocalGateKeys

/// Task 6: the unsaved editor draft. Mirrors android/app/src/test/.../editor/EditorDraftTest.kt.
@MainActor
final class EditorDraftTests: XCTestCase {
    let now: Int64 = 1_800_000_000
    let secret = "hunter2-very-secret-PASSWORD"
    var dir: URL!
    var file: URL!
    var clock: TestClock!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("draft-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        file = dir.appendingPathComponent(EditorDraftStore.fileName)
        clock = TestClock(now)
    }

    func keychain(_ key: [UInt8] = (0..<32).map { UInt8($0 + 7) }) -> InMemoryKeychainVault {
        let v = InMemoryKeychainVault()
        try? v.write(.localKey, key)
        return v
    }

    func store(_ vault: (any KeychainVault)?) -> EditorDraftStore {
        EditorDraftStore(file: file, keychain: { vault }, random: SystemRandomSource(), clock: clock)
    }

    func draft(_ id: String? = nil) -> EditorDraft {
        EditorDraft(kind: .web, itemID: id, baseHash: nil,
                    values: ["label": "Bank", "username": "ann", "password": secret], createdAt: now)
    }

    func test_round_trip() {
        let v = keychain()
        XCTAssertTrue(store(v).save(draft()))
        XCTAssertEqual(store(v).load(), draft())
    }

    func test_ciphertext_has_no_plaintext_bytes() throws {
        store(keychain()).save(draft())
        let bytes = Array(try Data(contentsOf: file))
        for needle in [secret, "Bank", "ann", "password", "web", "lgk-editor-draft-v1"] {
            let n = Array(needle.utf8)
            let found = (0...(bytes.count - n.count)).contains { i in Array(bytes[i..<(i + n.count)]) == n }
            XCTAssertFalse(found, "plaintext \(needle) in the file")
        }
    }

    func test_expires_after_seven_days() {
        let v = keychain()
        store(v).save(draft())
        clock.now = now + EditorDraftStore.maxAge - 1
        XCTAssertNotNil(store(v).load())
        clock.now = now + EditorDraftStore.maxAge + 1
        XCTAssertNil(store(v).load())
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }

    func test_wrong_key_deletes_the_draft() {
        store(keychain()).save(draft())
        XCTAssertNil(store(keychain([UInt8](repeating: 9, count: 32))).load())
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }

    func test_locked_writes_and_reads_nothing() {
        store(keychain()).save(draft())
        XCTAssertFalse(store(nil).save(draft()))
        XCTAssertNil(store(nil).load())
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path), "kept for the next unlock")
    }

    func test_one_draft_only() throws {
        let v = keychain()
        store(v).save(draft())
        store(v).save(EditorDraft(kind: .note, itemID: nil, baseHash: nil, values: ["title": "Second"], createdAt: now))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path), [EditorDraftStore.fileName])
        XCTAssertEqual(store(v).load()?.kind, .note)
    }

    func test_erase_deletes_the_draft() async throws {
        store(keychain()).save(draft())
        let vaultDir = dir.appendingPathComponent("Vault")
        let target = file!
        var eraser = VaultEraser(directory: { vaultDir }, keychains: [InMemoryKeychainVault()], identities: RecordingIdentityStore())
        eraser.draftFile = { target }
        try await eraser.erase()
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }

    func test_status_notices_a_changed_or_deleted_item() throws {
        guard case .object(let r) = validCard, let item = VaultItem(id: "0c000000-0000-4000-8000-000000000001", record: r) else {
            return XCTFail("card")
        }
        let pro = ProModel(purchases: FakePurchases(), licenseKeys: [:])
        let m = EditorModel(store: MemoryStore(), pro: pro, editing: item, kind: .card, clock: clock, random: CountingRandom(),
                            background: FakeBackgroundTasks())
        m.set("title", "Changed title")
        let d = m.draft(now: now)
        XCTAssertEqual(d.itemID, item.id)
        XCTAssertEqual(d.status(in: [item]), .sameItem)
        XCTAssertEqual(d.status(in: []), .itemDeleted)
        var changed = r; changed["title"] = .string("Synced")
        XCTAssertEqual(d.status(in: [VaultItem(id: item.id, record: changed)!]), .itemChanged)
        XCTAssertEqual(draft().status(in: [item]), .newItem)
        XCTAssertFalse(d.description.contains("Changed title"))
    }

    func test_restore_fills_the_editor() {
        let pro = ProModel(purchases: FakePurchases(), licenseKeys: [:])
        let m = EditorModel(store: MemoryStore(), pro: pro, editing: nil, kind: .web, clock: clock, random: CountingRandom(),
                            background: FakeBackgroundTasks())
        m.restore(draft().values)
        XCTAssertEqual(m.value("password"), secret)
    }
}
