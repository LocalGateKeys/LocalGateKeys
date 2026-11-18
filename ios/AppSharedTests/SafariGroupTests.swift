import XCTest
import LGKCore
@testable import AppShared

/// Audit 2026-11-10: the Safari extensions hold only the Safari app group. What they need from the app arrives there as
/// files (plan-full and erase-pending markers, the duress mirror), and an earlier build's folder is moved at launch.
final class SafariGroupTests: XCTestCase {
    var root: URL!
    let indexKey = Array(repeating: UInt8(7), count: 32)
    let inboxKey = Array(repeating: UInt8(8), count: 32)

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-safari-group-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    private func note(_ i: Int) -> JSONValue {
        .object(["ns": .string("item"), "record": .object(["id": .string("n\(i)"), "kind": .string("note")])])
    }

    private func exists(_ url: URL) -> Bool { FileManager.default.fileExists(atPath: url.path) }

    // MARK: markers

    func test_marker_places() {
        let files = root.appendingPathComponent("SafariSave", isDirectory: true)
        XCTAssertEqual(SafariSaveFiles.planFullURL(in: files), files.appendingPathComponent("plan-full"))
        XCTAssertEqual(SafariSaveFiles.erasePendingURL(beside: files).standardizedFileURL,
                       root.appendingPathComponent("SafariSave.erase-pending").standardizedFileURL,
                       "beside the folder, so the erase that deletes the folder keeps it")
        XCTAssertEqual(SafariSaveFiles.folder(in: root, profile: nil), files)
        let mirror = SafariSaveFiles.duressMirror(safariRoot: root)
        XCTAssertEqual(mirror?.dir, root.appendingPathComponent("Duress", isDirectory: true))
        XCTAssertNil(SafariSaveFiles.duressMirror(safariRoot: nil))
    }

    func test_publisher_writes_and_clears_the_plan_full_marker() throws {
        let vault = InMemoryKeychainVault()
        try vault.write(.safariIndexKey, indexKey)
        let out = root.appendingPathComponent("SafariSave", isDirectory: true)
        let publisher = SafariIndexPublisher(keychain: vault, directory: { out })
        var records: [String: JSONValue] = [:]
        for i in 0..<(ItemLimit.freeItems - 1) { records["n\(i)"] = note(i) }

        publisher.publish(StoreSnapshot(records: records, revision: 1))
        XCTAssertFalse(exists(SafariSaveFiles.planFullURL(in: out)), "room left")

        records["last"] = note(ItemLimit.freeItems)
        let full = StoreSnapshot(records: records, revision: 2)
        XCTAssertTrue(LocalStore.isPlanFull(full))
        publisher.publish(full)
        XCTAssertTrue(exists(SafariSaveFiles.planFullURL(in: out)))

        records["last"] = nil
        publisher.publish(StoreSnapshot(records: records, revision: 3))
        XCTAssertFalse(exists(SafariSaveFiles.planFullURL(in: out)), "a delete makes room again")
    }

    func test_erase_pending_is_reported_by_shared_style_settings_only() {
        final class Seen: @unchecked Sendable { var values: [Bool] = [] }
        let seen = Seen()
        let mirrored = AppSettings(defaults: UserDefaults(suiteName: "safari-group-\(UUID().uuidString)")!,
                                   onErasePendingChange: { seen.values.append($0) })
        mirrored.erasePending = true
        mirrored.erasePending = false
        XCTAssertEqual(seen.values, [true, false])
        XCTAssertFalse(mirrored.erasePending)
        // A plain instance (tests, previews) reports nothing and touches no container.
        let plain = AppSettings(defaults: UserDefaults(suiteName: "safari-group-\(UUID().uuidString)")!)
        plain.erasePending = true
        XCTAssertTrue(plain.erasePending)
    }

    // MARK: duress mirror

    #if os(iOS)
    func test_duress_mirror_follows_the_session_and_the_hold() throws {
        let shared = root.appendingPathComponent("shared", isDirectory: true)
        try FileManager.default.createDirectory(at: shared, withIntermediateDirectories: true)
        let mirror = try XCTUnwrap(SafariSaveFiles.duressMirror(safariRoot: root.appendingPathComponent("safari", isDirectory: true)))
        let duress = PhoneDuress(files: .under(shared), mirror: mirror, session: DuressSession())
        XCTAssertFalse(SafariSaveService.duressBlocked(mirror: mirror))
        XCTAssertFalse(SafariSaveService.duressBlocked(mirror: nil), "no Safari group: nothing to read")

        // The session marker (created by `openSession` in the app's second-vault folder).
        try FileManager.default.createDirectory(at: duress.files.dir, withIntermediateDirectories: true)
        duress.openSession()
        XCTAssertTrue(exists(mirror.session))
        XCTAssertTrue(SafariSaveService.duressBlocked(mirror: mirror))
        duress.closeSession()
        XCTAssertFalse(exists(mirror.session))
        XCTAssertFalse(SafariSaveService.duressBlocked(mirror: mirror))

        // The hold: the same bytes, read with the same rules.
        try duress.trip(decoyKey: Array(repeating: 3, count: 32))
        XCTAssertEqual(FileManager.default.contents(atPath: mirror.hold.path), FileManager.default.contents(atPath: duress.files.hold.path))
        XCTAssertTrue(SafariSaveService.duressBlocked(mirror: mirror))
        XCTAssertNil(duress.release(), "still held: kept")
        XCTAssertTrue(SafariSaveService.duressBlocked(mirror: mirror))
        XCTAssertTrue(duress.eraseAll())
        XCTAssertFalse(exists(mirror.hold))
        XCTAssertFalse(SafariSaveService.duressBlocked(mirror: mirror))
    }

    /// A hold from before the Safari group (no copy yet) is copied at launch; a damaged one fails closed.
    func test_launch_sync_copies_an_existing_hold_and_fails_closed() throws {
        let shared = root.appendingPathComponent("shared", isDirectory: true)
        try FileManager.default.createDirectory(at: shared, withIntermediateDirectories: true)
        let mirror = try XCTUnwrap(SafariSaveFiles.duressMirror(safariRoot: root.appendingPathComponent("safari", isDirectory: true)))
        let files = DuressFiles.under(shared)
        try PhoneDuress(files: files, session: DuressSession()).trip(decoyKey: Array(repeating: 3, count: 32))
        XCTAssertFalse(SafariSaveService.duressBlocked(mirror: mirror), "no copy yet")
        PhoneDuress(files: files, mirror: mirror, session: DuressSession()).syncMirror()
        XCTAssertTrue(SafariSaveService.duressBlocked(mirror: mirror))

        try Data("not json".utf8).write(to: files.hold)
        PhoneDuress(files: files, mirror: mirror, session: DuressSession()).syncMirror()
        XCTAssertTrue(SafariSaveService.duressBlocked(mirror: mirror), "unreadable: held")
    }
    #endif

    // MARK: migration

    private func blob(_ dir: URL, _ id: String) throws {
        try SafariSaveFiles.writeAtomically([1, 2, 3], to: dir.appendingPathComponent("inbox/\(id).blob"))
    }

    func test_migration_moves_the_whole_folder() throws {
        let shared = root.appendingPathComponent("shared", isDirectory: true)
        let safari = root.appendingPathComponent("safari", isDirectory: true)
        let old = SafariSaveFiles.folder(in: shared, profile: nil)
        try blob(old, "0b7e2c1a-0000-4000-8000-000000000001")
        try SafariSaveFiles.writeAtomically([9], to: SafariSaveFiles.indexURL(in: old))

        SafariGroupMigration.moveLegacyFolders(sharedRoot: shared, safariRoot: safari)
        let new = SafariSaveFiles.folder(in: safari, profile: nil)
        XCTAssertFalse(exists(old), "nothing left in the shared group")
        XCTAssertTrue(exists(new.appendingPathComponent("inbox/0b7e2c1a-0000-4000-8000-000000000001.blob")))
        XCTAssertTrue(exists(SafariSaveFiles.indexURL(in: new)))

        // Idempotent: a second launch has nothing to move.
        SafariGroupMigration.moveLegacyFolders(sharedRoot: shared, safariRoot: safari)
        XCTAssertTrue(exists(SafariSaveFiles.indexURL(in: new)))
    }

    /// The Safari group already has a folder (the extension saved before the app's first launch): only the waiting
    /// inbox entries move; the old index is dropped (republished at the next unlock).
    func test_migration_merges_the_inbox_into_an_existing_folder() throws {
        let shared = root.appendingPathComponent("shared", isDirectory: true)
        let safari = root.appendingPathComponent("safari", isDirectory: true)
        let old = SafariSaveFiles.folder(in: shared, profile: nil)
        let new = SafariSaveFiles.folder(in: safari, profile: nil)
        try blob(old, "0b7e2c1a-0000-4000-8000-000000000001")
        try SafariSaveFiles.writeAtomically([9], to: SafariSaveFiles.indexURL(in: old))
        try blob(new, "0b7e2c1a-0000-4000-8000-000000000002")

        SafariGroupMigration.moveLegacyFolders(sharedRoot: shared, safariRoot: safari)
        XCTAssertFalse(exists(old))
        let inbox = try FileManager.default.contentsOfDirectory(atPath: new.appendingPathComponent("inbox").path)
        XCTAssertEqual(Set(inbox), ["0b7e2c1a-0000-4000-8000-000000000001.blob", "0b7e2c1a-0000-4000-8000-000000000002.blob"])
        XCTAssertFalse(exists(SafariSaveFiles.indexURL(in: new)), "the old index is not carried over")
    }

    /// Moved blobs still open: sealed under the inbox key and bound to their file name, neither of which changes.
    func test_migrated_inbox_entries_still_open() throws {
        let shared = root.appendingPathComponent("shared", isDirectory: true)
        let safari = root.appendingPathComponent("safari", isDirectory: true)
        let old = SafariSaveFiles.folder(in: shared, profile: nil)
        try SafariInbox(directory: old.appendingPathComponent("inbox", isDirectory: true), key: inboxKey, now: { 1000 })
            .add(origin: "https://example.com", username: "alex", password: "pw1")

        SafariGroupMigration.moveLegacyFolders(sharedRoot: shared, safariRoot: safari)
        let moved = SafariInbox(directory: SafariSaveFiles.folder(in: safari, profile: nil).appendingPathComponent("inbox", isDirectory: true),
                                key: inboxKey, now: { 1000 })
        XCTAssertEqual(moved.entries().entries.map(\.username), ["alex"])
        XCTAssertEqual(moved.entries().damaged, [])
    }
}
