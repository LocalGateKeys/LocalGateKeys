import XCTest
import AppShared
@testable import LocalGateKeys

/// A `MemoryStore` that someone else (a sync) commits to just before each of our first `times` commits, so
/// those find the store stale.
final class InterferingStore: ItemStore, @unchecked Sendable {
    let inner: MemoryStore
    private var times: Int
    private let change: (inout StoreSnapshot) -> Void
    private(set) var staleCommits = 0

    init(_ inner: MemoryStore, times: Int = 1, change: @escaping (inout StoreSnapshot) -> Void) {
        self.inner = inner; self.times = times; self.change = change
    }

    func load() throws -> StoreSnapshot { try inner.load() }

    func commit(_ c: StoreChange) throws {
        if times > 0 {
            times -= 1
            change(&inner.snapshot)
            inner.snapshot.revision += 1
            staleCommits += 1
        }
        try inner.commit(c)
    }
}

/// Fixed values of these tests (outside the main-actor test class, so any closure can read them).
enum SafariFixture {
    static let origin = "https://accounts.example.com"
    static let existingID = "11111111-1111-4111-8111-111111111111"
}

/// The notices the import model showed.
@MainActor
final class NoticeLog {
    var messages: [String] = []
}

/// Holds the task a test cancels from inside a fake.
@MainActor
final class TaskBox {
    var task: Task<Void, Never>?
    var unlocked = true
}

@MainActor
final class SafariImporterTests: XCTestCase {
    let clock = TestClock(1_800_000_000)
    let key = Array(repeating: UInt8(5), count: 32)
    /// Stands in for `<app group>/SafariSave`.
    var root: URL!
    /// `root/inbox`.
    var dir: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-safari-import-\(UUID().uuidString)", isDirectory: true)
        dir = root.appendingPathComponent("inbox", isDirectory: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    func inbox(key: [UInt8]? = nil) -> SafariInbox {
        SafariInbox(directory: dir, key: key ?? self.key, now: { [clock] in clock.now })
    }

    /// What the Safari extension does on Save, at the clock's current time.
    func saveInSafari(_ origin: String = SafariFixture.origin, _ username: String = "ada@example.com", _ password: String) throws {
        try inbox().add(origin: origin, username: username, password: password)
    }

    func saveInSafari(password: String) throws {
        try saveInSafari(SafariFixture.origin, "ada@example.com", password)
    }

    func importer(_ store: any ItemStore, pro: Bool = false) -> SafariImporter {
        SafariImporter(store: store, inbox: inbox(), clock: clock, isPro: pro)
    }

    func waiting() -> [SafariInboxEntry] { inbox().entries().entries }

    func blobFiles() -> [URL] {
        ((try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [])
            .filter { $0.pathExtension == "blob" }
    }

    /// Every web login in the store, by record id.
    func logins(_ store: MemoryStore) -> [String: [String: JSONValue]] {
        store.snapshot.records.compactMapValues { w -> [String: JSONValue]? in
            guard case .object(let o) = w, case .object(let r)? = o["record"], r["kind"] == .string("web") else { return nil }
            return r
        }
    }

    func existingLogin(password: String = "Old-Pass-0", history: [JSONValue]? = nil) -> JSONValue {
        var r: [String: JSONValue] = [
            "id": .string(SafariFixture.existingID), "kind": .string("web"), "label": .string("My example"),
            "username": .string("ada@example.com"), "password": .string(password),
            "scope": rec(["origin": .string(SafariFixture.origin)]), "created_at": .int(1_700_000_000),
            "updated_at": .int(1_700_000_000), "favorite": .bool(false), "tags": .array([]),
        ]
        if let history { r["password_history"] = .array(history) }
        return .object(r)
    }

    func historyRow(_ password: String, _ at: Int64) -> JSONValue {
        rec(["password": .string(password), "changed_at": .int(at)])
    }

    // MARK: import

    func test_import_new_login() throws {
        let store = MemoryStore()
        try saveInSafari(password: "Maple-Orbit-7731")

        let result = try importer(store).run()

        XCTAssertEqual(result, SafariImportResult(saved: 1, waiting: 0, damaged: 0))
        XCTAssertEqual(result.notice, "1 login saved from Safari")
        XCTAssertEqual(store.commits, 1)
        let all = logins(store)
        XCTAssertEqual(all.count, 1)
        let (id, r) = try XCTUnwrap(all.first)
        XCTAssertEqual(r["id"], .string(id))
        XCTAssertEqual(r["label"], .string(OriginLabel.friendly(SafariFixture.origin)))
        XCTAssertEqual(r["label"], .string("example.com"))
        XCTAssertEqual(r["scope"]?.objectValue?["origin"], .string(SafariFixture.origin))
        XCTAssertEqual(r["username"], .string("ada@example.com"))
        XCTAssertEqual(r["password"], .string("Maple-Orbit-7731"))
        XCTAssertEqual(r["created_at"], .int(clock.now))
        XCTAssertEqual(r["updated_at"], .int(clock.now))
        XCTAssertEqual(r["favorite"], .bool(false))
        XCTAssertEqual(r["tags"], .array([]))
        XCTAssertNil(r["password_history"])
        // Stored in normal form and wrapped as the editor does.
        XCTAssertEqual(try Normalise.normalForm(ns: .entry, record: .object(r)), .object(r))
        XCTAssertEqual(store.snapshot.records[id], Wrapper.make(ns: .entry, record: .object(r)))
        XCTAssertTrue(store.snapshot.meta.isEmpty, "no SyncMeta: the next sync stamps it")
        XCTAssertTrue(waiting().isEmpty)
        XCTAssertTrue(blobFiles().isEmpty)
        // A second run finds nothing to do.
        XCTAssertEqual(try importer(store).run(), .nothing)
        XCTAssertEqual(store.commits, 1)
    }

    func test_import_update_pushes_history_max_5() throws {
        let old = (1...5).map { historyRow("Older-\($0)", 1_600_000_000 + Int64($0)) }
        let store = MemoryStore(snapshot([existingLogin(history: old)]))
        try saveInSafari(password: "New-Pass-1")

        let result = try importer(store).run()

        XCTAssertEqual(result, SafariImportResult(saved: 1, waiting: 0, damaged: 0))
        XCTAssertEqual(store.commits, 1)
        let all = logins(store)
        XCTAssertEqual(Array(all.keys), [SafariFixture.existingID])
        let r = try XCTUnwrap(all[SafariFixture.existingID])
        XCTAssertEqual(r["password"], .string("New-Pass-1"))
        XCTAssertEqual(r["label"], .string("My example"), "a name the user chose is kept")
        XCTAssertEqual(r["updated_at"], .int(clock.now))
        XCTAssertEqual(r["created_at"], .int(1_700_000_000))
        // Desktop upsert_web: {password, changed_at} of the old password first, at most 5.
        XCTAssertEqual(r["password_history"], .array([historyRow("Old-Pass-0", clock.now)] + Array(old.prefix(4))))
        XCTAssertEqual(try Normalise.normalForm(ns: .entry, record: .object(r)), .object(r))
        XCTAssertTrue(waiting().isEmpty)
    }

    func test_import_same_password_is_noop_and_removed() throws {
        let store = MemoryStore(snapshot([existingLogin(password: "Same-Pass")]))
        let before = store.snapshot
        try saveInSafari(password: "Same-Pass")

        let result = try importer(store).run()

        XCTAssertEqual(result, .nothing)
        XCTAssertNil(result.notice)
        XCTAssertEqual(store.commits, 0, "nothing changed, nothing written")
        XCTAssertEqual(store.snapshot, before)
        XCTAssertTrue(waiting().isEmpty, "the entry is removed all the same")
    }

    func test_over_limit_stays_in_inbox() throws {
        // Free plan, 3 notes + 1 login = 4 items: the vault is full.
        let store = MemoryStore(snapshot(numberedNotes(3) + [existingLogin()]))
        try saveInSafari(password: "Changed-Pass")                         // an update: always allowed
        clock.now += 10
        try saveInSafari("https://shop.example.org", "ada", "Shop-Pass")   // a new login: needs a slot

        let free = try importer(store, pro: false).run()

        XCTAssertEqual(free, SafariImportResult(saved: 1, waiting: 1, damaged: 0))
        XCTAssertEqual(free.notice, "1 login saved from Safari · 1 waiting: upgrade to Pro to import")
        XCTAssertEqual(logins(store)[SafariFixture.existingID]?["password"], .string("Changed-Pass"))
        XCTAssertEqual(logins(store).count, 1)
        XCTAssertEqual(waiting().map(\.origin), ["https://shop.example.org"])

        // Still free: it keeps waiting, and nothing is written.
        XCTAssertEqual(try importer(store, pro: false).run(), SafariImportResult(saved: 0, waiting: 1, damaged: 0))
        XCTAssertEqual(store.commits, 1)

        // Pro: it imports.
        XCTAssertEqual(try importer(store, pro: true).run(), SafariImportResult(saved: 1, waiting: 0, damaged: 0))
        XCTAssertEqual(logins(store).count, 2)
        XCTAssertTrue(waiting().isEmpty)
    }

    func test_damaged_entry_removed_and_counted() throws {
        let store = MemoryStore()
        try saveInSafari(password: "Good-Pass")
        // Garbage under a valid name, and an entry sealed under another key.
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data("not a blob".utf8).write(to: dir.appendingPathComponent("\(UUID().uuidString.lowercased()).blob"))
        try inbox(key: Array(repeating: 9, count: 32)).add(origin: "https://other.example", username: "bo", password: "x")
        XCTAssertEqual(blobFiles().count, 3)

        let result = try importer(store).run()

        XCTAssertEqual(result, SafariImportResult(saved: 1, waiting: 0, damaged: 2))
        XCTAssertEqual(result.notice, "1 login saved from Safari · 2 could not be read")
        XCTAssertEqual(logins(store).count, 1)
        XCTAssertTrue(blobFiles().isEmpty)
    }

    func test_only_damaged_entries_are_removed_without_a_commit() throws {
        let store = MemoryStore()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data("junk".utf8).write(to: dir.appendingPathComponent("\(UUID().uuidString.lowercased()).blob"))

        XCTAssertEqual(try importer(store).run(), SafariImportResult(saved: 0, waiting: 0, damaged: 1))
        XCTAssertEqual(store.commits, 0)
        XCTAssertTrue(blobFiles().isEmpty)
    }

    func test_stale_commit_retries_once() throws {
        // While we import, a sync brings the same login from the PC: the retry matches it and updates it
        // instead of adding a duplicate.
        let inner = MemoryStore()
        let synced = existingLogin(password: "From-PC")
        let store = InterferingStore(inner) { s in
            s.records[SafariFixture.existingID] = Wrapper.make(ns: .entry, record: synced)
        }
        try saveInSafari(password: "From-Safari")

        let result = try importer(store).run()

        XCTAssertEqual(result, SafariImportResult(saved: 1, waiting: 0, damaged: 0))
        XCTAssertEqual(store.staleCommits, 1)
        XCTAssertEqual(inner.commits, 1)
        let all = logins(inner)
        XCTAssertEqual(Array(all.keys), [SafariFixture.existingID])
        XCTAssertEqual(all[SafariFixture.existingID]?["password"], .string("From-Safari"))
        XCTAssertEqual(all[SafariFixture.existingID]?["password_history"], .array([historyRow("From-PC", clock.now)]))
        XCTAssertTrue(waiting().isEmpty)
    }

    func test_stale_twice_throws_and_keeps_the_inbox() throws {
        let inner = MemoryStore()
        let store = InterferingStore(inner, times: 2) { _ in }
        try saveInSafari(password: "Kept-Pass")

        XCTAssertThrowsError(try importer(store).run()) { error in
            guard case LocalStoreError.stale? = error as? LocalStoreError else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(store.staleCommits, 2)
        XCTAssertEqual(inner.commits, 0)
        XCTAssertEqual(waiting().count, 1, "nothing is lost: the next run imports it")
    }

    func test_import_two_entries_same_login_newest_wins() throws {
        let store = MemoryStore()
        let t = clock.now
        // Saved newest first on disk, so the order comes from captured_at, not from the files.
        clock.now = t + 10
        try saveInSafari(password: "Second-Pass")
        clock.now = t
        try saveInSafari(password: "First-Pass")
        clock.now = t + 20
        XCTAssertEqual(waiting().map(\.password), ["First-Pass", "Second-Pass"])

        let result = try importer(store).run()

        XCTAssertEqual(result, SafariImportResult(saved: 1, waiting: 0, damaged: 0), "one login, counted once")
        XCTAssertEqual(store.commits, 1, "one StoreChange for the batch")
        let all = logins(store)
        XCTAssertEqual(all.count, 1)
        let r = try XCTUnwrap(all.values.first)
        XCTAssertEqual(r["password"], .string("Second-Pass"))
        XCTAssertEqual(r["password_history"], .array([historyRow("First-Pass", clock.now)]))
        XCTAssertTrue(waiting().isEmpty)
    }

    func test_update_for_deleted_login_becomes_new() throws {
        // 4 notes + the login: over the free limit. The update waits in the inbox while the login is deleted.
        let store = MemoryStore(snapshot(numberedNotes(4) + [existingLogin()]))
        try saveInSafari(password: "Changed-Pass")
        XCTAssertEqual(EditorModel.delete(id: SafariFixture.existingID, store: store, clock: clock, background: FakeBackgroundTasks()), .saved)
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), 4)

        // It is now a new login, and the free vault is full: it waits.
        XCTAssertEqual(try importer(store, pro: false).run(), SafariImportResult(saved: 0, waiting: 1, damaged: 0))
        XCTAssertTrue(logins(store).isEmpty)
        XCTAssertEqual(waiting().count, 1)

        // With Pro it imports as a new login (a new id, never the deleted one back).
        XCTAssertEqual(try importer(store, pro: true).run(), SafariImportResult(saved: 1, waiting: 0, damaged: 0))
        let all = logins(store)
        XCTAssertEqual(all.count, 1)
        let (id, r) = try XCTUnwrap(all.first)
        XCTAssertNotEqual(id, SafariFixture.existingID)
        XCTAssertEqual(r["password"], .string("Changed-Pass"))
        XCTAssertEqual(r["label"], .string("example.com"))
        XCTAssertNil(r["password_history"])
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), 5)
    }

    func test_deleted_tombstoned_login_is_not_matched() throws {
        // A record still present but tombstoned in the sync meta is not live.
        let store = MemoryStore(snapshot([existingLogin()], deleted: [SafariFixture.existingID]))
        try saveInSafari(password: "Changed-Pass")

        XCTAssertEqual(try importer(store, pro: true).run(), SafariImportResult(saved: 1, waiting: 0, damaged: 0))
        XCTAssertEqual(logins(store)[SafariFixture.existingID]?["password"], .string("Old-Pass-0"))
        XCTAssertEqual(logins(store).count, 2)
    }

    /// A login a newer desktop stored with a field this app does not know: Normalise refuses any change to
    /// it. The Safari entry may be the only copy of the new password, so it is kept, never deleted.
    func test_refused_update_stays_in_inbox() throws {
        guard case .object(var stored) = existingLogin() else { return XCTFail("fixture") }
        stored["future_field"] = .string("from a newer desktop")
        let store = MemoryStore(snapshot([.object(stored)]))
        let before = store.snapshot
        try saveInSafari(password: "Only-Copy-1")

        let result = try importer(store).run()

        XCTAssertEqual(result, SafariImportResult(saved: 0, waiting: 0, damaged: 0, kept: 1))
        XCTAssertEqual(result.notice, "1 could not be imported")
        XCTAssertEqual(store.commits, 0)
        XCTAssertEqual(store.snapshot, before, "the stored login is left as it is")
        XCTAssertEqual(waiting().map(\.password), ["Only-Copy-1"], "the new password is not lost")
        XCTAssertEqual(blobFiles().count, 1)

        // Still refused next time: still kept, and with the other counts joined by " · ".
        try saveInSafari("https://shop.example.org", "ada", "Shop-Pass")
        let again = try importer(store, pro: true).run()
        XCTAssertEqual(again, SafariImportResult(saved: 1, waiting: 0, damaged: 0, kept: 1))
        XCTAssertEqual(again.notice, "1 login saved from Safari · 1 could not be imported")
        XCTAssertEqual(waiting().map(\.password), ["Only-Copy-1"])
    }

    /// The full update (old password pushed to the history) makes the login too large for the vault; the
    /// narrow retry changes only the password and updated_at, and imports.
    func test_refused_update_imports_through_the_narrow_retry() throws {
        let limit = 512 * 1024
        let oldPassword = String(repeating: "o", count: 2000)
        let newPassword = String(repeating: "n", count: 2000)
        let stored = try paddedLogin(password: oldPassword, size: limit - 100)
        XCTAssertNoThrow(try Normalise.normalForm(ns: .entry, record: stored), "the stored login itself is valid")
        let store = MemoryStore(snapshot([stored]))
        try saveInSafari(password: newPassword)

        let result = try importer(store).run()

        XCTAssertEqual(result, SafariImportResult(saved: 1, waiting: 0, damaged: 0))
        let r = try XCTUnwrap(logins(store)[SafariFixture.existingID])
        XCTAssertEqual(r["password"], .string(newPassword))
        XCTAssertEqual(r["updated_at"], .int(clock.now))
        XCTAssertNil(r["password_history"], "no history push in the narrow form")
        XCTAssertTrue(waiting().isEmpty)
    }

    /// A new login Normalise refuses because of its own fields (a username too long) is dropped and counted.
    func test_refused_new_login_is_dropped() throws {
        let store = MemoryStore()
        try saveInSafari(SafariFixture.origin, String(repeating: "u", count: 600), "Pass-1")

        let result = try importer(store, pro: true).run()

        XCTAssertEqual(result, SafariImportResult(saved: 0, waiting: 0, damaged: 1))
        XCTAssertEqual(result.notice, "1 could not be read")
        XCTAssertEqual(store.commits, 0)
        XCTAssertTrue(logins(store).isEmpty)
        XCTAssertTrue(waiting().isEmpty)
        XCTAssertTrue(blobFiles().isEmpty)
    }

    /// `existingLogin` padded with custom fields until its normal form is exactly `size` bytes.
    func paddedLogin(password: String, size target: Int) throws -> JSONValue {
        guard case .object(let base) = existingLogin(password: password) else { throw CocoaError(.coderInvalidValue) }
        func login(_ fields: [JSONValue]) -> JSONValue {
            var r = base
            r["custom_fields"] = .array(fields)
            return .object(r)
        }
        func size(_ fields: [JSONValue]) throws -> Int {
            try CanonicalJSON.encode(try Normalise.normalForm(ns: .entry, record: login(fields)), dialect: .utf8).count
        }
        let chunk = String(repeating: "x", count: 4000)
        let keys = (0..<16).map { "k\($0)" }
        var fields: [JSONValue] = []
        var current = try size(fields)
        while target - current > 70_000 {
            fields.append(.object(Dictionary(uniqueKeysWithValues: keys.map { ($0, JSONValue.string(chunk)) })))
            current = try size(fields)
        }
        while target - current > 4_100 {
            fields.append(.object(["v": .string(chunk)]))
            current = try size(fields)
        }
        fields.append(.object(["v": .string("")]))
        current = try size(fields)
        fields[fields.count - 1] = .object(["v": .string(String(repeating: "x", count: target - current))])
        XCTAssertEqual(try size(fields), target)
        return login(fields)
    }

    func test_notice_text() {
        XCTAssertEqual(SafariImportResult(saved: 1, waiting: 0, damaged: 0).notice, "1 login saved from Safari")
        XCTAssertEqual(SafariImportResult(saved: 2, waiting: 1, damaged: 1).notice,
                       "2 logins saved from Safari · 1 waiting: upgrade to Pro to import · 1 could not be read")
        XCTAssertEqual(SafariImportResult(saved: 0, waiting: 3, damaged: 0).notice, "3 waiting: upgrade to Pro to import")
        XCTAssertEqual(SafariImportResult(saved: 0, waiting: 0, damaged: 2).notice, "2 could not be read")
        XCTAssertNil(SafariImportResult(saved: 0, waiting: 0, damaged: 0).notice)
        XCTAssertEqual(SafariImportResult(saved: 0, waiting: 0, damaged: 0, kept: 2).notice, "2 could not be imported")
        XCTAssertEqual(SafariImportResult(saved: 1, waiting: 1, damaged: 1, kept: 1).notice,
                       "1 login saved from Safari · 1 waiting: upgrade to Pro to import · 1 could not be read · 1 could not be imported")
    }

    // MARK: keys and the app's import model

    func test_keys_ensure_creates_both_and_keeps_them() throws {
        let keychain = InMemoryKeychainVault()
        try SafariKeys.ensure(keychain: keychain)
        let index = try XCTUnwrap(try keychain.read(.safariIndexKey))
        let inboxKey = try XCTUnwrap(try keychain.read(.safariInboxKey))
        XCTAssertEqual(index.count, 32)
        XCTAssertEqual(inboxKey.count, 32)
        XCTAssertNotEqual(index, inboxKey)

        try SafariKeys.ensure(keychain: keychain)
        XCTAssertEqual(try keychain.read(.safariIndexKey), index)
        XCTAssertEqual(try keychain.read(.safariInboxKey), inboxKey)

        try keychain.write(.safariInboxKey, [1, 2, 3])   // malformed: replaced
        try SafariKeys.ensure(keychain: keychain)
        XCTAssertEqual(try keychain.read(.safariInboxKey)?.count, 32)
        XCTAssertEqual(try keychain.read(.safariIndexKey), index)
    }

    func test_model_imports_inside_a_background_task_and_shows_the_notice() throws {
        let keychain = InMemoryKeychainVault()
        try keychain.write(.safariInboxKey, key)
        let store = MemoryStore()
        let tasks = FakeBackgroundTasks()
        let shown = NoticeLog()
        let model = SafariImportModel(clock: clock, background: tasks, directory: { [root] in root! },
                                      show: { shown.messages.append($0) })
        try saveInSafari(password: "Pass-1")
        clock.now += 1
        try saveInSafari("https://b.example.com", "bo", "Pass-2")

        let pending = try XCTUnwrap(model.review(store: store, keychain: keychain))
        XCTAssertEqual(pending.count, 2)
        XCTAssertEqual(model.pending, pending)
        XCTAssertEqual(store.commits, 0, "nothing is imported before the user confirms")
        XCTAssertTrue(tasks.begun.isEmpty)

        let result = model.confirm(Set(pending.map(\.id)), store: store, keychain: keychain, isPro: false)

        XCTAssertEqual(result, SafariImportResult(saved: 2, waiting: 0, damaged: 0))
        XCTAssertEqual(shown.messages, ["2 logins saved from Safari"])
        XCTAssertEqual(tasks.begun, ["LocalGateKeys Safari import"])
        XCTAssertTrue(tasks.open.isEmpty)
        XCTAssertEqual(model.pending, [])

        // Nothing waiting: nothing to ask, no notice.
        XCTAssertEqual(model.review(store: store, keychain: keychain), [])
        XCTAssertEqual(model.confirm([], store: store, keychain: keychain, isPro: false), .nothing)
        XCTAssertEqual(shown.messages.count, 1)
    }

    /// Audit 2026-10-24 L-18: the review compares passwords in the app (unchanged ones are dropped without
    /// asking), says new or update, and only the confirmed entries are imported; declined ones are deleted.
    func test_review_then_confirm_imports_only_the_approved_entries() throws {
        let keychain = InMemoryKeychainVault()
        try keychain.write(.safariInboxKey, key)
        let store = MemoryStore(snapshot([existingLogin(password: "Old-Pass-0")]))
        let shown = NoticeLog()
        let model = SafariImportModel(clock: clock, background: FakeBackgroundTasks(), directory: { [root] in root! },
                                      show: { shown.messages.append($0) })
        try saveInSafari(password: "Old-Pass-0")                        // unchanged: dropped without asking
        clock.now += 1
        try saveInSafari(password: "New-Pass-1")                        // update
        clock.now += 1
        try saveInSafari("https://b.example.com", "bo", "Pass-2")       // new, declined
        clock.now += 1
        try saveInSafari("https://c.example.com", "cy", "Pass-3")       // new, approved

        let pending = try XCTUnwrap(model.review(store: store, keychain: keychain))
        XCTAssertEqual(pending.map(\.change), [.update, .new, .new])
        XCTAssertEqual(pending.map(\.username), ["ada@example.com", "bo", "cy"])
        XCTAssertEqual(pending.map(\.origin), [SafariFixture.origin, "https://b.example.com", "https://c.example.com"])
        XCTAssertEqual(waiting().count, 3, "the unchanged capture is gone")
        XCTAssertEqual(SafariReviewSheet.detail(pending[0]), "Updates the saved password \u{00B7} " + SafariFixture.origin)

        let approved: Set<String> = [pending[0].id, pending[2].id, "not-an-entry"]
        let result = model.confirm(approved, store: store, keychain: keychain, isPro: true)
        XCTAssertEqual(result, SafariImportResult(saved: 2, waiting: 0, damaged: 0))
        XCTAssertEqual(waiting(), [], "the declined entry is deleted")
        let byUser = Dictionary(uniqueKeysWithValues: logins(store).values.map { ($0["username"]?.stringValue ?? "", $0) })
        XCTAssertEqual(byUser["ada@example.com"]?["password"], .string("New-Pass-1"))
        XCTAssertNil(byUser["bo"])
        XCTAssertEqual(byUser["cy"]?["password"], .string("Pass-3"))
    }

    /// "Decide later" keeps every entry for the next review; a capture arriving after the review is not
    /// imported by a confirmation that did not show it.
    func test_later_keeps_entries_and_unseen_captures_are_not_imported() throws {
        let keychain = InMemoryKeychainVault()
        try keychain.write(.safariInboxKey, key)
        let store = MemoryStore()
        let model = SafariImportModel(clock: clock, background: FakeBackgroundTasks(), directory: { [root] in root! },
                                      show: { _ in })
        try saveInSafari(password: "Pass-1")
        XCTAssertEqual(model.review(store: store, keychain: keychain)?.count, 1)
        model.later()
        XCTAssertEqual(model.pending, [])
        XCTAssertEqual(waiting().count, 1)
        XCTAssertEqual(store.commits, 0)

        let shown = try XCTUnwrap(model.review(store: store, keychain: keychain))
        clock.now += 1
        try saveInSafari("https://late.example.com", "lee", "Pass-9")
        XCTAssertEqual(model.confirm(Set(shown.map(\.id)), store: store, keychain: keychain, isPro: true)?.saved, 1)
        XCTAssertEqual(waiting().map(\.username), ["lee"], "asked at the next review")
    }

    func test_model_without_inbox_key_does_nothing() throws {
        try saveInSafari(password: "Pass-1")
        let model = SafariImportModel(clock: clock, background: FakeBackgroundTasks(), directory: { [root] in root! },
                                      show: { _ in XCTFail("no notice") })
        XCTAssertNil(model.review(store: MemoryStore(), keychain: InMemoryKeychainVault()))
        XCTAssertNil(model.confirm([], store: MemoryStore(), keychain: InMemoryKeychainVault(), isPro: true))
        XCTAssertEqual(model.pending, [])
        XCTAssertEqual(waiting().count, 1)
    }

    func test_after_unlock_creates_keys_publishes_index_and_imports() async throws {
        let keychain = InMemoryKeychainVault()
        let store = MemoryStore(snapshot([existingLogin()]))
        let shown = NoticeLog()
        let model = SafariImportModel(clock: clock, background: FakeBackgroundTasks(), directory: { [root] in root! },
                                      show: { shown.messages.append($0) })
        let pro = ProModel(purchases: FakePurchases(), licenseKeys: [:])

        // First unlock: no keys yet, so nothing can be waiting. Both keys are created and the index published.
        await model.afterUnlock(store: store, keychain: keychain, pro: pro, isUnlocked: { true })
        let inboxKey = try XCTUnwrap(try keychain.read(.safariInboxKey))
        let indexKey = try XCTUnwrap(try keychain.read(.safariIndexKey))
        let index = try SafariIndex.decode(Array(try Data(contentsOf: SafariSaveFiles.indexURL(in: root))))
        XCTAssertEqual(index, SafariIndex.fingerprints(records: store.snapshot.records, key: indexKey))
        XCTAssertEqual(index.entries.count, 1)
        XCTAssertTrue(shown.messages.isEmpty)

        // Safari saves a new login; the next unlock asks, and imports it once confirmed.
        try inbox(key: inboxKey).add(origin: "https://new.example.com", username: "ada", password: "Pass-9")
        await model.afterUnlock(store: store, keychain: keychain, pro: pro, isUnlocked: { true })
        XCTAssertEqual(model.pending.map(\.username), ["ada"])
        XCTAssertTrue(shown.messages.isEmpty)
        XCTAssertEqual(logins(store).count, 1, "not imported before the user confirms")
        model.confirm(Set(model.pending.map(\.id)), store: store, keychain: keychain, isPro: pro.isPro)
        XCTAssertEqual(shown.messages, ["1 login saved from Safari"])
        XCTAssertEqual(logins(store).count, 2)
    }

    /// The vault locks while the entitlement is read: no keys written, nothing committed, inbox kept, no notice.
    func test_after_unlock_stops_if_the_vault_locks_during_refresh() async throws {
        let keychain = InMemoryKeychainVault()
        try keychain.write(.safariInboxKey, key)
        try saveInSafari(password: "Pass-1")
        let store = MemoryStore()
        let shown = NoticeLog()
        let model = SafariImportModel(clock: clock, background: FakeBackgroundTasks(), directory: { [root] in root! },
                                      show: { shown.messages.append($0) })
        let state = TaskBox()
        let purchases = FakePurchases()
        purchases.duringIsEntitled = { state.unlocked = false }
        let pro = ProModel(purchases: purchases, licenseKeys: [:])

        await model.afterUnlock(store: store, keychain: keychain, pro: pro, isUnlocked: { state.unlocked })

        XCTAssertEqual(store.commits, 0)
        XCTAssertNil(try keychain.read(.safariIndexKey), "no Keychain write after the lock")
        XCTAssertFalse(FileManager.default.fileExists(atPath: SafariSaveFiles.indexURL(in: root).path))
        XCTAssertEqual(waiting().count, 1)
        XCTAssertTrue(shown.messages.isEmpty)
    }

    /// The unlocked view goes away (task cancelled) during the entitlement read: nothing happens, and the
    /// cut-short read does not turn a purchased Pro off.
    func test_after_unlock_stops_if_cancelled_during_refresh_and_keeps_pro() async throws {
        let keychain = InMemoryKeychainVault()
        try keychain.write(.safariInboxKey, key)
        try saveInSafari(password: "Pass-1")
        let store = MemoryStore()
        let shown = NoticeLog()
        let model = SafariImportModel(clock: clock, background: FakeBackgroundTasks(), directory: { [root] in root! },
                                      show: { shown.messages.append($0) })
        let box = TaskBox()
        let purchases = FakePurchases()   // entitled == false: what a cut-short read would report
        purchases.duringIsEntitled = { box.task?.cancel() }
        let pro = ProModel(purchases: purchases, licenseKeys: [:], purchased: true)

        box.task = Task { await model.afterUnlock(store: store, keychain: keychain, pro: pro, isUnlocked: { true }) }
        await box.task?.value

        XCTAssertTrue(pro.isPro, "a cancelled refresh keeps the last known entitlement")
        XCTAssertEqual(store.commits, 0)
        XCTAssertNil(try keychain.read(.safariIndexKey))
        XCTAssertEqual(waiting().count, 1)
        XCTAssertTrue(shown.messages.isEmpty)
    }

    /// Back in the foreground before afterUnlock re-read Pro: ignored, so no import runs with a stale Pro
    /// state (no wrong "waiting: upgrade to Pro" notice). After afterUnlock it imports; after a lock it waits
    /// for the next afterUnlock again.
    func test_foreground_is_ignored_until_after_unlock_finished() async throws {
        let keychain = InMemoryKeychainVault()
        let store = MemoryStore()
        let model = SafariImportModel(clock: clock, background: FakeBackgroundTasks(), directory: { [root] in root! },
                                      show: { _ in })
        let pro = ProModel(purchases: FakePurchases(), licenseKeys: [:])

        model.foregrounded()
        XCTAssertFalse(model.ready)
        XCTAssertEqual(model.foregroundRuns, 0, "no import before the unlock's own import")

        await model.afterUnlock(store: store, keychain: keychain, pro: pro, isUnlocked: { true })
        XCTAssertTrue(model.ready)
        model.foregrounded()
        XCTAssertEqual(model.foregroundRuns, 1)

        model.locked()
        model.foregrounded()
        XCTAssertEqual(model.foregroundRuns, 1, "a lock waits for the next afterUnlock")

        // An afterUnlock cut short by a lock does not make the model ready.
        await model.afterUnlock(store: store, keychain: keychain, pro: pro, isUnlocked: { false })
        XCTAssertFalse(model.ready)
        model.foregrounded()
        XCTAssertEqual(model.foregroundRuns, 1)
    }
}
