import XCTest
import LGKCore
@testable import AppSharedMac

/// Recently deleted: delete tombstones and keeps the exact record, restore writes it back live, the free limit
/// keeps items in the trash, permanent delete and automatic emptying.
@MainActor
final class TrashModelTests: XCTestCase {
    private var dir: URL!
    private var store: LocalStore!
    private var local: InMemoryLocalData!
    private var needsPro: [ProReason] = []
    private var now = Date(timeIntervalSince1970: 1_800_000_000)
    private var pro = false

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-trash-\(UUID().uuidString)", isDirectory: true)
        store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        store.limitHints = nil
        local = InMemoryLocalData()
        needsPro = []; pro = false
        now = Date(timeIntervalSince1970: 1_800_000_000)
    }

    override func tearDown() async throws { try? FileManager.default.removeItem(at: dir) }

    private func model(activity: ActivityRecorder? = nil) -> TrashModel {
        TrashModel(store: store, local: local, isPro: { [unowned self] in pro }, onNeedsPro: { [unowned self] in needsPro.append($0) },
                   activity: activity, clock: { [unowned self] in now })
    }

    /// Adds a login (with a stored meta, as after a sync) and returns its id.
    @discardableResult
    private func addLogin(_ title: String, username: String = "sam") throws -> String {
        var r = EditorModel.newRecord(kind: .web, now: 1_700_000_000, random: SystemRandomSource())
        let id = try XCTUnwrap(r["id"]?.stringValue)
        r["label"] = .string(title); r["username"] = .string(username); r["password"] = .string("pw-\(title)")
        r["scope"] = .object(["origin": .string("https://\(title.lowercased()).example")])
        let normal = try Normalise.normalForm(ns: .entry, record: .object(r))
        var snap = try store.load()
        let wrapper = Wrapper.make(ns: .entry, record: normal)
        snap.records[id] = wrapper
        snap.meta[id] = try SyncMeta.live(wrapper, vv: [Self.device: 1])
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        return id
    }

    static let device = "0b6f3c1e-8a5d-4c2b-9f7e-1d2c3b4a5e6f"

    private func liveIDs() throws -> Set<String> { Set(VaultItem.items(from: try store.load()).map(\.id)) }

    func testDeleteMovesToTrashAndTombstones() throws {
        let id = try addLogin("Bank")
        let before = try store.load()
        let canonical = try CanonicalJSON.encode(XCTUnwrap(before.records[id]?.objectValue?["record"]), dialect: .utf8)
        try model().moveToTrash(id: id)
        let after = try store.load()
        XCTAssertNil(after.records[id], "the record leaves the store")
        XCTAssertFalse(try liveIDs().contains(id))
        let row = try XCTUnwrap(local.localData?.trash.first)
        XCTAssertEqual(Array(row.recordJSON.utf8), canonical, "the trash keeps the exact record")
        XCTAssertEqual(row.deletedAt, 1_800_000_000)
        // The next view publishes the delete as a tombstone with a bumped vector.
        let view = try SyncMeta.localView(records: after.records, meta: after.meta, device: Self.device, now: 1_800_000_001)
        XCTAssertEqual(view.states[id]?.deleted, true)
        XCTAssertEqual(view.meta[id]?.vv[Self.device], 2)
        let rows = model().rows
        XCTAssertEqual(rows.map(\.title), ["Bank"])
        XCTAssertEqual(rows.first?.detail, "Website login · sam")
    }

    func testDeleteLocalSaveFailsLeavesStoreUnchanged() throws {
        let id = try addLogin("Bank")
        let before = try store.load()
        local.failSaves = true
        XCTAssertThrowsError(try model().moveToTrash(id: id)) { XCTAssertEqual($0 as? TrashModel.Failure, .localSave) }
        let after = try store.load()
        XCTAssertEqual(after.records[id], before.records[id], "never lost from both")
        XCTAssertEqual(after.meta[id], before.meta[id])
        XCTAssertEqual(local.localData?.trash.count, 0)
    }

    func testDeleteStoreCommitFailsRemovesRow() throws {
        let id = try addLogin("Bank")
        let failing = FailingCommitStore(store)
        let m = TrashModel(store: failing, local: local, isPro: { true }, onNeedsPro: { _ in }, activity: nil, clock: { [unowned self] in now })
        XCTAssertThrowsError(try m.moveToTrash(id: id)) { XCTAssertEqual($0 as? TrashModel.Failure, .store) }
        XCTAssertTrue(try liveIDs().contains(id), "still live")
        XCTAssertEqual(local.localData?.trash.count, 0, "row removed again")
    }

    func testDeleteKeepsBothCopiesWhenCompensationFails() throws {
        let id = try addLogin("Bank")
        let failing = FailingCommitStore(store)
        failing.onCommit = { [unowned self] in local.failSaves = true }
        let m = TrashModel(store: failing, local: local, isPro: { true }, onNeedsPro: { _ in }, activity: nil, clock: { [unowned self] in now })
        XCTAssertThrowsError(try m.moveToTrash(id: id)) { XCTAssertEqual($0 as? TrashModel.Failure, .compensation) }
        XCTAssertTrue(try liveIDs().contains(id))
        XCTAssertEqual(local.localData?.trash.count, 1, "both copies kept")
        XCTAssertEqual(m.failures, [TrashModel.compensationMessage])
    }

    func testRestoreWritesLive() throws {
        let id = try addLogin("Bank")
        let original = try XCTUnwrap(try store.load().records[id])
        let m = model()
        try m.moveToTrash(id: id)
        // As after a sync: the delete is tombstoned in the stored meta.
        var snap = try store.load()
        let view = try SyncMeta.localView(records: snap.records, meta: snap.meta, device: Self.device, now: 1_800_000_001)
        snap.meta = view.meta
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        m.restore(Set(m.rows.map(\.id)))
        XCTAssertEqual(m.message, "Restored 1 item(s).")
        XCTAssertTrue(try liveIDs().contains(id))
        let restored = try store.load()
        XCTAssertEqual(try CanonicalJSON.encode(XCTUnwrap(restored.records[id]), dialect: .utf8),
                       try CanonicalJSON.encode(original, dialect: .utf8), "byte-identical record")
        XCTAssertEqual(local.localData?.trash.count, 0)
        // The next view publishes it live again above the tombstone.
        let next = try SyncMeta.localView(records: restored.records, meta: restored.meta, device: Self.device, now: 1_800_000_002)
        XCTAssertEqual(next.states[id]?.deleted, false)
        XCTAssertEqual(next.meta[id]?.vv[Self.device], 3)
    }

    func testRestoreAtLimitKeepsItemInTrash() throws {
        let gone = try addLogin("Gone")
        let m = model()
        try m.moveToTrash(id: gone)
        for n in 0..<ItemLimit.freeItems { try addLogin("Item\(n)") }
        let trashBefore = local.localData?.trash
        m.restore(Set(m.rows.map(\.id)))
        XCTAssertEqual(needsPro, [.itemLimit], "the Pro sheet shows")
        XCTAssertEqual(m.message, "Restored 0 item(s).")
        XCTAssertEqual(local.localData?.trash, trashBefore, "it stays in Recently deleted")
        XCTAssertFalse(try liveIDs().contains(gone))
        XCTAssertNil(try store.load().records[gone])
        // With Pro it comes back.
        pro = true
        m.restore(Set(m.rows.map(\.id)))
        XCTAssertTrue(try liveIDs().contains(gone))
    }

    func testPurgeAndEmpty() throws {
        let m = model()
        for t in ["A", "B", "C"] { try m.moveToTrash(id: try addLogin(t)); now += 10 }
        XCTAssertEqual(m.rows.map(\.title), ["C", "B", "A"], "newest first")
        XCTAssertEqual(m.countText, "3 item(s)")
        let b = try XCTUnwrap(m.rows.first { $0.title == "B" }).id
        m.toggle(b)
        XCTAssertEqual(m.countText, "1 of 3 selected")
        XCTAssertEqual(m.purgeConfirmText([b]),
                       "Permanently delete \u{2018}B\u{2019}? This cannot be undone. Previous backups can still contain it.")
        m.purge([b])
        XCTAssertEqual(m.message, "Permanently deleted 1 item(s).")
        XCTAssertEqual(m.rows.map(\.title), ["C", "A"])
        XCTAssertEqual(m.purgeConfirmText(Set(m.rows.map(\.id))),
                       "Permanently delete 2 items? This cannot be undone. Previous backups can still contain them.")
        m.emptyAll()
        XCTAssertEqual(m.message, "Permanently deleted 2 item(s).")
        XCTAssertTrue(m.rows.isEmpty)
        XCTAssertEqual(TrashModel.emptyText, "Recently deleted is empty.")
    }

    func testPurgeExpiredSaveFailureIsShown() throws {
        let m = model()
        try m.moveToTrash(id: try addLogin("Old"))
        now += 31 * 86_400
        local.failSaves = true
        m.purgeExpired()
        XCTAssertEqual(m.failures, ["Recently deleted could not be saved on this Mac."])
        XCTAssertEqual(m.message, "Expired items could not be removed.")
        XCTAssertEqual(local.localData?.trash.count, 1, "nothing changed")
    }

    func testAutoPurgeAfterRetention() throws {
        let m = model()
        try m.moveToTrash(id: try addLogin("Old"))
        XCTAssertEqual(m.retentionText, "Entries stay encrypted for 30 days. Expired entries are purged on the next vault write. "
                       + "Older backups may retain copies.")
        now += 29 * 86_400
        m.purgeExpired()
        XCTAssertEqual(m.rows.count, 1, "kept within 30 days")
        now += 2 * 86_400
        // Auto-purge off keeps it.
        var data = try XCTUnwrap(local.localData); data.preferences.trashAutoPurge = false
        try local.commitLocalData(data)
        m.purgeExpired()
        XCTAssertEqual(m.rows.count, 1)
        XCTAssertTrue(m.retentionText.hasPrefix("Automatic emptying is off"))
        data.preferences.trashAutoPurge = true
        try local.commitLocalData(data)
        m.purgeExpired()
        XCTAssertTrue(m.rows.isEmpty, "purged after 30 days")
        // A shorter retention from Settings applies at once.
        try m.moveToTrash(id: try addLogin("Recent"))
        now += 8 * 86_400
        let settings = MacSettingsModel(settings: AppSettings(defaults: UserDefaults(suiteName: "lgk-trash-\(UUID().uuidString)")!),
                                        pro: ProModel(purchases: NoPurchases()), passwords: nil, local: local, clock: { [unowned self] in now })
        settings.trashRetentionDays = 7
        XCTAssertEqual(local.localData?.preferences.trashRetentionDays, 7)
        XCTAssertTrue(m.rows.isEmpty)
    }
}

@MainActor
final class NoPurchases: ProPurchasing {
    func isEntitled() async -> Bool { false }
    func offer() async -> ProOffer { .unavailable }
    func purchase() async throws -> PurchaseOutcome { .cancelled }
    func restore() async throws -> Bool { false }
    func entitlementChanges() -> AsyncStream<Void> { AsyncStream { $0.finish() } }
}

/// A store whose commits always fail (reads pass through).
final class FailingCommitStore: ItemStore, @unchecked Sendable {
    let inner: any ItemStore
    var onCommit: (() -> Void)?
    init(_ inner: any ItemStore) { self.inner = inner }
    func load() throws -> StoreSnapshot { try inner.load() }
    func commit(_ change: StoreChange) throws {
        MainActor.assumeIsolated { onCommit?() }
        throw LocalDataError.invalid("commit failed")
    }
}
