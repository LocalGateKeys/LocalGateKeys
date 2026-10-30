import XCTest
import LGKCore
@testable import AppSharedMac

/// Activity history: content-free events only, recorded for copies, deletes, restores, unlock and lock.
@MainActor
final class ActivityRecorderTests: XCTestCase {
    func testActivityNeverStoresContent() throws {
        let local = InMemoryLocalData()
        let recorder = ActivityRecorder(host: local, clock: { Date(timeIntervalSince1970: 1_800_000_000) })
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-act-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        store.limitHints = nil
        var r = EditorModel.newRecord(kind: .web, now: 1_700_000_000, random: SystemRandomSource())
        let id = try XCTUnwrap(r["id"]?.stringValue)
        r["label"] = .string("SecretBankTitle"); r["username"] = .string("alice-user"); r["password"] = .string("hunter2-pass")
        r["scope"] = .object(["origin": .string("https://bank.example")])
        let normal = try Normalise.normalForm(ns: .entry, record: .object(r))
        var snap = try store.load()
        snap.records[id] = Wrapper.make(ns: .entry, record: normal)
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        let trash = TrashModel(store: store, local: local, isPro: { true }, onNeedsPro: { _ in }, activity: recorder)
        recorder.record(.credentialCopy, itemID: id, count: 1)
        try trash.moveToTrash(id: id)
        trash.restore(Set(trash.rows.map(\.id)))
        recorder.record(.itemUpdate, itemID: "not-a-uuid SecretBankTitle")
        let events = try XCTUnwrap(local.localData?.events)
        XCTAssertEqual(events.map(\.eventType), ["credential.copy", "item.delete", "item.restore", "item.update"])
        let encoded = String(decoding: try JSONEncoder().encode(events), as: UTF8.self)
        for secret in ["SecretBankTitle", "alice-user", "hunter2-pass", "example"] {
            XCTAssertFalse(encoded.contains(secret), "\(secret) must never be stored")
        }
        XCTAssertNil(events.last?.itemID, "a non-UUID id is dropped")
        XCTAssertEqual(events.first?.itemID, id.lowercased())
        // Every event the recorder can write passes the desktop's content rules.
        for event in ActivityRecorder.Event.allCases {
            XCTAssertNoThrow(try LocalData.safeEventType(event.rawValue), event.rawValue)
        }
        let rows = ActivityList.rows(events, timeZone: TimeZone(identifier: "UTC")!)
        XCTAssertEqual(rows.first?.event, "item.update", "newest first")
        XCTAssertEqual(rows.last?.when, "2027-01-15 08:00")
        XCTAssertEqual(ActivityList.emptyText, "No activity yet.")
    }

    func testEventsRecordedForCopyAndLock() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-act-lock-\(UUID().uuidString)", isDirectory: true)
        let suite = "lgk-act-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(at: dir); UserDefaults().removePersistentDomain(forName: suite) }
        let settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(), kdfParams: cheap)
        let lock = MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), startTimer: false)
        await lock.create(password: "correct horse battery", confirm: "correct horse battery", touchID: false)
        XCTAssertEqual(lock.state, .unlocked)
        lock.activity.record(.credentialCopy, count: 1)
        XCTAssertEqual(lock.localData?.events.map(\.eventType), ["session.unlock", "credential.copy"])
        lock.lock()
        XCTAssertNil(lock.localData)
        await lock.unlock(password: "correct horse battery")
        XCTAssertEqual(lock.localData?.events.map(\.eventType),
                       ["session.unlock", "credential.copy", "session.lock", "session.unlock"], "saved across the lock")
    }
}
