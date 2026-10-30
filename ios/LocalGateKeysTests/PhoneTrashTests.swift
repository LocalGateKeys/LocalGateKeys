import XCTest
import AppShared
@testable import LocalGateKeys

/// UX plan workstream 3: Recently deleted on the iPhone (the Mac TrashModel rules on the shared LocalData).
@MainActor
final class PhoneTrashTests: XCTestCase {
    let clock = TestClock(1_800_000_000)
    let id = "11111111-1111-4111-8111-111111111111"

    private func noteRecord(_ id: String) -> JSONValue {
        rec(["id": .string(id), "kind": .string("note"), "title": .string("Cabin"), "body": .string("x"),
             "created_at": .int(1_790_000_000), "updated_at": .int(1_790_000_000)])
    }

    let device = "d4444444-0000-4000-8000-00000000000d"

    /// A joined vault (the editor tests' group state), every record live with vector {desk: 3}.
    private func synced(_ records: [JSONValue]) -> StoreSnapshot {
        var snap = snapshot(records)
        let identity = try! DeviceIdentity(deviceID: device, signingPrivate: Array(repeating: 1, count: 32),
                                           exchangePrivate: Array(repeating: 2, count: 32))
        snap.sync = SyncGroupState(groupID: "g1", epoch: 1, key: Array(repeating: 3, count: 32), identity: identity, installID: "i1",
                                   hasFolder: false, lastSeen: [:], peerDigests: [:], membersEpoch: 1, members: [], keyring: nil,
                                   ownCounter: 0)
        for (key, wrapper) in snap.records { snap.meta[key] = try! SyncMeta.live(wrapper, vv: ["desk": 3]) }
        return snap
    }

    func testDeleteMovesToTrashAndWritesATombstone() throws {
        let store = MemoryStore(synced([noteRecord(id)]))
        let trash = PhoneTrash(local: InMemoryPhoneLocal(), store: store, isPro: { true }, clock: clock,
                               background: FakeBackgroundTasks())
        XCTAssertEqual(trash.moveToTrash(id: id), .saved)
        XCTAssertNil(store.snapshot.records[id])
        XCTAssertEqual(store.snapshot.meta[id]?.deleted, true)
        XCTAssertEqual(trash.rows.map(\.itemID), [id])
        XCTAssertEqual(trash.daysLeft(trash.rows[0]), 30)
    }

    func testUndoRestoresTheSameRecordAndRevivesTheTomb() throws {
        let store = MemoryStore(synced([noteRecord(id)]))
        let before = store.snapshot.records[id]
        let trash = PhoneTrash(local: InMemoryPhoneLocal(), store: store, isPro: { true }, clock: clock,
                               background: FakeBackgroundTasks())
        _ = trash.moveToTrash(id: id)
        XCTAssertEqual(trash.undoLastDelete(isPro: true), .restored)
        XCTAssertEqual(store.snapshot.records[id], before)
        XCTAssertEqual(store.snapshot.meta[id]?.deleted, false)
        // The tomb's vector is kept (desk 3, this device 1), so the next view bumps it once and the restore wins.
        XCTAssertEqual(store.snapshot.meta[id]?.vv, ["desk": 3, device: 1])
        XCTAssertTrue(trash.rows.isEmpty)
    }

    func testAFailedLocalSaveDeletesNothing() {
        let store = MemoryStore(synced([noteRecord(id)]))
        let local = InMemoryPhoneLocal(); local.failSaves = true
        let trash = PhoneTrash(local: local, store: store, isPro: { true }, clock: clock, background: FakeBackgroundTasks())
        XCTAssertEqual(trash.moveToTrash(id: id), .failed)
        XCTAssertNotNil(store.snapshot.records[id])
    }

    func testPurgeTimingFollowsRetention() throws {
        let store = MemoryStore(synced([noteRecord(id)]))
        let local = InMemoryPhoneLocal()
        let trash = PhoneTrash(local: local, store: store, isPro: { true }, clock: clock, background: FakeBackgroundTasks())
        _ = trash.moveToTrash(id: id)
        try trash.setRetentionDays(7)
        clock.now += 6 * 86_400
        trash.purgeExpired()
        XCTAssertEqual(trash.rows.count, 1)
        XCTAssertEqual(trash.daysLeft(trash.rows[0]), 1)
        clock.now += 2 * 86_400
        trash.purgeExpired()
        XCTAssertTrue(trash.rows.isEmpty)
    }

    func testRestoreIsRefusedOverTheFreeLimit() throws {
        // Free plan: the vault already holds the free limit of live items.
        var records: [JSONValue] = []
        for n in 0..<ItemLimit.freeItems { records.append(noteRecord(String(format: "22222222-2222-4222-8222-%012ld", n))) }
        records.append(noteRecord(id))
        let store = MemoryStore(synced(records))
        let trash = PhoneTrash(local: InMemoryPhoneLocal(), store: store, isPro: { false }, clock: clock,
                               background: FakeBackgroundTasks())
        _ = trash.moveToTrash(id: id)
        XCTAssertEqual(trash.restore(trash.rows[0].id, isPro: false), .limit)
        XCTAssertEqual(trash.rows.count, 1)
        XCTAssertEqual(trash.restore(trash.rows[0].id, isPro: true), .restored)
    }

    func testEmptyAll() throws {
        let store = MemoryStore(synced([noteRecord(id)]))
        let trash = PhoneTrash(local: InMemoryPhoneLocal(), store: store, isPro: { true }, clock: clock, background: FakeBackgroundTasks())
        _ = trash.moveToTrash(id: id)
        try trash.emptyAll()
        XCTAssertTrue(trash.rows.isEmpty)
    }

    func testLocalDataFileRoundTripsAndIsCiphertext() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("phone-local-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let key = [UInt8](repeating: 7, count: 32)
        let a = PhoneLocalData(directory: dir, key: key)
        var data = LocalData.empty
        data.trash = [try LocalData.TrashRow(record: noteRecord(id), deletedAt: 1_800_000_000)]
        try a.commitLocalData(data)
        let bytes = try Data(contentsOf: a.fileURL)
        XCTAssertNil(String(data: bytes, encoding: .utf8)?.range(of: "Cabin"))
        XCTAssertEqual(PhoneLocalData(directory: dir, key: key).localData?.trash.count, 1)
        // Another key can't read it: set aside, starts empty with the reset message.
        let other = PhoneLocalData(directory: dir, key: [UInt8](repeating: 8, count: 32))
        XCTAssertEqual(other.localData?.trash.count, 0)
        XCTAssertEqual(other.loadMessage, PhoneLocalData.resetMessage)
    }
}
