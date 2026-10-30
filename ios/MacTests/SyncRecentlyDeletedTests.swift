import XCTest
import LGKCore
@testable import AppSharedMac

private final class SyncTrashMemoryStore: ItemStore, @unchecked Sendable {
    var snapshot = StoreSnapshot()
    var failNext = false
    /// Runs inside the next commit, before it fails (another save landing meanwhile).
    var duringCommit: (() -> Void)?
    func load() throws -> StoreSnapshot { snapshot }
    func commit(_ change: StoreChange) throws {
        duringCommit?(); duringCommit = nil
        if failNext { failNext = false; throw LocalStoreError.stale(expected: change.baseRevision, actual: snapshot.revision + 1) }
        guard change.baseRevision == snapshot.revision else {
            throw LocalStoreError.stale(expected: change.baseRevision, actual: snapshot.revision)
        }
        snapshot = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: snapshot.revision + 1)
    }
}

/// Windows `vault_bridge`: a delete that arrives through sync moves the record to the trash and never purges.
/// Every Mac sync path (Wi-Fi client, cloud folder, Wi-Fi host) commits through `SyncSourceStore`, which copies
/// newly tombstoned live items into Recently deleted before the commit.
@MainActor
final class SyncRecentlyDeletedTests: XCTestCase {
    static let mac = "d5555555-0000-4000-8000-00000000000d"
    static let peer = "b2222222-0000-4000-8000-00000000000b"
    static let id = "33333333-bbbb-4000-8000-000000000003"
    static let now: Int64 = 1_790_000_000

    private func note(_ title: String) -> JSONValue {
        .object(["ns": .string("item"), "schema": .int(1), "updated_at": .int(Self.now),
                 "record": .object(["id": .string(Self.id), "kind": .string("note"), "title": .string(title),
                                    "favorite": .bool(false), "tags": .array([]), "created_at": .int(Self.now),
                                    "updated_at": .int(Self.now),
                                    "payload": .object(["body": .string("x"), "fields": .array([]), "template_id": .null])])])
    }

    /// A store holding one live note (vv {mac: 1}) and the sync source over it.
    private func setUp(local: InMemoryLocalData) throws -> (SyncTrashMemoryStore, SyncSourceStore) {
        let base = SyncTrashMemoryStore()
        let view = try SyncMeta.localView(records: [Self.id: note("Shared note")], meta: [:], device: Self.mac, now: Self.now)
        base.snapshot = StoreSnapshot(records: [Self.id: note("Shared note")], meta: view.meta, revision: 1)
        let publishing = PublishingItemStore(base: base) { _ in }
        return (base, SyncSourceStore(base: publishing, local: local))
    }

    /// The peer's tombstone dominates the Mac's version.
    private func peerTomb(over vv: [String: Int64]) throws -> PeerView {
        var next = vv
        next[Self.peer] = (vv[Self.peer] ?? 0) + 1
        return PeerView(deviceID: Self.peer, states: [try ItemState(itemID: Self.id, vv: next, deleted: true,
                                                                    deletedAt: Self.now + 10, item: nil)])
    }

    private func runSync(_ source: SyncSourceStore, _ view: PeerView) throws -> RunReport {
        let snap = try source.load()
        let report = SyncRunner.run(store: snap, views: [view], device: Self.mac, now: Self.now + 20)
        if let r = report.records, let m = report.meta, r != snap.records || m != snap.meta {
            try source.commit(StoreChange(baseRevision: snap.revision, records: r, meta: m, sync: snap.sync))
        }
        return report
    }

    func testSyncDeleteMovesItemToRecentlyDeleted() throws {
        let local = InMemoryLocalData()
        let (base, source) = try setUp(local: local)
        let report = try runSync(source, try peerTomb(over: base.snapshot.meta[Self.id]!.vv))
        XCTAssertEqual(report.deleted, 1)
        XCTAssertNil(base.snapshot.records[Self.id], "deleted in the vault, as on the other device")
        let trash = try XCTUnwrap(local.localData?.trash)
        XCTAssertEqual(trash.count, 1, "kept in Recently deleted, never purged")
        XCTAssertEqual((try trash[0].record()).objectValue?["title"], .string("Shared note"))
    }

    func testFailedSyncCommitTakesTheRowOutAgain() throws {
        let local = InMemoryLocalData()
        let (base, source) = try setUp(local: local)
        base.failNext = true
        XCTAssertThrowsError(try runSync(source, try peerTomb(over: base.snapshot.meta[Self.id]!.vv)))
        XCTAssertNotNil(base.snapshot.records[Self.id])
        XCTAssertEqual(local.localData?.trash.count, 0)
    }

    func testRollbackKeepsRowsSavedMeanwhile() throws {
        let local = InMemoryLocalData()
        let (base, source) = try setUp(local: local)
        let other = LocalData.TrashRow(recordJSON: #"{"id":"other","kind":"note","title":"Deleted here"}"#, deletedAt: 5)
        base.failNext = true
        base.duringCommit = {
            MainActor.assumeIsolated {
                var data = local.localData!
                data.trash.append(other)
                try! local.commitLocalData(data)
            }
        }
        XCTAssertThrowsError(try runSync(source, try peerTomb(over: base.snapshot.meta[Self.id]!.vv)))
        XCTAssertNotNil(base.snapshot.records[Self.id])
        XCTAssertEqual(local.localData?.trash, [other], "only the failed commit's rows are taken out")
    }

    func testRecentlyDeletedUnavailableRefusesTheDelete() throws {
        let local = InMemoryLocalData()
        let (base, source) = try setUp(local: local)
        local.failSaves = true
        XCTAssertThrowsError(try runSync(source, try peerTomb(over: base.snapshot.meta[Self.id]!.vv)))
        XCTAssertNotNil(base.snapshot.records[Self.id], "never deleted without its Recently deleted copy")
    }

    func testRestoringThenSyncingAgainDoesNotLoop() throws {
        let local = InMemoryLocalData()
        let (base, source) = try setUp(local: local)
        let tomb = try peerTomb(over: base.snapshot.meta[Self.id]!.vv)
        _ = try runSync(source, tomb)
        let trash = TrashModel(store: source, local: local, isPro: { true }, onNeedsPro: { _ in }, activity: nil,
                               clock: { Date(timeIntervalSince1970: TimeInterval(Self.now + 30)) })
        trash.restore(Set(trash.rows.map(\.id)))
        XCTAssertNotNil(base.snapshot.records[Self.id])
        XCTAssertEqual(local.localData?.trash.count, 0)
        // The same peer tombstone arrives again: the restored version beats it, nothing is deleted or trashed.
        let again = try runSync(source, tomb)
        XCTAssertEqual(again.deleted, 0)
        XCTAssertNotNil(base.snapshot.records[Self.id])
        XCTAssertEqual(local.localData?.trash.count, 0)
        // And once more: still stable.
        XCTAssertEqual(try runSync(source, tomb).deleted, 0)
    }

    // Every path goes through the hook: the coordinator's store (Wi-Fi client, SyncCoordinator.swift:436, and the
    // cloud folder, FolderSync.runOnce via folderRun) is checked in MacSyncWiringTests.testCoordinatorUsesPublishingStore;
    // the Wi-Fi host's (LanResponder.swift:158) in LanListenerTests.testNotListeningWhileLocked.
}
