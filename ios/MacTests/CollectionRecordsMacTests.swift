import XCTest
import LGKCore
@testable import AppSharedMac

/// In-memory store (one test at a time).
private final class CollectionTestStore: ItemStore, @unchecked Sendable {
    var snapshot: StoreSnapshot
    init(_ s: StoreSnapshot) { snapshot = s }
    func load() throws -> StoreSnapshot { snapshot }
    func commit(_ change: StoreChange) throws {
        guard change.baseRevision == snapshot.revision else { throw LocalStoreError.stale(expected: change.baseRevision, actual: snapshot.revision) }
        snapshot = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: snapshot.revision + 1)
    }
}

/// Sub-plan 07 Task 5c on the Mac: collection states (`col:`/`cm:`/`csl:`) live in the item store. Deletes arriving
/// from sync or a restore never put them in Recently deleted, the Mac's Recently deleted keeps an item's collections
/// and brings them back, and the list never shows them.
@MainActor
final class CollectionRecordsMacTests: XCTestCase {
    static let family = "3f2a6c1e-8b4d-4e7a-9c05-d1e2f3a4b5c6"
    static let noteID = "11111111-1111-4111-8111-111111111111"

    static func snapshot() -> StoreSnapshot {
        let note = Wrapper.make(ns: .item, record: .object([
            "id": .string(noteID), "kind": .string("note"), "title": .string("Cabin"),
            "created_at": .int(1_790_000_000), "updated_at": .int(1_790_000_000)]))
        return StoreSnapshot(records: [
            noteID: note,
            CollectionStates.catalogPrefix + family: CollectionStates.wrapper(CollectionStates.catalog(
                collectionID: family, name: "Family", description: "", createdAt: 1, updatedAt: 1)),
            CollectionStates.membershipPrefix + noteID: CollectionStates.wrapper(CollectionStates.membership(
                itemID: noteID, collectionIDs: [family])),
            "col:planted": Wrapper.make(ns: .item, record: .object([
                "id": .string("col:planted"), "kind": .string("note"), "title": .string("Planted"), "updated_at": .int(1)])),
        ], revision: 4)
    }

    func testRemoteDeletesNeverMoveCollectionStatesToTheTrash() throws {
        let rows = RemoteDeletes.trashRows(before: Self.snapshot(), records: [:], meta: [:], now: 9)
        XCTAssertEqual(rows.count, 1)
        guard case .object(let r) = try rows[0].record() else { return XCTFail("not an object") }
        XCTAssertEqual(r["id"], .string(Self.noteID))
        XCTAssertEqual(r["collection_ids"], .array([.string(Self.family)]))
    }

    func testTheMacTrashKeepsAndRestoresCollections() throws {
        let store = CollectionTestStore(Self.snapshot())
        let local = InMemoryLocalData()
        let model = TrashModel(store: store, local: local, isPro: { true }, onNeedsPro: { _ in }, activity: nil,
                               clock: { Date(timeIntervalSince1970: 1_800_000_000) })
        XCTAssertThrowsError(try model.moveToTrash(id: "col:planted")) { XCTAssertEqual($0 as? TrashModel.Failure, .notFound) }
        try model.moveToTrash(id: Self.noteID)
        XCTAssertNil(store.snapshot.records[Self.noteID])
        XCTAssertNil(store.snapshot.records[CollectionStates.membershipPrefix + Self.noteID])
        XCTAssertEqual(model.rows.map(\.itemID), [Self.noteID])
        model.restore(Set(model.rows.map(\.id)))
        XCTAssertEqual(model.failures, [])
        XCTAssertEqual(store.snapshot.records[Self.noteID], Self.snapshot().records[Self.noteID])
        XCTAssertEqual(store.snapshot.records[CollectionStates.membershipPrefix + Self.noteID],
                       Self.snapshot().records[CollectionStates.membershipPrefix + Self.noteID])
    }

    func testTheListShowsOnlyItems() {
        XCTAssertEqual(VaultItem.items(from: Self.snapshot()).map(\.id), [Self.noteID])
    }
}
