import XCTest
import LGKCore
@testable import AppShared

/// Sub-plan 07 Task 5c: collection states (`col:`/`cm:`/`csl:`) live in the item store, and the shared readers here
/// never count or index them: the free item limit and the Safari save index.
final class CollectionRecordsTests: XCTestCase {
    static let family = "3f2a6c1e-8b4d-4e7a-9c05-d1e2f3a4b5c6"
    static let note = "11111111-1111-4111-8111-111111111111"

    /// One web login, the three collection states and a login-shaped record planted under a reserved id.
    static func snapshot() -> StoreSnapshot {
        func login(_ id: String) -> JSONValue {
            Wrapper.make(ns: .entry, record: .object([
                "id": .string(id), "kind": .string("web"), "label": .string(id), "username": .string("alex"),
                "password": .string("pw1"), "scope": .object(["origin": .string("https://example.com")]), "updated_at": .int(1),
            ]))
        }
        return StoreSnapshot(records: [
            note: login(note),
            CollectionStates.catalogPrefix + family: CollectionStates.wrapper(CollectionStates.catalog(
                collectionID: family, name: "Family", description: "", createdAt: 1, updatedAt: 1)),
            CollectionStates.membershipPrefix + note: CollectionStates.wrapper(CollectionStates.membership(
                itemID: note, collectionIDs: [family])),
            CollectionStates.linkPrefix + family: CollectionStates.wrapper(CollectionStates.link(
                collectionID: family, mode: "edit", role: "owner")),
            "col:planted": Wrapper.make(ns: .entry, record: .object([
                "id": .string("col:planted"), "kind": .string("web"), "label": .string("x"), "username": .string("eve"),
                "password": .string("pw2"), "scope": .object(["origin": .string("https://example.org")]), "updated_at": .int(1),
            ])),
        ], revision: 1)
    }

    func test_reserved_records_are_not_counted_by_the_item_limit() {
        XCTAssertEqual(ItemLimit.liveCount(Self.snapshot()), 1)
        // One item below the free limit plus any number of collections still leave room on the free plan.
        var snap = Self.snapshot()
        for i in 0..<(ItemLimit.freeItems - 2) {
            let id = String(format: "aaaaaaaa-0000-4000-8000-%012ld", i)
            snap.records[id] = Wrapper.make(ns: .item, record: .object(["id": .string(id), "kind": .string("note"),
                                                                       "title": .string("N\(i)"), "updated_at": .int(1)]))
        }
        XCTAssertEqual(ItemLimit.liveCount(snap), ItemLimit.freeItems - 1)
        XCTAssertTrue(ItemLimit.allows(.create, snapshot: snap, isPro: false))
    }

    func test_the_safari_index_never_holds_a_collection_state() {
        let key = Array(repeating: UInt8(7), count: 32)
        let index = SafariIndex.fingerprints(records: Self.snapshot().records, key: key)
        XCTAssertEqual(index.entries.count, 1)
        XCTAssertEqual(index.classify(origin: "https://example.com", username: "alex", key: key), .exists)
        XCTAssertEqual(index.classify(origin: "https://example.org", username: "eve", key: key), .new)
        XCTAssertEqual(index, SafariIndex.fingerprints(records: Self.snapshot().itemRecords, key: key))
    }
}
