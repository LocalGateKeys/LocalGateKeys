import XCTest
import AppShared
@testable import LocalGateKeys

/// Sub-plan 07 task 5f: the iPhone's collections over the item store (`CollectionsModel`, the Vault list's
/// Collections filter, the editor's membership picker), on the free plan, with view-only shared items and the
/// one-time move of local collections at unlock.
@MainActor
final class CollectionsPhoneModelTests: XCTestCase {
    static let noteID = "11111111-1111-4111-8111-111111111111"
    static let cardID = "44444444-4444-4444-8444-444444444444"
    static let loginID = "22222222-2222-4222-8222-222222222222"
    static let family = "3f2a6c1e-8b4d-4e7a-9c05-d1e2f3a4b5c6"
    let clock = TestClock(1_800_000_000)

    static let noteRecord = rec(["id": .string(noteID), "kind": .string("note"), "title": .string("Cabin"),
                                 "payload": rec(["body": .string("x"), "fields": .array([])]),
                                 "created_at": .int(1_790_000_000), "updated_at": .int(1_790_000_000)])
    static let cardRecord = rec(["id": .string(cardID), "kind": .string("card"), "title": .string("Travel card"),
                                 "payload": rec(["brand": .string("visa")]),
                                 "created_at": .int(1_790_000_000), "updated_at": .int(1_790_000_000)])
    static let loginRecord = rec(["id": .string(loginID), "kind": .string("web"), "label": .string("Bank"),
                                  "username": .string("sam"), "password": .string("hunter2"),
                                  "scope": rec(["origin": .string("https://bank.example")]), "updated_at": .int(1_790_000_000)])

    /// Sequential canonical UUIDs for new collections.
    final class IDs {
        var n = 0
        func next() -> String { n += 1; return String(format: "aaaaaaaa-0000-4000-8000-%012ld", n) }
    }

    func model(_ store: MemoryStore, local: InMemoryPhoneLocal? = nil, ids: IDs = IDs()) -> CollectionsModel {
        CollectionsModel(store: store, localData: { local?.localData }, saveLocal: { try local?.commitLocalData($0) },
                         clock: clock, background: FakeBackgroundTasks(), newID: { ids.next() })
    }

    /// The store with `Family` holding the note, and a `csl:` link saying another of this person's devices holds
    /// Family as a member of a view-only share.
    static func viewOnlyFamily() -> StoreSnapshot {
        var snap = snapshot([noteRecord, cardRecord])
        snap.records[CollectionStates.catalogPrefix + family] = CollectionStates.wrapper(CollectionStates.catalog(
            collectionID: family, name: "Family", description: "", createdAt: 1, updatedAt: 1))
        snap.records[CollectionStates.membershipPrefix + noteID] = CollectionStates.wrapper(CollectionStates.membership(
            itemID: noteID, collectionIDs: [family]))
        snap.records[CollectionStates.linkPrefix + family] = CollectionStates.wrapper(CollectionStates.link(
            collectionID: family, mode: "read", role: "member"))
        return snap
    }

    func editor(_ store: MemoryStore, item: VaultItem?, kind: EditorKind) -> EditorModel {
        EditorModel(store: store, pro: ProModel(purchases: FakePurchases()), editing: item, kind: kind, clock: clock,
                    random: CountingRandom(), background: FakeBackgroundTasks())
    }

    func item(_ store: MemoryStore, _ id: String) throws -> VaultItem {
        try XCTUnwrap(VaultItem.items(from: store.snapshot).first { $0.id == id })
    }

    // MARK: - create, rename, delete, filter, membership

    func testCreatesRenamesSetsMembershipFiltersAndDeletesKeepingTheItems() throws {
        let store = MemoryStore(snapshot([Self.noteRecord, Self.cardRecord]))
        let trashed = try LocalData.TrashRow(record: rec(["id": .string("55555555-5555-4555-8555-555555555555"),
                                                          "kind": .string("note"), "title": .string("Old"),
                                                          "collection_ids": strs(["aaaaaaaa-0000-4000-8000-000000000001"])]),
                                             deletedAt: 1_799_000_000)
        let local = InMemoryPhoneLocal(LocalData(trash: [trashed]))
        let m = model(store, local: local)

        let id = try XCTUnwrap(m.create(name: "  Family "))
        XCTAssertEqual(m.rows.map(\.name), ["Family"])
        XCTAssertEqual(m.rows.first?.count, 0)
        XCTAssertNil(m.create(name: "family"))
        XCTAssertEqual(m.message, String(localized: "A collection with this name already exists."))
        XCTAssertNil(m.create(name: "   "))
        XCTAssertEqual(m.message, String(localized: "Enter a name for the collection."))

        XCTAssertTrue(m.rename(id, to: "Home"))
        XCTAssertEqual(m.rows.map(\.name), ["Home"])
        XCTAssertNil(m.message)

        XCTAssertTrue(m.setMemberships(itemID: Self.noteID, kind: "note", to: [id]))
        XCTAssertEqual(m.rows.first?.count, 1)
        XCTAssertEqual(CollectionCatalog.memberships(of: Self.noteID, in: store.snapshot), [id])

        // The Vault list's filter: only the note, remembered on this device, back to All items once it is gone.
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "CollectionsPhoneModelTests-\(UUID().uuidString)"))
        let list = VaultListModel(store: store, defaults: defaults)
        list.reload()
        XCTAssertNil(list.collectionFilter, "All items is the default")
        XCTAssertEqual(Set(list.listItems.map(\.id)), [Self.noteID, Self.cardID])
        list.collectionFilter = id
        XCTAssertEqual(list.listItems.map(\.id), [Self.noteID])
        XCTAssertEqual(list.collectionFilterName, "Home")
        list.sort = .titleAsc
        XCTAssertEqual(try XCTUnwrap(list.sortedItems(filter: .all)).map(\.id), [Self.noteID])
        list.sort = nil
        XCTAssertEqual(defaults.string(forKey: VaultListModel.collectionKey), id)
        let again = VaultListModel(store: store, defaults: defaults)
        again.reload()
        XCTAssertEqual(again.listItems.map(\.id), [Self.noteID], "the choice is remembered")

        XCTAssertTrue(m.delete(id))
        XCTAssertTrue(m.rows.isEmpty)
        XCTAssertEqual(Set(VaultItem.items(from: store.snapshot).map(\.id)), [Self.noteID, Self.cardID], "the items stay")
        XCTAssertTrue(CollectionCatalog.memberships(of: Self.noteID, in: store.snapshot).isEmpty)
        // The Recently deleted row forgets the deleted collection.
        let row = try XCTUnwrap(local.localData?.trash.first)
        XCTAssertNil(try row.record().objectValue?["collection_ids"])

        again.reload()
        XCTAssertNil(again.collectionFilter)
        XCTAssertNil(defaults.string(forKey: VaultListModel.collectionKey))
        XCTAssertEqual(again.listItems.count, 2)
    }

    func testStartersAreAddedOnceAndRemembered() throws {
        let store = MemoryStore(snapshot([Self.noteRecord]))
        let local = InMemoryPhoneLocal()
        let m = model(store, local: local)
        m.reload()
        XCTAssertTrue(m.missingStarters)
        XCTAssertTrue(m.addStarters())
        XCTAssertEqual(Set(m.rows.map(\.name)), Set(CollectionCatalog.starterNames))
        XCTAssertFalse(m.missingStarters)
        XCTAssertEqual(local.localData?.starterCollectionIDs.count, 4)
        let commits = store.commits
        XCTAssertTrue(m.addStarters())
        XCTAssertEqual(store.commits, commits, "nothing missing: nothing written")
    }

    // MARK: - free plan

    func testTheFreePlanAllowsEveryCollectionChange() throws {
        // A free vault at its item limit: collections are free and never count as items.
        var records = [Self.noteRecord]
        for i in 1..<ItemLimit.freeItems {
            records.append(rec(["id": .string(String(format: "99999999-aaaa-4000-8000-%012ld", i)), "kind": .string("note"),
                                "title": .string("n\(i)"), "payload": rec(["body": .string("")]), "updated_at": .int(1)]))
        }
        let store = MemoryStore(snapshot(records))
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), ItemLimit.freeItems)
        let m = model(store)
        let id = try XCTUnwrap(m.create(name: "Family"))
        XCTAssertTrue(m.addStarters())
        XCTAssertTrue(m.rename(id, to: "Home"))
        XCTAssertTrue(m.setMemberships(itemID: Self.noteID, kind: "note", to: [id]))
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), ItemLimit.freeItems)
        XCTAssertFalse(ItemLimit.allows(.create, snapshot: store.snapshot, isPro: false), "still at the item limit")

        // The editor of a free phone moves an existing note into a collection.
        let e = editor(store, item: try item(store, Self.noteID), kind: .note)
        e.loadCollections()
        XCTAssertTrue(e.offersCollections)
        XCTAssertEqual(e.memberships, [id])
        e.memberships = []
        XCTAssertEqual(e.save(), .saved)
        XCTAssertTrue(CollectionCatalog.memberships(of: Self.noteID, in: store.snapshot).isEmpty)
        XCTAssertTrue(m.delete(id))
    }

    func testANewNoteIsSavedIntoACollectionInOneCommit() throws {
        let store = MemoryStore()
        let m = model(store)
        let id = try XCTUnwrap(m.create(name: "Family"))
        let e = editor(store, item: nil, kind: .note)
        e.loadCollections()
        XCTAssertEqual(e.collections.map(\.id), [id])
        e.set("title", "Cabin"); e.set("body", "x")
        e.memberships = [id]
        XCTAssertEqual(e.membershipSummary, "Family")
        let commits = store.commits
        XCTAssertEqual(e.save(), .saved)
        XCTAssertEqual(store.commits, commits + 1)
        let saved = try XCTUnwrap(e.savedID)
        XCTAssertEqual(CollectionCatalog.memberships(of: saved, in: store.snapshot), [id])
        // Only the membership changed: it is saved without touching the record.
        let record = store.snapshot.records[saved]
        let again = editor(store, item: try item(store, saved), kind: .note)
        again.loadCollections()
        again.memberships = []
        XCTAssertEqual(again.save(), .saved)
        XCTAssertEqual(store.snapshot.records[saved], record)
        XCTAssertTrue(CollectionCatalog.memberships(of: saved, in: store.snapshot).isEmpty)
    }

    // MARK: - logins

    func testLoginsHaveNoPicker() throws {
        XCTAssertFalse(CollectionsModel.offersPicker(kind: "web"))
        XCTAssertFalse(CollectionsModel.offersPicker(kind: "desktop"))
        XCTAssertFalse(CollectionsModel.offersPicker(kind: "document"))
        XCTAssertTrue(CollectionsModel.offersPicker(kind: "note"))
        XCTAssertTrue(CollectionsModel.offersPicker(kind: "card"))

        let store = MemoryStore(snapshot([Self.loginRecord]))
        let m = model(store)
        let id = try XCTUnwrap(m.create(name: "Family"))
        let e = editor(store, item: try item(store, Self.loginID), kind: .web)
        XCTAssertFalse(e.offersCollections)
        XCTAssertFalse(m.setMemberships(itemID: Self.loginID, kind: "web", to: [id]))
        XCTAssertEqual(m.message, EditorModel.notMemberText)
        XCTAssertTrue(CollectionCatalog.memberships(of: Self.loginID, in: store.snapshot).isEmpty)
    }

    // MARK: - view-only shared items

    func testAReadOnlyItemRefusesEditDeleteAndMove() throws {
        let store = MemoryStore(Self.viewOnlyFamily())
        let before = store.snapshot

        let e = editor(store, item: try item(store, Self.noteID), kind: .note)
        e.loadCollections()
        XCTAssertTrue(e.isReadOnly, "it opens read-only")
        e.set("title", "Changed")
        XCTAssertEqual(e.save(), .invalid)
        XCTAssertEqual(e.error, EditorModel.readOnlyItemText)
        XCTAssertEqual(e.delete(using: nil), .invalid)
        XCTAssertEqual(EditorModel.delete(id: Self.noteID, store: store, clock: clock, background: FakeBackgroundTasks()), .invalid)
        XCTAssertEqual(VaultListModel.setFavorite(true, id: Self.noteID, store: store, clock: clock,
                                                  background: FakeBackgroundTasks()), .invalid)

        let m = model(store)
        XCTAssertFalse(m.setMemberships(itemID: Self.noteID, kind: "note", to: []), "not moved out")
        XCTAssertEqual(m.message, EditorModel.readOnlyCollectionText)
        XCTAssertFalse(m.setMemberships(itemID: Self.cardID, kind: "card", to: [Self.family]), "nothing moved in")
        XCTAssertFalse(m.rename(Self.family, to: "Ours"))
        XCTAssertEqual(m.message, EditorModel.readOnlyCollectionText)
        XCTAssertFalse(m.delete(Self.family))
        XCTAssertEqual(m.message, EditorModel.sharedDeleteText)
        m.reload()
        XCTAssertEqual(m.rows.first?.isShared, true)
        XCTAssertEqual(m.rows.first?.isReadOnly, true)
        XCTAssertEqual(store.snapshot, before, "nothing was written")
        XCTAssertEqual(store.commits, 0)

        // The card is not in the share: it still changes.
        XCTAssertFalse(EditorModel.itemIsReadOnly(Self.cardID, in: store.snapshot))
    }

    /// Read-only from this device's own share records (not a `csl:` link from another device): the catalog checks
    /// only the links, so the model refuses the rename itself. The share store here cannot be decoded, so it fails
    /// closed through `ShareGroups.readOnlyCollectionIDs`: every collection it names is view only.
    func testRenameRefusesACollectionThisDeviceHoldsViewOnly() throws {
        var snap = snapshot([Self.noteRecord])
        snap.records[CollectionStates.catalogPrefix + Self.family] = CollectionStates.wrapper(CollectionStates.catalog(
            collectionID: Self.family, name: "Family", description: "", createdAt: 1, updatedAt: 1))
        snap.shares = .object(["damaged-group": .object(["collection_id": .string(Self.family)])])
        let store = MemoryStore(snap)
        XCTAssertNil(snap.records[CollectionStates.linkPrefix + Self.family], "no csl: link: only the share store says so")
        XCTAssertTrue(ShareGroups.readOnlyCollectionIDs(in: snap).contains(Self.family))
        XCTAssertNotNil(try CollectionCatalog.rename(Self.family, to: "Ours", in: snap, now: clock.now),
                        "the catalog alone would not refuse it")

        let m = model(store)
        XCTAssertFalse(m.rename(Self.family, to: "Ours"))
        XCTAssertEqual(m.message, EditorModel.readOnlyCollectionText)
        XCTAssertFalse(m.delete(Self.family))
        XCTAssertEqual(store.commits, 0)
        XCTAssertEqual(CollectionCatalog.collections(in: store.snapshot).map(\.name), ["Family"])
    }

    // MARK: - unlock

    func testMigrationRunsOnceOnTheFirstUnlock() throws {
        let store = MemoryStore(snapshot([Self.noteRecord]))
        let old = "bbbbbbbb-0000-4000-8000-000000000001"
        let host = InMemoryPhoneLocal(LocalData(collections: [LocalData.Collection(id: old, name: "Trips", createdAt: 5, updatedAt: 6)],
                                                memberships: [Self.noteID: [old]]))
        var data = try XCTUnwrap(host.localData)
        XCTAssertTrue(CollectionsModel.migrate(store: store, local: &data, saveLocal: { try host.commitLocalData($0) }))
        XCTAssertEqual(CollectionCatalog.collections(in: store.snapshot).map(\.name), ["Trips"])
        XCTAssertEqual(CollectionCatalog.memberships(of: Self.noteID, in: store.snapshot), [old])
        XCTAssertTrue(data.collections.isEmpty)
        XCTAssertTrue(host.localData?.collections.isEmpty == true)
        XCTAssertTrue(host.localData?.memberships.isEmpty == true)
        let commits = store.commits

        // The next unlock finds nothing to move.
        var next = try XCTUnwrap(host.localData)
        XCTAssertFalse(CollectionsModel.migrate(store: store, local: &next, saveLocal: { try host.commitLocalData($0) }))
        XCTAssertEqual(store.commits, commits)
        XCTAssertEqual(CollectionCatalog.collections(in: store.snapshot).map(\.name), ["Trips"])
    }
}
