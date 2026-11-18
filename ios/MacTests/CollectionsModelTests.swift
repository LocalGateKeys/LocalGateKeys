import XCTest
import LGKCore
@testable import AppSharedMac

/// A clock fixed at one time.
private final class FixedNow: UnixClock, @unchecked Sendable {
    var now: Int64 = 1_792_929_600
}

/// Tags (normalised like `Normalise.normalizeTags`) and collections on the item store (sub-plan 07 task 5i): the
/// catalog, memberships, view-only collections, and the one-time move of an older Mac's local collections.
@MainActor
final class CollectionsModelTests: XCTestCase {
    private let noteID = "6f1d2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"
    private let loginID = "7a1d2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"
    private let trashedID = "8b1d2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"
    private var counter = 0
    private var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-mac-collections-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDown() async throws { try? FileManager.default.removeItem(at: dir) }

    private func nextID() -> String {
        counter += 1
        return String(format: "00000000-0000-4000-8000-%012d", counter)
    }

    private func item(_ id: String, _ kind: String) -> VaultItem {
        VaultItem(id: id, record: ["kind": .string(kind), "title": .string(id)])!
    }

    /// A store holding a note and a login.
    private func makeStore() throws -> LocalStore {
        let store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        store.limitHints = nil
        var records: [String: JSONValue] = [:]
        let note: JSONValue = .object(["id": .string(noteID), "kind": .string("note"), "title": .string("Router"),
                                       "created_at": .int(1_700_000_000), "updated_at": .int(1_700_000_001),
                                       "favorite": .bool(false), "tags": .array([]),
                                       "payload": .object(["body": .string("body"), "fields": .array([]), "template_id": .null])])
        records[noteID] = Wrapper.make(ns: .item, record: try Normalise.normalForm(ns: .item, record: note))
        records[loginID] = Wrapper.make(ns: .entry, record: .object(["id": .string(loginID), "kind": .string("web"),
                                                                     "title": .string("Bank")]))
        try store.commit(StoreChange(baseRevision: 0, records: records, meta: [:], sync: nil))
        return store
    }

    private func makeModel(_ store: any ItemStore, _ data: LocalData = LocalData()) -> (MacCollectionsModel, InMemoryLocalData) {
        let local = InMemoryLocalData(data)
        let model = MacCollectionsModel(store: store, local: local, activity: ActivityRecorder(host: local), clock: FixedNow(),
                                        newID: { [unowned self] in self.nextID() })
        model.reload()
        return (model, local)
    }

    /// Puts `itemID` in `ids` straight in the store (no checks).
    private func putIn(_ store: any ItemStore, _ itemID: String, _ ids: [String]) throws {
        let snap = try store.load()
        var records = snap.records
        records[CollectionStates.membershipPrefix + itemID] = CollectionStates.wrapper(
            CollectionStates.membership(itemID: itemID, collectionIDs: ids))
        try store.commit(StoreChange(baseRevision: snap.revision, records: records, meta: snap.meta, sync: snap.sync))
    }

    /// Another of this person's devices holds `collectionID` as a member of a view-only share (`csl:` link).
    private func makeViewOnly(_ store: any ItemStore, _ collectionID: String) throws {
        let snap = try store.load()
        var records = snap.records
        records[CollectionStates.linkPrefix + collectionID] = CollectionStates.wrapper(
            CollectionStates.link(collectionID: collectionID, mode: "read", role: "member"))
        try store.commit(StoreChange(baseRevision: snap.revision, records: records, meta: snap.meta, sync: snap.sync))
    }

    // MARK: - Existing cases, on the store

    func testTagsNormalised() throws {
        XCTAssertEqual(try MacCollectionsModel.tags(fromText: " Work, work ,home,, WORK , Home"), ["Work", "home"])
        XCTAssertEqual(try MacCollectionsModel.tags(fromText: ""), [])
        XCTAssertEqual(try MacCollectionsModel.tags(fromText: String(repeating: "t", count: 40)).count, 1)
        XCTAssertThrowsError(try MacCollectionsModel.tags(fromText: String(repeating: "t", count: 41)), "41 characters")
        XCTAssertEqual(try MacCollectionsModel.tags(fromText: (0..<20).map { "t\($0)" }.joined(separator: ",")).count, 20)
        XCTAssertThrowsError(try MacCollectionsModel.tags(fromText: (0..<21).map { "t\($0)" }.joined(separator: ",")), "21 tags")
        // Same rule as the synced store.
        XCTAssertEqual(try Normalise.tags(["A", "a", " b "]), ["A", "b"])
    }

    func testCollectionNamesUniqueCaseInsensitive() throws {
        let store = try makeStore()
        let (model, local) = makeModel(store)
        let id = try XCTUnwrap(model.create(name: "  Finance "))
        XCTAssertEqual(model.name(of: id), "Finance")
        XCTAssertNotNil(try store.load().records[CollectionStates.catalogPrefix + id], "a catalog row in the store")
        XCTAssertNil(model.create(name: "fINANCE"))
        XCTAssertEqual(model.message, EditorModel.collectionText(for: CollectionCatalog.Failure.duplicateName))
        XCTAssertNil(model.create(name: "   "))
        XCTAssertNil(model.create(name: String(repeating: "n", count: 101)))
        let other = try XCTUnwrap(model.create(name: "Bills"))
        XCTAssertFalse(model.rename(other, to: "finance"))
        XCTAssertTrue(model.rename(id, to: "FINANCE"))   // its own name in another case is fine
        XCTAssertEqual(model.name(of: id), "FINANCE")
        XCTAssertEqual(local.localData?.collections, [], "nothing goes into the local data")
        let types = local.localData?.events.map(\.eventType) ?? []
        XCTAssertEqual(types, ["collection.create", "collection.create", "collection.update"])
        XCTAssertTrue(local.localData?.events.allSatisfy { $0.itemID == nil } ?? false, "events carry no content")
    }

    func testDeleteCollectionKeepsItems() throws {
        let store = try makeStore()
        let (model, local) = makeModel(store)
        let a = try XCTUnwrap(model.create(name: "A")), b = try XCTUnwrap(model.create(name: "B"))
        XCTAssertTrue(model.setMemberships(of: noteID, kind: "note", to: [a, b]))
        XCTAssertEqual(model.count(of: a), 1)
        XCTAssertTrue(model.delete(a))
        XCTAssertNil(model.name(of: a))
        XCTAssertEqual(CollectionCatalog.memberships(of: noteID, in: try store.load()), [b], "the id is stripped, the other stays")
        XCTAssertNotNil(try store.load().records[noteID], "items are kept")
        XCTAssertEqual(local.localData?.events.last?.eventType, "collection.delete")
        XCTAssertTrue(model.delete(b))
        XCTAssertNil(try store.load().records[CollectionStates.membershipPrefix + noteID], "no collection left: no membership")
    }

    func testMembershipOnlyTypedMax20() throws {
        let store = try makeStore()
        let unknown = "11111111-2222-4333-8444-555555555555"
        try putIn(store, noteID, [unknown])   // from another device, a collection this Mac does not know
        let (model, _) = makeModel(store)
        var ids: [String] = []
        for n in 0..<20 { ids.append(try XCTUnwrap(model.create(name: "C\(n)"))) }
        XCTAssertFalse(model.setMemberships(of: loginID, kind: "web", to: [ids[0]]))
        XCTAssertEqual(model.message, EditorModel.notMemberText)
        XCTAssertEqual(CollectionCatalog.memberships(of: loginID, in: try store.load()), [])
        // The unknown id counts: 19 + 1 fits, 20 + 1 does not.
        XCTAssertTrue(model.setMemberships(of: noteID, kind: "note", to: Set(ids.prefix(19))))
        let stored = CollectionCatalog.memberships(of: noteID, in: try store.load())
        XCTAssertEqual(stored.count, 20)
        XCTAssertTrue(stored.contains(unknown), "unknown ids are preserved")
        XCTAssertFalse(model.shownMemberships(of: noteID).contains(unknown), "unknown ids are not shown")
        XCTAssertFalse(model.setMemberships(of: noteID, kind: "note", to: Set(ids)))
        XCTAssertEqual(model.message, MacCollectionsModel.tooManyText)
        // Leaving every known collection keeps only the unknown id.
        XCTAssertTrue(model.setMemberships(of: noteID, kind: "note", to: []))
        XCTAssertEqual(CollectionCatalog.memberships(of: noteID, in: try store.load()), [unknown])
    }

    func testSidebarCollectionSelection() {
        let note = item(noteID, "note"), login = item(loginID, "web")
        let c = "00000000-0000-4000-8000-000000000001"
        let filtered = SidebarModel.filter([note, login], by: .collection(c), memberships: [noteID: [c]])
        XCTAssertEqual(filtered.map(\.id), [noteID])
        let sidebar = SidebarModel(items: [note, login])
        sidebar.collections = [CollectionCatalog.Collection(id: c, name: "Bills", description: "", createdAt: 0, updatedAt: 0)]
        sidebar.memberships = [noteID: [c], loginID: [c]]
        XCTAssertEqual(sidebar.count(for: .collection(c)), 1, "logins never count")
        sidebar.selection = .collection(c)
        XCTAssertEqual(sidebar.title, "Bills")
    }

    func testEditorSavesTagsAndMemberships() throws {
        let store = try makeStore()
        let (model, _) = makeModel(store)
        let c = try XCTUnwrap(model.create(name: "Home"))
        let s = MacEditorSession(store: store, pro: ProModel(purchases: NoPurchases()), onNeedsPro: { _ in })
        s.collections = model
        XCTAssertTrue(s.startNew(.note))
        XCTAssertTrue(s.showsCollections)
        XCTAssertEqual(s.model?.collections.map(\.id).contains(c), true, "the picker lists the store's collections")
        s.model?.set("title", "Wifi notes")
        s.tagsText = "Home, home, router"
        s.chosenCollections = [c]
        XCTAssertTrue(s.isDirty)
        XCTAssertEqual(s.save(), .saved)
        let list = VaultListModel(store: store); list.reload()
        let note = try XCTUnwrap(list.items.first { $0.title == "Wifi notes" })
        XCTAssertEqual(note.tags, ["Home", "router"])
        XCTAssertEqual(CollectionCatalog.memberships(of: note.id, in: try store.load()), [c], "saved with the item")
        XCTAssertNil(note.record["collection_ids"], "memberships never go into the item's record")
        model.reload()
        XCTAssertEqual(model.memberships[note.id], [c])
        XCTAssertEqual(model.names(of: note.id), ["Home"])

        // Opening it again shows its collections; bad tags refuse the save and say why.
        s.startEdit(note)
        XCTAssertEqual(s.tagsText, "Home, router")
        XCTAssertEqual(s.chosenCollections, [c])
        XCTAssertFalse(s.isDirty)
        s.tagsText = String(repeating: "x", count: 41)
        XCTAssertEqual(s.save(), .invalid)
        XCTAssertNotNil(s.tagsError)
        s.cancel()

        // Logins and documents get tags but no collections picker.
        XCTAssertTrue(s.startNew(.web))
        XCTAssertFalse(s.showsCollections)
    }

    func testTrashKeepsMembershipsUntilPurged() throws {
        let store = try makeStore()
        let (model, local) = makeModel(store)
        let c = try XCTUnwrap(model.create(name: "Home"))
        XCTAssertTrue(model.setMemberships(of: noteID, kind: "note", to: [c]))
        let trash = TrashModel(store: store, local: local, isPro: { true }, onNeedsPro: { _ in }, activity: nil)
        // Deleted: the Recently deleted row keeps the note's collection; the store has no membership any more.
        try trash.moveToTrash(id: noteID)
        let row = try XCTUnwrap(local.localData?.trash.first)
        XCTAssertEqual(try row.record().objectValue?["collection_ids"], .array([.string(c)]))
        model.reload()
        XCTAssertNil(model.memberships[noteID])
        XCTAssertEqual(model.count(of: c), 0)
        // Restored: live again, in its collection.
        trash.restore(Set(trash.rows.map(\.id)))
        model.reload()
        XCTAssertEqual(model.shownMemberships(of: noteID), [c])
        // Deleted again and purged: gone, with its membership.
        try trash.moveToTrash(id: noteID)
        trash.purge(Set(trash.rows.map(\.id)))
        model.reload()
        XCTAssertNil(model.memberships[noteID])
        XCTAssertNil(try store.load().records[CollectionStates.membershipPrefix + noteID])
    }

    func testEditorRefusesTheWholeSaveWhenAMembershipIsRefused() throws {
        let store = try makeStore()
        let (model, _) = makeModel(store)
        var ids: [String] = []
        for n in 0..<21 { ids.append(try XCTUnwrap(model.create(name: "C\(n)"))) }
        let s = MacEditorSession(store: store, pro: ProModel(purchases: NoPurchases()), onNeedsPro: { _ in })
        s.collections = model
        XCTAssertTrue(s.startNew(.note))
        s.model?.set("title", "Router 2")
        s.chosenCollections = Set(ids)
        XCTAssertEqual(s.save(), .invalid)
        XCTAssertNotNil(s.model, "the form stays open")
        XCTAssertEqual(s.model?.error, EditorModel.collectionText(for: CollectionCatalog.Failure.tooMany))
        let list = VaultListModel(store: store); list.reload()
        XCTAssertFalse(list.items.contains { $0.title == "Router 2" }, "nothing is half saved")
        s.chosenCollections = Set(ids.prefix(2))
        XCTAssertEqual(s.save(), .saved)
        XCTAssertNil(s.model)
        list.reload()
        let saved = try XCTUnwrap(list.items.first { $0.title == "Router 2" })
        XCTAssertEqual(Set(CollectionCatalog.memberships(of: saved.id, in: try store.load())), Set(ids.prefix(2)))
    }

    // MARK: - View only (sub-plan 07; the 5f review's Mac case)

    func testViewOnlyCollectionAndItsItemsAreNeverChangedHere() throws {
        let store = try makeStore()
        let (model, local) = makeModel(store)
        let family = try XCTUnwrap(model.create(name: "Family"))
        let home = try XCTUnwrap(model.create(name: "Home"))
        XCTAssertTrue(model.setMemberships(of: noteID, kind: "note", to: [family]))
        try makeViewOnly(store, family)
        model.reload()
        let row = try XCTUnwrap(model.rows.first { $0.id == family })
        XCTAssertTrue(row.isReadOnly)
        XCTAssertTrue(row.isShared)
        XCTAssertFalse(try XCTUnwrap(model.rows.first { $0.id == home }).isReadOnly, "a local collection is not view only")
        XCTAssertTrue(model.isReadOnly(itemID: noteID))
        XCTAssertFalse(model.isReadOnly(itemID: loginID))

        // The collection: not renamed, not deleted.
        XCTAssertFalse(model.rename(family, to: "Our family"))
        XCTAssertEqual(model.message, EditorModel.readOnlyCollectionText)
        XCTAssertFalse(model.delete(family))
        XCTAssertEqual(model.name(of: family), "Family")
        // The item: not moved out (nor into another), not edited, not starred, not deleted.
        XCTAssertFalse(model.setMemberships(of: noteID, kind: "note", to: [home]))
        XCTAssertEqual(CollectionCatalog.memberships(of: noteID, in: try store.load()), [family])
        let list = VaultListModel(store: store); list.reload()
        let note = try XCTUnwrap(list.items.first { $0.id == noteID })
        let s = MacEditorSession(store: store, pro: ProModel(purchases: NoPurchases()), onNeedsPro: { _ in })
        s.collections = model
        s.startEdit(note)
        XCTAssertTrue(s.isReadOnly)
        XCTAssertEqual(s.model?.readOnlyCollections.contains(family), true, "the picker shows it locked")
        s.model?.set("title", "Changed")
        XCTAssertEqual(s.save(), .invalid)
        XCTAssertEqual(s.model?.error, EditorModel.readOnlyItemText)
        s.cancel()
        XCTAssertThrowsError(try ItemActions.setFavourite(id: noteID, true, store: store, clock: FixedNow())) {
            XCTAssertEqual("\($0)", "\(ItemActions.Failure.readOnly)")
        }
        let trash = TrashModel(store: store, local: local, isPro: { true }, onNeedsPro: { _ in }, activity: nil)
        XCTAssertThrowsError(try trash.moveToTrash(id: noteID)) { XCTAssertEqual($0 as? TrashModel.Failure, .readOnly) }
        XCTAssertNotNil(try store.load().records[noteID])
        XCTAssertEqual(local.localData?.trash.count, 0)
        // Its title is as it was.
        list.reload()
        XCTAssertEqual(list.items.first { $0.id == noteID }?.title, "Router")
    }

    // MARK: - The move of an older Mac's local collections (sub-plan 07)

    func testOldLocalCollectionsMoveIntoTheStoreWithTheirMemberships() throws {
        let store = try makeStore()
        let family = "3f2a6c1e-8b4d-4e7a-9c05-d1e2f3a4b5c6", work = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
        let trashRow = try LocalData.TrashRow(record: .object(["id": .string(trashedID), "kind": .string("note")]), deletedAt: 5)
        var data = try LocalData(trash: [trashRow], collections: [
            LocalData.Collection(id: family, name: "Family", createdAt: 1, updatedAt: 2),
            LocalData.Collection(id: work, name: "Work", createdAt: 1, updatedAt: 1, starter: true),
        ], memberships: [noteID: [family, work], trashedID: [family]]).validated()
        var saved: [LocalData] = []
        MacCollectionsModel.unlock(store: store, local: &data) { saved.append($0) }

        let snap = try store.load()
        XCTAssertEqual(CollectionCatalog.collections(in: snap).map(\.name), ["Family", "Work"])
        XCTAssertEqual(CollectionCatalog.memberships(of: noteID, in: snap), [family, work].sorted())
        XCTAssertTrue(snap.collectionsMigrated, "the done marker is in the store")
        XCTAssertEqual(data.collections, [])
        XCTAssertEqual(data.memberships, [:])
        XCTAssertEqual(data.starterCollectionIDs, [work])
        XCTAssertEqual(try data.trash[0].record().objectValue?["collection_ids"], .array([.string(family)]),
                       "a deleted item's collections ride in its Recently deleted row")
        XCTAssertEqual(saved, [data])

        // The model shows them at once.
        let (model, _) = makeModel(store, data)
        XCTAssertEqual(model.names(of: noteID), ["Family", "Work"])
        XCTAssertEqual(model.count(of: family), 1)
    }

    func testALaterLocalWriteAfterAFailedSaveDoesNotBringTheOldCollectionsBack() throws {
        let store = try makeStore()
        let family = "3f2a6c1e-8b4d-4e7a-9c05-d1e2f3a4b5c6", work = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
        let old = try LocalData(collections: [
            LocalData.Collection(id: family, name: "Family", createdAt: 1, updatedAt: 1),
            LocalData.Collection(id: work, name: "Work", createdAt: 1, updatedAt: 1),
        ], memberships: [noteID: [family]]).validated()
        struct SaveFailed: Error {}

        // Unlock: the store takes them, the local save fails; the in-memory copy is the cleared one anyway.
        var memory = old
        MacCollectionsModel.unlock(store: store, local: &memory) { _ in throw SaveFailed() }
        XCTAssertEqual(memory.collections, [])
        XCTAssertEqual(memory.memberships, [:])

        // The person deletes Work; a later local write (an activity event) saves the in-memory copy.
        let host = InMemoryLocalData(memory)
        let (model, _) = makeModel(store, memory)
        XCTAssertTrue(model.delete(work))
        ActivityRecorder(host: host).record(.sessionLock)
        XCTAssertEqual(host.localData?.collections, [], "the later write never carries the old collections")

        // The next unlock reads what that write saved: nothing comes back.
        var next = try XCTUnwrap(host.localData)
        MacCollectionsModel.unlock(store: store, local: &next) { _ in XCTFail("nothing to save") }
        XCTAssertEqual(CollectionCatalog.collections(in: try store.load()).map(\.id), [family])

        // Even an unlock from the old file (the app quit before any later write) brings nothing back: the marker.
        var stale = old
        MacCollectionsModel.unlock(store: store, local: &stale) { _ in }
        XCTAssertEqual(CollectionCatalog.collections(in: try store.load()).map(\.id), [family])
        XCTAssertEqual(stale.collections, [])
    }

    /// No automatic starters (fix round 1): an unlock adds none; "Add starter collections" adds the missing ones to
    /// the store, by name, with their ids kept as starters in the local data.
    func testStartersComeOnlyFromAddStarterCollections() throws {
        let store = try makeStore()
        var data = LocalData()
        MacCollectionsModel.unlock(store: store, local: &data) { _ in XCTFail("nothing to save") }
        XCTAssertEqual(CollectionCatalog.collections(in: try store.load()), [], "an unlock adds no starters")
        let (model, local) = makeModel(store, data)
        XCTAssertTrue(model.missingStarters)
        let personal = try XCTUnwrap(model.create(name: "personal"))   // one already there by name (any case)
        XCTAssertTrue(model.addStarters())
        let snap = try store.load()
        XCTAssertEqual(CollectionCatalog.collections(in: snap).count, CollectionCatalog.starterNames.count)
        XCTAssertTrue(CollectionCatalog.collections(in: snap).contains { $0.id == personal }, "not added twice")
        let added = Set(CollectionCatalog.collections(in: snap).map(\.id)).subtracting([personal])
        XCTAssertEqual(Set(local.localData?.starterCollectionIDs ?? []), added)
        XCTAssertEqual(local.localData?.collections, [], "never in the local data")
        XCTAssertFalse(model.missingStarters)
    }

    /// Through the real unlock: an older Mac's collections in `local-data.bin` are in the store after the next unlock,
    /// and the Mac-local data no longer holds them.
    func testUnlockMovesTheLocalFilesCollections() async throws {
        let suite = "lgk-mac-collections-\(UUID().uuidString)"
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        let vault = MacVault(directory: dir.appendingPathComponent("vault", isDirectory: true), keychain: InMemoryKeychainVault(),
                             biometric: FakeBiometricKeyStore(),
                             kdfParams: MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1))
        let lock = MacLockModel(vault: vault, settings: AppSettings(defaults: UserDefaults(suiteName: suite)!),
                                events: FakeSystemEvents(), startTimer: false)
        await lock.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertEqual(lock.state, .unlocked)
        let store = try XCTUnwrap(lock.store)
        XCTAssertEqual(CollectionCatalog.collections(in: try store.load()), [], "a new vault gets no starters by itself")
        XCTAssertEqual(lock.localData?.collections, [])

        // An older build wrote collections into the local data file.
        let id = try addNote(store)
        let family = "3f2a6c1e-8b4d-4e7a-9c05-d1e2f3a4b5c6"
        var old = try XCTUnwrap(lock.localData)
        old.collections = [LocalData.Collection(id: family, name: "Family", createdAt: 1, updatedAt: 1)]
        old.memberships = [id: [family]]
        try lock.commitLocalData(old)
        lock.lock()
        await lock.unlock(password: "correct horse")
        XCTAssertEqual(lock.state, .unlocked)
        let snap = try XCTUnwrap(lock.store).load()
        XCTAssertEqual(CollectionCatalog.memberships(of: id, in: snap), [family])
        XCTAssertTrue(CollectionCatalog.collections(in: snap).contains { $0.id == family && $0.name == "Family" })
        XCTAssertEqual(lock.localData?.collections, [])
        XCTAssertEqual(lock.localData?.memberships, [:])
        lock.lock()
    }

    private func addNote(_ store: any ItemStore) throws -> String {
        let snap = try store.load()
        var records = snap.records
        let id = UUID().uuidString.lowercased()
        let r: JSONValue = .object(["id": .string(id), "kind": .string("note"), "title": .string("Old note"),
                                    "created_at": .int(1_700_000_000), "updated_at": .int(1_700_000_001),
                                    "favorite": .bool(false), "tags": .array([]),
                                    "payload": .object(["body": .string("body"), "fields": .array([]), "template_id": .null])])
        records[id] = Wrapper.make(ns: .item, record: try Normalise.normalForm(ns: .item, record: r))
        try store.commit(StoreChange(baseRevision: snap.revision, records: records, meta: snap.meta, sync: snap.sync))
        return id
    }
}
