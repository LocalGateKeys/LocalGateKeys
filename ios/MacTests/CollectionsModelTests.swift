import XCTest
import LGKCore
@testable import AppSharedMac

/// Tags (normalised like `Normalise.normalizeTags`) and Mac-local collections with memberships keyed by item id.
@MainActor
final class CollectionsModelTests: XCTestCase {
    private let noteID = "6f1d2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"
    private let loginID = "7a1d2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"
    private var counter = 0

    private func item(_ id: String, _ kind: String) -> VaultItem {
        VaultItem(id: id, record: ["kind": .string(kind), "title": .string(id)])!
    }

    private func makeModel(_ data: LocalData = LocalData()) -> (CollectionsModel, InMemoryLocalData) {
        let local = InMemoryLocalData(data)
        let model = CollectionsModel(local: local, activity: ActivityRecorder(host: local),
                                     clock: { Date(timeIntervalSince1970: 1_792_929_600) },
                                     newID: { [unowned self] in self.counter += 1; return String(format: "00000000-0000-4000-8000-%012d", self.counter) })
        model.items = [item(noteID, "note"), item(loginID, "web")]
        return (model, local)
    }

    func testTagsNormalised() throws {
        XCTAssertEqual(try CollectionsModel.tags(fromText: " Work, work ,home,, WORK , Home"), ["Work", "home"])
        XCTAssertEqual(try CollectionsModel.tags(fromText: ""), [])
        XCTAssertEqual(try CollectionsModel.tags(fromText: String(repeating: "t", count: 40)).count, 1)
        XCTAssertThrowsError(try CollectionsModel.tags(fromText: String(repeating: "t", count: 41)), "41 characters")
        XCTAssertEqual(try CollectionsModel.tags(fromText: (0..<20).map { "t\($0)" }.joined(separator: ",")).count, 20)
        XCTAssertThrowsError(try CollectionsModel.tags(fromText: (0..<21).map { "t\($0)" }.joined(separator: ",")), "21 tags")
        // Same rule as the synced store.
        XCTAssertEqual(try Normalise.tags(["A", "a", " b "]), ["A", "b"])
    }

    func testCollectionNamesUniqueCaseInsensitive() throws {
        let (model, local) = makeModel()
        let id = try model.create(name: "  Finance ")
        XCTAssertEqual(model.name(of: id), "Finance")
        XCTAssertThrowsError(try model.create(name: "fINANCE"))
        XCTAssertEqual(model.message, CollectionsModel.duplicateNameText)
        XCTAssertThrowsError(try model.create(name: "   "))
        XCTAssertThrowsError(try model.create(name: String(repeating: "n", count: 101)))
        let other = try model.create(name: "Bills")
        XCTAssertThrowsError(try model.rename(other, to: "finance"))
        try model.rename(id, to: "FINANCE")   // its own name in another case is fine
        XCTAssertEqual(model.name(of: id), "FINANCE")
        XCTAssertEqual(local.localData?.collections.first { $0.id == id }?.revision, 2)
        let types = local.localData?.events.map(\.eventType) ?? []
        XCTAssertEqual(types, ["collection.create", "collection.create", "collection.update"])
        XCTAssertTrue(local.localData?.events.allSatisfy { $0.itemID == nil } ?? false, "events carry no content")
    }

    func testDeleteCollectionKeepsItems() throws {
        let (model, local) = makeModel()
        let a = try model.create(name: "A"), b = try model.create(name: "B")
        try model.setMemberships(of: noteID, kind: "note", to: [a, b])
        XCTAssertEqual(model.count(of: a), 1)
        try model.delete(a)
        XCTAssertNil(model.name(of: a))
        XCTAssertEqual(local.localData?.memberships[noteID], [b], "the id is stripped, the other stays")
        XCTAssertEqual(model.items.count, 2, "items are kept")
        XCTAssertEqual(local.localData?.events.last?.eventType, "collection.delete")
        try model.delete(b)
        XCTAssertNil(local.localData?.memberships[noteID], "an empty membership list is dropped")
    }

    func testMembershipOnlyTypedMax20() throws {
        let unknown = "11111111-2222-4333-8444-555555555555"
        var start = LocalData()
        start.memberships[noteID] = [unknown]
        let (model, local) = makeModel(start)
        var ids: [String] = []
        for n in 0..<20 { ids.append(try model.create(name: "C\(n)")) }
        XCTAssertThrowsError(try model.setMemberships(of: loginID, kind: "web", to: [ids[0]])) {
            XCTAssertEqual($0 as? CollectionsModel.Failure, .notTyped)
        }
        XCTAssertNil(local.localData?.memberships[loginID])
        // The unknown id counts: 19 + 1 fits, 20 + 1 does not.
        try model.setMemberships(of: noteID, kind: "note", to: Set(ids.prefix(19)))
        XCTAssertEqual(local.localData?.memberships[noteID]?.count, 20)
        XCTAssertEqual(local.localData?.memberships[noteID]?.first, unknown, "unknown ids are preserved")
        XCTAssertFalse(model.shownMemberships(of: noteID).contains(unknown), "unknown ids are not shown")
        XCTAssertThrowsError(try model.setMemberships(of: noteID, kind: "note", to: Set(ids))) {
            XCTAssertEqual($0 as? CollectionsModel.Failure, .tooMany)
        }
        XCTAssertEqual(model.message, CollectionsModel.tooManyText)
        // Leaving every known collection keeps only the unknown id.
        try model.setMemberships(of: noteID, kind: "note", to: [])
        XCTAssertEqual(local.localData?.memberships[noteID], [unknown])
        // Pruning drops memberships of items that are gone.
        try model.setMemberships(of: noteID, kind: "note", to: [ids[0]])
        model.items = [item(loginID, "web")]
        model.prune()
        XCTAssertNil(local.localData?.memberships[noteID])
    }

    func testSidebarCollectionSelection() {
        let note = item(noteID, "note"), login = item(loginID, "web")
        let c = "00000000-0000-4000-8000-000000000001"
        let filtered = SidebarModel.filter([note, login], by: .collection(c), memberships: [noteID: [c]])
        XCTAssertEqual(filtered.map(\.id), [noteID])
        let sidebar = SidebarModel(items: [note, login])
        sidebar.collections = [LocalData.Collection(id: c, name: "Bills", createdAt: 0, updatedAt: 0)]
        sidebar.memberships = [noteID: [c], loginID: [c]]
        XCTAssertEqual(sidebar.count(for: .collection(c)), 1, "logins never count")
        sidebar.selection = .collection(c)
        XCTAssertEqual(sidebar.title, "Bills")
    }

    func testEditorSavesTagsAndMemberships() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-mac-tags-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        store.limitHints = nil
        let (model, local) = makeModel()
        let c = try model.create(name: "Home")
        let s = MacEditorSession(store: store, pro: ProModel(purchases: NoPurchases()), onNeedsPro: { _ in })
        s.collections = model
        XCTAssertTrue(s.startNew(.note))
        XCTAssertTrue(s.showsCollections)
        s.model?.set("title", "Wifi notes")
        s.tagsText = "Home, home, router"
        s.chosenCollections = [c]
        XCTAssertEqual(s.save(), .saved)
        let list = VaultListModel(store: store); list.reload()
        let note = try XCTUnwrap(list.items.first { $0.title == "Wifi notes" })
        XCTAssertEqual(note.tags, ["Home", "router"])
        XCTAssertEqual(local.localData?.memberships[note.id], [c])
        XCTAssertNil(note.record["collection_ids"], "memberships never go into the synced record")

        // Bad tags refuse the save and say why.
        s.startEdit(note)
        XCTAssertEqual(s.tagsText, "Home, router")
        s.tagsText = String(repeating: "x", count: 41)
        XCTAssertEqual(s.save(), .invalid)
        XCTAssertNotNil(s.tagsError)
        s.cancel()

        // Logins get tags but no collections picker.
        XCTAssertTrue(s.startNew(.web))
        XCTAssertFalse(s.showsCollections)
    }

    func testTrashKeepsMembershipsUntilPurged() throws {
        let (model, local) = makeModel()
        let c = try model.create(name: "Home")
        try model.setMemberships(of: noteID, kind: "note", to: [c])
        // Deleted: the note is in Recently deleted, not live.
        var data = try XCTUnwrap(local.localData)
        data.trash = [try .init(record: .object(["id": .string(noteID), "kind": .string("note")]), deletedAt: 1)]
        try local.commitLocalData(data)
        model.items = [item(loginID, "web")]
        model.prune()
        XCTAssertEqual(local.localData?.memberships[noteID], [c], "kept while in Recently deleted")
        // Restored: live again, memberships intact.
        data = try XCTUnwrap(local.localData); data.trash = []; try local.commitLocalData(data)
        model.items = [item(noteID, "note"), item(loginID, "web")]
        model.prune()
        XCTAssertEqual(model.shownMemberships(of: noteID), [c])
        // Deleted again and purged: gone.
        model.items = [item(loginID, "web")]
        model.prune()
        XCTAssertNil(local.localData?.memberships[noteID])
    }

    func testEditorKeepsOpenWhenMembershipsFail() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-mac-tags-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        store.limitHints = nil
        let (model, local) = makeModel()
        let c = try model.create(name: "Home")
        let s = MacEditorSession(store: store, pro: ProModel(purchases: NoPurchases()), onNeedsPro: { _ in })
        s.collections = model
        XCTAssertTrue(s.startNew(.note))
        s.model?.set("title", "Router")
        s.chosenCollections = [c]
        local.failSaves = true
        XCTAssertEqual(s.save(), .failed)
        XCTAssertNotNil(s.model, "the form stays open")
        XCTAssertEqual(s.collectionsError, MacEditorSession.membershipsFailedText)
        let id = try XCTUnwrap(s.lastSavedID, "the new item's id comes from the save")
        XCTAssertEqual(s.editingID, id)
        let list = VaultListModel(store: store); list.reload()
        XCTAssertEqual(list.items.filter { $0.title == "Router" }.count, 1, "the record is saved once")
        local.failSaves = false
        XCTAssertEqual(s.save(), .saved)
        XCTAssertNil(s.model)
        list.reload()
        XCTAssertEqual(list.items.filter { $0.title == "Router" }.count, 1, "retry does not save the item again")
        XCTAssertEqual(local.localData?.memberships[id], [c])
    }
}
