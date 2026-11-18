import XCTest
import Foundation
@testable import LGKCore

// Personal collections in the item store (sub-plan 07 Task 5c): the catalog rules Windows has (`collections.py`), the
// Mac migration checked against the desktop's `states.json`, and the shared filter that keeps every collection state
// out of the item readers that live in LGKCore (sync view, sync run, backup restore, Watch codes, CXF export).

private func o(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let x)? = v { return x }; return [:] }
private func a(_ v: JSONValue?) -> [JSONValue] { if case .array(let x)? = v { return x }; return [] }
private func s(_ v: JSONValue?) -> String { if case .string(let x)? = v { return x }; return "" }
private func canonical(_ v: JSONValue?) throws -> [UInt8] { try CanonicalJSON.encode(try XCTUnwrap(v), dialect: .utf8) }

/// Fresh canonical UUIDs, counting up.
final class CatalogTestIDs {
    var n = 0
    func next() -> String {
        n += 1
        let h = String(n, radix: 16)
        return String(repeating: "0", count: 8 - h.count) + h + "-0000-4000-8000-000000000000"
    }
}

/// A store whose commit can be made to fail.
private final class FlakyStore: ItemStore, @unchecked Sendable {
    var snapshot: StoreSnapshot
    var failCommit = false
    init(_ s: StoreSnapshot) { snapshot = s }
    func load() throws -> StoreSnapshot { snapshot }
    func commit(_ change: StoreChange) throws {
        if failCommit { throw RecordError(nil, nil, "commit failed") }
        guard change.baseRevision == snapshot.revision else { throw RecordError("vault-changed", nil, "stale") }
        snapshot = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: snapshot.revision + 1,
                                 collectionsMigrated: change.collectionsMigrated ?? snapshot.collectionsMigrated)
    }
}

private struct SaveFailed: Error {}

final class CollectionCatalogTests: XCTestCase {
    static let family = "3f2a6c1e-8b4d-4e7a-9c05-d1e2f3a4b5c6"
    static let work = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
    static let note = "11111111-1111-4111-8111-111111111111"
    static let login = "22222222-2222-4222-8222-222222222222"
    static let document = "33333333-3333-4333-8333-333333333333"
    static let gone = "44444444-4444-4444-8444-444444444444"
    static let note2 = "55555555-5555-4555-8555-555555555555"
    static let unknown = "66666666-6666-4666-8666-666666666666"
    static let now: Int64 = 1_800_000_000
    static let devA = SharedCollectionVectorTests.mergeA
    static let devB = SharedCollectionVectorTests.mergeB

    static func item(_ id: String, kind: String = "note", title: String = "Cabin", extra: [String: JSONValue] = [:]) -> JSONValue {
        var r: [String: JSONValue] = ["id": .string(id), "kind": .string(kind), "title": .string(title),
                                      "created_at": .int(1), "updated_at": .int(1)]
        for (k, v) in extra { r[k] = v }
        return Wrapper.make(ns: kind == "web" || kind == "desktop" ? .entry : .item, record: .object(r))
    }

    /// A note, a second note, a login and a document.
    static func base() -> StoreSnapshot {
        StoreSnapshot(records: [note: item(note), note2: item(note2, title: "Boat"), login: item(login, kind: "web"),
                                document: item(document, kind: "document")], revision: 7)
    }

    static func make(_ snap: inout StoreSnapshot, _ name: String, _ gen: CatalogTestIDs) throws -> String {
        let (c, id) = try CollectionCatalog.create(name: name, in: snap, now: now, newID: gen.next)
        snap.records = c.records
        return id
    }

    func expect(_ failure: CollectionCatalog.Failure, _ body: () throws -> Any?, file: StaticString = #filePath, line: UInt = #line) {
        do {
            _ = try body()
            XCTFail("expected \(failure)", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? CollectionCatalog.Failure, failure, file: file, line: line)
        }
    }

    // MARK: catalog

    func test_create_and_rename_follow_the_limits_and_casefold_uniqueness() throws {
        var snap = Self.base()
        let gen = CatalogTestIDs()
        let (made, family) = try CollectionCatalog.create(name: "  Family ", description: "Home", in: snap, now: Self.now,
                                                          newID: gen.next)
        XCTAssertEqual(made.baseRevision, 7)
        XCTAssertEqual(made.meta, snap.meta)
        snap.records = made.records
        // Exactly the desktop's catalog record (stripped name, no revision or starter flag).
        XCTAssertEqual(snap.records[CollectionStates.catalogPrefix + family],
                       CollectionStates.wrapper(CollectionStates.catalog(collectionID: family, name: "Family", description: "Home",
                                                                         createdAt: Self.now, updatedAt: Self.now)))
        expect(.duplicateName) { try CollectionCatalog.create(name: "FAMILY", in: snap, now: Self.now, newID: gen.next) }
        let street = try Self.make(&snap, "Straße", gen)
        // Python casefold: "ß" folds to "ss".
        expect(.duplicateName) { try CollectionCatalog.create(name: "STRASSE", in: snap, now: Self.now, newID: gen.next) }
        expect(.emptyName) { try CollectionCatalog.create(name: " \t ", in: snap, now: Self.now, newID: gen.next) }
        expect(.longName) { try CollectionCatalog.create(name: String(repeating: "x", count: 101), in: snap, now: Self.now, newID: gen.next) }
        expect(.invalidText) { try CollectionCatalog.create(name: "a\u{0}b", in: snap, now: Self.now, newID: gen.next) }
        expect(.invalidID) { try CollectionCatalog.create(name: "Fresh", in: snap, now: Self.now, newID: { "NOT-A-UUID" }) }
        expect(.longDescription) {
            try CollectionCatalog.create(name: "Notes", description: String(repeating: "d", count: 501), in: snap, now: Self.now,
                                         newID: gen.next)
        }
        _ = try Self.make(&snap, String(repeating: "x", count: 100), gen)
        XCTAssertEqual(CollectionCatalog.collections(in: snap).map(\.id).first, family)

        // Rename: the same name is no change; another's name (ignoring case) is refused; the time never goes back.
        XCTAssertNil(try CollectionCatalog.rename(family, to: " Family", in: snap, now: Self.now + 5))
        expect(.duplicateName) { try CollectionCatalog.rename(family, to: "strasse", in: snap, now: Self.now) }
        XCTAssertNotNil(try CollectionCatalog.rename(street, to: "STRASSE", in: snap, now: Self.now), "its own name in other case")
        let renamed = try XCTUnwrap(CollectionCatalog.rename(family, to: "Home", description: "Ours", in: snap, now: Self.now - 100))
        snap.records = renamed.records
        let row = try XCTUnwrap(CollectionCatalog.collections(in: snap).first { $0.id == family })
        XCTAssertEqual([row.name, row.description], ["Home", "Ours"])
        XCTAssertEqual(row.updatedAt, Self.now)
        expect(.notFound) { try CollectionCatalog.rename(Self.unknown, to: "X", in: snap, now: Self.now) }
    }

    func test_the_501st_collection_is_refused() throws {
        var snap = Self.base()
        let gen = CatalogTestIDs()
        for i in 0..<CollectionCatalog.maxCollections {
            let id = gen.next()
            snap.records[CollectionStates.catalogPrefix + id] = try CollectionCatalog.catalogWrapper(
                id: id, name: "C\(i)", description: "", createdAt: 1, updatedAt: 1)
        }
        expect(.limit) { try CollectionCatalog.create(name: "One more", in: snap, now: Self.now, newID: gen.next) }
        // Collections are free: no Pro check anywhere in the catalog.
    }

    func test_delete_keeps_the_items_and_clears_memberships_and_trash_rows() throws {
        var snap = Self.base()
        let gen = CatalogTestIDs()
        let family = try Self.make(&snap, "Family", gen)
        let work = try Self.make(&snap, "Work", gen)
        snap.records = try XCTUnwrap(CollectionCatalog.setMemberships(itemID: Self.note, kind: "note", to: [family, work],
                                                                      in: snap)).records
        func row(_ title: String, _ ids: [String]?, _ at: Int64) throws -> LocalData.TrashRow {
            var r: [String: JSONValue] = ["id": .string(Self.gone), "kind": .string("note"), "title": .string(title)]
            if let ids { r["collection_ids"] = .array(ids.map { .string($0) }) }
            return try LocalData.TrashRow(record: .object(r), deletedAt: at)
        }
        let rows = [try row("Old", [family], 5), try row("Older", [family, work], 6), try row("Plain", nil, 7)]

        let (change, trash) = try CollectionCatalog.delete(family, in: snap, trash: rows, protected: [])
        var after = snap
        after.records = change.records
        XCTAssertNil(after.records[CollectionStates.catalogPrefix + family])
        XCTAssertEqual(after.records[Self.note], snap.records[Self.note], "the item stays")
        XCTAssertEqual(CollectionCatalog.memberships(of: Self.note, in: after), [work])
        let kept = try XCTUnwrap(trash)
        XCTAssertNil(o(try kept[0].record())["collection_ids"])
        XCTAssertEqual(o(try kept[1].record())["collection_ids"], .array([.string(work)]))
        XCTAssertEqual(kept[2], rows[2])
        XCTAssertEqual(kept.map(\.deletedAt), [5, 6, 7])

        // The last collection of an item: its membership record goes; no trash row changes.
        let (last, untouched) = try CollectionCatalog.delete(work, in: after, trash: [rows[2]], protected: [])
        XCTAssertNil(last.records[CollectionStates.membershipPrefix + Self.note])
        XCTAssertNil(untouched)
        XCTAssertNotNil(last.records[Self.note])
        expect(.notFound) { try CollectionCatalog.delete(family, in: after, trash: [], protected: []) }
    }

    func test_a_shared_collection_is_never_deleted_whichever_device_shares_it() throws {
        var snap = Self.base()
        let gen = CatalogTestIDs()
        let own = try Self.make(&snap, "Own share", gen)
        let linked = try Self.make(&snap, "Shared from my other device", gen)
        // This device's share record (the app passes its collections as `protected`).
        expect(.shared) { try CollectionCatalog.delete(own, in: snap, trash: [], protected: [own]) }
        // Another of this person's devices shares it: only its `csl:` link is here, whatever the role or mode.
        for (role, mode) in [("owner", "edit"), ("member", "read"), ("member", "edit")] {
            var withLink = snap
            withLink.records[CollectionStates.linkPrefix + linked] =
                CollectionStates.wrapper(CollectionStates.link(collectionID: linked, mode: mode, role: role))
            expect(.shared) { try CollectionCatalog.delete(linked, in: withLink, trash: [], protected: []) }
        }
        XCTAssertNoThrow(try CollectionCatalog.delete(linked, in: snap, trash: [], protected: [own]))
    }

    func test_starters_are_added_once_by_name() throws {
        var snap = Self.base()
        let gen = CatalogTestIDs()
        _ = try Self.make(&snap, "work", gen)
        let (change, made) = try CollectionCatalog.starters(in: snap, now: Self.now, newID: gen.next)
        snap.records = try XCTUnwrap(change).records
        XCTAssertEqual(made.count, 3)
        XCTAssertEqual(CollectionCatalog.collections(in: snap).map(\.name), ["Emergency", "Personal", "Travel", "work"])
        let again = try CollectionCatalog.starters(in: snap, now: Self.now, newID: gen.next)
        XCTAssertNil(again.change)
        XCTAssertEqual(again.ids, [])
    }

    // MARK: memberships

    func test_memberships_refuse_logins_documents_unknown_ids_a_21st_and_read_only_moves() throws {
        var snap = Self.base()
        let gen = CatalogTestIDs()
        var ids: [String] = []
        for i in 0..<21 { ids.append(try Self.make(&snap, "C\(i)", gen)) }
        expect(.notMember) { try CollectionCatalog.setMemberships(itemID: Self.login, kind: "web", to: [ids[0]], in: snap) }
        expect(.notMember) { try CollectionCatalog.setMemberships(itemID: Self.document, kind: "document", to: [ids[0]], in: snap) }
        expect(.unknownCollection) { try CollectionCatalog.setMemberships(itemID: Self.note, kind: "note", to: [Self.unknown], in: snap) }
        expect(.tooMany) { try CollectionCatalog.setMemberships(itemID: Self.note, kind: "note", to: ids, in: snap) }
        expect(.notFound) { try CollectionCatalog.setMemberships(itemID: Self.gone, kind: "note", to: [ids[0]], in: snap) }
        expect(.reserved) {
            try CollectionCatalog.setMemberships(itemID: CollectionStates.membershipPrefix + Self.note, kind: "note", to: [ids[0]], in: snap)
        }

        let twenty = Array(ids.prefix(20))
        let change = try XCTUnwrap(CollectionCatalog.setMemberships(itemID: Self.note, kind: "note", to: twenty.reversed(), in: snap))
        XCTAssertEqual(change.records[CollectionStates.membershipPrefix + Self.note],
                       CollectionStates.wrapper(CollectionStates.membership(itemID: Self.note, collectionIDs: twenty)))
        XCTAssertEqual(change.records[Self.note], snap.records[Self.note], "the item record keeps its v1 shape")
        snap.records = change.records
        XCTAssertNil(try CollectionCatalog.setMemberships(itemID: Self.note, kind: "note", to: twenty, in: snap))
        XCTAssertEqual(CollectionCatalog.items(in: ids[0], snapshot: snap), [Self.note])
        XCTAssertEqual(CollectionCatalog.items(in: ids[20], snapshot: snap), [])

        // Read-only (`ShareAccess.checkWritable` with the old and the new membership): never moved out of, nor into.
        let readOnly: Set<String> = [ids[19], ids[20]]
        XCTAssertThrowsError(try CollectionCatalog.setMemberships(itemID: Self.note, kind: "note", to: Array(ids.prefix(19)),
                                                                  in: snap, readOnly: readOnly)) { XCTAssertTrue($0 is ReadOnlyCollectionError) }
        XCTAssertThrowsError(try CollectionCatalog.setMemberships(itemID: Self.note2, kind: "note", to: [ids[20]], in: snap,
                                                                  readOnly: readOnly)) { XCTAssertTrue($0 is ReadOnlyCollectionError) }
        // The same ids another device linked as read-only (`csl:` read/member) are what the app passes in.
        snap.records[CollectionStates.linkPrefix + ids[20]] =
            CollectionStates.wrapper(CollectionStates.link(collectionID: ids[20], mode: "read", role: "member"))
        snap.records[CollectionStates.linkPrefix + ids[18]] =
            CollectionStates.wrapper(CollectionStates.link(collectionID: ids[18], mode: "edit", role: "member"))
        XCTAssertEqual(CollectionCatalog.linkedReadOnlyIDs(in: snap), [ids[20]])

        // An old membership of a document (kept by the Mac migration) can be left, never grown.
        snap.records[CollectionStates.membershipPrefix + Self.document] =
            CollectionStates.wrapper(CollectionStates.membership(itemID: Self.document, collectionIDs: [ids[0], Self.unknown]))
        expect(.notMember) {
            try CollectionCatalog.setMemberships(itemID: Self.document, kind: "document", to: [ids[0], ids[1], Self.unknown], in: snap)
        }
        let left = try XCTUnwrap(CollectionCatalog.setMemberships(itemID: Self.document, kind: "document", to: [Self.unknown], in: snap))
        XCTAssertEqual(CollectionCatalog.memberships(of: Self.document, in: StoreSnapshot(records: left.records)), [Self.unknown],
                       "an id from another device is kept")
        let none = try XCTUnwrap(CollectionCatalog.setMemberships(itemID: Self.document, kind: "document", to: [], in: snap))
        XCTAssertNil(none.records[CollectionStates.membershipPrefix + Self.document])
    }

    func test_trash_keeps_the_memberships_and_a_restore_brings_back_the_ones_that_still_exist() throws {
        var snap = Self.base()
        let gen = CatalogTestIDs()
        let family = try Self.make(&snap, "Family", gen)
        let work = try Self.make(&snap, "Work", gen)
        snap.records = try XCTUnwrap(CollectionCatalog.setMemberships(itemID: Self.note, kind: "note", to: [family, work],
                                                                      in: snap)).records
        let record = o(snap.records[Self.note])["record"]!
        let trashed = CollectionCatalog.trashRecord(record, itemID: Self.note, in: snap)
        XCTAssertEqual(o(trashed)["collection_ids"], JSONValue.array([family, work].sorted().map { JSONValue.string($0) }))
        var gone = snap
        gone.records[Self.note] = nil
        gone.records = CollectionCatalog.withoutMembership(Self.note, records: gone.records)
        XCTAssertNil(gone.records[CollectionStates.membershipPrefix + Self.note])
        // Work is deleted meanwhile: the restore brings back Family only, and the stored record has no collection_ids.
        gone.records = try CollectionCatalog.delete(work, in: gone, trash: [], protected: []).change.records
        let back = CollectionCatalog.restored(o(trashed), itemID: Self.note, records: gone.records)
        XCTAssertEqual(.object(back.record), record)
        XCTAssertEqual(CollectionCatalog.memberships(of: Self.note, in: StoreSnapshot(records: back.records)), [family])
        // A trash record without collections changes nothing.
        XCTAssertEqual(CollectionCatalog.trashRecord(record, itemID: Self.note2, in: snap), record)
    }

    func test_a_full_restore_keeps_the_catalog_and_the_memberships_of_restored_items() throws {
        var current = Self.base()
        let gen = CatalogTestIDs()
        let family = try Self.make(&current, "Family", gen)
        current.records = try XCTUnwrap(CollectionCatalog.setMemberships(itemID: Self.note, kind: "note", to: [family], in: current)).records
        current.records = try XCTUnwrap(CollectionCatalog.setMemberships(itemID: Self.note2, kind: "note", to: [family], in: current)).records
        // The backup brings back the first note only, plus a planted record under a reserved id.
        let restored: [String: JSONValue] = [Self.note: Self.item(Self.note), "col:planted": Self.item(Self.note2)]
        let out = CollectionCatalog.carriedOver(from: current.records, into: restored)
        XCTAssertEqual(Set(out.keys), [Self.note, CollectionStates.catalogPrefix + family, CollectionStates.membershipPrefix + Self.note])
        // A safety copy (a whole store) keeps its own states over the current ones.
        var copy = current.records
        copy[CollectionStates.catalogPrefix + family] = try CollectionCatalog.catalogWrapper(
            id: family, name: "Before", description: "", createdAt: 1, updatedAt: 1)
        // A collection made after the copy does not come back with it; a share link held now does.
        var now = current
        _ = try Self.make(&now, "Later", gen)
        now.records[CollectionStates.linkPrefix + family] =
            CollectionStates.wrapper(CollectionStates.link(collectionID: family, mode: "edit", role: "owner"))
        let undone = CollectionCatalog.carriedOver(from: now.records, into: copy)
        XCTAssertEqual(CollectionCatalog.collections(in: StoreSnapshot(records: undone)).map(\.name), ["Before"])
        XCTAssertNotNil(undone[CollectionStates.linkPrefix + family])
    }

    // MARK: Mac migration

    func test_migrating_mac_collections_gives_the_desktops_states() throws {
        let doc = o(try CanonicalJSON.parse(Array(try Data(contentsOf: Vectors.shareCollections("states.json")))))
        var valid: [String: [String: JSONValue]] = [:]
        for v in a(doc["valid"]) { valid[s(o(v)["id"])] = o(v) }
        let local = LocalData(collections: [
            LocalData.Collection(id: Self.family, name: "Family", description: "Shared at home", createdAt: 1_799_999_100,
                                 updatedAt: 1_799_999_200, revision: 4),
            LocalData.Collection(id: Self.work, name: "Work", createdAt: 1_799_999_000, updatedAt: 1_799_999_000, starter: true),
        ], memberships: [Self.note: [Self.work, Self.family]])
        let snap = StoreSnapshot(records: [Self.note: Self.item(Self.note)], revision: 3)
        let m = try XCTUnwrap(try CollectionCatalog.migrate(from: try local.validated(), into: snap))
        let change = try XCTUnwrap(m.change)
        XCTAssertEqual(change.baseRevision, 3)
        for id in [CollectionStates.catalogPrefix + Self.family, CollectionStates.membershipPrefix + Self.note] {
            let v = try XCTUnwrap(valid[id], id)
            XCTAssertEqual(try canonical(change.records[id]), try canonical(v["wrapper"]), id)
            XCTAssertEqual(try SyncMeta.digest(try XCTUnwrap(change.records[id])), s(v["digest"]), id)
        }
        // The other row as Python's `local_view` builds it: never `revision` or `starter`.
        XCTAssertEqual(change.records[CollectionStates.catalogPrefix + Self.work],
                       CollectionStates.wrapper(CollectionStates.catalog(collectionID: Self.work, name: "Work", description: "",
                                                                         createdAt: 1_799_999_000, updatedAt: 1_799_999_000)))
        for (id, w) in change.records where CollectionStates.isStateID(id) {
            let state = try ItemState(itemID: id, vv: [Self.devA: 1], deleted: false, deletedAt: nil, item: w)
            XCTAssertNoThrow(try CollectionStates.unwrap(state, isCopy: false), id)
        }
        XCTAssertEqual(change.records[Self.note], snap.records[Self.note])
        XCTAssertEqual(m.local.collections, [])
        XCTAssertEqual(m.local.memberships, [:])
        XCTAssertEqual(m.local.starterCollectionIDs, [Self.work])
        XCTAssertEqual([m.collections, m.renamed, m.memberships, m.trashMemberships, m.dropped], [2, 0, 1, 0, 0])
        XCTAssertNoThrow(try m.local.validated())
    }

    func test_migration_moves_deleted_items_into_their_trash_rows_renames_clashes_and_drops_only_what_cannot_exist() throws {
        let other = "77777777-7777-4777-8777-777777777777"
        var store = Self.base()
        store.records[CollectionStates.catalogPrefix + other] = try CollectionCatalog.catalogWrapper(
            id: other, name: "family", description: "", createdAt: 1, updatedAt: 1)
        let trashRow = try LocalData.TrashRow(record: .object(["id": .string(Self.gone), "kind": .string("note"),
                                                               "title": .string("Old")]), deletedAt: 9)
        let goneLogin = "88888888-8888-4888-8888-888888888888"
        let loginRow = try LocalData.TrashRow(record: .object(["id": .string(goneLogin), "kind": .string("web"),
                                                               "label": .string("Old login")]), deletedAt: 10)
        let blank = "99999999-9999-4999-8999-999999999999"
        let local = LocalData(trash: [trashRow, loginRow], collections: [
            LocalData.Collection(id: Self.family, name: "Family", createdAt: 1, updatedAt: 2),
            // Checked non-empty before stripping by the old Mac: it gets a plain name instead of stopping the migration.
            LocalData.Collection(id: blank, name: "\u{3000}", createdAt: 1, updatedAt: 2),
        ], memberships: [Self.note: [Self.family], Self.gone: [Self.family], Self.login: [Self.family],
                         Self.unknown: [Self.family], Self.document: [Self.family], goneLogin: [Self.family]])
        let m = try XCTUnwrap(try CollectionCatalog.migrate(from: try local.validated(), into: store))
        let records = try XCTUnwrap(m.change).records
        let names = CollectionCatalog.collections(in: StoreSnapshot(records: records)).map(\.name)
        XCTAssertEqual(names, ["Collection", "family", "Family (2)"])
        XCTAssertEqual(m.renamed, 2)
        // The note and the document (lossless: an old membership is kept, never grown) go to the store.
        XCTAssertEqual(CollectionCatalog.memberships(of: Self.note, in: StoreSnapshot(records: records)), [Self.family])
        XCTAssertEqual(CollectionCatalog.memberships(of: Self.document, in: StoreSnapshot(records: records)), [Self.family])
        // The deleted note keeps its collection in its Recently deleted row.
        XCTAssertEqual(o(try m.local.trash[0].record())["collection_ids"], .array([.string(Self.family)]))
        XCTAssertEqual(m.local.trash[0].deletedAt, 9)
        // A login never had collections and an item that is nowhere has nothing to keep.
        XCTAssertNil(records[CollectionStates.membershipPrefix + Self.login])
        XCTAssertNil(records[CollectionStates.membershipPrefix + Self.unknown])
        // A deleted login's row never gets collections, and a restore of such a row makes no membership.
        XCTAssertNil(o(try m.local.trash[1].record())["collection_ids"])
        let loginBack = CollectionCatalog.restored(["id": .string(goneLogin), "kind": .string("web"),
                                                    "collection_ids": .array([.string(Self.family)])],
                                                   itemID: goneLogin, records: records)
        XCTAssertNil(loginBack.records[CollectionStates.membershipPrefix + goneLogin])
        XCTAssertNil(loginBack.record["collection_ids"])
        XCTAssertEqual([m.memberships, m.trashMemberships, m.dropped], [2, 1, 3])
    }

    func test_migration_runs_once_and_survives_a_failure_midway() throws {
        let old = try LocalData(collections: [
            LocalData.Collection(id: Self.family, name: "Family", createdAt: 1, updatedAt: 1),
            LocalData.Collection(id: Self.work, name: "Work", createdAt: 1, updatedAt: 1, starter: true),
        ], memberships: [Self.note: [Self.family]]).validated()
        let store = FlakyStore(StoreSnapshot(records: [Self.note: Self.item(Self.note)], revision: 1))
        let before = store.snapshot
        var saved: LocalData?

        // 1. The store commit fails: nothing changed, the in-memory and the saved copy keep the old collections.
        var memory = old
        store.failCommit = true
        do { try CollectionMigration.run(store: store, local: &memory) { saved = $0 }; XCTFail("must throw") } catch {}
        XCTAssertNil(saved)
        XCTAssertEqual(memory, old)
        XCTAssertEqual(store.snapshot, before)

        // 2. The store commit works, the local save fails: the store holds the states, and the in-memory copy is
        //    already the cleared one (the saved file still has the old copy).
        store.failCommit = false
        do { try CollectionMigration.run(store: store, local: &memory) { _ in throw SaveFailed() }; XCTFail("must throw") } catch {
            XCTAssertTrue(error is SaveFailed)
        }
        let migrated = store.snapshot
        XCTAssertEqual(CollectionCatalog.collections(in: migrated).map(\.id), [Self.family, Self.work])
        XCTAssertEqual(CollectionCatalog.memberships(of: Self.note, in: migrated), [Self.family])
        XCTAssertEqual(memory.collections, [])
        XCTAssertEqual(memory.memberships, [:])
        XCTAssertEqual(memory.starterCollectionIDs, [Self.work])

        // 3. The person then deletes Work and takes the note out of Family, and a later local write (a trash row, an
        //    event) saves the in-memory copy: the old collections are not written back, so nothing comes back.
        var edited = store.snapshot
        edited.records = try CollectionCatalog.delete(Self.work, in: edited, trash: [], protected: []).change.records
        edited.records = try XCTUnwrap(CollectionCatalog.setMemberships(itemID: Self.note, kind: "note", to: [], in: edited)).records
        try store.commit(StoreChange(baseRevision: edited.revision, records: edited.records, meta: edited.meta, sync: edited.sync))
        let afterEdits = store.snapshot
        memory.events.append(LocalData.ActivityEvent(id: Self.unknown, eventType: "item.view", timestamp: 5))
        var reloaded = memory   // what that write saved, read again at the next unlock
        let rerun = try CollectionMigration.run(store: store, local: &reloaded) { _ in XCTFail("nothing to save") }
        XCTAssertNil(rerun)
        XCTAssertEqual(store.snapshot, afterEdits)
        XCTAssertEqual(CollectionCatalog.collections(in: store.snapshot).map(\.id), [Self.family])
        XCTAssertEqual(CollectionCatalog.memberships(of: Self.note, in: store.snapshot), [])
    }

    func test_the_done_marker_stops_a_rerun_from_an_old_local_file_bringing_collections_back() throws {
        let old = try LocalData(collections: [
            LocalData.Collection(id: Self.family, name: "Family", createdAt: 1, updatedAt: 1),
            LocalData.Collection(id: Self.work, name: "Work", createdAt: 1, updatedAt: 1, starter: true),
        ], memberships: [Self.note: [Self.family]]).validated()
        let store = FlakyStore(StoreSnapshot(records: [Self.note: Self.item(Self.note)], revision: 1))

        // Nothing to move: no commit, no marker.
        var empty = LocalData()
        let none = try CollectionMigration.run(store: store, local: &empty) { _ in XCTFail("nothing to save") }
        XCTAssertNil(none)
        XCTAssertEqual(store.snapshot.revision, 1)
        XCTAssertFalse(store.snapshot.collectionsMigrated)

        // The move commits the states and the marker together; the local save fails (the file keeps the old copy).
        var memory = old
        do { try CollectionMigration.run(store: store, local: &memory) { _ in throw SaveFailed() }; XCTFail("must throw") } catch {}
        XCTAssertTrue(store.snapshot.collectionsMigrated)
        XCTAssertEqual(CollectionCatalog.collections(in: store.snapshot).map(\.id), [Self.family, Self.work])

        // Work is deleted and the note leaves Family; then the app quits before any local write.
        var edited = store.snapshot
        edited.records = try CollectionCatalog.delete(Self.work, in: edited, trash: [], protected: []).change.records
        edited.records = try XCTUnwrap(CollectionCatalog.setMemberships(itemID: Self.note, kind: "note", to: [], in: edited)).records
        try store.commit(StoreChange(baseRevision: edited.revision, records: edited.records, meta: edited.meta, sync: edited.sync))
        let afterEdits = store.snapshot
        XCTAssertTrue(afterEdits.collectionsMigrated, "other commits keep the marker")

        // The next unlock reads the old file again: the store is left alone and only the local copy is cleared.
        var reread = old
        var saved: LocalData?
        let again = try CollectionMigration.run(store: store, local: &reread) { saved = $0 }
        XCTAssertNil(again)
        XCTAssertEqual(store.snapshot, afterEdits)
        XCTAssertEqual(CollectionCatalog.collections(in: store.snapshot).map(\.id), [Self.family])
        XCTAssertEqual(CollectionCatalog.memberships(of: Self.note, in: store.snapshot), [])
        XCTAssertEqual(reread.collections, [])
        XCTAssertEqual(reread.memberships, [:])
        XCTAssertEqual(saved, reread)
    }

    func test_local_data_keeps_starter_ids_and_reads_older_files() throws {
        let older = Data(#"{"trash":[],"events":[],"reminders":[],"collections":[],"preferences":{"trash_retention_days":30,"trash_auto_purge":true,"reminder_default_lead_days":0}}"#.utf8)
        let decoded = try JSONDecoder().decode(LocalData.self, from: older)
        XCTAssertEqual(decoded.starterCollectionIDs, [])
        var d = LocalData(starterCollectionIDs: [Self.work.uppercased(), Self.work])
        d = try d.validated()
        XCTAssertEqual(d.starterCollectionIDs, [Self.work])
        let round = try JSONDecoder().decode(LocalData.self, from: try JSONEncoder().encode(d))
        XCTAssertEqual(round, d)
        XCTAssertThrowsError(try LocalData(starterCollectionIDs: ["not-a-uuid"]).validated())
    }

    // MARK: readers in LGKCore

    /// A note with a code, a login, the three collection states, and a planted login-shaped record under a reserved id
    /// (only the shared filter keeps it out).
    static func planted() throws -> StoreSnapshot {
        var snap = base()
        let totp: JSONValue = .object(["secret": .string("JBSWY3DPEHPK3PXP"), "algorithm": .string("SHA1"),
                                       "digits": .int(6), "period": .int(30)])
        snap.records[note] = item(note, extra: ["totp": totp])
        snap.records[CollectionStates.catalogPrefix + family] = try CollectionCatalog.catalogWrapper(
            id: family, name: "Family", description: "", createdAt: 1, updatedAt: 1)
        snap.records[CollectionStates.membershipPrefix + note] =
            CollectionStates.wrapper(CollectionStates.membership(itemID: note, collectionIDs: [family]))
        snap.records[CollectionStates.linkPrefix + family] =
            CollectionStates.wrapper(CollectionStates.link(collectionID: family, mode: "read", role: "member"))
        snap.records["col:planted"] = Wrapper.make(ns: .entry, record: .object([
            "id": .string("col:planted"), "kind": .string("web"), "label": .string("Planted"), "totp": totp,
            "scope": .object(["origin": .string("https://example.com")]), "updated_at": .int(1)]))
        return snap
    }

    func test_item_records_leave_every_collection_state_out() throws {
        let snap = try Self.planted()
        XCTAssertEqual(Set(snap.itemRecords.keys), [Self.note, Self.note2, Self.login, Self.document])
        XCTAssertTrue(CollectionStates.isReserved("x", CollectionStates.wrapper(
            CollectionStates.link(collectionID: Self.family, mode: "read", role: "member"))), "a collection wrapper anywhere")
    }

    func test_the_sync_view_never_publishes_or_tombstones_collection_states() throws {
        var snap = try Self.planted()
        let published = try SyncMeta.live(try XCTUnwrap(snap.records[CollectionStates.catalogPrefix + Self.family]), vv: [Self.devB: 2])
        snap.meta[CollectionStates.catalogPrefix + Self.family] = published
        snap.meta[CollectionStates.membershipPrefix + Self.gone] = published   // its record is gone: still no tombstone
        let view = try SyncMeta.localView(records: snap.records, meta: snap.meta, device: Self.devA, now: Self.now)
        XCTAssertEqual(Set(view.states.keys), [Self.note, Self.note2, Self.login, Self.document])
        XCTAssertEqual(view.meta[CollectionStates.catalogPrefix + Self.family], published)
        XCTAssertEqual(view.meta[CollectionStates.membershipPrefix + Self.gone], published)
        XCTAssertNil(view.meta["col:planted"])
    }

    func test_a_sync_run_strips_the_peers_collection_states() throws {
        let snap = try Self.planted()
        let wrapper = CollectionStates.wrapper(CollectionStates.membership(itemID: Self.note2, collectionIDs: [Self.family]))
        let peer = PeerView(deviceID: Self.devB, states: [
            try ItemState(itemID: CollectionStates.catalogPrefix + Self.family, vv: [Self.devB: 5], deleted: true,
                          deletedAt: Self.now - 10, item: nil),
            try ItemState(itemID: CollectionStates.membershipPrefix + Self.note2, vv: [Self.devB: 5], deleted: false,
                          deletedAt: nil, item: wrapper),
        ])
        let report = SyncRunner.run(store: snap, views: [peer], device: Self.devA, now: Self.now)
        XCTAssertEqual(report.issues, [])
        let records = try XCTUnwrap(report.records)
        XCTAssertEqual(records[CollectionStates.catalogPrefix + Self.family], snap.records[CollectionStates.catalogPrefix + Self.family])
        XCTAssertNil(records[CollectionStates.membershipPrefix + Self.note2])
        XCTAssertFalse((report.ownStates ?? []).contains { CollectionStates.isStateID($0.itemID) })
    }

    func test_a_backup_restore_never_reads_collection_states() throws {
        let snap = try Self.planted()
        let backup = BackupPayload(createdAt: Self.now, platform: "ios", appVersion: "1.0.0", deviceID: Self.devB, proHint: false,
                                   states: [BackupState(id: CollectionStates.catalogPrefix + Self.family, deleted: true,
                                                        deletedAt: Self.now - 10, item: nil, vv: [Self.devB: 9])])
        let plan = try PhoneBackup.restoreStates(backup, into: snap, device: Self.devA, now: Self.now)
        XCTAssertEqual(plan.records[CollectionStates.catalogPrefix + Self.family], snap.records[CollectionStates.catalogPrefix + Self.family])
        XCTAssertEqual(plan.deleted, 0)
        XCTAssertEqual(plan.skipped, 1)
    }

    func test_watch_codes_and_cxf_export_skip_collection_states() throws {
        let snap = try Self.planted()
        XCTAssertEqual(WatchPins.codes(pins: ["col:planted", Self.note], snapshot: snap).map(\.id), [Self.note])
        let plan = try CXFExport.plan(snapshot: snap, ids: ["col:planted", CollectionStates.catalogPrefix + Self.family])
        XCTAssertTrue(plan.entries.isEmpty)
    }

    /// Starters are stored in English and only translated on screen; other names are shown as typed.
    func testDisplayNameTranslatesOnlyStarters() {
        for name in CollectionCatalog.starterNames { XCTAssertFalse(CollectionCatalog.displayName(name).isEmpty) }
        XCTAssertEqual(CollectionCatalog.displayName("Family"), "Family")
        XCTAssertEqual(CollectionCatalog.displayName("personal"), "personal")
    }
}
