import XCTest
import Foundation
@testable import LGKCore

// Personal collection sync (sub-plan 07 Task 5d), the Swift ports of the desktop's
// `tests/test_vault_bridge_collections.py` and `tests/test_collections_sync_e2e.py`: catalog rows, memberships and share
// links travel as `col:`/`cm:`/`csl:` states only between devices that read them (a folder member's signed `.lgkcol`, a
// Wi-Fi peer's `features` answer); item records keep their v1 shape, so an older peer gets exactly today's view and
// never loses anything. Byte checks against `tests/vectors/share/collections/states.json`.

private func o(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let x)? = v { return x }; return [:] }
private func a(_ v: JSONValue?) -> [JSONValue] { if case .array(let x)? = v { return x }; return [] }
private func s(_ v: JSONValue?) -> String { if case .string(let x)? = v { return x }; return "" }
private func canonical(_ v: JSONValue?) throws -> [UInt8] { try CanonicalJSON.encode(try XCTUnwrap(v), dialect: .utf8) }

/// One of a person's devices, in memory: its store, its personal-group device id and its share records.
private final class Dev {
    let id: String
    var snap = StoreSnapshot()
    var shares = CollectionShares.none
    init(_ id: String) { self.id = id }
}

final class CollectionSyncTests: XCTestCase {
    static let now: Int64 = 1_800_000_000
    static let family = "3f2a6c1e-8b4d-4e7a-9c05-d1e2f3a4b5c6"
    static let work = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
    static let other = "0000000b-0000-4000-8000-000000000000"
    static let low = "0000000a-0000-4000-8000-000000000000"
    static let n1 = "11111111-1111-4111-8111-111111111111"
    static let n2 = "55555555-5555-4555-8555-555555555555"
    static let personal = "77777777-7777-4777-8777-777777777777"
    static let cat = CollectionStates.catalogPrefix
    static let mem = CollectionStates.membershipPrefix
    static let lnk = CollectionStates.linkPrefix

    // MARK: helpers

    func create(_ snap: inout StoreSnapshot, _ id: String, _ name: String, description: String = "") throws {
        snap.records = try CollectionCatalog.create(name: name, description: description, in: snap, now: Self.now,
                                                    newID: { id }).change.records
    }

    func note(_ snap: inout StoreSnapshot, _ id: String, _ title: String, in collections: [String] = [], at: Int64 = 1) throws {
        snap.records[id] = CollectionCatalogTests.item(id, title: title, extra: ["updated_at": .int(at)])
        if !collections.isEmpty { try member(&snap, id, collections) }
    }

    func member(_ snap: inout StoreSnapshot, _ item: String, _ ids: [String]) throws {
        if let change = try CollectionCatalog.setMemberships(itemID: item, kind: "note", to: ids, in: snap) {
            snap.records = change.records
        }
    }

    func edit(_ snap: inout StoreSnapshot, _ item: String, title: String, at: Int64) {
        snap.records[item] = CollectionCatalogTests.item(item, title: title, extra: ["updated_at": .int(at)])
    }

    func title(_ snap: StoreSnapshot, _ item: String) -> String? {
        guard case .string(let t)? = o(o(snap.records[item])["record"])["title"] else { return nil }
        return t
    }

    func names(_ snap: StoreSnapshot) -> [String: String] {
        Dictionary(uniqueKeysWithValues: CollectionCatalog.collections(in: snap).map { ($0.id, $0.name) })
    }

    func membership(_ snap: StoreSnapshot, _ item: String) -> [String] { CollectionCatalog.memberships(of: item, in: snap) }

    /// Conflict copies stored as items (a collection state is never one).
    func copies(_ snap: StoreSnapshot) -> [String] {
        snap.itemRecords.keys.filter { (title(snap, $0) ?? "").hasSuffix(ConflictSuffix.suffix) }.sorted()
    }

    func stateIDs(_ ids: some Sequence<String>) -> Set<String> { Set(ids.filter(CollectionStates.isStateID)) }

    /// `dev`'s published view; its meta is kept, as a run's commit keeps it.
    @discardableResult
    fileprivate func view(_ dev: Dev, collections: Bool = true) throws -> [String: ItemState] {
        let v = try SyncMeta.localView(records: dev.snap.records, meta: dev.snap.meta, device: dev.id, now: Self.now,
                                       collections: collections, shares: dev.shares)
        dev.snap.meta = v.meta
        return v.states
    }

    @discardableResult
    fileprivate func run(_ dst: Dev, _ peer: PeerView, collections: Bool = true) -> RunReport {
        let report = SyncRunner.run(store: dst.snap, views: [peer], device: dst.id, now: Self.now, collections: collections,
                                    shares: dst.shares)
        if let records = report.records { dst.snap.records = records }
        if let meta = report.meta { dst.snap.meta = meta }
        return report
    }

    /// `dst` merges `src`'s personal view (one transport run with one peer).
    @discardableResult
    fileprivate func pull(_ dst: Dev, _ src: Dev, collections: Bool = true, srcCollections: Bool? = nil) throws -> RunReport {
        let theirs = try view(src, collections: srcCollections ?? collections)
        return run(dst, PeerView(deviceID: src.id, states: theirs.values.sorted { $0.itemID < $1.itemID }),
                   collections: collections)
    }

    fileprivate func sync(_ a: Dev, _ b: Dev, rounds: Int = 2, collections: Bool = true) throws {
        for _ in 0..<rounds {
            try pull(b, a, collections: collections)
            try pull(a, b, collections: collections)
        }
    }

    // MARK: between two devices of this version

    func test_collections_and_membership_sync_between_new_devices_and_settle() throws {
        let a = Dev("dev-a"), b = Dev("dev-b")
        try create(&a.snap, Self.family, "Family", description: "the house")
        try note(&a.snap, Self.n1, "Wi-Fi", in: [Self.family])
        try note(&a.snap, Self.n2, "Plain")
        XCTAssertEqual(try pull(b, a).issues, [])
        XCTAssertEqual(names(b.snap), [Self.family: "Family"])
        XCTAssertEqual(CollectionCatalog.collections(in: b.snap).first?.description, "the house")
        XCTAssertEqual(membership(b.snap, Self.n1), [Self.family])
        XCTAssertEqual(membership(b.snap, Self.n2), [])

        // B moves it from Family into a new Work collection; A follows.
        try create(&b.snap, Self.work, "Work")
        try member(&b.snap, Self.n1, [Self.work])
        XCTAssertEqual(try pull(a, b).issues, [])
        XCTAssertEqual(names(a.snap), [Self.family: "Family", Self.work: "Work"])
        XCTAssertEqual(membership(a.snap, Self.n1), [Self.work])
        // Settled: another round changes nothing on either side.
        try sync(a, b)
        let before = (try view(a), try view(b))
        try sync(a, b)
        XCTAssertEqual(try view(a), before.0)
        XCTAssertEqual(try view(b), before.1)
        XCTAssertEqual(stateIDs(before.0.keys), [Self.cat + Self.family, Self.cat + Self.work, Self.mem + Self.n1])
    }

    func test_items_without_collections_sync_exactly_as_before() throws {
        let a = Dev("dev-a")
        try create(&a.snap, Self.family, "Family")
        try note(&a.snap, Self.n1, "Tagged", in: [Self.family])
        try note(&a.snap, Self.n2, "Plain")
        let old = try SyncMeta.localView(records: a.snap.records, meta: a.snap.meta, device: a.id, now: Self.now).states
        let new = try SyncMeta.localView(records: a.snap.records, meta: a.snap.meta, device: a.id, now: Self.now,
                                         collections: true).states
        XCTAssertEqual(stateIDs(old.keys), [], "no collection state leaves for a peer that does not read them")
        XCTAssertEqual(new.filter { !CollectionStates.isStateID($0.key) }, old)
        for id in [Self.n1, Self.n2] {
            XCTAssertEqual(try canonical(new[id]?.item), try canonical(old[id]?.item), "byte for byte")
            XCTAssertEqual(Set(o(old[id]?.item).keys), ["ns", "schema", "updated_at", "record"])
            XCTAssertNil(o(o(old[id]?.item)["record"])["collection_ids"], "item records keep the v1 shape")
        }
        XCTAssertEqual(stateIDs(new.keys), [Self.cat + Self.family, Self.mem + Self.n1])
        XCTAssertTrue(new.values.filter { CollectionStates.isStateID($0.itemID) }
            .allSatisfy { o($0.item)["ns"] == .string(CollectionStates.namespace) })
    }

    func test_two_devices_change_one_membership_at_once_and_both_stay() throws {
        let a = Dev("dev-a"), b = Dev("dev-b")
        try create(&a.snap, Self.family, "X")
        try create(&a.snap, Self.work, "Y")
        try note(&a.snap, Self.n1, "Shared note")
        try sync(a, b)
        try member(&a.snap, Self.n1, [Self.family])
        try member(&b.snap, Self.n1, [Self.work])
        edit(&b.snap, Self.n1, title: "Renamed on B", at: 5)
        let report = try pull(b, a)
        XCTAssertEqual(report.issues, [])
        XCTAssertEqual(report.conflicts, 0, "a membership change is never a conflict the person sees")
        try sync(a, b, rounds: 3)
        for dev in [a, b] {
            XCTAssertEqual(membership(dev.snap, Self.n1), [Self.family, Self.work].sorted())
            XCTAssertEqual(title(dev.snap, Self.n1), "Renamed on B")
            XCTAssertEqual(copies(dev.snap), [], "a membership change never makes a conflict copy")
            XCTAssertEqual(Set(dev.snap.records.keys), [Self.n1, Self.cat + Self.family, Self.cat + Self.work, Self.mem + Self.n1],
                           "the engine's copy of a membership is never stored")
        }
    }

    func test_same_name_collections_made_on_two_devices_converge() throws {
        let a = Dev("dev-a"), b = Dev("dev-b")
        try create(&a.snap, Self.low, "Family")
        try create(&b.snap, Self.other, "family")
        try sync(a, b, rounds: 3)
        XCTAssertEqual(names(a.snap), names(b.snap))
        XCTAssertEqual(names(a.snap), [Self.low: "Family", Self.other: "family (2)"], "the larger id gets the number")
        // updated_at is untouched by the rename.
        XCTAssertEqual(CollectionCatalog.collections(in: a.snap).map(\.updatedAt), [Self.now, Self.now])
        let before = (try view(a), try view(b))
        try sync(a, b)
        XCTAssertEqual(try view(a), before.0)
        XCTAssertEqual(try view(b), before.1)
    }

    func test_deleting_a_collection_syncs_and_its_items_stay() throws {
        let a = Dev("dev-a"), b = Dev("dev-b")
        try create(&a.snap, Self.family, "Family")
        try note(&a.snap, Self.n1, "Kept", in: [Self.family])
        try sync(a, b)
        b.snap.records = try CollectionCatalog.delete(Self.family, in: b.snap, trash: [], protected: []).change.records
        try sync(a, b)
        for dev in [a, b] {
            XCTAssertEqual(names(dev.snap), [:])
            XCTAssertEqual(membership(dev.snap, Self.n1), [])
            XCTAssertNotNil(dev.snap.records[Self.n1])
            XCTAssertEqual(dev.snap.meta[Self.cat + Self.family]?.deleted, true)
        }
    }

    func test_a_removed_item_takes_its_membership_record_with_it() throws {
        let a = Dev("dev-a"), b = Dev("dev-b")
        try create(&a.snap, Self.family, "Family")
        try note(&a.snap, Self.n1, "Gone soon", in: [Self.family])
        try sync(a, b)
        a.snap.records[Self.n1] = nil   // the person deleted it (the trash row keeps its collections)
        a.snap.records[Self.mem + Self.n1] = nil
        try sync(a, b)
        for dev in [a, b] {
            XCTAssertNil(dev.snap.records[Self.n1])
            XCTAssertNil(dev.snap.records[Self.mem + Self.n1])
            XCTAssertEqual(dev.snap.meta[Self.mem + Self.n1]?.deleted, true)
            XCTAssertEqual(names(dev.snap), [Self.family: "Family"])
        }
    }

    // MARK: with an older peer (a v1 view: no collection states, records without collection_ids)

    func test_an_older_peer_edits_an_item_and_the_new_devices_keep_its_collections() throws {
        let a = Dev("dev-a"), b = Dev("dev-b"), old = Dev("dev-old")
        try create(&a.snap, Self.family, "Family")
        try note(&a.snap, Self.n1, "Door code", in: [Self.family])
        try sync(a, b)
        try sync(a, old, collections: false)   // the older peer only ever runs without collections
        XCTAssertEqual(membership(old.snap, Self.n1), [], "the older peer gets the item, not the membership")
        XCTAssertEqual(stateIDs(old.snap.records.keys), [])
        edit(&old.snap, Self.n1, title: "Door code (new)", at: 5)
        let report = try pull(a, old, collections: true, srcCollections: false)   // a v1 view in a collections run
        XCTAssertEqual(report.issues, [])
        XCTAssertEqual(report.conflicts, 0)
        XCTAssertEqual(title(a.snap, Self.n1), "Door code (new)")
        XCTAssertEqual(membership(a.snap, Self.n1), [Self.family], "the older peer's edit keeps the newer device's collections")
        try pull(b, a)
        XCTAssertEqual(title(b.snap, Self.n1), "Door code (new)")
        XCTAssertEqual(membership(b.snap, Self.n1), [Self.family])
        try pull(old, a, collections: false)
        XCTAssertEqual(title(old.snap, Self.n1), "Door code (new)")
        XCTAssertEqual(copies(a.snap), [])
        XCTAssertEqual(copies(old.snap), [])
    }

    func test_collection_states_reaching_a_run_without_collections_are_dropped() throws {
        let a = Dev("dev-a"), old = Dev("dev-old")
        try create(&a.snap, Self.family, "Family")
        try note(&a.snap, Self.n1, "Tagged", in: [Self.family])
        let report = try pull(old, a, collections: false, srcCollections: true)
        XCTAssertEqual(report.issues, [])
        XCTAssertNotNil(old.snap.records[Self.n1])
        XCTAssertEqual(stateIDs(old.snap.records.keys), [])
        XCTAssertEqual(stateIDs(try view(old, collections: false).keys), [])
        XCTAssertEqual(stateIDs(old.snap.meta.keys), [])
    }

    func test_a_run_without_collections_never_tombstones_them() throws {
        let a = Dev("dev-a"), b = Dev("dev-b")
        try create(&a.snap, Self.family, "Family")
        try note(&a.snap, Self.n1, "Tagged", in: [Self.family])
        try sync(a, b)
        let meta = a.snap.meta
        XCTAssertEqual(stateIDs(try view(a, collections: false).keys), [])
        XCTAssertEqual(a.snap.meta, meta, "their meta is left alone")
        try pull(b, a, collections: true, srcCollections: false)
        XCTAssertEqual(names(b.snap), [Self.family: "Family"])
        XCTAssertEqual(membership(b.snap, Self.n1), [Self.family])
        XCTAssertTrue(try view(a).values.filter { CollectionStates.isStateID($0.itemID) }.allSatisfy { !$0.deleted })
    }

    // MARK: waiting and refusing

    func test_a_membership_waits_for_its_item_and_collection() throws {
        let a = Dev("dev-a"), b = Dev("dev-b")
        try create(&a.snap, Self.family, "Family")
        try note(&a.snap, Self.n1, "Tagged", in: [Self.family])
        let theirs = try view(a)
        let report = run(b, PeerView(deviceID: a.id, states: [try XCTUnwrap(theirs[Self.mem + Self.n1])]))
        XCTAssertEqual(report.issues, [])
        XCTAssertNil(b.snap.meta[Self.mem + Self.n1], "it waits: no meta, so it comes again")
        XCTAssertNil(b.snap.records[Self.mem + Self.n1])
        // The item without its collection: still waiting.
        run(b, PeerView(deviceID: a.id, states: [try XCTUnwrap(theirs[Self.n1]), try XCTUnwrap(theirs[Self.mem + Self.n1])]))
        XCTAssertNil(b.snap.meta[Self.mem + Self.n1])
        try pull(b, a)
        XCTAssertEqual(membership(b.snap, Self.n1), [Self.family])
    }

    func test_a_malformed_membership_is_quarantined_alone() throws {
        let a = Dev("dev-a"), b = Dev("dev-b")
        try create(&a.snap, Self.family, "Family")
        try note(&a.snap, Self.n1, "Tagged", in: [Self.family])
        var theirs = try view(a)
        let good = try XCTUnwrap(theirs[Self.mem + Self.n1])
        var wrapper = o(good.item)
        var record = o(wrapper["record"])
        record["collection_ids"] = .array([.string(Self.family), .string("not-a-uuid")])
        wrapper["record"] = .object(record)
        theirs[good.itemID] = try ItemState(itemID: good.itemID, vv: good.vv, deleted: false, deletedAt: nil, item: .object(wrapper))
        let report = run(b, PeerView(deviceID: a.id, states: theirs.values.sorted { $0.itemID < $1.itemID }))
        XCTAssertEqual(report.issues.map(\.kind), ["bad-peer-record"])
        XCTAssertNotNil(b.snap.records[Self.n1])
        XCTAssertEqual(names(b.snap), [Self.family: "Family"])
        XCTAssertEqual(membership(b.snap, Self.n1), [])
    }

    func test_published_states_match_the_desktop_vectors_and_the_run_check_reads_them() throws {
        let doc = o(try CanonicalJSON.parse(Array(try Data(contentsOf: Vectors.shareCollections("states.json")))))
        let valid = a(doc["valid"]).map { o($0) }
        let wrappers = Dictionary(uniqueKeysWithValues: valid.map { (s($0["id"]), $0["wrapper"] ?? .null) })
        // The store the vectors describe: Family, a note in Family and Work, and Family shared on this device (read, member).
        let dev = Dev("dev-a")
        dev.snap.records[Self.cat + Self.family] = wrappers[Self.cat + Self.family]
        try note(&dev.snap, Self.n1, "Cabin")
        dev.snap.records[Self.mem + Self.n1] = wrappers[Self.mem + Self.n1]
        dev.shares = CollectionShares(links: [Self.family: CollectionShares.Link(mode: "read", role: "member")], readOnly: [Self.family])
        let states = try view(dev)
        XCTAssertEqual(stateIDs(states.keys), Set(wrappers.keys))
        for v in valid {
            let id = s(v["id"])
            let state = try XCTUnwrap(states[id])
            XCTAssertEqual(try canonical(state.item), try canonical(v["wrapper"]), id)
            XCTAssertEqual(try SyncMeta.digest(try XCTUnwrap(state.item)), s(v["digest"]), id)
            XCTAssertNil(SyncRunner.check(state, licenseKeys: [:], collections: true), id)
            // A stray top-level `id` under a reserved id is refused in the fold (quarantined alone), never taken for a copy.
            var stray = o(v["wrapper"])
            stray["id"] = .string(id)
            let strayState = try ItemState(itemID: id, vv: ["dev-b": 1], deleted: false, deletedAt: nil, item: .object(stray))
            XCTAssertEqual(SyncRunner.check(strayState, licenseKeys: [:], collections: true), "bad-remote", id)
        }
        // The share link says only the mode and this device's role: nothing else about the share leaves the device.
        XCTAssertEqual(Set(o(o(states[Self.lnk + Self.family]?.item)["record"]).keys), ["kind", "collection_id", "mode", "role"])
        for m in a(doc["malformed"]).map({ o($0) }) {
            let state = try ItemState(itemID: s(m["id"]), vv: ["dev-b": 1], deleted: false, deletedAt: nil, item: m["wrapper"])
            XCTAssertEqual(SyncRunner.check(state, licenseKeys: [:], collections: true), s(m["verdict"]), s(m["name"]))
        }
    }

    func test_without_readable_share_records_links_and_catalog_tombstones_wait() throws {
        let a = Dev("dev-a"), b = Dev("dev-b")
        a.shares = CollectionShares(links: [Self.family: CollectionShares.Link(mode: "edit", role: "owner")])
        try create(&a.snap, Self.family, "Family")
        try sync(a, b)
        XCTAssertEqual(b.snap.records[Self.lnk + Self.family],
                       CollectionStates.wrapper(CollectionStates.link(collectionID: Self.family, mode: "edit", role: "owner")))
        // B's catalog refuses: the collection is shared from another of this person's devices.
        XCTAssertThrowsError(try CollectionCatalog.delete(Self.family, in: b.snap, trash: [], protected: [])) {
            XCTAssertEqual($0 as? CollectionCatalog.Failure, .shared)
        }
        b.snap.records[Self.cat + Self.family] = nil   // an older or tampered app deletes it anyway
        a.shares.links = nil                           // A cannot read its share records right now
        let published = try view(a)
        XCTAssertNil(published[Self.lnk + Self.family], "no link is published while unknown")
        XCTAssertEqual(a.snap.meta[Self.lnk + Self.family]?.deleted, false, "nor tombstoned")
        try pull(a, b)
        XCTAssertEqual(names(a.snap), [Self.family: "Family"], "the tombstone waits")
        XCTAssertEqual(a.snap.meta[Self.cat + Self.family]?.deleted, false)
        // Readable again: shared here, so the row is republished above the tombstone and comes back on B.
        a.shares.links = [Self.family: CollectionShares.Link(mode: "edit", role: "owner")]
        try pull(a, b)
        XCTAssertEqual(names(a.snap), [Self.family: "Family"])
        try pull(b, a)
        XCTAssertEqual(names(b.snap), [Self.family: "Family"])
    }

    // MARK: shares across one person's own devices

    /// M1 is a member of an owner's `mode` share of Family (it holds the alarm code from the share); M2 is M1's second
    /// device, which is not in the share.
    fileprivate func member(mode: String) throws -> (Dev, Dev) {
        let m1 = Dev("dev-m1"), m2 = Dev("dev-m2")
        m1.shares = CollectionShares(links: [Self.family: CollectionShares.Link(mode: mode, role: "member")],
                                     readOnly: mode == "read" ? [Self.family] : [])
        try create(&m1.snap, Self.family, "Family")
        try note(&m1.snap, Self.n1, "Alarm code", in: [Self.family])
        try pull(m2, m1)
        XCTAssertEqual(membership(m2.snap, Self.n1), [Self.family])
        XCTAssertEqual(m2.snap.records[Self.lnk + Self.family],
                       CollectionStates.wrapper(CollectionStates.link(collectionID: Self.family, mode: mode, role: "member")))
        return (m1, m2)
    }

    func test_read_only_share_stays_read_only_on_a_members_second_device() throws {
        let (m1, m2) = try member(mode: "read")
        XCTAssertEqual(CollectionCatalog.linkedReadOnlyIDs(in: m2.snap), [Self.family])
        // M2's own catalog refuses a move into it, a rename and a delete, like the member's device does.
        try note(&m2.snap, Self.personal, "Personal")
        XCTAssertThrowsError(try CollectionCatalog.setMemberships(itemID: Self.personal, kind: "note", to: [Self.family],
                                                                  in: m2.snap)) { XCTAssertTrue($0 is ReadOnlyCollectionError) }
        XCTAssertThrowsError(try CollectionCatalog.setMemberships(itemID: Self.n1, kind: "note", to: [], in: m2.snap)) {
            XCTAssertTrue($0 is ReadOnlyCollectionError)
        }
        XCTAssertThrowsError(try CollectionCatalog.rename(Self.family, to: "Ours", in: m2.snap, now: Self.now)) {
            XCTAssertEqual($0 as? CollectionCatalog.Failure, .shared)
        }
        XCTAssertThrowsError(try CollectionCatalog.delete(Self.family, in: m2.snap, trash: [], protected: [])) {
            XCTAssertEqual($0 as? CollectionCatalog.Failure, .shared)
        }

        // Even a forced change on M2 (an older app, a tampered vault) never changes it on M1: an edit, a move of a
        // personal item into the share and a rename of the shared collection.
        edit(&m2.snap, Self.n1, title: "Forced on M2", at: 5)
        m2.snap.records[Self.mem + Self.personal] =
            CollectionStates.wrapper(CollectionStates.membership(itemID: Self.personal, collectionIDs: [Self.family]))
        m2.snap.records[Self.cat + Self.family] = try CollectionCatalog.catalogWrapper(
            id: Self.family, name: "Renamed on M2", description: "", createdAt: Self.now, updatedAt: Self.now + 100)
        XCTAssertEqual(try pull(m1, m2).issues, [])
        XCTAssertEqual(title(m1.snap, Self.n1), "Alarm code")
        XCTAssertEqual(membership(m1.snap, Self.personal), [], "a personal item is never added to a read-only share")
        XCTAssertNotNil(m1.snap.records[Self.personal], "the personal item itself syncs")
        XCTAssertEqual(names(m1.snap), [Self.family: "Family"], "the shared collection keeps its name")
        // M1's copy wins back on M2.
        try pull(m2, m1)
        XCTAssertEqual(title(m2.snap, Self.n1), "Alarm code")
        XCTAssertEqual(membership(m2.snap, Self.personal), [])
        XCTAssertEqual(names(m2.snap), [Self.family: "Family"])

        // A delete of the item, its membership and the collection from M2 is undone the same way.
        m2.snap.records[Self.n1] = nil
        m2.snap.records[Self.mem + Self.n1] = nil
        m2.snap.records[Self.cat + Self.family] = nil
        try sync(m1, m2)
        XCTAssertNotNil(m1.snap.records[Self.n1])
        XCTAssertEqual(membership(m1.snap, Self.n1), [Self.family])
        XCTAssertEqual(names(m1.snap), [Self.family: "Family"])
        XCTAssertNotNil(m2.snap.records[Self.n1])
        XCTAssertEqual(membership(m2.snap, Self.n1), [Self.family])
        XCTAssertEqual(names(m2.snap), [Self.family: "Family"])
        XCTAssertEqual(copies(m1.snap), [])

        // Settled without loops: another round changes nothing.
        let before = (try view(m1), try view(m2))
        try sync(m1, m2)
        XCTAssertEqual(try view(m1), before.0)
        XCTAssertEqual(try view(m2), before.1)

        // The owner's next edit (applied on M1 by the share run) reaches M2 through M1.
        edit(&m1.snap, Self.n1, title: "Alarm code v2", at: 10)
        try pull(m2, m1)
        XCTAssertEqual(title(m2.snap, Self.n1), "Alarm code v2")
    }

    // MARK: final fix wave B, finding 4 (a share link whose holder device is gone stays for ever)

    /// `dev` forgets its link of `collectionID` through `ShareGroups.forgetLink` (on a store holding its snapshot).
    fileprivate func forget(_ dev: Dev, _ collectionID: String) throws {
        let store = MemoryStore(dev.snap)
        try ShareGroups.forgetLink(store: store, collectionID: collectionID)
        dev.snap = try store.load()
    }

    func test_forgetting_the_link_of_a_lost_member_device_frees_the_collection_on_every_other_device() throws {
        let (_, m2) = try member(mode: "read")
        let m3 = Dev("dev-m3")
        try pull(m3, m2)
        XCTAssertEqual(CollectionCatalog.linkedReadOnlyIDs(in: m3.snap), [Self.family])
        XCTAssertEqual(ShareGroups.receivedLink(in: m2.snap, collectionID: Self.family),
                       CollectionShares.Link(mode: "read", role: "member"))
        // M1 (the device in the share) is lost.
        try forget(m2, Self.family)
        XCTAssertNil(m2.snap.records[Self.lnk + Self.family])
        XCTAssertNil(ShareGroups.receivedLink(in: m2.snap, collectionID: Self.family))
        XCTAssertEqual(CollectionCatalog.linkedReadOnlyIDs(in: m2.snap), [])
        XCTAssertEqual(try view(m2)[Self.lnk + Self.family]?.deleted, true, "M2 publishes the link's tombstone")
        try pull(m3, m2)
        XCTAssertNil(m3.snap.records[Self.lnk + Self.family])
        XCTAssertEqual(CollectionCatalog.linkedReadOnlyIDs(in: m3.snap), [])
        XCTAssertNoThrow(try CollectionCatalog.delete(Self.family, in: m3.snap, trash: [], protected: []))
    }

    func test_a_device_that_still_holds_the_share_publishes_its_link_again() throws {
        let (m1, m2) = try member(mode: "read")
        try forget(m2, Self.family)
        try pull(m1, m2)
        try pull(m2, m1)
        XCTAssertEqual(m2.snap.records[Self.lnk + Self.family],
                       CollectionStates.wrapper(CollectionStates.link(collectionID: Self.family, mode: "read", role: "member")))
        XCTAssertEqual(CollectionCatalog.linkedReadOnlyIDs(in: m2.snap), [Self.family])
    }

    func test_forget_link_refusals() throws {
        let (_, m2) = try member(mode: "read")
        XCTAssertThrowsError(try ShareGroups.forgetLink(store: MemoryStore(m2.snap), collectionID: Self.work)) {
            XCTAssertEqual(($0 as? ShareGroupError)?.reason, "no-link")
        }
        // A damaged share store counts as shared here (fails closed).
        var damaged = m2.snap
        damaged.shares = .string("not a share store")
        XCTAssertThrowsError(try ShareGroups.forgetLink(store: MemoryStore(damaged), collectionID: Self.family)) {
            XCTAssertEqual(($0 as? ShareGroupError)?.reason, "shared-here")
        }
        XCTAssertNil(ShareGroups.receivedLink(in: damaged, collectionID: Self.family))
    }

    // MARK: re-review wave B, B1 (one collection shared from two of this person's devices)

    func test_a_collection_shared_from_two_devices_settles_on_one_link() throws {
        let o1 = Dev("dev-o1"), o2 = Dev("dev-o2"), o3 = Dev("dev-o3")
        o1.shares = CollectionShares(links: [Self.family: CollectionShares.Link(mode: "read", role: "owner")])
        try create(&o1.snap, Self.family, "Family")
        try pull(o2, o1)
        // O2 forgot the link and shared Family again, in edit mode.
        o2.snap.records[Self.lnk + Self.family] = nil
        o2.shares = CollectionShares(links: [Self.family: CollectionShares.Link(mode: "edit", role: "owner")])
        var rounds: [[[String: Int64]]] = []
        for _ in 0..<5 {
            try pull(o1, o2)
            try pull(o2, o1)
            try pull(o3, o2)
            rounds.append(try [o1, o2, o3].map { try XCTUnwrap(try view($0)[Self.lnk + Self.family]).vv })
        }
        XCTAssertEqual(rounds[4], rounds[3], "\(rounds)")
        XCTAssertEqual(rounds[3], rounds[2], "\(rounds)")
        let read = CollectionStates.link(collectionID: Self.family, mode: "read", role: "owner")
        let edit = CollectionStates.link(collectionID: Self.family, mode: "edit", role: "owner")
        let winner = try CollectionSync.linkBeats(read, edit) ? read : edit
        for d in [o1, o2, o3] {
            XCTAssertEqual(try view(d)[Self.lnk + Self.family]?.item, CollectionStates.wrapper(winner), d.id)
        }
        // Both sharing devices keep the other's link (their share pages warn); the third holds the winner's.
        XCTAssertNotNil(o1.snap.records[Self.lnk + Self.family])
        XCTAssertNotNil(o2.snap.records[Self.lnk + Self.family])
        XCTAssertEqual(o3.snap.records[Self.lnk + Self.family], CollectionStates.wrapper(winner))
        // O2 stops sharing (its stored link goes with it, as `ShareGroups.leave` does): it settles on O1's link.
        o2.shares = CollectionShares.none
        o2.snap.records[Self.lnk + Self.family] = nil
        for _ in 0..<3 {
            try pull(o1, o2)
            try pull(o2, o1)
        }
        XCTAssertNil(o1.snap.records[Self.lnk + Self.family])
        XCTAssertEqual(o2.snap.records[Self.lnk + Self.family], CollectionStates.wrapper(read))
        let settled = try [o1, o2].map { try XCTUnwrap(try view($0)[Self.lnk + Self.family]).vv }
        try pull(o1, o2)
        try pull(o2, o1)
        XCTAssertEqual(try [o1, o2].map { try XCTUnwrap(try view($0)[Self.lnk + Self.family]).vv }, settled)
    }

    func test_an_owner_link_beats_a_member_link() throws {
        let owner = CollectionStates.link(collectionID: Self.family, mode: "read", role: "owner")
        let member = CollectionStates.link(collectionID: Self.family, mode: "read", role: "member")
        let editMember = CollectionStates.link(collectionID: Self.family, mode: "edit", role: "member")
        XCTAssertTrue(try CollectionSync.linkBeats(owner, member))
        XCTAssertFalse(try CollectionSync.linkBeats(member, owner))
        XCTAssertTrue(try CollectionSync.linkBeats(owner, editMember))
        XCTAssertNotEqual(try CollectionSync.linkBeats(member, editMember), try CollectionSync.linkBeats(editMember, member))
    }

    func test_edit_share_second_device_edits_reach_the_member_device() throws {
        let (m1, m2) = try member(mode: "edit")
        XCTAssertEqual(CollectionCatalog.linkedReadOnlyIDs(in: m2.snap), [])
        edit(&m2.snap, Self.n1, title: "Changed on M2", at: 5)
        try pull(m1, m2)
        XCTAssertEqual(title(m1.snap, Self.n1), "Changed on M2")
    }

    // MARK: Wi-Fi

    func test_lan_features_list_and_store() throws {
        XCTAssertEqual(LanFeatures.peers([], setting: "dev-b", capable: true), ["dev-b"])
        XCTAssertNil(LanFeatures.peers(["dev-b"], setting: "dev-b", capable: true))
        XCTAssertNil(LanFeatures.peers([], setting: "dev-b", capable: false))
        XCTAssertEqual(LanFeatures.peers(["dev-a", "dev-b"], setting: "dev-a", capable: false), ["dev-b"])
        let full = (0..<LanFeatures.maxPeers).map { "dev-\($0)" }
        XCTAssertNil(LanFeatures.peers(full, setting: "dev-x", capable: true), "bounded like the desktop")
        // setPeer: true saved, false nothing to change, nil not saved (past the bound, or the store refused).
        let store = PeerSavingStore(MemoryStore(StoreSnapshot(sync: try initiatorStore().snapshot.sync)))
        XCTAssertEqual(LanFeatures.setPeer("dev-b", capable: true, store: store), true)
        XCTAssertEqual(LanFeatures.setPeer("dev-b", capable: true, store: store), false)
        store.snapshot.sync?.collectionPeers = full
        XCTAssertNil(LanFeatures.setPeer("dev-x", capable: true, store: store))
        XCTAssertEqual(LanFeatures.setPeer("dev-0", capable: true, store: store), false, "a listed peer stays")
        store.snapshot.sync?.collectionPeers = []
        store.refusePeers = true
        XCTAssertNil(LanFeatures.setPeer("dev-b", capable: true, store: store))
        XCTAssertEqual(store.snapshot.sync?.collectionPeers, [])
        XCTAssertTrue(LanFeatures.readsCollections(["later", "collections"]))
        XCTAssertFalse(LanFeatures.readsCollections(["later"]))
    }

    /// A's store in the LAN vectors' group, as the initiator.
    func initiatorStore() throws -> MemoryStore {
        let gk = try LanTests().groupKey()
        return MemoryStore(StoreSnapshot(sync: SyncGroupState(groupID: gk.groupID, epoch: gk.epoch, key: gk.key,
                                                              identity: try KeyringTests.identity("A"),
                                                              installID: "lan-install-a", hasFolder: false)))
    }

    /// One Wi-Fi sync as the app's initiator runs it (SyncCoordinator.lanRun with collections): the view exchange, one
    /// merge, then `features` for a peer not yet listed, before any witness exchange.
    func lanSync(_ store: MemoryStore, client: LanClient, connector: LanTests.FakeConnector,
                 peer: PinnedPeer) async throws -> RunReport {
        let snap = store.snapshot
        let state = try XCTUnwrap(snap.sync)
        let withCollections = state.collectionPeers.contains(peer.deviceID)
        let local = try SyncMeta.localView(records: snap.records, meta: snap.meta, device: state.deviceID, now: Self.now,
                                           collections: withCollections)
        let found = try await client.exchange(peer: peer, localStates: local.states.values.sorted { $0.itemID < $1.itemID },
                                              ownCounter: 1, connector: connector)
        let report = SyncRunner.run(store: snap, views: [PeerView(deviceID: peer.deviceID, states: found.states)],
                                    device: state.deviceID, now: Self.now, collections: withCollections)
        try store.commit(StoreChange(baseRevision: snap.revision, records: report.records ?? snap.records,
                                     meta: report.meta ?? snap.meta, sync: snap.sync))
        if !withCollections, let answered = try? await client.exchangeFeatures(peer: peer, connector: connector) {
            LanFeatures.setPeer(peer.deviceID, capable: answered, store: store)
        }
        return report
    }

    /// B's responder (`collections` as given) behind a fake connection; every view A sends is decoded into `sent`.
    func lanPair(collections: Bool, sharesOf: (@Sendable (StoreSnapshot) -> CollectionShares)? = nil) throws
        -> (PeerSavingStore, LanResponder, LanClient, LanTests.FakeConnector, SentViews) {
        let gk = try LanTests().groupKey()
        let peerA = try LanResponderTests().lanPeer("A")
        let bStore = PeerSavingStore(try LanResponderTests().storeB(peers: [peerA]))
        let responder = LanResponder(store: bStore, installID: LanResponderTests.install,
                                     counters: HelloCounterSource(store: MemoryCounterStore(), clock: FixedClock(now: 0)),
                                     random: SystemRandomSource(), clock: FixedClock(now: Self.now), collections: collections,
                                     collectionSharesOf: sharesOf)
        let sent = SentViews()
        let b = try KeyringTests.identity("B"), pinnedA = try LanTests().pinned("A"), aID = try KeyringTests.identity("A").deviceID
        let connector = LanTests.FakeConnector { n in
            LanTests.FakeConnection(b: b, pinnedA: pinnedA, counter: Int64(n + 1), nonce: nil) { request in
                if case let .view(_, _, _, 0, 1, _, text) = try LanMessages.parse(request) {
                    sent.views.append(try ViewFile.decode(try Base64.decodeStrict(text), key: gk, expectedDeviceID: aID).states)
                }
                if case .features = try LanMessages.parse(request) { sent.features += 1 }
                return responder.serve(peer: peerA, request: request)
            }
        }
        let client = LanClient(identity: try KeyringTests.identity("A"), groupKey: gk,
                               counters: HelloCounterSource(store: MemoryCounterStore(), clock: FixedClock(now: Self.now)),
                               random: SystemRandomSource(), clock: FixedClock(now: Self.now))
        return (bStore, responder, client, connector, sent)
    }

    /// A store that can refuse to save a change of `collectionPeers` (a commit race with the host, a full disk);
    /// every other commit goes through.
    final class PeerSavingStore: ItemStore, @unchecked Sendable {
        let inner: MemoryStore
        var refusePeers = false
        init(_ inner: MemoryStore) { self.inner = inner }
        var snapshot: StoreSnapshot {
            get { inner.snapshot }
            set { inner.snapshot = newValue }
        }
        func load() throws -> StoreSnapshot { try inner.load() }
        func commit(_ change: StoreChange) throws {
            if refusePeers && change.sync?.collectionPeers != inner.snapshot.sync?.collectionPeers {
                throw FolderSyncError("busy", "refused by the test")
            }
            try inner.commit(change)
        }
    }

    final class SentViews: @unchecked Sendable {
        var views: [[ItemState]] = []
        var features = 0
    }

    func test_lan_learns_features_after_the_first_exchange_then_syncs_collections() async throws {
        let aStore = try initiatorStore()
        try create(&aStore.snapshot, Self.family, "Family")
        try note(&aStore.snapshot, Self.n1, "Wi-Fi", in: [Self.family])
        let (bStore, responder, client, connector, sent) = try lanPair(collections: true)
        let peerB = try LanTests().pinned("B")
        let aID = try KeyringTests.identity("A").deviceID, bID = peerB.deviceID

        let synced = try await lanSync(aStore, client: client, connector: connector, peer: peerB)
        XCTAssertEqual(synced.issues, [])
        // First exchange: features learnt both ways, nothing of the collections sent yet.
        XCTAssertEqual(aStore.snapshot.sync?.collectionPeers, [bID])
        XCTAssertEqual(bStore.snapshot.sync?.collectionPeers, [aID])
        XCTAssertEqual(sent.views.count, 1)
        XCTAssertEqual(stateIDs(sent.views[0].map(\.itemID)), [])
        XCTAssertNotNil(bStore.snapshot.records[Self.n1])
        XCTAssertEqual(names(bStore.snapshot), [:])

        let second = try await lanSync(aStore, client: client, connector: connector, peer: peerB)
        XCTAssertEqual(second.issues, [])
        XCTAssertEqual(sent.features, 1, "a listed peer is not asked again")
        XCTAssertEqual(names(bStore.snapshot), [Self.family: "Family"])
        XCTAssertEqual(membership(bStore.snapshot, Self.n1), [Self.family])

        // B takes it out of Family; A follows on the next exchange.
        try member(&bStore.snapshot, Self.n1, [])
        let third = try await lanSync(aStore, client: client, connector: connector, peer: peerB)
        XCTAssertEqual(third.issues, [])
        XCTAssertEqual(membership(aStore.snapshot, Self.n1), [])
        XCTAssertNil(responder.lastReport?.issues.first)

        // A peer whose list does not name collections is recorded as not capable.
        let peerA = try LanResponderTests().lanPeer("A")
        let reply = responder.serve(peer: peerA, request: try LanMessages.encode(.features(["later"])))
        XCTAssertEqual(try LanMessages.parse(reply), .features(LanFeatures.ours))
        XCTAssertEqual(bStore.snapshot.sync?.collectionPeers, [])
    }

    func test_lan_responder_that_cannot_save_the_peer_answers_local_data_and_is_asked_again() async throws {
        let aStore = try initiatorStore()
        try create(&aStore.snapshot, Self.family, "Family")
        try note(&aStore.snapshot, Self.n1, "Wi-Fi", in: [Self.family])
        let (bStore, responder, client, connector, sent) = try lanPair(collections: true)
        let peerB = try LanTests().pinned("B")
        bStore.refusePeers = true
        let first = try await lanSync(aStore, client: client, connector: connector, peer: peerB)
        XCTAssertEqual(first.issues, [])
        XCTAssertEqual(responder.lastReport?.issues.map(\.kind), ["local-data"])
        XCTAssertEqual(bStore.snapshot.sync?.collectionPeers, [])
        XCTAssertEqual(aStore.snapshot.sync?.collectionPeers, [], "not recorded: one-sided sync never starts")
        // The responder can save again: the initiator asks again and both sides learn it.
        bStore.refusePeers = false
        let second = try await lanSync(aStore, client: client, connector: connector, peer: peerB)
        XCTAssertEqual(second.issues, [])
        XCTAssertEqual(sent.features, 2)
        XCTAssertEqual(aStore.snapshot.sync?.collectionPeers, [peerB.deviceID])
        XCTAssertEqual(bStore.snapshot.sync?.collectionPeers, [try KeyringTests.identity("A").deviceID])
        let third = try await lanSync(aStore, client: client, connector: connector, peer: peerB)
        XCTAssertEqual(third.issues, [])
        XCTAssertEqual(names(bStore.snapshot), [Self.family: "Family"])
        XCTAssertEqual(membership(bStore.snapshot, Self.n1), [Self.family])
    }

    func test_lan_responder_reads_its_share_records_from_the_merged_snapshot_and_keeps_read_only_items() async throws {
        // 5g re-review R2: a read-only share holds through a responder merge built with `collectionSharesOf` (the share
        // records read from the very snapshot the merge uses), as the 5d case holds it with `collectionShares`.
        let aStore = try initiatorStore()
        let readOnly = CollectionShares(links: [Self.family: CollectionShares.Link(mode: "read", role: "member")],
                                        readOnly: [Self.family])
        let (bStore, responder, client, connector, _) = try lanPair(collections: true, sharesOf: { _ in readOnly })
        // B is the member of a read-only share of Family and holds its alarm code.
        try create(&bStore.snapshot, Self.family, "Family")
        try note(&bStore.snapshot, Self.n1, "Alarm code", in: [Self.family])
        let peerB = try LanTests().pinned("B")
        for _ in 0..<2 {
            let synced = try await lanSync(aStore, client: client, connector: connector, peer: peerB)
            XCTAssertEqual(synced.issues, [])
        }
        XCTAssertEqual(title(aStore.snapshot, Self.n1), "Alarm code")
        XCTAssertEqual(membership(aStore.snapshot, Self.n1), [Self.family])
        // A (another device of the person) edits the item and takes it out of Family: B keeps its own copy.
        // A now holds B's read-only link too, so `setMemberships` refuses the move: write it as an older build would.
        edit(&aStore.snapshot, Self.n1, title: "Changed on A", at: 50)
        aStore.snapshot.records[CollectionStates.membershipPrefix + Self.n1] =
            try CollectionCatalog.membershipWrapper(itemID: Self.n1, ids: [])
        let edited = try await lanSync(aStore, client: client, connector: connector, peer: peerB)
        XCTAssertEqual(edited.issues, [])
        XCTAssertEqual(title(bStore.snapshot, Self.n1), "Alarm code", "\(String(describing: responder.lastReport?.issues))")
        XCTAssertEqual(membership(bStore.snapshot, Self.n1), [Self.family])
    }

    func test_lan_older_responder_never_gets_collection_states() async throws {
        let aStore = try initiatorStore()
        try create(&aStore.snapshot, Self.family, "Family")
        try note(&aStore.snapshot, Self.n1, "Wi-Fi", in: [Self.family])
        let (bStore, responder, client, connector, sent) = try lanPair(collections: false)
        let peerB = try LanTests().pinned("B")
        for _ in 0..<3 {
            let synced = try await lanSync(aStore, client: client, connector: connector, peer: peerB)
            XCTAssertEqual(synced.issues, [])
        }
        XCTAssertEqual(sent.features, 3, "asked each time, answered as an older app")
        XCTAssertEqual(aStore.snapshot.sync?.collectionPeers, [])
        XCTAssertEqual(sent.views.count, 3)
        XCTAssertTrue(sent.views.allSatisfy { stateIDs($0.map(\.itemID)).isEmpty }, "no view with collection states")
        XCTAssertEqual(stateIDs(bStore.snapshot.records.keys), [])
        XCTAssertNotNil(bStore.snapshot.records[Self.n1])
        XCTAssertEqual(bStore.snapshot.sync?.collectionPeers, [])
        // Its answer to `features` is what an older app sends.
        let refused = responder.serve(peer: try LanResponderTests().lanPeer("A"),
                                      request: try LanMessages.encode(.features(LanFeatures.ours)))
        XCTAssertEqual(try LanMessages.parse(refused), .error(reason: "bad-message"))
    }

    // MARK: folder

    static var gk1: GroupKey { try! FolderSyncTests.epoch1() }

    /// The seeded epoch-1 folder (vector members A, B and C, which also read collections) and phones joined to it.
    func folderWithReaders() throws -> MemoryFolder {
        let folder = try FolderSyncTests.seededFolder()
        for who in ["A", "B", "C"] {
            try FolderBlobs(access: folder).writeCapability(Self.gk1, identity: try KeyringTests.identity(who),
                                                            clock: FixedClock(now: EngineTests.T0),
                                                            random: DetRand("col|\(who)"), feature: .collections)
        }
        return folder
    }

    func phone(_ folder: MemoryFolder, _ label: String, collections: Bool) throws -> (store: MemoryStore, id: String) {
        let store = MemoryStore()
        let pw = try KeyringTests.pwKey("1")
        _ = try FolderSync(access: folder, installID: "ios-\(label)", collections: collections)
            .join(store: store, deviceName: label, random: DetRand("5d|\(label)"),
                  clock: FixedClock(now: EngineTests.T0 + 1000)) { _ in pw }
        return (store, try XCTUnwrap(store.snapshot.sync).deviceID)
    }

    var clock = EngineTests.T0 + 2000

    @discardableResult
    func runPhone(_ folder: MemoryFolder, _ phone: (store: MemoryStore, id: String), _ label: String,
                  collections: Bool = true) throws -> RunReport {
        clock += 10
        let report = try FolderSync(access: folder, installID: "ios-\(label)", collections: collections)
            .runOnce(store: phone.store, random: DetRand("run|\(label)|\(clock)"), clock: FixedClock(now: clock))
        let bad: Set<String> = ["bad-peer-record", "apply-failed", "local-data", "write-failed", "busy", "bad-peer-data"]
        XCTAssertEqual(report.issues.filter { bad.contains($0.kind) }, [])
        return report
    }

    func published(_ folder: MemoryFolder, _ id: String) throws -> [String] {
        try ViewFile.decode(try XCTUnwrap(folder.files[FolderSyncTests.devPath(id)]), key: Self.gk1, expectedDeviceID: id)
            .states.map(\.itemID)
    }

    func test_folder_collections_sync_between_new_members_and_settle() throws {
        let folder = try folderWithReaders()
        let p1 = try phone(folder, "p1", collections: true), p2 = try phone(folder, "p2", collections: true)
        for p in [p1, p2] {
            let signer = Base64.encode(try XCTUnwrap(p.store.snapshot.sync).identity.signingPublicKey)
            XCTAssertTrue(FolderBlobs(access: folder).capable(Self.gk1, deviceID: p.id, signer: signer, feature: .collections),
                          "each phone wrote its signed .lgkcol")
        }
        try create(&p1.store.snapshot, Self.family, "Family")
        try note(&p1.store.snapshot, Self.n1, "Wi-Fi", in: [Self.family])
        for _ in 0..<2 {
            try runPhone(folder, p1, "p1")
            try runPhone(folder, p2, "p2")
        }
        XCTAssertTrue(stateIDs(try published(folder, p1.id)).contains(Self.cat + Self.family))
        XCTAssertEqual(names(p2.store.snapshot), [Self.family: "Family"])
        XCTAssertEqual(membership(p2.store.snapshot, Self.n1), [Self.family])
        try create(&p2.store.snapshot, Self.work, "Work")
        try member(&p2.store.snapshot, Self.n1, [Self.work])
        for _ in 0..<2 {
            try runPhone(folder, p2, "p2")
            try runPhone(folder, p1, "p1")
        }
        XCTAssertEqual(membership(p1.store.snapshot, Self.n1), [Self.work])
        // Settled: no view is written again.
        let files = (folder.files[FolderSyncTests.devPath(p1.id)], folder.files[FolderSyncTests.devPath(p2.id)])
        XCTAssertFalse(try runPhone(folder, p1, "p1").wrote)
        XCTAssertFalse(try runPhone(folder, p2, "p2").wrote)
        XCTAssertEqual(folder.files[FolderSyncTests.devPath(p1.id)], files.0)
        XCTAssertEqual(folder.files[FolderSyncTests.devPath(p2.id)], files.1)
    }

    func test_folder_older_member_gets_v1_views_until_it_updates() throws {
        let folder = try folderWithReaders()
        let p1 = try phone(folder, "p1", collections: true), p2 = try phone(folder, "p2", collections: false)
        XCTAssertNil(folder.files["\(FolderBlobs.dir)/\(p2.id).lgkcol"], "an older app writes no collections file")
        try create(&p1.store.snapshot, Self.family, "Family")
        try note(&p1.store.snapshot, Self.n1, "Wi-Fi", in: [Self.family])
        try runPhone(folder, p1, "p1")
        try runPhone(folder, p2, "p2", collections: false)
        XCTAssertEqual(stateIDs(try published(folder, p1.id)), [], "an older member never reads a collection state")
        XCTAssertEqual(stateIDs(p2.store.snapshot.records.keys), [])
        XCTAssertNotNil(p2.store.snapshot.records[Self.n1])
        edit(&p2.store.snapshot, Self.n1, title: "Wi-Fi (new)", at: 5)   // the older member edits it
        try runPhone(folder, p2, "p2", collections: false)
        try runPhone(folder, p1, "p1")
        XCTAssertEqual(title(p1.store.snapshot, Self.n1), "Wi-Fi (new)")
        XCTAssertEqual(membership(p1.store.snapshot, Self.n1), [Self.family], "the newer member keeps its collections")
        // P2 updates: it writes its file, and the collections follow.
        for _ in 0..<2 {
            try runPhone(folder, p2, "p2")
            try runPhone(folder, p1, "p1")
        }
        try runPhone(folder, p2, "p2")
        XCTAssertTrue(stateIDs(try published(folder, p1.id)).contains(Self.mem + Self.n1))
        XCTAssertEqual(names(p2.store.snapshot), [Self.family: "Family"])
        XCTAssertEqual(membership(p2.store.snapshot, Self.n1), [Self.family])
    }

    func test_folder_document_capability_does_not_count_for_collections() throws {
        let folder = try folderWithReaders()
        let p1 = try phone(folder, "p1", collections: true), p2 = try phone(folder, "p2", collections: true)
        let p2Identity = try XCTUnwrap(p2.store.snapshot.sync).identity
        let blobs = FolderBlobs(access: folder)
        try blobs.writeCapability(Self.gk1, identity: p2Identity, clock: FixedClock(now: EngineTests.T0), random: DetRand("doc"))
        let doc = try XCTUnwrap(FolderBlobs.capPaths(p2.id)), col = try XCTUnwrap(FolderBlobs.capPaths(p2.id, feature: .collections))
        // Someone with folder access copies P2's document capability under the collections name.
        folder.files[col.cap] = folder.files[doc.cap]
        folder.files[col.sig] = folder.files[doc.sig]
        let signer = Base64.encode(p2Identity.signingPublicKey)
        XCTAssertTrue(blobs.capable(Self.gk1, deviceID: p2.id, signer: signer), "the copied files verify as what they are")
        XCTAssertFalse(blobs.capable(Self.gk1, deviceID: p2.id, signer: signer, feature: .collections))
        try create(&p1.store.snapshot, Self.family, "Family")
        try runPhone(folder, p1, "p1")
        XCTAssertEqual(stateIDs(try published(folder, p1.id)), [], "P2 counts as older until it writes its own file")
        try runPhone(folder, p2, "p2")   // this version replaces the copy with a real one
        XCTAssertTrue(blobs.capable(Self.gk1, deviceID: p2.id, signer: signer, feature: .collections))
        try runPhone(folder, p1, "p1")
        XCTAssertTrue(stateIDs(try published(folder, p1.id)).contains(Self.cat + Self.family))
    }
}
