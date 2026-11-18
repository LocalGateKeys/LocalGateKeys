import XCTest
import Foundation
@testable import LGKCore

/// An item store with the host's Recently deleted: every live item a commit takes out is copied there with its
/// collections first (as the apps' `RemoteDeletes` do), and the share groups are kept unless a commit sets them (as
/// `LocalStore` does).
final class TrashingStore: ItemStore, @unchecked Sendable {
    private let lock = NSLock()
    private var current = StoreSnapshot()
    private var rows: [LocalData.TrashRow] = []

    func load() throws -> StoreSnapshot { lock.withLock { current } }

    func commit(_ change: StoreChange) throws {
        try lock.withLock {
            guard change.baseRevision == current.revision else { throw FolderSyncError("vault-changed") }
            for (id, w) in current.itemRecords.sorted(by: { $0.key < $1.key }) where change.records[id] == nil {
                guard case .object(let o) = w, let record = o["record"] else { continue }
                rows.append(try LocalData.TrashRow(record: CollectionCatalog.trashRecord(record, itemID: id, in: current),
                                                   deletedAt: 0))
            }
            let shares: JSONValue?
            switch change.shares {
            case .keep: shares = current.shares
            case .set(let value): shares = value
            }
            current = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync,
                                    revision: current.revision + 1, shares: shares)
        }
    }

    var trash: [LocalData.TrashRow] { lock.withLock { rows } }

    var trashIDs: Set<String> {
        Set(trash.compactMap { (row) -> String? in
            guard case .object(let r)? = try? row.record(), case .string(let id)? = r["id"] else { return nil }
            return id
        })
    }
}

/// Shared collections in LGKCore (sub-plan 07 Task 5e): `ShareGroups`, `ShareItemStore` and `FolderSync(share:)`.
/// Ports of the desktop's `test_share_group.py`, `test_vault_bridge_shared.py` and `test_folder_sync_shared.py`.
final class ShareRunnerTests: XCTestCase {
    static let pw = "correct horse battery staple 7!"
    static let pw2 = "another very long passphrase 42?"
    static let t0: Int64 = 1_800_000_000
    static let random = SystemRandomSource()
    /// A cheap stand-in for Argon2id (tests only): HKDF of the password with the keyring's salt.
    static let cheap: Keyring.KeyDerivation = { pw, salt in
        CryptoBox.hkdf(ikm: Array(pw.utf8), salt: salt, info: Array("share-runner-test".utf8), length: 32)
    }

    static let itemA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
    static let itemB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2"
    static let itemP = "cccccccc-cccc-4ccc-8ccc-ccccccccccc3"
    static let itemW = "dddddddd-dddd-4ddd-8ddd-ddddddddddd4"
    static let itemM = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee5"

    /// One device: its own item store and Recently deleted.
    final class Device {
        let store = TrashingStore()
        let install: String
        var isPro = true
        init(_ install: String) { self.install = install }
    }

    /// An owner and a member, each with its own vault, syncing one share group through `folder` (desktop `Share`).
    final class Share {
        let folder = MemoryFolder()
        let owner: Device
        let member = Device("install-member")
        var clock: Int64 = ShareRunnerTests.t0
        let cid: String
        let gid: String

        /// `shareFormat` 2: a share v1 group (items sealed with G), as apps before share v2 made them.
        init(mode: String = "edit", shareFormat: Int64 = 3) throws {
            let owner = Device("install-owner")
            let made = try CollectionCatalog.create(name: "Family", in: try owner.store.load(), now: ShareRunnerTests.t0)
            try owner.store.commit(made.change)
            let group = try ShareGroups.create(store: owner.store, collectionID: made.id, password: ShareRunnerTests.pw,
                                               deviceName: "Owner PC", sharedMode: mode, installID: owner.install,
                                               isPro: true, folder: nil, random: ShareRunnerTests.random,
                                               clock: FixedClock(now: ShareRunnerTests.t0), derive: ShareRunnerTests.cheap,
                                               shareFormat: shareFormat)
            self.owner = owner
            self.cid = made.id
            self.gid = group.groupID
        }

        func tick() -> FixedClock {
            clock += 1
            return FixedClock(now: clock)
        }

        func fs(_ d: Device) throws -> FolderSync {
            try FolderSync(access: folder, installID: d.install,
                           share: FolderSync.Share(groupID: gid, isPro: d.isPro, trash: ShareTrash.of(d.store.trash)))
        }

        @discardableResult
        func run(_ d: Device) throws -> RunReport {
            try fs(d).runOnce(store: d.store, random: ShareRunnerTests.random, clock: tick())
        }

        @discardableResult
        func join(_ d: Device, _ name: String) throws -> ShareGroups.Group {
            let raw = try XCTUnwrap(folder.files[FolderLayout.keyringPath])
            return try ShareGroups.join(store: d.store, keyring: raw, password: ShareRunnerTests.pw, deviceName: name,
                                        installID: d.install, isPro: d.isPro, folder: nil, random: ShareRunnerTests.random,
                                        clock: tick(), derive: ShareRunnerTests.cheap)
        }

        func pendingIDs() throws -> [String] {
            try ShareGroups.pendingMembers(in: try owner.store.load(), groupID: gid).map(\.deviceID)
        }

        func pendingNames() throws -> [String] {
            try ShareGroups.pendingMembers(in: try owner.store.load(), groupID: gid).map { $0.name ?? "" }.sorted()
        }

        /// The member joins, the owner adopts and approves it, and the member adopts the approval (desktop `join`).
        func connect() throws {
            try run(owner)
            try join(member, "Member PC")
            try run(member)
            try run(owner)
            try ShareGroups.approve(store: owner.store, groupID: gid, deviceIDs: try pendingIDs())
            try run(owner)
            try run(member)
        }

        func record(_ d: Device) throws -> ShareRecord { try XCTUnwrap(ShareGroups.records(in: d.store.load())[gid]) }
        func deviceID(_ d: Device) throws -> String { try record(d).state.deviceID }
    }

    // MARK: helpers

    static func noteRecord(_ id: String, _ title: String, body: String, at: Int64, favorite: Bool = false,
                           tags: [String] = []) -> JSONValue {
        .object(["id": .string(id), "kind": .string("note"), "title": .string(title), "created_at": .int(t0),
                 "updated_at": .int(at), "favorite": .bool(favorite), "tags": .array(tags.map { JSONValue.string($0) }),
                 "payload": .object(["body": .string(body), "fields": .array([]), "template_id": .null])])
    }

    /// Stores (or replaces) a note in `d`'s vault with exactly `collections`.
    static func put(_ d: Device, _ id: String, _ title: String, body: String, in collections: [String], at: Int64 = t0,
                    favorite: Bool = false, tags: [String] = []) throws {
        let s = try d.store.load()
        var records = s.records
        records[id] = Wrapper.make(ns: .item, record: noteRecord(id, title, body: body, at: at, favorite: favorite, tags: tags))
        records[CollectionStates.membershipPrefix + id] = try CollectionCatalog.membershipWrapper(itemID: id, ids: collections)
        try d.store.commit(StoreChange(baseRevision: s.revision, records: records, meta: s.meta, sync: s.sync))
    }

    static func record(_ d: Device, _ id: String) throws -> [String: JSONValue]? {
        guard case .object(let w)? = try d.store.load().records[id], case .object(let r)? = w["record"] else { return nil }
        return r
    }

    static func body(_ d: Device, _ id: String) throws -> String? {
        guard let r = try record(d, id), case .object(let p)? = r["payload"], case .string(let b)? = p["body"] else { return nil }
        return b
    }

    static func items(_ d: Device) throws -> Set<String> { Set(try d.store.load().itemRecords.keys) }

    static func collection(_ d: Device, _ name: String) throws -> String {
        let made = try CollectionCatalog.create(name: name, in: try d.store.load(), now: t0)
        try d.store.commit(made.change)
        return made.id
    }

    static func setMemberships(_ d: Device, _ id: String, _ ids: [String]) throws {
        let s = try d.store.load()
        if let change = try CollectionCatalog.setMemberships(itemID: id, kind: "note", to: ids, in: s) {
            try d.store.commit(change)
        }
    }

    static func kinds(_ r: RunReport) -> [String] { r.issues.map(\.kind) }

    static func reason(_ e: Error) -> String? {
        (e as? ShareGroupError)?.reason ?? (e as? KeyringError)?.reason ?? (e as? RemovalError)?.reason
    }

    // MARK: what leaves the device

    func test_the_member_receives_only_the_shared_item_and_tags_stay_personal() throws {
        let s = try Share()
        let work = try Self.collection(s.owner, "Work")
        try Self.put(s.owner, Self.itemA, "A", body: "shared text", in: [s.cid, work], favorite: true, tags: ["home"])
        try Self.put(s.owner, Self.itemP, "Personal", body: "my diary", in: [])
        try Self.put(s.owner, Self.itemW, "Work item", body: "work", in: [work])
        try Self.put(s.member, Self.itemM, "Member own", body: "member diary", in: [])
        try s.connect()
        XCTAssertEqual(try Self.items(s.member), [Self.itemA, Self.itemM])
        let got = try XCTUnwrap(try Self.record(s.member, Self.itemA))
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "shared text")
        XCTAssertEqual(got["tags"], .array([]))
        XCTAssertEqual(got["favorite"], .bool(false))
        XCTAssertNil(got["collection_ids"], "the store keeps the v1 item shape")
        let memberSnap = try s.member.store.load()
        XCTAssertEqual(CollectionCatalog.memberships(of: Self.itemA, in: memberSnap), [s.cid])
        XCTAssertEqual(CollectionCatalog.collections(in: memberSnap).map(\.id), [s.cid], "the owner's other collections stay private")
        XCTAssertEqual(CollectionCatalog.collections(in: memberSnap).map(\.name), ["Family"])
        // The published share record carries only the collection: no tags, favourite or other collection.
        let published = try XCTUnwrap(s.folder.files[FolderLayout.deviceFile(try s.deviceID(s.owner))!])
        let st = try s.record(s.owner).state
        // Share v2: sealed with the content key; the group key (what the share password opens) does not open it.
        let contentKey = try XCTUnwrap(try ShareGroups.viewKey(of: try s.record(s.owner)))
        XCTAssertNotEqual(contentKey.key, try st.groupKey().key)
        XCTAssertThrowsError(try ViewFile.decode(published, key: try st.groupKey(), expectedDeviceID: st.deviceID))
        let view = try ViewFile.decode(published, key: contentKey, expectedDeviceID: st.deviceID)
        XCTAssertEqual(view.states.map(\.itemID), [Self.itemA])
        guard case .object(let w)? = view.states.first?.item, case .object(let r)? = w["record"] else { return XCTFail() }
        XCTAssertNil(r["tags"]); XCTAssertNil(r["favorite"])
        XCTAssertEqual(r["collection_ids"], .array([.string(s.cid)]))
        // Nothing of the member's own vault went the other way, and the owner's own fields are untouched.
        try s.run(s.member)
        try s.run(s.owner)
        XCTAssertNil(try Self.record(s.owner, Self.itemM))
        XCTAssertEqual(try Self.record(s.owner, Self.itemA)?["tags"], .array([.string("home")]))
        // A tag or favourite change is not an edit of the share.
        try Self.put(s.member, Self.itemA, "A", body: "shared text", in: [s.cid], favorite: true, tags: ["member-tag"])
        try s.run(s.member)
        XCTAssertEqual(try s.run(s.owner).applied, 0)
    }

    func test_a_member_edit_reaches_the_owner_in_edit_mode() throws {
        let s = try Share()
        let home = try Self.collection(s.owner, "Home")
        try Self.put(s.owner, Self.itemA, "A", body: "v1", in: [s.cid, home])
        try s.connect()
        try Self.put(s.member, Self.itemA, "A", body: "v2 by member", in: [s.cid], at: Self.t0 + 100)
        try s.run(s.member)
        let report = try s.run(s.owner)
        XCTAssertEqual(report.applied, 1)
        XCTAssertEqual(try Self.body(s.owner, Self.itemA), "v2 by member")
        XCTAssertEqual(CollectionCatalog.memberships(of: Self.itemA, in: try s.owner.store.load()),
                       ShareKeyring.sortedIDs([s.cid, home]), "the owner keeps its own collections")
    }

    func test_both_edit_offline_and_both_versions_survive_on_both() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "v1", in: [s.cid])
        try s.connect()
        try Self.put(s.owner, Self.itemA, "A", body: "owner offline", in: [s.cid], at: Self.t0 + 50)
        try Self.put(s.member, Self.itemA, "A", body: "member offline", in: [s.cid], at: Self.t0 + 60)
        try s.run(s.member)
        try s.run(s.owner)
        try s.run(s.member)
        try s.run(s.owner)
        for d in [s.owner, s.member] {
            let snap = try d.store.load()
            let live = CollectionCatalog.items(in: s.cid, snapshot: snap)
            XCTAssertEqual(live.count, 2, "the conflict copy stays in the share")
            XCTAssertEqual(try live.compactMap { try Self.body(d, $0) }.sorted(), ["member offline", "owner offline"])
            let copy = try XCTUnwrap(live.first { $0 != Self.itemA })
            guard case .string(let title)? = try Self.record(d, copy)?["title"] else { return XCTFail() }
            XCTAssertTrue(title.hasSuffix(ConflictSuffix.suffix))
        }
    }

    func test_the_owner_untags_an_item_the_member_loses_it_the_owner_keeps_it() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "was shared", in: [s.cid])
        try s.connect()
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "was shared")
        let home = try Self.collection(s.member, "Home")
        try Self.put(s.member, Self.itemA, "A", body: "was shared", in: [s.cid, home], favorite: true, tags: ["mine"])
        try s.run(s.member)
        try Self.setMemberships(s.owner, Self.itemA, [])
        try s.run(s.owner)
        let report = try s.run(s.member)
        XCTAssertEqual(report.deleted, 1)
        XCTAssertNil(try Self.record(s.member, Self.itemA))
        XCTAssertTrue(s.member.store.trashIDs.contains(Self.itemA))
        XCTAssertEqual(try Self.body(s.owner, Self.itemA), "was shared")
        XCTAssertFalse(s.owner.store.trashIDs.contains(Self.itemA))
        // Tagging it again shares it again (back from the member's Recently deleted).
        try Self.setMemberships(s.owner, Self.itemA, [s.cid])
        try s.run(s.owner)
        try s.run(s.member)
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "was shared")
        XCTAssertEqual(CollectionCatalog.memberships(of: Self.itemA, in: try s.member.store.load()),
                       ShareKeyring.sortedIDs([s.cid, home]), "its other collections come back with it")
        XCTAssertEqual(try Self.record(s.member, Self.itemA)?["tags"], .array([.string("mine")]), "this device's own tags")
        XCTAssertEqual(try Self.record(s.member, Self.itemA)?["favorite"], .bool(true))
    }

    func test_an_owner_untag_while_a_member_edits_is_skipped_quietly_on_the_owner() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "v1", in: [s.cid])
        try s.connect()
        try Self.setMemberships(s.owner, Self.itemA, [])
        try s.run(s.owner)
        try Self.put(s.member, Self.itemA, "A", body: "member edit", in: [s.cid], at: Self.t0 + 100)
        try s.run(s.member)
        for _ in 0..<2 {
            let report = try s.run(s.owner)
            XCTAssertEqual(report.applied, 0)
            XCTAssertFalse(Self.kinds(report).contains("bad-peer-record"), "not a bad peer record")
            XCTAssertEqual(try Self.body(s.owner, Self.itemA), "v1")
            XCTAssertEqual(CollectionCatalog.memberships(of: Self.itemA, in: try s.owner.store.load()), [])
            XCTAssertEqual(try s.record(s.owner).meta[Self.itemA]?.deleted, true, "the owner keeps publishing the tombstone")
        }
    }

    func test_an_incoming_item_never_overwrites_or_deletes_a_personal_item() throws {
        let s = try Share()
        try s.connect()
        try Self.put(s.member, Self.itemP, "Mine", body: "member diary", in: [])
        try Self.put(s.member, Self.itemB, "Trashed mine", body: "old diary", in: [])
        let snap = try s.member.store.load()
        try s.member.store.commit(StoreChange(baseRevision: snap.revision,
                                              records: CollectionCatalog.withoutMembership(Self.itemB, records: snap.records)
                                                .filter { $0.key != Self.itemB },
                                              meta: snap.meta, sync: snap.sync))
        XCTAssertTrue(s.member.store.trashIDs.contains(Self.itemB))
        // The owner publishes items under those ids (a forged or a colliding id).
        try Self.put(s.owner, Self.itemP, "X", body: "overwritten", in: [s.cid])
        try Self.put(s.owner, Self.itemB, "Y", body: "restored", in: [s.cid])
        try s.run(s.owner)
        let report = try s.run(s.member)
        let refused = report.issues.filter { $0.kind == "bad-peer-record" }.map { String($0.detail.split(separator: ":").last ?? "") }
        XCTAssertEqual(Set(refused), [Self.itemP, Self.itemB])
        XCTAssertEqual(try Self.body(s.member, Self.itemP), "member diary")
        XCTAssertNil(try Self.record(s.member, Self.itemB))
        // A tombstone for a personal item is recorded in the share only.
        let o = try s.owner.store.load()
        try s.owner.store.commit(StoreChange(baseRevision: o.revision,
                                             records: CollectionCatalog.withoutMembership(Self.itemP, records: o.records)
                                               .filter { $0.key != Self.itemP },
                                             meta: o.meta, sync: o.sync))
        try s.run(s.owner)
        let after = try s.run(s.member)
        XCTAssertEqual(after.deleted, 0)
        XCTAssertEqual(try Self.body(s.member, Self.itemP), "member diary")
        XCTAssertFalse(s.member.store.trashIDs.contains(Self.itemP))
    }

    // MARK: read-only

    func test_a_read_only_member_never_publishes_a_local_change_and_the_owner_ignores_member_views() throws {
        let s = try Share(mode: "read")
        try Self.put(s.owner, Self.itemA, "A", body: "owner text", in: [s.cid])
        try s.connect()
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "owner text")
        let memberSnap = try s.member.store.load()
        let readOnly = ShareGroups.readOnlyCollectionIDs(in: memberSnap)
        XCTAssertEqual(readOnly, [s.cid])
        XCTAssertEqual(ShareGroups.readOnlyCollectionIDs(in: try s.owner.store.load()), [])
        // Refused up front: an edit, a move out and a move in.
        XCTAssertThrowsError(try ShareAccess.checkWritable(readOnly, .object(["collection_ids": .array([.string(s.cid)])])))
        XCTAssertThrowsError(try CollectionCatalog.setMemberships(itemID: Self.itemA, kind: "note", to: [], in: memberSnap,
                                                                  readOnly: readOnly))
        // Changes that bypass those checks (a bug, a damaged store): an edit and a new tagged item.
        try Self.put(s.member, Self.itemA, "A", body: "member tampered", in: [s.cid], at: Self.t0 + 100)
        try Self.put(s.member, Self.itemB, "Sneaky", body: "x", in: [s.cid], at: Self.t0 + 100)
        let report = try s.run(s.member)
        XCTAssertFalse((report.ownStates ?? []).contains { $0.itemID == Self.itemB }, "a new item is never published")
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "owner text", "the owner's version returns")
        // A member view that claims an edit (signed with the member's own key) is ignored by the owner.
        let st = try s.record(s.member).state
        let gk = try XCTUnwrap(try ShareGroups.viewKey(of: try s.record(s.member)))   // the approved member's content key
        var forged = Self.noteRecord(Self.itemA, "A", body: "forged", at: Self.t0 + 500)
        if case .object(var r) = forged {
            r["tags"] = nil; r["favorite"] = nil; r["collection_ids"] = .array([.string(s.cid)])
            forged = .object(r)
        }
        let ownerID = try s.deviceID(s.owner)
        let state = try ItemState(itemID: Self.itemA, vv: [st.deviceID: 99, ownerID: 99], deleted: false,
                                  deletedAt: nil, item: Wrapper.make(ns: .item, record: forged))
        let raw = try ViewFile.encode(key: gk, deviceID: st.deviceID, counter: 1000, states: [state],
                                      now: FixedClock(now: Self.t0 + 500), random: Self.random)
        s.folder.files[FolderLayout.deviceFile(st.deviceID)!] = raw
        s.folder.files[FolderLayout.signatureFile(st.deviceID)!] = try ViewSignature.sign(
            raw, header: try ViewFile.decodeHeader(raw), identity: st.identity)
        try s.run(s.owner)
        XCTAssertEqual(try Self.body(s.owner, Self.itemA), "owner text")
        // The owner edits freely and the edit flows; a delete moves it to the member's Recently deleted.
        try Self.put(s.owner, Self.itemA, "A", body: "owner v2", in: [s.cid], at: Self.t0 + 600)
        try s.run(s.owner)
        try s.run(s.member)
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "owner v2")
        let o = try s.owner.store.load()
        try s.owner.store.commit(StoreChange(baseRevision: o.revision,
                                             records: CollectionCatalog.withoutMembership(Self.itemA, records: o.records)
                                               .filter { $0.key != Self.itemA },
                                             meta: o.meta, sync: o.sync))
        try s.run(s.owner)
        try s.run(s.member)
        XCTAssertTrue(s.member.store.trashIDs.contains(Self.itemA))
    }

    // MARK: members

    func test_approve_accepts_only_pending_ids_and_only_on_the_owner() throws {
        let s = try Share()
        try s.run(s.owner)
        try s.join(s.member, "Member PC")
        try s.run(s.member)
        try s.run(s.owner)
        let memberID = try s.deviceID(s.member)
        let ownerID = try s.deviceID(s.owner)
        XCTAssertEqual(try s.pendingNames(), ["Member PC"])
        let refused: [[String]] = [[], [ownerID], ["11111111-1111-4111-8111-111111111111"], [memberID, "x-unknown"]]
        for bad in refused {
            XCTAssertThrowsError(try ShareGroups.approve(store: s.owner.store, groupID: s.gid, deviceIDs: bad)) {
                XCTAssertEqual(Self.reason($0), "not-pending")
            }
        }
        XCTAssertThrowsError(try ShareGroups.approve(store: s.member.store, groupID: s.gid, deviceIDs: [memberID])) {
            XCTAssertEqual(Self.reason($0), "not-owner")
        }
        let approved = try ShareGroups.approve(store: s.owner.store, groupID: s.gid, deviceIDs: [memberID])
        XCTAssertEqual(approved.map(\.deviceID), [memberID])
        XCTAssertEqual(approved.first?.name, "Member PC")
        XCTAssertEqual(approved.first?.approved, true)
        XCTAssertEqual(try s.pendingNames(), [])
    }

    func test_a_join_racing_the_owners_approval_is_merged_not_frozen() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "shared", in: [s.cid])
        let second = Device("install-j2")
        try s.run(s.owner)
        try s.join(s.member, "J1")
        try s.run(s.member)
        try s.run(s.owner)                         // adopts J1's join
        try s.join(second, "J2")                   // J2 joins from the folder before the owner's approval is written
        try s.run(second)
        try ShareGroups.approve(store: s.owner.store, groupID: s.gid, deviceIDs: [try s.deviceID(s.member)])
        let report = try s.run(s.owner)
        XCTAssertTrue(Self.kinds(report).contains("keyring-merged"))
        XCTAssertFalse(Self.kinds(report).contains("tampered"))
        XCTAssertEqual(try s.pendingNames(), ["J2"], "the new joiner stays pending")
        for d in [s.member, second] { XCTAssertFalse(Self.kinds(try s.run(d)).contains("tampered")) }
        XCTAssertFalse(Self.kinds(try s.run(s.owner)).contains("tampered"))
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "shared")
        // J2 receives the share once the owner approves it too.
        try ShareGroups.approve(store: s.owner.store, groupID: s.gid, deviceIDs: [try s.deviceID(second)])
        try s.run(s.owner)
        try s.run(second)
        XCTAssertEqual(try Self.body(second, Self.itemA), "shared")
    }

    func test_two_people_joining_at_once_the_superseded_one_joins_again() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "shared", in: [s.cid])
        let second = Device("install-j2")
        try s.run(s.owner)
        try s.join(s.member, "J1")
        try s.join(second, "J2")                   // both read the same keyring
        try s.run(s.member)
        let report = try s.run(second)
        XCTAssertTrue(Self.kinds(report).contains("superseded"))
        XCTAssertFalse(Self.kinds(report).contains("tampered"))
        XCTAssertFalse(Self.kinds(try s.run(s.owner)).contains("tampered"))
        XCTAssertEqual(try s.pendingNames(), ["J1"])
        // Join again: the same group and collection, a new place in the folder keyring.
        let raw = try XCTUnwrap(s.folder.files[FolderLayout.keyringPath])
        _ = try ShareGroups.rejoin(store: second.store, groupID: s.gid, keyring: raw, password: Self.pw,
                                   deviceName: "J2", installID: second.install, isPro: true, random: Self.random,
                                   clock: s.tick(), derive: Self.cheap)
        XCTAssertEqual(try ShareGroups.list(in: try second.store.load()).map(\.groupID), [s.gid])
        XCTAssertEqual(CollectionCatalog.collections(in: try second.store.load()).count, 1)
        let again = Self.kinds(try s.run(second))
        XCTAssertFalse(again.contains("superseded") || again.contains("tampered"))
        try s.run(s.owner)
        XCTAssertEqual(try s.pendingNames(), ["J1", "J2"])
        try ShareGroups.approve(store: s.owner.store, groupID: s.gid, deviceIDs: try s.pendingIDs())
        try s.run(s.owner)
        try s.run(second)
        XCTAssertEqual(try Self.body(second, Self.itemA), "shared")
    }

    func test_forged_member_changes_are_refused_and_the_trusted_keyring_is_written_back() throws {
        let s = try Share()
        try s.run(s.owner)
        let creation = try XCTUnwrap(s.folder.files[FolderLayout.keyringPath])   // owner only, owner-signed
        try s.connect()
        let trusted = try XCTUnwrap(try s.record(s.owner).state.keyring)
        // A member puts back an older owner-signed keyring of the same epoch: it drops an approved member.
        XCTAssertThrowsError(try ShareGroups.adopt(store: s.member.store, groupID: s.gid, keyring: creation)) {
            XCTAssertEqual(Self.reason($0), "tampered")
        }
        s.folder.files[FolderLayout.keyringPath] = creation
        let report = try s.run(s.owner)
        XCTAssertTrue(Self.kinds(report).contains("keyring-restored"))
        XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], trusted)
        XCTAssertEqual(try s.record(s.owner).state.members.count, 2, "nobody was dropped")
        // A member never writes over another group's keyring; the owner writes its own back (final review finding 1).
        let other = try Share()
        try other.run(other.owner)
        s.folder.files[FolderLayout.keyringPath] = try XCTUnwrap(other.folder.files[FolderLayout.keyringPath])
        XCTAssertEqual(Self.kinds(try s.run(s.member)), ["folder-has-other-group"])
        XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], other.folder.files[FolderLayout.keyringPath])
        // Said apart from a plain repair (final review A1), so two owners in one folder show up.
        XCTAssertTrue(Self.kinds(try s.run(s.owner)).contains("other-group-replaced"))
        XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], trusted)
        XCTAssertEqual(Self.kinds(try s.run(s.member)), [])
    }

    // MARK: final fix wave A, finding 1 (anyone with write access to the folder froze the share)

    /// One byte of `password_wrap.ct` flipped (no group key needed: the MAC then fails); re-MACed under `gk` if given.
    static func flippedPasswordWrap(_ raw: [UInt8], key gk: GroupKey? = nil) throws -> [UInt8] {
        guard case .object(var ring) = try CanonicalJSON.parse(raw), case .object(var wrap)? = ring["password_wrap"],
              case .string(let text)? = wrap["ct"] else { throw KeyringError("bad-keyring", "test keyring") }
        var ct = try Base64.decodeStrict(text)
        ct[0] ^= 1
        wrap["ct"] = .string(Base64.encode(ct))
        ring["password_wrap"] = .object(wrap)
        let out: JSONValue
        if let gk { out = try Keyring.finish(ring, key: gk) } else { out = .object(ring) }
        return try CanonicalJSON.encode(out, dialect: .utf8)
    }

    /// The owner edits the shared item and the member receives the edit.
    func ownerEditReachesMember(_ s: Share, _ text: String) throws -> Bool {
        try Self.put(s.owner, Self.itemA, "A", body: text, in: [s.cid], at: s.clock + 100)
        try s.run(s.owner)
        try s.run(s.member)
        return try Self.body(s.member, Self.itemA) == text
    }

    func test_a_flipped_byte_in_the_password_wrap_is_restored_by_the_owner_then_the_share_syncs() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "v1", in: [s.cid])
        try s.connect()
        let trusted = try XCTUnwrap(try s.record(s.owner).state.keyring)
        s.folder.files[FolderLayout.keyringPath] = try Self.flippedPasswordWrap(trusted)
        let report = Self.kinds(try s.run(s.owner))
        XCTAssertTrue(report.contains("keyring-restored") && !report.contains("tampered"), "\(report)")
        XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], trusted)
        XCTAssertEqual(Self.kinds(try s.run(s.member)), [])
        XCTAssertTrue(try ownerEditReachesMember(s, "v2"))
    }

    func test_a_member_restores_a_keyring_of_its_epoch_that_does_not_authenticate() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "v1", in: [s.cid])
        try s.connect()
        let trusted = try XCTUnwrap(try s.record(s.owner).state.keyring)
        s.folder.files[FolderLayout.keyringPath] = try Self.flippedPasswordWrap(trusted)
        let report = Self.kinds(try s.run(s.member))   // the member runs first
        XCTAssertTrue(report.contains("keyring-restored") && !report.contains("tampered"), "\(report)")
        XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], trusted)
        XCTAssertFalse(Self.kinds(try s.run(s.owner)).contains("tampered"))
        XCTAssertTrue(try ownerEditReachesMember(s, "v2"))
    }

    func test_the_owner_restores_over_bytes_that_do_not_parse_or_a_forged_later_epoch() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "v1", in: [s.cid])
        try s.connect()
        let trusted = try XCTUnwrap(try s.record(s.owner).state.keyring)
        for garbage in ["{}", "not json", "{\"group_id\":\"x\"}"].map({ Array($0.utf8) }) {
            s.folder.files[FolderLayout.keyringPath] = garbage
            // A member cannot tell what the folder should hold: it stops and writes nothing.
            let stopped = Self.kinds(try s.run(s.member))
            XCTAssertTrue(stopped == ["keyring-corrupt"] || stopped == ["folder-has-other-group"], "\(stopped)")
            XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], garbage)
            let restored = Self.kinds(try s.run(s.owner))
            // A keyring naming another group is said apart (final review A1).
            XCTAssertTrue(restored.contains("keyring-restored")
                          || (restored.contains("other-group-replaced") && stopped == ["folder-has-other-group"]), "\(restored)")
            XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], trusted)
        }
        // A later epoch nobody but the owner could sign (the owner signature covers the epoch).
        guard case .object(var ahead) = try CanonicalJSON.parse(trusted) else { return XCTFail("keyring") }
        ahead["epoch"] = .int(6)
        s.folder.files[FolderLayout.keyringPath] = try CanonicalJSON.encode(.object(ahead), dialect: .utf8)
        let report = Self.kinds(try s.run(s.owner))
        XCTAssertTrue(report.contains("keyring-restored") && !report.contains("rejoin-required"), "\(report)")
        XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], trusted)
        XCTAssertTrue(try ownerEditReachesMember(s, "v2"))
    }

    func test_a_members_rewrite_of_the_password_wrap_is_restored_by_any_device() throws {
        // A member holds G and can re-MAC a keyring that swaps the password wrap. In share v2 the owner signature
        // covers the password wrap (audit 2026-11-12 F-01), so it does not authenticate: a member's run puts its
        // trusted keyring back, and so does the owner's.
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "v1", in: [s.cid])
        try s.connect()
        let trusted = try XCTUnwrap(try s.record(s.owner).state.keyring)
        let memberKey = try s.record(s.member).state.groupKey()
        let forged = try Self.flippedPasswordWrap(trusted, key: memberKey)
        s.folder.files[FolderLayout.keyringPath] = forged
        XCTAssertTrue(Self.kinds(try s.run(s.member)).contains("keyring-restored"))
        XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], trusted)
        s.folder.files[FolderLayout.keyringPath] = forged
        XCTAssertTrue(Self.kinds(try s.run(s.owner)).contains("keyring-restored"))
        XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], trusted)
        XCTAssertTrue(try ownerEditReachesMember(s, "v2"))
    }

    // MARK: final fix wave B, A2 (a lapsed owner still repairs the keyring)

    func test_a_lapsed_owner_still_puts_a_damaged_keyring_back_and_syncs_nothing() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "v1", in: [s.cid])
        try s.connect()
        let trusted = try XCTUnwrap(try s.record(s.owner).state.keyring)
        s.folder.files[FolderLayout.keyringPath] = try Self.flippedPasswordWrap(trusted)
        s.owner.isPro = false
        let views = s.folder.files.filter { $0.key.hasPrefix("LocalGateKeys Sync/devices/") }
        try Self.put(s.owner, Self.itemA, "A", body: "v2", in: [s.cid], at: s.clock + 100)
        XCTAssertEqual(Self.kinds(try s.run(s.owner)), ["keyring-restored", "pro-required"])
        XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], trusted)
        XCTAssertEqual(s.folder.files.filter { $0.key.hasPrefix("LocalGateKeys Sync/devices/") }, views, "no view written without Pro")
        s.owner.isPro = true
        XCTAssertTrue(try ownerEditReachesMember(s, "v3"))
    }

    // MARK: final fix wave B, parked: the 64 KiB folder-reference cap (as lgk-core)

    func test_a_folder_reference_too_large_is_refused_by_create_join_and_set_folder_before_anything_is_written() throws {
        let s = try Share()
        try s.run(s.owner)
        let other = try Self.collection(s.owner, "Work")
        let big = [UInt8](repeating: 0, count: ShareRecord.maxFolderBytes + 1)
        let before = try s.owner.store.load()
        XCTAssertThrowsError(try ShareGroups.create(store: s.owner.store, collectionID: other, password: Self.pw,
                                                    deviceName: "PC", sharedMode: "edit", installID: s.owner.install,
                                                    isPro: true, folder: big, random: Self.random, clock: s.tick(),
                                                    derive: Self.cheap)) {
            XCTAssertEqual(Self.reason($0), "bad-folder")
        }
        XCTAssertEqual(try s.owner.store.load(), before)
        let raw = try XCTUnwrap(s.folder.files[FolderLayout.keyringPath])
        XCTAssertThrowsError(try ShareGroups.join(store: s.member.store, keyring: raw, password: Self.pw,
                                                  deviceName: "Member", installID: s.member.install, isPro: true,
                                                  folder: big, random: Self.random, clock: s.tick(), derive: Self.cheap)) {
            XCTAssertEqual(Self.reason($0), "bad-folder")
        }
        XCTAssertNil(try s.member.store.load().shares)
        XCTAssertThrowsError(try ShareGroups.setFolder(store: s.owner.store, groupID: s.gid, folder: big)) {
            XCTAssertEqual(Self.reason($0), "bad-folder")
        }
        XCTAssertEqual(try s.owner.store.load(), before, "the stored share stays readable")
        XCTAssertNoThrow(try ShareGroups.setFolder(store: s.owner.store, groupID: s.gid,
                                                   folder: [UInt8](repeating: 1, count: ShareRecord.maxFolderBytes)))
        XCTAssertNoThrow(try ShareGroups.records(in: try s.owner.store.load()))
    }

    // MARK: final fix wave A, finding 2 (a pending member got every item before approval)

    func test_a_pending_member_adopts_the_keyring_but_merges_and_writes_nothing_until_approved() throws {
        for mode in ["read", "edit"] {
            let s = try Share(mode: mode)
            try Self.put(s.owner, Self.itemA, "A", body: "family wifi", in: [s.cid])
            try s.run(s.owner)
            try s.join(s.member, "Member PC")
            if mode == "edit" { try Self.put(s.member, Self.itemM, "M", body: "member text", in: [s.cid]) }
            let report = try s.run(s.member)
            XCTAssertTrue(Self.kinds(report).contains("awaiting-approval"), "\(mode) \(Self.kinds(report))")
            XCTAssertNil(report.ownStates)
            XCTAssertFalse(report.wrote)
            XCTAssertFalse(try Self.items(s.member).contains(Self.itemA), "\(mode): nothing arrives before approval")
            let ownFile = try XCTUnwrap(FolderLayout.deviceFile(try s.deviceID(s.member)))
            XCTAssertNil(s.folder.files[ownFile], "\(mode): no own view before approval")
            try s.run(s.owner)   // adopts the join (pending)
            XCTAssertEqual(try s.pendingNames(), ["Member PC"])
            XCTAssertFalse(try Self.items(s.owner).contains(Self.itemM))
            XCTAssertEqual(try s.record(s.owner).state.keyring, try s.record(s.member).state.keyring,
                           "\(mode): the keyring is adopted")
            try ShareGroups.approve(store: s.owner.store, groupID: s.gid, deviceIDs: try s.pendingIDs())
            try s.run(s.owner)
            XCTAssertFalse(Self.kinds(try s.run(s.member)).contains("awaiting-approval"))
            XCTAssertEqual(try Self.body(s.member, Self.itemA), "family wifi")
            if mode == "edit" {
                try s.run(s.owner)
                XCTAssertEqual(try Self.body(s.owner, Self.itemM), "member text")
            }
        }
    }

    // MARK: share v2 (cryptographic approval gating)

    func test_a_pending_member_has_no_content_key_and_cannot_open_the_owners_view_with_the_share_password() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "family wifi", in: [s.cid])
        try s.run(s.owner)
        try s.join(s.member, "Member PC")
        XCTAssertTrue(Self.kinds(try s.run(s.member)).contains("awaiting-approval"))
        let rec = try s.record(s.member)
        XCTAssertNil(try ShareGroups.viewKey(of: rec), "no content wrap before approval")
        // Ignoring the approval would not help: G (what the share password opens) does not open the owner's view.
        let ownerFile = try XCTUnwrap(s.folder.files[try XCTUnwrap(FolderLayout.deviceFile(try s.deviceID(s.owner)))])
        XCTAssertThrowsError(try ViewFile.decode(ownerFile, key: try rec.state.groupKey(), expectedDeviceID: try s.deviceID(s.owner)))
        let group = try ShareGroups.group(of: rec)
        XCTAssertEqual(group.version, 2)
        XCTAssertFalse(ShareGroups.needsUpgrade(in: try s.owner.store.load(), groupID: s.gid))
        XCTAssertFalse(ShareGroups.needsUpgrade(in: try s.member.store.load(), groupID: s.gid))
        try s.run(s.owner)
        try ShareGroups.approve(store: s.owner.store, groupID: s.gid, deviceIDs: try s.pendingIDs())
        try s.run(s.owner)
        XCTAssertFalse(Self.kinds(try s.run(s.member)).contains("awaiting-approval"))
        let key = try XCTUnwrap(try ShareGroups.viewKey(in: try s.member.store.load(), groupID: s.gid))
        XCTAssertEqual(key, try ShareGroups.viewKey(of: try s.record(s.owner)))
        XCTAssertNotEqual(key.key, try s.record(s.member).state.groupKey().key)
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "family wifi")
    }

    func test_a_share_v1_syncs_with_g_until_the_owner_upgrades_it_then_everyone_moves_to_v2() throws {
        let s = try Share(shareFormat: 2)
        try Self.put(s.owner, Self.itemA, "A", body: "v1", in: [s.cid])
        try s.connect()
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "v1")
        let owner = try s.record(s.owner)
        XCTAssertEqual(try ShareGroups.group(of: owner).version, 1)
        XCTAssertEqual(try ShareGroups.viewKey(of: owner), try owner.state.groupKey(), "share v1: views sealed with G")
        XCTAssertTrue(ShareGroups.needsUpgrade(in: try s.owner.store.load(), groupID: s.gid))
        XCTAssertFalse(ShareGroups.needsUpgrade(in: try s.member.store.load(), groupID: s.gid), "only the owner upgrades")
        // A third device joins and stays pending through the upgrade.
        let third = Device("install-third")
        try s.join(third, "Third PC")
        XCTAssertTrue(Self.kinds(try s.run(third)).contains("awaiting-approval"))
        try s.run(s.owner)
        XCTAssertEqual(try s.pendingNames(), ["Third PC"])

        XCTAssertThrowsError(try ShareGroups.upgrade(store: s.member.store, groupID: s.gid, password: Self.pw,
                                                     random: Self.random, derive: Self.cheap)) {
            XCTAssertEqual(Self.reason($0), "not-owner")
        }
        XCTAssertThrowsError(try ShareGroups.upgrade(store: s.owner.store, groupID: s.gid, password: "short",
                                                     random: Self.random, derive: Self.cheap)) {
            XCTAssertEqual(Self.reason($0), "weak-password")
        }
        // The current share password may stay (it no longer opens any item).
        let upgraded = try ShareGroups.upgrade(store: s.owner.store, groupID: s.gid, password: Self.pw, random: Self.random,
                                               derive: Self.cheap)
        XCTAssertEqual(upgraded.version, 2)
        XCTAssertEqual(upgraded.members.filter { !$0.approved }.map(\.name), ["Third PC"], "pending stays pending")
        XCTAssertFalse(ShareGroups.needsUpgrade(in: try s.owner.store.load(), groupID: s.gid))
        XCTAssertThrowsError(try ShareGroups.upgrade(store: s.owner.store, groupID: s.gid, password: Self.pw,
                                                     random: Self.random, derive: Self.cheap)) {
            XCTAssertEqual(Self.reason($0), "already-upgraded")
        }
        let ownerState = try s.record(s.owner).state
        XCTAssertEqual(ownerState.epoch, 2)
        XCTAssertEqual(Keyring.obj(try ShareKeyring.parse(try XCTUnwrap(ownerState.keyring)))["format"], .int(3))

        // The owner's run writes the new keyring; the approved member adopts it and syncs on without typing anything.
        try Self.put(s.owner, Self.itemA, "A", body: "v2", in: [s.cid], at: Self.t0 + 50)
        try s.run(s.owner)
        XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], try s.record(s.owner).state.keyring)
        XCTAssertFalse(Self.kinds(try s.run(s.member)).contains("awaiting-approval"))
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "v2")
        let memberKey = try XCTUnwrap(try ShareGroups.viewKey(of: try s.record(s.member)))
        XCTAssertNotEqual(memberKey.key, try s.record(s.member).state.groupKey().key)
        // The pending device adopts the new epoch but has no content key.
        XCTAssertTrue(Self.kinds(try s.run(third)).contains("awaiting-approval"))
        XCTAssertNil(try ShareGroups.viewKey(of: try s.record(third)))
        XCTAssertFalse(try Self.items(third).contains(Self.itemA))
        try ShareGroups.approve(store: s.owner.store, groupID: s.gid, deviceIDs: try s.pendingIDs())
        try s.run(s.owner)
        XCTAssertFalse(Self.kinds(try s.run(third)).contains("awaiting-approval"))
        XCTAssertEqual(try Self.body(third, Self.itemA), "v2")
    }

    func test_removing_a_member_from_a_share_v1_upgrades_it() throws {
        let s = try Share(shareFormat: 2)
        try Self.put(s.owner, Self.itemA, "A", body: "shared", in: [s.cid])
        try s.connect()
        _ = try ShareGroups.removeMember(store: s.owner.store, groupID: s.gid, deviceID: try s.deviceID(s.member),
                                         newPassword: Self.pw2, random: Self.random, clock: s.tick(), derive: Self.cheap)
        let owner = try s.record(s.owner)
        XCTAssertEqual(try ShareGroups.group(of: owner).version, 2)
        XCTAssertEqual(owner.state.epoch, 2)
        let key = try XCTUnwrap(try ShareGroups.viewKey(of: owner))
        XCTAssertNotEqual(key.key, try owner.state.groupKey().key)
        XCTAssertFalse(ShareGroups.needsUpgrade(in: try s.owner.store.load(), groupID: s.gid))
    }

    func test_a_keyring_of_a_newer_format_stops_the_run_and_is_never_overwritten() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "shared", in: [s.cid])
        try s.connect()
        guard case .object(var newer) = try CanonicalJSON.parse(try XCTUnwrap(s.folder.files[FolderLayout.keyringPath])) else {
            return XCTFail("keyring")
        }
        newer["format"] = .int(4)
        newer["epoch"] = .int(9)
        let raw = try CanonicalJSON.encode(.object(newer), dialect: .utf8)
        s.folder.files[FolderLayout.keyringPath] = raw
        for d in [s.owner, s.member] {
            XCTAssertEqual(Self.kinds(try s.run(d)), ["update-required"])
            XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], raw, "never written over")
        }
        XCTAssertFalse(try s.fs(s.owner).writeShareKeyring(store: s.owner.store, groupID: s.gid))
        XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], raw)
        // A free device still stops there (and says Pro ended).
        s.member.isPro = false
        XCTAssertEqual(Self.kinds(try s.run(s.member)), ["update-required", "pro-required"])
        XCTAssertEqual(s.folder.files[FolderLayout.keyringPath], raw)
    }

    // MARK: removal

    func test_removing_a_member_trashes_the_shared_items_only_and_the_rotation_is_not_for_it() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "shared", in: [s.cid])
        try s.connect()
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "shared")
        try Self.put(s.member, Self.itemP, "Mine", body: "member diary", in: [])
        let work = try Self.collection(s.member, "Work")
        try Self.put(s.member, Self.itemW, "Work", body: "work", in: [work])
        let memberID = try s.deviceID(s.member)
        let notice = try ShareGroups.removeMember(store: s.owner.store, groupID: s.gid, deviceID: memberID,
                                                  newPassword: Self.pw2, random: Self.random, clock: s.tick(),
                                                  derive: Self.cheap)
        XCTAssertEqual(try ShareGroups.removedMembers(in: try s.owner.store.load(), groupID: s.gid).map(\.name), ["Member PC"])
        // The owner's own device never acts on a notice.
        let ring = try XCTUnwrap(try s.record(s.owner).state.keyring)
        XCTAssertThrowsError(try ShareGroups.applyShareRemoval(store: s.owner.store, groupID: s.gid, notice: notice,
                                                               folderKeyring: ring, trash: ShareTrash(count: 0))) {
            XCTAssertEqual(Self.reason($0), "owner")
        }
        XCTAssertEqual(try Self.body(s.owner, Self.itemA), "shared")
        // The notice first, then the rotated keyring.
        XCTAssertTrue(try s.fs(s.owner).publishShareNotice(deviceID: memberID, notice: notice))
        try s.run(s.owner)
        let rotated = try XCTUnwrap(s.folder.files[FolderLayout.keyringPath])
        XCTAssertEqual(rotated, ring)
        XCTAssertThrowsError(try ShareGroups.adopt(store: s.member.store, groupID: s.gid, keyring: rotated)) {
            XCTAssertEqual(Self.reason($0), "not-member")
        }
        let report = try s.run(s.member)
        XCTAssertEqual(Self.kinds(report), ["share-removed"])
        XCTAssertEqual(report.issues.first?.detail, s.cid)
        XCTAssertEqual(try Self.items(s.member), [Self.itemP, Self.itemW])
        XCTAssertTrue(s.member.store.trashIDs.contains(Self.itemA))
        XCTAssertEqual(try ShareGroups.records(in: try s.member.store.load()), [:])
        XCTAssertEqual(try Self.body(s.owner, Self.itemA), "shared")
    }

    func test_a_rotation_without_a_notice_only_stops_the_member() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "shared", in: [s.cid])
        try s.connect()
        _ = try ShareGroups.removeMember(store: s.owner.store, groupID: s.gid, deviceID: try s.deviceID(s.member),
                                         newPassword: Self.pw2, random: Self.random, clock: s.tick(), derive: Self.cheap)
        try s.run(s.owner)
        XCTAssertEqual(Self.kinds(try s.run(s.member)), ["rejoin-required"])
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "shared")
    }

    /// The pinned owner is the only signer (desktop audit M10): another approved member, whose signing key this
    /// member's keyring lists, cannot remove it, even beside a real rotation that no longer lists it.
    func test_a_removal_notice_signed_by_anyone_but_the_owner_is_refused() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "shared", in: [s.cid])
        try s.connect()
        let third = Device("install-c")
        try s.join(third, "C")
        try s.run(third)
        try s.run(s.owner)
        try ShareGroups.approve(store: s.owner.store, groupID: s.gid, deviceIDs: try s.pendingIDs())
        try s.run(s.owner)
        try s.run(s.member)
        try s.run(third)
        let b = try s.record(s.member).state
        let c = try XCTUnwrap(ShareGroups.records(in: third.store.load())[s.gid]).state
        let approved = try ShareGroups.group(of: try s.record(s.owner)).members.filter(\.approved).map(\.deviceID)
        XCTAssertEqual(Set(approved), [try s.deviceID(s.owner), b.deviceID, c.deviceID])
        let bRing = try ShareKeyring.parse(try XCTUnwrap(b.keyring))
        XCTAssertNotNil(Keyring.memberSigningKeys(bRing)[c.deviceID], "B's keyring lists C's signing key")
        // The owner really removes B: the rotated keyring no longer lists B, so only the signer rules can refuse.
        let real = try ShareGroups.removeMember(store: s.owner.store, groupID: s.gid, deviceID: b.deviceID,
                                                newPassword: Self.pw2, random: Self.random, clock: s.tick(),
                                                derive: Self.cheap)
        let rotated = try XCTUnwrap(try s.record(s.owner).state.keyring)
        let byMember = try RemovalNotice.make(identity: c.identity, groupID: s.gid, deviceID: b.deviceID,
                                              epoch: b.epoch + 1, issuedAt: Self.t0)
        let strangerID = try DeviceIdentity.generate(random: Self.random)
        let stranger = try RemovalNotice.make(identity: strangerID, groupID: s.gid, deviceID: b.deviceID,
                                              epoch: b.epoch + 1, issuedAt: Self.t0)
        // `make` refuses a self-signed notice, so forge one as a dishonest device would.
        let selfBody = RemovalNoticeBody(groupID: s.gid, deviceID: b.deviceID, epoch: b.epoch + 1,
                                         signer: b.identity.deviceID, issuedAt: Self.t0)
        var selfObject = RemovalNotice.body(selfBody)
        selfObject["sig"] = .string(Base64.encode(try b.identity.sign(try RemovalNotice.message(selfBody))))
        let selfSigned = try CanonicalJSON.encode(.object(selfObject), dialect: .utf8)
        let cases: [([UInt8], String)] = [(byMember, "unknown-signer"), (stranger, "unknown-signer"), (selfSigned, "stale")]
        for (notice, why) in cases {
            XCTAssertThrowsError(try ShareGroups.applyShareRemoval(store: s.member.store, groupID: s.gid, notice: notice,
                                                                   folderKeyring: rotated, trash: ShareTrash(count: 0))) {
                XCTAssertEqual(($0 as? RemovalError)?.reason, why)
            }
        }
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "shared")
        XCTAssertNotNil(try ShareGroups.records(in: try s.member.store.load())[s.gid])
        // The owner's own notice beside the same keyring is accepted.
        XCTAssertEqual(try ShareGroups.applyShareRemoval(store: s.member.store, groupID: s.gid, notice: real,
                                                         folderKeyring: rotated, trash: ShareTrash(count: 0)), 1)
    }

    /// Desktop `test_removal_keeps_a_shared_document_that_a_personal_item_links`: documents leave after the items that
    /// link them, and one still linked from outside the collection stays.
    func test_removal_keeps_a_document_still_linked_from_outside_the_collection() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "shared", in: [s.cid])
        try s.connect()
        let docKept = "11111111-2222-4333-8444-555555555555"
        let docGone = "66666666-7777-4888-8999-aaaaaaaaaaaa"
        func document(_ id: String) -> JSONValue {
            Wrapper.make(ns: .item, record: .object(["id": .string(id), "kind": .string("document"), "title": .string("Doc"),
                                                    "created_at": .int(Self.t0), "updated_at": .int(Self.t0)]))
        }
        func linking(_ record: JSONValue, _ doc: String) -> JSONValue {
            guard case .object(var r) = record, case .object(var p)? = r["payload"] else { return record }
            p["document_ids"] = .array([.string(doc)])
            r["payload"] = .object(p)
            return .object(r)
        }
        let m = try s.member.store.load()
        var records = m.records
        records[docKept] = document(docKept)
        records[docGone] = document(docGone)
        for id in [docKept, docGone] {
            records[CollectionStates.membershipPrefix + id] = try CollectionCatalog.membershipWrapper(itemID: id, ids: [s.cid])
        }
        // The shared item A links one document (A leaves first, so it goes too); a personal note links the other.
        guard case .object(let wa)? = records[Self.itemA], let ra = wa["record"] else { return XCTFail() }
        records[Self.itemA] = Wrapper.make(ns: .item, record: linking(ra, docGone))
        records[Self.itemP] = Wrapper.make(ns: .item, record: linking(Self.noteRecord(Self.itemP, "Mine", body: "diary",
                                                                                     at: Self.t0), docKept))
        try s.member.store.commit(StoreChange(baseRevision: m.revision, records: records, meta: m.meta, sync: m.sync))
        let notice = try ShareGroups.removeMember(store: s.owner.store, groupID: s.gid, deviceID: try s.deviceID(s.member),
                                                  newPassword: Self.pw2, random: Self.random, clock: s.tick(),
                                                  derive: Self.cheap)
        let ring = try XCTUnwrap(try s.record(s.owner).state.keyring)
        XCTAssertEqual(try ShareGroups.applyShareRemoval(store: s.member.store, groupID: s.gid, notice: notice,
                                                         folderKeyring: ring, trash: ShareTrash(count: 0)), 2)
        XCTAssertEqual(try Self.items(s.member), [Self.itemP, docKept])
        XCTAssertEqual(s.member.store.trashIDs, [Self.itemA, docGone])
    }

    func test_a_share_commit_on_a_changed_vault_or_outside_the_collection_is_refused() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "shared", in: [s.cid])
        try Self.put(s.owner, Self.itemP, "Personal", body: "diary", in: [])
        let shareStore = ShareItemStore(base: s.owner.store, groupID: s.gid, trash: ShareTrash(count: 0))
        let view = try shareStore.load()
        XCTAssertEqual(Set(view.records.keys), [Self.itemA])
        // A personal id in the result never reaches the vault.
        var records = view.records
        var forged = Self.noteRecord(Self.itemP, "X", body: "overwritten", at: Self.t0)
        if case .object(var r) = forged {
            r["tags"] = nil; r["favorite"] = nil; r["collection_ids"] = .array([.string(s.cid)])
            forged = .object(r)
        }
        records[Self.itemP] = Wrapper.make(ns: .item, record: forged)
        XCTAssertThrowsError(try shareStore.commit(StoreChange(baseRevision: view.revision, records: records,
                                                               meta: view.meta, sync: view.sync))) {
            XCTAssertEqual(Self.reason($0), "bad-remote")
        }
        XCTAssertEqual(try Self.body(s.owner, Self.itemP), "diary")
        try Self.put(s.owner, Self.itemA, "A", body: "edited meanwhile", in: [s.cid], at: Self.t0 + 9)
        XCTAssertThrowsError(try shareStore.commit(StoreChange(baseRevision: view.revision, records: view.records,
                                                               meta: view.meta, sync: view.sync))) {
            XCTAssertEqual(Self.reason($0), "store-changed")
        }
        XCTAssertEqual(try Self.body(s.owner, Self.itemA), "edited meanwhile")
    }

    func test_a_full_trash_refuses_the_removal_and_changes_nothing() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "shared", in: [s.cid])
        try s.connect()
        let memberID = try s.deviceID(s.member)
        let notice = try ShareGroups.removeMember(store: s.owner.store, groupID: s.gid, deviceID: memberID,
                                                  newPassword: Self.pw2, random: Self.random, clock: s.tick(),
                                                  derive: Self.cheap)
        let ring = try XCTUnwrap(try s.record(s.owner).state.keyring)
        XCTAssertThrowsError(try ShareGroups.applyShareRemoval(store: s.member.store, groupID: s.gid, notice: notice,
                                                               folderKeyring: ring,
                                                               trash: ShareTrash(count: LocalData.maxTrash))) {
            XCTAssertEqual(Self.reason($0), "trash-full")
        }
        XCTAssertThrowsError(try ShareGroups.applyShareRemoval(store: s.member.store, groupID: s.gid, notice: notice,
                                                               folderKeyring: ring, trash: ShareTrash(count: nil))) {
            XCTAssertEqual(Self.reason($0), "item-error")
        }
        XCTAssertEqual(try Self.body(s.member, Self.itemA), "shared")
        XCTAssertEqual(try ShareGroups.applyShareRemoval(store: s.member.store, groupID: s.gid, notice: notice,
                                                         folderKeyring: ring, trash: ShareTrash(count: 0)), 1)
    }

    // MARK: Pro

    struct DerivationCalled: Error {}

    func test_a_free_device_cannot_create_join_or_sync_but_can_remove_and_leave() throws {
        let never: Keyring.KeyDerivation = { _, _ in throw DerivationCalled() }
        let s = try Share()
        try s.run(s.owner)
        let raw = try XCTUnwrap(s.folder.files[FolderLayout.keyringPath])
        let free = Device("install-free")
        let mine = try Self.collection(free, "Mine")
        XCTAssertThrowsError(try ShareGroups.create(store: free.store, collectionID: mine, password: Self.pw, deviceName: "Free",
                                                    sharedMode: "edit", installID: free.install, isPro: false, folder: nil,
                                                    random: Self.random, clock: s.tick(), derive: never)) {
            XCTAssertTrue($0 is ShareProRequiredError, "refused before any key derivation")
        }
        XCTAssertThrowsError(try ShareGroups.join(store: free.store, keyring: raw, password: Self.pw, deviceName: "Free",
                                                  installID: free.install, isPro: false, folder: nil, random: Self.random,
                                                  clock: s.tick(), derive: never)) {
            XCTAssertTrue($0 is ShareProRequiredError)
        }
        XCTAssertNil(try free.store.load().shares)
        // A share whose Pro lapsed stops syncing and writes nothing, but removing and leaving still work.
        try s.connect()
        s.owner.isPro = false
        let before = s.folder.files
        XCTAssertEqual(Self.kinds(try s.run(s.owner)), ["pro-required"])
        XCTAssertEqual(s.folder.files, before)
        _ = try ShareGroups.removeMember(store: s.owner.store, groupID: s.gid, deviceID: try s.deviceID(s.member),
                                         newPassword: Self.pw2, random: Self.random, clock: s.tick(), derive: Self.cheap)
        s.member.isPro = false
        try ShareGroups.leave(store: s.member.store, groupID: s.gid)
        XCTAssertEqual(try ShareGroups.records(in: try s.member.store.load()), [:])
        XCTAssertEqual(CollectionCatalog.collections(in: try s.member.store.load()).map(\.id), [s.cid], "the collection stays")
    }

    // MARK: secrets

    func test_share_secrets_never_reach_the_personal_view_a_backup_or_a_description() throws {
        let s = try Share()
        try Self.put(s.owner, Self.itemA, "A", body: "shared", in: [s.cid])
        try s.connect()
        for d in [s.owner, s.member] {
            let snap = try d.store.load()
            let rec = try XCTUnwrap(try ShareGroups.records(in: snap)[s.gid])
            let secrets = [Base64.encode(rec.state.key), Base64.encode(rec.state.identity.signingPrivateKey),
                           Base64.encode(rec.state.identity.exchangePrivateKey), s.gid, rec.state.deviceID]
            // The personal view (what personal sync and the encrypted backup carry), collections on.
            let view = try SyncMeta.localView(records: snap.records, meta: snap.meta, device: "personal-device", now: Self.t0,
                                              collections: true, shares: ShareGroups.collectionShares(in: snap))
            let text = String(decoding: try CanonicalJSON.encode(
                .array(view.states.values.compactMap(\.item)), dialect: .utf8), as: UTF8.self)
            for secret in secrets { XCTAssertFalse(text.contains(secret)) }
            // Only the link (mode and role) says the collection is shared.
            let link = try XCTUnwrap(view.states[CollectionStates.linkPrefix + s.cid]?.item)
            guard case .object(let w) = link, case .object(let r)? = w["record"] else { return XCTFail() }
            XCTAssertEqual(Set(r.keys), ["kind", "collection_id", "mode", "role"])
            XCTAssertNil(view.states.keys.first { $0.contains(s.gid) })
            // Never in a description either.
            let group = try ShareGroups.group(of: rec)
            let described = "\(rec) \(group) \(ShareGroupError("x", "y"))"
            for secret in secrets.prefix(3) { XCTAssertFalse(described.contains(secret)) }
            XCTAssertFalse(described.contains("Family"))
        }
    }

    // MARK: stored shape

    func test_stored_share_groups_are_checked_and_a_damaged_one_fails_closed() throws {
        let s = try Share(mode: "read")
        try s.connect()
        let snap = try s.member.store.load()
        let decoded = try ShareGroups.records(in: snap)
        XCTAssertEqual(ShareRecord.encode(decoded), snap.shares, "the stored shape round-trips")
        XCTAssertEqual(ShareGroups.shareLinks(in: snap), [s.cid: CollectionShares.Link(mode: "read", role: "member")])
        guard case .object(var groups)? = snap.shares, case .object(var rec)? = groups[s.gid] else { return XCTFail() }
        var cases: [JSONValue] = []
        rec["shared_mode"] = .string("edit"); cases.append(.object(rec))          // not what the keyring pins
        rec["shared_mode"] = .string("read"); rec["role"] = .string("owner"); cases.append(.object(rec))  // not the owner
        rec["role"] = .string("member"); rec["extra"] = .bool(true); cases.append(.object(rec))
        for bad in cases {
            groups[s.gid] = bad
            var damaged = snap
            damaged.shares = .object(groups)
            XCTAssertThrowsError(try ShareGroups.records(in: damaged)) { XCTAssertEqual(Self.reason($0), "bad-state") }
            XCTAssertEqual(ShareGroups.readOnlyCollectionIDs(in: damaged), [s.cid], "fails closed")
            XCTAssertNil(ShareGroups.shareLinks(in: damaged))
            XCTAssertTrue(ShareGroups.protectedCollectionIDs(in: damaged).contains(s.cid))
        }
        var garbage = snap
        garbage.shares = .string("damaged")
        XCTAssertEqual(ShareGroups.readOnlyCollectionIDs(in: garbage), [s.cid], "unreadable: every collection")
    }

    func test_create_and_join_refusals() throws {
        let s = try Share()
        try s.run(s.owner)
        let raw = try XCTUnwrap(s.folder.files[FolderLayout.keyringPath])
        func create(_ d: Device, _ cid: String) throws {
            _ = try ShareGroups.create(store: d.store, collectionID: cid, password: Self.pw, deviceName: "PC",
                                       sharedMode: "edit", installID: d.install, isPro: true, folder: nil,
                                       random: Self.random, clock: s.tick(), derive: Self.cheap)
        }
        XCTAssertThrowsError(try create(s.owner, s.cid)) { XCTAssertEqual(Self.reason($0), "already-shared") }
        XCTAssertThrowsError(try create(s.owner, "99999999-9999-4999-8999-999999999999")) {
            XCTAssertEqual(Self.reason($0), "no-collection")
        }
        XCTAssertThrowsError(try s.join(s.owner, "Again")) { XCTAssertEqual(Self.reason($0), "already-joined") }
        // A vault that already has the collection (by id) never marks it shared.
        let clash = Device("install-clash")
        let s0 = try clash.store.load()
        var records = s0.records
        records[CollectionStates.catalogPrefix + s.cid] = try CollectionCatalog.catalogWrapper(
            id: s.cid, name: "Mine", description: "", createdAt: Self.t0, updatedAt: Self.t0)
        try clash.store.commit(StoreChange(baseRevision: s0.revision, records: records, meta: s0.meta, sync: s0.sync))
        XCTAssertThrowsError(try s.join(clash, "Clash")) { XCTAssertEqual(Self.reason($0), "collection-exists") }
        XCTAssertNil(try clash.store.load().shares)
        // A wrong password changes nothing.
        let wrong = Device("install-wrong")
        XCTAssertThrowsError(try ShareGroups.join(store: wrong.store, keyring: raw, password: "not the share password at all 9",
                                                  deviceName: "W", installID: wrong.install, isPro: true, folder: nil,
                                                  random: Self.random, clock: s.tick(), derive: Self.cheap))
        XCTAssertEqual(try wrong.store.load(), StoreSnapshot())
        // A name clash keeps both collections.
        let named = Device("install-named")
        _ = try Self.collection(named, "Family")
        try s.join(named, "Named")
        XCTAssertEqual(CollectionCatalog.collections(in: try named.store.load()).map(\.name).sorted(), ["Family", "Family (2)"])
    }
}
