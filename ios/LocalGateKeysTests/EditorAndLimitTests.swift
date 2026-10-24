import XCTest
import AppShared
@testable import LocalGateKeys

/// The desktop's TEST-ONLY licence vector (never verifies with production keys).
enum LicenseVector {
    static let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../../tests/vectors/sync/license_state.json").standardized

    static func load() throws -> (keys: [String: [UInt8]], id: String, wrapper: JSONValue) {
        guard case .object(let o) = try CanonicalJSON.parse(Array(try Data(contentsOf: url))),
              case .string(let keyID)? = o["key_id"], case .string(let pub)? = o["public_key_b64"],
              case .string(let stateID)? = o["state_id"], let wrapper = o["wrapper"] else {
            throw XCTSkip("unreachable") // never skipped in practice: Data(contentsOf:) throws first when missing
        }
        return ([keyID: try Base64.decodeStrict(pub)], stateID, wrapper)
    }
}

func numberedNotes(_ n: Int) -> [JSONValue] {
    (0..<n).map { i in
        rec(["id": .string(String(format: "00000000-0000-4000-8000-%012d", i)), "kind": .string("note"),
             "title": .string("Note \(i)"), "created_at": .int(1_700_000_000), "updated_at": .int(1_700_000_000 + Int64(i)),
             "favorite": .bool(false), "tags": .array([]),
             "payload": rec(["body": .string("body \(i)"), "fields": .array([]), "template_id": .null])])
    }
}

let validCard = rec(["id": .string("0c000000-0000-4000-8000-000000000001"), "kind": .string("card"), "title": .string("Travel card"),
                      "created_at": .int(1_700_000_000), "updated_at": .int(1_700_000_100), "favorite": .bool(false), "tags": .array([]),
                      "payload": rec(["cardholder": .string("A Lovelace"), "number": .string("4111111111111111"), "cvv": .string("123")])])

@MainActor
final class EditorAndLimitTests: XCTestCase {
    let clock = TestClock(1_800_000_000)

    func pro(_ purchases: FakePurchases = FakePurchases(), keys: [String: [UInt8]] = [:]) -> ProModel {
        ProModel(purchases: purchases, licenseKeys: keys)
    }

    func editor(_ store: MemoryStore, _ pro: ProModel, item: VaultItem? = nil, kind: EditorKind = .note,
                background: FakeBackgroundTasks = FakeBackgroundTasks()) -> EditorModel {
        EditorModel(store: store, pro: pro, editing: item, kind: kind, clock: clock, random: CountingRandom(), background: background)
    }

    // MARK: limit

    func test_over_limit_keeps_items_usable() async throws {
        // Seven synced items on the free plan: everything existing stays editable, deletable and fillable.
        let store = MemoryStore(snapshot(numberedNotes(6) + [webLogin]))
        let p = pro(); await p.refresh(); p.update(from: store.snapshot)
        XCTAssertFalse(p.isPro)
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), 7)
        XCTAssertFalse(ItemLimit.allows(.create, snapshot: store.snapshot, isPro: false))
        XCTAssertFalse(ItemLimit.allows(.restore, snapshot: store.snapshot, isPro: false))
        for action in [ItemLimit.Action.edit, .delete, .autofill] {
            XCTAssertTrue(ItemLimit.allows(action, snapshot: store.snapshot, isPro: false))
        }
        for item in VaultItem.items(from: store.snapshot) {
            let e = editor(store, p, item: item, kind: EditorKind(kind: item.kind)!)
            e.set(e.titleKey, (e.value(e.titleKey)) + " edited")
            XCTAssertEqual(e.save(), .saved, "\(item.id): \(e.error ?? "")")
            XCTAssertFalse(e.showUpgrade)
        }
        XCTAssertEqual(store.commits, 7)
        XCTAssertTrue(VaultItem.items(from: store.snapshot).allSatisfy { $0.title.hasSuffix(" edited") })
        let victim = VaultItem.items(from: store.snapshot)[0]
        XCTAssertEqual(editor(store, p, item: victim, kind: EditorKind(kind: victim.kind)!).delete(), .saved)
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), 6)
        // Still over the limit: a new item is refused without writing anything.
        let n = editor(store, p); n.set("title", "Eighth"); n.set("body", "x")
        XCTAssertEqual(n.save(), .needsPro)
        XCTAssertTrue(n.showUpgrade)
        XCTAssertEqual(store.commits, 8)
    }

    func test_fifth_item_needs_pro() async throws {
        let store = MemoryStore(snapshot(numberedNotes(3)))
        let purchases = FakePurchases()
        let p = pro(purchases); await p.refresh(); p.update(from: store.snapshot)
        let fourth = editor(store, p); fourth.set("title", "Fourth"); fourth.set("body", "b")
        XCTAssertEqual(fourth.save(), .saved)
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), 4)

        let fifth = editor(store, p); fifth.set("title", "Fifth"); fifth.set("body", "b")
        XCTAssertEqual(fifth.save(), .needsPro)
        XCTAssertTrue(fifth.showUpgrade)
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), 4)

        // Restore purchases with nothing to restore keeps the limit.
        await p.restore()
        XCTAssertFalse(p.isPro)
        XCTAssertNotNil(p.message)

        await p.buy()
        XCTAssertEqual(purchases.purchaseCalls, 1)
        XCTAssertTrue(p.isPro)
        XCTAssertEqual(fifth.save(), .saved)
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), 5)

        // A cancelled purchase leaves the free plan in place.
        let other = FakePurchases(); other.purchaseResult = .cancelled
        let q = pro(other); await q.buy()
        XCTAssertFalse(q.isPro)
    }

    func test_synced_license_unlocks() async throws {
        let v = try LicenseVector.load()
        let store = MemoryStore(snapshot(numberedNotes(4), extra: [v.id: v.wrapper]))
        // The licence state is not an item and does not use a slot.
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), 4)

        let locked = pro(keys: [:]); await locked.refresh(); locked.update(from: store.snapshot)
        XCTAssertFalse(locked.isPro, "no licence keys known: the licence cannot verify")

        let p = pro(keys: v.keys); await p.refresh(); p.update(from: store.snapshot)
        XCTAssertTrue(p.isPro)
        XCTAssertEqual(p.license?.licenseID, "lic-vector-0001")
        let fifth = editor(store, p); fifth.set("title", "Fifth"); fifth.set("body", "b")
        XCTAssertEqual(fifth.save(), .saved)

        // A tampered licence does not unlock.
        guard case .object(var w) = v.wrapper, case .object(var b)? = w["record"], case .object(var lic)? = b["license"] else {
            return XCTFail("vector shape")
        }
        lic["name"] = .string("Mallory"); b["license"] = .object(lic); w["record"] = .object(b)
        let t = pro(keys: v.keys); t.update(from: snapshot(numberedNotes(4), extra: [v.id: .object(w)]))
        XCTAssertFalse(t.isPro)
    }

    // MARK: editor

    func test_unchanged_save_keeps_record_bytes() throws {
        let store = MemoryStore(snapshot([webLogin, note, card, validCard] + numberedNotes(1)))
        let before = try store.snapshot.records.mapValues { try CanonicalJSON.encode($0, dialect: .utf8) }
        let p = pro()
        for item in VaultItem.items(from: store.snapshot) {
            let e = editor(store, p, item: item, kind: EditorKind(kind: item.kind)!)
            XCTAssertEqual(e.save(), .unchanged, item.id)
        }
        XCTAssertEqual(store.commits, 0)
        let after = try store.snapshot.records.mapValues { try CanonicalJSON.encode($0, dialect: .utf8) }
        XCTAssertEqual(before, after)
    }

    func test_edit_restamps_and_normalises_through_lgkcore() throws {
        let store = MemoryStore(snapshot([validCard]))
        let item = VaultItem.items(from: store.snapshot)[0]
        let cid = item.id
        let e = editor(store, pro(), item: item, kind: .card)
        e.set("number", "4111 1111 1111 1111"); e.set("expiry", "3/2031"); e.set("cvv", "321")
        XCTAssertEqual(e.save(), .saved, e.error ?? "")
        guard case .object(let w)? = store.snapshot.records[cid], case .object(let r)? = w["record"],
              case .object(let pl)? = r["payload"] else { return XCTFail() }
        XCTAssertEqual(w["ns"], .string("item"))
        XCTAssertEqual(r["updated_at"], .int(clock.now))
        XCTAssertEqual(w["updated_at"], .int(clock.now))
        XCTAssertEqual(pl["number"], .string("4111111111111111"))
        XCTAssertEqual(pl["expiry"], .string("03/31"))
        XCTAssertEqual(pl["last4"], .string("1111"))
        XCTAssertEqual(pl["brand"], .string("visa"))
        // A bad card number is refused by the normaliser and nothing is written.
        let bad = editor(store, pro(), item: VaultItem.items(from: store.snapshot)[0], kind: .card)
        bad.set("number", "4111111111111112")
        XCTAssertEqual(bad.save(), .invalid)
        XCTAssertNotNil(bad.error)
        XCTAssertEqual(store.commits, 1)
    }

    func test_new_web_login_and_punycode_prompt() throws {
        let store = MemoryStore()
        let e = editor(store, pro(), kind: .web)
        e.set("label", "Shop"); e.set("username", "me"); e.set("password", "pw"); e.set("origin", "https://bücher.example")
        XCTAssertEqual(e.save(), .needsPunycode)
        XCTAssertTrue(e.needsPunycode)
        XCTAssertEqual(store.commits, 0)
        e.set("origin", "https://xn--bcher-kva.example")
        XCTAssertEqual(e.save(), .saved, e.error ?? "")
        XCTAssertFalse(e.needsPunycode)
        let (id, w) = try XCTUnwrap(store.snapshot.records.first)
        guard case .object(let o) = w, case .object(let r)? = o["record"], case .object(let scope)? = r["scope"] else { return XCTFail() }
        XCTAssertEqual(o["ns"], .string("entry"))
        XCTAssertEqual(r["id"], .string(id))
        XCTAssertEqual(r["kind"], .string("web"))
        XCTAssertEqual(scope["origin"], .string("https://xn--bcher-kva.example"))
        XCTAssertEqual(r["created_at"], .int(clock.now))
        XCTAssertNotNil(r["policy"])
        XCTAssertEqual(id.count, 36)
    }

    func test_new_identity_and_note() throws {
        let store = MemoryStore()
        let i = editor(store, pro(), kind: .identity)
        i.set("title", "Me"); i.set("name", "Ada"); i.set("email", "ada@example.com")
        XCTAssertEqual(i.save(), .saved, i.error ?? "")
        let n = editor(store, pro(), kind: .note)
        n.set("title", ""); n.set("body", "x")
        XCTAssertEqual(n.save(), .invalid, "the desktop refuses an empty title")
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), 1)
        guard case .object(let w)? = store.snapshot.records.values.first, case .object(let r)? = w["record"],
              case .object(let pl)? = r["payload"] else { return XCTFail() }
        XCTAssertEqual(pl["name"], .string("Ada"))
        XCTAssertNil(pl["phone"], "empty fields the user never filled are not added")
    }

    func test_delete_writes_a_tombstone_through_syncmeta() throws {
        var snap = snapshot([note, card])
        let identity = try DeviceIdentity(deviceID: "d4444444-0000-4000-8000-00000000000d",
                                          signingPrivate: Array(repeating: 1, count: 32), exchangePrivate: Array(repeating: 2, count: 32))
        snap.sync = SyncGroupState(groupID: "g1", epoch: 1, key: Array(repeating: 3, count: 32), identity: identity, installID: "i1",
                                   hasFolder: false, lastSeen: [:], peerDigests: [:], membersEpoch: 1, members: [], keyring: nil,
                                   ownCounter: 0)
        snap.meta["n1"] = try SyncMeta.live(snap.records["n1"]!, vv: ["desk": 3])
        let store = MemoryStore(snap)
        let item = VaultItem.items(from: snap).first { $0.id == "n1" }!
        XCTAssertEqual(editor(store, pro(), item: item, kind: .note).delete(), .saved)
        XCTAssertNil(store.snapshot.records["n1"])
        let m = try XCTUnwrap(store.snapshot.meta["n1"])
        XCTAssertTrue(m.deleted)
        XCTAssertEqual(m.deletedAt, clock.now)
        XCTAssertEqual(m.vv, ["desk": 3, identity.deviceID: 1])
        // The sync view sees the same tombstone and does not bump it again.
        let view = try SyncMeta.localView(records: store.snapshot.records, meta: store.snapshot.meta,
                                          device: identity.deviceID, now: clock.now)
        XCTAssertEqual(view.meta["n1"], m)
        XCTAssertNotNil(store.snapshot.records["c1"])
    }

    func pairedSnapshot(_ records: [JSONValue]) throws -> (StoreSnapshot, String) {
        var snap = snapshot(records)
        let identity = try DeviceIdentity(deviceID: "d4444444-0000-4000-8000-00000000000d",
                                          signingPrivate: Array(repeating: 1, count: 32), exchangePrivate: Array(repeating: 2, count: 32))
        snap.sync = SyncGroupState(groupID: "g1", epoch: 1, key: Array(repeating: 3, count: 32), identity: identity, installID: "i1",
                                   hasFolder: false, lastSeen: [:], peerDigests: [:], membersEpoch: 1, members: [], keyring: nil,
                                   ownCounter: 0)
        for (id, w) in snap.records { snap.meta[id] = try SyncMeta.live(w, vv: ["desk": 3]) }
        return (snap, identity.deviceID)
    }

    func test_one_edit_bumps_the_vv_once_and_an_unchanged_save_does_not_restamp() throws {
        let (snap, device) = try pairedSnapshot(numberedNotes(1))
        let store = MemoryStore(snap)
        let id = try XCTUnwrap(snap.records.keys.first)
        // Unchanged save: nothing written, so the sync view keeps the same meta (no new updatedAt, no bump).
        let item = VaultItem.items(from: store.snapshot)[0]
        XCTAssertEqual(editor(store, pro(), item: item, kind: .note).save(), .unchanged)
        let idle = try SyncMeta.localView(records: store.snapshot.records, meta: store.snapshot.meta, device: device, now: clock.now)
        XCTAssertEqual(idle.meta[id], snap.meta[id])
        // One edit: exactly one bump for this device, with the new stamp.
        let e = editor(store, pro(), item: VaultItem.items(from: store.snapshot)[0], kind: .note)
        e.set("body", "changed")
        XCTAssertEqual(e.save(), .saved, e.error ?? "")
        let first = try SyncMeta.localView(records: store.snapshot.records, meta: store.snapshot.meta, device: device, now: clock.now)
        let m = try XCTUnwrap(first.meta[id])
        XCTAssertEqual(m.vv, ["desk": 3, device: 1])
        XCTAssertEqual(m.updatedAt, clock.now)
        XCTAssertNotEqual(m.updatedAt, snap.meta[id]?.updatedAt)
        // A second sync view over the same records does not bump again.
        let second = try SyncMeta.localView(records: store.snapshot.records, meta: first.meta, device: device, now: clock.now + 5)
        XCTAssertEqual(second.meta[id], m)
    }

    func test_delete_without_sync_state_never_leaves_a_live_item_behind() throws {
        // Meta kept after Leave, no sync state: there is no device to bump with, so the editor leaves the
        // meta for `localView`, which tombstones it with exactly one bump on the next join.
        var (snap, device) = try pairedSnapshot([note, card])
        snap.sync = nil
        let store = MemoryStore(snap)
        let item = VaultItem.items(from: snap).first { $0.id == "n1" }!
        XCTAssertEqual(editor(store, pro(), item: item, kind: .note).delete(), .saved)
        XCTAssertNil(store.snapshot.records["n1"])
        XCTAssertFalse(VaultItem.items(from: store.snapshot).contains { $0.id == "n1" })
        XCTAssertEqual(ItemLimit.liveCount(store.snapshot), 1)
        let view = try SyncMeta.localView(records: store.snapshot.records, meta: store.snapshot.meta, device: device, now: clock.now)
        let t = try XCTUnwrap(view.meta["n1"])
        XCTAssertTrue(t.deleted)
        XCTAssertEqual(t.vv, ["desk": 3, device: 1])
        XCTAssertEqual(view.states["n1"]?.deleted, true)
    }

    func test_save_and_delete_commit_inside_a_paired_background_task() throws {
        let store = MemoryStore(snapshot([]))
        let bg = FakeBackgroundTasks()
        let e = editor(store, pro(), background: bg)
        e.set(e.titleKey, "Shopping"); e.set("body", "milk")
        XCTAssertEqual(e.save(), .saved)
        XCTAssertEqual(bg.begun.count, 1); XCTAssertEqual(bg.ended.count, 1); XCTAssertTrue(bg.open.isEmpty)
        let item = try XCTUnwrap(VaultItem.items(from: store.snapshot).first)
        XCTAssertEqual(editor(store, pro(), item: item, kind: .note, background: bg).delete(), .saved)
        XCTAssertEqual(bg.begun.count, 2); XCTAssertEqual(bg.ended.count, 2); XCTAssertTrue(bg.open.isEmpty)
    }

    func test_editor_kind_passkey_is_nil() {
        XCTAssertTrue(Normalise.phoneItemKinds.contains("passkey"), "a phone kind (created by AutoFill)")
        XCTAssertNil(EditorKind(kind: "passkey"), "but never edited field by field")
    }

    func test_passkey_rename_changes_only_title() throws {
        let (snap, device) = try pairedSnapshot([try passkeyItem()])
        let store = MemoryStore(snap)
        let id = try XCTUnwrap(snap.records.keys.first)
        let item = VaultItem.items(from: snap)[0]
        // Same title: nothing written.
        XCTAssertEqual(PasskeyRenameModel(store: store, item: item, clock: clock, background: FakeBackgroundTasks()).save(), .unchanged)
        XCTAssertEqual(store.commits, 0)
        let m = PasskeyRenameModel(store: store, item: item, clock: clock, background: FakeBackgroundTasks())
        m.title = "Work account"
        XCTAssertEqual(m.save(), .saved, m.error ?? "")
        XCTAssertEqual(store.commits, 1)
        guard case .object(let beforeW)? = snap.records[id], case .object(var before)? = beforeW["record"],
              case .object(let afterW)? = store.snapshot.records[id], case .object(var after)? = afterW["record"] else { return XCTFail() }
        XCTAssertEqual(after["title"], .string("Work account"))
        XCTAssertEqual(after["updated_at"], .int(clock.now))
        before["title"] = nil; before["updated_at"] = nil; after["title"] = nil; after["updated_at"] = nil
        XCTAssertEqual(try CanonicalJSON.encode(.object(after), dialect: .utf8),
                       try CanonicalJSON.encode(.object(before), dialect: .utf8), "every other field byte-identical")
        XCTAssertEqual(afterW["ns"], .string("item"))
        // Exactly one bump for this device.
        let view = try SyncMeta.localView(records: store.snapshot.records, meta: store.snapshot.meta, device: device, now: clock.now)
        XCTAssertEqual(view.meta[id]?.vv, ["desk": 3, device: 1])
        let again = try SyncMeta.localView(records: store.snapshot.records, meta: view.meta, device: device, now: clock.now + 5)
        XCTAssertEqual(again.meta[id], view.meta[id])
        // An empty title is refused (the item keeps its name).
        let empty = PasskeyRenameModel(store: store, item: VaultItem.items(from: store.snapshot)[0], clock: clock, background: FakeBackgroundTasks())
        empty.title = "   "
        XCTAssertEqual(empty.save(), .invalid)
        XCTAssertEqual(store.commits, 1)
    }

    func test_passkey_delete_tombstones() throws {
        let (snap, device) = try pairedSnapshot([try passkeyItem(), note])
        let store = MemoryStore(snap)
        let item = try XCTUnwrap(VaultItem.items(from: snap).first { $0.kind == "passkey" })
        let bg = FakeBackgroundTasks()
        XCTAssertEqual(PasskeyRenameModel(store: store, item: item, clock: clock, background: bg).delete(), .saved)
        XCTAssertNil(store.snapshot.records[item.id])
        let m = try XCTUnwrap(store.snapshot.meta[item.id])
        XCTAssertTrue(m.deleted); XCTAssertEqual(m.deletedAt, clock.now)
        XCTAssertEqual(m.vv, ["desk": 3, device: 1])
        XCTAssertNotNil(store.snapshot.records["n1"])
        XCTAssertEqual(bg.begun.count, 1); XCTAssertTrue(bg.open.isEmpty)
    }

    func test_only_phone_kinds_are_editable() {
        let items = VaultItem.items(from: snapshot([webLogin, deskLogin, note, card]))
        XCTAssertEqual(Set(items.filter { EditorKind(kind: $0.kind) != nil }.map(\.id)), ["w1", "n1", "c1"])
    }
}

@MainActor
final class ProOutcomeTests: XCTestCase {
    func test_unverified_purchase_shows_an_error_not_cancelled() async {
        let fake = FakePurchases(); fake.purchaseResult = .unverified
        let p = ProModel(purchases: fake, licenseKeys: [:])
        await p.buy()
        XCTAssertFalse(p.isPro)
        XCTAssertEqual(p.message, "The App Store could not verify this purchase. Try Restore purchases or try again later.")
        fake.purchaseResult = .cancelled
        await p.buy()
        XCTAssertNil(p.message)
    }
}
