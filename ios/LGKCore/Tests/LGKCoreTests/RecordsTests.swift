import XCTest
import Foundation
import Crypto
@testable import LGKCore

final class RecordsTests: XCTestCase {
    static let phone = "d4444444-0000-4000-8000-00000000000d"

    func load(_ file: String) throws -> [String: JSONValue] {
        guard case .object(let o) = try CanonicalJSON.parse(Array(Vectors.data(file))) else { throw JSONError.syntax }
        return o
    }

    func reason(_ body: () throws -> Any, _ msg: String = "", line: UInt = #line) -> String? {
        do { _ = try body(); return "accepted" } catch let e as RecordError { return e.reason } catch {
            XCTFail("\(msg): unexpected \(error)", line: line); return nil
        }
    }

    func licenseKeys() throws -> [String: [UInt8]] {
        let o = try load("license_state.json")
        return [MergeVectors.str(o["key_id"])!: try Base64.decodeStrict(MergeVectors.str(o["public_key_b64"])!)]
    }

    // MARK: wrapper

    func test_schema_cases() throws {
        let rows = MergeVectors.arr(try load("schema_cases.json")["cases"])
        XCTAssertGreaterThanOrEqual(rows.count, 10)
        for row in rows {
            let c = MergeVectors.obj(row)
            let name = MergeVectors.str(c["name"])!
            let state = try ItemState(itemID: MergeVectors.str(c["item_id"])!, vv: ["a": 1], deleted: false, deletedAt: nil,
                                      item: c["wrapper"]!)
            XCTAssertEqual(reason({ try Wrapper.unwrap(state, isCopy: false) }, name), MergeVectors.str(c["expect"]), name)
        }
    }

    func test_wrapper_make_rank_rule() throws {
        func rec(_ u: JSONValue?) -> JSONValue {
            var o: [String: JSONValue] = ["id": .string("x"), "kind": .string("note")]
            if let u { o["updated_at"] = u }
            return .object(o)
        }
        func rank(_ w: JSONValue) -> JSONValue? { MergeVectors.obj(w)["updated_at"] }
        XCTAssertEqual(rank(Wrapper.make(ns: .item, record: rec(.int(5)))), .int(5))
        XCTAssertEqual(rank(Wrapper.make(ns: .item, record: rec(.float(5)))), .int(0))
        XCTAssertEqual(rank(Wrapper.make(ns: .item, record: rec(.int(1 << 53)))), .int(0))
        XCTAssertEqual(rank(Wrapper.make(ns: .item, record: rec(.int(-1)))), .int(0))
        XCTAssertEqual(rank(Wrapper.make(ns: .item, record: rec(nil))), .int(0))
        XCTAssertEqual(rank(Wrapper.make(ns: .license, record: rec(.int(5)))), .int(0))
        XCTAssertEqual(MergeVectors.obj(Wrapper.make(ns: .entry, record: rec(nil)))["schema"], .int(1))
    }

    // MARK: licence

    func test_license_vector_verifies() throws {
        let o = try load("license_state.json")
        let keys = try licenseKeys()
        let info = try License.verify(bundle: o["bundle"]!, keys: keys)
        XCTAssertEqual(info.licenseID, "lic-vector-0001")
        XCTAssertEqual(info.name, "Ada Lovelace")
        XCTAssertEqual(info.updatesUntil, "2027-09-21")
        XCTAssertEqual(License.stateID(licenseID: info.licenseID), MergeVectors.str(o["state_id"]))
        let wrapper = Wrapper.make(ns: .license, record: o["bundle"]!)
        XCTAssertEqual(wrapper, o["wrapper"])
        XCTAssertEqual(Vectors.hexString(try CanonicalJSON.encode(wrapper, dialect: .utf8)), MergeVectors.str(o["wrapper_canonical_hex"]))
        XCTAssertThrowsError(try License.verify(bundle: o["bundle"]!, keys: [:])) { XCTAssertEqual(($0 as? LicenseError)?.reason, "unknown-key") }
    }

    func test_license_cases() throws {
        let o = try load("license_state.json")
        let keys = try licenseKeys()
        let rows = MergeVectors.arr(o["cases"])
        XCTAssertGreaterThanOrEqual(rows.count, 10)
        for row in rows {
            let c = MergeVectors.obj(row)
            let name = MergeVectors.str(c["name"])!
            let state = try ItemState(itemID: MergeVectors.str(c["state_id"])!, vv: [EngineTests.A: 1], deleted: false,
                                      deletedAt: nil, item: c["wrapper"]!)
            let isCopy = c["copy"] == .bool(true)
            let outcome = MergeOutcome(upserts: isCopy ? [] : [state], deletes: [], conflicts: [], copies: isCopy ? [state] : [])
            var got: String?
            do {
                let r = try SyncMeta.applyRemote(outcome, records: [:], meta: [:], device: Self.phone, now: EngineTests.T0,
                                                 licenseKeys: keys)
                if r.records.isEmpty && r.meta.isEmpty && r.licenses.isEmpty { got = "dropped" } else {
                    got = "accepted"
                    XCTAssertEqual(r.records[state.itemID], c["wrapper"], name)
                    XCTAssertEqual(r.licenses, [MergeVectors.obj(c["wrapper"])["record"]!], name)
                    XCTAssertEqual(r.meta[state.itemID]?.vv, state.vv, name)
                }
            } catch let e as RecordError {
                got = e.reason
                XCTAssertEqual(e.itemID, state.itemID, name)
            }
            XCTAssertEqual(got, MergeVectors.str(c["expect"]), name)
        }
    }

    func test_license_is_never_deleted_and_republished() throws {
        let o = try load("license_state.json")
        let keys = try licenseKeys()
        let sid = MergeVectors.str(o["state_id"])!
        let s = try ItemState(itemID: sid, vv: [EngineTests.A: 1], deleted: false, deletedAt: nil, item: o["wrapper"]!)
        let r = try SyncMeta.applyRemote(MergeOutcome(upserts: [s], deletes: [], conflicts: [], copies: []),
                                         records: [:], meta: [:], device: Self.phone, now: EngineTests.T0, licenseKeys: keys)
        let tomb = try ItemState(itemID: sid, vv: [EngineTests.A: 2], deleted: true, deletedAt: EngineTests.T0, item: nil)
        let r2 = try SyncMeta.applyRemote(MergeOutcome(upserts: [], deletes: [tomb], conflicts: [], copies: []),
                                          records: r.records, meta: r.meta, device: Self.phone, now: EngineTests.T0, licenseKeys: keys)
        XCTAssertEqual(r2.records[sid], o["wrapper"])
        XCTAssertEqual(r2.meta[sid]?.deleted, false)
        XCTAssertEqual(r2.meta[sid]?.vv, [EngineTests.A: 2, Self.phone: 1])
        // Same id, other bytes: bad-remote.
        var other = MergeVectors.obj(o["wrapper"])
        var rec = MergeVectors.obj(other["record"]); rec["extra"] = .int(1); other["record"] = .object(rec)
        let s3 = try ItemState(itemID: sid, vv: [EngineTests.A: 3], deleted: false, deletedAt: nil, item: .object(other))
        XCTAssertEqual(reason({ try SyncMeta.applyRemote(MergeOutcome(upserts: [s3], deletes: [], conflicts: [], copies: []),
                                                       records: r2.records, meta: r2.meta, device: Self.phone,
                                                       now: EngineTests.T0, licenseKeys: keys) }), "bad-remote")
        // No licence keys in this build: dropped without a write.
        let r4 = try SyncMeta.applyRemote(MergeOutcome(upserts: [s], deletes: [], conflicts: [], copies: []),
                                          records: [:], meta: [:], device: Self.phone, now: EngineTests.T0, licenseKeys: [:])
        XCTAssertTrue(r4.records.isEmpty && r4.meta.isEmpty)
        // A licence that is no longer stored goes quiet: never tombstoned.
        let view = try SyncMeta.localView(records: [:], meta: r2.meta, device: Self.phone, now: EngineTests.T0)
        XCTAssertNil(view.states[sid])
    }

    func test_license_republish_with_overflowing_counter_refuses_only_that_state() throws {
        // Desktop wraps the republish bump in _blame: bad-remote for the licence id, not a bare engine error.
        let o = try load("license_state.json")
        let keys = try licenseKeys()
        let sid = MergeVectors.str(o["state_id"])!
        let s = try ItemState(itemID: sid, vv: [EngineTests.A: 1], deleted: false, deletedAt: nil, item: o["wrapper"]!)
        let r = try SyncMeta.applyRemote(MergeOutcome(upserts: [s], deletes: [], conflicts: [], copies: []),
                                         records: [:], meta: [:], device: Self.phone, now: EngineTests.T0, licenseKeys: keys)
        let tomb = try ItemState(itemID: sid, vv: [EngineTests.A: 2, Self.phone: VersionVector.maxCounter], deleted: true,
                                 deletedAt: EngineTests.T0, item: nil)
        do {
            _ = try SyncMeta.applyRemote(MergeOutcome(upserts: [], deletes: [tomb], conflicts: [], copies: []),
                                         records: r.records, meta: r.meta, device: Self.phone, now: EngineTests.T0, licenseKeys: keys)
            XCTFail("an overflowing licence republish was accepted")
        } catch let e as RecordError {
            XCTAssertEqual(e.reason, "bad-remote")
            XCTAssertEqual(e.itemID, sid)
        }
    }

    // MARK: suffix

    func test_suffix_truncation_counts_code_points() {
        XCTAssertEqual(ConflictSuffix.apply("Bank", limit: 512), "Bank (sync conflict)")
        XCTAssertEqual(ConflictSuffix.apply("Bank (sync conflict)", limit: 512), "Bank (sync conflict)")
        let key = "\u{1F511}"  // 1 code point, 2 UTF-16 units, 4 UTF-8 bytes
        let long = String(repeating: key, count: 600)
        let out = ConflictSuffix.apply(long, limit: 512)
        XCTAssertEqual(out.unicodeScalars.count, 512)
        XCTAssertEqual(out, String(repeating: key, count: 496) + " (sync conflict)")
        // e + combining acute: 2 code points, 1 grapheme.
        let comb = String(repeating: "e\u{301}", count: 10)
        let cut = ConflictSuffix.apply(comb, limit: 21)
        XCTAssertEqual(cut.unicodeScalars.count, 21)
        XCTAssertEqual(Array(cut.unicodeScalars.prefix(5)).map(\.value), [0x65, 0x301, 0x65, 0x301, 0x65])
        XCTAssertEqual(ConflictSuffix.apply("abc", limit: 10), " (sync conflict)")
        XCTAssertEqual(ConflictSuffix.apply("x", limit: 0), " (sync conflict)")
        let em = try! load("expected_merge.json")
        XCTAssertEqual(MergeVectors.str(em["conflict_suffix"]), ConflictSuffix.suffix)
    }

    // MARK: sync meta

    func groupKey() throws -> GroupKey {
        guard case .object(let o) = try CanonicalJSON.parse(Array(Vectors.data("expected.json"))),
              case .object(let epochs)? = o["epochs"], case .object(let e1)? = epochs["1"],
              case .string(let hex)? = e1["group_key_hex"] else { throw JSONError.syntax }
        return try GroupKey(groupID: GroupTests.groupID, epoch: 1, key: Vectors.hex(hex))
    }

    func view(_ name: String) throws -> (header: ViewHeader, states: [ItemState]) {
        let d = GroupTests.devices.first { $0.name == name }!
        return try ViewFile.decode(Array(Vectors.data("devices/\(name).lgksync")), key: groupKey(), expectedDeviceID: d.id)
    }

    func test_untouched_records_republish_identically() throws {
        for d in GroupTests.devices {
            let v = try view(d.name)
            let outcome = try Engine.merge(local: [:], remote: v.states)
            let applied = try SyncMeta.applyRemote(outcome, records: [:], meta: [:], device: Self.phone,
                                                   now: EngineTests.T0 + 1000, licenseKeys: [:])
            XCTAssertEqual(applied.records.count, v.states.filter { !$0.deleted }.count, d.name)
            let local = try SyncMeta.localView(records: applied.records, meta: applied.meta, device: Self.phone,
                                               now: EngineTests.T0 + 1000)
            XCTAssertEqual(local.meta, applied.meta, "\(d.name): an untouched record must not look edited")
            let mine = local.states.values.sorted { $0.itemID < $1.itemID }
            XCTAssertEqual(mine.count, v.states.count)
            for (got, exp) in zip(mine, v.states) {
                XCTAssertEqual(got, exp, "\(d.name) \(got.itemID)")
                if let g = got.item {
                    XCTAssertEqual(try CanonicalJSON.encode(g, dialect: .utf8), try CanonicalJSON.encode(exp.item!, dialect: .utf8))
                }
            }
            // Re-encoding with the generator's nonces gives the device file byte for byte.
            let raw = try ViewFile.encode(key: groupKey(), deviceID: d.id, counter: d.counter, states: mine,
                                          now: FixedClock(now: EngineTests.T0 + d.written), random: DetRand("view|\(d.name)"))
            XCTAssertEqual(raw, Array(try Vectors.data("devices/\(d.name).lgksync")), d.name)
        }
        // Float and int survive: 100.0 stays 100.0.
        let a = try view("A")
        let bytes = try a.states.compactMap(\.item).map { String(decoding: try CanonicalJSON.encode($0, dialect: .utf8), as: UTF8.self) }
        XCTAssertTrue(bytes.contains { $0.contains("\"f_100\":100.0") })
    }

    func test_fold_of_ABC_matches_bridge_stored_states() throws {
        let views = try GroupTests.devices.map { PeerView(deviceID: $0.id, states: try view($0.name).states) }
        let fold = Engine.fold(local: [:], views: views)
        XCTAssertTrue(fold.quarantined.isEmpty && fold.badViews.isEmpty)
        let applied = try SyncMeta.applyRemote(fold.outcome, records: [:], meta: [:], device: Self.phone,
                                               now: EngineTests.T0 + 1000, licenseKeys: [:])
        let local = try SyncMeta.localView(records: applied.records, meta: applied.meta, device: Self.phone, now: EngineTests.T0 + 1000)
        let want = try MergeVectors.arr(MergeVectors.expectedMerge()["bridge_stored_states"]).map(MergeVectors.state)
        let got = local.states.values.sorted { $0.itemID < $1.itemID }
        XCTAssertEqual(got, want)
    }

    func test_local_edit_bumps_own_counter_once() throws {
        let v = try view("A")
        let applied = try SyncMeta.applyRemote(try Engine.merge(local: [:], remote: v.states), records: [:], meta: [:],
                                               device: Self.phone, now: EngineTests.T0, licenseKeys: [:])
        var records = applied.records
        let id = EngineTests.NOTE
        var w = MergeVectors.obj(records[id]); var rec = MergeVectors.obj(w["record"])
        rec["title"] = .string("Edited on the phone"); rec["updated_at"] = .int(EngineTests.T0 + 5)
        let edited = try Normalise.normalForm(ns: .item, record: .object(rec))
        records[id] = Wrapper.make(ns: .item, record: edited)
        w = MergeVectors.obj(records[id])
        XCTAssertEqual(w["updated_at"], .int(EngineTests.T0 + 5))
        let first = try SyncMeta.localView(records: records, meta: applied.meta, device: Self.phone, now: EngineTests.T0 + 10)
        let before = v.states.first { $0.itemID == id }!.vv
        XCTAssertEqual(first.states[id]?.vv, try VersionVector.bump(before, device: Self.phone))
        // A second view without further edits does not bump again.
        let second = try SyncMeta.localView(records: records, meta: first.meta, device: Self.phone, now: EngineTests.T0 + 20)
        XCTAssertEqual(second.states[id]?.vv, first.states[id]?.vv)
        XCTAssertEqual(second.meta, first.meta)
        // Other records are untouched.
        for s in v.states where s.itemID != id { XCTAssertEqual(second.states[s.itemID], s) }
        // Deleting locally: one tombstone with a bumped vector and deleted_at = now.
        records[id] = nil
        let third = try SyncMeta.localView(records: records, meta: second.meta, device: Self.phone, now: EngineTests.T0 + 30)
        let tomb = third.states[id]!
        XCTAssertTrue(tomb.deleted)
        XCTAssertEqual(tomb.deletedAt, EngineTests.T0 + 30)
        XCTAssertEqual(tomb.vv[Self.phone], 2)
        let fourth = try SyncMeta.localView(records: records, meta: third.meta, device: Self.phone, now: EngineTests.T0 + 40)
        XCTAssertEqual(fourth.states[id], tomb)
        // Tombstones older than 365 days are pruned.
        let later = try SyncMeta.localView(records: records, meta: third.meta, device: Self.phone,
                                           now: EngineTests.T0 + 30 + 365 * 86400 + 1)
        XCTAssertNil(later.states[id])
        XCTAssertNil(later.meta[id])
    }

    func test_overflowing_counter_skips_only_that_record() throws {
        // A vector stored before the plausibility rule (audit M-6) may already hold the maximum.
        let v = try view("A")
        let applied = try SyncMeta.applyRemote(try Engine.merge(local: [:], remote: v.states), records: [:], meta: [:],
                                               device: Self.phone, now: EngineTests.T0, licenseKeys: [:])
        let id = EngineTests.NOTE
        var meta = applied.meta
        meta[id]!.vv[Self.phone] = VersionVector.maxCounter
        var records = applied.records
        var rec = MergeVectors.obj(MergeVectors.obj(records[id])["record"])
        rec["title"] = .string("Edited on the phone")
        records[id] = Wrapper.make(ns: .item, record: try Normalise.normalForm(ns: .item, record: .object(rec)))
        let edited = try SyncMeta.localView(records: records, meta: meta, device: Self.phone, now: EngineTests.T0 + 10)
        XCTAssertEqual(edited.skipped[id], SyncMeta.counterOverflow)
        XCTAssertNil(edited.states[id])
        XCTAssertEqual(edited.meta[id], meta[id])
        for s in v.states where s.itemID != id { XCTAssertEqual(edited.states[s.itemID], s) }
        // A delete that cannot be recorded publishes nothing for that record.
        records[id] = nil
        let removed = try SyncMeta.localView(records: records, meta: meta, device: Self.phone, now: EngineTests.T0 + 20)
        XCTAssertNil(removed.states[id])
        XCTAssertEqual(removed.meta[id], meta[id])
    }

    func test_apply_remote_rules() throws {
        let v = try view("A")
        let base = try SyncMeta.applyRemote(try Engine.merge(local: [:], remote: v.states), records: [:], meta: [:],
                                            device: Self.phone, now: EngineTests.T0, licenseKeys: [:])
        let id = EngineTests.NOTE
        // Remote tombstone: deleted_at capped at now; stale tombstones ignored.
        let tomb = try ItemState(itemID: id, vv: [EngineTests.A: 5], deleted: true, deletedAt: EngineTests.T0 + 999, item: nil)
        let r = try SyncMeta.applyRemote(MergeOutcome(upserts: [], deletes: [tomb], conflicts: [], copies: []),
                                         records: base.records, meta: base.meta, device: Self.phone, now: EngineTests.T0 + 10,
                                         licenseKeys: [:])
        XCTAssertNil(r.records[id])
        XCTAssertEqual(r.meta[id], SyncMeta(digest: nil, body: nil, updatedAt: nil, vv: [EngineTests.A: 5], deleted: true,
                                            deletedAt: EngineTests.T0 + 10))
        XCTAssertEqual(r.deleted, 1)
        let old = try ItemState(itemID: id, vv: [EngineTests.A: 5], deleted: true, deletedAt: 1, item: nil)
        let r2 = try SyncMeta.applyRemote(MergeOutcome(upserts: [], deletes: [old], conflicts: [], copies: []),
                                          records: base.records, meta: base.meta, device: Self.phone, now: EngineTests.T0,
                                          licenseKeys: [:])
        XCTAssertEqual(r2.records, base.records)
        // A local edit made after the view was taken: vault-changed, nothing applied.
        var changed = base.records
        var rec = MergeVectors.obj(MergeVectors.obj(changed[id])["record"]); rec["title"] = .string("x")
        changed[id] = Wrapper.make(ns: .item, record: .object(rec))
        XCTAssertEqual(reason({ try SyncMeta.applyRemote(MergeOutcome(upserts: [], deletes: [tomb], conflicts: [], copies: []),
                                                       records: changed, meta: base.meta, device: Self.phone,
                                                       now: EngineTests.T0, licenseKeys: [:]) }), "vault-changed")
        // Copies are stored with the suffix and the loser's vector.
        let loser = v.states.first { $0.itemID == id }!
        guard case .object(var cw) = loser.item! else { return XCTFail() }
        cw["id"] = .string("9e9a151e-b5a5-5e08-b722-1d16a2f77f8e")
        let copy = try ItemState(itemID: "9e9a151e-b5a5-5e08-b722-1d16a2f77f8e", vv: loser.vv, deleted: false, deletedAt: nil,
                                 item: .object(cw))
        let r3 = try SyncMeta.applyRemote(MergeOutcome(upserts: [], deletes: [], conflicts: [], copies: [copy]),
                                          records: base.records, meta: base.meta, device: Self.phone, now: EngineTests.T0,
                                          licenseKeys: [:])
        let stored = MergeVectors.obj(MergeVectors.obj(r3.records[copy.itemID])["record"])
        XCTAssertEqual(stored["id"], .string(copy.itemID))
        XCTAssertTrue(MergeVectors.str(stored["title"])!.hasSuffix(" (sync conflict)"))
        XCTAssertNil(MergeVectors.obj(r3.records[copy.itemID])["id"])
        XCTAssertEqual(r3.meta[copy.itemID]?.vv, loser.vv)
    }
}
