import XCTest
import Foundation
import Crypto
@testable import LGKCore

final class EngineTests: XCTestCase {
    static let A = "a1111111-0000-4000-8000-00000000000a"
    static let B = "b2222222-0000-4000-8000-00000000000b"
    static let C = "c3333333-0000-4000-8000-00000000000c"
    static let LOGIN_EDITED = "11111111-aaaa-4000-8000-000000000001"
    static let NOTE = "22222222-aaaa-4000-8000-000000000002"
    static let DESKTOP = "33333333-aaaa-4000-8000-000000000003"
    static let LOGIN_DELETED = "44444444-aaaa-4000-8000-000000000004"
    static let BOOKMARK = "55555555-aaaa-4000-8000-000000000005"
    static let NOTE_UNICODE = "66666666-aaaa-4000-8000-000000000006"
    static let LOGIN_TIE = "77777777-aaaa-4000-8000-000000000007"
    static let T0: Int64 = 1_790_000_000

    // MARK: vector helpers (shared with GroupTests, see Support/MergeVectors.swift)

    func expectedMerge() throws -> [String: JSONValue] { try MergeVectors.expectedMerge() }
    func arr(_ v: JSONValue?) -> [JSONValue] { MergeVectors.arr(v) }
    func obj(_ v: JSONValue?) -> [String: JSONValue] { MergeVectors.obj(v) }
    func str(_ v: JSONValue?) -> String? { MergeVectors.str(v) }
    func state(_ j: JSONValue) throws -> ItemState { try MergeVectors.state(j) }
    func sha(_ v: JSONValue) throws -> String { try MergeVectors.sha(v) }
    func deviceStates() throws -> [String: [ItemState]] { try MergeVectors.deviceStates() }

    func ids(_ s: [ItemState]) -> [String] { s.map(\.itemID).sorted() }

    // MARK: tests

    func test_merge_all_six_orders_match_expected_engine_states() throws {
        let em = try expectedMerge()
        let expected = try arr(em["engine_states"]).map(state)
        let views = try deviceStates()
        let orders = [["A", "B", "C"], ["A", "C", "B"], ["B", "A", "C"], ["B", "C", "A"], ["C", "A", "B"], ["C", "B", "A"]]
        let steps = obj(em["fold_steps"])
        for order in orders {
            var local = Dictionary(uniqueKeysWithValues: views[order[0]]!.map { ($0.itemID, $0) })
            for (n, name) in order.dropFirst().enumerated() {
                let out = try Engine.merge(local: local, remote: views[name]!)
                if let rec = arr(steps[order.joined()]).dropFirst(n).first {
                    let r = obj(rec)
                    XCTAssertEqual(ids(out.upserts), arr(r["upserts"]).compactMap(str), "\(order) step \(n)")
                    XCTAssertEqual(ids(out.deletes), arr(r["deletes"]).compactMap(str), "\(order) step \(n)")
                    XCTAssertEqual(ids(out.copies), arr(r["copies"]).compactMap(str), "\(order) step \(n)")
                    XCTAssertEqual(out.conflicts.map(\.0.itemID).sorted(), arr(r["conflicts"]).compactMap(str))
                }
                for s in out.upserts + out.deletes + out.copies { local[s.itemID] = s }
            }
            let got = local.values.sorted { $0.itemID < $1.itemID }
            XCTAssertEqual(got, expected, "order \(order.joined())")
            for (g, e) in zip(got, expected) where g.item != nil {
                XCTAssertEqual(try CanonicalJSON.encode(g.item!, dialect: .utf8),
                               try CanonicalJSON.encode(e.item!, dialect: .utf8))
            }
        }
        XCTAssertEqual(steps.keys.sorted(), ["ABC", "CBA"])
    }

    func test_fold_matches_expected_engine_states_in_any_view_order() throws {
        let expected = try arr(try expectedMerge()["engine_states"]).map(state)
        let views = try deviceStates()
        for first in ["A", "B", "C"] {
            let local = Dictionary(uniqueKeysWithValues: views[first]!.map { ($0.itemID, $0) })
            let peers = ["C", "A", "B"].filter { $0 != first }.map { PeerView(deviceID: $0, states: views[$0]!) }
            let r = Engine.fold(local: local, views: peers)
            XCTAssertTrue(r.quarantined.isEmpty)
            XCTAssertTrue(r.badViews.isEmpty)
            var final = local
            for s in r.outcome.upserts + r.outcome.deletes + r.outcome.copies { final[s.itemID] = s }
            XCTAssertEqual(final.values.sorted { $0.itemID < $1.itemID }, expected, first)
        }
    }

    func test_fold_quarantines_one_record_and_drops_bad_views() throws {
        let views = try deviceStates()
        let local = Dictionary(uniqueKeysWithValues: views["A"]!.map { ($0.itemID, $0) })
        let dup = PeerView(deviceID: "Z", states: [views["B"]![0], views["B"]![0]])
        let r = Engine.fold(local: local, views: [PeerView(deviceID: "B", states: views["B"]!), dup]) { s in
            s.itemID == Self.NOTE_UNICODE ? "bad-remote" : nil
        }
        XCTAssertEqual(r.badViews, ["Z"])
        XCTAssertEqual(r.quarantined, [FoldQuarantine(device: "B", item: Self.NOTE_UNICODE, reason: "bad-remote")])
        XCTAssertFalse(r.outcome.upserts.contains { $0.itemID == Self.NOTE_UNICODE })
        XCTAssertTrue(r.outcome.upserts.contains { $0.itemID == Self.BOOKMARK })
    }

    func test_fold_copy_from_earlier_view_superseded_by_peer_copy() throws {
        let v = try deviceStates()
        let local = Dictionary(uniqueKeysWithValues: v["A"]!.map { ($0.itemID, $0) })
        // B's merge creates the copy; C (here a peer that already stores that copy) carries it.
        let first = Engine.fold(local: local, views: [PeerView(deviceID: "B", states: v["B"]!)])
        let copy = first.outcome.copies[0]
        let stored = try ItemState(itemID: copy.itemID, vv: copy.vv.merging([Self.C: 1]) { $0 + $1 },
                                   deleted: false, deletedAt: nil, item: copy.item)
        let r = Engine.fold(local: local, views: [PeerView(deviceID: "B", states: v["B"]!),
                                                  PeerView(deviceID: "C", states: v["C"]! + [stored])])
        XCTAssertTrue(r.badViews.isEmpty)
        let all = r.outcome.upserts + r.outcome.copies
        XCTAssertEqual(all.first { $0.itemID == copy.itemID }, stored)
        XCTAssertFalse(r.outcome.copies.contains { $0.itemID == copy.itemID })
    }

    func test_conflict_copy_ids_match_vectors() throws {
        let em = try expectedMerge()
        let copies = arr(em["conflict_copies"])
        XCTAssertEqual(copies.count, 2)
        for c in copies {
            let o = obj(c)
            XCTAssertEqual(try sha(o["loser_wrapper"]!), str(o["content_digest"]))
            XCTAssertEqual(try ConflictCopy.id(itemID: str(o["original_id"])!, contentDigest: str(o["content_digest"])!),
                           str(o["copy_id"]))
            XCTAssertEqual(try ConflictCopy.contentDigest(o["loser_wrapper"]!), str(o["content_digest"]))
        }
        XCTAssertThrowsError(try ConflictCopy.id(itemID: Self.LOGIN_TIE, contentDigest: ""))
        // Upper-case hyphenated uuid is still a uuid namespace; non-uuid ids hash through the URL namespace.
        XCTAssertEqual(try ConflictCopy.id(itemID: Self.LOGIN_TIE.uppercased(), contentDigest: "x"),
                       try ConflictCopy.id(itemID: Self.LOGIN_TIE, contentDigest: "x"))
        XCTAssertNotEqual(try ConflictCopy.id(itemID: "lic:abc", contentDigest: "x"),
                          try ConflictCopy.id(itemID: "lic:abd", contentDigest: "x"))
    }

    func test_canonical_sha256_per_state() throws {
        let em = try expectedMerge()
        for key in ["engine_states", "bridge_stored_states"] {
            for j in arr(em[key]) {
                let o = obj(j)
                if case .object = o["item"]! {
                    XCTAssertEqual(try sha(o["item"]!), str(o["canonical_sha256"]), str(o["id"]) ?? "")
                } else {
                    XCTAssertEqual(o["canonical_sha256"], .null)
                }
            }
        }
    }

    func test_equal_vectors_merge_is_idempotent() throws {
        // Fuzz finding S-1 (2026-10-24): a no-op upsert and conflict must not repeat every round.
        let item: JSONValue = .object(["updated_at": .int(0), "v": .int(0)])
        let alive = try ItemState(itemID: "item-1", vv: [:], deleted: false, deletedAt: nil, item: item)
        let gone = try ItemState(itemID: "item-1", vv: [:], deleted: true, deletedAt: nil, item: nil)
        var out = try Engine.merge(local: ["item-1": alive], remote: [gone])
        XCTAssertTrue(out.upserts.isEmpty && out.deletes.isEmpty && out.conflicts.isEmpty && out.copies.isEmpty)
        out = try Engine.merge(local: ["item-1": gone], remote: [alive])
        XCTAssertEqual(out.upserts, [alive])
        XCTAssertEqual(out.conflicts.count, 1)
        XCTAssertTrue(try Engine.merge(local: ["item-1": alive], remote: [alive]).upserts.isEmpty)
    }

    func test_edit_beats_delete() throws {
        let item: JSONValue = .object(["updated_at": .int(5), "x": .string("live")])
        let local = try ItemState(itemID: "i", vv: ["b": 1, "c": 0], deleted: false, deletedAt: nil, item: item)
        XCTAssertEqual(local.vv, ["b": 1])
        let tomb = try ItemState(itemID: "i", vv: ["c": 1], deleted: true, deletedAt: 9, item: nil)
        // remote delete vs local edit: live side kept with the merged vector
        var out = try Engine.merge(local: ["i": local], remote: [tomb])
        XCTAssertEqual(out.upserts, [try ItemState(itemID: "i", vv: ["b": 1, "c": 1], deleted: false, deletedAt: nil, item: item)])
        XCTAssertEqual(out.deletes, [])
        XCTAssertEqual(out.conflicts.count, 1)
        // local delete vs remote edit
        out = try Engine.merge(local: ["i": tomb], remote: [local])
        XCTAssertEqual(out.upserts.map(\.vv), [["b": 1, "c": 1]])
        XCTAssertEqual(out.upserts.first?.item, item)
        // both deleted: max deleted_at, only when it differs from local
        let t2 = try ItemState(itemID: "i", vv: ["b": 1], deleted: true, deletedAt: 12, item: nil)
        out = try Engine.merge(local: ["i": tomb], remote: [t2])
        XCTAssertEqual(out.deletes, [try ItemState(itemID: "i", vv: ["b": 1, "c": 1], deleted: true, deletedAt: 12, item: nil)])
        out = try Engine.merge(local: ["i": tomb], remote: [tomb])
        XCTAssertTrue(out.deletes.isEmpty && out.upserts.isEmpty)
    }

    func test_updated_at_tie_breaks_by_digest() throws {
        let v = try deviceStates()
        let a = v["A"]!.first { $0.itemID == Self.LOGIN_TIE }!
        let b = v["B"]!.first { $0.itemID == Self.LOGIN_TIE }!
        let expectedWinner = try sha(a.item!) > sha(b.item!) ? a : b
        for (l, r) in [(a, b), (b, a)] {
            let out = try Engine.merge(local: [l.itemID: l], remote: [r])
            XCTAssertEqual(out.upserts.count, 1)
            XCTAssertEqual(out.upserts[0].item, expectedWinner.item)
            XCTAssertEqual(out.upserts[0].vv, [Self.A: 2, Self.B: 1])
            XCTAssertEqual(out.copies.map(\.itemID), ["9e9a151e-b5a5-5e08-b722-1d16a2f77f8d"])
            XCTAssertEqual(out.copies[0].vv, [Self.A: 1, Self.B: 1])
        }
        // a float / bool / negative updated_at counts as 0
        let x = try ItemState(itemID: "i", vv: ["a": 1], deleted: false, deletedAt: nil, item: .object(["updated_at": .float(9e9)]))
        let y = try ItemState(itemID: "i", vv: ["b": 1], deleted: false, deletedAt: nil, item: .object(["updated_at": .int(1)]))
        XCTAssertEqual(try Engine.merge(local: ["i": x], remote: [y]).upserts.first?.item, y.item)
    }

    func test_validation_and_version_vectors() throws {
        XCTAssertThrowsError(try ItemState(itemID: "é", vv: [:], deleted: true, deletedAt: nil, item: nil))
        XCTAssertThrowsError(try ItemState(itemID: "i", vv: ["a": -1], deleted: true, deletedAt: nil, item: nil))
        XCTAssertThrowsError(try ItemState(itemID: "i", vv: ["a": 1 << 53], deleted: true, deletedAt: nil, item: nil))
        XCTAssertThrowsError(try ItemState(itemID: "i", vv: [:], deleted: true, deletedAt: -1, item: nil))
        XCTAssertThrowsError(try ItemState(itemID: "i", vv: [:], deleted: false, deletedAt: nil, item: nil))
        XCTAssertThrowsError(try ItemState(itemID: "i", vv: [:], deleted: false, deletedAt: nil, item: .array([])))
        XCTAssertThrowsError(try ItemState(itemID: "i", vv: [:], deleted: false, deletedAt: nil, item: .object(["n": .int(.min)])))
        XCTAssertThrowsError(try ItemState(itemID: "i", vv: [:], deleted: false, deletedAt: nil, item: .object(["n": .float(.nan)])))
        var deep: JSONValue = .null
        for _ in 0..<65 { deep = .array([deep]) }
        XCTAssertThrowsError(try ItemState(itemID: "i", vv: [:], deleted: false, deletedAt: nil, item: .object(["d": deep])))
        XCTAssertEqual(try VersionVector.compare(["a": 1], ["a": 1, "b": 0]), .equal)
        XCTAssertEqual(try VersionVector.compare(["a": 2], ["a": 1]), .a)
        XCTAssertEqual(try VersionVector.compare(["a": 1], ["b": 1]), .concurrent)
        XCTAssertEqual(try VersionVector.compare([:], ["b": 1]), .b)
        XCTAssertEqual(try VersionVector.bump(["a": 1, "z": 0], device: "b"), ["a": 1, "b": 1])
        XCTAssertThrowsError(try VersionVector.bump(["a": (1 << 53) - 1], device: "a"))
        XCTAssertEqual(VersionVector.max(["a": 1, "b": 3], ["a": 2]), ["a": 2, "b": 3])
        let s = try ItemState(itemID: "i", vv: [:], deleted: true, deletedAt: nil, item: nil)
        XCTAssertThrowsError(try Engine.merge(local: [:], remote: [s, s]))
        XCTAssertThrowsError(try Engine.merge(local: ["j": s], remote: []))
    }
}
