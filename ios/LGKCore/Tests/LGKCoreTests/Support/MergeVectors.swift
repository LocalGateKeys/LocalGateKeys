import Foundation
import Crypto
@testable import LGKCore

/// expected_merge.json helpers (CanonicalJSON only, never Foundation JSON).
enum MergeVectors {

    static func expectedMerge() throws -> [String: JSONValue] {
        guard case .object(let o) = try CanonicalJSON.parse(Array(Vectors.data("expected_merge.json"))) else {
            throw JSONError.syntax
        }
        return o
    }

    static func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { return a }; return [] }
    static func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
    static func str(_ v: JSONValue?) -> String? { if case .string(let s)? = v { return s }; return nil }

    static func state(_ j: JSONValue) throws -> ItemState {
        let o = obj(j)
        var vv: [String: Int64] = [:]
        for (k, v) in obj(o["vv"]) { if case .int(let n) = v { vv[k] = n } }
        var at: Int64?
        if case .int(let n)? = o["deleted_at"] { at = n }
        var deleted = false
        if case .bool(let b)? = o["deleted"] { deleted = b }
        let item: JSONValue? = (o["item"] == .null || o["item"] == nil) ? nil : o["item"]
        return try ItemState(itemID: str(o["id"])!, vv: vv, deleted: deleted, deletedAt: at, item: item)
    }

    static func sha(_ v: JSONValue) throws -> String {
        Vectors.hexString(Array(SHA256.hash(data: try CanonicalJSON.encode(v, dialect: .utf8))))
    }

    /// The A/B/C engine inputs (scripts/make_sync_vectors.py device_states), rebuilt from the
    /// plain-JSON states in expected_merge.json. States every other device dominates
    /// (A's doomed login and base bookmark, C's base login and base tie login) get placeholder
    /// content: a dominated state never reaches the result.
    static func deviceStates() throws -> [String: [ItemState]] {
        let em = try expectedMerge()
        var final: [String: ItemState] = [:]
        for j in arr(em["engine_states"]) { let s = try MergeVectors.state(j); final[s.itemID] = s }
        var loser: [String: JSONValue] = [:]
        for c in arr(em["conflict_copies"]) {
            let o = obj(c)
            loser[str(o["original_id"])!] = o["loser_wrapper"]!
        }
        let (a, b, c) = (EngineTests.A, EngineTests.B, EngineTests.C)
        func live(_ id: String, _ vv: [String: Int64], _ item: JSONValue) throws -> ItemState {
            try ItemState(itemID: id, vv: vv, deleted: false, deletedAt: nil, item: item)
        }
        func tomb(_ id: String, _ vv: [String: Int64], _ at: Int64) throws -> ItemState {
            try ItemState(itemID: id, vv: vv, deleted: true, deletedAt: EngineTests.T0 + at, item: nil)
        }
        func placeholder(_ id: String, _ label: String) -> JSONValue {
            .object(["ns": .string("entry"), "schema": .int(1), "updated_at": .int(0),
                     "record": .object(["id": .string(id), "label": .string(label)])])
        }
        let f = { (id: String) in final[id]!.item! }
        return [
            "A": [
                try live(EngineTests.LOGIN_EDITED, [a: 2], f(EngineTests.LOGIN_EDITED)),
                try live(EngineTests.NOTE, [a: 1], f(EngineTests.NOTE)),
                try live(EngineTests.DESKTOP, [b: 1], f(EngineTests.DESKTOP)),
                try live(EngineTests.LOGIN_DELETED, [a: 1], placeholder(EngineTests.LOGIN_DELETED, "doomed")),
                try live(EngineTests.BOOKMARK, [a: 1], placeholder(EngineTests.BOOKMARK, "bookmark base")),
                try live(EngineTests.LOGIN_TIE, [a: 2], f(EngineTests.LOGIN_TIE)),
            ],
            "B": [
                try live(EngineTests.LOGIN_EDITED, [a: 1, b: 1], loser[EngineTests.LOGIN_EDITED]!),
                try live(EngineTests.NOTE, [a: 1], f(EngineTests.NOTE)),
                try live(EngineTests.DESKTOP, [b: 1], f(EngineTests.DESKTOP)),
                try live(EngineTests.LOGIN_DELETED, [a: 1], placeholder(EngineTests.LOGIN_DELETED, "doomed")),
                try live(EngineTests.BOOKMARK, [a: 1, b: 1], f(EngineTests.BOOKMARK)),
                try live(EngineTests.NOTE_UNICODE, [b: 1], f(EngineTests.NOTE_UNICODE)),
                try live(EngineTests.LOGIN_TIE, [a: 1, b: 1], loser[EngineTests.LOGIN_TIE]!),
            ],
            "C": [
                try live(EngineTests.LOGIN_EDITED, [a: 1], placeholder(EngineTests.LOGIN_EDITED, "login base")),
                try live(EngineTests.NOTE, [a: 1], f(EngineTests.NOTE)),
                try live(EngineTests.DESKTOP, [b: 1], f(EngineTests.DESKTOP)),
                try tomb(EngineTests.LOGIN_DELETED, [a: 1, c: 1], 300),
                try tomb(EngineTests.BOOKMARK, [a: 1, c: 1], 350),
                try live(EngineTests.LOGIN_TIE, [a: 1], placeholder(EngineTests.LOGIN_TIE, "tie base")),
            ],
        ]
    }

}
