import XCTest
@testable import LGKCore

/// The shared vectors of the 2026-11-15 feature pack contract (`tests/vectors/{history,travel,hygiene,access,
/// privacy_proof,import/report}`), written by the Windows agent. Each file is `{"cases": [...]}` or a bare list; a
/// missing file skips its test (the files land in the same pack).
final class FeaturePackVectorTests: XCTestCase {
    typealias Obj = [String: JSONValue]

    static func cases(_ relative: String) throws -> [Obj] {
        let url = Vectors.shared(relative)
        guard FileManager.default.fileExists(atPath: url.path) else { throw XCTSkip("vector file missing: \(relative)") }
        let v = try CanonicalJSON.parse(Array(try Data(contentsOf: url)))
        let list: [JSONValue]
        switch v {
        case .array(let a): list = a
        case .object(let o): guard case .array(let a)? = o["cases"] else { throw XCTSkip("no cases in \(relative)") }; list = a
        default: throw XCTSkip("unexpected shape: \(relative)")
        }
        return list.compactMap { if case .object(let o) = $0 { return o }; return nil }
    }

    static func name(_ c: Obj) -> String { if case .string(let s)? = c["name"] ?? c["id"] { return s }; return "?" }
    static func obj(_ v: JSONValue?) -> Obj { if case .object(let o)? = v { return o }; return [:] }
    static func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }
    static func int(_ v: JSONValue?) -> Int64 { if case .int(let n)? = v { return n }; return 0 }
    static func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { return a }; return [] }
    static func strings(_ v: JSONValue?) -> [String] {
        guard case .array(let a)? = v else { return [] }
        return a.compactMap { if case .string(let s) = $0 { return s }; return nil }
    }
    /// Records given as a map (id → record) or as a list of records with `id`.
    static func records(_ v: JSONValue?) -> [String: Obj] {
        switch v {
        case .object(let o)?: return o.compactMapValues { if case .object(let r) = $0 { return r }; return nil }
        case .array(let a)?:
            var out: [String: Obj] = [:]
            for row in a { if case .object(let r) = row { out[str(r["id"])] = r } }
            return out
        default: return [:]
        }
    }

    // MARK: history

    func test_history_prune_vectors() throws {
        for c in try Self.cases("history/prune.json") {
            let rows: [ItemHistory.Row] = try Self.arr(c["rows"]).map { v in
                let r = Self.obj(v)
                return try ItemHistory.Row(snapshotID: Self.str(r["snapshot_id"]), itemID: Self.str(r["item_id"]),
                                           ns: Self.str(r["ns"]), createdAt: Self.int(r["created_at"]),
                                           changeType: ItemHistory.ChangeType(rawValue: Self.str(r["change_type"])) ?? .update,
                                           record: r["record"] ?? .object([:]))
            }
            let l = Self.obj(c["limits"])
            let limits = ItemHistory.Limits(maxVersions: Int(Self.int(l["max_versions"])), maxAgeDays: Self.int(l["max_age_days"]),
                                            maxBytes: Int(Self.int(l["max_bytes"])))
            let kept = ItemHistory.prune(rows, now: Self.int(c["now"]), limits: limits)
            XCTAssertEqual(Set(kept.map(\.snapshotID)), Set(Self.strings(c["expected_ids"])), Self.name(c))
        }
    }

    func test_history_diff_vectors() throws {
        for c in try Self.cases("history/diff.json") {
            let got = ItemHistory.diff(before: Self.obj(c["before"]), after: Self.obj(c["after"]), kind: Self.str(c["kind"]),
                                       reveal: c["reveal"] == .bool(true))
            let want = Self.arr(c["expected"])
            XCTAssertEqual(got.count, want.count, Self.name(c))
            for (g, w) in zip(got, want) {
                let o = Self.obj(w)
                XCTAssertEqual(g.field, Self.str(o["field"]), Self.name(c))
                XCTAssertEqual(g.before ?? .null, o["before"] ?? .null, "\(Self.name(c)) \(g.field) before")
                XCTAssertEqual(g.after ?? .null, o["after"] ?? .null, "\(Self.name(c)) \(g.field) after")
                XCTAssertEqual(g.secret, o["secret"] == .bool(true), "\(Self.name(c)) \(g.field) secret")
            }
        }
    }

    func test_history_restore_field_vectors() throws {
        for c in try Self.cases("history/restore_field.json") {
            let result = Result { () throws(ItemHistory.RestoreError) -> JSONValue in
                try ItemHistory.restoreField(current: Self.obj(c["current"]), snapshot: Self.obj(c["snapshot"]),
                                             path: Self.str(c["path"]), now: Self.int(c["now"]))
            }
            switch result {
            case .success(let got):
                XCTAssertNil(c["error"], Self.name(c))
                if let want = c["expected"] {
                    XCTAssertEqual(try RecordDigest.canon(got), try RecordDigest.canon(want), Self.name(c))
                }
            case .failure(let error):
                XCTAssertEqual(error.rawValue, Self.str(c["error"]), Self.name(c))
            }
        }
    }

    // MARK: travel

    func test_travel_visible_vectors() throws {
        for c in try Self.cases("travel/visible.json") {
            let subjects = Self.arr(c["items"]).map { v -> TravelMode.Subject in
                let o = Self.obj(v)
                return TravelMode.Subject(id: Self.str(o["id"]), kind: Self.str(o["kind"]), tags: Self.strings(o["tags"]),
                                          collections: Self.strings(o["collections"]))
            }
            let s = Self.obj(c["setting"])
            let setting = TravelMode(on: s["on"] == .bool(true), collections: Self.strings(s["collections"]),
                                     tags: Self.strings(s["tags"]), since: Self.int(s["since"]))
            XCTAssertEqual(setting.hiddenIDs(subjects), Set(Self.strings(c["expected_hidden"])), Self.name(c))
        }
    }

    // MARK: hygiene

    func test_hygiene_duplicates_vectors() throws {
        for c in try Self.cases("hygiene/duplicates.json") {
            let today = c["today"] == nil ? "2026-11-15" : Self.str(c["today"])
            let got = Hygiene.findings(Self.records(c["records"]), now: Self.int(c["now"]), today: today,
                                       matcher: URLMatcher(rules: URLMatchTests.rules))   // every type, as the desktop test
            let wantSet = Set(Self.arr(c["expected"]).map { v -> String in
                let o = Self.obj(v)
                return Self.str(o["type"]) + ":" + Self.strings(o["ids"]).joined(separator: ",")
            })
            XCTAssertEqual(Set(got.map { $0.type.rawValue + ":" + $0.ids.joined(separator: ",") }), wantSet, Self.name(c))
        }
    }

    func test_hygiene_expired_vectors() throws {
        for c in try Self.cases("hygiene/expired.json") {
            let records = Self.records(c["records"])
            let today = Self.str(c["today"])
            let got = Set(records.filter { Hygiene.isExpired($0.value, today: today) }.keys)
            XCTAssertEqual(got, Set(Self.strings(c["expected_ids"])), Self.name(c))
        }
    }

    func test_hygiene_merge_vectors() throws {
        for c in try Self.cases("hygiene/merge.json") {
            let result = Result { () throws(Hygiene.MergeRefusal) -> [String: JSONValue] in
                try Hygiene.merge(keeper: Self.obj(c["keeper"]), other: Self.obj(c["other"]), now: Self.int(c["now"]))
            }
            switch result {
            case .success(let got):
                XCTAssertNil(c["error"], Self.name(c))
                if let want = c["expected"] {
                    XCTAssertEqual(try RecordDigest.canon(.object(got)), try RecordDigest.canon(want), Self.name(c))
                }
            case .failure(let error):
                XCTAssertEqual(error.rawValue, Self.str(c["error"]), Self.name(c))
            }
        }
    }

    /// Every JSON file in `hygiene/` and `privacy_proof/` is one the tests above read (a new file needs a test).
    func test_hygiene_and_privacy_proof_folders_have_no_unread_files() throws {
        let fm = FileManager.default
        func json(_ folder: String) throws -> Set<String> {
            let dir = Vectors.shared(folder)
            guard fm.fileExists(atPath: dir.path) else { throw XCTSkip("\(folder) missing") }
            return Set(try fm.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".json") })
        }
        XCTAssertEqual(try json("hygiene"), ["duplicates.json", "expired.json", "merge.json"])
        XCTAssertEqual(try json("privacy_proof"), ["signed.json", "unsigned.json"])
    }

    // MARK: access

    func test_access_effective_vectors() throws {
        for c in try Self.cases("access/effective.json") {
            let device: AccessRules.DeviceClass = Self.str(c["device_class"]) == "phone" ? .phone : .computer
            let e = AccessRules.effective(Self.obj(c["record"]), device: device, today: Self.str(c["today"]))
            let w = Self.obj(c["expected"])
            XCTAssertEqual(e.reauth, w["reauth"] == .bool(true), "\(Self.name(c)) reauth")
            XCTAssertEqual(e.autofill, w["autofill"] == .bool(true), "\(Self.name(c)) autofill")
            XCTAssertEqual(e.copyOnce, w["copy_once"] == .bool(true), "\(Self.name(c)) copy_once")
            XCTAssertEqual(e.phoneView, w["phone_view"] == .bool(true), "\(Self.name(c)) phone_view")
            XCTAssertEqual(e.expired, w["expired"] == .bool(true), "\(Self.name(c)) expired")
        }
    }

    func test_access_preserve_vectors() throws {
        for c in try Self.cases("access/preserve.json") {
            let got = try Normalise.normalForm(ns: .entry, record: c["input_entry"] ?? .null)
            let wantScope = Self.obj(Self.obj(c["expected_normal_form"])["scope"])["access"]
            let gotScope = Self.obj(Self.obj(got)["scope"])["access"]
            XCTAssertEqual(try RecordDigest.canon(gotScope ?? .null), try RecordDigest.canon(wantScope ?? .null), Self.name(c))
            if let full = c["expected_normal_form"] {
                XCTAssertEqual(try RecordDigest.canon(got), try RecordDigest.canon(full), Self.name(c))
            }
        }
    }

    func test_access_stricter_vectors() throws {
        for c in try Self.cases("access/stricter.json") {
            let got = AccessRules.stricter(c["a"], c["b"])
            XCTAssertEqual(try RecordDigest.canon(got ?? .null), try RecordDigest.canon(c["expected"] ?? .null), Self.name(c))
        }
    }

    // MARK: privacy proof

    func test_privacy_proof_signed_vector() throws {
        let url = Vectors.shared("privacy_proof/signed.json")
        guard FileManager.default.fileExists(atPath: url.path) else { throw XCTSkip("privacy_proof/signed.json missing") }
        let v = Self.obj(try CanonicalJSON.parse(Array(try Data(contentsOf: url))))
        let unsigned = Self.obj(v["unsigned_document"])
        let wantHex = Self.str(v["signed_bytes_hex"])
        XCTAssertFalse(wantHex.isEmpty)
        // D (`signed_body`) and the full signed file both give the vector's signed bytes (only `signature.value` is
        // left out); the document without a signature object has none.
        XCTAssertEqual(Vectors.hexString(try PrivacyProof.signedBytes(Self.obj(v["signed_body"]))), wantHex)
        XCTAssertEqual(Vectors.hexString(try PrivacyProof.signedBytes(Self.obj(v["signed_document"]))), wantHex)
        XCTAssertThrowsError(try PrivacyProof.signedBytes(unsigned))
        // CryptoKit's Ed25519 is hedged (randomised), so this build's signature bytes differ from the deterministic
        // vector: this device's file must have the vector's shape and signed bytes, and both signatures must verify.
        let ids = Self.obj(Self.obj(try CanonicalJSON.parse(Array(Vectors.data("identities.json"))))["devices"])
        let a = Self.obj(Self.obj(ids["A"])["private"])
        let identity = try DeviceIdentity(deviceID: Self.str(a["device_id"]), signingPrivate: try Base64.decodeStrict(Self.str(a["signing_private"])),
                                          exchangePrivate: try Base64.decodeStrict(Self.str(a["exchange_private"])))
        XCTAssertEqual(identity.deviceID, Self.str(v["device_id"]))
        let signed = try PrivacyProof.signed(unsigned, identity: identity)
        XCTAssertEqual(Vectors.hexString(try PrivacyProof.signedBytes(signed)), wantHex)
        guard case .object(var mySig)? = signed["signature"], case .string(let myValue)? = mySig["value"] else {
            return XCTFail("signature object missing")
        }
        mySig["value"] = nil
        XCTAssertEqual(JSONValue.object(mySig), Self.obj(v["signed_body"])["signature"])
        XCTAssertTrue(DeviceIdentity.verify(signature: try Base64.decodeStrict(myValue), message: try PrivacyProof.signedBytes(signed),
                                            publicKey: identity.signingPublicKey))
        var shape = signed
        shape["signature"] = v["signature"]
        XCTAssertEqual(try PrivacyProof.fileBytes(shape), try RecordDigest.canon(v["signed_document"] ?? .null))
        let mine = PrivacyProof.verify(try PrivacyProof.fileBytes(signed))
        XCTAssertEqual(mine.verdict, .valid)
        XCTAssertEqual(mine.deviceID, Self.str(v["device_id"]))
        XCTAssertEqual(mine.fingerprint, Self.str(v["fingerprint"]))
        let theirs = PrivacyProof.verify(try RecordDigest.canon(v["signed_document"] ?? .null))
        XCTAssertEqual(theirs.verdict, .valid)
        XCTAssertEqual(theirs.fingerprint, Self.str(v["fingerprint"]))
        XCTAssertEqual(PrivacyProof.verify(Array(try Data(contentsOf: url))).verdict, .invalid, "the vector wrapper is not a proof file")
    }

    func test_privacy_proof_unsigned_and_rejected_vectors() throws {
        let unsigned = Vectors.shared("privacy_proof/unsigned.json")
        guard FileManager.default.fileExists(atPath: unsigned.path) else { throw XCTSkip("privacy_proof/unsigned.json missing") }
        let raw = Self.obj(try CanonicalJSON.parse(Array(try Data(contentsOf: unsigned))))
        let bytes: [UInt8]
        if let document = raw["document"] { bytes = try RecordDigest.canon(document) } else { bytes = Array(try Data(contentsOf: unsigned)) }
        XCTAssertEqual(PrivacyProof.verify(bytes).verdict, .unsigned)
        XCTAssertEqual(Self.str(raw["expected_result"]), "unsigned")
        // Every file in rejected/ verifies `invalid`; the named ones must be there.
        let dir = Vectors.shared("privacy_proof/rejected")
        let names = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".json") }.sorted()
        let required = ["device_id_changed", "duplicate_key", "extra_top_key", "key_fields_unsigned", "tampered_fact",
                        "version_1", "version_3", "wrong_prefix"]
        XCTAssertTrue(Set(required.map { $0 + ".json" }).isSubset(of: Set(names)), "\(names)")
        for name in names {
            let url = dir.appendingPathComponent(name)
            XCTAssertEqual(PrivacyProof.verify(Array(try Data(contentsOf: url))).verdict, .invalid, name)
        }
    }

    // MARK: import undo

    func test_import_undo_vectors() throws {
        for c in try Self.cases("import/report/undo.json") {
            let j = Self.obj(c["journal"])
            var journal = ImportJournal(importID: Self.str(j["import_id"]), at: Self.int(j["at"]), source: Self.str(j["source"]))
            for (id, d) in Self.obj(j["created"]) { journal.created[id] = Self.str(d) }
            for (id, row) in Self.obj(j["replaced"]) {
                let r = Self.obj(row)
                journal.replaced[id] = try ImportJournal.Replaced(before: r["before"] ?? .null, after: Self.str(r["after"]))
            }
            let current = Self.records(c["current_records"])
            let now = Self.int(c["now"])
            let plan = journal.undo(current: current, now: now)
            var after = current
            for id in plan.trash { after[id] = nil }
            for (id, r) in plan.restore {
                var r = r
                if c["now"] == nil, let cur = current[id] { r["updated_at"] = cur["updated_at"] }   // no clock in the vector
                after[id] = r
            }
            let want = Self.records(c["expected_after_undo"])
            if c["now"] != nil {
                XCTAssertEqual(Set(after.keys), Set(want.keys), Self.name(c))
                for (id, r) in want { XCTAssertEqual(try RecordDigest.canon(.object(after[id] ?? [:])), try RecordDigest.canon(.object(r)), "\(Self.name(c)) \(id)") }
            } else {
                XCTAssertEqual(Set(after.keys), Set(want.keys), Self.name(c))
            }
            XCTAssertEqual(Set(plan.kept), Set(Self.strings(c["expected_kept_ids"])), Self.name(c))
        }
    }
}
