import XCTest
@testable import LGKCore

/// Unit tests of the 2026-11-15 feature pack rules that do not need the shared vectors.
final class FeaturePackTests: XCTestCase {
    typealias Obj = [String: JSONValue]

    func login(_ id: String, origin: String = "https://example.com", user: String = "ann", password: String = "pw1",
               updated: Int64 = 1_000, tags: [String] = [], extra: Obj = [:]) -> Obj {
        var r: Obj = ["id": .string(id), "kind": .string("web"), "label": .string("Example"), "username": .string(user),
                      "password": .string(password), "scope": .object(["origin": .string(origin)]),
                      "created_at": .int(100), "updated_at": .int(updated), "tags": .array(tags.map(JSONValue.string))]
        for (k, v) in extra { r[k] = v }
        return r
    }

    func row(_ sid: String, item: String, at: Int64, record: JSONValue = .object(["a": .int(1)])) throws -> ItemHistory.Row {
        try ItemHistory.Row(snapshotID: sid, itemID: item, ns: "entry", createdAt: at, changeType: .update, record: record)
    }

    // MARK: history

    func test_prune_age_versions_and_bytes() throws {
        let now: Int64 = 100 * 86_400
        let rows = [
            try row("a", item: "1", at: now - 31 * 86_400),            // too old for Free
            try row("b", item: "1", at: now - 10), try row("c", item: "1", at: now - 10),   // tie on created_at
            try row("d", item: "1", at: now - 5), try row("e", item: "1", at: now - 4),
            try row("f", item: "1", at: now - 3), try row("g", item: "1", at: now - 2),
        ]
        let free = ItemHistory.prune(rows, now: now, limits: .free)
        // Newest 5 of b...g: g f e d, then b (snapshot id ascending among equal times).
        XCTAssertEqual(Set(free.map(\.snapshotID)), ["b", "d", "e", "f", "g"])
        let pro = ItemHistory.prune(rows, now: now, limits: .pro)
        XCTAssertEqual(pro.count, 7)
        let size = rows[1].canonicalSize
        let capped = ItemHistory.prune(rows, now: now, limits: .init(maxVersions: 30, maxAgeDays: 365, maxBytes: size * 3))
        XCTAssertEqual(Set(capped.map(\.snapshotID)), ["e", "f", "g"])
    }

    func test_row_size_matches_canonical_row() throws {
        let r = try row("s", item: "i", at: 5, record: .object(["ü": .string("ñ"), "n": .int(3)]))
        let full: JSONValue = .object(["snapshot_id": .string("s"), "item_id": .string("i"), "ns": .string("entry"),
                                       "created_at": .int(5), "change_type": .string("update"),
                                       "record": .object(["ü": .string("ñ"), "n": .int(3)])])
        XCTAssertEqual(r.canonicalSize, try RecordDigest.canon(full).count)
    }

    func test_diff_masks_secrets_and_ignores_local_fields() {
        let before = login("1", password: "old", tags: ["A"], extra: ["site_icon": .string("x"),
                                                                       "policy": .object(["sign_in": .string("never")])])
        var after = login("1", password: "new", updated: 2_000, tags: ["B"])
        after["custom_fields"] = .array([.object(["k": .string("v")])])
        let d = ItemHistory.diff(before: before, after: after, kind: "web")
        XCTAssertEqual(d.map(\.field), ["custom_fields", "password", "tags"])
        XCTAssertEqual(d[1].before, .string(ItemHistory.protectedMarker))
        XCTAssertNil(d[0].before)   // a missing side stays null, also when secret (shared vector history/diff)
        XCTAssertEqual(d[0].after, .string(ItemHistory.protectedMarker))
        XCTAssertEqual(d[2].after, .array([.string("B")]))
        let revealed = ItemHistory.diff(before: before, after: after, kind: "web", reveal: true)
        XCTAssertEqual(revealed[1].before, .string("old"))
        XCTAssertNil(revealed[0].before)
        XCTAssertTrue(ItemHistory.isSecret("payload.name", kind: "identity"))
        XCTAssertFalse(ItemHistory.isSecret("payload.template_id", kind: "identity"))
        XCTAssertTrue(ItemHistory.isSecret("totp.secret", kind: "web"))
    }

    func test_restore_field() throws {
        let current = login("8f0d3c6e-1f3c-4a5b-9d2e-000000000001", user: "new", password: "now")
        let snapshot = login("8f0d3c6e-1f3c-4a5b-9d2e-000000000001", user: "old", password: "then")
        guard case .object(let u) = try ItemHistory.restoreField(current: current, snapshot: snapshot, path: "username", now: 5_000)
        else { return XCTFail() }
        XCTAssertEqual(u["username"], .string("old"))
        XCTAssertEqual(u["updated_at"], .int(5_000))
        guard case .object(let p) = try ItemHistory.restoreField(current: current, snapshot: snapshot, path: "password", now: 5_000)
        else { return XCTFail() }
        XCTAssertEqual(p["password"], .string("then"))
        XCTAssertEqual(p["password_history"], .array([.object(["password": .string("now"), "changed_at": .int(5_000)])]))
        XCTAssertThrowsError(try ItemHistory.restoreField(current: current, snapshot: snapshot, path: "created_at", now: 1)) {
            XCTAssertEqual($0 as? ItemHistory.RestoreError, .notRestorable)
        }
    }

    func test_capture_rows_skip_local_only_changes() throws {
        let id = "8f0d3c6e-1f3c-4a5b-9d2e-000000000002"
        let a = login(id)
        var iconOnly = a; iconOnly["site_icon"] = .string("data:x")
        var edited = a; edited["username"] = .string("bob")
        let before = StoreSnapshot(records: [id: Wrapper.make(ns: .entry, record: .object(a))])
        XCTAssertTrue(ItemHistory.rows(before: before, records: [id: Wrapper.make(ns: .entry, record: .object(iconOnly))],
                                       meta: [:], changeType: .update, now: 9).isEmpty)
        let rows = ItemHistory.rows(before: before, records: [id: Wrapper.make(ns: .entry, record: .object(edited))],
                                    meta: [:], changeType: .sync, now: 9, newID: { "s1" })
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0].changeType, "sync")
        XCTAssertEqual(rows[0].recordObject["username"], .string("ann"))
    }

    // MARK: travel

    func test_travel_hides_by_tag_and_collection() {
        let col = "0b6c0a8e-3c1d-4c7e-9a43-6b2b9a1f0001"
        let subjects = [
            TravelMode.Subject(id: "login", kind: "web", tags: [" bank "], collections: []),
            TravelMode.Subject(id: "oldLogin", kind: "web", tags: [], collections: [col]),
            TravelMode.Subject(id: "card", kind: "card", tags: [], collections: [col.uppercased()]),
            TravelMode.Subject(id: "note", kind: "note", tags: ["Other"], collections: []),
        ]
        let on = TravelMode(on: true, collections: [col], tags: ["BANK"], since: 1)
        XCTAssertEqual(on.hiddenIDs(subjects), ["login", "card"])
        XCTAssertEqual(TravelMode(on: false, collections: [col], tags: ["BANK"]).hiddenIDs(subjects), [])
        XCTAssertFalse(on.changeNeedsPro(to: .off))
        XCTAssertTrue(TravelMode.off.changeNeedsPro(to: on))
        XCTAssertThrowsError(try TravelMode(on: true, tags: (0..<21).map { "t\($0)" }).validated())
    }

    /// Scan 2026-11-15 S-L4: a stored travel setting that can't be read hides every item, survives a save, needs the
    /// owner check to change, and is cleared by turning travel mode off.
    func test_unreadable_travel_setting_fails_closed() throws {
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(LocalData())) as? [String: Any])
        object["travel_mode"] = ["on": "yes", "tags": 3]
        let data = try JSONDecoder().decode(LocalData.self, from: JSONSerialization.data(withJSONObject: object))
        let travel = data.travel
        XCTAssertTrue(travel.on && travel.unreadable)
        let subjects = [TravelMode.Subject(id: "a", kind: "web", tags: [], collections: []),
                        TravelMode.Subject(id: "b", kind: "note", tags: ["x"], collections: [])]
        XCTAssertEqual(travel.hiddenIDs(subjects), ["a", "b"])
        let again = try JSONDecoder().decode(LocalData.self, from: JSONEncoder().encode(try data.validated()))
        XCTAssertEqual(again.travel, travel, "kept across a save")
        XCTAssertTrue(travel.revealsHidden(to: TravelMode(on: true, tags: ["x"])))
        var off = travel
        off.on = false
        XCTAssertTrue(travel.revealsHidden(to: off))
        let saved = try off.validated()
        XCTAssertFalse(saved.unreadable)
        XCTAssertEqual(TravelMode(on: true, tags: ["x"]).hiddenIDs(subjects), ["b"])
    }

    // MARK: hygiene

    func test_findings() {
        let now: Int64 = 2_000_000_000
        var records: [String: Obj] = [
            "a": login("a", user: "Ann ", password: "x", updated: now - 10),
            "b": login("b", user: "ann", password: "x", updated: now - 5),
            "c": login("c", user: "ANN", password: "y", updated: now - 1),
            "d": login("d", origin: "https://www.example.com", user: "ann", updated: now - 1),
            "e": login("e", user: "", password: "z", updated: now - 800 * 86_400),
        ]
        records["k"] = ["id": .string("k"), "kind": .string("desktop"), "updated_at": .int(0)]
        records["card"] = ["id": .string("card"), "kind": .string("card"), "updated_at": .int(now),
                           "payload": .object(["number": .string("4111111111111111"), "expiry": .string("10/26")])]
        let f = Hygiene.findings(records, now: now, today: "2026-11-15", matcher: URLMatcher(rules: URLMatchTests.rules))
        XCTAssertEqual(f.first { $0.type == .sameLogin }?.ids, ["b", "a"])
        XCTAssertEqual(f.first { $0.type == .sameAccountOtherPassword }?.ids, ["c", "b", "a"])
        XCTAssertEqual(Set(f.first { $0.type == .sameSite }?.ids ?? []), ["a", "b", "c", "d"])
        XCTAssertEqual(f.first { $0.type == .notChanged2y }?.ids, ["e"])
        XCTAssertEqual(f.first { $0.type == .expired }?.ids, ["card"])
        XCTAssertFalse(f.contains { $0.ids.contains("k") })
    }

    func test_expired_rules() {
        func card(_ e: String) -> Obj { ["kind": .string("card"), "payload": .object(["expiry": .string(e)])] }
        XCTAssertFalse(Hygiene.isExpired(card("12/26"), today: "2026-12-31"))
        XCTAssertTrue(Hygiene.isExpired(card("12/26"), today: "2027-01-01"))
        let lic: Obj = ["kind": .string("license"), "payload": .object(["expiration_date": .string("20261114")])]
        XCTAssertTrue(Hygiene.isExpired(lic, today: "2026-11-15"))
        let week: Obj = ["kind": .string("license"), "payload": .object(["expiration_date": .string("2026-W01")])]
        XCTAssertFalse(Hygiene.isExpired(week, today: "2027-11-15"))
        let sub: Obj = ["kind": .string("subscription"), "payload": .object(["expiration_date": .string("2020-01-01"),
                                                                             "active": .bool(false)])]
        XCTAssertFalse(Hygiene.isExpired(sub, today: "2026-11-15"))
    }

    func test_merge_logins() throws {
        var keeper = login("k", password: "keep", tags: ["Bank", "x"], extra: [
            "notes": .string("mine"), "recovery_codes": .array([.string("1")]),
            "scope": .object(["origin": .string("https://example.com"), "access": .object(["copy": .string("once")])]),
        ])
        keeper["favorite"] = .bool(false)
        let other = login("o", password: "other", tags: ["bank", "y"], extra: [
            "notes": .string("theirs"), "recovery_codes": .array([.string("1"), .string("2")]), "favorite": .bool(true),
            "scope": .object(["origin": .string("https://example.com"),
                              "access": .object(["phones": .string("view"), "expires": .string("2027-01-01")])]),
            "policy": .object(["fill": .string("never")]),
        ])
        let m = try Hygiene.merge(keeper: keeper, other: other, now: 77)
        XCTAssertEqual(m["tags"], .array([.string("Bank"), .string("x"), .string("y")]))
        XCTAssertEqual(m["password"], .string("keep"))
        XCTAssertEqual(m["password_history"], .array([.object(["password": .string("other"), "changed_at": .int(77)])]))
        XCTAssertEqual(m["notes"], .string("mine\n\ntheirs"))
        XCTAssertEqual(m["recovery_codes"], .array([.string("1"), .string("2")]))
        XCTAssertEqual(m["favorite"], .bool(true))
        guard case .object(let scope)? = m["scope"] else { return XCTFail() }
        XCTAssertEqual(scope["access"], .object(["copy": .string("once"), "phones": .string("view"), "expires": .string("2027-01-01")]))
        XCTAssertNil(scope["urls"], "same origin: nothing added, scope.urls stays absent")
        guard case .object(let policy)? = m["policy"] else { return XCTFail() }
        XCTAssertEqual(policy["fill"], .string("never"))
        let long = login("o", extra: ["notes": .string(String(repeating: "n", count: 20_000))])
        XCTAssertThrowsError(try Hygiene.merge(keeper: keeper, other: long, now: 1)) {
            XCTAssertEqual($0 as? Hygiene.MergeRefusal, .notesTooLong)
        }
    }

    func test_merge_matches_windows_details() throws {
        // Final review S-L1, S-L3: an empty code counts as none, a non-boolean require_master_password stays strict,
        // and keys neither record has are not written (the same digest as Windows).
        let keeper = login("k", extra: ["totp": .object([:]), "policy": .object(["require_master_password": .string("always")])])
        var bare = login("o", extra: ["totp": .object(["secret": .string("JBSWY3DPEHPK3PXP")])])
        bare["tags"] = nil
        let m = try Hygiene.merge(keeper: keeper, other: bare, now: 5)
        XCTAssertEqual(m["totp"], .object(["secret": .string("JBSWY3DPEHPK3PXP")]))
        XCTAssertEqual(m["policy"], .object(["require_master_password": .bool(true)]))
        var plainKeeper = login("k2"); plainKeeper["tags"] = nil
        let plain = try Hygiene.merge(keeper: plainKeeper, other: bare, now: 5)
        XCTAssertNil(plain["tags"]); XCTAssertNil(plain["policy"]); XCTAssertNil(plain["favorite"]); XCTAssertNil(plain["notes"])
        func strict(_ value: JSONValue) -> JSONValue? {
            guard case .object(let p) = Normalise.policy(.object(["require_master_password": value])) else { return nil }
            return p["require_master_password"]
        }
        XCTAssertEqual(strict(.string("always")), .bool(true), "normalising never loosens the rule")
        XCTAssertEqual(strict(.null), .bool(true))
        XCTAssertEqual(strict(.bool(false)), .bool(false))
    }

    func test_summary_counts_distinct_items_in_duplicate_groups() {
        // Final review S-L2: Windows `hygiene.summary` counts each item once, however many groups it is in.
        let s = Hygiene.summary([Hygiene.Finding(type: .sameLogin, ids: ["a", "b", "c"]),
                                 Hygiene.Finding(type: .sameSite, ids: ["a", "b"]),
                                 Hygiene.Finding(type: .notChanged2y, ids: ["d"])])
        XCTAssertEqual(s, Hygiene.Summary(duplicates: 3, notChanged: 1, expired: 0))
    }

    func test_undo_journal_reverts_only_untouched_keepers() {
        let before = login("k", user: "a")
        let written = login("k", user: "b")
        let j = Hygiene.UndoJournal(trashed: ["o"], merged: ["k": .init(before: before, writtenDigest: RecordDigest.digest(.object(written)))])
        XCTAssertEqual(j.revertibleKeepers(current: ["k": written])["k"], before)
        XCTAssertTrue(j.revertibleKeepers(current: ["k": login("k", user: "c")]).isEmpty)
    }

    // MARK: access

    func test_access_effective() {
        func rec(_ access: JSONValue?, policy: Obj = [:]) -> Obj {
            var scope: Obj = ["origin": .string("https://e.com")]
            scope["access"] = access
            return ["kind": .string("web"), "scope": .object(scope), "policy": .object(policy)]
        }
        XCTAssertEqual(AccessRules.effective(rec(nil), device: .phone, today: "2026-11-15"), .open)
        let view = AccessRules.effective(rec(.object(["phones": .string("view")])), device: .phone, today: "2026-11-15")
        XCTAssertTrue(view.phoneView); XCTAssertFalse(view.autofill); XCTAssertFalse(view.reauth)
        XCTAssertTrue(AccessRules.effective(rec(.object(["phones": .string("view")])), device: .computer, today: "2026-11-15").autofill)
        XCTAssertTrue(AccessRules.effective(rec(.object(["copy": .string("twice")])), device: .phone, today: "2026-11-15").copyOnce)
        let unknown = AccessRules.effective(rec(.object(["biometric_only": .bool(true)])), device: .computer, today: "2026-11-15")
        XCTAssertEqual(unknown, .init(reauth: true, autofill: false, copyOnce: true, phoneView: true, expired: false, unknownRule: true))
        XCTAssertTrue(AccessRules.effective(rec(.string("x")), device: .computer, today: "2026-11-15").unknownRule)
        for (date, expired) in [("2026-11-15", true), ("2026-11-14", true), ("2026-11-16", false), ("2026-13-01", true)] {
            let e = AccessRules.effective(rec(.object(["expires": .string(date)])), device: .computer, today: "2026-11-15")
            XCTAssertEqual(e.expired, expired, date)
            XCTAssertEqual(e.reauth, expired, date)
        }
        let strict = AccessRules.effective(rec(nil, policy: ["require_master_password": .bool(true), "fill": .string("never")]),
                                           device: .phone, today: "2026-11-15")
        XCTAssertTrue(strict.reauth); XCTAssertFalse(strict.autofill)
        // Unknown = strictest (scan 2026-11-15 A-L1): a non-boolean require_master_password asks every time.
        XCTAssertTrue(AccessRules.effective(rec(nil, policy: ["require_master_password": .string("yes")]),
                                            device: .computer, today: "2026-11-15").reauth)
        XCTAssertFalse(AccessRules.requiresMasterPassword(rec(nil, policy: ["require_master_password": .bool(false)])))
        XCTAssertFalse(AccessRules.requiresMasterPassword(rec(nil)))
    }

    func test_access_loosens_needs_the_owner() {
        func rec(_ access: JSONValue?, policy: Obj = [:]) -> Obj {
            var scope: Obj = ["origin": .string("https://e.com")]
            scope["access"] = access
            return ["kind": .string("web"), "scope": .object(scope), "policy": .object(policy)]
        }
        let open = rec(nil)
        let strictPolicy = rec(nil, policy: ["require_master_password": .bool(true)])
        let never = rec(nil, policy: ["fill": .string("never")])
        XCTAssertTrue(AccessRules.loosens(from: strictPolicy, to: open))
        XCTAssertTrue(AccessRules.loosens(from: rec(nil, policy: ["require_master_password": .string("yes")]), to: open))
        XCTAssertTrue(AccessRules.loosens(from: never, to: open))
        XCTAssertFalse(AccessRules.loosens(from: open, to: strictPolicy), "tightening never asks")
        XCTAssertFalse(AccessRules.loosens(from: open, to: never))
        let once = rec(.object(["copy": .string("once")])), view = rec(.object(["phones": .string("view")]))
        XCTAssertTrue(AccessRules.loosens(from: once, to: open))
        XCTAssertTrue(AccessRules.loosens(from: view, to: rec(.object(["phones": .string("full")]))))
        XCTAssertFalse(AccessRules.loosens(from: open, to: once))
        XCTAssertFalse(AccessRules.loosens(from: once, to: rec(.object(["copy": .string("once"), "phones": .string("view")]))))
        let expires = rec(.object(["expires": .string("2026-12-01")]))
        XCTAssertTrue(AccessRules.loosens(from: expires, to: open), "expiry removed")
        XCTAssertTrue(AccessRules.loosens(from: expires, to: rec(.object(["expires": .string("2027-01-01")]))), "later")
        XCTAssertFalse(AccessRules.loosens(from: expires, to: rec(.object(["expires": .string("2026-11-20")]))), "earlier")
        XCTAssertTrue(AccessRules.loosens(from: rec(.object(["expires": .string("2026-13-01")])), to: expires),
                      "a malformed expiry reads as expired now")
        // A rule from a newer version reads as all rules on.
        XCTAssertTrue(AccessRules.loosens(from: rec(.string("x")), to: once))
        XCTAssertTrue(AccessRules.loosens(from: rec(.object(["future": .bool(true)])), to: open))
        XCTAssertFalse(AccessRules.loosens(from: once, to: rec(.object(["future": .bool(true)]))))
    }

    func test_access_write_form_keeps_unknown_keys() throws {
        let scope: Obj = ["origin": .string("https://e.com"), "access": .object(["future": .string("ü"), "copy": .string("once")])]
        let out = try AccessRules.writing(.init(copyOnce: false, phonesView: true), into: scope)
        XCTAssertEqual(out["access"], .object(["future": .string("ü"), "phones": .string("view")]))
        let cleared = try AccessRules.writing(.init(), into: ["origin": .string("x"), "access": .object(["copy": .string("once")])])
        XCTAssertNil(cleared["access"])
        XCTAssertTrue(AccessRules.tightens(from: .init(), to: .init(copyOnce: true)))
        XCTAssertFalse(AccessRules.tightens(from: .init(copyOnce: true), to: .init()))
        XCTAssertTrue(AccessRules.tightens(from: .init(expires: "2027-01-01"), to: .init(expires: "2026-12-01")))
        XCTAssertFalse(AccessRules.tightens(from: .init(expires: "2026-12-01"), to: .init(expires: "2027-01-01")))
    }

    func test_normaliser_keeps_scope_access() throws {
        let access: JSONValue = .object(["copy": .string("once"), "zukünftig": .string("é")])
        let entry: JSONValue = .object(["id": .string("x1"), "kind": .string("web"), "label": .string("L"), "username": .string(""),
                                        "password": .string(""), "scope": .object(["origin": .string("https://e.com"), "access": access])])
        guard case .object(let out) = try Normalise.normalForm(ns: .entry, record: entry), case .object(let s)? = out["scope"] else {
            return XCTFail()
        }
        XCTAssertEqual(try RecordDigest.canon(s["access"] ?? .null), try RecordDigest.canon(access))
    }

    // MARK: privacy proof

    func test_privacy_proof_sign_and_verify() throws {
        let identity = try DeviceIdentity.generate(random: SystemRandomSource())
        let doc = PrivacyProof.document(platform: "ios", appVersion: "1.3", generatedAt: "2026-11-15T10:00:00Z",
                                        facts: .init(sync: .folder, devices: 2, shares: 0, items: 12, breachChecks: false,
                                                     strictOffline: true, updateCheck: false))
        let signed = try PrivacyProof.signed(doc, identity: identity)
        let v = PrivacyProof.verify(try PrivacyProof.fileBytes(signed))
        XCTAssertEqual(v.verdict, .valid)
        XCTAssertEqual(v.deviceID, identity.deviceID)
        XCTAssertEqual(v.fingerprint?.count, 16)
        var tampered = signed
        tampered["claims"] = .array([])
        XCTAssertEqual(PrivacyProof.verify(try PrivacyProof.fileBytes(tampered)).verdict, .invalid)
        // Version 2: the device id and key are signed too, so editing them breaks the signature.
        XCTAssertEqual(signed["version"], .int(2))
        guard case .object(var sig)? = signed["signature"] else { return XCTFail("signature object missing") }
        sig["device_id"] = .string("b2222222-0000-4000-8000-00000000000b")
        var renamed = signed
        renamed["signature"] = .object(sig)
        XCTAssertEqual(PrivacyProof.verify(try PrivacyProof.fileBytes(renamed)).verdict, .invalid)
        let unsigned = try PrivacyProof.signed(doc, identity: nil)
        XCTAssertEqual(PrivacyProof.verify(try PrivacyProof.fileBytes(unsigned)).verdict, .unsigned)
        var extra = unsigned
        extra["x"] = .int(1)
        XCTAssertEqual(PrivacyProof.verify(try PrivacyProof.fileBytes(extra)).verdict, .invalid)
        XCTAssertEqual(PrivacyProof.verify(Array(#"{"format":"lgk-privacy-proof","format":"x"}"#.utf8)).verdict, .invalid)
    }

    /// Scan 2026-11-15 S-L5: verify refuses every file Windows `check_shape` refuses, before the signature.
    func test_privacy_proof_shape_matches_windows() throws {
        let facts = PrivacyProof.Facts(sync: .off, devices: 1, shares: 0, items: 3, breachChecks: true,
                                       strictOffline: false, updateCheck: false)
        let doc = try PrivacyProof.signed(PrivacyProof.document(platform: "ios", appVersion: "1.3",
                                                                generatedAt: "2026-11-15T10:00:00Z", facts: facts), identity: nil)
        func verdict(_ change: (inout [String: JSONValue]) -> Void) throws -> PrivacyProof.Verdict {
            var d = doc
            change(&d)
            return PrivacyProof.verify(try PrivacyProof.fileBytes(d)).verdict
        }
        XCTAssertEqual(try verdict { _ in }, .unsigned)
        XCTAssertEqual(try verdict { $0["generated_at"] = .string("2026-11-15 10:00:00") }, .invalid)
        XCTAssertEqual(try verdict { $0["app"] = .object(["platform": .string("linux"), "version": .string("1")]) }, .invalid)
        XCTAssertEqual(try verdict { $0["app"] = .object(["platform": .string("ios"), "version": .string(String(repeating: "9", count: 65))]) }, .invalid)
        XCTAssertEqual(try verdict { d in
            guard case .object(var f)? = d["facts"] else { return }
            f["sync"] = .string("cloud"); d["facts"] = .object(f)
        }, .invalid)
        XCTAssertEqual(try verdict { d in
            guard case .object(var f)? = d["facts"] else { return }
            f["items"] = .int(-1); d["facts"] = .object(f)
        }, .invalid)
        XCTAssertEqual(try verdict { d in
            guard case .object(var f)? = d["facts"] else { return }
            f["strict_offline"] = .int(0); d["facts"] = .object(f)
        }, .invalid)
        XCTAssertEqual(try verdict { $0["claims"] = .array([.string("breach_prefix_only"), .string("breach_prefix_only")]) }, .invalid)
        XCTAssertEqual(try verdict { $0["claims"] = .array([.string("never_online")]) }, .invalid)
        let row: JSONValue = .object(["purpose": .string("p"), "host": .string("h"), "result": .string("ok"), "at": .string("t")])
        XCTAssertEqual(try verdict { $0["network"] = .object(["available": .bool(true), "since": .null,
                                                              "entries": .array(Array(repeating: row, count: 1001)),
                                                              "counts": .object([:])]) }, .invalid)
        XCTAssertEqual(try verdict { $0["network"] = .object(["available": .bool(true), "since": .string("yesterday"),
                                                              "entries": .array([row]), "counts": .object([:])]) }, .invalid)
        XCTAssertEqual(try verdict { $0["network"] = .object(["available": .bool(true), "since": .string("2026-11-01T00:00:00Z"),
                                                              "entries": .array([row]), "counts": .object(["icons": .int(2)])]) },
                       .unsigned)
        XCTAssertEqual(try verdict { $0["signature"] = .object(["alg": .string("Ed25519"), "device_id": .string(""),
                                                                "public_key": .string(""), "value": .string("")]) }, .invalid)
    }

    /// Strict Ed25519 before CryptoKit (`tests/test_privacy_proof_ed25519.py`): RFC 8032 section 7.1 TEST 1 passes;
    /// S >= L, small-order A or R and non-canonical encodings are refused.
    func test_privacy_proof_strict_ed25519_checks() throws {
        let pk = Vectors.hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        let sig = Vectors.hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        func accepted(_ key: [UInt8], _ signature: [UInt8], _ message: [UInt8] = []) -> Bool {
            PrivacyProof.strictEd25519(publicKey: key, signature: signature)
                && DeviceIdentity.verify(signature: signature, message: message, publicKey: key)
        }
        XCTAssertTrue(accepted(pk, sig))
        XCTAssertFalse(accepted(pk, sig, [0]))
        let r = Array(sig[0..<32]), s = Array(sig[32..<64])
        // S >= L: S + L (the same point equation), L itself, all ones.
        XCTAssertFalse(accepted(pk, r + Vectors.hex("4c8c7872aa064e049dbb3013fbf29380d25bf5f0595bbe24655141438e7a101b")))
        XCTAssertFalse(accepted(pk, r + PrivacyProof.groupOrder))
        XCTAssertFalse(accepted(pk, r + [UInt8](repeating: 0xff, count: 32)))
        XCTAssertTrue(PrivacyProof.scalarBelowL(s))
        // The 8 small-order points, as A or as R (the classic forgery: small A, R = identity, S = 0).
        XCTAssertEqual(PrivacyProof.smallOrderPoints.count, 8)
        let identity = Vectors.hex("0100000000000000000000000000000000000000000000000000000000000000")
        for small in PrivacyProof.smallOrderPoints {
            for message in [[UInt8](), Array("any message".utf8), Array("privacy proof".utf8)] {
                XCTAssertFalse(accepted(small, identity + [UInt8](repeating: 0, count: 32), message))
                XCTAssertFalse(accepted(small, small + [UInt8](repeating: 0, count: 32), message))
            }
            XCTAssertFalse(accepted(pk, small + s))
        }
        // Non-canonical encodings: y >= p (p + 1, p, p + 18, 2^255 - 1) and x = 0 with the sign bit set (y = 1, p - 1).
        let nonCanonical = ["eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                            "0100000000000000000000000000000000000000000000000000000000000080",
                            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"].map(Vectors.hex)
        for raw in nonCanonical {
            XCTAssertFalse(PrivacyProof.canonicalPoint(raw), Vectors.hexString(raw))
            XCTAssertFalse(accepted(raw, identity + [UInt8](repeating: 0, count: 32)))
            XCTAssertFalse(accepted(pk, raw + s))
        }
        XCTAssertTrue(PrivacyProof.canonicalPoint(pk))
        XCTAssertTrue(PrivacyProof.canonicalPoint(r))
        // Wrong lengths.
        XCTAssertFalse(accepted(Array(pk.prefix(31)), sig))
        XCTAssertFalse(accepted(pk + [0], sig))
        XCTAssertFalse(accepted(pk, Array(sig.prefix(63))))
        XCTAssertFalse(accepted(pk, sig + [0]))

        // A proof file: a small-order key with R = identity, S = 0 never verifies, whatever the device id.
        let doc = PrivacyProof.document(platform: "ios", appVersion: "1.3", generatedAt: "2026-11-15T10:00:00Z",
                                        facts: .init(sync: .folder, devices: 2, shares: 0, items: 1, breachChecks: false,
                                                     strictOffline: true, updateCheck: false))
        for small in PrivacyProof.smallOrderPoints {
            var forged = doc
            forged["signature"] = .object(["alg": .string("Ed25519"), "device_id": .string("a1111111-0000-4000-8000-00000000000a"),
                                           "public_key": .string(Base64.encode(small)),
                                           "value": .string(Base64.encode(identity + [UInt8](repeating: 0, count: 32)))])
            XCTAssertEqual(PrivacyProof.verify(try PrivacyProof.fileBytes(forged)).verdict, .invalid)
        }
        // A real proof re-signed with S + L (same equation) is refused.
        let device = try DeviceIdentity.generate(random: SystemRandomSource())
        let signed = try PrivacyProof.signed(doc, identity: device)
        guard case .object(var sigObj)? = signed["signature"], case .string(let value)? = sigObj["value"] else {
            return XCTFail("signature object missing")
        }
        var raw = try Base64.decodeStrict(value)
        var carry = 0
        for i in 0..<32 {   // S += L, little-endian
            let sum = Int(raw[32 + i]) + Int(PrivacyProof.groupOrder[i]) + carry
            raw[32 + i] = UInt8(sum & 0xff)
            carry = sum >> 8
        }
        sigObj["value"] = .string(Base64.encode(raw))
        var widened = signed
        widened["signature"] = .object(sigObj)
        XCTAssertEqual(PrivacyProof.verify(try PrivacyProof.fileBytes(signed)).verdict, .valid)
        XCTAssertEqual(PrivacyProof.verify(try PrivacyProof.fileBytes(widened)).verdict, .invalid)
    }

    // MARK: import journal, passkey dismissals, local data

    func test_import_journal_undo() throws {
        let before: [String: Obj] = ["r": login("r", user: "old")]
        let after: [String: Obj] = ["r": login("r", user: "new"), "c": login("c"), "c2": login("c2")]
        let j = try ImportJournal.make(importID: "i", at: 10, source: "bitwarden", ids: ["r", "c", "c2"], before: before, after: after)
        XCTAssertEqual(Set(j.created.keys), ["c", "c2"])
        var current = after
        current["c2"] = login("c2", user: "edited")
        let u = j.undo(current: current, now: 99)
        XCTAssertEqual(u.trash, ["c"])
        XCTAssertEqual(u.kept, ["c2"])
        XCTAssertEqual(u.restore["r"]?["username"], .string("old"))
        XCTAssertEqual(u.restore["r"]?["updated_at"], .int(99))
        XCTAssertTrue(j.isUndoable(now: 10 + 7 * 86_400))
        XCTAssertFalse(j.isUndoable(now: 11 + 7 * 86_400))
    }

    func test_passkey_dismissals() {
        var d: [String: Int64] = [:]
        d = PasskeyUpgrade.dismissing("Example.com", in: d, now: 100)
        XCTAssertTrue(PasskeyUpgrade.isDismissed("example.com", in: d, now: 100 + 89 * 86_400))
        XCTAssertFalse(PasskeyUpgrade.isDismissed("example.com", in: d, now: 100 + 90 * 86_400))
        for i in 0..<510 { d = PasskeyUpgrade.dismissing("d\(i).com", in: d, now: 200 + Int64(i)) }
        XCTAssertEqual(d.count, 500)
        XCTAssertNil(d["example.com"])
    }

    func test_local_data_round_trip_and_old_files() throws {
        var data = LocalData()
        data.itemHistory = [try row("s", item: "i", at: 3)]
        data.travelMode = TravelMode(on: true, collections: ["0B6C0A8E-3C1D-4C7E-9A43-6B2B9A1F0001"], tags: [" Bank "], since: 4)
        data.passkeyUpgradeDismissed = ["example.com": 5]
        let back = try JSONDecoder().decode(LocalData.self, from: JSONEncoder().encode(data.validated()))
        XCTAssertEqual(back.itemHistory, data.itemHistory)
        XCTAssertEqual(back.travelMode?.collections, ["0b6c0a8e-3c1d-4c7e-9a43-6b2b9a1f0001"])
        XCTAssertEqual(back.travelMode?.tags, ["Bank"])
        let old = #"{"trash":[],"events":[],"reminders":[],"collections":[],"preferences":{"trash_retention_days":30,"trash_auto_purge":true,"reminder_default_lead_days":0}}"#
        let decoded = try JSONDecoder().decode(LocalData.self, from: Data(old.utf8))
        XCTAssertTrue(decoded.itemHistory.isEmpty)
        XCTAssertFalse(decoded.travel.on)
    }
}
