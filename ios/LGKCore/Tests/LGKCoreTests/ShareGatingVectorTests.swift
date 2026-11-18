import XCTest
import Foundation
@testable import LGKCore

// Share v2 (keyring format 3, cryptographic approval gating; spec docs/superpowers/specs/2026-11-12-collections-crypto-gating.md)
// against the desktop's bytes in `tests/vectors/share/collections/gating.json` (scripts/make_share_gating_vectors.py):
// create, joins, approval, removal rotation and the v1 upgrade written byte for byte from the recorded random draws (up
// to our hedged Ed25519 signatures, as `SharedCollectionVectorTests`), the content key each device opens, the view sealed
// with C (never opened with G), and the keyrings a device must refuse.

private func o(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let x)? = v { return x }; return [:] }
private func a(_ v: JSONValue?) -> [JSONValue] { if case .array(let x)? = v { return x }; return [] }
private func s(_ v: JSONValue?) -> String { if case .string(let x)? = v { return x }; return "" }
private func i(_ v: JSONValue?) -> Int64 { if case .int(let x)? = v { return x }; return -1 }
private func canonical(_ v: JSONValue) throws -> [UInt8] { try CanonicalJSON.encode(v, dialect: .utf8) }

final class ShareGatingVectorTests: XCTestCase {
    var doc: [String: JSONValue] = [:]
    var gid = ""
    var cid = ""
    var now: Int64 = 0
    var pin = ShareKeyring.Pin(collectionID: "", owner: "", ownerKey: "", sharedMode: "")

    override func setUpWithError() throws {
        doc = o(try CanonicalJSON.parse(Array(try Data(contentsOf: Vectors.shareCollections("gating.json")))))
        gid = s(doc["group_id"])
        cid = s(doc["collection_id"])
        now = i(doc["now"])
        pin = try ShareKeyring.Pin.of(try keyring("create"))
    }

    // MARK: helpers

    func id(_ who: String) throws -> DeviceIdentity { try KeyringTests.identity(who) }
    func kase(_ name: String) -> [String: JSONValue] { o(doc[name]) }
    func keyring(_ name: String) throws -> JSONValue { try XCTUnwrap(kase(name)["keyring"]) }
    func queue(_ c: [String: JSONValue]) -> QueueRandom { QueueRandom(a(c["random_reads_hex"]).map { Vectors.hex(s($0)) }) }
    var password: String { s(doc["password"]) }
    var newPassword: String { s(doc["new_password"]) }

    /// The production Argon2id outputs the generator recorded (`password|salt`); a miss gives a zero key.
    func table() -> Keyring.KeyDerivation {
        let known = o(doc["argon2"]).mapValues { Vectors.hex(s($0)) }
        return { pw, salt in known["\(pw)|\(Base64.encode(salt))"] ?? [UInt8](repeating: 0, count: 32) }
    }

    func pwKey(_ keyring: JSONValue) -> [UInt8] {
        let salt = s(o(o(keyring)["kdf"])["salt"])
        return Vectors.hex(s(o(doc["argon2"])["\(password)|\(salt)"]))
    }

    func gk1() throws -> GroupKey { try GroupKey(groupID: gid, epoch: 1, key: Vectors.hex(s(kase("create")["group_key_hex"]))) }
    func ck1() throws -> GroupKey { try GroupKey(groupID: gid, epoch: 1, key: Vectors.hex(s(kase("create")["content_key_hex"]))) }

    func reason(_ f: () throws -> Any?) -> String? {
        do { _ = try f(); return nil } catch let e as KeyringError { return e.reason } catch let e as SyncFormatError {
            return e.reason
        } catch {
            return "other: \(error)"
        }
    }

    func ids(_ v: JSONValue?) -> Set<String> { Set(a(v).map { s($0) }) }

    /// `mine` with the desktop's signatures from `desktop` and the MAC recomputed under `gk`: CryptoKit hedges Ed25519.
    /// The content block (commitment and wraps) is data, drawn from the same random bytes, so it must match as it is.
    func withDesktopSignatures(_ mine: JSONValue, _ desktop: JSONValue, key gk: GroupKey) throws -> JSONValue {
        var m = o(mine)
        let d = o(desktop)
        if case .object(var sig)? = m["owner_sig"], case .object(let theirs)? = d["owner_sig"] {
            sig["sig"] = theirs["sig"]
            m["owner_sig"] = .object(sig)
        }
        var proofs: [String: JSONValue] = [:]
        for e in a(d["members"]) { proofs[s(o(e)["device_id"])] = o(e)["signing_proof"] ?? .null }
        m["members"] = .array(a(m["members"]).map { e in
            var eo = o(e)
            if let p = proofs[s(eo["device_id"])] { eo["signing_proof"] = p }
            return .object(eo)
        })
        return try Keyring.finish(m, key: gk)
    }

    /// Byte equality with the vector up to our hedged signatures, which must verify (structure, owner sig, MAC).
    func assertMatches(_ mine: JSONValue, _ desktop: JSONValue, key gk: GroupKey, _ what: String,
                       file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(try canonical(try withDesktopSignatures(mine, desktop, key: gk)), try canonical(desktop), what,
                       file: file, line: line)
        XCTAssertNoThrow(try ShareKeyring.parse(try canonical(mine)), what, file: file, line: line)
        XCTAssertNoThrow(try ShareKeyring.parse(try canonical(desktop)), what, file: file, line: line)
        XCTAssertTrue(Keyring.macOK(mine, key: gk), what, file: file, line: line)
        XCTAssertEqual(o(mine)["format"], .int(3), what, file: file, line: line)
    }

    // MARK: writers, byte for byte

    func test_owner_creates_a_share_v2_keyring_byte_for_byte() throws {
        let c = kase("create")
        let random = queue(c)
        let spec = ShareKeyring.Spec(collectionID: cid, name: s(doc["name"]), sharedMode: s(doc["shared_mode"]))
        let (created, gk) = try ShareKeyring.create(password: password, identity: try id("A"), name: "Owner phone", spec: spec,
                                                    random: random, now: FixedClock(now: now), derive: table())
        XCTAssertTrue(random.isEmpty)
        try assertMatches(created, try keyring("create"), key: gk, "create")
        XCTAssertEqual(gk.groupID, gid)
        XCTAssertEqual(gk.key, Vectors.hex(s(c["group_key_hex"])))
        XCTAssertEqual(try ShareKeyring.openContentKey(created, identity: try id("A")), try ck1())
        XCTAssertEqual(ShareKeyring.shareVersion(created), 2)
        XCTAssertNotEqual(try ck1().key, gk.key)
        // Only share formats 2 (legacy) and 3 are written.
        XCTAssertEqual(reason {
            try ShareKeyring.create(password: self.password, identity: try self.id("A"), name: "Owner phone", spec: spec,
                                    random: DetRand("f"), now: FixedClock(now: self.now), derive: self.table(), shareFormat: 4)
        }, "bad-format")
        // The legacy knob writes share v1 (format 2, no content block).
        let (v1, _) = try ShareKeyring.create(password: password, identity: try id("A"), name: "Owner phone", spec: spec,
                                              random: DetRand("v1"), now: FixedClock(now: now), derive: table(), shareFormat: 2)
        XCTAssertEqual(o(v1)["format"], .int(2))
        XCTAssertNil(o(v1)["content"])
        XCTAssertEqual(ShareKeyring.shareVersion(v1), 1)
        XCTAssertEqual(reason { try ShareKeyring.openContentKey(v1, identity: try self.id("A")) }, "not-share-v2")
    }

    func test_joins_and_approval_byte_for_byte() throws {
        let created = try keyring("create")
        let jb = kase("join_b")
        let rb = queue(jb)
        let (joinedB, gkB) = try ShareKeyring.join(created, passwordKey: pwKey(created), identity: try id("B"), name: "Bea",
                                                   random: rb, now: FixedClock(now: now + 60))
        XCTAssertTrue(rb.isEmpty)
        try assertMatches(joinedB, try keyring("join_b"), key: try gk1(), "join_b")
        XCTAssertEqual(gkB, try gk1())

        let ab = kase("approve_b")
        let ra = queue(ab)
        let approved = try ShareKeyring.approvePending(try keyring("join_b"), trusted: try gk1(), identity: try id("A"),
                                                       deviceIDs: a(ab["approve"]).map { s($0) }, random: ra)
        XCTAssertTrue(ra.isEmpty)
        try assertMatches(approved, try keyring("approve_b"), key: try gk1(), "approve_b")
        XCTAssertEqual(try ShareKeyring.openContentKey(approved, identity: try id("B")), try ck1())
        XCTAssertNoThrow(try ShareKeyring.checkSameEpochGrowth(old: try keyring("join_b"), new: approved))

        let jc = kase("join_c")
        let rc = queue(jc)
        let (joinedC, _) = try ShareKeyring.join(try keyring("approve_b"), passwordKey: pwKey(try keyring("approve_b")),
                                                 identity: try id("C"), name: "Cy", random: rc, now: FixedClock(now: now + 120))
        XCTAssertTrue(rc.isEmpty)
        try assertMatches(joinedC, try keyring("join_c"), key: try gk1(), "join_c")
        // A non-owner never approves, and a share v2 approval needs the owner's own content wrap.
        XCTAssertEqual(reason {
            try ShareKeyring.approve(joinedC, trusted: try self.gk1(), identity: try self.id("B"), approve: [try self.id("C").deviceID])
        }, "not-owner")
    }

    func test_owner_removes_byte_for_byte_with_a_new_content_key() throws {
        let joinedC = try keyring("join_c")
        let r = kase("remove_b")
        let remove = a(r["remove"]).map { s($0) }
        let random = queue(r)
        let (rotated, gk2) = try ShareKeyring.rotate(joinedC, trusted: try gk1(), identity: try id("A"), newPassword: newPassword,
                                                     remove: remove, random: random, derive: table())
        XCTAssertTrue(random.isEmpty)
        try assertMatches(rotated, try keyring("remove_b"), key: gk2, "remove_b")
        XCTAssertEqual(gk2.epoch, 2)
        XCTAssertEqual(gk2.key, Vectors.hex(s(r["group_key_hex"])))
        XCTAssertEqual(try ShareKeyring.openContentKey(rotated, identity: try id("A"))?.key, Vectors.hex(s(r["content_key_hex"])))
        XCTAssertEqual(ShareKeyring.approvedMembers(rotated), [try id("A").deviceID])

        // remove_member in one step draws the same bytes (B and the pending C go).
        let removed = try ShareKeyring.removeMember(joinedC, trusted: try gk1(), identity: try id("A"), deviceID: try id("B").deviceID,
                                                    newPassword: newPassword, random: queue(r), issuedAt: now, derive: table())
        try assertMatches(removed.keyring, try keyring("remove_b"), key: removed.key, "removeMember")
        XCTAssertEqual(removed.dropped, remove)
    }

    func test_owner_upgrades_share_v1_byte_for_byte() throws {
        let u = kase("upgrade")
        let stored = try XCTUnwrap(u["stored"])
        let storedGID = s(o(stored)["group_id"])
        let trusted = try GroupKey(groupID: storedGID, epoch: i(o(stored)["epoch"]), key: Vectors.hex(s(u["stored_group_key_hex"])))
        XCTAssertEqual(ShareKeyring.shareVersion(stored), 1)
        XCTAssertEqual(o(stored)["format"], .int(2))
        let random = queue(u)
        // The current share password is kept (allowed for the upgrade only).
        let (upgraded, gk) = try ShareKeyring.upgrade(stored, trusted: trusted, identity: try id("A"), password: s(u["password"]),
                                                      random: random, derive: table())
        XCTAssertTrue(random.isEmpty)
        try assertMatches(upgraded, try XCTUnwrap(u["keyring"]), key: gk, "upgrade")
        XCTAssertEqual(gk.epoch, trusted.epoch + 1)
        XCTAssertEqual(gk.key, Vectors.hex(s(u["group_key_hex"])))
        XCTAssertEqual(ShareKeyring.approvedMembers(upgraded), ids(u["approved"]))
        let content = Vectors.hex(s(u["content_key_hex"]))
        XCTAssertEqual(try ShareKeyring.openContentKey(upgraded, identity: try id("A"))?.key, content)
        XCTAssertEqual(try ShareKeyring.openContentKey(upgraded, identity: try id("B"))?.key, content)
        XCTAssertNil(try ShareKeyring.openContentKey(upgraded, identity: try id("C")))
        // Every member adopts it at epoch + 1 (pending C too: it stays pending).
        let pinV1 = try ShareKeyring.Pin.of(stored)
        for who in ["B", "C"] {
            XCTAssertEqual(try ShareKeyring.adopt(stored: stored, candidate: upgraded, trusted: trusted, identity: try id(who),
                                                  pin: pinV1), gk, who)
        }
        XCTAssertEqual(ShareKeyring.pending(upgraded, own: try id("A").deviceID), [try id("C").deviceID])

        // Refusals: a share v2 keyring, a personal one, another member, a weak password.
        XCTAssertEqual(reason {
            try ShareKeyring.upgrade(upgraded, trusted: gk, identity: try self.id("A"), password: self.password, random: DetRand("u"),
                                     derive: self.table())
        }, "already-v2")
        let personal = try ShareKeyring.parse(Array(try Vectors.data("keyring_epoch1.json")))
        XCTAssertEqual(reason {
            try ShareKeyring.upgrade(personal, trusted: trusted, identity: try self.id("A"), password: self.password,
                                     random: DetRand("p"), derive: self.table())
        }, "not-share")
        XCTAssertEqual(reason {
            try ShareKeyring.upgrade(stored, trusted: trusted, identity: try self.id("B"), password: self.password,
                                     random: DetRand("b"), derive: self.table())
        }, "not-owner")
        XCTAssertEqual(reason {
            try ShareKeyring.upgrade(stored, trusted: trusted, identity: try self.id("A"), password: "short",
                                     random: DetRand("w"), derive: self.table())
        }, "weak-password")
        // A plain rotation still refuses the current password.
        XCTAssertEqual(reason {
            try ShareKeyring.rotate(stored, trusted: trusted, identity: try self.id("A"), newPassword: self.password, remove: [],
                                    random: DetRand("r"), derive: self.table())
        }, "password-reused")
    }

    // MARK: reading

    func test_each_device_opens_exactly_its_content_key() throws {
        let open = o(doc["open"])
        XCTAssertEqual(Set(open.keys), ["create", "join_b", "approve_b", "join_c", "remove_b", "upgrade"])
        for (name, devices) in open {
            let ring = try keyring(name)
            for (who, want) in o(devices) {
                let got = try ShareKeyring.openContentKey(ring, identity: try id(who))
                if case .string(let hex) = want {
                    XCTAssertEqual(got?.key, Vectors.hex(hex), "\(name) \(who)")
                } else {
                    XCTAssertNil(got, "\(name) \(who)")
                }
            }
        }
    }

    func test_view_is_sealed_with_the_content_key_and_never_opens_with_the_group_key() throws {
        let v = kase("view")
        let device = try id(s(v["device"]))
        let states = try a(v["states"]).map { e -> ItemState in
            let st = o(e)
            return try ItemState(itemID: s(st["id"]), vv: o(st["vv"]).mapValues { i($0) }, deleted: false, deletedAt: nil,
                                 item: st["item"])
        }
        let raw = try ViewFile.encode(key: try ck1(), deviceID: device.deviceID, counter: 1, states: states,
                                      now: FixedClock(now: now), random: QueueRandom(a(v["nonce_reads_hex"]).map { Vectors.hex(s($0)) }))
        XCTAssertEqual(raw, try Base64.decodeStrict(s(v["view_b64"])))
        XCTAssertEqual(try ViewFile.decode(raw, key: try ck1(), expectedDeviceID: device.deviceID).states, states)
        XCTAssertEqual(reason { try ViewFile.decode(raw, key: try self.gk1(), expectedDeviceID: device.deviceID) },
                       s(v["group_key_reason"]))
    }

    // MARK: refusals

    func test_adopt_refuses_exactly_what_the_desktop_refuses() throws {
        let negative = a(doc["negative"]).map { o($0) }
        XCTAssertEqual(negative.count, 14)
        for c in negative {
            let trusted = try GroupKey(groupID: gid, epoch: i(c["trusted_epoch"]), key: Vectors.hex(s(c["trusted_key_hex"])))
            let got = reason {
                try ShareKeyring.adopt(stored: try XCTUnwrap(c["stored"]), candidate: try XCTUnwrap(c["candidate"]),
                                       trusted: trusted, identity: try self.id(s(c["device"])), pin: self.pin)
            }
            XCTAssertEqual(got, s(c["reason"]), s(c["name"]))
        }
        // The owner's removal rotation: the approved and the pending member both adopt epoch + 1.
        let positive = a(doc["positive"]).map { o($0) }
        XCTAssertEqual(positive.count, 2)
        for c in positive {
            let trusted = try GroupKey(groupID: gid, epoch: i(c["trusted_epoch"]), key: Vectors.hex(s(c["trusted_key_hex"])))
            let stored = try XCTUnwrap(c["stored"]), candidate = try XCTUnwrap(c["candidate"])
            let gk = try ShareKeyring.adopt(stored: stored, candidate: candidate, trusted: trusted, identity: try id(s(c["device"])),
                                            pin: pin)
            XCTAssertEqual(gk.epoch, i(c["new_epoch"]), s(c["name"]))
            XCTAssertEqual(gk.key, Vectors.hex(s(c["new_key_hex"])), s(c["name"]))
        }
        let openNegative = a(doc["open_negative"]).map { o($0) }
        XCTAssertEqual(openNegative.count, 1)
        for c in openNegative {
            let ring = try XCTUnwrap(c["keyring"])
            // The structure (owner signature included) is fine: only opening the wrap finds the wrong commitment.
            XCTAssertNoThrow(try ShareKeyring.parse(try canonical(ring)), s(c["name"]))
            XCTAssertEqual(reason { try ShareKeyring.openContentKey(ring, identity: try self.id(s(c["device"]))) }, s(c["reason"]),
                           s(c["name"]))
        }
    }

    func test_same_epoch_growth_fixes_the_content_block() throws {
        let created = try keyring("create"), approved = try keyring("approve_b")
        XCTAssertNoThrow(try ShareKeyring.checkSameEpochGrowth(old: created, new: approved))
        // The owner's content wrap swapped or dropped, or the commitment changed: tampering.
        var swapped = o(approved)
        var content = o(swapped["content"])
        var wraps = o(content["wraps"])
        let aID = try id("A").deviceID, bID = try id("B").deviceID
        wraps[aID] = wraps[bID]
        content["wraps"] = .object(wraps)
        swapped["content"] = .object(content)
        XCTAssertEqual(reason { try ShareKeyring.checkSameEpochGrowth(old: approved, new: .object(swapped)) }, "tampered")
        var recommitted = o(approved)
        var c2 = o(recommitted["content"])
        c2["commit"] = .string(Base64.encode([UInt8](repeating: 0, count: 32)))
        recommitted["content"] = .object(c2)
        XCTAssertEqual(reason { try ShareKeyring.checkSameEpochGrowth(old: approved, new: .object(recommitted)) }, "tampered")
        var dropped = o(approved)
        dropped["content"] = nil
        XCTAssertEqual(reason { try ShareKeyring.checkSameEpochGrowth(old: approved, new: .object(dropped)) }, "tampered")
    }

    func test_owner_merge_reuses_its_stored_content_wraps() throws {
        let joinedB = try keyring("join_b"), approved = try keyring("approve_b")
        let g1 = try gk1(), owner = try id("A"), b = try id("B"), c = try id("C")
        // C joined from the folder's joined_b while the owner approved B on its own copy.
        let (racedC, _) = try ShareKeyring.join(joinedB, passwordKey: pwKey(joinedB), identity: c, name: "Cy",
                                                random: DetRand("race"), now: FixedClock(now: now + 90))
        XCTAssertEqual(o(racedC)["format"], .int(3))
        XCTAssertEqual(reason { try ShareKeyring.adopt(stored: approved, candidate: racedC, trusted: g1, identity: owner, pin: self.pin) },
                       "tampered")
        let merged = try XCTUnwrap(ShareKeyring.reconcileOwner(stored: approved, folder: racedC, trusted: g1, identity: owner, pin: pin))
        XCTAssertEqual(ShareKeyring.approvedMembers(merged), [owner.deviceID, b.deviceID])
        XCTAssertEqual(ShareKeyring.pending(merged, own: owner.deviceID), [c.deviceID])
        XCTAssertNoThrow(try ShareKeyring.checkSameEpochGrowth(old: approved, new: merged))
        XCTAssertTrue(ShareKeyring.sameJSON(o(o(merged)["content"])["wraps"], o(o(approved)["content"])["wraps"]))
        XCTAssertEqual(try ShareKeyring.openContentKey(merged, identity: b), try ck1())
        XCTAssertNil(try ShareKeyring.openContentKey(merged, identity: c))
    }
}
