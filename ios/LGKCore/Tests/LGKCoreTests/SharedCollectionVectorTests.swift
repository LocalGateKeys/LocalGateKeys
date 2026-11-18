import XCTest
import Foundation
@testable import LGKCore

// Shared collections (sub-plan 07 Task 5b, the Swift mirror of the Kotlin `SharedCollectionTest`) against the
// desktop's bytes in `tests/vectors/share/collections/` (scripts/make_share_collection_vectors.py): share keyrings
// written and adopted, owner-signed removal, the share view, personal collection states, the `.lgkcol` capability, the
// `features` message, Pro and read-only gating.
//
// CryptoKit signs Ed25519 with hedged randomness, the desktop deterministically (RFC 8032). A keyring this device
// writes is therefore compared with the vector after copying the desktop's signatures (`owner_sig.sig`, each member's
// `signing_proof`) into it and recomputing the MAC: every other byte must be identical, and the desktop signatures
// must verify over our message. Our own signatures are verified separately (`ShareKeyring.parse`).

private func o(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let x)? = v { return x }; return [:] }
private func a(_ v: JSONValue?) -> [JSONValue] { if case .array(let x)? = v { return x }; return [] }
private func s(_ v: JSONValue?) -> String { if case .string(let x)? = v { return x }; return "" }
private func i(_ v: JSONValue?) -> Int64 { if case .int(let x)? = v { return x }; return -1 }
private func canonical(_ v: JSONValue) throws -> [UInt8] { try CanonicalJSON.encode(v, dialect: .utf8) }
private func loadVector(_ name: String) throws -> [String: JSONValue] {
    o(try CanonicalJSON.parse(Array(try Data(contentsOf: Vectors.shareCollections(name)))))
}

final class SharedCollectionVectorTests: XCTestCase {
    static let mergeA = "a1111111-0000-4000-8000-00000000000a"
    static let mergeB = "b2222222-0000-4000-8000-00000000000b"
    static let other = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"

    var ring: [String: JSONValue] = [:]
    var gid = ""
    var cid = ""
    var now: Int64 = 0
    var pin = ShareKeyring.Pin(collectionID: "", owner: "", ownerKey: "", sharedMode: "")

    override func setUpWithError() throws {
        ring = try loadVector("keyring.json")
        gid = s(ring["group_id"])
        cid = s(ring["collection_id"])
        now = i(ring["now"])
        pin = try ShareKeyring.Pin.of(try XCTUnwrap(o(ring["create"])["keyring"]))
    }

    // MARK: helpers

    func id(_ who: String) throws -> DeviceIdentity { try KeyringTests.identity(who) }
    func kase(_ name: String) -> [String: JSONValue] { o(ring[name]) }
    func keyring(_ name: String) throws -> JSONValue { try XCTUnwrap(kase(name)["keyring"]) }
    func queue(_ c: [String: JSONValue]) -> QueueRandom { QueueRandom(a(c["random_reads_hex"]).map { Vectors.hex(s($0)) }) }
    var password: String { s(ring["password"]) }
    var newPassword: String { s(ring["new_password"]) }

    /// The production Argon2id outputs the generator recorded (`password|salt`); a miss gives a zero key, which opens
    /// nothing (as the Kotlin test).
    func table() -> Keyring.KeyDerivation {
        let known = o(ring["argon2"]).mapValues { Vectors.hex(s($0)) }
        return { pw, salt in known["\(pw)|\(Base64.encode(salt))"] ?? [UInt8](repeating: 0, count: 32) }
    }

    /// The Argon2id key of `password` with `keyring`'s salt.
    func pwKey(_ keyring: JSONValue, _ pw: String? = nil) -> [UInt8] {
        let salt = s(o(o(keyring)["kdf"])["salt"])
        return Vectors.hex(s(o(ring["argon2"])["\(pw ?? password)|\(salt)"]))
    }

    func gk1() throws -> GroupKey { try GroupKey(groupID: gid, epoch: 1, key: Vectors.hex(s(kase("create")["group_key_hex"]))) }

    func reason(_ f: () throws -> Any?) -> String? {
        do { _ = try f(); return nil } catch let e as KeyringError { return e.reason } catch let e as RecordError {
            return e.reason
        } catch let e as RemovalError { return e.reason } catch let e as LanSyncError { return e.reason } catch {
            return "other: \(error)"
        }
    }

    func ids(_ v: JSONValue?) -> Set<String> { Set(a(v).map { s($0) }) }

    /// `mine` with the desktop's signatures from `desktop` and the MAC recomputed under `gk` (see the file comment).
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
    }

    // MARK: keyring writers, byte for byte

    func test_owner_creates_the_share_keyring_byte_for_byte() throws {
        let c = kase("create")
        let random = queue(c)
        let spec = ShareKeyring.Spec(collectionID: cid, name: s(ring["name"]), sharedMode: s(ring["shared_mode"]))
        // keyring.json is the legacy share v1 (format 2): written with the explicit v1 knob (share v2 is `gating.json`).
        let (created, gk) = try ShareKeyring.create(password: password, identity: try id("A"), name: "Owner phone", spec: spec,
                                                    random: random, now: FixedClock(now: now), derive: table(), shareFormat: 2)
        XCTAssertTrue(random.isEmpty)
        try assertMatches(created, try keyring("create"), key: gk, "create")
        XCTAssertEqual(gk.groupID, gid)
        XCTAssertEqual(gk.key, Vectors.hex(s(c["group_key_hex"])))
        XCTAssertEqual(try ShareKeyring.shareName(created, key: gk), s(ring["name"]))
        XCTAssertEqual(ShareKeyring.approvedMembers(created), ids(c["approved"]))
        // The name never appears in the keyring's bytes.
        XCTAssertFalse(String(decoding: try canonical(created), as: UTF8.self).contains("Family"))
        let owner = try id("A")
        XCTAssertEqual(pin, ShareKeyring.Pin(collectionID: cid, owner: owner.deviceID, ownerKey: Base64.encode(owner.signingPublicKey),
                                             sharedMode: "read"))
        let pinned = o(ring["pinned"])
        XCTAssertEqual(pin, ShareKeyring.Pin(collectionID: s(pinned["collection_id"]), owner: s(pinned["owner"]),
                                             ownerKey: s(pinned["owner_key"]), sharedMode: s(pinned["shared_mode"])))
        XCTAssertFalse(String(describing: spec).contains("Family"))
    }

    func test_joins_and_approval_byte_for_byte() throws {
        let created = try keyring("create")
        let b = kase("join_b")
        let random = queue(b)
        let (joinedB, gkB) = try ShareKeyring.join(created, passwordKey: pwKey(created), identity: try id("B"), name: "Bea",
                                                   random: random, now: FixedClock(now: now + 60))
        XCTAssertTrue(random.isEmpty)
        try assertMatches(joinedB, try keyring("join_b"), key: try gk1(), "join_b")
        XCTAssertEqual(gkB, try gk1())
        XCTAssertEqual(ShareKeyring.pending(try keyring("join_b"), own: try id("A").deviceID), [try id("B").deviceID])
        XCTAssertEqual(ShareKeyring.approvedMembers(joinedB), ids(b["approved"]))

        let approved = try ShareKeyring.approvePending(try keyring("join_b"), trusted: try gk1(), identity: try id("A"),
                                                       deviceIDs: [try id("B").deviceID])
        try assertMatches(approved, try keyring("approve_b"), key: try gk1(), "approve_b")
        XCTAssertEqual(ShareKeyring.approvedMembers(approved), ids(kase("approve_b")["approved"]))

        let c = kase("join_c")
        let rc = queue(c)
        let (joinedC, _) = try ShareKeyring.join(try keyring("approve_b"), passwordKey: pwKey(try keyring("approve_b")),
                                                 identity: try id("C"), name: "Cy", random: rc, now: FixedClock(now: now + 120))
        XCTAssertTrue(rc.isEmpty)
        try assertMatches(joinedC, try keyring("join_c"), key: try gk1(), "join_c")
        let names: [String: String?] = [try id("A").deviceID: "Owner phone", try id("B").deviceID: "Bea", try id("C").deviceID: "Cy"]
        XCTAssertEqual(Keyring.memberNames(joinedC, key: try gk1()), names)
    }

    func test_owner_removes_a_member_byte_for_byte_and_only_the_owner_notice_counts() throws {
        let joinedC = try keyring("join_c")
        let r = kase("remove_b")
        let random = queue(r)
        let remove = a(r["remove"]).map { s($0) }
        let (rotated, gk2) = try ShareKeyring.rotate(joinedC, trusted: try gk1(), identity: try id("A"), newPassword: newPassword,
                                                     remove: remove, random: random, derive: table())
        XCTAssertTrue(random.isEmpty)
        try assertMatches(rotated, try keyring("remove_b"), key: gk2, "remove_b")
        XCTAssertEqual(gk2.key, Vectors.hex(s(r["group_key_hex"])))
        XCTAssertEqual(gk2.epoch, 2)
        XCTAssertEqual(try ShareKeyring.shareName(rotated, key: gk2), s(ring["name"]))
        XCTAssertEqual(ShareKeyring.approvedMembers(rotated), [try id("A").deviceID])

        // The notice: the desktop's bytes up to our hedged signature, which verifies.
        let issued = i(r["notice_issued_at"])
        let desktopNotice = Array(s(r["notice"]).utf8)
        let notice = try RemovalNotice.make(identity: try id("A"), groupID: gid, deviceID: try id("B").deviceID, epoch: 2,
                                            issuedAt: issued)
        let mine = try RemovalNotice.parse(notice), theirs = try RemovalNotice.parse(desktopNotice)
        XCTAssertEqual(mine.notice, theirs.notice)
        XCTAssertEqual(mine.message, theirs.message)
        XCTAssertEqual(String(decoding: notice, as: UTF8.self)
            .replacingOccurrences(of: Base64.encode(mine.signature), with: Base64.encode(theirs.signature)), s(r["notice"]))
        let ringBytes = try canonical(rotated)
        let watchB = try XCTUnwrap(ShareAccess.removalWatch(groupID: gid, deviceID: try id("B").deviceID, epoch: 1,
                                                            installID: "", folder: ".", pin: pin))
        XCTAssertEqual(watchB.signers, [try id("A").deviceID: Base64.encode(try id("A").signingPublicKey)])
        XCTAssertEqual(watchB.signers, o(r["watch_signers"]).mapValues { s($0) })
        XCTAssertEqual(try RemovalNotice.verify(notice, watch: watchB, folderKeyring: ringBytes).signer, try id("A").deviceID)
        XCTAssertEqual(try RemovalNotice.verify(desktopNotice, watch: watchB, folderKeyring: ringBytes).signer, try id("A").deviceID)

        // remove_member in one step: B and the never-approved C go, the notice names B. It also upgrades this share v1
        // to share v2 (format 3, a new content key for the owner), so after the v1 draws it draws C and the owner's wrap.
        let removed = try ShareKeyring.removeMember(joinedC, trusted: try gk1(), identity: try id("A"), deviceID: try id("B").deviceID,
                                                    newPassword: newPassword, random: queue(r), issuedAt: issued, derive: table())
        XCTAssertEqual(removed.key, gk2)
        XCTAssertEqual(Keyring.obj(removed.keyring)["format"], .int(3))
        XCTAssertEqual(ShareKeyring.shareVersion(removed.keyring), 2)
        XCTAssertNoThrow(try ShareKeyring.parse(try canonical(removed.keyring)))
        XCTAssertEqual(ShareKeyring.approvedMembers(removed.keyring), [try id("A").deviceID])
        XCTAssertNotNil(try ShareKeyring.openContentKey(removed.keyring, identity: try id("A")))
        XCTAssertEqual(ShareKeyring.memberIDs(removed.keyring), ShareKeyring.memberIDs(rotated))
        XCTAssertEqual(try ShareKeyring.shareName(removed.keyring, key: removed.key), s(ring["name"]))
        XCTAssertEqual(try RemovalNotice.parse(removed.notice).notice, theirs.notice)
        XCTAssertEqual(removed.dropped, remove)
        XCTAssertFalse(String(describing: removed).contains(Base64.encode(removed.key.key)))
        XCTAssertEqual(reason {
            try ShareKeyring.removeMember(joinedC, trusted: try self.gk1(), identity: try self.id("B"), deviceID: try self.id("C").deviceID,
                                          newPassword: self.newPassword, random: DetRand("x"), issuedAt: issued, derive: self.table())
        }, "not-owner")
        // The owner's device never acts on a notice; a member's notice is not the owner's.
        XCTAssertNil(ShareAccess.removalWatch(groupID: gid, deviceID: try id("A").deviceID, epoch: 1, installID: "", folder: ".", pin: pin))
        let forged = kase("forged_notice")
        let watchC = try XCTUnwrap(ShareAccess.removalWatch(groupID: gid, deviceID: try id("C").deviceID, epoch: 1,
                                                            installID: "", folder: ".", pin: pin))
        XCTAssertEqual(reason { try RemovalNotice.verify(Array(s(forged["notice"]).utf8), watch: watchC, folderKeyring: ringBytes) },
                       s(forged["reason"]))
    }

    func test_only_the_owner_changes_the_share() throws {
        let joinedC = try keyring("join_c")
        let approved = try keyring("approve_b")
        let g1 = try gk1(), b = try id("B"), c = try id("C"), owner = try id("A")
        XCTAssertEqual(reason { try ShareKeyring.approve(joinedC, trusted: g1, identity: b, approve: [c.deviceID]) }, "not-owner")
        XCTAssertEqual(reason {
            try ShareKeyring.rotate(joinedC, trusted: g1, identity: b, newPassword: self.newPassword, remove: [c.deviceID],
                                    random: DetRand("b"), derive: self.table())
        }, "not-owner")
        XCTAssertEqual(reason { try ShareKeyring.approvePending(approved, trusted: g1, identity: owner, deviceIDs: [b.deviceID]) },
                       "not-pending")
        XCTAssertEqual(reason { try ShareKeyring.approvePending(joinedC, trusted: g1, identity: owner, deviceIDs: []) }, "not-pending")
        for spec in [ShareKeyring.Spec(collectionID: cid.uppercased(), name: "Family", sharedMode: "read"),
                     ShareKeyring.Spec(collectionID: cid, name: " Family", sharedMode: "read"),
                     ShareKeyring.Spec(collectionID: cid, name: "Family", sharedMode: "write"),
                     ShareKeyring.Spec(collectionID: cid, name: String(repeating: "x", count: 101), sharedMode: "read")] {
            XCTAssertEqual(reason {
                try ShareKeyring.create(password: "pw", identity: owner, name: "x", spec: spec, random: DetRand("s"),
                                        now: FixedClock(now: self.now), derive: self.table())
            }, "bad-metadata", spec.description)
        }
    }

    // MARK: device sync and shares stay apart

    func test_device_sync_refuses_a_share_keyring_and_a_share_refuses_a_device_sync_keyring() throws {
        let created = try keyring("create")
        let share = try canonical(created)
        XCTAssertEqual(reason { try Keyring.parse(share) }, "share-group")
        XCTAssertEqual(reason { try Keyring.accept(created, trusted: try self.gk1(), identity: try self.id("A")) }, "share-group")
        XCTAssertEqual(reason { try Keyring.unwrapWithPassword(created, password: self.password) }, "share-group")
        XCTAssertEqual(reason {
            try Keyring.join(created, identity: try self.id("C"), name: "Cy", random: DetRand("j"), now: FixedClock(now: self.now)) {
                self.pwKey(created)
            }
        }, "share-group")
        XCTAssertEqual(reason {
            try Keyring.rotate(created, trusted: try self.gk1(), identity: try self.id("A"), newPassword: self.newPassword,
                               remove: [], random: DetRand("r"), derive: self.table())
        }, "share-group")
        XCTAssertNoThrow(try ShareKeyring.parse(share))
        let personal = Array(try Vectors.data("keyring_epoch1.json"))
        let parsed = try ShareKeyring.parse(personal)
        XCTAssertEqual(reason { try ShareKeyring.requireShare(parsed) }, "not-share")
        XCTAssertEqual(reason { try ShareKeyring.Pin.of(parsed) }, "not-share")
        XCTAssertEqual(reason {
            try ShareKeyring.join(parsed, passwordKey: [UInt8](repeating: 0, count: 32), identity: try self.id("C"), name: "Cy",
                                  random: DetRand("d"), now: FixedClock(now: self.now))
        }, "not-share")
        // A collection state id is never an item id in device sync.
        let item: JSONValue = .object(["ns": .string("item"), "schema": .int(1), "updated_at": .int(0),
                                       "record": .object(["id": .string("col:\(cid)"), "kind": .string("note")])])
        let state = try ItemState(itemID: "col:\(cid)", vv: [Self.mergeA: 1], deleted: false, deletedAt: nil, item: item)
        XCTAssertEqual(reason { try Wrapper.unwrap(state, isCopy: false) }, "bad-remote")
    }

    // MARK: adopting: the negative and positive vectors

    func test_adopt_refuses_exactly_what_the_desktop_refuses() throws {
        let negative = a(ring["negative"])
        XCTAssertEqual(negative.count, 6)
        for c in negative.map { o($0) } {
            let trusted = try GroupKey(groupID: gid, epoch: i(c["trusted_epoch"]), key: Vectors.hex(s(c["trusted_key_hex"])))
            let device = try id(s(c["device"]))
            let got = reason {
                try ShareKeyring.adopt(stored: try XCTUnwrap(c["stored"]), candidate: try XCTUnwrap(c["candidate"]),
                                       trusted: trusted, identity: device, pin: self.pin)
            }
            XCTAssertEqual(got, s(c["reason"]), s(c["name"]))
        }
        let positive = a(ring["positive"])
        XCTAssertEqual(positive.count, 3)
        for c in positive.map { o($0) } {
            let trusted = try GroupKey(groupID: gid, epoch: i(c["trusted_epoch"]), key: Vectors.hex(s(c["trusted_key_hex"])))
            let stored = try XCTUnwrap(c["stored"]), candidate = try XCTUnwrap(c["candidate"])
            let gk = try ShareKeyring.adopt(stored: stored, candidate: candidate, trusted: trusted, identity: try id(s(c["device"])),
                                            pin: pin)
            XCTAssertEqual(gk.epoch, i(c["new_epoch"]), s(c["name"]))
            XCTAssertEqual(gk.key, Vectors.hex(s(c["new_key_hex"])), s(c["name"]))
            XCTAssertTrue(ShareKeyring.growsFrom(old: stored, new: candidate), s(c["name"]))
            XCTAssertFalse(ShareKeyring.growsFrom(old: candidate, new: stored), s(c["name"]))
        }
        // The removed member: the rotation wraps no key for it.
        XCTAssertEqual(reason {
            try ShareKeyring.adopt(stored: try self.keyring("join_c"), candidate: try self.keyring("remove_b"), trusted: try self.gk1(),
                                   identity: try self.id("B"), pin: self.pin)
        }, "not-member")
        // Another pin (a different owner key) is tampering even for a genuine keyring.
        let other = ShareKeyring.Pin(collectionID: pin.collectionID, owner: pin.owner,
                                     ownerKey: Base64.encode(try id("B").signingPublicKey), sharedMode: pin.sharedMode)
        XCTAssertEqual(reason {
            try ShareKeyring.adopt(stored: try self.keyring("join_b"), candidate: try self.keyring("approve_b"), trusted: try self.gk1(),
                                   identity: try self.id("B"), pin: other)
        }, "tampered")
    }

    func test_owner_merges_a_join_that_raced_its_approval_and_a_lost_join_is_told_to_join_again() throws {
        let created = try keyring("create"), joinedB = try keyring("join_b"), approved = try keyring("approve_b")
        let g1 = try gk1(), owner = try id("A"), b = try id("B"), c = try id("C")
        // C joined from the folder's joined_b while the owner approved B on its own copy.
        let (racedC, _) = try ShareKeyring.join(joinedB, passwordKey: pwKey(joinedB), identity: c, name: "Cy",
                                                random: DetRand("race"), now: FixedClock(now: now + 90))
        XCTAssertEqual(reason { try ShareKeyring.adopt(stored: approved, candidate: racedC, trusted: g1, identity: owner, pin: self.pin) },
                       "tampered")
        let merged = try XCTUnwrap(ShareKeyring.reconcileOwner(stored: approved, folder: racedC, trusted: g1, identity: owner, pin: pin))
        XCTAssertEqual(ShareKeyring.approvedMembers(merged), [owner.deviceID, b.deviceID])
        XCTAssertEqual(ShareKeyring.pending(merged, own: owner.deviceID), [c.deviceID])
        XCTAssertNoThrow(try ShareKeyring.checkSameEpochGrowth(old: approved, new: merged))
        XCTAssertNil(ShareKeyring.reconcileOwner(stored: approved, folder: racedC, trusted: g1, identity: b, pin: pin))

        // B and C joined from the same created keyring; C's keyring reached the folder.
        let (onlyC, _) = try ShareKeyring.join(created, passwordKey: pwKey(created), identity: c, name: "Cy",
                                               random: DetRand("c-first"), now: FixedClock(now: now + 61))
        XCTAssertTrue(ShareKeyring.supersededJoin(stored: joinedB, folder: onlyC, trusted: g1, identity: b, pin: pin))
        XCTAssertFalse(ShareKeyring.supersededJoin(stored: joinedB, folder: joinedB, trusted: g1, identity: b, pin: pin))
        XCTAssertFalse(ShareKeyring.supersededJoin(stored: created, folder: onlyC, trusted: g1, identity: owner, pin: pin))
        // A folder keyring that also dropped someone else (B) is not a lost join, nor is another epoch.
        XCTAssertFalse(ShareKeyring.supersededJoin(stored: try keyring("join_c"), folder: created, trusted: g1, identity: c, pin: pin))
        XCTAssertFalse(ShareKeyring.supersededJoin(stored: try keyring("join_c"), folder: try keyring("remove_b"), trusted: g1,
                                                   identity: c, pin: pin))
    }

    // MARK: the share view

    func test_share_view_publishes_only_the_collection_with_personal_fields_stripped() throws {
        let view = try loadVector("view.json")
        let c = s(view["collection_id"])
        let expected = a(view["shared"]).map { o($0) }
        let shared = a(view["vault_items"]).filter { ShareView.isShared($0, collectionID: c) }
        XCTAssertEqual(shared.map { s(o($0)["id"]) }, expected.map { s($0["id"]) })
        for (record, e) in zip(shared, expected) {
            let w = try ShareView.wrapper(record, collectionID: c)
            XCTAssertEqual(try canonical(w), try canonical(try XCTUnwrap(e["wrapper"])), s(e["id"]))
            XCTAssertEqual(try SyncMeta.digest(w), s(e["digest"]), s(e["id"]))
        }
        for unshared in a(view["vault_items"]) where !ShareView.isShared(unshared, collectionID: c) {
            XCTAssertThrowsError(try ShareView.wrapper(unshared, collectionID: c), s(o(unshared)["id"]))
        }
        let incoming = a(view["incoming"]).map { o($0) }
        XCTAssertFalse(incoming.isEmpty)
        for k in incoming {
            let state = try ItemState(itemID: s(k["id"]), vv: [Self.mergeB: 1], deleted: false, deletedAt: nil, item: k["wrapper"])
            XCTAssertEqual(reason { try ShareView.checkIncoming(state, collectionID: c) } ?? "ok", s(k["verdict"]), s(k["name"]))
        }
        XCTAssertEqual(ShareView.localOnlyItemFields, a(view["share_local_only_item_fields"]).map { s($0) })
    }

    // MARK: personal collection states

    func test_collection_states_match_the_desktop_and_malformed_ones_are_refused() throws {
        let doc = try loadVector("states.json")
        let prefixes = o(doc["prefixes"])
        XCTAssertEqual([CollectionStates.catalogPrefix, CollectionStates.membershipPrefix, CollectionStates.linkPrefix],
                       ["catalog", "membership", "link"].map { s(prefixes[$0]) })
        let valid = a(doc["valid"]).map { o($0) }
        XCTAssertEqual(valid.count, 3)
        let copyID = "8f1e2d3c-4b5a-4968-8776-655443322110"
        for v in valid {
            let sid = s(v["id"])
            let state = try ItemState(itemID: sid, vv: [Self.mergeA: 1], deleted: false, deletedAt: nil, item: v["wrapper"])
            let record = try CollectionStates.unwrap(state, isCopy: false)
            let rebuilt: JSONValue
            switch s(record["kind"]) {
            case "collection":
                rebuilt = CollectionStates.catalog(collectionID: s(record["collection_id"]), name: s(record["name"]),
                                                   description: s(record["description"]), createdAt: i(record["created_at"]),
                                                   updatedAt: i(record["updated_at"]))
            case "membership":
                rebuilt = CollectionStates.membership(itemID: s(record["item_id"]),
                                                      collectionIDs: Array(a(record["collection_ids"]).map { s($0) }.reversed()))
            default:
                rebuilt = CollectionStates.link(collectionID: s(record["collection_id"]), mode: s(record["mode"]), role: s(record["role"]))
            }
            let wrapper = CollectionStates.wrapper(rebuilt)
            XCTAssertEqual(try canonical(wrapper), try canonical(try XCTUnwrap(v["wrapper"])), sid)
            XCTAssertEqual(try SyncMeta.digest(wrapper), s(v["digest"]), sid)
            XCTAssertEqual(CollectionStates.stateID(rebuilt), sid)
            // A device without collection sync refuses them in device sync: quarantined, never stored.
            XCTAssertEqual(SyncRunner.check(state, licenseKeys: [:]), "bad-remote", sid)
            // A conflict copy of a collection state names its state through its record.
            var copy = o(v["wrapper"])
            copy["id"] = JSONValue.string(copyID)
            let copyState = try ItemState(itemID: copyID, vv: [Self.mergeA: 1], deleted: false, deletedAt: nil, item: .object(copy))
            XCTAssertNoThrow(try CollectionStates.unwrap(copyState, isCopy: true), sid)
        }
        let malformed = a(doc["malformed"]).map { o($0) }
        XCTAssertEqual(malformed.count, 23)
        for m in malformed {
            let state = try ItemState(itemID: s(m["id"]), vv: [Self.mergeA: 1], deleted: false, deletedAt: nil, item: m["wrapper"])
            XCTAssertEqual(reason { try CollectionStates.unwrap(state, isCopy: false) }, s(m["verdict"]), s(m["name"]))
        }
        XCTAssertEqual(CollectionStates.union([Self.other], [cid, Self.other]), [cid, Self.other])
        let many = (0..<21).map { String(format: "%08d-0000-4000-8000-000000000000", $0) }
        XCTAssertNil(CollectionStates.union(Array(many[0..<15]), Array(many[15...])))
        XCTAssertEqual(CollectionStates.union(Array(many[0..<10]), Array(many[10..<20]))?.count, 20)
    }

    // MARK: capability file and features message

    func test_lgkcol_capability_and_features_message() throws {
        let doc = try loadVector("capability.json")
        let gk = try GroupKey(groupID: s(doc["group_id"]), epoch: i(doc["epoch"]), key: Vectors.hex(s(doc["group_key_hex"])))
        let deviceA = try id("A"), deviceB = try id("B")
        let signer = Base64.encode(deviceA.signingPublicKey)
        func file(_ name: String) throws -> (raw: [UInt8], sig: [UInt8]) {
            (try Base64.decodeStrict(s(o(doc[name])["file_b64"])), try Base64.decodeStrict(s(o(doc[name])["sig_b64"])))
        }
        let col = try file("lgkcol"), cap = try file("lgkcap")
        XCTAssertEqual(i(o(doc["lgkcol"])["counter"]), FeatureCapability.Feature.collections.counter)
        XCTAssertEqual(i(o(doc["lgkcap"])["counter"]), FeatureCapability.Feature.documents.counter)
        XCTAssertEqual(FeatureCapability.Feature.collections.suffix, s(o(doc["suffixes"])["collections"]))
        XCTAssertEqual(FeatureCapability.Feature.collections.signatureSuffix, s(o(doc["suffixes"])["collections_sig"]))
        XCTAssertEqual(FeatureCapability.Feature.documents.suffix, FolderBlobs.capSuffix)
        XCTAssertTrue(FeatureCapability.verify(col.raw, sig: col.sig, key: gk, deviceID: deviceA.deviceID, signer: signer, feature: .collections))
        XCTAssertTrue(FeatureCapability.verify(cap.raw, sig: cap.sig, key: gk, deviceID: deviceA.deviceID, signer: signer, feature: .documents))
        // A file copied under the other name never counts; nor another signer or another device.
        XCTAssertFalse(FeatureCapability.verify(cap.raw, sig: cap.sig, key: gk, deviceID: deviceA.deviceID, signer: signer, feature: .collections))
        XCTAssertFalse(FeatureCapability.verify(col.raw, sig: col.sig, key: gk, deviceID: deviceA.deviceID, signer: signer, feature: .documents))
        XCTAssertFalse(FeatureCapability.verify(col.raw, sig: col.sig, key: gk, deviceID: deviceA.deviceID,
                                                signer: Base64.encode(deviceB.signingPublicKey), feature: .collections))
        XCTAssertFalse(FeatureCapability.verify(col.raw, sig: col.sig, key: gk, deviceID: deviceB.deviceID, signer: signer, feature: .collections))
        XCTAssertFalse(FeatureCapability.verify(col.raw, sig: col.sig, key: gk, deviceID: deviceA.deviceID, signer: nil, feature: .collections))
        let mine = try FeatureCapability.encode(key: gk, identity: deviceA, feature: .collections, clock: FixedClock(now: now),
                                                random: DetRand("cap"))
        XCTAssertTrue(FeatureCapability.verify(mine.file, sig: mine.sig, key: gk, deviceID: deviceA.deviceID, signer: signer, feature: .collections))

        // The folder's documents check: `.lgkcap` counts, a `.lgkcol` copied under its name does not.
        let folder = MemoryFolder()
        let paths = try XCTUnwrap(FolderBlobs.capPaths(deviceA.deviceID))
        folder.files[paths.cap] = cap.raw
        folder.files[paths.sig] = cap.sig
        XCTAssertTrue(FolderBlobs(access: folder).capable(gk, deviceID: deviceA.deviceID, signer: signer))
        folder.files[paths.cap] = col.raw
        folder.files[paths.sig] = col.sig
        XCTAssertFalse(FolderBlobs(access: folder).capable(gk, deviceID: deviceA.deviceID, signer: signer))

        XCTAssertEqual(try LanFeatures.encode([LanFeatures.collections]), Array(s(doc["features_message"]).utf8))
        XCTAssertEqual(a(doc["features"]).map { s($0) }, [LanFeatures.collections])
        XCTAssertEqual(i(doc["max_features"]), Int64(LanFeatures.maxFeatures))
        let messages = a(doc["messages"]).map { o($0) }
        XCTAssertEqual(messages.count, 9)
        for m in messages {
            XCTAssertEqual(reason { try LanFeatures.parse(Array(s(m["raw"]).utf8)) } ?? "ok", s(m["verdict"]), s(m["name"]))
        }
        // The live parser reads it (5d), with the same verdicts; whether a responder answers or refuses it is
        // CollectionSyncTests'.
        XCTAssertEqual(try LanMessages.parse(try LanFeatures.encode([LanFeatures.collections])), .features([LanFeatures.collections]))
        XCTAssertEqual(try LanMessages.encode(.features(LanFeatures.ours)), Array(s(doc["features_message"]).utf8))
        for m in messages {
            XCTAssertEqual(reason { try LanMessages.parse(Array(s(m["raw"]).utf8)) } ?? "ok", s(m["verdict"]), s(m["name"]))
        }
    }

    // MARK: Pro and read-only

    func test_pro_gates_create_join_and_sync_but_never_removal() throws {
        for action in [ShareAccess.Action.create, .join, .sync] {
            XCTAssertThrowsError(try ShareAccess.requirePro(action, isPro: false)) { XCTAssertTrue($0 is ShareProRequiredError) }
            XCTAssertNoThrow(try ShareAccess.requirePro(action, isPro: true))
        }
        for action in [ShareAccess.Action.remove, .approve, .leave] {
            XCTAssertNoThrow(try ShareAccess.requirePro(action, isPro: false))
        }
    }

    func test_read_only_share_refuses_edits_moves_and_fails_closed() throws {
        let shares = [
            ShareAccess.Membership(collectionID: cid, role: "member", sharedMode: "read"),
            ShareAccess.Membership(collectionID: Self.other, role: "member", sharedMode: "edit"),
            ShareAccess.Membership(collectionID: "0f0f0f0f-0000-4000-8000-000000000000", role: "owner", sharedMode: "read"),
        ]
        let all = Set(shares.map(\.collectionID))
        let readOnly = ShareAccess.readOnlyCollectionIDs(shares, sharedCollectionIDs: all)
        XCTAssertEqual(readOnly, [cid])
        XCTAssertEqual(ShareAccess.readOnlyCollectionIDs(nil, sharedCollectionIDs: all), all)
        func item(_ c: String...) -> JSONValue { .object(["collection_ids": .array(c.map { .string($0) })]) }
        func refused(_ f: () throws -> Void) -> Bool {
            do { try f(); return false } catch { return error is ReadOnlyCollectionError }
        }
        XCTAssertTrue(refused { try ShareAccess.checkWritable(readOnly, item(self.cid)) })
        XCTAssertTrue(refused { try ShareAccess.checkWritable(readOnly, item(Self.other), item(Self.other, self.cid)) })   // move in
        XCTAssertTrue(refused { try ShareAccess.checkWritable(readOnly, item(self.cid), item()) })   // move out
        XCTAssertNoThrow(try ShareAccess.checkWritable(readOnly, item(Self.other), item(Self.other)))
        XCTAssertNoThrow(try ShareAccess.checkWritable(readOnly, nil, item()))
        XCTAssertNoThrow(try ShareAccess.checkWritable([], item(cid)))
    }
}
