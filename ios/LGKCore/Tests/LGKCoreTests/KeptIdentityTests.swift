import XCTest
import Foundation
@testable import LGKCore

/// Design 2026-11-17 "Keep the device id when a device leaves and rejoins": the folder join (rules 3 and 6) and the
/// host's acceptance of a known id with the same keys (rule 4). The app's Leave and Wi-Fi join are in
/// `SyncCoordinatorTests`.
final class KeptIdentityTests: XCTestCase {
    static let T0 = FolderSyncTests.T0
    typealias F = FolderSyncTests

    // MARK: folder

    /// Two phones in the seeded group (P and Q, separate installations).
    func twoPhones() throws -> (MemoryFolder, (MemoryStore, FolderSync), (MemoryStore, FolderSync)) {
        let folder = try F.seededFolder()
        let pw = try KeyringTests.pwKey("1")
        let p = (MemoryStore(), try FolderSync(access: folder, installID: "ios-install-p"))
        let q = (MemoryStore(), try FolderSync(access: folder, installID: "ios-install-q"))
        _ = try p.1.join(store: p.0, deviceName: "iPhone", random: DetRand("kept|p"), clock: FixedClock(now: Self.T0 + 1000)) { _ in pw }
        _ = try q.1.join(store: q.0, deviceName: "iPad", random: DetRand("kept|q"), clock: FixedClock(now: Self.T0 + 1010)) { _ in pw }
        return (folder, p, q)
    }

    /// Leave as `SyncCoordinator.clear` does it: the group goes, the identity is kept, in one commit.
    func leave(_ store: MemoryStore) throws -> KeptIdentity {
        let snap = store.snapshot
        let kept = KeptIdentity(leaving: try XCTUnwrap(snap.sync))
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: nil,
                                     keptIdentity: .set(kept)))
        return kept
    }

    func rejoin(_ phone: (MemoryStore, FolderSync), at t: Int64, label: String) throws -> RunReport {
        let pw = try KeyringTests.pwKey("1")
        return try phone.1.join(store: phone.0, deviceName: "iPhone", random: DetRand(label), clock: FixedClock(now: t)) { _ in pw }
    }

    func edit(_ store: MemoryStore, _ title: String, at t: Int64) throws {
        var snap = store.snapshot
        var w = MergeVectors.obj(snap.records[EngineTests.NOTE]); var rec = MergeVectors.obj(w["record"])
        rec["title"] = .string(title); rec["updated_at"] = .int(t)
        w = MergeVectors.obj(Wrapper.make(ns: .item, record: try Normalise.normalForm(ns: .item, record: .object(rec))))
        snap.records[EngineTests.NOTE] = .object(w)
        store.snapshot = snap
    }

    func title(_ store: MemoryStore) -> String? {
        MergeVectors.str(MergeVectors.obj(MergeVectors.obj(store.snapshot.records[EngineTests.NOTE])["record"])["title"])
    }

    func memberEntries(_ folder: MemoryFolder, _ id: String) throws -> Int {
        let ring = try Keyring.parse(try XCTUnwrap(folder.files[F.keyringPath]))
        return MergeVectors.arr(MergeVectors.obj(ring)["members"]).filter { MergeVectors.str(MergeVectors.obj($0)["device_id"]) == id }.count
    }

    static let refusals: Set<String> = ["rollback", "suspicious-rewrite", "implausible-counter", "view-forged", "view-unsigned",
                                        "signer-changed", "own-file-rewritten", "peer-vault-rollback", "vault-rollback",
                                        "member-dropped", "keyring-corrupt", "tampered"]

    func test_leave_then_join_the_same_folder_keeps_the_id_and_one_member_entry_and_counters_continue() throws {
        let (folder, p, q) = try twoPhones()
        let pid = try XCTUnwrap(p.0.snapshot.sync).deviceID
        let members = try XCTUnwrap(q.0.snapshot.sync).members.count
        // P edits and writes counter 2; Q accepts it (Q now refuses any lower counter from P).
        try edit(p.0, "Before leave", at: Self.T0 + 1050)
        XCTAssertEqual(p.1.runOnce(store: p.0, random: DetRand("p1"), clock: FixedClock(now: Self.T0 + 1100)).issues, [])
        XCTAssertEqual(p.0.snapshot.sync?.ownCounter, 2)
        _ = q.1.runOnce(store: q.0, random: DetRand("q1"), clock: FixedClock(now: Self.T0 + 1200))
        XCTAssertEqual(q.0.snapshot.sync?.lastSeen[pid], 2)
        XCTAssertEqual(title(q.0), "Before leave")

        let kept = try leave(p.0)
        XCTAssertNil(p.0.snapshot.sync)
        XCTAssertEqual(kept.deviceID, pid); XCTAssertEqual(kept.ownCounter, 2)

        let report = try rejoin(p, at: Self.T0 + 1300, label: "kept|p-again")
        XCTAssertTrue(Set(report.issues.map(\.kind)).isDisjoint(with: Self.refusals), "\(report.issues)")
        let state = try XCTUnwrap(p.0.snapshot.sync)
        XCTAssertEqual(state.deviceID, pid, "the same group reuses the kept identity")
        XCTAssertEqual(state.identity, kept.identity)
        XCTAssertNil(p.0.snapshot.keptIdentity, "a join that used it makes it the live identity again")
        XCTAssertEqual(try memberEntries(folder, pid), 1, "its keyring entry is rewritten, not added")
        XCTAssertEqual(state.members.count, members)
        XCTAssertGreaterThanOrEqual(state.ownCounter, 2, "the view counter continues from the one Q accepted")
        let own = try ViewFile.decode(try XCTUnwrap(folder.files[F.devPath(pid)]), key: F.epoch1(), expectedDeviceID: pid)
        XCTAssertEqual(own.header.counter, state.ownCounter)

        // Q accepts the rejoined device's file: no replay or rollback refusal; items sync both ways.
        try edit(p.0, "After rejoin on P", at: Self.T0 + 1350)
        XCTAssertTrue(Set(p.1.runOnce(store: p.0, random: DetRand("p2"), clock: FixedClock(now: Self.T0 + 1400)).issues.map(\.kind))
            .isDisjoint(with: Self.refusals))
        let qr = q.1.runOnce(store: q.0, random: DetRand("q2"), clock: FixedClock(now: Self.T0 + 1500))
        XCTAssertTrue(Set(qr.issues.map(\.kind)).isDisjoint(with: Self.refusals), "\(qr.issues)")
        XCTAssertEqual(q.0.snapshot.sync?.lastSeen[pid], p.0.snapshot.sync?.ownCounter)
        XCTAssertGreaterThan(try XCTUnwrap(p.0.snapshot.sync).ownCounter, 2)
        XCTAssertEqual(title(q.0), "After rejoin on P")
        XCTAssertEqual(q.0.snapshot.sync?.members.count, members)
        try edit(q.0, "From Q", at: Self.T0 + 1550)
        _ = q.1.runOnce(store: q.0, random: DetRand("q3"), clock: FixedClock(now: Self.T0 + 1600))
        let pr = p.1.runOnce(store: p.0, random: DetRand("p3"), clock: FixedClock(now: Self.T0 + 1700))
        XCTAssertTrue(Set(pr.issues.map(\.kind)).isDisjoint(with: Self.refusals), "\(pr.issues)")
        XCTAssertEqual(title(p.0), "From Q")
    }

    func test_the_generation_offset_continues_so_peers_see_no_rollback() throws {
        let (_, p, _) = try twoPhones()
        var snap = p.0.snapshot
        snap.sync?.generationOffset = 500
        p.0.snapshot = snap
        let kept = try leave(p.0)
        XCTAssertEqual(kept.generationOffset, 500)
        _ = try rejoin(p, at: Self.T0 + 1300, label: "kept|gen")
        XCTAssertEqual(p.0.snapshot.sync?.generationOffset, 500)
    }

    func test_a_listed_id_with_another_exchange_key_drops_the_kept_identity() throws {
        let (folder, p, _) = try twoPhones()
        let kept = try leave(p.0)
        // Another device now holds this id in the keyring, with its own keys.
        guard case .object(var o) = try Keyring.parse(try XCTUnwrap(folder.files[F.keyringPath])) else { return XCTFail() }
        o["members"] = .array(MergeVectors.arr(o["members"]).filter { MergeVectors.str(MergeVectors.obj($0)["device_id"]) != kept.deviceID })
        var wraps = MergeVectors.obj(o["device_wraps"]); wraps[kept.deviceID] = nil; o["device_wraps"] = .object(wraps)
        let stripped = try Keyring.finish(o, key: try F.epoch1())
        let other = try DeviceIdentity.generate(deviceID: kept.deviceID, random: DetRand("other"))
        let pw = try KeyringTests.pwKey("1")
        let (taken, _) = try Keyring.join(stripped, identity: other, name: "Other", random: DetRand("o"),
                                          now: FixedClock(now: Self.T0 + 1200)) { pw }
        folder.files[F.keyringPath] = try CanonicalJSON.encode(taken, dialect: .utf8)
        _ = try? rejoin(p, at: Self.T0 + 1300, label: "kept|other-key")
        XCTAssertNotEqual(p.0.snapshot.sync?.deviceID, kept.deviceID, "joins with a new identity")
        XCTAssertNotNil(p.0.snapshot.sync)
        XCTAssertNil(p.0.snapshot.keptIdentity, "and drops the kept one")
    }

    func test_a_removal_notice_for_the_id_drops_the_kept_identity() throws {
        let (folder, p, q) = try twoPhones()
        let kept = try leave(p.0)
        let qs = try XCTUnwrap(q.0.snapshot.sync)
        folder.files[try XCTUnwrap(RemovalNotice.path(kept.deviceID))] = try RemovalNotice.make(
            identity: qs.identity, groupID: qs.groupID, deviceID: kept.deviceID, epoch: 2, issuedAt: Self.T0 + 1200)
        _ = try rejoin(p, at: Self.T0 + 1300, label: "kept|removed")
        let state = try XCTUnwrap(p.0.snapshot.sync)
        XCTAssertNotEqual(state.deviceID, kept.deviceID)
        XCTAssertEqual(state.ownCounter, 1, "a new identity starts its own counter")
        XCTAssertNil(p.0.snapshot.keptIdentity)
    }

    func test_a_kept_identity_of_another_group_is_left_alone_and_a_lower_epoch_drops_it() throws {
        let (_, p, _) = try twoPhones()
        var kept = try leave(p.0)
        kept.groupID = "another-group"
        var snap = p.0.snapshot; snap.keptIdentity = kept; p.0.snapshot = snap
        _ = try rejoin(p, at: Self.T0 + 1300, label: "kept|other-group")
        XCTAssertNotEqual(p.0.snapshot.sync?.deviceID, kept.deviceID)
        XCTAssertEqual(p.0.snapshot.keptIdentity, kept, "another group's kept identity stays")

        let (_, r, _) = try twoPhones()
        var later = try leave(r.0)
        later.epoch = 7   // it last held a newer key than this folder offers: a rolled-back keyring
        snap = r.0.snapshot; snap.keptIdentity = later; r.0.snapshot = snap
        _ = try rejoin(r, at: Self.T0 + 1300, label: "kept|old-epoch")
        XCTAssertNotEqual(r.0.snapshot.sync?.deviceID, later.deviceID)
        XCTAssertNil(r.0.snapshot.keptIdentity)
    }

    func test_a_failed_join_keeps_the_kept_identity() throws {
        let (_, p, _) = try twoPhones()
        let kept = try leave(p.0)
        XCTAssertThrowsError(try p.1.join(store: p.0, deviceName: "iPhone", random: DetRand("x"), clock: FixedClock(now: Self.T0 + 1300)) { _ in
            throw KeyringError("password", "wrong")
        })
        XCTAssertEqual(p.0.snapshot.keptIdentity, kept)
    }

    func test_keyring_rejoin_rewrites_only_an_entry_with_the_same_exchange_key() throws {
        let ring = try Keyring.parse(Array(try Vectors.data("keyring_epoch1.json")))
        let b = try KeyringTests.identity("B")
        let pw = try KeyringTests.pwKey("1")
        XCTAssertThrowsError(try Keyring.join(ring, identity: b, name: "B", random: DetRand("j"), now: FixedClock(now: Self.T0)) { pw })
        let (rejoined, _) = try Keyring.join(ring, identity: b, name: "B again", random: DetRand("j"), now: FixedClock(now: Self.T0),
                                             rejoin: true) { pw }
        let before = MergeVectors.arr(MergeVectors.obj(ring)["members"]).compactMap { MergeVectors.str(MergeVectors.obj($0)["device_id"]) }
        let after = MergeVectors.arr(MergeVectors.obj(rejoined)["members"]).compactMap { MergeVectors.str(MergeVectors.obj($0)["device_id"]) }
        XCTAssertEqual(after, before, "same members, same order")
        XCTAssertNoThrow(try Keyring.accept(rejoined, trusted: try F.epoch1(), identity: b))
        let impostor = try DeviceIdentity(deviceID: b.deviceID, signingPrivate: Array(repeating: 5, count: 32),
                                          exchangePrivate: Array(repeating: 6, count: 32))
        XCTAssertThrowsError(try Keyring.join(ring, identity: impostor, name: "B", random: DetRand("j"), now: FixedClock(now: Self.T0),
                                              rejoin: true) { pw }) { XCTAssertEqual(($0 as? KeyringError)?.reason, "already-member") }
    }

    func test_the_stored_form_round_trips_and_refuses_anything_else() throws {
        let kept = KeptIdentity(identity: try KeyringTests.identity("B"), groupID: "g-1", epoch: 3, ownCounter: 9, generationOffset: 4)
        XCTAssertEqual(try KeptIdentity(json: kept.json), kept)
        guard case .object(var o) = kept.json else { return XCTFail() }
        o["extra"] = .int(1)
        XCTAssertThrowsError(try KeptIdentity(json: .object(o)))
        o["extra"] = nil; o["own_counter"] = .int(-1)
        XCTAssertThrowsError(try KeptIdentity(json: .object(o)))
    }

    // MARK: host (Wi-Fi)

    let t0: Int64 = 1_790_000_030
    let groupID = "kept-group-1"

    func hostState(peers: [LanPeer], members: [String] = []) throws -> SyncGroupState {
        SyncGroupState(groupID: groupID, epoch: 1, key: Array(repeating: 9, count: 32), identity: try KeyringTests.identity("A"),
                       installID: "host", hasFolder: false, members: members, lanPeers: peers,
                       peerGenerations: [try KeyringTests.identity("B").deviceID: 42])
    }

    func peer(_ id: DeviceIdentity, name: String = "Old name", revoked: Bool = false) -> LanPeer {
        LanPeer(deviceID: id.deviceID, groupID: groupID, name: name, endpoint: nil, signingPublic: id.signingPublicKey,
                exchangePublic: id.exchangePublicKey, pairedAt: 100, revoked: revoked, hello: 3)
    }

    /// A new offer of the host in `state`, its armed session, and `who`'s request for it.
    func request(_ who: DeviceIdentity, state: SyncGroupState, name: String = "New name") throws
        -> (PairingOffer, OfferSession, [UInt8]) {
        let clocks = TestClocks(wall: t0)
        let (offer, _) = try PairingOffer.create(group: groupID, identity: state.identity,
                                                 endpoint: try LanEndpoint(validating: "192.168.1.20", port: 48201),
                                                 now: clocks, random: SystemRandomSource())
        let session = try OfferSession(offer: offer, inviter: state.identity, wall: clocks, monotonic: clocks)
        let raw = try Enrollment.buildRequest(offer: offer, identity: who, name: name, random: SystemRandomSource(), now: clocks)
        return (offer, session, raw)
    }

    func test_a_paired_device_pairing_again_with_the_same_keys_replaces_its_entry() throws {
        let b = try KeyringTests.identity("B")
        let state = try hostState(peers: [peer(b)])
        let (offer, session, raw) = try request(b, state: state)
        guard case .verified(let req) = LanPeers.verifyEnrollment(raw, session: session, state: state) else {
            return XCTFail("a known id with the same keys goes on to the Accept prompt")
        }
        XCTAssertEqual(req.deviceID, b.deviceID)
        let (reply, next) = try LanPeers.acceptEnrollment(req, offer: offer, state: state, now: t0, random: SystemRandomSource())
        XCTAssertEqual(next.lanPeers.count, 1, "the entry is replaced, not added")
        let entry = try XCTUnwrap(LanPeers.entry(next, b.deviceID))
        XCTAssertEqual(entry.name, "New name"); XCTAssertEqual(entry.pairedAt, t0); XCTAssertFalse(entry.revoked)
        XCTAssertEqual(entry.hello, 3)
        XCTAssertEqual(entry.signingPublic, b.signingPublicKey)
        XCTAssertEqual(next.peerGenerations, state.peerGenerations, "rollback memory for the id is kept")
        let gk = try Enrollment.openReply(offer: offer, identity: b, raw: reply, name: "New name", reveal: offer.reveal)
        XCTAssertEqual(gk.key, state.key)
    }

    func test_a_full_host_still_takes_a_rejoin_but_no_new_device() throws {
        let b = try KeyringTests.identity("B"), c = try KeyringTests.identity("C")
        var peers = [peer(b)]
        for i in 0..<(LanPeers.maxPeers - 1) {
            peers.append(peer(try DeviceIdentity.generate(random: DetRand("full|\(i)"))))
        }
        let state = try hostState(peers: peers)
        var (offer, session, raw) = try request(b, state: state)
        guard case .verified(let req) = LanPeers.verifyEnrollment(raw, session: session, state: state) else { return XCTFail() }
        let (_, next) = try LanPeers.acceptEnrollment(req, offer: offer, state: state, now: t0, random: SystemRandomSource())
        XCTAssertEqual(next.lanPeers.count, LanPeers.maxPeers)
        (offer, session, raw) = try request(c, state: state)
        XCTAssertEqual(LanPeers.verifyEnrollment(raw, session: session, state: state), .refuse(try Enrollment.refusal("full")))
        XCTAssertEqual(session.attempts, 0)
    }

    func test_other_keys_a_revoked_id_a_folder_only_member_and_the_hosts_own_id_are_refused_as_before() throws {
        let b = try KeyringTests.identity("B")
        let impostor = try DeviceIdentity(deviceID: b.deviceID, signingPrivate: Array(repeating: 5, count: 32),
                                          exchangePrivate: Array(repeating: 6, count: 32))
        let refused = OfferSession.Outcome.refuse(try Enrollment.refusal("refused"))
        // Same id, other keys.
        var state = try hostState(peers: [peer(b)])
        var (offer, session, raw) = try request(impostor, state: state)
        XCTAssertEqual(LanPeers.verifyEnrollment(raw, session: session, state: state), refused)
        // Revoked.
        state = try hostState(peers: [peer(b, revoked: true)])
        (offer, session, raw) = try request(b, state: state)
        XCTAssertEqual(LanPeers.verifyEnrollment(raw, session: session, state: state), refused)
        // Known only from the folder's member list: its keys are not compared.
        state = try hostState(peers: [], members: [b.deviceID])
        (offer, session, raw) = try request(b, state: state)
        XCTAssertEqual(LanPeers.verifyEnrollment(raw, session: session, state: state), refused)
        _ = offer
        // The host's own id never rejoins, whatever its keys.
        let host = try KeyringTests.identity("A")
        state = try hostState(peers: [peer(host)])
        let own = Enrollment.Request(deviceID: host.deviceID, signingPublic: host.signingPublicKey, exchangePublic: host.exchangePublicKey,
                                     endpoint: nil, transcript: [], body: [], name: "A")
        XCTAssertFalse(LanPeers.rejoining(own, in: state))
        // And accept re-checks: a peer revoked while the prompt was open is refused there too.
        state = try hostState(peers: [peer(b)])
        (offer, session, raw) = try request(b, state: state)
        guard case .verified(let req) = LanPeers.verifyEnrollment(raw, session: session, state: state) else { return XCTFail() }
        let (revoked, _) = LanPeers.revoking(b.deviceID, in: state)
        XCTAssertThrowsError(try LanPeers.acceptEnrollment(req, offer: offer, state: revoked, now: t0, random: SystemRandomSource()))
    }
}
