import XCTest
import Crypto
@testable import LGKCore

private func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
private func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { return a }; return [] }
private func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }
private func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }
private func vec(_ name: String) throws -> [String: JSONValue] { obj(try CanonicalJSON.parse(Array(Vectors.data(name)))) }

final class LanResponderTests: XCTestCase {
    static let groupID = LanTests.groupID
    static let install = "mac-install-0001"
    let t0: Int64 = 1790000900

    func identity(_ who: String) throws -> DeviceIdentity { try KeyringTests.identity(who) }
    func lanPeer(_ who: String, revoked: Bool = false) throws -> LanPeer {
        let i = try identity(who)
        return LanPeer(deviceID: i.deviceID, groupID: Self.groupID, name: who, signingPublic: i.signingPublicKey,
                       exchangePublic: i.exchangePublicKey, pairedAt: 1, revoked: revoked)
    }
    /// A listed peer with made-up keys (serving compares keys only; no handshake).
    func fakePeer(_ n: Int) -> LanPeer {
        LanPeer(deviceID: String(format: "f%07d-0000-4000-8000-000000000000", n), groupID: Self.groupID,
                signingPublic: [UInt8](repeating: UInt8(n), count: 32), exchangePublic: [UInt8](repeating: UInt8(n + 100), count: 32))
    }
    func groupKey() throws -> GroupKey { try LanTests().groupKey() }

    /// B's vault (empty) in the vectors' group, listing `peers`.
    func storeB(peers: [LanPeer]) throws -> MemoryStore {
        let gk = try groupKey()
        return MemoryStore(StoreSnapshot(sync: SyncGroupState(groupID: gk.groupID, epoch: 1, key: gk.key, identity: try identity("B"),
                                                              installID: Self.install, hasFolder: false, ownCounter: 4, lanPeers: peers)))
    }

    func responder(_ store: MemoryStore, counters: MemoryCounterStore = MemoryCounterStore(), random: any RandomSource = SystemRandomSource(),
                   now: Int64? = nil, clock: (any UnixClock)? = nil) -> LanResponder {
        LanResponder(store: store, installID: Self.install, counters: HelloCounterSource(store: counters, clock: FixedClock(now: 0)),
                     random: random, clock: clock ?? FixedClock(now: now ?? t0))
    }

    func accepted(_ o: LanResponder.Opening) throws -> LanResponderConnection {
        guard case .accepted(let c) = o else { throw LanSyncError("not-accepted") }
        return c
    }

    func helloFrame(_ c: [String: JSONValue], _ who: String = "initiator") throws -> [UInt8] {
        try LanTransport.encodeFrame(bytes(str(obj(obj(c["hello"])[who])["text"])))
    }

    func reason(_ plain: [UInt8]) -> String? {
        if case .error(let r)? = try? LanMessages.parse(plain) { return r }
        return nil
    }

    // MARK: vectors

    func testResponderMatchesRecordedConnections() throws {
        let m = try vec("lan/messages.json")
        let conns = arr(m["connections"]).map(obj)
        let pinnedB = try LanTests().pinned("B")
        let store = try storeB(peers: [try lanPeer("A")])
        let recordedB = obj(obj(m["views"])["responder"])
        for (n, c) in conns.enumerated() {
            let res = obj(obj(c["hello"])["responder"])
            let random = QueueRandom([Vectors.hex(str(res["nonce_hex"])), Vectors.hex(str(res["ephemeral_private_hex"]))])
            let r = responder(store, random: random)
            var conn = try accepted(try r.accept(helloFrame: try helloFrame(c)))
            XCTAssertTrue(random.isEmpty)
            // B's recorded hello recreated: same session id, nonce, ephemeral key and counter (hedged signature, which verifies).
            let mine = try SessionHello.parse(try LanTransport.decodeFrame(conn.helloFrame))
            let recorded = try SessionHello.parse(bytes(str(res["text"])))
            XCTAssertEqual(mine.unsignedJSON, recorded.unsignedJSON)
            try SessionHello.verify(mine, pinned: pinnedB, groupID: Self.groupID)
            XCTAssertEqual(conn.peer.deviceID, try identity("A").deviceID)
            // The recorded channel (its key comes from the recorded, deterministically signed hellos).
            conn.channel = try SecureChannel(key: Vectors.hex(str(c["key"])), sessionID: Vectors.hex(str(c["session_id"])), role: .responder)
            let request = Array(try Vectors.data("lan/" + str(obj(c["request"])["file"])))
            let response = Array(try Vectors.data("lan/" + str(obj(c["response"])["file"])))
            switch n {
            case 0:   // view chunk 0 -> ack 0, byte for byte
                XCTAssertEqual(try r.respond(&conn, requestFrame: request), response)
            case 1:   // the last chunk needs chunk 0 first: replay it in this responder, then answer with a fresh view
                let plain0 = try LanTests().messagePlain(conns[0], "request", key: Vectors.hex(str(conns[0]["key"])))
                XCTAssertEqual(try LanMessages.parse(r.serve(peer: conn.peer, request: plain0)),
                               .ack(transfer: str(obj(obj(m["views"])["initiator"])["transfer"]), seq: 0))
                let sealed = try r.respond(&conn, requestFrame: request)
                var initiator = try SecureChannel(key: Vectors.hex(str(c["key"])), sessionID: Vectors.hex(str(c["session_id"])), role: .initiator)
                guard case let .view(g, e, _, 0, total, _, _) = try LanMessages.parse(try initiator.open(sealed)) else { return XCTFail("no view") }
                XCTAssertEqual(g, Self.groupID); XCTAssertEqual(e, 1); XCTAssertEqual(total, 2)
                XCTAssertEqual(r.bufferedTransfers.outgoing, 1)
                XCTAssertEqual(r.lastReport?.wrote, true)
            default:  // next 1 -> chunk 1 of B's recorded view, byte for byte
                let parts = try (0..<2).map { i -> [UInt8] in
                    guard case let .view(_, _, _, _, _, _, v) = try LanMessages.parse(
                        try LanTests().messagePlain(conns[i + 1], "response", key: Vectors.hex(str(conns[i + 1]["key"])))) else { return [] }
                    return try Base64.decodeStrict(v)
                }
                r.inbox.store(LanInbox.Outgoing(transfer: str(recordedB["transfer"]), parts: parts, size: Int64(parts.joined().count),
                                                groupKey: try groupKey(), started: t0), peer: conn.peer.deviceID)
                XCTAssertEqual(try r.respond(&conn, requestFrame: request), response)
                XCTAssertEqual(r.bufferedTransfers.outgoing, 0)   // the last chunk was handed out
            }
        }
        // The received view of A merged into B's vault through SyncRunner and was committed.
        XCTAssertEqual(store.commits, 1)
        XCTAssertEqual(store.snapshot.records.count, 20)
    }

    func testVersionRefusalAndErrorReasons() throws {
        let sv = try vec("lan/session.json")
        let r = responder(try storeB(peers: [try lanPeer("A")]))
        guard case .refuse(let frame) = try r.accept(helloFrame: try LanTransport.encodeFrame(bytes(str(obj(sv["legacy_hello"])["text"])))) else {
            return XCTFail("a version-1 hello must get the version refusal")
        }
        XCTAssertEqual(try LanTransport.decodeFrame(frame), bytes(str(sv["version_refusal"])))
        // Every error a responder sends is one the vectors list.
        let listed = Set(arr(try vec("lan/messages.json")["errors"]).map { str(obj($0)["reason"]) })
        XCTAssertEqual(reason(r.serve(peer: try lanPeer("A"), request: bytes("{}"))), "bad-message")
        XCTAssertTrue(listed.contains("bad-message"))
    }

    // MARK: refusals

    func testReplayedCounterRefused() throws {
        let c = obj(arr(try vec("lan/messages.json")["connections"])[0])
        let counters = MemoryCounterStore()
        let r = responder(try storeB(peers: [try lanPeer("A")]), counters: counters)
        _ = try accepted(try r.accept(helloFrame: try helloFrame(c)))
        XCTAssertEqual(counters.inbound[try identity("A").deviceID], 1)
        XCTAssertThrowsError(try r.accept(helloFrame: try helloFrame(c))) {
            XCTAssertEqual($0 as? LanTransportError, .replay("Session hello counter did not increase"))
        }
        // A tampered counter breaks the signature and is not saved.
        counters.inbound = [:]
        var o = obj(try CanonicalJSON.parse(bytes(str(obj(obj(c["hello"])["initiator"])["text"]))))
        o["counter"] = .int(2)
        XCTAssertThrowsError(try r.accept(helloFrame: try LanTransport.encodeFrame(try CanonicalJSON.encode(.object(o), dialect: .ascii)))) {
            XCTAssertEqual($0 as? LanTransportError, .authentication("Session hello signature is invalid"))
        }
        XCTAssertEqual(counters.inbound, [:])
    }

    func testUnknownPeerRefused() throws {
        let c = obj(arr(try vec("lan/messages.json")["connections"])[0])
        let counters = MemoryCounterStore()
        let r = responder(try storeB(peers: [fakePeer(1)]), counters: counters)
        XCTAssertThrowsError(try r.accept(helloFrame: try helloFrame(c))) {
            XCTAssertEqual($0 as? LanTransportError, .authentication("Peer is not explicitly paired"))
        }
        XCTAssertEqual(counters.inbound, [:])
        // Listed under A's id but with other keys: refused by the hello check.
        var other = fakePeer(2); other.deviceID = try identity("A").deviceID
        XCTAssertThrowsError(try responder(try storeB(peers: [other])).accept(helloFrame: try helloFrame(c)))
        // Serving re-checks the current list: an unlisted peer or changed keys get unknown-peer.
        let view = try LanMessages.encode(.next(transfer: String(repeating: "a", count: 32), seq: 1))
        XCTAssertEqual(reason(r.serve(peer: try lanPeer("A"), request: view)), "unknown-peer")
        XCTAssertEqual(r.lastReport?.issues, [SyncIssue("unknown-peer", try identity("A").deviceID)])
        // A host's sync run takes the report once; the next run sees nothing new.
        XCTAssertEqual(r.takeReport()?.issues, [SyncIssue("unknown-peer", try identity("A").deviceID)])
        XCTAssertNil(r.takeReport())
        XCTAssertNil(r.lastReport)
        var changed = fakePeer(1); changed.signingPublic = [UInt8](repeating: 9, count: 32)
        XCTAssertEqual(reason(r.serve(peer: changed, request: view)), "unknown-peer")
        // No group state at all.
        XCTAssertThrowsError(try responder(MemoryStore()).accept(helloFrame: try helloFrame(c)))
        XCTAssertEqual(reason(responder(MemoryStore()).serve(peer: fakePeer(1), request: view)), "not-joined")
    }

    func testRevokedPeerRefused() throws {
        let c = obj(arr(try vec("lan/messages.json")["connections"])[0])
        let store = try storeB(peers: [try lanPeer("A")])
        let r = responder(store)
        var conn = try accepted(try r.accept(helloFrame: try helloFrame(c)))
        // Revoked after the hello: the request gets `revoked`.
        let (revoked, listed) = LanPeers.revoking(try identity("A").deviceID, in: store.snapshot.sync!)
        XCTAssertTrue(listed)
        store.snapshot.sync = revoked
        conn.channel = try SecureChannel(key: Vectors.hex(str(c["key"])), sessionID: Vectors.hex(str(c["session_id"])), role: .responder)
        let sealed = try r.respond(&conn, requestFrame: Array(try Vectors.data("lan/" + str(obj(c["request"])["file"]))))
        var ini = try SecureChannel(key: Vectors.hex(str(c["key"])), sessionID: Vectors.hex(str(c["session_id"])), role: .initiator)
        XCTAssertEqual(reason(try ini.open(sealed)), "revoked")
        XCTAssertEqual(r.lastReport?.issues, [SyncIssue("peer-revoked", try identity("A").deviceID)])
        XCTAssertEqual(store.commits, 0)
        // A new hello of a revoked peer is refused before any counter is saved.
        let counters = MemoryCounterStore()
        XCTAssertThrowsError(try responder(store, counters: counters).accept(helloFrame: try helloFrame(c))) {
            XCTAssertEqual($0 as? LanTransportError, .authentication("Peer device has been revoked"))
        }
        XCTAssertEqual(counters.inbound, [:])
        // Its id stays reserved: it cannot enrol again under it.
        XCTAssertTrue(LanPeers.reservedIDs(revoked).contains(try identity("A").deviceID))
    }

    func testChunkLimitsEnforced() throws {
        let peers = (1...3).map(fakePeer)
        let store = try storeB(peers: peers)
        let clock = TestClocks(wall: t0)
        let r = responder(store, clock: clock)
        func chunk(_ peer: Int, seq: Int64, total: Int64, size: Int64, data: [UInt8], transfer: String = String(repeating: "a", count: 32),
                   epoch: Int64 = 1, group: String = LanResponderTests.groupID) -> String? {
            let m = LanMessage.view(groupID: group, epoch: epoch, transfer: transfer, seq: seq, total: total, size: size, view: Base64.encode(data))
            let reply = r.serve(peer: peers[peer - 1], request: try! LanMessages.encode(m))
            if case .ack(_, let s)? = try? LanMessages.parse(reply) { return "ack\(s)" }
            return reason(reply)
        }
        let limit = LanMessages.chunkLimit
        XCTAssertEqual(LanMessages.chunkBytes, 512 * 1024); XCTAssertEqual(limit, 560 * 1024)
        XCTAssertEqual(LanInbox.transferTTL, 300); XCTAssertEqual(LanInbox.maxTransfers, 2)
        // Over the chunk limit (still a well-formed message) -> too-large; at the limit -> accepted.
        XCTAssertEqual(chunk(1, seq: 0, total: 2, size: Int64(limit + 2), data: [UInt8](repeating: 1, count: limit + 1)), "too-large")
        XCTAssertEqual(chunk(1, seq: 0, total: 2, size: Int64(limit + 1), data: [UInt8](repeating: 1, count: limit)), "ack0")
        // Out of order, another transfer, changed size, or more bytes than announced -> bad-chunk (buffer dropped).
        XCTAssertEqual(chunk(1, seq: 1, total: 3, size: Int64(limit + 1), data: [1]), "bad-chunk")
        XCTAssertEqual(r.bufferedTransfers.incoming, 0)
        XCTAssertEqual(chunk(1, seq: 0, total: 2, size: 2, data: [1]), "ack0")
        XCTAssertEqual(chunk(1, seq: 1, total: 2, size: 2, data: [1], transfer: String(repeating: "b", count: 32)), "bad-chunk")
        XCTAssertEqual(chunk(1, seq: 0, total: 2, size: 2, data: [1]), "ack0")
        XCTAssertEqual(chunk(1, seq: 1, total: 2, size: 2, data: [1, 2]), "bad-chunk")
        XCTAssertEqual(chunk(1, seq: 0, total: 2, size: 2, data: [1, 2, 3]), "bad-chunk")  // received > size on chunk 0
        // Empty chunk.
        XCTAssertEqual(chunk(1, seq: 0, total: 1, size: 1, data: []), "bad-chunk")
        // The parser's bounds (64 MiB views, 65,536 chunks).
        let t = String(repeating: "a", count: 32)
        let big = #"{"epoch":1,"group_id":"\#(Self.groupID)","seq":0,"size":67108865,"total":1,"transfer":"\#(t)","type":"view","view":"AA=="}"#
        XCTAssertEqual(reason(r.serve(peer: peers[0], request: bytes(big))), "too-large")
        let many = #"{"epoch":1,"group_id":"\#(Self.groupID)","seq":0,"size":67108864,"total":65537,"transfer":"\#(t)","type":"view","view":"AA=="}"#
        XCTAssertEqual(reason(r.serve(peer: peers[0], request: bytes(many))), "too-large")
        // Group and epoch.
        XCTAssertEqual(chunk(1, seq: 0, total: 1, size: 1, data: [1], group: "other"), "group-mismatch")
        XCTAssertEqual(chunk(1, seq: 0, total: 1, size: 1, data: [1], epoch: 2), "peer-epoch-behind")
        XCTAssertEqual(r.lastReport?.issues, [SyncIssue("epoch-behind", peers[0].deviceID)])
        // A whole view that does not decode.
        XCTAssertEqual(chunk(1, seq: 0, total: 1, size: 3, data: [1, 2, 3]), "bad-view")
        // At most two transfers: the third peer's start drops the oldest.
        XCTAssertEqual(chunk(1, seq: 0, total: 2, size: 2, data: [1]), "ack0")
        clock.advance(wall: 1, mono: 1)
        XCTAssertEqual(chunk(2, seq: 0, total: 2, size: 2, data: [1]), "ack0")
        clock.advance(wall: 1, mono: 1)
        XCTAssertEqual(chunk(3, seq: 0, total: 2, size: 2, data: [1]), "ack0")
        XCTAssertEqual(r.bufferedTransfers.incoming, 2)
        XCTAssertEqual(chunk(1, seq: 1, total: 2, size: 2, data: [1]), "bad-chunk")   // peer 1's was dropped
        // TTL 300 s: peer 2's transfer (started at t0+1) is kept at t0+301 and gone at t0+302.
        clock.advance(wall: 299, mono: 299)
        XCTAssertEqual(reason(r.serve(peer: peers[0], request: try LanMessages.encode(.next(transfer: t, seq: 1)))), "bad-chunk")
        XCTAssertEqual(r.bufferedTransfers.incoming, 2)
        clock.advance(wall: 1, mono: 1)
        XCTAssertEqual(reason(r.serve(peer: peers[1], request: try LanMessages.encode(.next(transfer: t, seq: 1)))), "bad-chunk")
        XCTAssertEqual(r.bufferedTransfers.incoming, 1)   // expired on that request; peer 3's (t0+2) is still within 300 s
        XCTAssertEqual(chunk(2, seq: 1, total: 2, size: 2, data: [1]), "bad-chunk")
        // `next` without a transfer from this responder.
        XCTAssertEqual(reason(r.serve(peer: peers[2], request: try LanMessages.encode(.next(transfer: t, seq: 1)))), "bad-chunk")
        // `ack` is not a request.
        XCTAssertEqual(reason(r.serve(peer: peers[2], request: try LanMessages.encode(.ack(transfer: t, seq: 0)))), "bad-message")
        XCTAssertEqual(store.commits, 0)
    }

    // MARK: peers and enrollment

    func testSixteenPeerLimit() throws {
        let gk = try groupKey()
        var state = SyncGroupState(groupID: gk.groupID, epoch: 1, key: gk.key, identity: try identity("A"), installID: Self.install)
        for n in 1...16 { state = try LanPeers.adding(fakePeer(n), to: state) }
        XCTAssertEqual(state.lanPeers.count, 16)
        XCTAssertEqual(try LanPeers.adding(fakePeer(3), to: state).lanPeers.count, 16)   // replacing an entry is fine
        XCTAssertThrowsError(try LanPeers.adding(fakePeer(17), to: state)) { XCTAssertEqual(($0 as? LanSyncError)?.reason, "too-many-peers") }
        // A revoked entry still counts.
        state = LanPeers.revoking(fakePeer(1).deviceID, in: state).0
        XCTAssertThrowsError(try LanPeers.adding(fakePeer(17), to: state))
        // Enrollment answers `full` before anything is consumed.
        let offer = try HostPairingTests().offer()
        let clocks = TestClocks(wall: 1790000030)
        let session = try OfferSession(offer: offer, inviter: try identity("A"), wall: clocks, monotonic: clocks)
        let request = Array(try Vectors.data("lan/enroll_request.bin"))
        XCTAssertEqual(LanPeers.verifyEnrollment(request, session: session, state: state), .refuse(try Enrollment.refusal("full")))
        XCTAssertFalse(session.isExhausted)
        guard case .verified(let req) = LanPeers.verifyEnrollment(request, session: session, state: SyncGroupState(
            groupID: gk.groupID, epoch: 1, key: gk.key, identity: try identity("A"), installID: Self.install)) else { return XCTFail() }
        XCTAssertThrowsError(try LanPeers.acceptEnrollment(req, offer: offer, state: state, now: 1, random: SystemRandomSource())) {
            XCTAssertEqual($0 as? PairingError, .refused("full"))
        }
    }

    func testAcceptedEnrollmentPinsPeerOnce() throws {
        let gk = try groupKey()
        let a = try identity("A"), b = try identity("B")
        let state = SyncGroupState(groupID: gk.groupID, epoch: 1, key: gk.key, identity: a, installID: Self.install)
        let offer = try HostPairingTests().offer()
        XCTAssertEqual(offer.groupID, gk.groupID)
        let clocks = TestClocks(wall: 1790000030)
        let session = try OfferSession(offer: offer, inviter: a, wall: clocks, monotonic: clocks)
        let raw = Array(try Vectors.data("lan/enroll_request.bin"))
        guard case .verified(let req) = LanPeers.verifyEnrollment(raw, session: session, state: state) else { return XCTFail("must verify") }
        let (reply, pinned) = try LanPeers.acceptEnrollment(req, offer: offer, state: state, now: 1790000031, random: SystemRandomSource())
        XCTAssertEqual(try Enrollment.openReply(offer: offer, identity: b, raw: reply, endpoint: req.endpoint, name: req.name), gk)
        XCTAssertEqual(pinned.lanPeers, [LanPeer(deviceID: b.deviceID, groupID: gk.groupID, name: req.name, endpoint: req.endpoint,
                                                 signingPublic: b.signingPublicKey, exchangePublic: b.exchangePublicKey, pairedAt: 1790000031)])
        XCTAssertEqual(pinned.lanPeers[0].pinned.fingerprint, b.fingerprint)
        // Replayed: used up, nothing more to pin.
        XCTAssertEqual(LanPeers.verifyEnrollment(raw, session: session, state: pinned), .refuse(try Enrollment.refusal("used-or-expired")))
        // The id is now reserved (a second accept of the same request is refused).
        XCTAssertThrowsError(try LanPeers.acceptEnrollment(req, offer: offer, state: pinned, now: 1, random: SystemRandomSource())) {
            XCTAssertEqual($0 as? PairingError, .refused("refused"))
        }
        // Expired: refused with the Windows reason.
        let late = try OfferSession(offer: offer, inviter: a, wall: clocks, monotonic: clocks)
        clocks.advance(wall: 121, mono: 121)
        XCTAssertEqual(LanPeers.verifyEnrollment(raw, session: late, state: state), .refuse(try Enrollment.refusal("used-or-expired")))
    }

    func testOfferOfAnotherGroupOrInviterRefused() throws {
        let gk = try groupKey()
        let offer = try HostPairingTests().offer()
        let raw = Array(try Vectors.data("lan/enroll_request.bin"))
        let other = try GroupKey(groupID: "7c1d8e4f-0000-4000-8000-000000000001", epoch: 1, key: gk.key)
        for state in [SyncGroupState(groupID: other.groupID, epoch: 1, key: gk.key, identity: try identity("A"), installID: Self.install),
                      SyncGroupState(groupID: gk.groupID, epoch: 1, key: gk.key, identity: try identity("C"), installID: Self.install)] {
            let clocks = TestClocks(wall: 1790000030)
            let session = try OfferSession(offer: offer, inviter: try identity("A"), wall: clocks, monotonic: clocks)
            XCTAssertEqual(LanPeers.verifyEnrollment(raw, session: session, state: state), .refuse(try Enrollment.refusal("refused")))
            XCTAssertFalse(session.isListening)   // the offer is disarmed
            XCTAssertEqual(LanPeers.verifyEnrollment(raw, session: session, state: state), .close)
            // Accepting a verified request against such a state pins nothing.
            let fresh = try OfferSession(offer: offer, inviter: try identity("A"), wall: clocks, monotonic: clocks)
            guard case .verified(let req) = fresh.handle(raw) else { return XCTFail() }
            XCTAssertThrowsError(try LanPeers.acceptEnrollment(req, offer: offer, state: state, now: 1, random: SystemRandomSource())) {
                XCTAssertEqual($0 as? PairingError, .refused("refused"))
            }
        }
        XCTAssertThrowsError(try LanPeers.verifyEnrollment(raw, session: try OfferSession(offer: offer, inviter: try identity("A")), state: nil).refusedOrThrow())
    }

    func testLanPeerStoredFormRoundTrips() throws {
        var p = try lanPeer("A")
        p.endpoint = try LanEndpoint(validating: "192.168.1.20", port: 47821)
        XCTAssertEqual(try LanPeer(json: p.json), p)
        p.name = nil; p.endpoint = nil; p.revoked = true
        XCTAssertEqual(try LanPeer(json: p.json), p)
        XCTAssertThrowsError(try LanPeer(json: .object(["device_id": .string("x")])))
    }
}

private extension OfferSession.Outcome {
    /// Throws for a refusal or close (no state: nothing can be verified).
    func refusedOrThrow() throws {
        if case .verified = self { return }
        throw LanSyncError("refused")
    }
}
