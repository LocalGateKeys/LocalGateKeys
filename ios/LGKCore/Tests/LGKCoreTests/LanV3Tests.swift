import XCTest
import Crypto
@testable import LGKCore

private func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
private func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { return a }; return [] }
private func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }
private func int(_ v: JSONValue?) -> Int64 { if case .int(let i)? = v { return i }; return -1 }
private func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }
private func vec(_ name: String) throws -> [String: JSONValue] { obj(try CanonicalJSON.parse(Array(Vectors.data(name)))) }
private func sha(_ b: [UInt8]) -> String { Vectors.hexString(Array(SHA256.hash(data: b))) }

/// LAN protocol version 3 (docs/formats/LAN_SYNC_V3.md, vectors `tests/vectors/sync/lan/v3/`): the sealed hello,
/// the downgrade pin and commit-then-reveal pairing, with every check of the spec's section 4.
final class LanV3Tests: XCTestCase {
    static let groupID = LanTests.groupID
    static let install = "mac-install-0001"
    let t0: Int64 = 1790000030

    func identity(_ who: String) throws -> DeviceIdentity { try KeyringTests.identity(who) }
    func pinned(_ who: String) throws -> PinnedPeer { try LanTests().pinned(who) }
    func session() throws -> [String: JSONValue] { try vec("lan/v3/session.json") }
    func enroll() throws -> [String: JSONValue] { try vec("lan/v3/enroll.json") }
    func offer() throws -> PairingOffer {
        try PairingOffer.parseQR(String(decoding: try Vectors.data("lan/v3/qr_payload.txt"), as: UTF8.self))
    }

    // MARK: sealed hello (section 2)

    func test_sealed_hellos_match_the_vectors_and_open_only_for_the_responder() throws {
        let doc = try session()
        XCTAssertEqual(int(doc["sealed_plaintext_bytes"]), Int64(SealedHello.plaintextBytes))
        XCTAssertEqual(try LanTransport.versionRefusal(), bytes(str(doc["version_refusal"])))
        let sessions = arr(doc["sessions"]).map(obj)
        XCTAssertEqual(sessions.map { str($0["name"]) }, ["a-initiates", "b-initiates"])
        for (n, s) in sessions.enumerated() {
            let hello = obj(s["hello"]), sealed = obj(s["sealed_hello"])
            let ini = obj(hello["initiator"]), res = obj(hello["responder"])
            let iniID = try identity(str(s["initiator_device"])), resID = try identity(str(s["responder_device"]))
            // The inner hellos: version 3, the v3 signing label, strict parse, the pinned keys.
            let hi = try SessionHello.parse(bytes(str(ini["text"])), version: 3)
            let hr = try SessionHello.parse(bytes(str(res["text"])), version: 3)
            XCTAssertEqual(hi.version, 3); XCTAssertEqual(hr.version, 3)
            XCTAssertThrowsError(try SessionHello.parse(bytes(str(ini["text"]))))   // not a clear-text (version-2) hello
            XCTAssertEqual(try hi.toBytes(), bytes(str(ini["text"])))
            XCTAssertEqual(Vectors.hexString(try hi.signingBytes()), str(ini["signing_input_hex"]))
            XCTAssertEqual(Vectors.hexString(try hr.signingBytes()), str(res["signing_input_hex"]))
            try SessionHello.verify(hi, pinned: try pinned(str(s["initiator_device"])), groupID: Self.groupID)
            try SessionHello.verify(hr, pinned: try pinned(str(s["responder_device"])), groupID: Self.groupID)
            XCTAssertEqual(try hi.toBytes().count, Int(int(sealed["initiator_inner_length"])))
            XCTAssertEqual(try hr.toBytes().count, Int(int(sealed["responder_inner_length"])))

            // Every sealing value, from the listed private x_i.
            let x = Vectors.hex(str(sealed["ephemeral_private_hex"]))
            XCTAssertEqual(Vectors.hexString(resID.exchangePublicKey), str(sealed["responder_static_public_hex"]))
            let es = try DeviceIdentity.x25519(privateKey: x, peerPublic: resID.exchangePublicKey)
            XCTAssertEqual(Vectors.hexString(es.shared), str(sealed["es_hex"]))
            XCTAssertEqual(Vectors.hexString(es.ownPublic), str(sealed["ephemeral_public_hex"]))
            XCTAssertEqual(Vectors.hexString(es.ownPublic + resID.exchangePublicKey), str(sealed["hkdf_salt_hex"]))
            XCTAssertEqual(Vectors.hexString(SealedHello.nonce), str(sealed["nonce_hex"]))
            XCTAssertEqual(sha(try SealedHello.pad(hi)), str(sealed["initiator_plaintext_sha256"]))
            XCTAssertEqual(sha(try SealedHello.pad(hr)), str(sealed["responder_plaintext_sha256"]))
            XCTAssertEqual(SealedHello.label + Array("initiator".utf8), bytes(str(sealed["info_initiator"])))
            XCTAssertEqual(SealedHello.label + Array("responder".utf8), bytes(str(sealed["info_responder"])))

            // Seal both hellos and compare byte for byte.
            let random = QueueRandom([x])
            let first = try SealedHello.sealInitiator(hi, responderExchangePublic: resID.exchangePublicKey, random: random)
            XCTAssertTrue(random.isEmpty)
            XCTAssertEqual(first.payload, bytes(str(sealed["initiator_frame"])))
            XCTAssertEqual(Vectors.hexString(try first.context.key(.initiator)), str(sealed["key_initiator_hex"]))
            XCTAssertEqual(Vectors.hexString(try first.context.key(.responder)), str(sealed["key_responder_hex"]))
            XCTAssertEqual(Vectors.hexString(first.context.aad), str(sealed["aad_hex"]))
            XCTAssertEqual(try SealedHello.sealResponder(hr, context: first.context), bytes(str(sealed["responder_frame"])))
            XCTAssertEqual("\(first.context)", "SealContext(<redacted>)")

            // Open them in both roles.
            let opened = try SealedHello.openInitiator(first.payload, identity: resID)
            XCTAssertEqual(try opened.hello.toBytes(), bytes(str(ini["text"])))
            XCTAssertEqual(try opened.context.key(.responder), try first.context.key(.responder))
            XCTAssertEqual(try SealedHello.openResponder(bytes(str(sealed["responder_frame"])), context: first.context).toBytes(),
                           bytes(str(res["text"])))
            // Only the intended responder opens the first frame (the initiator and C cannot).
            for outsider in ["A", "B", "C"] where outsider != str(s["responder_device"]) {
                XCTAssertThrowsError(try SealedHello.openInitiator(first.payload, identity: try identity(outsider)), outsider) {
                    XCTAssertEqual($0 as? LanTransportError, .authentication("Sealed hello is not for this device"))
                }
            }
            // The responder answer opens only under this connection's context.
            let other = try SealedHello.sealInitiator(hi, responderExchangePublic: resID.exchangePublicKey, random: SystemRandomSource())
            XCTAssertThrowsError(try SealedHello.openResponder(bytes(str(sealed["responder_frame"])), context: other.context))
            // A wiped context derives nothing.
            other.context.wipe()
            XCTAssertThrowsError(try other.context.key(.initiator))

            // The session key: the version-2 recipe with v3 labels.
            let sid = Vectors.hex(str(s["session_id"]))
            let transcript = try SecureChannel.transcript(try hi.toBytes(), try hr.toBytes())
            XCTAssertEqual(Vectors.hexString(transcript), str(s["transcript_sorted_hex"]))
            let shared = try iniID.exchange(with: resID.exchangePublicKey)
            XCTAssertEqual(Vectors.hexString(shared), str(s["shared_secret_hex"]))
            let ephI = Vectors.hex(str(ini["ephemeral_private_hex"])), ephR = Vectors.hex(str(res["ephemeral_private_hex"]))
            let (ephShared, _) = try DeviceIdentity.x25519(privateKey: ephI, peerPublic: hr.ephemeralPublic)
            XCTAssertEqual(Vectors.hexString(ephShared), str(s["ephemeral_shared_secret_hex"]))
            XCTAssertEqual(Vectors.hexString(ephShared + shared), str(s["ikm_hex"]))
            XCTAssertEqual(Vectors.hexString(SecureChannel.salt(transcript: transcript, version: 3)), str(s["salt"]))
            XCTAssertEqual(Vectors.hexString(SecureChannel.info(sessionID: sid, version: 3)), str(s["info_hex"]))
            let key = try SecureChannel.deriveKey(ephemeralShared: ephShared, staticShared: shared, sessionID: sid, transcript: transcript,
                                                  version: 3)
            XCTAssertEqual(Vectors.hexString(key), str(s["key"]))
            XCTAssertNotEqual(try SecureChannel.deriveKey(ephemeralShared: ephShared, staticShared: shared, sessionID: sid,
                                                          transcript: transcript), key)   // the v2 labels give another key
            let ci = try SecureChannel(local: iniID, remote: try pinned(str(s["responder_device"])), groupID: Self.groupID, sessionID: sid,
                                       role: .initiator, localHello: try hi.withEphemeral(privateKey: ephI), remoteHello: hr)
            let cr = try SecureChannel(local: resID, remote: try pinned(str(s["initiator_device"])), groupID: Self.groupID, sessionID: sid,
                                       role: .responder, localHello: try hr.withEphemeral(privateKey: ephR), remoteHello: hi)
            XCTAssertEqual(ci.key, key); XCTAssertEqual(cr.key, key)
            XCTAssertEqual(Vectors.hexString(SecureChannel.prefix(key: key, role: .initiator)), str(s["prefix_initiator"]))
            XCTAssertEqual(Vectors.hexString(SecureChannel.prefix(key: key, role: .responder)), str(s["prefix_responder"]))
            // Both hellos of one connection must have the same version.
            let v2 = try SessionHello.make(identity: iniID, groupID: Self.groupID, sessionID: sid, counter: 1, random: SystemRandomSource())
            XCTAssertThrowsError(try SecureChannel(local: iniID, remote: try pinned(str(s["responder_device"])), groupID: Self.groupID,
                                                   sessionID: sid, role: .initiator, localHello: v2, remoteHello: hr))

            // The request and response frames (metadata version stays 2).
            for (role, name) in [(SecureChannel.Role.initiator, "request"), (.responder, "response")] {
                let e = obj(s[name])
                try LanTests().checkFrame(key: key, sid: sid, role: role, plain: bytes(str(e["plaintext"])),
                                          frame: Vectors.hex(str(e["frame_hex"])), entry: e)
            }
            if n == 0 {
                XCTAssertEqual(Array(try Vectors.data("lan/v3/sealed_hello_initiator.bin")), try LanTransport.encodeFrame(first.payload))
                XCTAssertEqual(Array(try Vectors.data("lan/v3/sealed_hello_responder.bin")),
                               try LanTransport.encodeFrame(bytes(str(sealed["responder_frame"]))))
                XCTAssertEqual(Array(try Vectors.data("lan/v3/frame_initiator.bin")), Vectors.hex(str(obj(s["request"])["frame_hex"])))
                XCTAssertEqual(Array(try Vectors.data("lan/v3/frame_responder.bin")), Vectors.hex(str(obj(s["response"])["frame_hex"])))
            }
        }
    }

    func test_sealed_frame_parsers_are_strict() throws {
        let s = obj(arr(try session()["sessions"])[0])
        let b = try identity("B")
        let first = obj(try CanonicalJSON.parse(bytes(str(obj(s["sealed_hello"])["initiator_frame"]))))
        XCTAssertNoThrow(try SealedHello.openInitiator(try CanonicalJSON.encode(.object(first), dialect: .ascii), identity: b))
        var variants: [[String: JSONValue]] = []
        var extra = first; extra["x"] = .int(1); variants.append(extra)
        for k in first.keys { var m = first; m[k] = nil; variants.append(m) }
        for v: JSONValue in [.int(2), .int(4), .string("3"), .float(3.0)] { var m = first; m["version"] = v; variants.append(m) }
        var signed = first; signed["signature"] = .string(Base64.encode([UInt8](repeating: 1, count: 64))); variants.append(signed)
        var shortEph = first; shortEph["eph"] = .string(Base64.encode([1, 2, 3])); variants.append(shortEph)
        var shortBox = first; shortBox["box"] = .string(Base64.encode([UInt8](repeating: 0, count: 1039))); variants.append(shortBox)
        // A tampered box (one bit) does not open.
        var box = try Base64.decodeStrict(str(first["box"])); box[100] ^= 1
        var tampered = first; tampered["box"] = .string(Base64.encode(box)); variants.append(tampered)
        for v in variants {
            XCTAssertThrowsError(try SealedHello.openInitiator(try CanonicalJSON.encode(.object(v), dialect: .ascii), identity: b))
        }
        // Padding: the length must be 1 ... 1022 and every padding byte zero.
        let hello = try SessionHello.parse(bytes(str(obj(obj(s["hello"])["initiator"])["text"])), version: 3)
        let padded = try SealedHello.pad(hello)
        XCTAssertEqual(padded.count, 1024)
        XCTAssertEqual(try SealedHello.unpad(padded), hello)
        var dirty = padded; dirty[1023] = 1
        XCTAssertThrowsError(try SealedHello.unpad(dirty))
        var zero = padded; zero[0] = 0; zero[1] = 0
        XCTAssertThrowsError(try SealedHello.unpad(zero))
        var long = padded; long[0] = 0x03; long[1] = 0xFF
        XCTAssertThrowsError(try SealedHello.unpad(long))
        // A version-2 hello is never sealed.
        let v2 = try SessionHello.make(identity: try identity("A"), groupID: Self.groupID, sessionID: hello.sessionID, counter: 1,
                                       random: SystemRandomSource())
        XCTAssertThrowsError(try SealedHello.sealInitiator(v2, responderExchangePublic: b.exchangePublicKey, random: SystemRandomSource()))
    }

    // MARK: responder rules and the pin (sections 2.3 and 2.5)

    func storeB(peers: [LanPeer]) throws -> MemoryStore { try LanResponderTests().storeB(peers: peers) }

    /// A fresh clear-text (version-2) hello of `who` with `counter`.
    func clearHello(_ who: String, counter: Int64) throws -> [UInt8] {
        let h = try SessionHello.make(identity: try identity(who), groupID: Self.groupID, sessionID: [UInt8](repeating: 7, count: 16),
                                      counter: counter, random: SystemRandomSource())
        return try LanTransport.encodeFrame(try h.toBytes())
    }

    func test_responder_answers_sealed_and_pins_after_the_request() throws {
        let s = obj(arr(try session()["sessions"])[0])   // A initiates to B
        let hello = obj(s["hello"]), sealed = obj(s["sealed_hello"])
        let res = obj(hello["responder"])
        let a = try identity("A"), b = try identity("B")
        let peerA = try LanResponderTests().lanPeer("A")
        let store = try storeB(peers: [peerA])
        let random = QueueRandom([Vectors.hex(str(res["nonce_hex"])), Vectors.hex(str(res["ephemeral_private_hex"]))])
        let r = LanResponderTests().responder(store, random: random)
        let first = Array(try Vectors.data("lan/v3/sealed_hello_initiator.bin"))
        guard case .accepted(var conn) = try r.accept(helloFrame: first) else { return XCTFail("a sealed hello of a listed peer is answered") }
        XCTAssertTrue(random.isEmpty)
        XCTAssertTrue(conn.sealed)
        XCTAssertFalse(r.isSealed(a.deviceID))   // pinned only once the request opens
        // The answer is sealed: it opens under the initiator's context to B's hello (same values, hedged signature).
        let hi = try SessionHello.parse(bytes(str(obj(hello["initiator"])["text"])), version: 3)
        let ctx = try SealedHello.sealInitiator(hi, responderExchangePublic: b.exchangePublicKey,
                                                random: QueueRandom([Vectors.hex(str(sealed["ephemeral_private_hex"]))])).context
        let answer = try LanTransport.decodeFrame(conn.helloFrame)
        XCTAssertThrowsError(try SessionHello.parse(answer))   // never a clear-text hello
        let mine = try SealedHello.openResponder(answer, context: ctx)
        XCTAssertEqual(mine.unsignedJSON, try SessionHello.parse(bytes(str(res["text"])), version: 3).unsignedJSON)
        try SessionHello.verify(mine, pinned: try pinned("B"), groupID: Self.groupID)
        // The recorded channel (its key comes from the recorded, deterministically signed hellos).
        conn.channel = try SecureChannel(key: Vectors.hex(str(s["key"])), sessionID: Vectors.hex(str(s["session_id"])), role: .responder)
        _ = try r.respond(&conn, requestFrame: Array(try Vectors.data("lan/v3/frame_initiator.bin")))
        XCTAssertTrue(r.isSealed(a.deviceID))
        XCTAssertEqual(LanPeers.entry(try XCTUnwrap(store.snapshot.sync), a.deviceID)?.hello, 3)
        XCTAssertEqual(LanPeers.entry(try XCTUnwrap(store.snapshot.sync), a.deviceID)?.sealed, true)

        // From now on A's clear-text hello is refused with the version refusal, once it verified.
        let clear = obj(arr(try vec("lan/messages.json")["connections"])[0])
        let counters = MemoryCounterStore()
        let fresh = LanResponderTests().responder(store, counters: counters)   // the stored pin, nothing in memory
        guard case .refuse(let frame) = try fresh.accept(helloFrame: try LanResponderTests().helloFrame(clear)) else {
            return XCTFail("a pinned peer's clear-text hello must get the version refusal")
        }
        XCTAssertEqual(try LanTransport.decodeFrame(frame), bytes(#"{"refused":"version","version":3}"#))
        // A clear-text hello that does not verify gets no answer at all.
        var o = obj(try CanonicalJSON.parse(bytes(str(obj(obj(clear["hello"])["initiator"])["text"]))))
        o["counter"] = .int(5)
        XCTAssertThrowsError(try fresh.accept(helloFrame: try LanTransport.encodeFrame(try CanonicalJSON.encode(.object(o), dialect: .ascii))))
        // The in-memory pin alone refuses too (a failed save keeps it).
        let unsaved = try storeB(peers: [peerA])
        let memory = LanResponderTests().responder(unsaved, random: QueueRandom([Vectors.hex(str(res["nonce_hex"])),
                                                                                 Vectors.hex(str(res["ephemeral_private_hex"]))]))
        guard case .accepted(var c2) = try memory.accept(helloFrame: first) else { return XCTFail() }
        c2.channel = try SecureChannel(key: Vectors.hex(str(s["key"])), sessionID: Vectors.hex(str(s["session_id"])), role: .responder)
        _ = try memory.respond(&c2, requestFrame: Array(try Vectors.data("lan/v3/frame_initiator.bin")))
        unsaved.snapshot.sync?.lanPeers[0].hello = nil
        XCTAssertNil(LanPeers.entry(try XCTUnwrap(unsaved.snapshot.sync), a.deviceID)?.hello)
        guard case .refuse = try memory.accept(helloFrame: try clearHello("A", counter: 2)) else {   // counter 1 was the sealed hello's
            return XCTFail("the in-memory pin must refuse the clear-text hello")
        }
        // An unpinned peer's clear-text hello is still answered in clear text (version 2).
        let open = LanResponderTests().responder(try storeB(peers: [peerA]))
        guard case .accepted(let c3) = try open.accept(helloFrame: try LanResponderTests().helloFrame(clear)) else { return XCTFail() }
        XCTAssertFalse(c3.sealed)
        XCTAssertEqual(try SessionHello.parse(try LanTransport.decodeFrame(c3.helloFrame)).version, 2)
    }

    func test_responder_closes_silently_on_any_sealed_failure() throws {
        let first = Array(try Vectors.data("lan/v3/sealed_hello_initiator.bin"))
        // Sealed to B, but this device is C (A listed): no answer, no counter saved.
        let gk = try LanTests().groupKey()
        let c = MemoryStore(StoreSnapshot(sync: SyncGroupState(groupID: gk.groupID, epoch: 1, key: gk.key, identity: try identity("C"),
                                                               installID: Self.install, hasFolder: false,
                                                               lanPeers: [try LanResponderTests().lanPeer("A")])))
        let counters = MemoryCounterStore()
        XCTAssertThrowsError(try LanResponderTests().responder(c, counters: counters).accept(helloFrame: first))
        XCTAssertEqual(counters.inbound, [:])
        // B, but A is not listed: closed.
        XCTAssertThrowsError(try LanResponderTests().responder(try storeB(peers: [])).accept(helloFrame: first))
        // A replayed sealed frame (counter not increasing): closed.
        let store = try storeB(peers: [try LanResponderTests().lanPeer("A")])
        let seen = MemoryCounterStore()
        _ = try LanResponderTests().responder(store, counters: seen).accept(helloFrame: first)
        XCTAssertThrowsError(try LanResponderTests().responder(store, counters: seen).accept(helloFrame: first)) {
            XCTAssertEqual($0 as? LanTransportError, .replay("Session hello counter did not increase"))
        }
        // A hello of another version (not 2, not 3) gets the version-3 refusal.
        let legacy = bytes(str(obj(try vec("lan/session.json")["legacy_hello"])["text"]))
        guard case .refuse(let frame) = try LanResponderTests().responder(store).accept(helloFrame: try LanTransport.encodeFrame(legacy)) else {
            return XCTFail()
        }
        XCTAssertEqual(try LanTransport.decodeFrame(frame), try LanTransport.versionRefusal())
    }

    func test_lan_peer_entry_keeps_the_pin_and_unknown_fields() throws {
        let a = try identity("A")
        var json = try LanResponderTests().lanPeer("A").json
        guard case .object(var o) = json else { return XCTFail() }
        XCTAssertNil(o["hello"])   // absent = not pinned
        o["hello"] = .int(3); o["future_field"] = .array([.int(1)])
        json = .object(o)
        let peer = try LanPeer(json: json)
        XCTAssertEqual(peer.hello, 3)
        XCTAssertTrue(peer.sealed)
        XCTAssertEqual(peer.json, json)   // unknown fields survive a save
        // A hello value that is not an integer is no pin, and is kept as it is.
        o["hello"] = .string("3")
        let odd = try LanPeer(json: .object(o))
        XCTAssertNil(odd.hello); XCTAssertFalse(odd.sealed)
        XCTAssertEqual(odd.json, .object(o))
        // Pinning: only a listed peer, once.
        let gk = try LanTests().groupKey()
        let state = SyncGroupState(groupID: gk.groupID, epoch: 1, key: gk.key, identity: try identity("B"), installID: Self.install,
                                   hasFolder: false, lanPeers: [try LanResponderTests().lanPeer("A")])
        let pinnedState = try XCTUnwrap(LanPeers.pinningSealed(a.deviceID, in: state))
        XCTAssertEqual(LanPeers.entry(pinnedState, a.deviceID)?.hello, 3)
        XCTAssertNil(LanPeers.pinningSealed(a.deviceID, in: pinnedState))
        XCTAssertNil(LanPeers.pinningSealed(try identity("C").deviceID, in: state))
        let store = MemoryStore(StoreSnapshot(sync: state))
        XCTAssertTrue(LanPeers.pinSealed(a.deviceID, store: store))
        XCTAssertFalse(LanPeers.pinSealed(a.deviceID, store: store))
        XCTAssertEqual(store.commits, 1)
    }

    // MARK: commit-then-reveal pairing (section 3)

    func test_reveal_commit_code_and_reply() throws {
        let doc = try enroll()
        let o = try offer()
        XCTAssertEqual(o.version, 2)
        XCTAssertEqual(Vectors.hexString(try XCTUnwrap(o.commit)), str(doc["commit_hex"]))
        XCTAssertEqual(o.bundleJSON, doc["offer_bundle"])
        XCTAssertEqual(try o.qrPayload(), str(doc["qr_payload"]))
        XCTAssertEqual(Enrollment.enrollVersion(for: o), 3)
        XCTAssertNil(o.reveal)   // a scanned offer never carries the reveal
        let frame = Array(try Vectors.data("lan/v3/enroll_reveal.bin"))
        XCTAssertEqual(frame, bytes(str(obj(doc["reveal_frame"])["text"])))
        let reveal = try Enrollment.openReveal(offer: o, raw: frame)
        XCTAssertEqual(Vectors.hexString(reveal), str(doc["reveal_hex"]))
        XCTAssertEqual(Enrollment.commitment(reveal), o.commit)
        XCTAssertEqual(Enrollment.commitLabel, bytes(str(doc["commit_label"])))
        // The inviter's own offer sends exactly this frame.
        let own = try o.withReveal(reveal)
        XCTAssertEqual(try Enrollment.revealFrame(offer: own), frame)
        XCTAssertThrowsError(try Enrollment.revealFrame(offer: o))   // not created here: no reveal to send
        XCTAssertThrowsError(try o.withReveal([UInt8](repeating: 1, count: 32)))
        // The code covers the reveal.
        let req = obj(doc["request"])
        let transcript = bytes(str(req["transcript"]))
        let code = str(obj(doc["verification_code"])["code"])
        XCTAssertEqual(code, "375941")
        XCTAssertEqual(Enrollment.verificationCode(transcript: transcript, reveal: reveal), code)
        XCTAssertNotEqual(Enrollment.verificationCode(transcript: transcript), code)
        let b = try identity("B")
        let ep = obj(req["invitee_endpoint"])
        let endpoint = try LanEndpoint(validating: str(ep["host"]), port: Int(int(ep["port"])))
        let name = str(req["name"])
        XCTAssertEqual(try Enrollment.transcript(offer: o, deviceID: b.deviceID, signingPublic: b.signingPublicKey,
                                                 exchangePublic: b.exchangePublicKey, endpoint: endpoint, name: name), transcript)
        XCTAssertEqual(try Enrollment.verificationCode(offer: o, identity: b, endpoint: endpoint, name: name, reveal: reveal), code)
        XCTAssertThrowsError(try Enrollment.verificationCode(offer: o, identity: b, endpoint: endpoint, name: name))   // no code before the reveal
        // The reply opens with the reveal and is refused without (or with another one).
        let reply = Array(try Vectors.data("lan/v3/enroll_reply.bin"))
        XCTAssertThrowsError(try Enrollment.openReply(offer: o, identity: b, raw: reply, endpoint: endpoint, name: name)) {
            XCTAssertEqual($0 as? PairingError, .authentication("The inviting device sent no valid reveal before its reply"))
        }
        XCTAssertThrowsError(try Enrollment.openReply(offer: o, identity: b, raw: reply, endpoint: endpoint, name: name,
                                                      reveal: [UInt8](repeating: 1, count: 32)))
        let gk = try Enrollment.openReply(offer: o, identity: b, raw: reply, endpoint: endpoint, name: name, reveal: reveal)
        let rep = obj(doc["reply"])
        XCTAssertEqual(gk.groupID, str(rep["group_id"]))
        XCTAssertEqual(gk.epoch, int(rep["epoch"]))
        XCTAssertEqual(Vectors.hexString(gk.key), str(rep["key_hex"]))
        // A refusal still reads without a reveal (it comes instead of one).
        XCTAssertThrowsError(try Enrollment.openReply(offer: o, identity: b, raw: try Enrollment.refusal("declined"))) {
            XCTAssertEqual($0 as? PairingError, .refused("declined"))
        }
    }

    func test_reveal_frame_is_strict() throws {
        let o = try offer()
        let good = Array(try Vectors.data("lan/v3/enroll_reveal.bin"))
        let reveal = try Enrollment.openReveal(offer: o, raw: good)
        var other = reveal; other[0] ^= 1
        let cases: [[UInt8]] = [
            Enrollment.revealMagic + bytes(#"{"reveal":"\#(Base64.encode(other))"}"#),          // does not match the commit
            Enrollment.revealMagic + bytes(#"{"reveal":"\#(Base64.encode(reveal))","x":1}"#),   // extra field
            Enrollment.revealMagic + bytes(#"{"reveal":"\#(Base64.encode([1, 2, 3]))"}"#),      // 3 bytes
            Enrollment.replyMagic + Array(good[Enrollment.revealMagic.count...]),               // another magic
            good + [UInt8](repeating: 0x20, count: 256),                                          // over 256 bytes
        ]
        for raw in cases { XCTAssertThrowsError(try Enrollment.openReveal(offer: o, raw: raw)) }
        XCTAssertThrowsError(try Enrollment.openReveal(offer: o, raw: Enrollment.revealMagic + bytes(#"{"reveal":"\#(Base64.encode(other))"}"#))) {
            XCTAssertEqual($0 as? PairingError, .authentication("Enrollment reveal does not match the QR code"))
        }
        // A version-1 offer has no commitment: there is nothing to check a reveal against.
        let v1 = try LanTests().offer()
        XCTAssertNil(v1.commit)
        XCTAssertEqual(Enrollment.enrollVersion(for: v1), 2)
        XCTAssertThrowsError(try Enrollment.openReveal(offer: v1, raw: good))
        XCTAssertNil(try Enrollment.revealFrame(offer: v1))
    }

    func test_inviter_verifies_shows_code_v3_and_pins_at_enrollment() throws {
        let doc = try enroll()
        let o = try offer()
        let reveal = try Enrollment.openReveal(offer: o, raw: Array(try Vectors.data("lan/v3/enroll_reveal.bin")))
        let own = try o.withReveal(reveal)
        let a = try identity("A"), b = try identity("B")
        let clocks = TestClocks(wall: int(doc["now"]))
        // A version-2 offer is armed only with its reveal.
        XCTAssertThrowsError(try OfferSession(offer: o, inviter: a, wall: clocks, monotonic: clocks))
        let s = try OfferSession(offer: own, inviter: a, wall: clocks, monotonic: clocks)
        guard case .verified(let r) = s.handle(Array(try Vectors.data("lan/v3/enroll_request.bin"))) else {
            return XCTFail("the recorded version-3 request verifies")
        }
        XCTAssertEqual(r.code, str(obj(doc["verification_code"])["code"]))
        XCTAssertEqual(r.name, str(obj(doc["request"])["name"]))
        XCTAssertEqual(r.deviceID, b.deviceID)
        XCTAssertEqual(r.transcript, bytes(str(obj(doc["request"])["transcript"])))
        // Accept: the new device is pinned to the sealed hello at once, and its reply opens with the reveal.
        let gk = try GroupKey(groupID: o.groupID, epoch: 1, key: Vectors.hex(str(obj(doc["reply"])["key_hex"])))
        let state = SyncGroupState(groupID: o.groupID, epoch: 1, key: gk.key, identity: a, installID: Self.install, hasFolder: false)
        let (reply, pinnedState) = try LanPeers.acceptEnrollment(r, offer: own, state: state, now: int(doc["now"]), random: SystemRandomSource())
        XCTAssertEqual(LanPeers.entry(pinnedState, b.deviceID)?.hello, 3)
        let ep = obj(obj(doc["request"])["invitee_endpoint"])
        XCTAssertEqual(try Enrollment.openReply(offer: o, identity: b, raw: reply,
                                                endpoint: try LanEndpoint(validating: str(ep["host"]), port: Int(int(ep["port"]))),
                                                name: r.name, reveal: reveal), gk)
        // A version-1 offer's device is not pinned at enrollment (its first sealed sync pins it).
        let v1 = try OfferSession(offer: try LanTests().offer(), inviter: a, wall: TestClocks(wall: t0), monotonic: TestClocks(wall: t0))
        guard case .verified(let r1) = v1.handle(Array(try Vectors.data("lan/enroll_request.bin"))) else { return XCTFail() }
        XCTAssertNil(r1.reveal)
        let (_, s1) = try LanPeers.acceptEnrollment(r1, offer: try LanTests().offer(), state: state, now: t0, random: SystemRandomSource())
        XCTAssertNil(LanPeers.entry(s1, b.deviceID)?.hello)
    }

    func test_older_body_on_a_version_2_offer_gets_update_needed_first() throws {
        let doc = try enroll()
        let o = try offer()
        let own = try o.withReveal(try Enrollment.openReveal(offer: o, raw: Array(try Vectors.data("lan/v3/enroll_reveal.bin"))))
        let a = try identity("A"), b = try identity("B")
        // A released build reads the QR (unknown keys ignored) and sends a version-2 body for the same offer.
        let released = PairingOffer(version: 1, offerID: o.offerID, groupID: o.groupID, endpoint: o.endpoint,
                                    inviterDeviceID: o.inviterDeviceID, inviterSigningPublic: o.inviterSigningPublic,
                                    inviterExchangePublic: o.inviterExchangePublic, certificateFingerprint: o.certificateFingerprint,
                                    expiresAt: o.expiresAt, transcriptNonce: o.transcriptNonce, pairingSecret: o.pairingSecret, code: o.code)
        let old = try Enrollment.buildRequest(offer: released, identity: b, random: SystemRandomSource(), now: FixedClock(now: int(doc["now"])))
        let clocks = TestClocks(wall: int(doc["now"]))
        let s = try OfferSession(offer: own, inviter: a, wall: clocks, monotonic: clocks)
        XCTAssertEqual(s.handle(old), .refuse(bytes(str(obj(doc["refusals"])["version_2_body_on_version_2_offer"]))))
        // The new device reads it as "update needed".
        XCTAssertThrowsError(try Enrollment.openReply(offer: o, identity: b, raw: bytes(str(obj(doc["refusals"])["version_2_body_on_version_2_offer"])))) {
            XCTAssertEqual($0 as? PairingError, .refused("update-needed"))
        }
    }
}
