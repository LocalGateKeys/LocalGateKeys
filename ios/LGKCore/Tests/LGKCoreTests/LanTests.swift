import XCTest
import Crypto
@testable import LGKCore

// Why signatures are excluded from some byte comparisons: CryptoKit/swift-crypto signs Ed25519 with
// hedged randomness on Apple platforms, while the desktop signs per RFC 8032 (deterministic). Any valid
// signature verifies on both sides, so Swift-made enrollment requests and hellos are compared with the
// vectors field by field except the signature, which must verify instead. Everything derived from the
// RECORDED hellos (transcript, salt, key, prefixes, frames) stays byte-pinned.

/// Hands out the queued byte strings in order (each call must ask for exactly the queued length).
final class QueueRandom: RandomSource, @unchecked Sendable {
    private var queue: [[UInt8]]
    private let lock = NSLock()
    init(_ q: [[UInt8]]) { queue = q }
    var isEmpty: Bool { lock.withLock { queue.isEmpty } }
    func bytes(count: Int) -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        guard !queue.isEmpty else { return SystemRandomSource().bytes(count: count) }
        let v = queue.removeFirst()
        precondition(v.count == count, "queued \(v.count) bytes, asked \(count)")
        return v
    }
}

/// Test fake: methods take the lock; tests read and seed the fields directly from one thread.
final class MemoryCounterStore: CounterStore, @unchecked Sendable {
    var hello: Int64 = 0
    var saves: [Int64] = []
    var inbound: [String: Int64] = [:]
    private let lock = NSLock()
    func persistedHelloCounter() throws -> Int64 { lock.withLock { hello } }
    func persistHelloCounter(_ last: Int64) throws { lock.withLock { hello = last; saves.append(last) } }
    func lastAcceptedCounter(peer: String) throws -> Int64 { lock.withLock { inbound[peer] ?? 0 } }
    func setLastAcceptedCounter(_ counter: Int64, peer: String) throws { lock.withLock { inbound[peer] = counter } }
}

private func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
private func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { return a }; return [] }
private func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }
private func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }
private func vec(_ name: String) throws -> [String: JSONValue] { obj(try CanonicalJSON.parse(Array(Vectors.data(name)))) }
private func sha(_ b: [UInt8]) -> String { Vectors.hexString(Array(SHA256.hash(data: b))) }

final class LanTests: XCTestCase {
    static let groupID = "5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64"

    func identity(_ who: String) throws -> DeviceIdentity { try KeyringTests.identity(who) }
    func pinned(_ who: String) throws -> PinnedPeer {
        let i = try identity(who)
        return PinnedPeer(deviceID: i.deviceID, groupID: Self.groupID, signingPublic: i.signingPublicKey,
                          exchangePublic: i.exchangePublicKey, endpoint: nil)
    }
    func lan() throws -> [String: JSONValue] { try vec("lan/expected_lan.json") }
    func offer() throws -> PairingOffer { try PairingOffer.parseQR(String(decoding: try Vectors.data("lan/qr_payload.txt"), as: UTF8.self)) }
    func groupKey() throws -> GroupKey {
        try GroupKey(groupID: Self.groupID, epoch: 1, key: Vectors.hex(str(obj(try lan()["reply"])["key_hex"])))
    }

    // MARK: QR

    func test_qr_payload_parses_to_expected_offer() throws {
        let o = try offer()
        XCTAssertEqual(o.bundleJSON, try lan()["offer_bundle"])
        XCTAssertEqual(o.endpoint, LanEndpoint(host: "192.168.1.20", port: 48201))
        XCTAssertEqual(o.inviterPeer.fingerprint, o.certificateFingerprint)
        let text = String(decoding: try Vectors.data("lan/qr_payload.txt"), as: UTF8.self)
        XCTAssertEqual(text, str(try lan()["qr_payload"]))
        for bad in ["lgk-pairx" + text.dropFirst(9), text + "=", text + "A", "lgk-pair:", String(text.dropFirst(9))] {
            XCTAssertThrowsError(try PairingOffer.parseQR(bad), bad)
        }
        // Non-canonical JSON (whitespace) and an unknown key (ignored, as on the desktop).
        var bundle = obj(try lan()["offer_bundle"])
        let spaced = bytes(" ") + (try CanonicalJSON.encode(.object(bundle), dialect: .ascii))
        XCTAssertThrowsError(try PairingOffer.parseQR("lgk-pair:" + Base64URL.encodeNoPad(spaced)))
        bundle["zz_future"] = .int(3)
        let extra = try CanonicalJSON.encode(.object(bundle), dialect: .ascii)
        XCTAssertEqual(try PairingOffer.parseQR("lgk-pair:" + Base64URL.encodeNoPad(extra)), o)
        bundle["expires_at"] = .float(1790000120.0)
        XCTAssertThrowsError(try PairingOffer.parseQR("lgk-pair:" + Base64URL.encodeNoPad(try CanonicalJSON.encode(.object(bundle), dialect: .ascii))))
    }

    // MARK: enrollment

    func enrollmentCases() throws -> [(file: String, reply: String, req: [String: JSONValue], rep: [String: JSONValue], endpoint: LanEndpoint?)] {
        let x = try lan()
        return [("lan/enroll_request.bin", "lan/enroll_reply.bin", obj(x["request"]), obj(x["reply"]), LanEndpoint(host: "192.168.1.31", port: 48202)),
                ("lan/enroll_request_no_endpoint.bin", "lan/enroll_reply_no_endpoint.bin", obj(x["request_no_endpoint"]), obj(x["reply_no_endpoint"]), nil)]
    }

    func test_enrollment_request_vector_opens_and_verifies() throws {
        let o = try offer(), a = try identity("A")
        for c in try enrollmentCases() {
            let raw = Array(try Vectors.data(c.file))
            XCTAssertTrue(raw.starts(with: Enrollment.requestMagic))
            let r = try Enrollment.openRequest(offer: o, inviter: a, raw: raw)  // MAC and the vector's signature verified inside
            XCTAssertEqual(r.body, bytes(str(c.req["plaintext"])))
            XCTAssertEqual(r.transcript, bytes(str(c.req["transcript"])))
            XCTAssertEqual(sha(r.transcript), str(c.req["transcript_sha256_hex"]))
            XCTAssertEqual(r.endpoint, c.endpoint)
            XCTAssertEqual(r.deviceID, try identity("B").deviceID)
            // tampered ciphertext
            var bad = raw; bad[bad.count - 5] ^= 1
            XCTAssertThrowsError(try Enrollment.openRequest(offer: o, inviter: a, raw: bad))
        }
    }

    func test_enrollment_request_built_with_injected_randomness() throws {
        let o = try offer(), a = try identity("A"), b = try identity("B")
        for c in try enrollmentCases() {
            let random = QueueRandom([Vectors.hex(str(c.req["ephemeral_private_hex"])), try Base64.decodeStrict(str(c.req["nonce_b64"]))])
            let raw = try Enrollment.buildRequest(offer: o, identity: b, endpoint: c.endpoint, random: random,
                                                  now: FixedClock(now: 1790000030))
            XCTAssertTrue(random.isEmpty)
            let vector = Array(try Vectors.data(c.file))
            // Outer JSON: everything but `ct` is byte-identical (ct carries the hedged signature).
            var mine = obj(try CanonicalJSON.parse(Array(raw[Enrollment.requestMagic.count...])))
            var theirs = obj(try CanonicalJSON.parse(Array(vector[Enrollment.requestMagic.count...])))
            XCTAssertEqual(try Base64.decodeStrict(str(mine["ct"])).count, try Base64.decodeStrict(str(theirs["ct"])).count)
            mine["ct"] = nil; theirs["ct"] = nil
            XCTAssertEqual(mine, theirs)
            XCTAssertEqual(try CanonicalJSON.encode(.object(["eph": mine["eph"]!, "offer_id": mine["offer_id"]!]), dialect: .ascii), bytes(str(c.req["aad"])))
            // Body: equal to the vector except the signature, which verifies (openRequest checks it).
            let r = try Enrollment.openRequest(offer: o, inviter: a, raw: raw)
            var body = obj(try CanonicalJSON.parse(r.body)), want = obj(try CanonicalJSON.parse(bytes(str(c.req["plaintext"]))))
            body["signature"] = nil; want["signature"] = nil
            XCTAssertEqual(body, want)
            XCTAssertEqual(r.transcript, bytes(str(c.req["transcript"])))
        }
        XCTAssertThrowsError(try Enrollment.buildRequest(offer: o, identity: b, random: SystemRandomSource(), now: FixedClock(now: 1790000120))) {
            XCTAssertEqual($0 as? PairingError, .expired)
        }
        XCTAssertThrowsError(try Enrollment.buildRequest(offer: o, identity: a, random: SystemRandomSource(), now: FixedClock(now: 1790000030)))
    }

    func test_enrollment_reply_opens_to_epoch1_key() throws {
        let o = try offer(), b = try identity("B"), gk = try groupKey()
        for c in try enrollmentCases() {
            let raw = Array(try Vectors.data(c.reply))
            XCTAssertEqual(try Enrollment.openReply(offer: o, identity: b, raw: raw, endpoint: c.endpoint), gk)
            XCTAssertEqual(Vectors.hexString(gk.key), str(c.rep["key_hex"]))
            // The reply is bound to the announced endpoint.
            let other: LanEndpoint? = c.endpoint == nil ? LanEndpoint(host: "192.168.1.31", port: 48202) : nil
            XCTAssertThrowsError(try Enrollment.openReply(offer: o, identity: b, raw: raw, endpoint: other))
            XCTAssertThrowsError(try Enrollment.openReply(offer: o, identity: try identity("C"), raw: raw, endpoint: c.endpoint))
        }
        XCTAssertThrowsError(try Enrollment.openReply(offer: o, identity: b, raw: Enrollment.refusedMagic + bytes(#"{"reason":"full"}"#))) {
            XCTAssertEqual($0 as? PairingError, .refused("full"))
        }
        XCTAssertThrowsError(try Enrollment.openReply(offer: o, identity: b, raw: Enrollment.refusedMagic + bytes(#"{"reason":"x"}"#))) {
            XCTAssertEqual($0 as? PairingError, .refused("refused"))
        }
        let f = obj(try lan()["framing"])
        XCTAssertEqual(Vectors.hexString(Enrollment.requestMagic), str(f["request_magic_hex"]))
        XCTAssertEqual(Vectors.hexString(Enrollment.replyMagic), str(f["reply_magic_hex"]))
        XCTAssertEqual(Vectors.hexString(Enrollment.refusedMagic), str(f["refused_magic_hex"]))
    }

    // MARK: session handshake

    /// Checks one recorded connection (session.json or messages.json entry) and returns its key.
    func checkConnection(_ s: [String: JSONValue]) throws -> [UInt8] {
        let hello = obj(s["hello"])
        let ini = obj(hello["initiator"]), res = obj(hello["responder"])
        let iniID = try identity(str(ini["device"])), resID = try identity(str(res["device"]))
        let hi = try SessionHello.parse(bytes(str(ini["text"]))), hr = try SessionHello.parse(bytes(str(res["text"])))
        XCTAssertEqual(try hi.toBytes(), bytes(str(ini["text"])))
        XCTAssertEqual(Vectors.hexString(try hi.signingBytes()), str(ini["signing_input_hex"]))
        XCTAssertEqual(Vectors.hexString(try hr.signingBytes()), str(res["signing_input_hex"]))
        XCTAssertEqual(hi.counter, { if case .int(let i)? = ini["counter"] { return i }; return -1 }())
        try SessionHello.verify(hi, pinned: try pinned(str(ini["device"])), groupID: Self.groupID)
        try SessionHello.verify(hr, pinned: try pinned(str(res["device"])), groupID: Self.groupID)
        let sid = Vectors.hex(str(s["session_id"]))
        XCTAssertEqual(hi.sessionID, sid); XCTAssertEqual(hr.sessionID, sid)
        let transcript = try SecureChannel.transcript(try hi.toBytes(), try hr.toBytes())
        XCTAssertEqual(Vectors.hexString(transcript), str(s["transcript_sorted_hex"]))
        XCTAssertEqual(transcript.starts(with: try hi.toBytes()) ? "initiator" : "responder", str(s["sorted_first"]))
        let shared = try iniID.exchange(with: resID.exchangePublicKey)
        XCTAssertEqual(Vectors.hexString(shared), str(s["shared_secret_hex"]))
        XCTAssertEqual(Vectors.hexString(SecureChannel.salt(transcript: transcript)), str(s["salt"]))
        XCTAssertEqual(Vectors.hexString(SecureChannel.info(sessionID: sid)), str(s["info_hex"]))
        let key = try SecureChannel.deriveKey(shared: shared, sessionID: sid, transcript: transcript)
        XCTAssertEqual(Vectors.hexString(key), str(s["key"]))
        XCTAssertEqual(Vectors.hexString(SecureChannel.prefix(key: key, role: .initiator)), str(s["prefix_initiator"]))
        XCTAssertEqual(Vectors.hexString(SecureChannel.prefix(key: key, role: .responder)), str(s["prefix_responder"]))
        // Both sides derive the same key from the recorded hellos.
        let ci = try SecureChannel(local: iniID, remote: try pinned(str(res["device"])), groupID: Self.groupID, sessionID: sid,
                                   role: .initiator, localHello: hi, remoteHello: hr)
        let cr = try SecureChannel(local: resID, remote: try pinned(str(ini["device"])), groupID: Self.groupID, sessionID: sid,
                                   role: .responder, localHello: hr, remoteHello: hi)
        XCTAssertEqual(ci.key, key); XCTAssertEqual(cr.key, key)
        return key
    }

    /// Seals `plain` as `role` with a fresh channel and requires the recorded frame bytes; opens them back.
    func checkFrame(key: [UInt8], sid: [UInt8], role: SecureChannel.Role, plain: [UInt8], frame: [UInt8], entry: [String: JSONValue]) throws {
        var sender = try SecureChannel(key: key, sessionID: sid, role: role)
        var receiver = try SecureChannel(key: key, sessionID: sid, role: role == .initiator ? .responder : .initiator)
        XCTAssertEqual(try sender.seal(plain), frame)
        XCTAssertEqual(try receiver.open(frame), plain)
        XCTAssertThrowsError(try receiver.open(frame)) { XCTAssertEqual($0 as? LanTransportError, .replay("Duplicate or out-of-order encrypted frame")) }
        let outer = try SecureChannel.parseFrame(try LanTransport.decodeFrame(frame))
        var meta = outer; meta["ciphertext"] = nil
        XCTAssertEqual(try CanonicalJSON.encode(.object(meta), dialect: .ascii), bytes(str(entry["aad"])))
        XCTAssertEqual(Vectors.hexString(try Base64.decodeStrict(str(outer["nonce"]))), str(entry["nonce"]))
        XCTAssertEqual(sha(frame), str(entry["frame_sha256"]))
        XCTAssertEqual(sha(plain), str(entry["plaintext_sha256"]))
    }

    func test_session_json_connections() throws {
        let sessions = arr(try vec("lan/session.json")["sessions"])
        XCTAssertEqual(sessions.count, 3)
        for (n, sv) in sessions.enumerated() {
            let s = obj(sv)
            let key = try checkConnection(s)
            let sid = Vectors.hex(str(s["session_id"]))
            for (role, name) in [(SecureChannel.Role.initiator, "request"), (.responder, "response")] {
                let e = obj(s[name])
                try checkFrame(key: key, sid: sid, role: role, plain: bytes(str(e["plaintext"])), frame: Vectors.hex(str(e["frame_hex"])), entry: e)
            }
            if n == 0 {
                let h = obj(s["hello"])
                XCTAssertEqual(Array(try Vectors.data("lan/hello_initiator.bin")), try LanTransport.encodeFrame(bytes(str(obj(h["initiator"])["text"]))))
                XCTAssertEqual(Array(try Vectors.data("lan/hello_responder.bin")), try LanTransport.encodeFrame(bytes(str(obj(h["responder"])["text"]))))
                XCTAssertEqual(Array(try Vectors.data("lan/frame_initiator.bin")), Vectors.hex(str(obj(s["request"])["frame_hex"])))
                XCTAssertEqual(Array(try Vectors.data("lan/frame_responder.bin")), Vectors.hex(str(obj(s["response"])["frame_hex"])))
            }
        }
    }

    func test_swift_hello_matches_vector_except_signature() throws {
        let s = obj(arr(try vec("lan/session.json")["sessions"])[2])  // counters 9 and 10
        let ini = obj(obj(s["hello"])["initiator"])
        let recorded = try SessionHello.parse(bytes(str(ini["text"])))
        let mine = try SessionHello.make(identity: try identity("A"), groupID: Self.groupID, sessionID: Vectors.hex(str(s["session_id"])),
                                         counter: 9, random: QueueRandom([Vectors.hex(str(ini["nonce_hex"]))]))
        XCTAssertEqual(try mine.signingBytes(), Vectors.hex(str(ini["signing_input_hex"])))
        XCTAssertEqual(mine.unsignedJSON, recorded.unsignedJSON)
        try SessionHello.verify(mine, pinned: try pinned("A"), groupID: Self.groupID)
        XCTAssertThrowsError(try SessionHello.verify(mine, pinned: try pinned("B"), groupID: Self.groupID))
        let wrongExchange = PinnedPeer(deviceID: mine.deviceID, groupID: Self.groupID, signingPublic: mine.signingPublic,
                                       exchangePublic: try identity("B").exchangePublicKey, endpoint: nil)
        XCTAssertThrowsError(try SessionHello.verify(mine, pinned: wrongExchange, groupID: Self.groupID))
        XCTAssertThrowsError(try SessionHello.verify(recorded, pinned: try pinned("A"), groupID: "other-group"))
    }

    func test_hello_and_frame_parsers_are_strict() throws {
        let s = obj(arr(try vec("lan/session.json")["sessions"])[0])
        let hello = obj(try CanonicalJSON.parse(bytes(str(obj(obj(s["hello"])["initiator"])["text"]))))
        let frame = try SecureChannel.parseFrame(try LanTransport.decodeFrame(Vectors.hex(str(obj(s["request"])["frame_hex"]))))
        func variants(_ o: [String: JSONValue]) -> [[UInt8]] {
            var out: [[UInt8]] = []
            var extra = o; extra["extra"] = .int(1); out.append(try! CanonicalJSON.encode(.object(extra), dialect: .ascii))
            for k in o.keys { var m = o; m[k] = nil; out.append(try! CanonicalJSON.encode(.object(m), dialect: .ascii)) }
            for v: JSONValue in [.bool(true), .float(1.0), .string("1"), .int(2)] {
                var m = o; m["version"] = v; out.append(try! CanonicalJSON.encode(.object(m), dialect: .ascii))
            }
            let text = String(decoding: try! CanonicalJSON.encode(.object(o), dialect: .ascii), as: UTF8.self)
            out.append(bytes(String(text.dropLast()) + #","version":1}"#))  // duplicate key
            return out
        }
        XCTAssertNoThrow(try SessionHello.parse(try CanonicalJSON.encode(.object(hello), dialect: .ascii)))
        for v in variants(hello) { XCTAssertThrowsError(try SessionHello.parse(v), String(decoding: v, as: UTF8.self)) }
        for v in variants(frame) { XCTAssertThrowsError(try SecureChannel.parseFrame(v), String(decoding: v, as: UTF8.self)) }
        var neg = hello; neg["counter"] = .int(-1)
        XCTAssertThrowsError(try SessionHello.parse(try CanonicalJSON.encode(.object(neg), dialect: .ascii)))
        var short = hello; short["nonce"] = .string(Base64.encode([1, 2, 3]))
        XCTAssertThrowsError(try SessionHello.parse(try CanonicalJSON.encode(.object(short), dialect: .ascii)))
        XCTAssertThrowsError(try LanTransport.decodeFrame([0, 0, 0, 2, 1]))
    }

    // MARK: messages

    func messagePlain(_ conn: [String: JSONValue], _ role: String, key: [UInt8]) throws -> [UInt8] {
        let e = obj(conn[role])
        let frame = Array(try Vectors.data("lan/" + str(e["file"])))
        var ch = try SecureChannel(key: key, sessionID: Vectors.hex(str(conn["session_id"])), role: role == "request" ? .responder : .initiator)
        let plain = try ch.open(frame)
        if case .string(let p)? = e["plaintext"] { XCTAssertEqual(plain, bytes(p)) }
        return plain
    }

    func test_messages_json_frames_and_views() throws {
        let m = try vec("lan/messages.json"), gk = try groupKey()
        let conns = arr(m["connections"]).map(obj)
        XCTAssertEqual(conns.count, 3)
        var viewA: [UInt8] = [], viewB: [UInt8] = []
        for c in conns {
            let key = try checkConnection(c)
            let sid = Vectors.hex(str(c["session_id"]))
            for (role, name) in [(SecureChannel.Role.initiator, "request"), (.responder, "response")] {
                let e = obj(c[name])
                let plain = try messagePlain(c, name, key: key)
                XCTAssertEqual(plain.count, { if case .int(let i)? = e["plaintext_size"] { return Int(i) }; return -1 }())
                try checkFrame(key: key, sid: sid, role: role, plain: plain, frame: Array(try Vectors.data("lan/" + str(e["file"]))), entry: e)
                let msg = try LanMessages.parse(plain)
                XCTAssertEqual(try LanMessages.encode(msg), plain)
                if case let .view(_, _, transfer, _, _, _, v) = msg {
                    if transfer == str(obj(obj(m["views"])["initiator"])["transfer"]) { viewA += try Base64.decodeStrict(v) }
                    else { viewB += try Base64.decodeStrict(v) }
                }
            }
        }
        for (raw, who, dev) in [(viewA, "initiator", "A"), (viewB, "responder", "B")] {
            let info = obj(obj(m["views"])[who])
            XCTAssertEqual(sha(raw), str(info["sha256"]))
            XCTAssertEqual(LanMessages.splitView(raw).map { $0.count }, arr(info["chunk_sizes"]).map { if case .int(let i) = $0 { return Int(i) }; return -1 })
            let decoded = try ViewFile.decode(raw, key: gk, expectedDeviceID: try identity(dev).deviceID)
            XCTAssertEqual(decoded.states.count, 20)
        }
        let errors = arr(m["errors"]).map(obj)
        XCTAssertEqual(errors.map { str($0["reason"]) }, LanMessages.errorReasons)
        for e in errors {
            XCTAssertEqual(try LanMessages.encode(.error(reason: str(e["reason"]))), bytes(str(e["plaintext"])))
        }
    }

    func test_message_parser_rejects_bad_shapes() throws {
        let t = String(repeating: "a", count: 32)
        let ok = #"{"seq":0,"transfer":"\#(t)","type":"ack"}"#
        XCTAssertEqual(try LanMessages.parse(bytes(ok)), .ack(transfer: t, seq: 0))
        for bad in [#"{"seq":0,"transfer":"\#(t)","type":"ack","x":1}"#, #"{"seq":0,"type":"ack"}"#,
                    #"{"seq":0.0,"transfer":"\#(t)","type":"ack"}"#, #"{"seq":0,"transfer":"\#(t.uppercased())","type":"ack"}"#,
                    #"{"seq":0,"transfer":"\#(t)","type":"ack","seq":0}"#, #"{"reason":"","type":"error"}"#, #"{"type":"hello"}"#,
                    #"{"epoch":1,"group_id":"g","seq":1,"size":5,"total":1,"transfer":"\#(t)","type":"view","view":"AA=="}"#] {
            XCTAssertThrowsError(try LanMessages.parse(bytes(bad)), bad) { XCTAssertEqual(($0 as? LanSyncError)?.reason, "bad-message") }
        }
        XCTAssertThrowsError(try LanMessages.parse(bytes(#"{"epoch":1,"group_id":"g","seq":0,"size":67108865,"total":1,"transfer":"\#(t)","type":"view","view":"AA=="}"#))) {
            XCTAssertEqual(($0 as? LanSyncError)?.reason, "too-large")
        }
    }

    // MARK: addresses

    func test_lan_address_table() throws {
        let r = try vec("lan/lan_ranges.json")
        XCTAssertEqual(arr(r["networks"]).map { str($0) }, LanAddress.networks)
        let cases = arr(r["cases"]).map(obj)
        XCTAssertEqual(cases.count, 19)
        for c in cases {
            XCTAssertEqual(LanAddress.isLAN(str(c["address"])), c["lan"] == .bool(true), str(c["address"]))
        }
        XCTAssertFalse(LanAddress.isLAN("192.168.01.1"))
        XCTAssertFalse(LanAddress.isLAN("fe80::1::2"))
        XCTAssertEqual(LanAddress.normalisedLAN("FE80:0:0:0:0:0:0:0001"), "fe80::1")
        XCTAssertEqual(LanAddress.normalisedLAN("fd00:0:0:1:0:0:0:1"), "fd00:0:0:1::1")
        XCTAssertEqual(LanAddress.normalisedLAN("fd00:0:0:1:1:0:0:1"), "fd00::1:1:0:0:1")  // first longest run
        XCTAssertEqual(LanAddress.normalisedLAN("::1"), "::1")
    }

    // MARK: hello counters

    func test_hello_counters_come_from_persisted_blocks_and_never_repeat() throws {
        let store = MemoryCounterStore()
        let src = HelloCounterSource(store: store, clock: FixedClock(now: 10))
        XCTAssertEqual(try src.nextCounter(), 10_000_000)
        XCTAssertEqual(store.saves, [10_000_063])  // saved before the first value is used
        for _ in 1..<64 { _ = try src.nextCounter() }
        XCTAssertEqual(store.saves.count, 1)
        XCTAssertEqual(try src.nextCounter(), 10_000_064)
        XCTAssertEqual(store.saves, [10_000_063, 10_000_127])
        // Restart with the clock set backwards: continues above the persisted block.
        let again = HelloCounterSource(store: store, clock: FixedClock(now: 1))
        XCTAssertEqual(try again.nextCounter(), 10_000_128)
        // Inbound: must increase per peer.
        try again.acceptInbound(5, peer: "p")
        XCTAssertThrowsError(try again.acceptInbound(5, peer: "p"))
        XCTAssertThrowsError(try again.acceptInbound(4, peer: "p"))
        try again.acceptInbound(6, peer: "p")
        try again.acceptInbound(1, peer: "q")
    }

    // MARK: client

    /// A live responder holding B's identity: checks the client's hello, answers with a hello of
    /// `responderCounter` (and the recorded nonce when given), opens the request and seals `answer(request)`.
    /// Test fake used by one request at a time (the client calls `exchange` sequentially).
    final class FakeConnection: LanConnection, @unchecked Sendable {
        let b: DeviceIdentity
        let pinnedA: PinnedPeer
        let counter: Int64
        let nonce: [UInt8]?
        let answer: ([UInt8]) throws -> [UInt8]
        var clientHello: SessionHello?
        var localHello: SessionHello?
        var channel: SecureChannel?
        init(b: DeviceIdentity, pinnedA: PinnedPeer, counter: Int64, nonce: [UInt8]?, answer: @escaping ([UInt8]) throws -> [UInt8]) {
            self.b = b; self.pinnedA = pinnedA; self.counter = counter; self.nonce = nonce; self.answer = answer
        }
        func exchange(_ frame: [UInt8]) async throws -> [UInt8] {
            if channel == nil {
                let h = try SessionHello.parse(try LanTransport.decodeFrame(frame))
                try SessionHello.verify(h, pinned: pinnedA, groupID: LanTests.groupID)
                let mine = try SessionHello.make(identity: b, groupID: LanTests.groupID, sessionID: h.sessionID, counter: counter,
                                                 random: nonce.map { FixedRandom(value: $0) } ?? FixedRandom(value: SystemRandomSource().bytes(count: 32)))
                clientHello = h; localHello = mine
                channel = try SecureChannel(local: b, remote: pinnedA, groupID: LanTests.groupID, sessionID: h.sessionID,
                                            role: .responder, localHello: mine, remoteHello: h)
                return try LanTransport.encodeFrame(try mine.toBytes())
            }
            let request = try channel!.open(frame)
            return try channel!.seal(try answer(request))
        }
    }

    final class FakeConnector: LanConnector, @unchecked Sendable {
        var make: (Int) throws -> FakeConnection
        var opened: [FakeConnection] = []
        private let lock = NSLock()
        init(make: @escaping (Int) throws -> FakeConnection) { self.make = make }
        func connect(to peer: PinnedPeer) async throws -> any LanConnection {
            try lock.withLock { let c = try make(opened.count); opened.append(c); return c }
        }
    }

    func test_client_against_recorded_exchange() async throws {
        // Each messages.json connection through the client's per-connection step with a fresh counter
        // store (the recorded hellos all carry counter 1). The client's hello must equal the recorded
        // one except the signature; the plaintexts are compared byte for byte both ways.
        let m = try vec("lan/messages.json")
        let a = try identity("A"), b = try identity("B")
        for c in arr(m["connections"]).map(obj) {
            let key = try checkConnection(c)
            let request = try messagePlain(c, "request", key: key), response = try messagePlain(c, "response", key: key)
            let hello = obj(c["hello"])
            let client = LanClient(identity: a, groupKey: try groupKey(),
                                   counters: HelloCounterSource(store: MemoryCounterStore(), clock: FixedClock(now: 0)),
                                   random: QueueRandom([Vectors.hex(str(c["session_id"])), Vectors.hex(str(obj(hello["initiator"])["nonce_hex"]))]),
                                   clock: FixedClock(now: 0))
            var seen: [UInt8] = []
            let conn = FakeConnection(b: b, pinnedA: try pinned("A"), counter: 1, nonce: Vectors.hex(str(obj(hello["responder"])["nonce_hex"]))) {
                seen = $0; return response
            }
            let got = try await client.request(request, peer: try pinned("B"), connection: conn)
            XCTAssertEqual(got, response)
            XCTAssertEqual(seen, request)
            let recorded = try SessionHello.parse(bytes(str(obj(hello["initiator"])["text"])))
            XCTAssertEqual(conn.clientHello?.unsignedJSON, recorded.unsignedJSON)
            // B's recorded hello recreated (same session id, nonce and counter; hedged signature).
            XCTAssertEqual(conn.localHello?.unsignedJSON, try SessionHello.parse(bytes(str(obj(hello["responder"])["text"]))).unsignedJSON)
        }
    }

    func recordedViews() throws -> (aStates: [ItemState], bResponses: [[UInt8]], bStates: [ItemState]) {
        let m = try vec("lan/messages.json"), gk = try groupKey()
        let conns = arr(m["connections"]).map(obj)
        var viewA: [UInt8] = []
        var responses: [[UInt8]] = []
        var viewB: [UInt8] = []
        for c in conns {
            let key = try checkConnection(c)
            if case let .view(_, _, _, _, _, _, v) = try LanMessages.parse(try messagePlain(c, "request", key: key)) { viewA += try Base64.decodeStrict(v) }
            let resp = try messagePlain(c, "response", key: key)
            responses.append(resp)
            if case let .view(_, _, _, _, _, _, v) = try LanMessages.parse(resp) { viewB += try Base64.decodeStrict(v) }
        }
        return (try ViewFile.decode(viewA, key: gk, expectedDeviceID: try identity("A").deviceID).states, responses,
                try ViewFile.decode(viewB, key: gk, expectedDeviceID: try identity("B").deviceID).states)
    }

    func test_client_sync_choreography_with_live_responder() async throws {
        let (aStates, responses, bStates) = try recordedViews()
        let a = try identity("A"), b = try identity("B"), gk = try groupKey()
        var received: [UInt8] = []
        var kinds: [String] = []
        let connector = FakeConnector { n in
            FakeConnection(b: b, pinnedA: try self.pinned("A"), counter: Int64(n + 1), nonce: nil) { req in
                let msg = try LanMessages.parse(req)
                switch (n, msg) {
                case let (0, .view(_, _, t, 0, 2, _, v)):
                    kinds.append("view0"); received += try Base64.decodeStrict(v)
                    return try LanMessages.encode(.ack(transfer: t, seq: 0))
                case let (1, .view(_, _, _, 1, 2, _, v)):
                    kinds.append("view1"); received += try Base64.decodeStrict(v)
                    return responses[1]
                case (2, .next(let t, 1)):
                    kinds.append("next1")
                    guard case let .view(_, _, tb, _, _, _, _) = try LanMessages.parse(responses[1]), tb == t else { throw LanSyncError("bad-test") }
                    return responses[2]
                default:
                    throw LanSyncError("unexpected", "\(n) \(msg)")
                }
            }
        }
        let store = MemoryCounterStore()
        let client = LanClient(identity: a, groupKey: gk, counters: HelloCounterSource(store: store, clock: FixedClock(now: 1790000900)),
                               random: SystemRandomSource(), clock: FixedClock(now: 1790000900))
        let states = try await client.sync(peer: try pinned("B"), localStates: aStates, ownCounter: 7, connector: connector)
        XCTAssertEqual(kinds, ["view0", "view1", "next1"])
        XCTAssertEqual(states, bStates)
        let sent = try ViewFile.decode(received, key: gk, expectedDeviceID: a.deviceID)
        XCTAssertEqual(sent.states, aStates)
        XCTAssertEqual(sent.header.counter, 7)
        // Three connections, three distinct increasing hello counters; the responder's were recorded.
        let counters = connector.opened.compactMap { $0.clientHello?.counter }
        XCTAssertEqual(counters, [1790000900_000_000, 1790000900_000_001, 1790000900_000_002])
        XCTAssertEqual(store.inbound[b.deviceID], 3)
    }

    /// Fails like a dropped hello: records the client's hello, then throws `LanPeerNotAnswering`.
    final class DroppingConnection: LanConnection, @unchecked Sendable {
        var hello: SessionHello?
        func exchange(_ frame: [UInt8]) async throws -> [UInt8] {
            hello = try SessionHello.parse(try LanTransport.decodeFrame(frame))
            throw LanPeerNotAnswering("reply lost")
        }
    }

    final class ScriptConnector: LanConnector, @unchecked Sendable {
        let make: (Int) throws -> any LanConnection
        var opened: [any LanConnection] = []
        init(_ make: @escaping (Int) throws -> any LanConnection) { self.make = make }
        func connect(to peer: PinnedPeer) async throws -> any LanConnection {
            let c = try make(opened.count); opened.append(c); return c
        }
    }

    final class Sleeps: @unchecked Sendable {
        var log: [UInt64] = []
        var fn: @Sendable (UInt64) async -> Void { { [self] in log.append($0) } }
    }

    func test_unanswered_request_is_retried_once_with_a_new_hello() async throws {
        let (aStates, responses, bStates) = try recordedViews()
        let a = try identity("A"), b = try identity("B"), gk = try groupKey()
        let dropped = DroppingConnection()
        var live: [FakeConnection] = []
        var n = 0
        let connector = ScriptConnector { i in
            if i == 1 { return dropped }   // the second request's hello gets no answer
            n += 1
            let c = FakeConnection(b: b, pinnedA: try self.pinned("A"), counter: Int64(n), nonce: nil) { req in
                switch try LanMessages.parse(req) {
                case let .view(_, _, t, 0, _, _, _): return try LanMessages.encode(.ack(transfer: t, seq: 0))
                case .view(_, _, _, 1, _, _, _): return responses[1]
                case .next: return responses[2]
                default: throw LanSyncError("unexpected")
                }
            }
            live.append(c); return c
        }
        let sleeps = Sleeps()
        let client = LanClient(identity: a, groupKey: gk, counters: HelloCounterSource(store: MemoryCounterStore(), clock: FixedClock(now: 1790000900)),
                               random: SystemRandomSource(), clock: FixedClock(now: 1790000900), sleep: sleeps.fn)
        let states = try await client.sync(peer: try pinned("B"), localStates: aStates, ownCounter: 7, connector: connector)
        XCTAssertEqual(states, bStates)
        XCTAssertEqual(connector.opened.count, 4)
        XCTAssertEqual(sleeps.log, [50_000_000])
        let lost = try XCTUnwrap(dropped.hello), retried = try XCTUnwrap(live[1].clientHello)
        XCTAssertGreaterThan(retried.counter, lost.counter)
        XCTAssertNotEqual(retried.sessionID, lost.sessionID)
        XCTAssertNotEqual(try retried.toBytes(), try lost.toBytes())
    }

    func test_first_request_and_second_failure_are_not_retried() async throws {
        let (aStates, _, _) = try recordedViews()
        let a = try identity("A"), gk = try groupKey()
        let sleeps = Sleeps()
        let client = LanClient(identity: a, groupKey: gk, counters: HelloCounterSource(store: MemoryCounterStore(), clock: FixedClock(now: 1790000900)),
                               random: SystemRandomSource(), clock: FixedClock(now: 1790000900), sleep: sleeps.fn)
        let first = ScriptConnector { _ in DroppingConnection() }
        do { _ = try await client.sync(peer: try pinned("B"), localStates: aStates, ownCounter: 7, connector: first); XCTFail() }
        catch is LanPeerNotAnswering {}
        XCTAssertEqual(first.opened.count, 1); XCTAssertEqual(sleeps.log, [])
    }

    func test_client_rejects_non_increasing_responder_counter() async throws {
        let a = try identity("A"), b = try identity("B")
        let store = MemoryCounterStore()
        let client = LanClient(identity: a, groupKey: try groupKey(), counters: HelloCounterSource(store: store, clock: FixedClock(now: 0)),
                               random: SystemRandomSource(), clock: FixedClock(now: 0))
        let ack = try LanMessages.encode(.error(reason: "bad-chunk"))
        _ = try await client.request(bytes("x"), peer: try pinned("B"),
                                     connection: FakeConnection(b: b, pinnedA: try pinned("A"), counter: 4, nonce: nil) { _ in ack })
        for replay in [Int64(4), 3] {
            do {
                _ = try await client.request(bytes("x"), peer: try pinned("B"),
                                             connection: FakeConnection(b: b, pinnedA: try pinned("A"), counter: replay, nonce: nil) { _ in ack })
                XCTFail("accepted counter \(replay)")
            } catch let e as LanTransportError {
                XCTAssertEqual(e, .replay("Session hello counter did not increase"))
            }
        }
        // A refusal surfaces as the desktop issue code.
        let refusing = FakeConnector { _ in FakeConnection(b: b, pinnedA: try self.pinned("A"), counter: 100, nonce: nil) { _ in
            try LanMessages.encode(.error(reason: "rejoin-required")) } }
        do {
            _ = try await client.sync(peer: try pinned("B"), localStates: [], ownCounter: 0, connector: refusing)
            XCTFail("expected refusal")
        } catch let e as LanSyncError { XCTAssertEqual(e.reason, "peer-rejoin-required") }
    }
}
