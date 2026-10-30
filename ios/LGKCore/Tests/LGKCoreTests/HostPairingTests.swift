import XCTest
import Crypto
@testable import LGKCore

private func obj(_ v: JSONValue?) -> [String: JSONValue] { if case .object(let o)? = v { return o }; return [:] }
private func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { return a }; return [] }
private func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }
private func int(_ v: JSONValue?) -> Int64 { if case .int(let i)? = v { return i }; return -1 }

/// A settable wall clock and monotonic clock (no sleeping in tests).
final class TestClocks: UnixClock, MonotonicClock, @unchecked Sendable {
    private let lock = NSLock()
    private var wallNow: Int64
    private var mono: Double
    init(wall: Int64, mono: Double = 1000) { wallNow = wall; self.mono = mono }
    var now: Int64 { lock.withLock { wallNow } }
    var seconds: Double { lock.withLock { mono } }
    func advance(wall: Int64, mono: Double) { lock.withLock { wallNow += wall; self.mono += mono } }
}

final class HostPairingTests: XCTestCase {
    let t0: Int64 = 1790000030
    func a() throws -> DeviceIdentity { try KeyringTests.identity("A") }
    func b() throws -> DeviceIdentity { try KeyringTests.identity("B") }
    func lan() throws -> [String: JSONValue] { obj(try CanonicalJSON.parse(Array(Vectors.data("lan/expected_lan.json")))) }
    func offer() throws -> PairingOffer { try PairingOffer.parseQR(String(decoding: try Vectors.data("lan/qr_payload.txt"), as: UTF8.self)) }
    func request() throws -> [UInt8] { Array(try Vectors.data("lan/enroll_request.bin")) }
    func refusal(_ r: String) -> OfferSession.Outcome { .refuse(try! Enrollment.refusal(r)) }

    func session(_ clocks: TestClocks) throws -> OfferSession {
        try OfferSession(offer: try offer(), inviter: try a(), wall: clocks, monotonic: clocks)
    }

    /// A request that decrypts but fails the MAC (the sender guessed a wrong pairing secret): counts as an attempt.
    func wrongSecretRequest() throws -> [UInt8] {
        let o = try offer()
        let forged = PairingOffer(version: o.version, offerID: o.offerID, groupID: o.groupID, endpoint: o.endpoint,
                                  inviterDeviceID: o.inviterDeviceID, inviterSigningPublic: o.inviterSigningPublic,
                                  inviterExchangePublic: o.inviterExchangePublic, certificateFingerprint: o.certificateFingerprint,
                                  expiresAt: o.expiresAt, transcriptNonce: o.transcriptNonce,
                                  pairingSecret: [UInt8](repeating: 7, count: 32), code: o.code)
        return try Enrollment.buildRequest(offer: forged, identity: try b(), random: SystemRandomSource(), now: FixedClock(now: t0))
    }

    func testQRPayloadMatchesPython() throws {
        let cases = arr(obj(try CanonicalJSON.parse(Array(Vectors.data("mac/host_offer.json"))))["cases"])
        XCTAssertEqual(cases.count, 2)
        for c in cases.map({ obj($0) }) {
            let reads = arr(c["random_reads_hex"]).map { Vectors.hex(str($0)) }
            let random = QueueRandom(reads)
            let ep = obj(c["endpoint"])
            let (o, secret) = try PairingOffer.create(group: str(c["group_id"]), identity: try a(),
                                                      endpoint: try LanEndpoint(validating: str(ep["host"]), port: Int(int(ep["port"]))),
                                                      now: FixedClock(now: int(c["now"])), random: random)
            XCTAssertTrue(random.isEmpty, str(c["name"]))
            XCTAssertEqual(try o.qrPayload(), str(c["qr_payload"]), str(c["name"]))
            XCTAssertEqual(o.bundleJSON, c["offer_bundle"])
            XCTAssertEqual(o.expiresAt, int(c["now"]) + 120)
            XCTAssertEqual(secret.code, o.code)
            XCTAssertEqual(secret.pairingSecret, o.pairingSecret)
            XCTAssertEqual(try PairingOffer.parseQR(try o.qrPayload()), o)
        }
        // The existing LAN vector's offer re-encodes to its QR text byte for byte.
        let text = String(decoding: try Vectors.data("lan/qr_payload.txt"), as: UTF8.self)
        XCTAssertEqual(try offer().qrPayload(), text)
        // Only a LAN endpoint is offered.
        XCTAssertThrowsError(try PairingOffer.create(group: LanTests.groupID, identity: try a(), endpoint: LanEndpoint(host: "8.8.8.8", port: 47821),
                                                     now: FixedClock(now: t0), random: SystemRandomSource()))
    }

    func testSealReplyMatchesVector() throws {
        let x = try lan()
        let cases = [("lan/enroll_request.bin", "lan/enroll_reply.bin", obj(x["reply"]), LanEndpoint(host: "192.168.1.31", port: 48202), obj(x["request"])),
                     ("lan/enroll_request_no_endpoint.bin", "lan/enroll_reply_no_endpoint.bin", obj(x["reply_no_endpoint"]), nil, obj(x["request_no_endpoint"]))]
        let o = try offer(), inviter = try a()
        for (reqFile, repFile, rep, endpoint, req) in cases {
            let request = try Enrollment.openRequest(offer: o, inviter: inviter, raw: Array(try Vectors.data(reqFile)))
            let vector = Array(try Vectors.data(repFile))
            let outer = obj(try CanonicalJSON.parse(Array(vector[Enrollment.replyMagic.count...])))
            let pythonSig = try Base64.decodeStrict(str(outer["sig"]))
            let gk = try GroupKey(groupID: str(rep["group_id"]), epoch: int(rep["epoch"]), key: Vectors.hex(str(rep["key_hex"])))
            func randomness() throws -> QueueRandom {
                QueueRandom([Vectors.hex(str(rep["ephemeral_private_hex"])), try Base64.decodeStrict(str(rep["nonce_b64"]))])
            }
            // With the desktop's deterministic signature the whole frame is byte-identical (the signed message must match).
            let pinned = try Enrollment.sealReply(inviter: inviter, offer: o, request: request, groupKey: gk, random: try randomness()) { message in
                XCTAssertTrue(DeviceIdentity.verify(signature: pythonSig, message: message, publicKey: inviter.signingPublicKey))
                return pythonSig
            }
            XCTAssertEqual(pinned, vector, repFile)
            // With the real (hedged) signer: same bytes but the signature, and the new device opens it.
            let real = try Enrollment.sealReply(inviter: inviter, offer: o, request: request, groupKey: gk, random: try randomness())
            var mine = obj(try CanonicalJSON.parse(Array(real[Enrollment.replyMagic.count...]))), theirs = outer
            mine["sig"] = nil; theirs["sig"] = nil
            XCTAssertEqual(mine, theirs)
            XCTAssertEqual(try Enrollment.openReply(offer: o, identity: try b(), raw: real, endpoint: endpoint, name: str(req["name"])), gk)
        }
    }

    func testOfferOneUse() throws {
        let clocks = TestClocks(wall: t0)
        let s = try session(clocks)
        guard case .verified(let r) = s.handle(try request()) else { return XCTFail("first use must verify") }
        XCTAssertEqual(r.deviceID, try b().deviceID)
        XCTAssertTrue(s.isExhausted)
        XCTAssertEqual(s.handle(try request()), refusal("used-or-expired"))  // a replay
        // A full peer list is refused before anything is consumed.
        let s2 = try session(TestClocks(wall: t0))
        XCTAssertEqual(s2.handle(try request(), peerCount: 16), refusal("full"))
        XCTAssertFalse(s2.isExhausted)
        guard case .verified = s2.handle(try request(), peerCount: 15) else { return XCTFail() }
    }

    func testFiveAttemptsThenRefused() throws {
        let s = try session(TestClocks(wall: t0))
        for i in 1...5 {
            XCTAssertEqual(s.handle(try wrongSecretRequest()), refusal("refused"))
            XCTAssertEqual(s.attempts, i)
        }
        XCTAssertTrue(s.isExhausted)
        // The sixth try, even a correct one, is refused as used up.
        XCTAssertEqual(s.handle(try request()), refusal("used-or-expired"))
        // A reserved device id counts as an attempt too.
        let s2 = try session(TestClocks(wall: t0))
        XCTAssertEqual(s2.handle(try request(), reservedIDs: [try b().deviceID]), refusal("refused"))
        XCTAssertEqual(s2.attempts, 1)
    }

    func testExpiredThenGraceRefusal() throws {
        // Wall clock expiry (TTL 120 s from offer creation: expires_at 1790000120).
        let c1 = TestClocks(wall: t0)
        let s1 = try session(c1)
        c1.advance(wall: 90, mono: 90)
        XCTAssertEqual(s1.handle(try request()), refusal("used-or-expired"))
        XCTAssertEqual(s1.attempts, 0)
        // Monotonic expiry: the wall clock set back cannot extend the offer.
        let c2 = TestClocks(wall: t0)
        let s2 = try session(c2)
        c2.advance(wall: -3600, mono: 90)
        XCTAssertEqual(s2.handle(try request()), refusal("used-or-expired"))
        // Grace period: still a clear refusal 599 s after expiry, then no answer at all.
        let c3 = TestClocks(wall: t0)
        let s3 = try session(c3)
        c3.advance(wall: 90 + 599, mono: 90 + 599)
        s3.expire()
        XCTAssertTrue(s3.isListening)
        XCTAssertEqual(s3.handle(try request()), refusal("used-or-expired"))
        c3.advance(wall: 1, mono: 1)
        XCTAssertEqual(s3.handle(try request()), .close)
        XCTAssertFalse(s3.isListening)
        // Monotonic grace end with the wall clock held back.
        let c4 = TestClocks(wall: t0)
        let s4 = try session(c4)
        c4.advance(wall: 0, mono: 90 + 600)
        XCTAssertEqual(s4.handle(try request()), .close)
        // A stopped session answers nothing.
        let s5 = try session(TestClocks(wall: t0))
        s5.stop()
        XCTAssertEqual(s5.handle(try request()), .close)
    }

    func testRequestTamperRefused() throws {
        let s = try session(TestClocks(wall: t0))
        var bad = try request(); bad[bad.count - 5] ^= 1  // ciphertext: does not decrypt, not counted
        XCTAssertEqual(s.handle(bad), refusal("refused"))
        XCTAssertEqual(s.handle(Array("LGKENROLL1\n{}".utf8)), refusal("refused"))
        XCTAssertEqual(s.handle([UInt8](repeating: 0x41, count: 20_000)), refusal("refused"))
        XCTAssertEqual(s.attempts, 0)
        XCTAssertFalse(s.isExhausted)
        guard case .verified = s.handle(try request()) else { return XCTFail("the real request still verifies") }
        // An inviter that does not match the offer cannot arm it.
        XCTAssertThrowsError(try OfferSession(offer: try offer(), inviter: try b()))
    }

    func testSecretComparisonsAndRefusalFallback() throws {
        XCTAssertTrue(Keyring.constantTimeEqual([1, 2, 3], [1, 2, 3]))
        XCTAssertFalse(Keyring.constantTimeEqual([1, 2, 3], [1, 2, 4]))
        XCTAssertFalse(Keyring.constantTimeEqual([1, 2, 3], [1, 2]))
        XCTAssertEqual(OfferSession.refusal("no-such-reason"), refusal("refused"))
        XCTAssertEqual(OfferSession.refusal("full"), refusal("full"))
    }
}
