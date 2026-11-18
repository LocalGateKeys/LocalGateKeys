package app.localgatekeys.core.lan

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.QueueRandom
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.sync.SyncGroupState
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** A settable wall clock and monotonic clock (no sleeping in tests; Swift `TestClocks`). */
class TestClocks(wall: Long, mono: Double = 1000.0) : UnixClock, MonotonicClock {
    @Volatile private var wallNow = wall
    @Volatile private var mono = mono
    override val now: Long get() = wallNow
    override fun seconds(): Double = mono

    @Synchronized
    fun advance(wall: Long, mono: Double) {
        wallNow += wall
        this.mono += mono
    }
}

/** Host-side pairing: Swift `HostPairingTests` and the peer cases of `LanResponderTests`, against `tests/vectors/sync`. */
class HostPairingTest {
    private val t0 = 1_790_000_030L
    private val groupId = "5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64"
    private val install = "android-install-0001"

    private fun obj(v: JsonValue?): Map<String, JsonValue> = (v as? JsonValue.Obj)?.fields ?: emptyMap()
    private fun arr(v: JsonValue?): List<JsonValue> = (v as? JsonValue.Arr)?.items ?: emptyList()
    private fun str(v: JsonValue?): String = (v as? JsonValue.Str)?.v ?: ""
    private fun int(v: JsonValue?): Long = (v as JsonValue.Int).v

    private fun lan(): Map<String, JsonValue> = obj(Vectors.json(Vectors.sync("lan/expected_lan.json")))
    private fun offer(): PairingOffer = PairingOffer.parseQr(String(Vectors.sync("lan/qr_payload.txt").readBytes(), Charsets.UTF_8))
    private fun request(): ByteArray = Vectors.sync("lan/enroll_request.bin").readBytes()
    private fun refusal(r: String): OfferSession.Outcome = OfferSession.Outcome.Refuse(Enrollment.refusal(r))
    private fun identity(who: String): DeviceIdentity = SyncFixtures.identity(who)
    private fun a(): DeviceIdentity = identity("A")
    private fun b(): DeviceIdentity = identity("B")
    private fun groupKey(): GroupKey = GroupKey(groupId, 1, Vectors.hex(str(obj(lan()["reply"])["key_hex"])))

    private fun session(clocks: TestClocks): OfferSession = OfferSession(offer(), a(), clocks, clocks)

    private fun state(who: String = "A", group: String = groupId, peers: List<LanPeer> = emptyList()): SyncGroupState =
        SyncGroupState(group, 1, groupKey().key, identity(who), install, hasFolder = false, lanPeers = peers)

    private fun fakePeer(n: Int): LanPeer = LanPeer(
        "f%07d-0000-4000-8000-000000000000".format(n), groupId,
        signingPublic = ByteArray(32) { n.toByte() }, exchangePublic = ByteArray(32) { (n + 100).toByte() },
    )

    /** A request that decrypts but fails the MAC (a wrong pairing secret): counts as an attempt. */
    private fun wrongSecretRequest(): ByteArray {
        val o = offer()
        val forged = PairingOffer(
            o.version, o.offerId, o.groupId, o.endpoint, o.inviterDeviceId, o.inviterSigningPublic, o.inviterExchangePublic,
            o.certificateFingerprint, o.expiresAt, o.transcriptNonce, ByteArray(32) { 7 }, o.code,
        )
        return Enrollment.buildRequest(forged, b(), "Phone", null, SystemRandomSource(), FixedClock(t0))
    }

    @Test
    fun qr_payload_matches_python() {
        val cases = arr(obj(Vectors.json(Vectors.sync("mac/host_offer.json")))["cases"])
        assertEquals(2, cases.size)
        for (c in cases.map { obj(it) }) {
            val reads = arr(c["random_reads_hex"]).map { Vectors.hex(str(it)) }
            val random = QueueRandom(reads)
            val ep = obj(c["endpoint"])
            val (o, secret) = PairingOffer.create(
                str(c["group_id"]), a(), LanEndpoint(str(ep["host"]), int(ep["port"]).toInt()), FixedClock(int(c["now"])), random,
            )
            assertTrue(random.isEmpty, str(c["name"]))
            val reveal = reads.last()
            assertEquals(PairingOffer.COMMIT_VERSION, o.version)
            assertContentEquals(reveal, o.reveal)
            assertContentEquals(Enrollment.commit(reveal), o.commit)
            assertFalse(o.qrPayload().contains(Base64Std.encode(reveal)))
            assertEquals(str(c["qr_payload"]), o.qrPayload(), str(c["name"]))
            assertEquals(c["offer_bundle"], o.bundleJson)
            assertEquals(int(c["now"]) + 120, o.expiresAt)
            assertEquals(o.code, secret.code)
            assertEquals(o.offerId, secret.offerId)
            assertContentEquals(o.pairingSecret, secret.pairingSecret)
            assertEquals(o.bundleJson, PairingOffer.parseQr(o.qrPayload()).bundleJson)
        }
        // The existing LAN vector's offer re-encodes to its QR text byte for byte.
        assertEquals(String(Vectors.sync("lan/qr_payload.txt").readBytes(), Charsets.UTF_8), offer().qrPayload())
        // Only a LAN endpoint is offered.
        assertFailsWith<PairingException> { LanEndpoint("8.8.8.8", 47821) }
    }

    @Test
    fun seal_reply_matches_vector() {
        val x = lan()
        val cases = listOf(
            listOf("lan/enroll_request.bin", "lan/enroll_reply.bin", "reply", "request"),
            listOf("lan/enroll_request_no_endpoint.bin", "lan/enroll_reply_no_endpoint.bin", "reply_no_endpoint", "request_no_endpoint"),
        )
        val o = offer()
        val inviter = a()
        for ((reqFile, repFile, repKey, reqKey) in cases) {
            val rep = obj(x[repKey])
            val req = obj(x[reqKey])
            val request = Enrollment.openRequest(o, inviter, Vectors.sync(reqFile).readBytes())
            val vector = Vectors.sync(repFile).readBytes()
            val outer = obj(CanonicalJson.parse(vector.copyOfRange(Enrollment.REPLY_MAGIC.size, vector.size)))
            val pythonSig = Base64Std.decodeStrict(str(outer["sig"]))
            val gk = GroupKey(str(rep["group_id"]), int(rep["epoch"]), Vectors.hex(str(rep["key_hex"])))
            fun randomness() = QueueRandom(listOf(Vectors.hex(str(rep["ephemeral_private_hex"])), Base64Std.decodeStrict(str(rep["nonce_b64"]))))
            // With the desktop's signature the whole frame is byte-identical (the signed message must match).
            val pinned = Enrollment.sealReply(o, request, gk, randomness()) { message ->
                assertTrue(DeviceIdentity.verify(pythonSig, message, inviter.signingPublicKey))
                pythonSig
            }
            assertContentEquals(vector, pinned, repFile)
            // With the real signer: same fields but the signature, and the new device opens it.
            val real = Enrollment.sealReply(inviter, o, request, gk, randomness())
            val mine = obj(CanonicalJson.parse(real.copyOfRange(Enrollment.REPLY_MAGIC.size, real.size))) - "sig"
            assertEquals(outer - "sig", mine)
            val endpoint = request.endpoint
            assertEquals(gk, Enrollment.openReply(o, b(), real, str(req["name"]), endpoint))
        }
    }

    @Test
    fun offer_is_one_use() {
        val s = session(TestClocks(t0))
        val r = assertIs<OfferSession.Outcome.Verified>(s.handle(request()))
        assertEquals(b().deviceId, r.request.deviceId)
        assertTrue(s.isExhausted)
        assertEquals(refusal("used-or-expired"), s.handle(request())) // a replay
        // A full peer list is refused before anything is consumed.
        val s2 = session(TestClocks(t0))
        assertEquals(refusal("full"), s2.handle(request(), peerCount = 16))
        assertFalse(s2.isExhausted)
        assertIs<OfferSession.Outcome.Verified>(s2.handle(request(), peerCount = 15))
    }

    @Test
    fun five_attempts_then_refused() {
        val s = session(TestClocks(t0))
        for (i in 1..5) {
            assertEquals(refusal("refused"), s.handle(wrongSecretRequest()))
            assertEquals(i, s.attempts)
        }
        assertTrue(s.isExhausted)
        assertEquals(refusal("used-or-expired"), s.handle(request()))
        // A reserved device id counts as an attempt too.
        val s2 = session(TestClocks(t0))
        assertEquals(refusal("refused"), s2.handle(request(), reservedIds = setOf(b().deviceId)))
        assertEquals(1, s2.attempts)
    }

    @Test
    fun expired_then_grace_refusal_then_silence() {
        // Wall clock expiry (TTL 120 s from offer creation: expires_at 1790000120).
        val c1 = TestClocks(t0)
        val s1 = session(c1)
        c1.advance(90, 90.0)
        assertEquals(refusal("used-or-expired"), s1.handle(request()))
        assertEquals(0, s1.attempts)
        // Monotonic expiry: the wall clock set back cannot extend the offer.
        val c2 = TestClocks(t0)
        val s2 = session(c2)
        c2.advance(-3600, 90.0)
        assertEquals(refusal("used-or-expired"), s2.handle(request()))
        // Grace period: still a clear refusal 599 s after expiry, then no answer at all.
        val c3 = TestClocks(t0)
        val s3 = session(c3)
        c3.advance(90 + 599, 90.0 + 599)
        s3.expire()
        assertTrue(s3.isListening)
        assertEquals(refusal("used-or-expired"), s3.handle(request()))
        c3.advance(1, 1.0)
        assertEquals(OfferSession.Outcome.Close, s3.handle(request()))
        assertFalse(s3.isListening)
        // Monotonic grace end with the wall clock held back.
        val c4 = TestClocks(t0)
        val s4 = session(c4)
        c4.advance(0, 90.0 + 600)
        assertEquals(OfferSession.Outcome.Close, s4.handle(request()))
        // A stopped session answers nothing.
        val s5 = session(TestClocks(t0))
        s5.stop()
        assertEquals(OfferSession.Outcome.Close, s5.handle(request()))
    }

    @Test
    fun tampered_requests_are_refused_without_counting() {
        val s = session(TestClocks(t0))
        val bad = request()
        bad[bad.size - 5] = (bad[bad.size - 5].toInt() xor 1).toByte()
        assertEquals(refusal("refused"), s.handle(bad))
        assertEquals(refusal("refused"), s.handle("LGKENROLL1\n{}".toByteArray()))
        assertEquals(refusal("refused"), s.handle(ByteArray(20_000) { 0x41 }))
        assertEquals(0, s.attempts)
        assertFalse(s.isExhausted)
        assertIs<OfferSession.Outcome.Verified>(s.handle(request()))
        // An inviter that does not match the offer cannot arm it.
        assertFailsWith<Exception> { OfferSession(offer(), b()) }
    }

    @Test
    fun secret_comparisons_and_refusal_fallback() {
        assertTrue(Keyring.constantTimeEqual(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 3)))
        assertFalse(Keyring.constantTimeEqual(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 4)))
        assertFalse(Keyring.constantTimeEqual(byteArrayOf(1, 2, 3), byteArrayOf(1, 2)))
        assertEquals(refusal("refused"), OfferSession.refusal("no-such-reason"))
        assertEquals(refusal("full"), OfferSession.refusal("full"))
    }

    // ---- peers and enrollment (Swift LanResponderTests) ----

    @Test
    fun sixteen_peer_limit() {
        var st = state()
        for (n in 1..16) st = LanPeers.adding(fakePeer(n), st)
        assertEquals(16, st.lanPeers.size)
        assertEquals(16, LanPeers.adding(fakePeer(3), st).lanPeers.size) // replacing an entry is fine
        assertEquals("too-many-peers", assertFailsWith<LanSyncException> { LanPeers.adding(fakePeer(17), st) }.reason)
        // A revoked entry still counts.
        st = LanPeers.revoking(fakePeer(1).deviceId, st).first
        assertFailsWith<LanSyncException> { LanPeers.adding(fakePeer(17), st) }
        // Enrollment answers `full` before anything is consumed.
        val clocks = TestClocks(t0)
        val session = OfferSession(offer(), a(), clocks, clocks)
        assertEquals(refusal("full"), LanPeers.verifyEnrollment(request(), session, st))
        assertFalse(session.isExhausted)
        val req = assertIs<OfferSession.Outcome.Verified>(LanPeers.verifyEnrollment(request(), session, state())).request
        val err = assertFailsWith<PairingException> { LanPeers.acceptEnrollment(req, offer(), st, 1, SystemRandomSource()) }
        assertEquals(PairingException.Kind.REFUSED, err.kind)
        assertEquals("full", err.detail)
    }

    @Test
    fun accepted_enrollment_pins_the_peer_once() {
        val st = state()
        val o = offer()
        val clocks = TestClocks(t0)
        val session = OfferSession(o, a(), clocks, clocks)
        val raw = request()
        val req = assertIs<OfferSession.Outcome.Verified>(LanPeers.verifyEnrollment(raw, session, st)).request
        val (reply, pinned) = LanPeers.acceptEnrollment(req, o, st, t0 + 1, SystemRandomSource())
        assertEquals(groupKey(), Enrollment.openReply(o, b(), reply, req.name, req.endpoint))
        val bi = b()
        assertEquals(
            listOf(LanPeer(bi.deviceId, groupId, req.name, req.endpoint, bi.signingPublicKey, bi.exchangePublicKey, t0 + 1)),
            pinned.lanPeers,
        )
        assertEquals(bi.fingerprint, pinned.lanPeers[0].pinned.fingerprint)
        // A phone host keeps no endpoint for its peers.
        val (_, noEndpoint) = LanPeers.acceptEnrollment(req, o, st, t0 + 1, SystemRandomSource(), keepEndpoint = false)
        assertEquals(null, noEndpoint.lanPeers[0].endpoint)
        // Replayed: used up, nothing more to pin.
        assertEquals(refusal("used-or-expired"), LanPeers.verifyEnrollment(raw, session, pinned))
        // The id is now reserved for any other keys; the same device with the same keys may pair again (rule 4 below).
        val other = LanPeer(bi.deviceId, groupId, signingPublic = ByteArray(32) { 1 }, exchangePublic = bi.exchangePublicKey)
        val again = assertFailsWith<PairingException> {
            LanPeers.acceptEnrollment(req, o, st.copy(lanPeers = listOf(other)), 1, SystemRandomSource())
        }
        assertEquals("refused", again.detail)
        // Expired: refused with the Windows reason.
        val late = OfferSession(o, a(), clocks, clocks)
        clocks.advance(121, 121.0)
        assertEquals(refusal("used-or-expired"), LanPeers.verifyEnrollment(raw, late, st))
    }

    // ---- a known device pairing again (design 2026-11-17 keep-device-id-on-rejoin, rule 4) ----

    /** B as a phone host keeps it after an earlier pairing: no endpoint, pinned to the sealed hello. */
    private fun pairedB(): LanPeer {
        val bi = b()
        return LanPeer(bi.deviceId, groupId, "Old name", null, bi.signingPublicKey, bi.exchangePublicKey, t0 - 500, hello = 3)
    }

    @Test
    fun a_paired_device_with_the_same_keys_pairs_again_in_place() {
        val bi = b()
        val o = offer()
        val st = state(peers = listOf(fakePeer(1), pairedB(), fakePeer(2))).copy(
            lastSeen = mapOf(bi.deviceId to 7), peerGenerations = mapOf(bi.deviceId to 42), witnessPeers = listOf(bi.deviceId),
        )
        val clocks = TestClocks(t0)
        val session = OfferSession(o, a(), clocks, clocks)
        val req = assertIs<OfferSession.Outcome.Verified>(LanPeers.verifyEnrollment(request(), session, st)).request
        assertEquals(0, session.attempts)
        val (reply, after) = LanPeers.acceptEnrollment(req, o, st, t0 + 1, SystemRandomSource(), keepEndpoint = false)
        assertEquals(groupKey(), Enrollment.openReply(o, bi, reply, req.name, req.endpoint))
        // One entry, in its place: name, address, pairing time and protocol pin replaced (a version-1 offer: no pin).
        assertEquals(listOf(fakePeer(1).deviceId, bi.deviceId, fakePeer(2).deviceId), after.lanPeers.map { it.deviceId })
        assertEquals(
            LanPeer(bi.deviceId, groupId, req.name, null, bi.signingPublicKey, bi.exchangePublicKey, t0 + 1),
            after.lanPeers[1],
        )
        // What this host holds for the id stays, so an old session of it still cannot be replayed.
        assertEquals(mapOf(bi.deviceId to 7L), after.lastSeen)
        assertEquals(mapOf(bi.deviceId to 42L), after.peerGenerations)
        assertEquals(listOf(bi.deviceId), after.witnessPeers)

        // It takes no new place: a full host still lets it pair again, and only it.
        var full = state(peers = listOf(pairedB()))
        for (n in 1..15) full = LanPeers.adding(fakePeer(n), full)
        assertEquals(16, full.lanPeers.size)
        val s2 = OfferSession(o, a(), clocks, clocks)
        val req2 = assertIs<OfferSession.Outcome.Verified>(LanPeers.verifyEnrollment(request(), s2, full)).request
        assertEquals(16, LanPeers.acceptEnrollment(req2, o, full, t0 + 2, SystemRandomSource()).second.lanPeers.size)
        val notB = full.copy(lanPeers = full.lanPeers.map { if (it.deviceId == bi.deviceId) fakePeer(16) else it })
        val s3 = OfferSession(o, a(), clocks, clocks)
        assertEquals(refusal("full"), LanPeers.verifyEnrollment(request(), s3, notB))
        assertFalse(s3.isExhausted)
        assertEquals(0, s3.attempts)
    }

    @Test
    fun a_known_id_with_other_keys_a_revoked_id_a_member_only_id_and_the_own_id_are_refused_as_before() {
        val bi = b()
        val o = offer()
        val listed = pairedB()
        val otherSigning = LanPeer(bi.deviceId, groupId, null, null, ByteArray(32) { 1 }, bi.exchangePublicKey, t0)
        val otherExchange = LanPeer(bi.deviceId, groupId, null, null, bi.signingPublicKey, ByteArray(32) { 9 }, t0)
        val refusedStates = listOf(
            state(peers = listOf(otherSigning)),
            state(peers = listOf(otherExchange)),
            state(peers = listOf(listed.copy(revoked = true))),
            state().copy(members = listOf(a().deviceId, bi.deviceId)), // known only from the folder member list
        )
        for (st in refusedStates) {
            val clocks = TestClocks(t0)
            val session = OfferSession(o, a(), clocks, clocks)
            assertEquals(refusal("refused"), LanPeers.verifyEnrollment(request(), session, st))
            assertEquals(1, session.attempts) // counted, as a reserved id always was
            val req = Enrollment.openRequest(o, a(), request())
            assertEquals(null, LanPeers.rejoining(st, req))
            val err = assertFailsWith<PairingException> { LanPeers.acceptEnrollment(req, o, st, 1, SystemRandomSource()) }
            assertEquals("refused", err.detail)
        }
        // This device's own id never pairs, even when listed with the request's keys.
        val req = Enrollment.openRequest(o, a(), request())
        assertEquals(null, LanPeers.rejoining(state(who = "B", peers = listOf(listed)), req))
        assertEquals(listed, LanPeers.rejoining(state(peers = listOf(listed)), req))
    }

    @Test
    fun offer_of_another_group_or_inviter_is_refused() {
        val o = offer()
        val raw = request()
        for (st in listOf(state(group = "7c1d8e4f-0000-4000-8000-000000000001"), state(who = "C"))) {
            val clocks = TestClocks(t0)
            val session = OfferSession(o, a(), clocks, clocks)
            assertEquals(refusal("refused"), LanPeers.verifyEnrollment(raw, session, st))
            assertFalse(session.isListening) // the offer is disarmed
            assertEquals(OfferSession.Outcome.Close, LanPeers.verifyEnrollment(raw, session, st))
            val fresh = OfferSession(o, a(), clocks, clocks)
            val req = assertIs<OfferSession.Outcome.Verified>(fresh.handle(raw)).request
            val err = assertFailsWith<PairingException> { LanPeers.acceptEnrollment(req, o, st, 1, SystemRandomSource()) }
            assertEquals("refused", err.detail)
        }
        // No state at all: nothing verifies.
        assertFalse(LanPeers.verifyEnrollment(raw, OfferSession(o, a()), null) is OfferSession.Outcome.Verified)
    }

    @Test
    fun lan_peer_stored_form_round_trips() {
        val ai = a()
        var p = LanPeer(ai.deviceId, groupId, "A", LanEndpoint("192.168.1.20", 47821), ai.signingPublicKey, ai.exchangePublicKey, 1)
        assertEquals(p, LanPeer.fromJson(p.json))
        p = p.copy(name = null, endpoint = null, revoked = true)
        assertEquals(p, LanPeer.fromJson(p.json))
        val sealed = p.copy(hello = 3)
        assertTrue(LanPeer.fromJson(sealed.json).sealed)
        assertFailsWith<LanSyncException> { LanPeer.fromJson(JsonValue.Obj(mapOf("device_id" to JsonValue.Str("x")))) }
    }

    @Test
    fun a_wifi_group_is_made_with_this_device_alone() {
        val st = LanPeers.createWifiGroup(install, SystemRandomSource())
        assertEquals(1, st.epoch)
        assertFalse(st.hasFolder)
        assertEquals(install, st.installId)
        assertTrue(st.lanPeers.isEmpty())
        assertTrue(Regex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").matches(st.groupId))
        assertEquals(32, st.groupKey().key.size)
        assertFailsWith<Exception> { LanPeers.createWifiGroup("", SystemRandomSource()) }
    }
}
