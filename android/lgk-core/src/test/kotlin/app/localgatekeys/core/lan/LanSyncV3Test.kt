package app.localgatekeys.core.lan

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.primitives.X25519
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MemoryCounterStore
import app.localgatekeys.core.support.QueueRandom
import app.localgatekeys.core.support.Vectors
import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * LAN protocol version 3 (`docs/formats/LAN_SYNC_V3.md`): the checks of section 4 against
 * `tests/vectors/sync/lan/v3/`, and the behaviour of the desktop tests `test_sync_sealed_hello.py` and the
 * commit-then-reveal cases of `test_sync_lan.py` that apply to Android (initiator and invitee only).
 */
class LanSyncV3Test {
    private val groupId = "5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64"

    private fun obj(v: JsonValue?): Map<String, JsonValue> = (v as? JsonValue.Obj)?.fields ?: emptyMap()
    private fun arr(v: JsonValue?): List<JsonValue> = (v as? JsonValue.Arr)?.items ?: emptyList()
    private fun str(v: JsonValue?): String = (v as? JsonValue.Str)?.v ?: ""
    private fun int(v: JsonValue?): Long = (v as JsonValue.Int).v
    private fun bytes(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)
    private fun file(name: String): File = Vectors.sync("lan/v3/$name")
    private fun vec(name: String): Map<String, JsonValue> = obj(Vectors.json(file(name)))
    private fun hex(v: JsonValue?): ByteArray = Vectors.hex(str(v))
    private fun sha(b: ByteArray): String = Vectors.hexString(MessageDigest.getInstance("SHA-256").digest(b))
    private fun canon(m: Map<String, JsonValue>): ByteArray = CanonicalJson.encode(JsonValue.Obj(m), Dialect.ASCII)

    private fun identity(who: String): DeviceIdentity {
        val ids = obj(Vectors.json(Vectors.sync("identities.json")).obj().fields["devices"])
        val p = obj(obj(ids[who])["private"])
        return DeviceIdentity(
            str(p["device_id"]),
            Base64Std.decodeStrict(str(p["signing_private"])),
            Base64Std.decodeStrict(str(p["exchange_private"])),
        )
    }

    private fun pinned(who: String): PinnedPeer {
        val i = identity(who)
        return PinnedPeer(i.deviceId, groupId, i.signingPublicKey, i.exchangePublicKey, null)
    }

    private fun groupKey(): GroupKey =
        GroupKey(groupId, 1, Vectors.hex(str(obj(obj(Vectors.json(Vectors.sync("lan/expected_lan.json")))["reply"])["key_hex"])))

    private fun sessions(): List<Map<String, JsonValue>> = arr(vec("session.json")["sessions"]).map { obj(it) }

    /** The recorded version-3 hello of [side] re-made from its private values (so it can derive once). */
    private fun remade(side: Map<String, JsonValue>, sid: ByteArray): SessionHello = SessionHello.make(
        identity(str(side["device"])), groupId, sid, int(side["counter"]),
        QueueRandom(listOf(hex(side["nonce_hex"]), hex(side["ephemeral_private_hex"]))), LanTransport.VERSION,
    )

    // ---- section 4: sessions ----

    @Test
    fun inner_hellos_are_version_3_and_match_byte_for_byte() {
        for (s in sessions()) {
            val sid = hex(s["session_id"])
            for (role in listOf("initiator", "responder")) {
                val side = obj(obj(s["hello"])[role])
                val made = remade(side, sid)
                assertContentEquals(bytes(str(side["text"])), made.toBytes())
                assertContentEquals(hex(side["signing_input_hex"]), made.signingBytes())
                assertTrue(made.signingBytes().copyOf(36).contentEquals(bytes("localgatekeys|sync|session-hello|v3|")))
                val parsed = SessionHello.parse(bytes(str(side["text"])), LanTransport.VERSION)
                assertEquals(made, parsed)
                SessionHello.verify(parsed, pinned(str(side["device"])), groupId)
                // A version-3 hello is not a clear-text first frame, and a version-2 parse refuses it.
                assertFailsWith<LanTransportException> { SessionHello.parse(bytes(str(side["text"]))) }
            }
        }
    }

    @Test
    fun both_hellos_seal_byte_for_byte_and_open_in_both_roles() {
        for (s in sessions()) {
            val sid = hex(s["session_id"])
            val ini = obj(obj(s["hello"])["initiator"])
            val res = obj(obj(s["hello"])["responder"])
            val sh = obj(s["sealed_hello"])
            val hi = SessionHello.parse(bytes(str(ini["text"])), LanTransport.VERSION)
            val hr = SessionHello.parse(bytes(str(res["text"])), LanTransport.VERSION)
            val responder = identity(str(res["device"]))
            val staticR = hex(sh["responder_static_public_hex"])
            assertContentEquals(responder.exchangePublicKey, staticR)
            val ephPrivate = hex(sh["ephemeral_private_hex"])
            assertContentEquals(hex(sh["ephemeral_public_hex"]), X25519.publicKey(ephPrivate))
            assertContentEquals(hex(sh["es_hex"]), X25519.agree(ephPrivate, staticR))
            assertContentEquals(hex(sh["hkdf_salt_hex"]), hex(sh["ephemeral_public_hex"]) + staticR)
            assertContentEquals(ByteArray(12), hex(sh["nonce_hex"]))
            assertEquals("localgatekeys|sync|sealed-hello|v3|initiator", str(sh["info_initiator"]))
            assertEquals("localgatekeys|sync|sealed-hello|v3|responder", str(sh["info_responder"]))
            // Seal: the initiator's frame, then the responder's answer under the same context.
            val (first, ctx) = SealedHello.sealInitiator(hi, staticR, ephPrivate)
            assertContentEquals(bytes(str(sh["initiator_frame"])), first)
            assertContentEquals(hex(sh["key_initiator_hex"]), ctx.key(SecureChannel.Role.INITIATOR))
            assertContentEquals(hex(sh["key_responder_hex"]), ctx.key(SecureChannel.Role.RESPONDER))
            assertContentEquals(hex(sh["aad_hex"]), ctx.aad())
            val padded = SealedHello.pad(hi)
            assertEquals(int(sh["initiator_inner_length"]), hi.toBytes().size.toLong())
            assertEquals(1024, padded.size)
            assertEquals(str(sh["initiator_plaintext_sha256"]), sha(padded))
            assertEquals(str(sh["responder_plaintext_sha256"]), sha(SealedHello.pad(hr)))
            assertEquals(int(sh["responder_inner_length"]), hr.toBytes().size.toLong())
            assertContentEquals(bytes(str(sh["responder_frame"])), SealedHello.sealResponder(hr, ctx))
            // Open as the responder (its static key), then as the initiator (the context).
            val (openedHi, rctx) = SealedHello.openInitiator(bytes(str(sh["initiator_frame"])), responder)
            assertEquals(hi, openedHi)
            assertEquals(LanTransport.VERSION, openedHi.version)
            assertEquals(hr, SealedHello.openResponder(bytes(str(sh["responder_frame"])), rctx))
            assertEquals(hr, SealedHello.openResponder(bytes(str(sh["responder_frame"])), ctx))
            // Both frames have a fixed length whatever the device ids.
            val initFields = (CanonicalJson.parse(bytes(str(sh["initiator_frame"]))) as JsonValue.Obj).fields
            assertEquals(SealedHello.BOX_BYTES, Base64Std.decodeStrict(str(initFields["box"])).size)
            ctx.wipe()
            assertFailsWith<LanTransportException> { ctx.key(SecureChannel.Role.INITIATOR) }
            assertTrue(sid.size == LanTransport.SESSION_ID_BYTES)
        }
    }

    @Test
    fun first_connection_frame_is_refused_with_the_keys_of_a_and_c() {
        val s = sessions()[0]
        val sh = obj(s["sealed_hello"])
        val frame = bytes(str(sh["initiator_frame"]))
        assertEquals("B", str(obj(obj(s["hello"])["responder"])["device"]))
        SealedHello.openInitiator(frame, identity("B"))
        for (who in listOf("A", "C")) {
            val e = assertFailsWith<LanTransportException> { SealedHello.openInitiator(frame, identity(who)) }
            assertEquals(LanTransportException.Kind.AUTHENTICATION, e.kind)
        }
        // A responder holding A's or C's key closes without a word.
        for (who in listOf("A", "C")) {
            assertNull(responder(identity(who), listOf("A", "B", "C")).first(frame))
        }
    }

    @Test
    fun session_key_and_the_recorded_frames() {
        for (s in sessions()) {
            val sid = hex(s["session_id"])
            val ini = obj(obj(s["hello"])["initiator"])
            val res = obj(obj(s["hello"])["responder"])
            val hi = SessionHello.parse(bytes(str(ini["text"])), LanTransport.VERSION)
            val hr = SessionHello.parse(bytes(str(res["text"])), LanTransport.VERSION)
            val transcript = SecureChannel.transcript(hi.toBytes(), hr.toBytes())
            assertContentEquals(hex(s["transcript_sorted_hex"]), transcript)
            assertEquals(str(s["salt"]), Vectors.hexString(SecureChannel.salt(transcript, LanTransport.VERSION)))
            assertContentEquals(hex(s["info_hex"]), SecureChannel.info(sid, LanTransport.VERSION))
            assertContentEquals(hex(s["key"]), SecureChannel.deriveKey(hex(s["ikm_hex"]), sid, transcript, LanTransport.VERSION))
            // The v2 labels give another key.
            assertFalse(hex(s["key"]).contentEquals(SecureChannel.deriveKey(hex(s["ikm_hex"]), sid, transcript)))
            val initiator = SecureChannel(
                identity(str(ini["device"])), pinned(str(res["device"])), groupId, sid, SecureChannel.Role.INITIATOR, remade(ini, sid), hr,
            )
            val responder = SecureChannel(
                identity(str(res["device"])), pinned(str(ini["device"])), groupId, sid, SecureChannel.Role.RESPONDER, remade(res, sid), hi,
            )
            assertContentEquals(hex(s["key"]), initiator.key)
            assertContentEquals(hex(s["key"]), responder.key)
            assertEquals(str(s["prefix_initiator"]), Vectors.hexString(initiator.sendPrefix))
            assertEquals(str(s["prefix_responder"]), Vectors.hexString(responder.sendPrefix))
            val request = obj(s["request"])
            val response = obj(s["response"])
            assertContentEquals(bytes(str(request["plaintext"])), responder.open(hex(request["frame_hex"])))
            assertContentEquals(bytes(str(response["plaintext"])), initiator.open(hex(response["frame_hex"])))
            assertContentEquals(hex(request["frame_hex"]), initiator.seal(bytes(str(request["plaintext"]))))
            // The frames keep the version-2 layout.
            assertEquals(JsonValue.Int(2), SecureChannel.parseFrame(LanTransport.decodeFrame(hex(request["frame_hex"])))["version"])
            // A version-2 hello and a version-3 hello never make one session.
            assertFailsWith<LanTransportException> {
                SecureChannel(
                    identity(str(ini["device"])), pinned(str(res["device"])), groupId, sid, SecureChannel.Role.INITIATOR,
                    SessionHello.make(identity(str(ini["device"])), groupId, sid, 1, SystemRandomSource()), hr,
                )
            }
        }
    }

    @Test
    fun the_bin_files_are_the_first_connection() {
        val s = sessions()[0]
        val sh = obj(s["sealed_hello"])
        assertContentEquals(LanTransport.encodeFrame(bytes(str(sh["initiator_frame"]))), file("sealed_hello_initiator.bin").readBytes())
        assertContentEquals(LanTransport.encodeFrame(bytes(str(sh["responder_frame"]))), file("sealed_hello_responder.bin").readBytes())
        assertContentEquals(hex(obj(s["request"])["frame_hex"]), file("frame_initiator.bin").readBytes())
        assertContentEquals(hex(obj(s["response"])["frame_hex"]), file("frame_responder.bin").readBytes())
        assertEquals(1024L, int(vec("session.json")["sealed_plaintext_bytes"]))
        assertContentEquals(bytes(str(vec("session.json")["version_refusal"])), LanTransport.versionRefusal())
    }

    @Test
    fun sealed_frames_are_parsed_strictly_and_padding_is_checked() {
        val sh = obj(sessions()[0]["sealed_hello"])
        val b = identity("B")
        val good = (CanonicalJson.parse(bytes(str(sh["initiator_frame"]))) as JsonValue.Obj).fields
        fun refused(m: Map<String, JsonValue>) = assertFailsWith<LanTransportException> { SealedHello.openInitiator(canon(m), b) }
        refused(good + ("signature" to JsonValue.Str("x")))
        refused(good + ("version" to JsonValue.Int(2)))
        refused(good + ("extra" to JsonValue.Int(1)))
        refused(good - "signature")
        refused(good + ("eph" to JsonValue.Str(Base64Std.encode(ByteArray(31) { 9 }))))
        refused(good + ("eph" to JsonValue.Str(Base64Std.encode(ByteArray(32)))))
        val box = Base64Std.decodeStrict(str(good["box"]))
        refused(good + ("box" to JsonValue.Str(Base64Std.encode(box.copyOf(box.size - 1)))))
        val flipped = box.copyOf().also { it[5] = (it[5].toInt() xor 1).toByte() }
        refused(good + ("box" to JsonValue.Str(Base64Std.encode(flipped))))
        // Padding: a forged box (right key, wrong padding) still fails.
        val eph = hex(sh["ephemeral_private_hex"])
        val ephPublic = X25519.publicKey(eph)
        val key = CryptoBox.hkdf(
            X25519.agree(eph, b.exchangePublicKey), ephPublic + b.exchangePublicKey,
            bytes("localgatekeys|sync|sealed-hello|v3|initiator"), 32,
        )
        val aad = bytes("localgatekeys|sync|sealed-hello|v3|") + ephPublic
        val hi = SessionHello.parse(bytes(str(obj(obj(sessions()[0]["hello"])["initiator"])["text"])), LanTransport.VERSION)
        fun forged(plain: ByteArray): ByteArray = canon(
            mapOf(
                "box" to JsonValue.Str(Base64Std.encode(CryptoBox.sealGcm(key, ByteArray(12), plain, aad))),
                "eph" to JsonValue.Str(Base64Std.encode(ephPublic)),
                "signature" to JsonValue.Str(""),
                "version" to JsonValue.Int(3),
            ),
        )
        val padded = SealedHello.pad(hi)
        assertEquals(hi, SealedHello.openInitiator(forged(padded), b).first) // the forge itself is right
        val dirty = padded.copyOf().also { it[1023] = 1 }
        assertFailsWith<LanTransportException> { SealedHello.openInitiator(forged(dirty), b) }
        val zeroLength = padded.copyOf().also { it[0] = 0; it[1] = 0 }
        assertFailsWith<LanTransportException> { SealedHello.openInitiator(forged(zeroLength), b) }
        val tooLong = padded.copyOf().also { it[0] = 0x03; it[1] = 0xFF.toByte() }
        assertFailsWith<LanTransportException> { SealedHello.openInitiator(forged(tooLong), b) }
        // A version-2 hello inside a sealed frame is refused.
        val v2 = SessionHello.make(identity("A"), groupId, hi.sessionId, 5, SystemRandomSource())
        val inner = v2.toBytes()
        val plain2 = ByteArray(1024).also { it[0] = (inner.size ushr 8).toByte(); it[1] = inner.size.toByte(); inner.copyInto(it, 2) }
        assertFailsWith<LanTransportException> { SealedHello.openInitiator(forged(plain2), b) }
        // The responder's answer: exact keys only.
        val (_, ctx) = SealedHello.openInitiator(bytes(str(sh["initiator_frame"])), b)
        val answer = (CanonicalJson.parse(bytes(str(sh["responder_frame"]))) as JsonValue.Obj).fields
        assertFailsWith<LanTransportException> { SealedHello.openResponder(canon(answer + ("eph" to good.getValue("eph"))), ctx) }
        assertFailsWith<LanTransportException> { SealedHello.openResponder(canon(answer + ("version" to JsonValue.Int(2))), ctx) }
        // The initiator's own box is not a responder answer.
        assertFailsWith<LanTransportException> { SealedHello.openResponder(canon(mapOf("box" to good.getValue("box"), "version" to JsonValue.Int(3))), ctx) }
    }

    // ---- behaviour: responder rules (spec 2.3) and the pin (2.5) ----

    private fun responder(
        who: DeviceIdentity,
        members: List<String>,
        pins: SealedPeers = SealedPeers(),
        counters: HelloCounterSource = HelloCounterSource(MemoryCounterStore(), FixedClock(1790000900)),
        answer: (ByteArray) -> ByteArray = { bytes("{\"type\":\"pong\"}") },
    ): LanResponder {
        val peers = members.associate { pinned(it).deviceId to pinned(it) }
        return LanResponder(who, groupId, { peers[it] }, counters, SystemRandomSource(), pins) { _, plain -> answer(plain) }
    }

    private fun client(who: String = "A", store: MemoryCounterStore = MemoryCounterStore()): LanClient =
        LanClient(identity(who), groupKey(), HelloCounterSource(store, FixedClock(1790000900)), SystemRandomSource(), FixedClock(1790000900))

    private fun sealedFirst(from: String, to: String, counter: Long): ByteArray {
        val h = SessionHello.make(identity(from), groupId, SystemRandomSource().bytes(16), counter, SystemRandomSource(), LanTransport.VERSION)
        return SealedHello.sealInitiator(h, identity(to).exchangePublicKey, SystemRandomSource()).first
    }

    @Test
    fun a_sealed_session_works_and_pins_the_peer_once() {
        val saved = ArrayList<String>()
        val pins = SealedPeers(onSealed = { saved.add(it) })
        val counters = HelloCounterSource(MemoryCounterStore(), FixedClock(1790000900))
        val c = client()
        repeat(2) {
            val got = c.request(bytes("{\"type\":\"ping\"}"), pinned("B"), responder(identity("B"), listOf("A"), pins, counters).connection())
            assertContentEquals(bytes("{\"type\":\"pong\"}"), got)
        }
        assertTrue(identity("A").deviceId in pins)
        assertEquals(listOf(identity("A").deviceId), saved) // persisted once
    }

    @Test
    fun the_pin_waits_for_the_first_encrypted_frame() {
        val pins = SealedPeers()
        val host = responder(identity("B"), listOf("A"), pins)
        assertTrue(host.first(sealedFirst("A", "B", 1)) != null)
        assertFalse(identity("A").deviceId in pins) // a captured hello alone does not pin
        assertNull(host.request(LanTransport.encodeFrame(bytes("{\"x\":1}"))))
        assertFalse(identity("A").deviceId in pins)
    }

    @Test
    fun silence_for_a_non_member_a_wrong_key_garbage_and_a_replay() {
        val b = identity("B")
        // Not a member: C seals to B's real key, but B does not pin C.
        assertNull(responder(b, listOf("A")).first(sealedFirst("C", "B", 1)))
        // Sealed to another device's key.
        assertNull(responder(b, listOf("A")).first(sealedFirst("A", "C", 1)))
        // Garbage and empty JSON.
        assertNull(responder(b, listOf("A")).first(bytes("hello")))
        assertNull(responder(b, listOf("A")).first(bytes("{}")))
        // A replayed sealed frame (same counter) gets no second answer.
        val counters = HelloCounterSource(MemoryCounterStore(), FixedClock(1790000900))
        val frame = sealedFirst("A", "B", 7)
        assertTrue(responder(b, listOf("A"), counters = counters).first(frame) != null)
        assertNull(responder(b, listOf("A"), counters = counters).first(frame))
        // A client facing silence: the peer did not answer.
        val silent = responder(identity("C"), listOf("A")).connection()
        assertFailsWith<LanPeerNotAnswering> { client().request(bytes("{}"), pinned("B"), silent) }
    }

    @Test
    fun a_clear_hello_is_answered_until_the_peer_is_pinned_then_refused() {
        val b = identity("B")
        val a = identity("A")
        val pins = SealedPeers()
        val counters = HelloCounterSource(MemoryCounterStore(), FixedClock(1790000900))
        fun clear(counter: Long, signer: DeviceIdentity = a): ByteArray =
            SessionHello.make(signer, groupId, SystemRandomSource().bytes(16), counter, SystemRandomSource()).toBytes()
        // Not pinned: a released (version-2) initiator still gets a clear-text version-2 hello.
        val answer = responder(b, listOf("A"), pins, counters).first(clear(1))!!
        assertEquals(LanTransport.PLAIN_HELLO_VERSION, SessionHello.parse(answer).version)
        // The first sealed session pins A.
        client().request(bytes("{}"), pinned("B"), responder(b, listOf("A"), pins, counters).connection())
        assertTrue(a.deviceId in pins)
        // Pinned: a verified clear hello gets only the version-3 refusal (downgrade refused).
        assertContentEquals(LanTransport.versionRefusal(), responder(b, listOf("A"), pins, counters).first(clear(Long.MAX_VALUE / 2)))
        // A clear hello that does not verify (signed by C as A) is closed without an answer.
        val forged = (CanonicalJson.parse(clear(Long.MAX_VALUE / 2 + 1, identity("C"))) as JsonValue.Obj).fields +
            mapOf("device_id" to JsonValue.Str(a.deviceId))
        assertNull(responder(b, listOf("A"), pins, counters).first(canon(forged)))
        // A replayed clear hello is closed too.
        assertNull(responder(b, listOf("A"), pins, counters).first(clear(1)))
    }

    @Test
    fun a_hello_of_another_version_gets_the_version_3_refusal() {
        val legacy = bytes(str(obj(Vectors.json(Vectors.sync("lan/session.json"))).let { obj(it["legacy_hello"]) }["text"]))
        assertContentEquals(LanTransport.versionRefusal(), responder(identity("B"), listOf("A")).first(legacy))
        val v4 = canon(mapOf("version" to JsonValue.Int(4), "signature" to JsonValue.Str("x")))
        assertContentEquals(LanTransport.versionRefusal(), responder(identity("B"), listOf("A")).first(v4))
    }

    @Test
    fun an_old_peer_is_reported_and_never_gets_a_clear_hello() {
        // A released build answers the sealed frame with its version-2 refusal.
        val v2Refusal = bytes(str(obj(Vectors.json(Vectors.sync("lan/session.json")))["version_refusal"]))
        var sent = ByteArray(0)
        val old = object : LanConnection {
            var calls = 0
            override fun exchange(frame: ByteArray): ByteArray {
                calls++
                sent = LanTransport.decodeFrame(frame)
                return LanTransport.encodeFrame(v2Refusal)
            }
        }
        val e = assertFailsWith<LanSyncException> { client().request(bytes("{}"), pinned("B"), old) }
        assertEquals("peer-update-needed", e.reason)
        assertEquals(1, old.calls)
        val first = (CanonicalJson.parse(sent) as JsonValue.Obj).fields
        assertEquals(setOf("box", "eph", "signature", "version"), first.keys)
        assertEquals(JsonValue.Str(""), first["signature"])
        // What a version-2 parser makes of it: a hello of another version (it answers its refusal).
        assertEquals(3L, SessionHello.otherVersion(sent))
        // A newer peer: this device needs the update.
        val newer = object : LanConnection {
            override fun exchange(frame: ByteArray): ByteArray =
                LanTransport.encodeFrame(bytes("{\"refused\":\"version\",\"version\":4}"))
        }
        assertEquals("lan-update-needed", assertFailsWith<LanSyncException> { client().request(bytes("{}"), pinned("B"), newer) }.reason)
    }

    @Test
    fun the_sealed_frames_reveal_no_identifier_and_have_a_fixed_size() {
        val sizes = HashSet<Int>()
        for (who in listOf("A", "C")) {
            val frame = sealedFirst(who, "B", 1)
            sizes.add(frame.size)
            val text = String(frame, Charsets.US_ASCII)
            assertFalse(text.contains(identity(who).deviceId))
            assertFalse(text.contains(groupId))
            assertFalse(text.contains(Base64Std.encode(identity(who).signingPublicKey)))
        }
        assertEquals(1, sizes.size)
        // Fresh sealing key per connection.
        assertNotEquals(String(sealedFirst("A", "B", 1)), String(sealedFirst("A", "B", 1)))
    }

    // ---- section 4: commit-then-reveal enrollment ----

    private fun enroll(): Map<String, JsonValue> = vec("enroll.json")
    private fun offer(): PairingOffer = PairingOffer.parseQr(String(file("qr_payload.txt").readBytes(), Charsets.UTF_8))
    private fun reveal(): ByteArray = hex(enroll()["reveal_hex"])
    private fun inviterOffer(o: PairingOffer = offer(), reveal: ByteArray? = reveal()): PairingOffer = PairingOffer(
        o.version, o.offerId, o.groupId, o.endpoint, o.inviterDeviceId, o.inviterSigningPublic, o.inviterExchangePublic,
        o.certificateFingerprint, o.expiresAt, o.transcriptNonce, o.pairingSecret, o.code, o.commit, reveal,
    )
    private fun requestEndpoint(): LanEndpoint {
        val e = obj(obj(enroll()["request"])["invitee_endpoint"])
        return LanEndpoint(str(e["host"]), int(e["port"]).toInt())
    }
    private fun name(): String = str(obj(enroll()["request"])["name"])

    @Test
    fun the_version_2_offer_carries_the_commitment() {
        val e = enroll()
        val o = offer()
        assertEquals(str(e["qr_payload"]), String(file("qr_payload.txt").readBytes(), Charsets.UTF_8))
        assertEquals(2L, o.version)
        assertEquals(e["offer_bundle"], o.bundleJson)
        assertContentEquals(hex(e["commit_hex"]), o.commit)
        assertEquals("localgatekeys|sync|enroll-commit|v3|", str(e["commit_label"]))
        assertContentEquals(hex(e["commit_hex"]), Enrollment.commit(reveal()))
        assertNull(o.reveal)
        assertEquals(Enrollment.VERSION, Enrollment.version(o))
        // The reveal is nowhere in the QR.
        assertFalse(String(file("qr_payload.txt").readBytes()).contains(Base64Std.encode(reveal())))
        // A version-2 bundle without a 32-byte commit, and a version-1 offer with one, are malformed.
        val bundle = obj(e["offer_bundle"])
        fun kind(m: Map<String, JsonValue>) = assertFailsWith<PairingException> { PairingOffer.fromBundle(JsonValue.Obj(m)) }.kind
        assertEquals(PairingException.Kind.MALFORMED, kind(bundle - "commit"))
        assertEquals(PairingException.Kind.MALFORMED, kind(bundle + ("commit" to JsonValue.Str(Base64Std.encode(ByteArray(31))))))
        assertFailsWith<PairingException> { inviterOffer(reveal = ByteArray(32) { 1 }) }
        val v1 = PairingOffer.fromBundle(JsonValue.Obj(bundle + ("version" to JsonValue.Int(1))))
        assertNull(v1.commit) // a released parser's view: the commit key is ignored
        assertFailsWith<PairingException> {
            PairingOffer(
                1, o.offerId, o.groupId, o.endpoint, o.inviterDeviceId, o.inviterSigningPublic, o.inviterExchangePublic,
                o.certificateFingerprint, o.expiresAt, o.transcriptNonce, o.pairingSecret, o.code, o.commit,
            )
        }
    }

    @Test
    fun the_request_is_version_3_and_matches_the_vector() {
        val e = enroll()
        val req = obj(e["request"])
        val b = identity("B")
        assertEquals(str(req["device_id"]), b.deviceId)
        val raw = Enrollment.buildRequest(
            offer(), b, name(), requestEndpoint(),
            QueueRandom(listOf(hex(req["ephemeral_private_hex"]), Base64Std.decodeStrict(str(req["nonce_b64"])))),
            FixedClock(int(e["now"])),
        )
        assertContentEquals(file("enroll_request.bin").readBytes(), raw)
        val transcript = Enrollment.transcript(offer(), b.deviceId, b.signingPublicKey, b.exchangePublicKey, requestEndpoint(), name())
        assertContentEquals(bytes(str(req["transcript"])), transcript)
        assertEquals(JsonValue.Int(3), obj(CanonicalJson.parse(transcript))["version"])
        // The inviter opens it (version 3), and its request carries the code the user compares.
        val opened = Enrollment.openRequest(inviterOffer(), identity("A"), raw)
        assertContentEquals(bytes(str(req["plaintext"])), opened.body)
        assertEquals(JsonValue.Int(3), obj(CanonicalJson.parse(opened.body))["version"])
        assertEquals(str(obj(e["verification_code"])["code"]), opened.code)
        assertContentEquals(file("enroll_reveal.bin").readBytes(), Enrollment.revealFrame(inviterOffer()))
    }

    @Test
    fun reveal_checks_against_the_commit_then_the_code_and_the_reply() {
        val e = enroll()
        val o = offer()
        val b = identity("B")
        val frame = file("enroll_reveal.bin").readBytes()
        assertEquals(str(obj(e["reveal_frame"])["text"]), String(frame, Charsets.UTF_8))
        assertContentEquals(hex(obj(e["reveal_frame"])["magic_hex"]), Enrollment.REVEAL_MAGIC)
        assertTrue(Enrollment.isReveal(frame))
        val reveal = Enrollment.openReveal(o, frame)
        assertContentEquals(reveal(), reveal)
        // The code covers the transcript and the reveal.
        val code = str(obj(e["verification_code"])["code"])
        val transcript = bytes(str(obj(e["request"])["transcript"]))
        assertEquals(code, Enrollment.verificationCode(transcript, reveal))
        assertEquals(code, Enrollment.verificationCode(o, b, requestEndpoint(), name(), reveal))
        assertNotEquals(code, Enrollment.verificationCode(transcript))
        // The reply opens with the reveal ...
        val reply = file("enroll_reply.bin").readBytes()
        val r = obj(e["reply"])
        val gk = Enrollment.openReply(o, b, reply, name(), requestEndpoint(), reveal)
        assertEquals(GroupKey(str(r["group_id"]), int(r["epoch"]), hex(r["key_hex"])), gk)
        // ... and is refused without it, or with another one.
        for (bad in listOf(null, ByteArray(32) { 7 }, reveal.copyOf(31))) {
            val err = assertFailsWith<PairingException> { Enrollment.openReply(o, b, reply, name(), requestEndpoint(), bad) }
            assertEquals(PairingException.Kind.AUTHENTICATION, err.kind)
        }
        // A refusal still reads as a refusal (no reveal was sent for it).
        val refusal = bytes(str(obj(e["refusals"])["version_2_body_on_version_2_offer"]))
        val refused = assertFailsWith<PairingException> { Enrollment.openReply(o, b, refusal, name(), requestEndpoint()) }
        assertEquals(PairingException.Kind.REFUSED, refused.kind)
        assertEquals("update-needed", refused.detail)
    }

    @Test
    fun a_reveal_that_does_not_match_or_is_malformed_aborts() {
        val o = offer()
        val good = file("enroll_reveal.bin").readBytes()
        val other = Enrollment.REVEAL_MAGIC + canon(mapOf("reveal" to JsonValue.Str(Base64Std.encode(ByteArray(32) { 5 }))))
        assertEquals(PairingException.Kind.AUTHENTICATION, assertFailsWith<PairingException> { Enrollment.openReveal(o, other) }.kind)
        for (bad in listOf(
            good.copyOf(good.size - 1),
            Enrollment.REVEAL_MAGIC + canon(mapOf("reveal" to JsonValue.Str(Base64Std.encode(reveal())), "x" to JsonValue.Int(1))),
            Enrollment.REVEAL_MAGIC + canon(mapOf("reveal" to JsonValue.Str(Base64Std.encode(reveal().copyOf(31))))),
            Enrollment.REPLY_MAGIC + good.copyOfRange(Enrollment.REVEAL_MAGIC.size, good.size),
            good + ByteArray(256),
        )) {
            assertFailsWith<PairingException> { Enrollment.openReveal(o, bad) }
        }
        // A version-1 offer has no commitment: a reveal frame is not for it.
        val v1 = PairingOffer.parseQr(String(Vectors.sync("lan/qr_payload.txt").readBytes(), Charsets.UTF_8))
        assertFailsWith<PairingException> { Enrollment.openReveal(v1, good) }
        assertNull(Enrollment.revealFrame(v1))
        // The code of a version-2 offer cannot be shown without the reveal.
        assertFailsWith<PairingException> { Enrollment.verificationCode(o, identity("B"), null, "Pixel") }
    }

    @Test
    fun grinding_the_code_fails_because_the_reveal_comes_after_the_request() {
        // Holding the QR, an attacker can build any number of requests, but each code also needs the reveal it does
        // not know: the codes it can compute without it are version-2 codes, which differ from what the screens show.
        val o = offer()
        val transcript = bytes(str(obj(enroll()["request"])["transcript"]))
        val shown = Enrollment.verificationCode(transcript, reveal())
        val guesses = (0 until 64).map { Enrollment.verificationCode(transcript, ByteArray(32) { b -> (it * 31 + b).toByte() }) }
        assertTrue(guesses.count { it == shown } <= 1)
        // The inviter refuses a version-2 body (a released build, or a grinder without the reveal step) for a
        // version-2 offer with update-needed, and sends no reveal for it.
        val legacy = PairingOffer(
            1, o.offerId, o.groupId, o.endpoint, o.inviterDeviceId, o.inviterSigningPublic, o.inviterExchangePublic,
            o.certificateFingerprint, o.expiresAt, o.transcriptNonce, o.pairingSecret, o.code,
        )
        val oldBody = Enrollment.buildRequest(legacy, identity("B"), "Pixel", null, SystemRandomSource(), FixedClock(int(enroll()["now"])))
        val e = assertFailsWith<PairingException> { Enrollment.openRequest(inviterOffer(), identity("A"), oldBody) }
        assertEquals(PairingException.Kind.MALFORMED, e.kind)
        assertTrue(e.detail.contains("needs an update"), e.detail)
    }

    @Test
    fun a_version_1_offer_keeps_the_old_flow() {
        val v1 = PairingOffer.parseQr(String(Vectors.sync("lan/qr_payload.txt").readBytes(), Charsets.UTF_8))
        assertEquals(1L, v1.version)
        assertEquals(Enrollment.LEGACY_VERSION, Enrollment.version(v1))
        val raw = Enrollment.buildRequest(v1, identity("B"), "Pixel", null, SystemRandomSource(), FixedClock(1790000030))
        val r = Enrollment.openRequest(v1, identity("A"), raw)
        assertEquals(JsonValue.Int(2), obj(CanonicalJson.parse(r.body))["version"])
        assertEquals(Enrollment.verificationCode(v1, identity("B"), null, "Pixel"), r.code)
    }
}
