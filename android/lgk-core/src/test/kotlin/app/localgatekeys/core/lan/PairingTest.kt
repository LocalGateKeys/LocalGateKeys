package app.localgatekeys.core.lan

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Base64Url
import app.localgatekeys.core.support.FixedClock
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
import kotlin.test.assertTrue

/** Port of the QR, enrollment and LAN-address parts of Swift `LanTests` (session/frame/message/client parts: Task 10). */
class PairingTest {
    private val groupId = "5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64"

    private fun obj(v: JsonValue?): Map<String, JsonValue> = (v as? JsonValue.Obj)?.fields ?: emptyMap()
    private fun arr(v: JsonValue?): List<JsonValue> = (v as? JsonValue.Arr)?.items ?: emptyList()
    private fun str(v: JsonValue?): String = (v as? JsonValue.Str)?.v ?: ""
    private fun bytes(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)
    private fun lanFile(name: String): File = Vectors.sync("lan/$name")
    private fun vec(name: String): Map<String, JsonValue> = obj(Vectors.json(lanFile(name)))
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

    private fun lan(): Map<String, JsonValue> = vec("expected_lan.json")
    private fun qrText(): String = String(lanFile("qr_payload.txt").readBytes(), Charsets.UTF_8)
    private fun offer(): PairingOffer = PairingOffer.parseQr(qrText())
    private fun groupKey(): GroupKey = GroupKey(groupId, 1, Vectors.hex(str(obj(lan()["reply"])["key_hex"])))

    private fun kind(block: () -> Unit): PairingException.Kind = assertFailsWith<PairingException> { block() }.kind

    // ---- QR ----

    @Test
    fun qr_payload_parses_to_expected_offer() {
        val o = offer()
        assertEquals(lan()["offer_bundle"], o.bundleJson)
        assertEquals(LanEndpoint("192.168.1.20", 48201), o.endpoint)
        assertEquals(o.certificateFingerprint, o.inviterPeer.fingerprint)
        val text = qrText()
        assertEquals(str(lan()["qr_payload"]), text)
        for (bad in listOf("lgk-pairx" + text.drop(9), text + "=", text + "A", "lgk-pair:", text.drop(9))) {
            assertEquals(PairingException.Kind.MALFORMED, kind { PairingOffer.parseQr(bad) }, bad)
        }
        // Non-canonical JSON (whitespace) and an unknown key (ignored, as on the desktop).
        val bundle = obj(lan()["offer_bundle"]).toMutableMap()
        val spaced = bytes(" ") + canon(bundle)
        assertEquals(PairingException.Kind.MALFORMED, kind { PairingOffer.parseQr("lgk-pair:" + Base64Url.encodeNoPad(spaced)) })
        bundle["zz_future"] = JsonValue.Int(3)
        assertEquals(o, PairingOffer.parseQr("lgk-pair:" + Base64Url.encodeNoPad(canon(bundle))))
        bundle["expires_at"] = JsonValue.Float(1790000120.0)
        assertEquals(PairingException.Kind.MALFORMED, kind { PairingOffer.parseQr("lgk-pair:" + Base64Url.encodeNoPad(canon(bundle))) })
    }

    @Test
    fun qr_rejections_use_the_swift_checks() {
        val text = qrText()
        // Too long: more than 1200 code points.
        assertEquals(PairingException.Kind.MALFORMED, kind { PairingOffer.parseQr("lgk-pair:" + "A".repeat(PairingOffer.MAX_QR_PAYLOAD)) })
        // Non-ASCII body and a body length that is 1 mod 4 are malformed, never another exception type.
        assertEquals(PairingException.Kind.MALFORMED, kind { PairingOffer.parseQr("lgk-pair:éééé") })
        assertEquals(PairingException.Kind.MALFORMED, kind { PairingOffer.parseQr("lgk-pair:AAAAA") })
        // Bundle field checks.
        val good = obj(lan()["offer_bundle"])
        fun with(key: String, v: JsonValue?): Map<String, JsonValue> =
            good.toMutableMap().also { if (v == null) it.remove(key) else it[key] = v }
        fun parse(m: Map<String, JsonValue>) = PairingOffer.fromBundle(JsonValue.Obj(m))
        assertEquals(PairingException.Kind.MALFORMED, kind { parse(with("endpoint", null)) })
        assertEquals(PairingException.Kind.MALFORMED, kind { parse(with("code", JsonValue.Str("1234567"))) })
        assertEquals(PairingException.Kind.MALFORMED, kind { parse(with("code", JsonValue.Str("1234567a"))) })
        assertEquals(PairingException.Kind.MALFORMED, kind { parse(with("expires_at", JsonValue.Int(0))) })
        assertEquals(PairingException.Kind.MALFORMED, kind { parse(with("expires_at", JsonValue.Int(1L shl 53))) })
        assertEquals(PairingException.Kind.MALFORMED, kind { parse(with("certificate_fingerprint", JsonValue.Str("A".repeat(64)))) })
        assertEquals(PairingException.Kind.MALFORMED, kind { parse(with("version", JsonValue.Str("1"))) })
        assertEquals(1L, parse(with("version", null)).version)
        assertEquals(PairingException.Kind.MALFORMED, kind { parse(with("transcript_nonce", JsonValue.Str(Base64Std.encode(ByteArray(31))))) })
        assertEquals(PairingException.Kind.MALFORMED, kind { PairingOffer.fromBundle(JsonValue.Str(text)) })
        val ep = obj(good["endpoint"])
        assertEquals(
            PairingException.Kind.MALFORMED,
            kind { parse(with("endpoint", JsonValue.Obj(ep + ("host" to JsonValue.Str("8.8.8.8"))))) },
        )
    }

    // ---- endpoints ----

    @Test
    fun lan_endpoint_validates_and_normalises() {
        assertEquals("fe80::1", LanEndpoint("FE80:0:0:0:0:0:0:0001", 1).host)
        assertEquals(PairingException.Kind.MALFORMED, kind { LanEndpoint("8.8.8.8", 80) })
        assertEquals(PairingException.Kind.MALFORMED, kind { LanEndpoint("192.168.1.1", 0) })
        assertEquals(PairingException.Kind.MALFORMED, kind { LanEndpoint("192.168.1.1", 65536) })
        assertEquals(LanEndpoint("192.168.1.1", 65535), LanEndpoint("192.168.1.1", 65535))
        assertNotEquals(LanEndpoint("192.168.1.1", 1), LanEndpoint("192.168.1.1", 2))
    }

    // ---- enrollment ----

    private class Case(
        val file: String,
        val reply: String,
        val req: Map<String, JsonValue>,
        val rep: Map<String, JsonValue>,
        val endpoint: LanEndpoint?,
    )

    private fun cases(): List<Case> {
        val x = lan()
        return listOf(
            Case("enroll_request.bin", "enroll_reply.bin", obj(x["request"]), obj(x["reply"]), LanEndpoint("192.168.1.31", 48202)),
            Case("enroll_request_no_endpoint.bin", "enroll_reply_no_endpoint.bin", obj(x["request_no_endpoint"]), obj(x["reply_no_endpoint"]), null),
        )
    }

    private fun startsWith(a: ByteArray, p: ByteArray) = a.size >= p.size && a.copyOf(p.size).contentEquals(p)

    @Test
    fun enrollment_request_vector_opens_and_verifies() {
        val o = offer()
        val a = identity("A")
        for (c in cases()) {
            val raw = lanFile(c.file).readBytes()
            assertTrue(startsWith(raw, Enrollment.REQUEST_MAGIC))
            val r = Enrollment.openRequest(o, a, raw) // MAC and the vector's signature verified inside
            assertContentEquals(bytes(str(c.req["plaintext"])), r.body)
            assertContentEquals(bytes(str(c.req["transcript"])), r.transcript)
            assertEquals(str(c.req["transcript_sha256_hex"]), sha(r.transcript))
            assertEquals(c.endpoint, r.endpoint)
            assertEquals(identity("B").deviceId, r.deviceId)
            val bad = raw.copyOf()
            bad[bad.size - 5] = (bad[bad.size - 5].toInt() xor 1).toByte()
            assertFailsWith<PairingException> { Enrollment.openRequest(o, a, bad) }
        }
    }

    @Test
    fun enrollment_request_built_with_injected_randomness() {
        val o = offer()
        val a = identity("A")
        val b = identity("B")
        for (c in cases()) {
            val random = QueueRandom(listOf(Vectors.hex(str(c.req["ephemeral_private_hex"])), Base64Std.decodeStrict(str(c.req["nonce_b64"]))))
            val raw = Enrollment.buildRequest(o, b, c.endpoint, random, FixedClock(1790000030))
            assertTrue(random.isEmpty)
            val vector = lanFile(c.file).readBytes()
            // Ed25519 here is deterministic (RFC 8032), so the whole request is byte-identical.
            assertContentEquals(vector, raw)
            val mine = obj(CanonicalJson.parse(raw.copyOfRange(Enrollment.REQUEST_MAGIC.size, raw.size)))
            assertContentEquals(bytes(str(c.req["aad"])), canon(mapOf("eph" to mine["eph"]!!, "offer_id" to mine["offer_id"]!!)))
            val r = Enrollment.openRequest(o, a, raw)
            val body = obj(CanonicalJson.parse(r.body)).toMutableMap()
            val want = obj(CanonicalJson.parse(bytes(str(c.req["plaintext"])))).toMutableMap()
            body.remove("signature")
            want.remove("signature")
            assertEquals(want, body)
            assertContentEquals(bytes(str(c.req["transcript"])), r.transcript)
        }
        assertEquals(
            PairingException.Kind.EXPIRED,
            kind { Enrollment.buildRequest(o, b, null, QueueRandom(emptyList()), FixedClock(1790000120)) },
        )
        assertEquals(
            PairingException.Kind.AUTHENTICATION,
            kind { Enrollment.buildRequest(o, a, null, QueueRandom(emptyList()), FixedClock(1790000030)) },
        )
        assertEquals(
            PairingException.Kind.MALFORMED,
            kind { Enrollment.buildRequest(o, b, null, QueueRandom(emptyList()), FixedClock(-1)) },
        )
    }

    @Test
    fun enrollment_request_checks_framing_and_inviter_key() {
        val o = offer()
        val a = identity("A")
        val raw = lanFile("enroll_request.bin").readBytes()
        assertEquals(PairingException.Kind.MALFORMED, kind { Enrollment.openRequest(o, a, Enrollment.REQUEST_MAGIC) })
        assertEquals(PairingException.Kind.MALFORMED, kind { Enrollment.openRequest(o, a, raw.copyOfRange(1, raw.size)) })
        assertEquals(PairingException.Kind.MALFORMED, kind { Enrollment.openRequest(o, a, raw + ByteArray(Enrollment.MAX_BYTES)) })
        // Opened with the wrong inviter key: authentication, not malformed.
        assertEquals(PairingException.Kind.AUTHENTICATION, kind { Enrollment.openRequest(o, identity("C"), raw) })
    }

    @Test
    fun enrollment_reply_opens_to_epoch1_key() {
        val o = offer()
        val b = identity("B")
        val gk = groupKey()
        for (c in cases()) {
            val raw = lanFile(c.reply).readBytes()
            assertEquals(gk, Enrollment.openReply(o, b, raw, c.endpoint))
            assertEquals(str(c.rep["key_hex"]), Vectors.hexString(gk.key))
            // The reply is bound to the announced endpoint.
            val other = if (c.endpoint == null) LanEndpoint("192.168.1.31", 48202) else null
            assertFailsWith<PairingException> { Enrollment.openReply(o, b, raw, other) }
            assertFailsWith<PairingException> { Enrollment.openReply(o, identity("C"), raw, c.endpoint) }
        }
        val full = assertFailsWith<PairingException> { Enrollment.openReply(o, b, Enrollment.REFUSED_MAGIC + bytes("{\"reason\":\"full\"}")) }
        assertEquals(PairingException.Kind.REFUSED, full.kind)
        assertEquals("full", full.detail)
        val unknown = assertFailsWith<PairingException> { Enrollment.openReply(o, b, Enrollment.REFUSED_MAGIC + bytes("{\"reason\":\"x\"}")) }
        assertEquals(PairingException.Kind.REFUSED, unknown.kind)
        assertEquals("refused", unknown.detail)
        val junk = assertFailsWith<PairingException> { Enrollment.openReply(o, b, Enrollment.REFUSED_MAGIC + bytes("not json")) }
        assertEquals("refused", junk.detail)
        assertEquals(PairingException.Kind.MALFORMED, kind { Enrollment.openReply(o, b, Enrollment.REPLY_MAGIC + bytes("{}")) })
        val f = obj(lan()["framing"])
        assertEquals(str(f["request_magic_hex"]), Vectors.hexString(Enrollment.REQUEST_MAGIC))
        assertEquals(str(f["reply_magic_hex"]), Vectors.hexString(Enrollment.REPLY_MAGIC))
        assertEquals(str(f["refused_magic_hex"]), Vectors.hexString(Enrollment.REFUSED_MAGIC))
    }

    // ---- LAN addresses ----

    @Test
    fun lan_address_table() {
        val r = vec("lan_ranges.json")
        assertEquals(arr(r["networks"]).map { str(it) }, LanAddress.networks)
        val cases = arr(r["cases"]).map { obj(it) }
        assertEquals(19, cases.size)
        for (c in cases) {
            assertEquals(c["lan"] == JsonValue.Bool(true), LanAddress.isLan(str(c["address"])), str(c["address"]))
        }
        assertFalse(LanAddress.isLan("192.168.01.1"))
        assertFalse(LanAddress.isLan("fe80::1::2"))
        assertEquals("fe80::1", LanAddress.normalisedLan("FE80:0:0:0:0:0:0:0001"))
        assertEquals("fd00:0:0:1::1", LanAddress.normalisedLan("fd00:0:0:1:0:0:0:1"))
        assertEquals("fd00::1:1:0:0:1", LanAddress.normalisedLan("fd00:0:0:1:1:0:0:1")) // first longest run
        assertEquals("::1", LanAddress.normalisedLan("::1"))
    }

    @Test
    fun lan_address_rejections() {
        for (bad in listOf("fe80::1%eth0", "::ffff:192.168.1.1", "", "1.2.3", "192.168.1.1 ", "１０.0.0.1", "10.0.0.256", "::", "8.8.8.8")) {
            assertFalse(LanAddress.isLan(bad), bad)
        }
        assertEquals(null, LanAddress.parse("fe80::1%eth0"))
        assertTrue(LanAddress.parse("10.0.0.1") is LanAddress.Parsed.V4)
        assertTrue(LanAddress.parse("fe80::1") is LanAddress.Parsed.V6)
        assertEquals(LanAddress.parse("10.0.0.1"), LanAddress.parse("10.0.0.1"))
    }
}
