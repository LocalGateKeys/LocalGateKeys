package app.localgatekeys.core.proof

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.support.Vectors
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.Test
import app.localgatekeys.core.support.assertEq
import app.localgatekeys.core.support.assertTr

class PrivacyProofTest {
    private fun deviceA(): DeviceIdentity {
        val a = ((Vectors.json(Vectors.sync("identities.json")) as JsonValue.Obj).fields["devices"] as JsonValue.Obj).fields["A"] as JsonValue.Obj
        val p = (a.fields["private"] as JsonValue.Obj).fields
        return DeviceIdentity(
            (p["device_id"] as JsonValue.Str).v, Base64Std.decodeStrict((p["signing_private"] as JsonValue.Str).v),
            Base64Std.decodeStrict((p["exchange_private"] as JsonValue.Str).v),
        )
    }

    private val facts = PrivacyProof.Facts("wifi", 2, 0, 120, breachChecks = false, strictOffline = true, updateCheck = true)
    private fun doc() = PrivacyProof.document("2026-11-15T10:00:00Z", "android", "0.5.0", facts, emptyList())

    @Test
    fun signedVerifiesAndTamperFails() {
        val signed = PrivacyProof.sign(doc(), deviceA())
        val bytes = PrivacyProof.encode(signed)
        val v = PrivacyProof.verify(bytes)
        assertEquals(PrivacyProof.Status.VALID, v.status)
        assertEquals(deviceA().deviceId, v.deviceId)
        assertEquals(16, v.fingerprint.length)
        val tampered = signed + ("facts" to PrivacyProof.Facts("off", 2, 0, 120, false, true, true).json())
        assertEquals(PrivacyProof.Status.INVALID, PrivacyProof.verify(PrivacyProof.encode(tampered)).status)
        assertEquals(PrivacyProof.Status.INVALID, PrivacyProof.verify(PrivacyProof.encode(signed + ("extra" to JsonValue.Int(1)))).status)
        assertEquals(PrivacyProof.Status.INVALID, PrivacyProof.verify(PrivacyProof.encode(signed + ("version" to JsonValue.Int(3)))).status)
        val dup = String(bytes, Charsets.UTF_8).replaceFirst("{", "{\"format\":\"x\",")
        assertEquals(PrivacyProof.Status.INVALID, PrivacyProof.verify(dup.toByteArray()).status)
        // Signed without the domain prefix.
        val raw = deviceA().sign(CanonicalJson.encode(JsonValue.Obj(doc()), Dialect.UTF8))
        val sig = (signed["signature"] as JsonValue.Obj).fields + ("value" to JsonValue.Str(Base64Std.encode(raw)))
        assertEquals(PrivacyProof.Status.INVALID, PrivacyProof.verify(PrivacyProof.encode(signed + ("signature" to JsonValue.Obj(sig)))).status)
    }

    @Test
    fun unsignedWhenSyncIsOff() {
        val d = PrivacyProof.sign(doc(), null)
        assertEquals(JsonValue.Null, d["signature"])
        assertEquals(PrivacyProof.Status.UNSIGNED, PrivacyProof.verify(PrivacyProof.encode(d)).status)
        val network = (d["network"] as JsonValue.Obj).fields
        assertEquals(JsonValue.Bool(false), network["available"])
        assertTrue(PrivacyProof.fileName("2026-11-15") == "LocalGateKeys-privacy-proof-2026-11-15.json")
    }

    // MARK: shared vectors (tests/vectors/privacy_proof/)

    private fun obj(v: JsonValue?) = (v as JsonValue.Obj).fields

    @Test
    fun signedVector() {
        val c = obj(Vectors.json(Vectors.optional("privacy_proof/signed.json")))
        val unsigned = obj(c["unsigned_document"])
        val signed = PrivacyProof.sign(unsigned, deviceA())
        val body = LinkedHashMap(signed).also { it["signature"] = JsonValue.Obj(obj(signed["signature"]) - "value") }
        assertEquals(c["signed_body"], JsonValue.Obj(body))
        assertEquals((c["signed_bytes_hex"] as JsonValue.Str).v, Hex.lower(PrivacyProof.signedBytes(signed)))
        assertEquals(c["signature"], signed["signature"])
        assertEquals(c["signed_document"], JsonValue.Obj(signed))
        assertEquals((c["fingerprint"] as JsonValue.Str).v, PrivacyProof.fingerprint(deviceA().signingPublicKey))
        val v = PrivacyProof.verify(PrivacyProof.encode(obj(c["signed_document"])))
        assertEquals(PrivacyProof.Status.VALID, v.status)
        assertEquals((c["device_id"] as JsonValue.Str).v, v.deviceId)
        assertEquals((c["fingerprint"] as JsonValue.Str).v, v.fingerprint)
    }

    @Test
    fun unsignedAndRejectedVectors() {
        val u = Vectors.optional("privacy_proof/unsigned.json")
        val unsigned = obj(Vectors.json(u))
        assertEquals(PrivacyProof.Status.UNSIGNED, PrivacyProof.verify(PrivacyProof.encode(obj(unsigned["document"]))).status)
        val files = File(u.parentFile, "rejected").listFiles { f -> f.name.endsWith(".json") }!!.sortedBy { it.name }
        assertTr("rejected vectors present", files.size >= 8)
        for (f in files) assertEq(f.name, PrivacyProof.Status.INVALID, PrivacyProof.verify(f.readBytes()).status)
    }

    // MARK: strict Ed25519 (contract §5.2)

    @Test
    fun strictEd25519RefusesMalleableAndSmallOrder() {
        val id = deviceA()
        val msg = "abc".toByteArray()
        val sig = id.sign(msg)
        val pub = id.signingPublicKey
        assertTrue(app.localgatekeys.core.primitives.Ed25519.verifyStrict(sig, msg, pub))
        // S + L
        val l = java.math.BigInteger.ONE.shiftLeft(252) + java.math.BigInteger("27742317777372353535851937790883648493")
        val s = java.math.BigInteger(1, sig.copyOfRange(32, 64).reversedArray()) + l
        val sBytes = s.toByteArray().reversedArray().copyOf(32)
        assertTrue(!app.localgatekeys.core.primitives.Ed25519.verifyStrict(sig.copyOfRange(0, 32) + sBytes, msg, pub))
        // Identity R, S = 0 forgery against a small-order key.
        val identity = ByteArray(32).also { it[0] = 1 }
        assertTrue(!app.localgatekeys.core.primitives.Ed25519.verifyStrict(identity + ByteArray(32), msg, identity))
        assertTrue(!app.localgatekeys.core.primitives.Ed25519.verifyStrict(identity + ByteArray(32), msg, pub))
        // Non-canonical key: y >= p.
        val big = ByteArray(32) { 0xff.toByte() }.also { it[31] = 0x7f }
        assertTrue(!app.localgatekeys.core.primitives.Ed25519.verifyStrict(sig, msg, big))
        // x = 0 with the sign bit set (identity with sign bit).
        val negZero = identity.copyOf().also { it[31] = 0x80.toByte() }
        assertTrue(!app.localgatekeys.core.primitives.Ed25519.verifyStrict(sig, msg, negZero))
    }
}
