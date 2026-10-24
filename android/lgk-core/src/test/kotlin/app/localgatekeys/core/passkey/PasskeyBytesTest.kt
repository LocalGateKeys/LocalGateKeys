package app.localgatekeys.core.passkey

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Url
import app.localgatekeys.core.support.Vectors
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Port of Swift `PasskeyBytesTests`. */
class PasskeyBytesTest {
    private fun list(name: String): List<Map<String, JsonValue>> {
        val rows = Vectors.json(Vectors.sync("passkeys/$name")).arr()
        assertTrue(rows.isNotEmpty(), name)
        return rows.map { it.obj().fields }
    }

    private fun s(v: Map<String, JsonValue>, k: String): String = v.getValue(k).str()

    private fun key(v: Map<String, JsonValue>): PasskeyKey = assertNotNull(PasskeyKey.fromPkcs8B64Url(s(v, "private_key_b64u")))

    private fun p256(): ECParameterSpec {
        val ap = AlgorithmParameters.getInstance("EC")
        ap.init(ECGenParameterSpec("secp256r1"))
        return ap.getParameterSpec(ECParameterSpec::class.java)
    }

    private fun publicKey(x: ByteArray, y: ByteArray): ECPublicKey =
        KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, x), BigInteger(1, y)), p256())) as ECPublicKey

    @Test
    fun aaguid_constant() {
        assertEquals("b7d2a6f01c4e4a5b9e3d5a1f7c2e8d41", Vectors.hexString(Passkey.AAGUID))
        assertEquals(16, Passkey.CREDENTIAL_ID_LENGTH)
    }

    @Test
    fun authenticator_data_matches_vectors() {
        for (v in list("assertion.json")) {
            val ad = Passkey.authenticatorData(s(v, "rp_id"), (v.getValue("user_verified") as JsonValue.Bool).v, null)
            assertEquals(s(v, "authenticator_data_hex"), Vectors.hexString(ad))
        }
        for (v in list("registration.json")) {
            val k = key(v)
            val ad = Passkey.authenticatorData(
                s(v, "rp_id"),
                true,
                Vectors.hex(s(v, "credential_id_hex")) to Passkey.coseEs256Key(k.publicKey),
            )
            assertEquals(s(v, "authenticator_data_hex"), Vectors.hexString(ad))
        }
    }

    @Test
    fun cose_key_matches_vectors() {
        for (v in list("registration.json")) {
            assertEquals(s(v, "cose_key_hex"), Vectors.hexString(Passkey.coseEs256Key(key(v).publicKey)))
        }
    }

    @Test
    fun attestation_object_matches_vectors() {
        for (v in list("registration.json")) {
            val att = Passkey.noneAttestationObject(Vectors.hex(s(v, "authenticator_data_hex")))
            assertEquals(s(v, "attestation_object_hex"), Vectors.hexString(att))
        }
    }

    @Test
    fun signature_verifies_with_vector_public_key() {
        for (v in list("assertion.json")) {
            val k = key(v)
            val pub = publicKey(Vectors.hex(s(v, "public_key_x_hex")), Vectors.hex(s(v, "public_key_y_hex")))
            assertEquals(pub.w, k.publicKey.w)
            val ad = Vectors.hex(s(v, "authenticator_data_hex"))
            val cdh = Vectors.hex(s(v, "client_data_hash_hex"))
            val der = k.sign(ad, cdh)
            fun verify(msg: ByteArray): Boolean {
                val sig = Signature.getInstance("SHA256withECDSA")
                sig.initVerify(pub)
                sig.update(msg)
                return sig.verify(der)
            }
            assertTrue(verify(ad + cdh))
            assertFalse(verify(ad + cdh + byteArrayOf(0)))
        }
    }

    @Test
    fun pkcs8_roundtrip_matches_desktop_encoding() {
        for (v in list("assertion.json") + list("registration.json")) {
            assertEquals(s(v, "private_key_b64u"), key(v).pkcs8B64Url)
        }
        val g = PasskeyKey.generate()
        val back = assertNotNull(PasskeyKey.fromPkcs8B64Url(g.pkcs8B64Url))
        assertEquals(g.publicKey.w, back.publicKey.w)
        assertTrue(g.pkcs8B64Url.startsWith("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg"))
    }

    @Test
    fun rejects_non_p256_key() {
        var checked = 0
        for (r in list("records.json")) {
            val name = s(r, "name")
            if (name != "rs256-import" && name != "garbage-key") continue
            assertEquals(JsonValue.Bool(false), r["usable"])
            val pk = r.getValue("input").obj().fields.getValue("private_key").str()
            assertNull(PasskeyKey.fromPkcs8B64Url(pk), name)
            checked++
        }
        assertEquals(2, checked)
        assertNull(PasskeyKey.fromPkcs8B64Url(""))
        assertNull(PasskeyKey.fromPkcs8B64Url("MIGH+AgEA"))
    }

    @Test
    fun rejects_ed25519_pkcs8() {
        val seed = ByteArray(32) { (it * 7 + 1).toByte() }
        val der = byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20) + seed
        assertNull(PasskeyKey.fromPkcs8B64Url(Base64Url.encodeNoPad(der)))
    }

    @Test
    fun rejects_p384_pkcs8() {
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp384r1"))
        val kp = gen.generateKeyPair()
        assertNull(PasskeyKey.fromPkcs8B64Url(Base64Url.encodeNoPad(kp.private.encoded)))
    }

    @Test
    fun base64url_helpers() {
        val fbff = byteArrayOf(0xfb.toByte(), 0xff.toByte())
        assertEquals("-_8", Base64Url.encodeNoPad(fbff))
        assertContentEquals(fbff, Base64Url.decodeLenient("-_8", 2))
        assertNull(Base64Url.decodeLenient("-_8", 1))
        assertNull(Base64Url.decodeLenient("-_8=", 4))
        assertNull(Base64Url.decodeLenient("abcde", 8))
        assertContentEquals(ByteArray(0), Base64Url.decodeLenient("", 4))
    }

    @Test
    fun sign_rejects_client_data_hash_not_32_bytes() {
        val k = PasskeyKey.generate()
        for (n in listOf(0, 31, 33, 64)) {
            val e = assertFailsWith<PasskeyKeyException>("$n") { k.sign(byteArrayOf(1, 2, 3), ByteArray(n) { 7 }) }
            assertEquals(PasskeyKeyException.Kind.BAD_CLIENT_DATA_HASH, e.kind)
        }
        k.sign(byteArrayOf(1, 2, 3), ByteArray(32) { 7 })
    }

    @Test
    fun authenticator_data_accepts_max_u16_credential_id() {
        val id = ByteArray(0xFFFF) { 1 }
        val ad = Passkey.authenticatorData("example.com", true, id to byteArrayOf(0xA0.toByte()))
        assertContentEquals(byteArrayOf(0xFF.toByte(), 0xFF.toByte()), ad.copyOfRange(53, 55))
        assertFailsWith<IllegalArgumentException> { Passkey.authenticatorData("example.com", true, ByteArray(0x10000) to ByteArray(0)) }
    }

    @Test
    fun cbor_head_widths() {
        fun e(c: Cbor) = Vectors.hexString(c.encoded())
        assertEquals("17", e(Cbor.Integer(23)))
        assertEquals("1818", e(Cbor.Integer(24)))
        assertEquals("19ffff", e(Cbor.Integer(0xFFFF)))
        assertEquals("1a00010000", e(Cbor.Integer(0x10000)))
        assertEquals("1b0000000100000000", e(Cbor.Integer(0x1_0000_0000L)))
        assertEquals("20", e(Cbor.Integer(-1)))
        assertEquals("26", e(Cbor.Integer(-7)))
        assertEquals("3863", e(Cbor.Integer(-100)))
        assertEquals("63666d74", e(Cbor.Text("fmt")))
        assertEquals("420102", e(Cbor.Bytes(byteArrayOf(1, 2))))
        assertEquals("a0", e(Cbor.Mapping(emptyList())))
    }
}
