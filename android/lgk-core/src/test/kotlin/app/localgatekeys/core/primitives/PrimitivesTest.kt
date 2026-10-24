package app.localgatekeys.core.primitives

import app.localgatekeys.core.support.Vectors
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PrimitivesTest {
    private fun b(s: String) = s.toByteArray(Charsets.UTF_8)

    @Test fun base64_canonical_and_noncanonical() {
        assertEquals("", Base64Std.encode(ByteArray(0)))
        assertEquals("Zm9vYmFy", Base64Std.encode(b("foobar")))
        for ((s, v) in listOf("" to "", "Zg==" to "f", "Zm8=" to "fo", "Zm9v" to "foo")) {
            assertContentEquals(b(v), Base64Std.decodeStrict(s))
        }
        for (bad in listOf("Zh==", "Zm9=", "Zg=", "Zg", "Zm9v\n", " Zm9v", "Zg==Zg==", "Z===", "Zm9v====", "Zm-v", "Zm_v", "Zm9", "=Zg=", "Zg=A")) {
            assertFailsWith<Base64Exception>(bad) { Base64Std.decodeStrict(bad) }
        }
        assertContentEquals(byteArrayOf(0xFB.toByte(), 0xFF.toByte(), 0xBF.toByte()), Base64Std.decodeStrict("+/+/"))
    }

    @Test fun strict_base64_rejects_spare_bits_and_missing_padding() {
        // java.util.Base64 accepts all of these; the strict decoder must not.
        for (bad in listOf("Zh==", "Zm9=", "Zg", "Zm8", "Zg=")) {
            assertFailsWith<Base64Exception>(bad) { Base64Std.decodeStrict(bad) }
        }
        for (bad in listOf("-_-_AR", "AR", "Zh", "AAB")) {
            assertFailsWith<Base64Exception>(bad) { Base64Url.decodeNoPadStrict(bad) }
        }
    }

    @Test fun base64url_nopad() {
        val raw = byteArrayOf(0xFB.toByte(), 0xFF.toByte(), 0xBF.toByte(), 0x01)
        assertEquals("-_-_AQ", Base64Url.encodeNoPad(raw))
        assertContentEquals(raw, Base64Url.decodeNoPadStrict("-_-_AQ"))
        assertContentEquals(ByteArray(0), Base64Url.decodeNoPadStrict(""))
        for (bad in listOf("-_-_AR", "-_-_AQ==", "+/+/", "A", "AAAAA", "Zm 9v", "Zh")) {
            assertFailsWith<Base64Exception>(bad) { Base64Url.decodeNoPadStrict(bad) }
        }
    }

    @Test fun base64url_lenient_matches_desktop() {
        val raw = byteArrayOf(0xFB.toByte(), 0xFF.toByte(), 0xBF.toByte(), 0x01)
        assertContentEquals(raw, Base64Url.decodeLenient("-_-_AQ", 64))
        // Spare bits are ignored, as Python's urlsafe_b64decode does.
        assertContentEquals(raw, Base64Url.decodeLenient("-_-_AR", 64))
        assertContentEquals(ByteArray(0), Base64Url.decodeLenient("", 64))
        assertNull(Base64Url.decodeLenient("A", 64))
        assertNull(Base64Url.decodeLenient("+/+/", 64))
        assertNull(Base64Url.decodeLenient("AAAA", 2))
        assertContentEquals(ByteArray(3), Base64Url.decodeLenient("AAAA", 3))
        assertNull(Base64Url.decodeLenient("AA==", 64))
    }

    @Test fun hex_round_trip() {
        assertEquals("00ff10ab", Hex.lower(byteArrayOf(0, -1, 0x10, 0xAB.toByte())))
        assertContentEquals(byteArrayOf(0, -1, 0x10, 0xAB.toByte()), Hex.decode("00FF10ab"))
        assertFailsWith<IllegalArgumentException> { Hex.decode("abc") }
        assertFailsWith<IllegalArgumentException> { Hex.decode("zz") }
    }

    @Test fun identifier_table() {
        val valid = listOf("a", "A.b_c:d-e", "11111111-aaaa-4000-8000-000000000001", "a".repeat(128))
        for (v in valid) assertTrue(Identifier.isValid(v), v)
        val invalid = listOf("", "a".repeat(129), "a b", "é", "a/b", "a\n", "aＡ")
        for (v in invalid) assertFalse(Identifier.isValid(v), v)
        for (v in listOf("dev1", "my.device", "COMX", "CON1", "a-b_c")) assertTrue(Identifier.isSafeDeviceFile(v), v)
        for (v in listOf("a:b", ".hidden", "trail.", "con", "Nul", "COM0", "lpt0", "LPT9.txt", "com1.x.y", "aux", "bad id", "")) {
            assertFalse(Identifier.isSafeDeviceFile(v), v)
        }
    }

    @Test fun scalars_count_compare_truncate_prefix() {
        val emoji = "a😀b" // a, U+1F600, b
        assertEquals(3, Scalars.count(emoji))
        assertEquals("a😀", Scalars.truncate(emoji, 2))
        assertEquals(emoji, Scalars.truncate(emoji, 3))
        assertEquals(emoji, Scalars.truncate(emoji, 10))
        assertEquals("", Scalars.truncate(emoji, 0))
        // U+FF5E (BMP) sorts below U+1F600 by code point, but above its high surrogate in UTF-16.
        assertTrue(Scalars.compare("～", "😀") < 0)
        assertTrue("～".compareTo("😀") > 0)
        assertEquals(0, Scalars.compare("abc", "abc"))
        assertTrue(Scalars.compare("ab", "abc") < 0)
        assertTrue(Scalars.compare("b", "abc") > 0)
        assertTrue(Scalars.hasPrefix(emoji, "a😀"))
        assertFalse(Scalars.hasPrefix(emoji, "a\uD83D"))
        assertTrue(Scalars.hasPrefix("abc", ""))
    }

    @Test fun uuid5_known_and_conflict_copies() {
        assertEquals("7af94e2b-4dd9-50f0-9c9a-8a48519bdef0", UUID5.make(UUID5.namespaceUrl, "python.org").toString())
        val merge = Vectors.json(Vectors.sync("expected_merge.json"))
        val copies = merge.obj().fields.getValue("conflict_copies").arr()
        assertTrue(copies.isNotEmpty())
        for (c in copies) {
            val o = c.obj().fields
            assertEquals(
                o.getValue("copy_id").str(),
                UUID5.conflictCopyId(o.getValue("original_id").str(), o.getValue("content_digest").str()),
            )
        }
        val ns = UUID5.make(UUID5.namespaceUrl, "lgk-item:note-1")
        assertEquals(UUID5.make(ns, "lgk-copy:ab").toString(), UUID5.conflictCopyId("note-1", "ab"))
        // Hyphenated UUID ids (any case) are used as the namespace directly.
        val id = "11111111-AAAA-4000-8000-000000000001"
        assertEquals(UUID5.make(UUID.fromString(id), "lgk-copy:ab").toString(), UUID5.conflictCopyId(id, "ab"))
    }

    @Test fun hkdf_and_gcm() {
        val okm = CryptoBox.hkdf(ByteArray(22) { 0x0b }, Vectors.hex("000102030405060708090a0b0c"), Vectors.hex("f0f1f2f3f4f5f6f7f8f9"), 42)
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", Vectors.hexString(okm))
        val key = ByteArray(32) { 7 }
        val nonce = ByteArray(12) { 9 }
        val ct = CryptoBox.sealGcm(key, nonce, b("hello"), byteArrayOf(1, 2))
        assertEquals(5 + 16, ct.size)
        assertContentEquals(b("hello"), CryptoBox.openGcm(key, nonce, ct, byteArrayOf(1, 2)))
        assertEquals(
            CryptoBoxException.Kind.AUTHENTICATION_FAILED,
            assertFailsWith<CryptoBoxException> { CryptoBox.openGcm(key, nonce, ct, byteArrayOf(1, 3)) }.kind,
        )
        val t = ct.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals(
            CryptoBoxException.Kind.AUTHENTICATION_FAILED,
            assertFailsWith<CryptoBoxException> { CryptoBox.openGcm(key, nonce, t, byteArrayOf(1, 2)) }.kind,
        )
        assertEquals(
            CryptoBoxException.Kind.AUTHENTICATION_FAILED,
            assertFailsWith<CryptoBoxException> { CryptoBox.openGcm(key, nonce, byteArrayOf(1, 2), ByteArray(0)) }.kind,
        )
        assertEquals(
            CryptoBoxException.Kind.BAD_KEY_OR_NONCE,
            assertFailsWith<CryptoBoxException> { CryptoBox.sealGcm(byteArrayOf(1), nonce, ByteArray(0), ByteArray(0)) }.kind,
        )
        assertEquals(
            CryptoBoxException.Kind.BAD_KEY_OR_NONCE,
            assertFailsWith<CryptoBoxException> { CryptoBox.openGcm(key, ByteArray(8), ct, byteArrayOf(1, 2)) }.kind,
        )
    }

    @Test fun ed25519_rfc8032_vector() {
        // RFC 8032 section 7.1, test 1 (empty message).
        val seed = Vectors.hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        val pub = Ed25519.publicKey(seed)
        assertEquals("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", Vectors.hexString(pub))
        val sig = Ed25519.sign(seed, ByteArray(0))
        assertEquals(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            Vectors.hexString(sig),
        )
        assertTrue(Ed25519.verify(sig, ByteArray(0), pub))
        assertFalse(Ed25519.verify(sig, b("x"), pub))
        assertFalse(Ed25519.verify(sig.copyOf(63), ByteArray(0), pub))
        assertFalse(Ed25519.verify(sig, ByteArray(0), pub.copyOf(31)))
    }

    @Test fun x25519_rfc7748_vector() {
        val a = Vectors.hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val bPriv = Vectors.hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val aPub = X25519.publicKey(a)
        val bPub = X25519.publicKey(bPriv)
        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", Vectors.hexString(aPub))
        assertEquals("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", Vectors.hexString(bPub))
        val shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        assertEquals(shared, Vectors.hexString(X25519.agree(a, bPub)))
        assertEquals(shared, Vectors.hexString(X25519.agree(bPriv, aPub)))
    }

    @Test fun x25519_rejects_all_zero_shared_secret() {
        val priv = ByteArray(32) { 5 }
        // Small-order points yield an all-zero shared secret.
        val zero = ByteArray(32)
        assertFailsWith<IllegalArgumentException> { X25519.agree(priv, zero) }
        val order8 = Vectors.hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
        assertFailsWith<IllegalArgumentException> { X25519.agree(priv, order8) }
        assertFailsWith<IllegalArgumentException> { X25519.agree(priv, ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { X25519.agree(ByteArray(31), zero) }
    }

    @Test fun system_sources_work() {
        val r = SystemRandomSource()
        assertEquals(16, r.bytes(16).size)
        assertEquals(0, r.bytes(0).size)
        assertFalse(r.bytes(32).all { it == 0.toByte() })
        assertTrue(SystemClock().now > 1_700_000_000L)
    }
}
