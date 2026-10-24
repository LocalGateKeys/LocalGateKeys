package app.localgatekeys.core.totp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Port of Swift `TOTPTests`. */
class TotpTest {
    private val seeds = mapOf(
        "SHA1" to "12345678901234567890",
        "SHA256" to "12345678901234567890123456789012",
        "SHA512" to "1234567890123456789012345678901234567890123456789012345678901234",
    )

    private data class Row(val t: Long, val alg: String, val expected: String)

    private val table = listOf(
        Row(59, "SHA1", "94287082"), Row(59, "SHA256", "46119246"), Row(59, "SHA512", "90693936"),
        Row(1111111109, "SHA1", "07081804"), Row(1111111109, "SHA256", "68084774"), Row(1111111109, "SHA512", "25091201"),
        Row(1111111111, "SHA1", "14050471"), Row(1111111111, "SHA256", "67062674"), Row(1111111111, "SHA512", "99943326"),
        Row(1234567890, "SHA1", "89005924"), Row(1234567890, "SHA256", "91819424"), Row(1234567890, "SHA512", "93441116"),
        Row(2000000000, "SHA1", "69279037"), Row(2000000000, "SHA256", "90698825"), Row(2000000000, "SHA512", "38618901"),
        Row(20000000000, "SHA1", "65353130"), Row(20000000000, "SHA256", "77737706"), Row(20000000000, "SHA512", "47863826"),
    )

    private fun b32(s: String): String {
        val alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val out = StringBuilder()
        var acc = 0
        var bits = 0
        for (b in s.toByteArray(Charsets.UTF_8)) {
            acc = (acc shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                out.append(alpha[(acc shr bits) and 31])
            }
            acc = acc and ((1 shl bits) - 1)
        }
        if (bits > 0) out.append(alpha[(acc shl (5 - bits)) and 31])
        return out.toString()
    }

    private fun kind(block: () -> Unit): TotpException.Kind = assertFailsWith<TotpException> { block() }.kind

    @Test
    fun rfc6238_vectors() {
        for (r in table) {
            assertEquals(r.expected, Totp.code(b32(seeds.getValue(r.alg)), r.alg, 8, 30, r.t), "${r.alg} at ${r.t}")
        }
    }

    @Test
    fun six_digit_truncation() {
        assertEquals("287082", Totp.code(b32(seeds.getValue("SHA1")), "SHA1", 6, 30, 59))
    }

    @Test
    fun odd_secrets_match_desktop() {
        fun c(s: String) = Totp.code(s, "SHA1", 6, 30, 59)
        assertEquals("996554", c("JBSWY3DPEHPK3PXP"))
        assertEquals("996554", c("jbswy3dpehpk3pxp"))
        assertEquals("996554", c("  JBSW Y3DP-EHPK\t3PXP\n"))
        assertEquals("996554", Totp.code("JBSWY3DPEHPK3PXP", "sha1", 6, 30, 59))
        val bad = listOf(
            "", "   ", "!!!!", "JBSW Y3DP EHPK 3PXP====", "JBSWY3DPEHPK3PXP=", "JBSWY3DPEHPK3PXP======",
            "JBSWY3DPEHPK3PX=", "GEZDGNA=", "GEZDGNBVGY3TQOJ", "1111111111111111", "A".repeat(4097),
        )
        for (b in bad) assertFailsWith<TotpException>(b) { c(b) }
        val s = "JBSWY3DPEHPK3PXP"
        assertFailsWith<TotpException> { Totp.code(s, "MD5", 6, 30, 0) }
        assertFailsWith<TotpException> { Totp.code(s, "SHA1", 5, 30, 0) }
        assertFailsWith<TotpException> { Totp.code(s, "SHA1", 9, 30, 0) }
        assertFailsWith<TotpException> { Totp.code(s, "SHA1", 6, 14, 0) }
        assertFailsWith<TotpException> { Totp.code(s, "SHA1", 6, 121, 0) }
        assertFailsWith<TotpException> { Totp.code(s, "SHA1", 6, 30, -1) }
        Totp.code(s, "SHA256", 7, 15, 0)
        Totp.code(s, "SHA512", 8, 120, 0)
    }

    @Test
    fun normalize_secret_matches_desktop() {
        assertEquals("JBSWY3DPEHPK3PXP", Totp.normalizeSecret(" jbsw-y3dp ehpk3pxp "))
        assertEquals(TotpException.Kind.SECRET_TOO_SHORT, kind { Totp.normalizeSecret("JBSW") })
        assertEquals(TotpException.Kind.INVALID_BASE32, kind { Totp.normalizeSecret("not base32!") })
        assertEquals(TotpException.Kind.EMPTY_SECRET, kind { Totp.normalizeSecret("  ") })
    }

    @Test
    fun parse_otpauth_uri() {
        val c = Totp.parseOtpauthUri("otpauth://totp/Example:ada?secret=jbswy3dpehpk3pxp&issuer=Example&algorithm=sha256&digits=8&period=60")
        assertEquals(TotpConfig("JBSWY3DPEHPK3PXP", "SHA256", 8, 60), c)
        assertEquals(TotpConfig("JBSWY3DPEHPK3PXP"), Totp.parseOtpauthUri("OTPAUTH://TOTP/x?secret=JBSWY3DPEHPK3PXP"))
        val s = "secret=JBSWY3DPEHPK3PXP"
        assertEquals(TotpException.Kind.NOT_OTPAUTH_URI, kind { Totp.parseOtpauthUri("otpauth://hotp/x?$s") })
        assertEquals(TotpException.Kind.DUPLICATE_PARAMETER, kind { Totp.parseOtpauthUri("otpauth://totp/x?$s&$s") })
        assertEquals(TotpException.Kind.UNSUPPORTED_DIGITS, kind { Totp.parseOtpauthUri("otpauth://totp/x?$s&digits=9") })
        assertEquals(TotpException.Kind.INVALID_PARAMETER, kind { Totp.parseOtpauthUri("otpauth://totp/x?$s&period=-1") })
        assertEquals(TotpException.Kind.UNSUPPORTED_ALGORITHM, kind { Totp.parseOtpauthUri("otpauth://totp/x?$s&algorithm=MD5") })
    }

    @Test
    fun parse_field_keeps_defaults_for_bare_secret() {
        assertNull(Totp.parseField("   "))
        val d = TotpConfig("", "SHA512", 7, 45)
        assertEquals(TotpConfig("JBSWY3DPEHPK3PXP", "SHA512", 7, 45), Totp.parseField("jbswy3dpehpk3pxp", d))
        assertEquals(
            TotpConfig("JBSWY3DPEHPK3PXP", "SHA256", 8, 60),
            Totp.parseField(" otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60\n"),
        )
    }

    @Test
    fun otpauth_matches_python_query_parsing() {
        val base = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"
        assertEquals(TotpException.Kind.INVALID_PARAMETER, kind { Totp.parseOtpauthUri("$base&digits") })
        assertEquals(TotpException.Kind.DUPLICATE_PARAMETER, kind { Totp.parseOtpauthUri("$base&secret") })
        assertEquals(
            TotpConfig("JBSWY3DPEHPK3PXP", digits = 8),
            Totp.parseOtpauthUri("otpauth://totp/x?secret=JBSW%59%33DPEHPK3PXP&issuer=%ZZ%41&digits=%38"),
        )
        assertEquals(TotpConfig("JBSWY3DPEHPK3PXP"), Totp.parseOtpauthUri("$base#&digits=9"))
        assertEquals(
            TotpConfig("JBSWY3DPEHPK3PXP", digits = 8),
            Totp.parseOtpauthUri("otpauth://to\ttp/x?secret=JBSWY3D\nPEHPK3PXP&digits=8"),
        )
        assertEquals("%ZZA", Totp.pyUnquote("%ZZ%41"))
        assertEquals("é�%4", Totp.pyUnquote("%C3%A9%FF%4"))
    }

    @Test
    fun messages_cover_every_kind() {
        for (k in TotpException.Kind.values()) assertTrue(Totp.message(TotpException(k)).isNotEmpty())
        assertEquals("The 2FA secret is too short.", Totp.message(TotpException(TotpException.Kind.SECRET_TOO_SHORT)))
    }

    @Test
    fun config_to_string_hides_the_secret() {
        val text = TotpConfig(secret = "JBSWY3DPEHPK3PXP").toString()
        assertFalse(text.contains("JBSWY3DPEHPK3PXP"))
    }
}
