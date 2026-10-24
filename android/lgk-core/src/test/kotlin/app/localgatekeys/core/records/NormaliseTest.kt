package app.localgatekeys.core.records

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail

/** Port of Swift `NormaliseTests`: normalise/entries.json and items.json (README "Normalisation tables"). */
class NormaliseTest {
    private val phoneKinds: Set<String> = Normalise.phoneEntryKinds + Normalise.phoneItemKinds - "passkey"

    /** Kinds the desktop does not know at all: the phone rejects them like the desktop does. */
    private val unknownKinds = setOf("spaceship")

    private fun cases(file: String): List<Map<String, JsonValue>> {
        val rows = Vectors.json(Vectors.sync(file)).obj().fields["cases"]!!.arr()
        assertTrue(rows.isNotEmpty(), file)
        return rows.map { obj(it) }
    }

    private fun canonical(v: JsonValue): String = String(CanonicalJson.encode(v, Dialect.UTF8), Charsets.UTF_8)

    private fun run(file: String): Int {
        var checked = 0
        for (c in cases(file)) {
            val name = str(c["name"])!!
            val ns = Namespace.fromWire(str(c["ns"])!!)!!
            val input = c["input"]!!
            val kind = str(obj(input)["kind"]) ?: ""
            val result = runCatching { Normalise.normalForm(ns, input) }
            if (kind !in phoneKinds && kind !in unknownKinds) {
                // Never normalised on the phone: refused so the caller passes the record through.
                val e = result.exceptionOrNull() as? NormaliseException ?: fail("$name: $result")
                assertEquals(NormaliseException.Kind.NOT_PHONE_KIND, e.kind, name)
                continue
            }
            checked += 1
            if ("idna" in name) {
                val e = result.exceptionOrNull() as? NormaliseException ?: fail("$name: $result")
                assertEquals(NormaliseException.Kind.NEEDS_PUNYCODE, e.kind, name)
                continue
            }
            if (c["error"] == JsonValue.Str("rejected")) {
                val e = result.exceptionOrNull() as? NormaliseException ?: fail("$name: $result")
                assertEquals(NormaliseException.Kind.REJECTED, e.kind, "$name: ${e.message}")
                continue
            }
            assertEquals(JsonValue.Null, c["error"], name)
            val got = result.getOrElse { fail("$name: $it") }
            assertEquals(canonical(c["output"]!!), canonical(got), name)
            if (c["already_normal"] == JsonValue.Bool(true)) assertEquals(canonical(input), canonical(got), name)
            // Normal form is a fixed point.
            assertEquals(canonical(got), canonical(Normalise.normalForm(ns, got)), name)
        }
        return checked
    }

    @Test
    fun entries_vectors() {
        assertEquals(53, run("normalise/entries.json")) // 53 of 57 rows; the 4 desktop rows are refused
    }

    @Test
    fun items_vectors() {
        assertEquals(62, run("normalise/items.json")) // all 62 rows
    }

    @Test
    fun origin_canonicalize() {
        assertEquals("https://example.com", Origin.canonicalize("HTTPS://Example.COM:443/"))
        assertEquals("https://[2001:db8::1]:8443", Origin.canonicalize("https://[2001:DB8::1]:8443"))
        assertEquals("http://127.0.0.1:3000", Origin.canonicalize("http://127.0.0.1:3000"))
        assertEquals("http://[::1]", Origin.canonicalize("http://[::1]"))
        assertEquals("https://a.example.com", Origin.canonicalize("https://a.example.com."))
        assertEquals(
            OriginException.Kind.NEEDS_PUNYCODE,
            assertFailsWith<OriginException> { Origin.canonicalize("https://bücher.example") }.kind,
        )
        val bad = listOf(
            "", "ftp://example.com", "https://user@example.com", "https://example.com?q", "https://example.com#f",
            "https://example.com/x", "http://example.com", "https://", "https://a..b.com", "https://example.com:99999",
            "https://example.com:8x", "https://[example.com]", "https://[::1", "a".repeat(2049),
            "https://" + "a".repeat(64) + ".com",
            // Audit 2026-10-24: forbidden host code points, whitespace, bracket tricks, zone ids, mapped addresses.
            "https://a.example.com..", "https://paypal.com\\.evil.com", "https://a%2fb.com", "https://a^b.com",
            "https://example.com ", " https://example.com", "https://evil.com[::1]", "https://[::1].:8443",
            "https://[v1.abc]", "https://[::1%25eth0]", "https://[::ffff:127.0.0.1]",
        )
        for (b in bad) {
            assertEquals(OriginException.Kind.INVALID, assertFailsWith<OriginException>(b) { Origin.canonicalize(b) }.kind, b)
        }
    }

    @Test
    fun card_payload_normalises() {
        val rec = mapOf(
            "id" to JsonValue.Str("88888888-AAAA-4000-8000-000000000008"), "kind" to JsonValue.Str("card"),
            "title" to JsonValue.Str("Visa"), "created_at" to JsonValue.Int(1), "updated_at" to JsonValue.Int(2),
            "tags" to JsonValue.Arr(listOf(JsonValue.Str(" Work "), JsonValue.Str("work"))),
            "payload" to JsonValue.Obj(
                mapOf(
                    "number" to JsonValue.Str("4111 1111-1111 1111"), "expiry" to JsonValue.Str("3/2031"),
                    "cvv" to JsonValue.Str(" 123 "), "template_id" to JsonValue.Null,
                ),
            ),
        )
        val out = Normalise.normalForm(Namespace.ITEM, JsonValue.Obj(rec))
        val p = obj(obj(out)["payload"])
        assertEquals(JsonValue.Str("4111111111111111"), p["number"])
        assertEquals(JsonValue.Str("visa"), p["brand"])
        assertEquals(JsonValue.Str("1111"), p["last4"])
        assertEquals(JsonValue.Str("03/31"), p["expiry"])
        assertEquals(JsonValue.Str("123"), p["cvv"])
        assertEquals(JsonValue.Arr(listOf(JsonValue.Str("Work"))), obj(out)["tags"])
        // NFC and NFD spellings are different tags (Python compares code points).
        val twin = rec.toMutableMap()
        twin["tags"] = JsonValue.Arr(listOf(JsonValue.Str("\u00e9"), JsonValue.Str("e\u0301"), JsonValue.Str("\u00c9")))
        val tw = Normalise.normalForm(Namespace.ITEM, JsonValue.Obj(twin))
        assertEquals(
            canonical(JsonValue.Arr(listOf(JsonValue.Str("\u00e9"), JsonValue.Str("e\u0301")))),
            canonical(obj(tw)["tags"]!!),
        )
        // Web URL rows that differ only by normalisation form are both kept.
        val rows = Normalise.webURLs(
            JsonValue.Arr(
                listOf(
                    JsonValue.Obj(mapOf("url" to JsonValue.Str("https://a.example/\u00e9"), "match" to JsonValue.Str("starts_with"))),
                    JsonValue.Obj(mapOf("url" to JsonValue.Str("https://a.example/e\u0301"), "match" to JsonValue.Str("starts_with"))),
                ),
            ),
        )
        assertEquals(2, rows.arr().size)
        val bad = rec.toMutableMap()
        bad["payload"] = JsonValue.Obj(mapOf("number" to JsonValue.Str("4111111111111112")))
        val e = assertFailsWith<NormaliseException> { Normalise.normalForm(Namespace.ITEM, JsonValue.Obj(bad)) }
        assertEquals(NormaliseException.Kind.REJECTED, e.kind)
    }

    @Test
    fun ssh_public_key_with_unknown_base64_character_is_rejected() {
        fun key(pub: String) = JsonValue.Obj(
            mapOf(
                "id" to JsonValue.Str("99999999-AAAA-4000-8000-000000000009"), "kind" to JsonValue.Str("ssh_key"),
                "title" to JsonValue.Str("k"), "created_at" to JsonValue.Int(1), "updated_at" to JsonValue.Int(2),
                "payload" to JsonValue.Obj(mapOf("public_key" to JsonValue.Str(pub))),
            ),
        )
        // Same length and padding rules as a valid body; only the character differs.
        val ok = Normalise.normalForm(Namespace.ITEM, key("ssh-ed25519 AAAAAAAA"))
        assertTrue(obj(obj(ok)["payload"])["fingerprint"]!!.str().startsWith("SHA256:"))
        for (bad in listOf("AAAA*AAA", "AAAA-AAA", "AAAA_AAA", "AAAA.AAA")) {
            val e = assertFailsWith<NormaliseException>(bad) { Normalise.normalForm(Namespace.ITEM, key("ssh-ed25519 $bad")) }
            assertEquals(NormaliseException.Kind.REJECTED, e.kind, bad)
        }
    }

    /** Python `str.strip()` whitespace, which differs from Kotlin `trim()` (Kotlin-only check). */
    @Test
    fun py_strip_matches_python_whitespace() {
        assertEquals("a b", PyStrip.strip("\u001c\u0085\u00a0\u2007\u202f\u3000 a b\t\n\u000b\u000c\r\u001f\u2028\u2029\u205f"))
        // U+200B (zero width space) and U+FEFF are not whitespace in Python.
        assertEquals("\u200ba\ufeff", PyStrip.strip("\u200ba\ufeff"))
        assertEquals("", PyStrip.strip(" \u1680 "))
        assertEquals(listOf("a", "b"), PyStrip.split("\u00a0a\u2003b\u001e"))
    }

    /** Desktop `normalize_url` / `origin_of` (Kotlin-only spot checks; the vectors cover them through `urls`). */
    @Test
    fun normalize_url_and_origin_of() {
        assertEquals("https://example.com/a?b=1", Origin.normalizeUrl("HTTPS://Example.com:443/a?b=1#frag"))
        assertEquals("https://example.com/", Origin.normalizeUrl("https://example.com"))
        assertEquals("http://[::1]:8080/x", Origin.normalizeUrl("http://[::1]:8080/x"))
        assertEquals("https://example.com:8443", Origin.originOf("https://example.com:8443/path?q"))
        assertEquals(OriginException.Kind.INVALID, assertFailsWith<OriginException> { Origin.normalizeUrl("https://ex ample.com") }.kind)
        assertEquals(OriginException.Kind.INVALID, assertFailsWith<OriginException> { Origin.normalizeUrl("https://a\u00a0b.com") }.kind)
        assertEquals(OriginException.Kind.NEEDS_PUNYCODE, assertFailsWith<OriginException> { Origin.originOf("https://ü.example/") }.kind)
    }
}
