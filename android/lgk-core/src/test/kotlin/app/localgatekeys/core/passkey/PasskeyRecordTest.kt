package app.localgatekeys.core.passkey

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Url
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.NormaliseException
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/** Port of Swift `PasskeyRecordTests`. */
class PasskeyRecordTest {
    private val itemId = "9a550000-0000-4000-8000-000000000001"

    private fun cases(): List<Map<String, JsonValue>> {
        val rows = Vectors.json(Vectors.sync("passkeys/records.json")).arr()
        assertTrue(rows.isNotEmpty())
        return rows.map { it.obj().fields }
    }

    private fun str(s: String): JsonValue = JsonValue.Str(s)

    private fun item(payload: JsonValue, title: String = "Example (ada)"): JsonValue = JsonValue.Obj(
        mapOf(
            "id" to str(itemId),
            "kind" to str("passkey"),
            "title" to str(title),
            "created_at" to JsonValue.Int(1_700_000_000),
            "updated_at" to JsonValue.Int(1_700_000_000),
            "favorite" to JsonValue.Bool(false),
            "tags" to JsonValue.Arr(emptyList()),
            "payload" to payload,
        ),
    )

    private fun canon(v: JsonValue): ByteArray = CanonicalJson.encode(v, Dialect.UTF8)

    @Test
    fun passkey_is_a_phone_kind() {
        assertTrue("passkey" in Normalise.phoneItemKinds)
    }

    @Test
    fun records_vectors_validity_and_usability() {
        for (c in cases()) {
            val name = c.getValue("name").str()
            val valid = (c.getValue("valid") as JsonValue.Bool).v
            val usable = (c.getValue("usable") as JsonValue.Bool).v
            val input = c.getValue("input")
            val record = item(input)
            try {
                val out = Normalise.normalForm(Namespace.ITEM, record)
                assertTrue(valid, name)
                assertEquals(c["normalised"], out.obj().fields["payload"], name)
            } catch (e: NormaliseException) {
                assertFalse(valid, "$name: $e")
            }
            val pk = assertNotNull(PasskeyRecord.from(Wrapper.make(Namespace.ITEM, record), itemId), name)
            assertEquals(usable, pk.key != null, name)
            assertEquals(itemId, pk.itemId)
            if (usable) {
                assertEquals("example.com", pk.rpId, name)
                assertEquals("ada", pk.userName)
                assertEquals("Example (ada)", pk.title)
                assertContentEquals("user-handle-1".toByteArray(), pk.userHandle)
                assertEquals(16, pk.credentialId.size)
            }
        }
    }

    @Test
    fun from_strips_credential_id() {
        val made = PasskeyRecord.newPayload(
            "example.com", "Example", "ada", "Ada", byteArrayOf(1, 2), ByteArray(16) { 9 }, PasskeyKey.generate(), "2026-10-18",
        )
        val p = made.fields.obj().fields.toMutableMap()
        p["credential_id"] = str("  ${p.getValue("credential_id").str()}\n")
        val pk = assertNotNull(PasskeyRecord.from(item(JsonValue.Obj(p)), itemId))
        assertContentEquals(ByteArray(16) { 9 }, pk.credentialId)
        assertNotNull(pk.key)
    }

    @Test
    fun from_ignores_other_kinds() {
        val o = mutableMapOf<String, JsonValue>(
            "id" to str(itemId),
            "kind" to str("note"),
            "title" to str("n"),
            "payload" to JsonValue.Obj(mapOf("body" to str("x"))),
        )
        assertNull(PasskeyRecord.from(Wrapper.make(Namespace.ITEM, JsonValue.Obj(o)), itemId))
        o["kind"] = str("web")
        assertNull(PasskeyRecord.from(Wrapper.make(Namespace.ENTRY, JsonValue.Obj(o)), itemId))
    }

    private fun payload(rpName: String, userName: String, rpId: String = "example.com") = PasskeyRecord.newPayload(
        rpId, rpName, userName, "Ada Lovelace", "user-handle-1".toByteArray(), ByteArray(16) { 7 }, PasskeyKey.generate(), "2026-10-18",
    )

    @Test
    fun new_payload_title_rules() {
        assertEquals("Example (ada)", payload("Example", "ada").title)
        assertEquals("example.com (ada)", payload("", "ada").title)
        assertEquals("Example", payload("Example", "").title)
        assertEquals("example.com", payload("", "").title)
    }

    @Test
    fun new_payload_fields_match_desktop_create_credential() {
        val f = payload("Example", "ada", " Example.COM ").fields.obj().fields
        assertEquals(str("example.com"), f["relying_party_id"])
        assertEquals(str("ES256"), f["algorithm"])
        assertEquals(JsonValue.Bool(true), f["discoverable"])
        assertEquals(str("2026-10-18"), f["created"])
        assertEquals(str(Base64Url.encodeNoPad("user-handle-1".toByteArray())), f["user_handle"])
        assertEquals(str(Base64Url.encodeNoPad(ByteArray(16) { 7 })), f["credential_id"])
        assertEquals(JsonValue.Null, f["template_id"])
        val k = f.getValue("private_key").str()
        assertNotNull(PasskeyKey.fromPkcs8B64Url(k))
        assertFalse(k.contains("="))
    }

    @Test
    fun new_payload_normalises_identically() {
        val p = payload("Example", "ada")
        val record = item(p.fields, p.title)
        val out = Normalise.normalForm(Namespace.ITEM, record)
        assertContentEquals(canon(record), canon(out))
        val pk = assertNotNull(PasskeyRecord.from(Wrapper.make(Namespace.ITEM, out), itemId))
        assertNotNull(pk.key)
    }

    /** A passkey the phone only stores republishes exactly as received. */
    @Test
    fun untouched_passkey_republishes_identically() {
        var n = 0
        for (c in cases()) {
            if (c["valid"] != JsonValue.Bool(true)) continue
            val wrapper = Wrapper.make(Namespace.ITEM, item(c.getValue("input")))
            val bytes = canon(wrapper)
            val state = ItemState(itemId, mapOf("a" to 1L), false, null, wrapper)
            val (ns, rec) = Wrapper.unwrap(state, false)
            assertContentEquals(bytes, canon(Wrapper.make(ns, rec)))
            PasskeyRecord.from(wrapper, itemId)
            assertContentEquals(bytes, canon(wrapper))
            n++
        }
        assertTrue(n > 0)
    }

    @Test
    fun normaliser_rejects_bad_passkey_payloads() {
        val base = mapOf<String, JsonValue>("relying_party_id" to str("example.com"))
        fun with(vararg kv: Pair<String, JsonValue>) = JsonValue.Obj(base + kv)
        val bad = listOf(
            with("extra" to str("x")),
            with("relying_party_id" to str("https://example.com")),
            with("algorithm" to str("HS256")),
            with("discoverable" to str("yes")),
            with("discoverable" to JsonValue.Null),
            with("created" to str("2026-9-21")),
            with("user_handle" to str("a+b")),
            with("user_name" to JsonValue.Null),
        )
        for (p in bad) {
            try {
                Normalise.normalForm(Namespace.ITEM, item(p))
                fail("$p")
            } catch (_: NormaliseException) {
            }
        }
        for (d in listOf("20260921", "2026-W38", "2026W381", "")) {
            Normalise.normalForm(Namespace.ITEM, item(with("created" to str(d))))
        }
        Normalise.normalForm(Namespace.ITEM, item(with("created" to JsonValue.Null, "algorithm" to JsonValue.Null)))
    }

    @Test
    fun normalise_rp_id_strips_and_casefolds() {
        assertEquals("example.com", PasskeyRecord.normaliseRpId(" Example.COM "))
        assertEquals("login.example.com", PasskeyRecord.normaliseRpId("login.example.com"))
    }

    @Test
    fun equality_compares_byte_content_and_to_string_hides_bytes() {
        fun rec(h: Byte) = PasskeyRecord("i", "t", "example.com", "ada", byteArrayOf(h, 2), byteArrayOf(7, 8), null)
        assertEquals(rec(1), rec(1))
        assertEquals(rec(1).hashCode(), rec(1).hashCode())
        assertFalse(rec(1) == rec(9))
        assertFalse(rec(1).toString().contains("["))
        assertFalse(rec(1).toString().contains("B@"))
    }

    @Test
    fun equality_compares_the_key_by_content() {
        val k = PasskeyKey.generate()
        val same = PasskeyKey.fromPkcs8B64Url(k.pkcs8B64Url)!!
        fun rec(key: PasskeyKey) = PasskeyRecord("i", "t", "example.com", "ada", byteArrayOf(1), byteArrayOf(7), key)
        assertEquals(rec(k), rec(same))
        assertEquals(rec(k).hashCode(), rec(same).hashCode())
        assertFalse(rec(k) == rec(PasskeyKey.generate()))
        assertFalse(rec(k).toString().contains(k.pkcs8B64Url))
        assertFalse(k.toString().contains(k.pkcs8B64Url))
    }
}
