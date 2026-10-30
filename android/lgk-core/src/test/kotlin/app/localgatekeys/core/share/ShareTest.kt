package app.localgatekeys.core.share

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.support.Vectors
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** `.lgkshare` v1 against the shared vectors (port of tests/test_share_format.py). */
class ShareTest {
    private val vectors = Vectors.json(File(Vectors.root, "share/v1.json").also { check(it.isFile) { "vector missing: $it" } }).obj().fields
    private val opens = vectors.getValue("opens").arr().map { it.obj().fields }
    private val legacy = vectors.getValue("legacy").arr().map { it.obj().fields }
    private val refused = vectors.getValue("refused").arr().map { it.obj().fields }
    private val random = SystemRandomSource()

    private fun Map<String, JsonValue>.s(k: String) = getValue(k).str()

    @Test fun vector_opens_and_reseals_byte_for_byte() {
        assertEquals(6, opens.size)
        for (case in opens + legacy) {
            val data = case.s("package").toByteArray(Charsets.UTF_8)
            val opened = Share.open(data, case.s("code"), case.getValue("now").long())
            assertEquals(case.getValue("item"), opened.item, case.s("name"))
            assertEquals(case.s("sender"), opened.sender)
            assertEquals(case.s("id"), opened.id)
            assertEquals(case.getValue("now").long() + Share.LIFETIME, opened.expiresAt)
            val again = Share.seal(
                case.getValue("item"), case.s("code"), case.s("sender"), case.getValue("now").long(), random,
                packageId = case.s("id"), salt = Base64Std.decodeStrict(case.s("salt")), nonce = Base64Std.decodeStrict(case.s("nonce")),
            )
            assertContentEquals(data, again, case.s("name"))
        }
    }

    @Test fun vector_refusals() {
        assertEquals(8, refused.size)
        for (case in refused) {
            val e = assertFailsWith<ShareException>(case.s("name")) {
                Share.open(case.s("package").toByteArray(Charsets.UTF_8), case.s("code"), case.getValue("now").long())
            }
            assertEquals(case.s("reason"), e.reason, case.s("name"))
        }
    }

    @Test fun stored_shape_is_kept_and_display_shape_is_converted() {
        for (case in opens) assertEquals(case.getValue("item"), Share.storedForm(case.getValue("item").obj()), case.s("name"))
        for (case in legacy) assertEquals(case.getValue("stored"), Share.storedForm(case.getValue("item").obj()), case.s("name"))
    }

    @Test fun header_is_readable_without_the_code_and_holds_no_secret() {
        val case = opens[0]
        val header = Share.readHeader(case.s("package").toByteArray(Charsets.UTF_8))
        assertEquals("Alex's iPhone", header.sender)
        assertEquals(case.s("id"), header.id)
        assertFalse("correct-horse" in case.s("package"))
        assertFalse("Home Wi-Fi" in case.s("package"))
    }

    @Test fun open_once_per_device_and_code_spelling() {
        val case = opens[0]
        val data = case.s("package").toByteArray(Charsets.UTF_8)
        val now = case.getValue("now").long()
        val e = assertFailsWith<ShareException> { Share.open(data, case.s("code"), now, setOf(case.s("id"))) }
        assertEquals("already-opened", e.reason)
        assertEquals(case.s("id"), Share.open(data, "Maple · River · Onion · Seven · Lamp · Quote", now).id)
        assertEquals(case.s("id"), Share.open(data, "maple-river-onion-seven-lamp-quote", now).id)
    }

    @Test fun fresh_code_and_qr_round_trip() {
        val code = Share.generateCode(random)
        assertEquals(6, code.split(" ").size)
        assertEquals(code, Share.normalizeCode(code))
        assertEquals(code, Share.codeFromQrText(Share.codeQrText(code)))
        val item = JsonValue.Obj(mapOf("kind" to JsonValue.Str("note"), "title" to JsonValue.Str("n"), "fields" to JsonValue.Obj(mapOf("text" to JsonValue.Str("x")))))
        val data = Share.seal(item, code, "PC", 100, random)
        assertTrue(Share.fitsQr(data))
        assertTrue(Share.looksLikePackage(data.toString(Charsets.UTF_8)))
        assertEquals(JsonValue.Str("n"), Share.open(data, code, 200).item.fields["title"])
        assertEquals("bad-code", assertFailsWith<ShareException> { Share.codeFromQrText("maple-river") }.reason)
    }

    @Test fun passkeys_attachments_and_local_fields_never_travel() {
        val code = Share.generateCode(random)
        fun obj(vararg p: Pair<String, JsonValue>) = JsonValue.Obj(mapOf(*p))
        assertEquals("not-shareable", assertFailsWith<ShareException> {
            Share.seal(obj("kind" to JsonValue.Str("passkey"), "title" to JsonValue.Str("p")), code, "PC", 1, random)
        }.reason)
        assertEquals("not-shareable", assertFailsWith<ShareException> {
            Share.seal(obj("kind" to JsonValue.Str("web"), "attachments" to JsonValue.Arr(listOf(obj("id" to JsonValue.Str("a"))))), code, "PC", 1, random)
        }.reason)
        val data = Share.seal(
            obj("kind" to JsonValue.Str("web"), "label" to JsonValue.Str("A"), "policy" to obj("fill" to JsonValue.Str("auto")),
                "password_history" to JsonValue.Arr(listOf(obj()))),
            code, "PC", 1, random,
        )
        assertEquals(obj("kind" to JsonValue.Str("web"), "label" to JsonValue.Str("A")), Share.open(data, code, 2).item)
    }

    @Test fun long_sender_is_cut_to_64_code_points_and_header_checks_hold() {
        val code = Share.generateCode(random)
        val item = JsonValue.Obj(mapOf("kind" to JsonValue.Str("note")))
        val data = Share.seal(item, code, "  " + "é".repeat(80) + " ", 1, random)
        assertEquals("é".repeat(64), Share.readHeader(data).sender)
        val tampered = CanonicalJson.parse(data).obj().fields.toMutableMap()
        tampered["extra"] = JsonValue.Int(1)
        val bytes = CanonicalJson.encode(JsonValue.Obj(tampered), app.localgatekeys.core.json.Dialect.UTF8)
        assertEquals("malformed", assertFailsWith<ShareException> { Share.readHeader(bytes) }.reason)
        assertEquals("malformed", assertFailsWith<ShareException> { Share.readHeader("nope".toByteArray()) }.reason)
    }
}
