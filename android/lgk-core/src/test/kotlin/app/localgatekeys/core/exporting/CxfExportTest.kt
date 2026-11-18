package app.localgatekeys.core.exporting

import app.localgatekeys.core.importing.CxfImport
import app.localgatekeys.core.importing.ImportCandidate
import app.localgatekeys.core.importing.PyJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.passkey.PasskeyKey
import app.localgatekeys.core.primitives.Base64Url
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.StoreSnapshot
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** CXF export: the exact inverse of [CxfImport] (the Windows `tests/test_export_cxf.py` cases). */
class CxfExportTest {
    private val now = 1_794_139_200L // 2026-11-08 12:00 UTC
    private val random = SystemRandomSource()

    private fun s(v: String): JsonValue = JsonValue.Str(v)

    private fun passkeyCandidate(privateKey: String) = ImportCandidate(
        kind = ImportCandidate.Kind.PASSKEY, title = "Passkey Site", username = "bob", urls = listOf("https://pk.example.test"),
        passkey = linkedMapOf(
            "relying_party_id" to "pk.example.test", "user_handle" to Base64Url.encodeNoPad(byteArrayOf(10, 11, 12)),
            "credential_id" to Base64Url.encodeNoPad(byteArrayOf(1, 2, 3, 4)), "private_key" to privateKey, "algorithm" to "ES256",
            "user_name" to "bob", "user_display_name" to "Bob B", "created" to "2026-01-02",
        ),
    )

    @Test
    fun roundtrip_login_passkey_note() {
        val login = ImportCandidate(
            kind = ImportCandidate.Kind.LOGIN, title = "Example Mail", username = "ada", password = "correct horse",
            urls = listOf("https://mail.example.test/login", "https://example.test"), notes = "in the drawer",
            totp = CxfImport.totpUri("JBSWY3DPEHPK3PXP", label = "Example:ada", issuer = "Example", digits = 8, period = 60, algorithm = "SHA256"),
            created = 1_700_000_000L,
        )
        val bare = ImportCandidate(kind = ImportCandidate.Kind.LOGIN, title = "Plain", username = "u", password = "p", urls = listOf("https://plain.test"))
        val note = ImportCandidate(kind = ImportCandidate.Kind.NOTE, title = "Memo", notes = "remember the milk\nand bread")
        val passkey = passkeyCandidate(PasskeyKey.generate().pkcs8B64Url)
        val data = CxfExport.build(listOf(login, bare, note, passkey), now, random)
        val (records, skipped) = CxfImport.parse(data)
        assertEquals(emptyList(), skipped)
        assertEquals(listOf(login, bare, note, passkey), records)
        val doc = PyJson.parse(String(data, Charsets.UTF_8))
        val items = (doc["items"] as PyJson.Arr).items
        assertEquals(4, items.size)
        val key = (items[3]["credentials"] as PyJson.Arr).items.first { it["type"] == PyJson.Str("passkey") }["key"]!!.str
        assertFalse('=' in key || '+' in key || '/' in key, "base64url PKCS#8 DER, as the CXF spec reads it")
        assertNotNull(PasskeyKey.fromPkcs8B64Url(key))
    }

    @Test
    fun build_refuses_unsupported_kinds() {
        assertFailsWith<IllegalArgumentException> {
            CxfExport.build(listOf(ImportCandidate(kind = ImportCandidate.Kind.IDENTITY, title = "Me", identity = mapOf("given_name" to "A"))), now, random)
        }
    }

    private class Vault(val snapshot: StoreSnapshot, val ids: Map<String, String>, val privateKey: String)

    private fun vault(passkeyNotes: String = ""): Vault {
        val records = LinkedHashMap<String, JsonValue>()
        fun put(id: String, ns: Namespace, fields: Map<String, JsonValue>) {
            records[id] = Wrapper.make(ns, JsonValue.Obj(linkedMapOf<String, JsonValue>("id" to s(id), "created_at" to JsonValue.Int(1_700_000_000L), "updated_at" to JsonValue.Int(1_700_000_100L)) + fields))
        }
        fun web(origin: String, user: String, pw: String, label: String, extra: Map<String, JsonValue> = emptyMap()) = linkedMapOf(
            "kind" to s("web"), "label" to s(label), "username" to s(user), "password" to s(pw),
            "scope" to JsonValue.Obj(linkedMapOf("origin" to s(origin), "urls" to JsonValue.Arr(listOf(JsonValue.Obj(linkedMapOf("url" to s(origin), "match" to s("exact_origin"))))))),
        ) + extra
        val ids = mapOf("login" to "11111111-1111-4111-8111-111111111111", "other" to "22222222-2222-4222-8222-222222222222",
            "note" to "33333333-3333-4333-8333-333333333333", "identity" to "44444444-4444-4444-8444-444444444444",
            "passkey" to "55555555-5555-4555-8555-555555555555")
        put(ids["login"]!!, Namespace.ENTRY, web("https://a.test", "alice", "pw-alice", "A site", mapOf(
            "totp" to JsonValue.Obj(linkedMapOf("secret" to s("JBSWY3DPEHPK3PXP"), "digits" to JsonValue.Int(6), "period" to JsonValue.Int(30), "algorithm" to s("SHA1"))),
        )))
        put(ids["other"]!!, Namespace.ENTRY, web("https://b.test", "bob", "pw-bob", "B site"))
        put(ids["note"]!!, Namespace.ITEM, mapOf("kind" to s("note"), "title" to s("Memo"), "payload" to JsonValue.Obj(mapOf("body" to s("the body"), "fields" to JsonValue.Arr(emptyList())))))
        put(ids["identity"]!!, Namespace.ITEM, mapOf("kind" to s("identity"), "title" to s("Me"), "payload" to JsonValue.Obj(mapOf("given_name" to s("Alice")))))
        val key = PasskeyKey.generate().pkcs8B64Url
        put(ids["passkey"]!!, Namespace.ITEM, mapOf("kind" to s("passkey"), "title" to s("PK site"), "payload" to JsonValue.Obj(linkedMapOf(
            "relying_party_id" to s("pk.example.test"), "credential_id" to s(Base64Url.encodeNoPad(byteArrayOf(1, 2, 3))),
            "user_handle" to s(Base64Url.encodeNoPad(byteArrayOf(9))), "private_key" to s(key), "algorithm" to s("ES256"),
            "user_name" to s("carol"), "created" to s("2026-01-02"), "notes" to s(passkeyNotes),
        ))))
        return Vault(StoreSnapshot(records = records), ids, key)
    }

    private fun release(v: Vault, calls: MutableList<List<String>>): (List<String>) -> Map<String, String> = { ids ->
        calls.add(ids)
        CxfExport.privateKeys(v.snapshot, ids)
    }

    @Test
    fun only_selected_ids_exported() {
        val v = vault()
        val calls = ArrayList<List<String>>()
        val result = CxfExport.export(v.snapshot, listOf(v.ids["login"]!!, v.ids["note"]!!, v.ids["passkey"]!!), release(v, calls), now, random)
        assertEquals(listOf(listOf(v.ids["passkey"]!!)), calls)
        val (records, skipped) = CxfImport.parse(result.bytes)
        assertEquals(emptyList(), skipped)
        assertEquals(listOf("A site", "Memo", "PK site"), records.map { it.title }.sorted())
        val login = records.first { it.title == "A site" }
        assertEquals(Triple("alice", "pw-alice", listOf("https://a.test")), Triple(login.username, login.password, login.urls))
        assertEquals("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP", login.totp)
        val passkey = records.first { it.kind == ImportCandidate.Kind.PASSKEY }.passkey
        assertEquals(v.privateKey, passkey["private_key"])
        assertEquals("carol", passkey["user_name"])
        assertEquals("2026-01-02", passkey["created"])
        assertEquals(3, result.count)
        assertFalse("pw-bob" in String(result.bytes, Charsets.UTF_8))
    }

    @Test
    fun no_passkey_selected_does_not_release() {
        val v = vault()
        val calls = ArrayList<List<String>>()
        CxfExport.export(v.snapshot, listOf(v.ids["other"]!!), release(v, calls), now, random)
        assertEquals(emptyList(), calls)
    }

    @Test
    fun plan_holds_no_private_key() {
        val v = vault()
        val plan = CxfExport.plan(v.snapshot, listOf(v.ids["passkey"]!!))
        assertEquals(mapOf(v.ids["passkey"]!! to "PK site"), plan.passkeys)
        assertTrue(plan.records.none { (_, r) -> r.passkey.containsKey("private_key") })
    }

    @Test
    fun unsupported_kind_is_skipped_and_named() {
        val v = vault()
        val result = CxfExport.export(v.snapshot, listOf(v.ids["identity"]!!, v.ids["note"]!!), release(v, ArrayList()), now, random)
        assertEquals(1, result.count)
        assertEquals(listOf(CxfDiagnostic(CxfDiagnostic.Kind.KIND_SKIPPED, "Me")), result.diagnostics)
    }

    @Test
    fun totp_left_out_when_not_requested() {
        val v = vault()
        val result = CxfExport.export(v.snapshot, listOf(v.ids["login"]!!), release(v, ArrayList()), now, random, includeTotp = false)
        assertFalse("JBSWY3DPEHPK3PXP" in String(result.bytes, Charsets.UTF_8))
    }

    @Test
    fun declined_release_makes_nothing() {
        val v = vault()
        assertFailsWith<SecurityException> {
            CxfExport.export(v.snapshot, listOf(v.ids["login"]!!, v.ids["passkey"]!!), { throw SecurityException("declined") }, now, random)
        }
    }

    @Test
    fun missing_released_key_aborts() {
        val v = vault()
        val e = assertFailsWith<CxfExportException> { CxfExport.export(v.snapshot, listOf(v.ids["passkey"]!!), { emptyMap() }, now, random) }
        assertEquals(CxfExportException.Kind.PASSKEY_KEY_MISSING, e.kind)
        assertEquals("PK site", e.title)
    }

    @Test
    fun empty_selection_is_refused() {
        val v = vault()
        val e = assertFailsWith<CxfExportException> { CxfExport.export(v.snapshot, emptyList(), { emptyMap() }, now, random) }
        assertEquals(CxfExportException.Kind.CHOOSE_ITEMS, e.kind)
        val none = assertFailsWith<CxfExportException> { CxfExport.export(v.snapshot, listOf(v.ids["identity"]!!), { emptyMap() }, now, random) }
        assertEquals(CxfExportException.Kind.NOTHING_TO_EXPORT, none.kind)
    }

    @Test
    fun empty_logins_stay_logins() {
        val withNotes = ImportCandidate(kind = ImportCandidate.Kind.LOGIN, title = "Only notes", notes = "kept here", urls = listOf("https://n.test"))
        val empty = ImportCandidate(kind = ImportCandidate.Kind.LOGIN, title = "Empty")
        val (records, skipped) = CxfImport.parse(CxfExport.build(listOf(withNotes, empty), now, random))
        assertEquals(emptyList(), skipped)
        assertEquals(listOf(withNotes, empty), records)
    }

    @Test
    fun passkey_notes_left_out_are_named() {
        val v = vault(passkeyNotes = "backup codes elsewhere")
        val result = CxfExport.export(v.snapshot, listOf(v.ids["passkey"]!!), { CxfExport.privateKeys(v.snapshot, it) }, now, random)
        assertEquals(1, result.count)
        assertEquals(listOf(CxfDiagnostic(CxfDiagnostic.Kind.PASSKEY_NOTES_LEFT_OUT, "PK site")), result.diagnostics)
        assertFalse("backup codes elsewhere" in String(result.bytes, Charsets.UTF_8))
    }

    @Test
    fun custom_fields_and_recovery_codes_are_named() {
        val records = LinkedHashMap<String, JsonValue>()
        records["x"] = Wrapper.make(Namespace.ENTRY, JsonValue.Obj(linkedMapOf(
            "id" to s("x"), "kind" to s("web"), "label" to s("Coded"), "username" to s("u"), "password" to s("p"),
            "scope" to JsonValue.Obj(mapOf("origin" to s("https://c.test"))), "recovery_codes" to JsonValue.Arr(listOf(s("r-1"))),
        )))
        val result = CxfExport.export(StoreSnapshot(records = records), listOf("x"), { emptyMap() }, now, random)
        assertEquals(listOf(CxfDiagnostic(CxfDiagnostic.Kind.FIELDS_LEFT_OUT, "Coded")), result.diagnostics)
        assertFalse("r-1" in String(result.bytes, Charsets.UTF_8))
    }

    @Test
    fun results_never_print_secrets() {
        val v = vault()
        val result = CxfExport.export(v.snapshot, listOf(v.ids["passkey"]!!), { CxfExport.privateKeys(v.snapshot, it) }, now, random)
        assertFalse(v.privateKey in result.toString())
        assertFalse(v.privateKey in CxfExport.plan(v.snapshot, listOf(v.ids["passkey"]!!)).toString())
    }
}
