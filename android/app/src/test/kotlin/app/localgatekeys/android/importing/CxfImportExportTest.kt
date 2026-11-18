package app.localgatekeys.android.importing

import app.localgatekeys.android.backup.CxfExportFlow
import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.numberedNotes
import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.core.importing.CxfImport
import app.localgatekeys.core.importing.ImportFormat
import app.localgatekeys.core.importing.ImportSource
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.passkey.PasskeyRecord
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Credential Exchange files on the phone: the review and commit of an import (passkeys included) and the export flow. */
class CxfImportExportTest {
    private val now = 1_800_000_000L
    private val repo = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot is not set"))
    private val sample = File(repo, "tests/vectors/cxf/apple-passwords-sample.json").readBytes()

    private fun review(store: CountingStore, data: ByteArray = sample, pro: Boolean = true) =
        ImportReview(ImportSource.candidates(data, ImportFormat.CXF), store.load(), pro, TestClock(now), CountingRandom(), EnglishTxt())

    private fun records(store: CountingStore): Map<String, Map<String, JsonValue>> =
        store.snapshot.records.mapValues { ((it.value as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields }

    private fun doc(vararg items: String): ByteArray = """{"id": "QQ", "items": [${items.joinToString(",")}]}""".toByteArray()

    @Test fun sample_applies_with_a_usable_passkey() {
        val store = CountingStore()
        val r = review(store)
        assertTrue(r.issues.contains("Skipped 1 credential of a type LocalGateKeys cannot store: credit-card (1)."))
        val out = r.commit(store)
        assertEquals(3, out.created)
        val passkeys = store.snapshot.records.filter { (_, w) -> (((w as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields["kind"]) == JsonValue.Str("passkey") }
        assertEquals(1, passkeys.size)
        val (id, wrapper) = passkeys.entries.single()
        val payload = (records(store)[id]!!["payload"] as JsonValue.Obj).fields
        assertEquals(JsonValue.Str("pk.example.test"), payload["relying_party_id"])
        assertEquals(JsonValue.Str("ES256"), payload["algorithm"])
        assertEquals(JsonValue.Str("bob"), payload["user_name"])
        val usable = PasskeyRecord.from(wrapper, id)
        assertNotNull(usable?.key)
        assertEquals("pk.example.test", usable!!.rpId)
        // The same file again: the passkey is already saved.
        val again = review(store)
        assertTrue(again.rows.filter { it.kind == ImportDraft.Kind.PASSKEY }.all { it.base == ImportRowStatus.DUPLICATE && it.decision == ImportDecision.SKIP })
    }

    @Test fun free_vault_with_14_items_imports_one_of_three() {
        val store = CountingStore(app.localgatekeys.android.vault.snapshot(numberedNotes(ItemLimit.FREE_ITEMS - 1)))
        val r = review(store, pro = false)
        assertEquals(1, r.freeSlots)
        val rows = r.rows.filter { it.base != ImportRowStatus.SKIPPED_SOURCE }
        assertEquals(1, rows.count { it.kind == ImportDraft.Kind.PASSKEY })
        assertEquals(listOf(false, true, true), rows.map { it.limited })
        assertEquals("1 will be imported on the free plan; 2 need Pro", r.limitNote)
        r.commit(store)
        assertEquals(ItemLimit.FREE_ITEMS, ItemLimit.liveCount(store.snapshot))
    }

    @Test fun an_orphan_code_is_kept_in_a_secure_note() {
        val store = CountingStore()
        val r = review(store, doc("""{"id": "a", "title": "Codes", "scope": {"urls": ["https://c.test"]}, "credentials": [{"type": "totp", "secret": "JBSWY3DPEHPK3PXP"}]}"""))
        val row = r.rows.single { it.base != ImportRowStatus.SKIPPED_SOURCE }
        assertEquals(ImportDraft.Kind.NOTE, row.kind)
        val code = row.draft.customFields.single { it.name == "One-time password (otpauth)" }
        assertTrue(code.hidden)
        assertTrue("secret=JBSWY3DPEHPK3PXP" in code.value)
    }

    @Test fun a_passkey_the_vault_refuses_is_skipped_with_its_reason() {
        val key = app.localgatekeys.core.passkey.PasskeyKey.generate().pkcs8B64Url
        val store = CountingStore()
        val r = review(store, doc("""{"id": "a", "title": "P", "credentials": [{"type": "passkey", "credentialId": "AQID", "rpId": "not a host", "key": "$key"}]}"""))
        val row = r.rows.single()
        assertEquals(ImportRowStatus.SKIPPED_SOURCE, row.base)
        assertEquals("Row 1: the passkey could not be stored; it was skipped.", row.reason)
        assertEquals(0, r.willImport)
    }

    // MARK: export

    private fun imported(): CountingStore = CountingStore().also { review(it).commit(it) }

    private fun flow(store: CountingStore, answers: MutableList<Boolean>, asked: MutableList<Unit> = ArrayList()) =
        CxfExportFlow({ store }, { asked.add(Unit); answers.removeAt(0) }, TestClock(now), CountingRandom(), Dispatchers.Unconfined, EnglishTxt())

    @Test fun export_after_the_owner_check_round_trips() = runBlocking {
        val store = imported()
        val asked = ArrayList<Unit>()
        val f = flow(store, mutableListOf(true), asked)
        f.load()
        assertEquals(3, f.state.value.choices.size)
        assertFalse(f.warnings().any { "Passkey private keys" in it })
        f.selectAll(true)
        assertTrue(f.warnings().any { "Passkey private keys" in it })
        assertTrue(f.warnings().first().startsWith("This export stores every password"))
        val bytes = f.make()!!
        assertEquals(1, asked.size)
        val copy = bytes.copyOf()
        val (records, skipped) = app.localgatekeys.core.importing.CxfImport.candidates(copy).let { it.candidates to it.skipped }
        assertTrue(skipped.isEmpty())
        val original = ImportSource.candidates(sample, ImportFormat.CXF).candidates
        assertEquals(original.single { it.kind == app.localgatekeys.core.importing.ImportCandidate.Kind.PASSKEY }.passkey["private_key"],
            records.single { it.kind == app.localgatekeys.core.importing.ImportCandidate.Kind.PASSKEY }.passkey["private_key"])
        f.written(true)
        assertArrayEquals(ByteArray(bytes.size), bytes)
        assertTrue(f.state.value.saved)
        assertEquals("Saved 3 items to the CXF file.", f.state.value.message)
    }

    @Test fun declined_owner_check_makes_nothing() = runBlocking {
        val store = imported()
        val f = flow(store, mutableListOf(false))
        f.load()
        f.selectAll(true)
        assertNull(f.make())
        assertEquals(EnglishTxt().s(app.localgatekeys.android.R.string.cxf_export_declined), f.state.value.message)
        assertFalse(f.state.value.saved)
    }

    @Test fun nothing_selected_asks_nothing() = runBlocking {
        val store = imported()
        val asked = ArrayList<Unit>()
        val f = flow(store, mutableListOf(), asked)
        f.load()
        assertNull(f.make())
        assertTrue(asked.isEmpty())
        assertEquals(EnglishTxt().s(app.localgatekeys.android.R.string.cxf_export_choose), f.state.value.message)
    }

    @Test fun a_cancelled_picker_is_not_a_failure_and_clears_the_bytes() = runBlocking {
        val f = flow(imported(), mutableListOf(true))
        f.load()
        f.selectAll(true)
        val bytes = f.make()!!
        f.cancelled()
        assertArrayEquals(ByteArray(bytes.size), bytes)
        assertNull(f.state.value.message)
        assertFalse(f.state.value.saved)
    }

    @Test fun a_dropped_job_clears_the_bytes() = runBlocking {
        val f = flow(imported(), mutableListOf(true, true))
        f.load()
        f.selectAll(true)
        val first = f.make()!!
        f.clear() // the screen left while the picker was open
        assertArrayEquals(ByteArray(first.size), first)
        val second = f.make()!!
        f.written(null)
        assertArrayEquals(ByteArray(second.size), second)
    }

    @Test fun an_item_deleted_before_export_is_named_without_its_id() {
        val store = imported()
        val gone = "99999999-9999-4999-8999-999999999999"
        val plan = app.localgatekeys.core.exporting.CxfExport.plan(store.snapshot, listOf(gone))
        val line = CxfExportFlow.diagnostic(plan.diagnostics.single(), EnglishTxt())
        assertEquals("An item was deleted before the export and was skipped.", line)
        assertFalse(gone in line)
    }

    @Test fun text_files_are_read_only_to_the_cap_and_zips_further() {
        class Counting(private val size: Int, private val head: ByteArray) : java.io.InputStream() {
            var served = 0
            override fun read(): Int = if (served >= size) -1 else (if (served < head.size) head[served].toInt() and 0xFF else ' '.code).also { served++ }
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (served >= size) return -1
                val n = minOf(len, size - served)
                for (k in 0 until n) b[off + k] = (if (served + k < head.size) head[served + k] else ' '.code.toByte())
                served += n
                return n
            }
        }
        val twenty = 20 * 1024 * 1024
        val text = Counting(twenty, "{\"items\": [".toByteArray())
        val read = ImportRead.read(text)
        assertEquals(ImportSource.MAX_SOURCE_BYTES + 1, read.size)
        assertEquals(ImportSource.MAX_SOURCE_BYTES + 1, text.served)
        val zip = Counting(twenty, byteArrayOf(0x50, 0x4B, 0x03, 0x04))
        assertEquals(twenty, ImportRead.read(zip).size)
        val kdbx = Counting(twenty, byteArrayOf(0x03, 0xD9.toByte(), 0xA2.toByte(), 0x9A.toByte()))
        val kdbxRead = ImportRead.read(kdbx)
        assertEquals(twenty, kdbxRead.size)
        assertTrue(kdbx.served > ImportSource.MAX_SOURCE_BYTES + 1)
        // Past the text cap, a KeePass database is not refused as too large (the phone then names it unsupported).
        val keepass = ImportFlow({ CountingStore() }, { true }, TestClock(now), CountingRandom(), Dispatchers.Unconfined, EnglishTxt())
        runBlocking { keepass.chose(kdbxRead, "big.kdbx") }
        assertFalse(keepass.state.value.error == EnglishTxt().s(app.localgatekeys.android.R.string.import_failure_too_large))
        assertEquals(10, ImportRead.read(Counting(10, ByteArray(0))).size)
        // The flow refuses the capped text at once, as too large.
        val flow = ImportFlow({ CountingStore() }, { true }, TestClock(now), CountingRandom(), Dispatchers.Unconfined, EnglishTxt())
        runBlocking { flow.chose(read, "big.json") }
        assertEquals(EnglishTxt().s(app.localgatekeys.android.R.string.import_failure_too_large), flow.state.value.error)
    }

    @Test fun skipped_types_line_is_translated_from_its_code() {
        val line = CxfImport.candidates(doc("""{"id": "a", "credentials": [{"type": "wifi"}, {"type": "wifi"}]}""")).skipped.single()
        assertEquals("Skipped 2 credentials of types LocalGateKeys cannot store: wifi (2).", ImportReview.skipText(line, EnglishTxt()))
    }

    private fun passkeyDoc(credentialId: String, handle: String, user: String, key: String) = doc(
        """{"id": "p", "title": "Example Passkey Site", "scope": {"urls": ["https://pk.example.test"]}, "credentials": [""" +
            """{"type": "passkey", "credentialId": "$credentialId", "rpId": "pk.example.test", "username": "$user", "userHandle": "$handle", "key": "$key"}]}""",
    )

    @Test fun same_site_passkeys_match_by_credential_not_title() {
        val key = app.localgatekeys.core.passkey.PasskeyKey.generate().pkcs8B64Url
        val store = CountingStore()
        val rng = CountingRandom() // one source across the imports, so new item ids differ
        fun review(store: CountingStore, data: ByteArray) =
            ImportReview(ImportSource.candidates(data, ImportFormat.CXF), store.load(), true, TestClock(now), rng, EnglishTxt())
        review(store, passkeyDoc("AQIDBAUGBwg", "CgsMDQ4P", "bob", key)).commit(store)
        // A second account on the same site: same title, another credential id -> a new item, never a conflict.
        val second = review(store, passkeyDoc("CQkJCQkJCQk", "AQEBAQ", "eve", key))
        val row = second.rows.single()
        assertEquals(ImportRowStatus.NEW, row.base)
        assertNull(row.targetId)
        second.commit(store)
        val passkeys = records(store).values.filter { it["kind"] == JsonValue.Str("passkey") }
        assertEquals(2, passkeys.size)
        // The same credential id again is a duplicate of the stored one.
        val again = review(store, passkeyDoc("CQkJCQkJCQk", "AQEBAQ", "eve", key)).rows.single()
        assertEquals(ImportRowStatus.DUPLICATE, again.base)
        assertEquals(ImportDecision.SKIP, again.decision)
        assertNotNull(again.targetId)
    }
}
