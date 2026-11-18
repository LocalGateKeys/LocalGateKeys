package app.localgatekeys.android.importing

import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.trash.InMemoryLocalData
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.core.importing.ImportFormat
import app.localgatekeys.core.json.JsonValue
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The switch report after an import (contract 2026-11-15 section 6.1, scan A-L12): a port of Windows
 * `import_report.build_report`, counted from what the import's commit wrote.
 */
class SwitchReportTest {
    private val now = 1_800_000_000L
    private val repo = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot is not set"))
    private fun fixture(name: String) = File(repo, "tests/fixtures/imports/$name").readBytes()
    private val txt = EnglishTxt()
    private val random = CountingRandom()

    private fun flow(store: CountingStore, pro: Boolean = true, local: InMemoryLocalData? = null) =
        ImportFlow({ store }, { pro }, TestClock(now), random, Dispatchers.Unconfined, txt, local = local)

    private fun csv(vararg rows: String): ByteArray = (listOf("name,url,username,password,note") + rows.toList()).joinToString("\n", postfix = "\n").toByteArray()

    @Test fun bitwarden_json_matches_the_windows_report() = runBlocking {
        // Windows on the same file (tests/fixtures/imports/bitwarden.json, empty vault, Pro): kinds card 1, identity 1,
        // note 3, web 2; total 7, written 6, added 7, updated 0; 1 row the file could not provide; 14 custom fields
        // (free plan, as that Windows run: the login's TOTP is kept as a "Two-factor key (needs Pro)" field).
        val store = CountingStore()
        val f = flow(store, pro = false)
        f.chose(fixture("bitwarden.json"), "bitwarden.json")
        assertTrue(f.commit())
        val r = f.state.value.report!!
        assertEquals(
            listOf(SwitchReport.KindCount("card", 1), SwitchReport.KindCount("identity", 1), SwitchReport.KindCount("note", 3), SwitchReport.KindCount("web", 2)),
            r.kinds,
        )
        assertEquals(7, r.total)
        assertEquals(6, r.written)
        assertEquals(7, r.added)
        assertEquals(0, r.updated)
        assertEquals(1, r.unreadableRows)
        assertEquals(14, r.fieldsKept)
        assertEquals(0, r.duplicates)
        assertTrue(r.notCarried.isEmpty())
        assertEquals(SwitchReport.Passkeys(0, 0, 0), r.passkeys)
        // The counts are what the store holds now.
        assertEquals(7, store.snapshot.records.size)
        assertEquals("Imported 6 of 7, 1 skipped (rows the file could not provide).", r.summary(txt))
        assertEquals(listOf("1 card", "1 identity", "3 secure notes", "2 logins"), r.kinds.map { SwitchReport.countLine(it, txt) })
        assertFalse(r.toString().contains("Example"))
    }

    @Test fun skipped_rows_are_named_with_their_reason() = runBlocking {
        val store = CountingStore()
        val first = flow(store)
        first.chose(csv("One,https://one.example,ann,pw-one-123456"), "chrome.csv")
        assertTrue(first.commit())
        // Same row again (duplicate, skipped by default), a new row the person skips, and a new row that is added.
        val f = flow(store)
        f.chose(csv("One,https://one.example,ann,pw-one-123456", "Two,https://two.example,bob,pw-two-123456", "Three,https://three.example,cy,pw-three-123456"), "chrome.csv")
        val two = f.state.value.rows.single { it.title == "Two" }
        f.set(ImportDecision.SKIP, two.id)
        assertTrue(f.commit())
        val r = f.state.value.report!!
        assertEquals(listOf(SwitchReport.KindCount("web", 1)), r.kinds)
        assertEquals(3, r.total)
        assertEquals(1, r.written)
        assertEquals(1, r.duplicates)
        assertEquals(
            listOf(SwitchReport.NotCarried(2, "One", SwitchReport.SkipReason.DUPLICATE), SwitchReport.NotCarried(3, "Two", SwitchReport.SkipReason.SKIPPED)),
            r.notCarried,
        )
        assertEquals("Imported 1 of 3, 2 skipped (already in the vault: 1, skipped in the review: 1).", r.summary(txt))
    }

    @Test fun rows_past_the_free_plan_are_reported_as_needing_pro() = runBlocking {
        val store = CountingStore(app.localgatekeys.android.vault.snapshot(
            app.localgatekeys.android.editor.numberedNotes(app.localgatekeys.android.pro.ItemLimit.FREE_ITEMS - 1)))
        val f = flow(store, pro = false)
        f.chose(csv("A,https://a.example,a,pw-a-123456", "B,https://b.example,b,pw-b-123456"), "chrome.csv")
        assertTrue(f.commit())
        val r = f.state.value.report!!
        assertEquals(listOf(SwitchReport.KindCount("web", 1)), r.kinds)
        assertEquals(listOf(SwitchReport.SkipReason.NEEDS_PRO), r.notCarried.map { it.reason })
        assertEquals("needs Pro (free plan full)", SwitchReport.reasonText(SwitchReport.SkipReason.NEEDS_PRO, txt))
    }

    @Test fun replacing_counts_as_updated_and_undo_still_works() = runBlocking {
        val store = CountingStore()
        val local = InMemoryLocalData()
        val first = flow(store, local = local)
        first.chose(csv("One,https://one.example,ann,pw-one-123456"), "chrome.csv")
        assertTrue(first.commit())
        val f = flow(store, local = local)
        f.chose(csv("One,https://one.example,ann,pw-changed-123456"), "chrome.csv")
        f.setAllExisting(ImportDecision.REPLACE)
        assertTrue(f.commit())
        val r = f.state.value.report!!
        assertTrue(r.kinds.isEmpty())
        assertEquals(1, r.written)
        assertEquals(1, r.updated)
        assertEquals("Imported 1 of 1.", r.summary(txt))
        assertTrue(f.state.value.canUndo)
        f.undo()
        val pw = store.snapshot.records.values.map { ((it as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields["password"] }
        assertEquals(listOf(JsonValue.Str("pw-one-123456")), pw)
    }

    @Test fun counts_never_exceed_what_arrived() {
        // Windows `test_report_never_claims_more_than_arrived`: three passkey rows taken, one arrived.
        fun row(id: Int, decision: ImportDecision = ImportDecision.ADD) =
            ImportRow(id, id + 1, ImportDraft(ImportDraft.Kind.PASSKEY, title = "P$id"), decision = decision)
        val rows = listOf(row(0), row(1), row(2))
        val after = mapOf("only-one" to mapOf("kind" to JsonValue.Str("passkey")))
        val r = SwitchReport.build(rows, emptyMap(), after)
        assertEquals(1, r.added)
        assertEquals(listOf(SwitchReport.KindCount("passkey", 1)), r.kinds)
        assertEquals(SwitchReport.Passkeys(3, 1, 2), r.passkeys)
        assertEquals("1 passkey", SwitchReport.countLine(r.kinds.single(), txt))
        // An item that was there before is not counted as arrived.
        val again = SwitchReport.build(rows, after, after)
        assertTrue(again.kinds.isEmpty())
        assertEquals("No new items were added.", txt.s(app.localgatekeys.android.R.string.import_report_nothing_added))
    }

    @Test fun reason_codes_match_windows() {
        assertEquals(listOf("needs_pro", "duplicate", "skipped", "unreadable"), SwitchReport.SkipReason.entries.map { it.code })
        val limited = ImportRow(0, 1, ImportDraft(ImportDraft.Kind.LOGIN), base = ImportRowStatus.DUPLICATE, limited = true)
        assertEquals(SwitchReport.SkipReason.NEEDS_PRO, SwitchReport.reason(limited))
        assertEquals(SwitchReport.SkipReason.SKIPPED, SwitchReport.reason(limited.copy(limited = false, base = ImportRowStatus.CONFLICT, decision = ImportDecision.SKIP)))
    }

    @Test fun only_skipped_source_rows_count_as_unreadable() {
        // Windows `skipped_rows`: messages ending in "skipped." and rows the review dropped; other messages are notes.
        fun src(id: Int, row: Int, reason: String) =
            ImportRow(id, row, ImportDraft(ImportDraft.Kind.NOTE), base = ImportRowStatus.SKIPPED_SOURCE, decision = ImportDecision.SKIP, reason = reason)
        val rows = listOf(
            src(0, 0, "Item 7: in the Bitwarden trash; skipped."),
            src(1, 0, "1 login(s) have passkeys; only the password was imported."),
            src(2, 5, "Row 5: no password or address."),
        )
        val r = SwitchReport.build(rows, emptyMap(), emptyMap())
        assertEquals(2, r.unreadableRows)
        assertEquals(2, r.total)
        assertTrue(r.notCarried.isEmpty())
        assertEquals("Imported 0 of 2, 2 skipped (rows the file could not provide).", r.summary(txt))
    }
}
