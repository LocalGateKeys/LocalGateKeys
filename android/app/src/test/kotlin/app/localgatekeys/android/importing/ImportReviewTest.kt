package app.localgatekeys.android.importing

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.importing.ImportFormat
import app.localgatekeys.core.importing.ImportSource
import app.localgatekeys.core.json.JsonValue
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The review and commit of an import (port of the iPhone `ImportReviewModel` rules) over the shared fixtures. */
class ImportReviewTest {
    private val now = 1_800_000_000L
    private val repo = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot is not set"))
    private fun fixture(name: String) = File(repo, "tests/fixtures/imports/$name").readBytes()

    private fun review(store: CountingStore, name: String, format: ImportFormat, pro: Boolean = true, password: String? = null) =
        ImportReview(
            ImportSource.candidates(fixture(name), format, app.localgatekeys.core.importing.ImportOptions(password)),
            store.load(), pro, TestClock(now), CountingRandom(),
            EnglishTxt(),
        )

    private fun records(store: CountingStore): List<Map<String, JsonValue>> =
        store.snapshot.records.values.map { ((it as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields }

    private fun str(r: Map<String, JsonValue>, k: String) = (r[k] as? JsonValue.Str)?.v

    @Test fun chrome_rows_become_web_logins_in_one_commit() {
        val store = CountingStore()
        val r = review(store, "chrome.csv", ImportFormat.CHROME)
        val logins = r.rows.filter { it.kind == ImportDraft.Kind.LOGIN }
        assertTrue(logins.isNotEmpty())
        // shop.example.com twice with another password: the repeat is kept as a secure-note copy by default.
        val repeat = r.rows.single { it.inImportDuplicate }
        assertEquals(ImportDecision.KEEP_BOTH, repeat.decision)
        val out = r.commit(store)
        assertEquals(1, store.commits)
        assertEquals(0, out.updated)
        assertTrue(out.created >= 3)
        val web = records(store).filter { it["kind"] == JsonValue.Str("web") }
        val accounts = web.single { str(it, "password") == "chrome-pass-1" }
        assertEquals("https://accounts.example.com", str((accounts["scope"] as JsonValue.Obj).fields, "origin"))
        assertEquals("alex@example.com", str(accounts, "username"))
        assertEquals("Main account", str(accounts, "notes"))
        // The list model reads every imported record.
        assertEquals(store.snapshot.records.size, VaultItem.items(store.snapshot).size)
    }

    @Test fun importing_the_same_file_twice_changes_nothing() {
        val store = CountingStore()
        review(store, "chrome.csv", ImportFormat.CHROME).commit(store)
        val before = store.snapshot.records
        val again = review(store, "chrome.csv", ImportFormat.CHROME)
        assertTrue(again.rows.all { it.decision == ImportDecision.SKIP })
        assertEquals(0, again.willImport)
        val out = again.commit(store)
        assertEquals(0, out.created + out.updated)
        assertEquals(1, store.commits)
        assertEquals(before, store.snapshot.records)
    }

    @Test fun replace_updates_the_existing_login_and_keeps_the_old_password_in_history() {
        val store = CountingStore()
        review(store, "chrome.csv", ImportFormat.CHROME).commit(store)
        val changed = "name,url,username,password\naccounts,https://accounts.example.com/x,alex@example.com,new-pass\n".toByteArray()
        val r = ImportReview(ImportSource.candidates(changed, ImportFormat.CHROME), store.load(), true, TestClock(now + 10), CountingRandom(), EnglishTxt())
        val row = r.rows.single()
        assertEquals(ImportRowStatus.CONFLICT, row.base)
        assertEquals(ImportDecision.SKIP, row.decision)
        // Add is not offered for an account the vault has.
        r.set(ImportDecision.ADD, row.id)
        assertEquals(ImportDecision.SKIP, r.rows.single().decision)
        r.set(ImportDecision.REPLACE, row.id)
        val count = store.snapshot.records.size
        val out = r.commit(store)
        assertEquals(1, out.updated)
        assertEquals(count, store.snapshot.records.size)
        val rec = records(store).single { str(it, "username") == "alex@example.com" && str(it, "password") == "new-pass" }
        val history = (rec["password_history"] as JsonValue.Arr).items
        assertEquals("chrome-pass-1", str((history[0] as JsonValue.Obj).fields, "password"))
        assertEquals(now + 10, (rec["updated_at"] as JsonValue.Int).v)
    }

    @Test fun skip_duplicates_and_replace_all_apply_to_existing_rows_only() {
        val store = CountingStore()
        review(store, "chrome.csv", ImportFormat.CHROME).commit(store)
        val r = review(store, "chrome.csv", ImportFormat.CHROME)
        r.setAllExisting(ImportDecision.REPLACE)
        assertTrue(r.rows.filter { it.targetId != null }.all { it.decision == ImportDecision.REPLACE })
        r.setAllExisting(ImportDecision.SKIP)
        assertTrue(r.rows.all { it.decision == ImportDecision.SKIP })
    }

    @Test fun the_free_plan_limit_is_respected() {
        val store = CountingStore()
        val r = review(store, "bitwarden.json", ImportFormat.BITWARDEN, pro = false)
        assertEquals(4, r.freeSlots)
        assertTrue(r.rows.count { it.limited } > 0)
        assertTrue(r.limitNote.contains("need Pro"))
        val out = r.commit(store)
        assertTrue(out.limited > 0)
        assertEquals(4, store.snapshot.records.size)
        // Full now: a further import adds nothing.
        val more = review(store, "firefox.csv", ImportFormat.FIREFOX, pro = false)
        assertEquals(0, more.freeSlots)
        assertEquals(0, more.willImport)
    }

    @Test fun free_plan_keeps_two_factor_keys_as_hidden_fields() {
        val store = CountingStore()
        val r = review(store, "safari.csv", ImportFormat.APPLE_CSV, pro = false)
        val row = r.rows.single()
        assertEquals("", row.draft.totp)
        assertTrue(row.draft.customFields.any { it.hidden && it.name == "Two-factor key (needs Pro)" })
        r.commit(store)
        val rec = records(store).single()
        assertNull(rec["totp"])
        // On Pro the key becomes the item's 2FA.
        val pro = CountingStore()
        review(pro, "safari.csv", ImportFormat.APPLE_CSV, pro = true).commit(pro)
        assertEquals("JBSWY3DPEHPK3PXP", str((records(pro).single()["totp"] as JsonValue.Obj).fields, "secret"))
    }

    @Test fun bitwarden_cards_identities_and_notes_are_saved_as_phone_items() {
        val store = CountingStore()
        val r = review(store, "bitwarden.json", ImportFormat.BITWARDEN)
        r.commit(store)
        val kinds = records(store).mapNotNull { str(it, "kind") }.toSet()
        assertTrue("web" in kinds)
        assertTrue("note" in kinds)
        assertTrue(kinds.any { it == "card" || it == "identity" })
    }

    @Test fun onepassword_bare_export_data_imports() {
        val store = CountingStore()
        val r = review(store, "onepassword/export.data", ImportFormat.ONE_PASSWORD_1PUX)
        val out = r.commit(store)
        assertTrue(out.created > 0)
        assertEquals(1, store.commits)
    }

    @Test fun stale_target_is_refused() {
        val store = CountingStore()
        review(store, "chrome.csv", ImportFormat.CHROME).commit(store)
        val changed = "name,url,username,password\naccounts,https://accounts.example.com/,alex@example.com,new-pass\n".toByteArray()
        val r = ImportReview(ImportSource.candidates(changed, ImportFormat.CHROME), store.load(), true, TestClock(now), CountingRandom(), EnglishTxt())
        r.set(ImportDecision.REPLACE, r.rows.single().id)
        // Someone edits the login after the review.
        ImportReview(
            ImportSource.candidates("name,url,username,password\nx,https://accounts.example.com/,alex@example.com,third\n".toByteArray(), ImportFormat.CHROME),
            store.load(), true, TestClock(now + 1), CountingRandom(),
            EnglishTxt(),
        ).also { it.set(ImportDecision.REPLACE, it.rows.single().id) }.commit(store)
        val e = runCatching { r.commit(store) }.exceptionOrNull()
        assertTrue(e is ImportReviewException)
        assertEquals(ImportReviewException.Kind.TARGET_REVISION_CHANGED, (e as ImportReviewException).kind)
    }

    private fun flow(store: CountingStore, changed: () -> Unit = {}) =
        ImportFlow({ store }, { true }, TestClock(now), CountingRandom(), Dispatchers.Unconfined, EnglishTxt(), onChanged = changed)

    @Test fun flow_wrong_bitwarden_password_asks_again_then_opens() = runBlocking {
        val store = CountingStore()
        var changed = 0
        val f = flow(store) { changed++ }
        f.chose(fixture("bitwarden_protected.json"), "bitwarden_protected.json")
        assertEquals(ImportFlow.Step.PASSWORD, f.state.value.step)
        assertEquals(ImportFormat.BITWARDEN_ENCRYPTED, f.state.value.format)
        f.updatePassword("not the password")
        f.open()
        assertEquals(ImportFlow.Step.PASSWORD, f.state.value.step)
        assertEquals("Wrong password or corrupted export (MAC mismatch)", f.state.value.error)
        assertEquals("", f.password.value)
        f.updatePassword("fixture export password")
        f.open()
        assertEquals(ImportFlow.Step.REVIEW, f.state.value.step)
        assertTrue(f.commit())
        assertEquals(ImportFlow.Step.DONE, f.state.value.step)
        assertEquals(1, changed)
        assertEquals(1, store.commits)
        assertFalse(f.toString().contains("fixture export password"))
    }

    @Test fun flow_refuses_oversize_unknown_and_pc_only_files() = runBlocking {
        val f = flow(CountingStore())
        f.chose(ByteArray(ImportSource.MAX_ARCHIVE_BYTES + 1), "big.csv")
        assertEquals(EnglishTxt().s(ImportText.TOO_LARGE), f.state.value.error)
        assertEquals(ImportFlow.Step.CHOOSE, f.state.value.step)
        f.chose(byteArrayOf(0, 1, 2, 3), "x.bin")
        assertEquals(EnglishTxt().s(ImportText.NOT_RECOGNISED), f.state.value.error)
        f.chose(fixture("lastpass.csv"), "lastpass.csv")
        assertEquals(ImportText.unsupported(ImportFormat.LAST_PASS, EnglishTxt()), f.state.value.error)
        f.chose(null, "")
        assertEquals(EnglishTxt().s(ImportText.READ_FAILED), f.state.value.error)
    }

    @Test fun flow_generic_csv_asks_for_columns() = runBlocking {
        val store = CountingStore()
        val f = flow(store)
        f.chose("Site,Who,Secret\nhttps://a.example,alex,pw-a\n".toByteArray(), "other.csv")
        val s = f.state.value
        assertEquals(ImportFlow.Step.MAPPING, s.step)
        assertEquals(listOf("Site", "Who", "Secret"), s.header)
        // The Windows guess: "site" and "secret" are aliases, "who" is not.
        assertEquals(0, s.mapping.url)
        assertEquals(2, s.mapping.password)
        assertNull(s.mapping.username)
        f.choose(s.mapping.copy(username = 1))
        f.applyMapping()
        assertEquals(ImportFlow.Step.REVIEW, f.state.value.step)
        assertTrue(f.commit())
        val rec = records(store).single()
        assertEquals("pw-a", str(rec, "password"))
        assertNotNull(rec["scope"])
    }
}
