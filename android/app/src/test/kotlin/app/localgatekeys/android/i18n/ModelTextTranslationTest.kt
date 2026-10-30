package app.localgatekeys.android.i18n

import app.localgatekeys.android.R
import app.localgatekeys.android.backup.BackupText
import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.importing.ImportReview
import app.localgatekeys.android.sync.SyncWording
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.importing.ImportFormat
import app.localgatekeys.core.importing.ImportOptions
import app.localgatekeys.core.importing.ImportSource
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.sync.SyncIssue
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Task 2b: the text models show their text through [Txt] (here a stand-in for another language that prefixes "DE:"),
 * keep their rules on stable codes, and write nothing translated into data.
 */
class ModelTextTranslationTest {
    private val en = EnglishTxt()
    private val de = object : Txt {
        override fun s(id: Int, vararg args: Any) = "DE:" + en.s(id, *args)
        override fun plural(id: Int, count: Int, vararg args: Any) = "DE:" + en.plural(id, count, *args)
    }
    private val now = 1_800_000_000L

    private fun json(store: CountingStore): String =
        store.snapshot.records.values.joinToString("\n") { String(CanonicalJson.encode(it, Dialect.UTF8), Charsets.UTF_8) }

    @Test fun an_import_made_in_another_language_stores_english_data_and_shows_translated_notes() {
        val repo = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot is not set"))
        val bytes = File(repo, "tests/fixtures/imports/chrome.csv").readBytes()
        val store = CountingStore()
        val review = ImportReview(ImportSource.candidates(bytes, ImportFormat.CHROME, ImportOptions(null)), store.load(), true, TestClock(now), CountingRandom(), de)
        // What the person reads follows the language ...
        assertTrue(review.summary, review.summary.startsWith("DE:"))
        assertTrue(review.issues.isNotEmpty() && review.issues.all { it.startsWith("DE:") })
        assertEquals("DE:Keep both", de.s(R.string.incoming_sheet_keep_both))
        review.commit(store)
        // ... and what is stored does not: no UI text reached any record, and the kept copy has the fixed English suffix.
        val stored = json(store)
        assertFalse(stored, stored.contains("DE:"))
        assertTrue(stored, stored.contains("(imported copy)"))
    }

    @Test fun the_editor_tells_the_pro_message_by_flag_and_stores_no_ui_text() {
        val store = CountingStore()
        val e = EditorModel(store, null, EditorKind.WEB, { false }, TestClock(now), CountingRandom(), de)
        e.set("label", "Shop"); e.set("origin", "https://shop.example"); e.set("totp", "JBSWY3DPEHPK3PXP")
        assertEquals(SaveResult.NEEDS_PRO, e.save())
        assertTrue(e.totpErrorIsPro)
        assertTrue(e.totpError!!.startsWith("DE:"))
        assertEquals(0, store.commits)
        // The person edits the field: the Pro flag goes with the message, whatever language it was in.
        e.set("totp", "")
        assertFalse(e.totpErrorIsPro)
        assertEquals(SaveResult.SAVED, e.save())
        assertFalse(json(store).contains("DE:"))
        // A refused amount and a refused website are shown translated but never kept.
        val p = EditorModel(CountingStore(), null, EditorKind.PURCHASE, { true }, TestClock(now), CountingRandom(), de)
        p.set("title", "Laptop"); p.set("amount_minor", "abc")
        assertEquals(SaveResult.INVALID, p.save())
        assertEquals("DE:Enter the amount as a number, for example 12.99.", p.amountError)
    }

    @Test fun kind_labels_and_new_item_titles_follow_the_language_but_unknown_kinds_show_their_raw_name() {
        assertEquals("DE:Website login", VaultItem.kindLabel("web", de))
        assertEquals("DE:New wi-fi network", de.s(EditorKind.WIFI.newTitle))
        assertEquals("Mystery box", VaultItem.kindLabel("mystery_box", de))
        assertEquals("DE:Item", VaultItem.kindLabel("", de))
    }

    @Test fun a_backup_read_failure_is_mapped_from_its_reason_code_to_translated_text() {
        val reasons = listOf(
            "not-a-backup" to "This is not a LocalGateKeys phone backup.",
            "unsupported-version" to "This backup was made by a newer version of LocalGateKeys. Update the app and try again.",
            "bad-kdf" to "This backup uses unsupported password-protection settings.",
            "wrong-password-or-damaged" to "Wrong password, or the file is damaged.",
            "bad-payload" to "The backup was opened but its contents are not valid.",
            "too-large" to "This file is too large to be a phone backup.",
        )
        for ((reason, english) in reasons) {
            assertEquals(reason, english, BackupText(en).failure(reason))
            assertEquals(reason, "DE:$english", BackupText(de).failure(reason))
        }
        assertEquals("DE:The backup could not be read.", BackupText(de).failure("something-new"))
    }

    @Test fun sync_issue_text_follows_the_language_while_the_keyring_device_name_does_not() {
        val words = SyncWording(de)
        assertTrue(words.text(SyncIssue("keyring-missing")).startsWith("DE:"))
        assertTrue(words.errorText("password").startsWith("DE:"))
        assertTrue(words.views(listOf(SyncIssue("busy"))).single().text.startsWith("DE:"))
        assertEquals("Android phone", SyncWording.DEVICE_NAME)
        assertNotEquals(SyncWording.DEVICE_NAME, de.s(R.string.sync_this_device))
    }

    @Test fun a_record_saved_in_another_language_holds_only_what_the_person_typed() {
        val store = CountingStore()
        val e = EditorModel(store, null, EditorKind.WIFI, { true }, TestClock(now), CountingRandom(), de)
        e.set("title", "Home"); e.set("ssid", "Home Wi-Fi"); e.set("password", "secret-pass")
        assertEquals(SaveResult.SAVED, e.save())
        val stored = json(store)
        assertFalse(stored, stored.contains("DE:"))
        assertTrue(stored, stored.contains("\"security\":\"wpa2\""))
    }

    @Test fun plural_resources_pick_the_one_form_in_english() {
        assertEquals("1 device", en.plural(R.plurals.sync_pill_devices, 1, 1))
        assertEquals("3 devices", en.plural(R.plurals.sync_pill_devices, 3, 3))
        assertEquals("Use at most 1 decimal.", en.plural(R.plurals.amount_max_decimals, 1, 1))
    }
}
