package app.localgatekeys.android.settings

import app.localgatekeys.android.i18n.appTxt
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.i18n.AndroidTxt
import android.os.Build
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performImeAction
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.performTextInput
import app.localgatekeys.android.backup.BackupText
import app.localgatekeys.android.backup.ExportFlow
import app.localgatekeys.android.backup.PhoneRestore
import app.localgatekeys.android.backup.RestoreAttempts
import app.localgatekeys.android.backup.RestoreFlow
import app.localgatekeys.android.detail.ClipboardSink
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.android.pro.ProModel
import app.localgatekeys.android.pro.ProOffer
import app.localgatekeys.android.pro.ProPurchasing
import app.localgatekeys.android.pro.PurchaseOutcome
import app.localgatekeys.android.ui.detail.CopyToast
import app.localgatekeys.android.ui.detail.DetailSeams
import app.localgatekeys.android.ui.editor.EditorSeams
import app.localgatekeys.android.ui.settings.BackupDocuments
import app.localgatekeys.android.ui.settings.BackupSeams
import app.localgatekeys.android.ui.settings.ExportBackupScreen
import app.localgatekeys.android.ui.settings.RestoreBackupScreen
import app.localgatekeys.android.ui.settings.SettingsSeams
import app.localgatekeys.android.ui.shell.RootScaffold
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.vault.VaultSeams
import app.localgatekeys.android.unlock.LockScheduler
import app.localgatekeys.android.unlock.LockTimer
import app.localgatekeys.android.vault.Copier
import app.localgatekeys.android.vault.VaultListModel
import app.localgatekeys.core.backup.PhoneBackupFormat
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.json.JsonValue.Obj
import app.localgatekeys.core.json.JsonValue.Str
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** The app's own English texts (the test device runs in English), resolved from the target app's resources. */
private val txt: Txt get() = AndroidTxt(androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext.resources)

/** Settings and the backup pages on the device, over fakes (no real picker, no Google Play, no real vault). */
class SettingsScreenTest {
    @get:Rule val rule = createComposeRule()

    private class FakePurchases : ProPurchasing {
        override suspend fun isEntitled() = false
        override suspend fun offer() = ProOffer.Available("$4.99")
        override suspend fun purchase() = PurchaseOutcome.PURCHASED
        override suspend fun restore() = false
        override suspend fun purchaseToken(): String? = null
        override fun entitlementChanges(): Flow<Unit> = emptyFlow()
    }

    private class FixedClock(override var now: Long) : UnixClock

    private class Counting : RandomSource {
        private var n = 0
        override fun bytes(count: Int): ByteArray = ByteArray(count) { (n++ and 0xff).toByte() }
    }

    private class MemorySink : ClipboardSink {
        var text: String? = null
        override fun set(text: String, sensitive: Boolean) { this.text = text }
        override fun current(): String? = text
        override fun clear() { text = null }
    }

    private object NoTimers : LockScheduler {
        override fun schedule(afterSeconds: Long, action: () -> Unit): LockTimer = object : LockTimer { override fun cancel() {} }
    }

    private class Store(var snapshot: StoreSnapshot = StoreSnapshot()) : ItemStore {
        var commits = 0
        override fun load() = snapshot
        override fun commit(change: StoreChange) {
            check(change.baseRevision == snapshot.revision)
            snapshot = StoreSnapshot(change.records, change.meta, change.sync, snapshot.revision + 1)
            commits++
        }
    }

    /** Records what the pages asked the pickers for; [opened] is what "open" returns. */
    private class FakeDocuments(var opened: ByteArray? = null) : BackupDocuments {
        var savedName: String? = null
        var savedBytes: ByteArray? = null
        override fun save(name: String, bytes: ByteArray, done: (Boolean?) -> Unit) {
            savedName = name; savedBytes = bytes; done(true)
        }
        override fun open(done: (ByteArray?) -> Unit) = done(opened)
    }

    private val clock = FixedClock(1_800_000_000)
    private val settings = AppSettings(MemoryStore())
    private val clipboard = SecretClipboard(MemorySink(), settings, NoTimers, clock).also { it.focusChanged(true) }
    private val toast = CopyToast(CopyToast.showsOwnMessage(Build.VERSION.SDK_INT))
    private val good = "correct horse battery staple 42"
    private val kdf = mapOf("time_cost" to 1, "memory_cost_kib" to 8192, "parallelism" to 1)
    private val otherPhone = "b2222222-0000-4000-8000-00000000000b"

    private val urls = ArrayList<String>()
    private var erased = 0
    private var locked = 0
    private var owner = false
    private var applied: Appearance? = null

    private fun seams() = SettingsSeams(
        lockNow = { locked++ },
        noteActivity = {},
        appearance = { applied = it },
        erase = { erased++ },
        autofill = AutofillStatusModel(isEnabled = { false }, open = { throw IllegalStateException("no service yet") }, t = txt),
        acknowledgements = { listOf(Acknowledgement("ZXing", "Apache-2.0", "Apache License text")) },
        version = "0.1.0 (1)",
        openUrl = { urls.add(it) },
        confirmOwner = { owner },
    )

    private fun backupSeams(store: Store) = BackupSeams(
        exporter = { error("not used") },
        restorer = { PhoneRestore(store, { false }, clock, installId = { "0123456789abcdef0123456789abcdef" }) },
        attempts = RestoreAttempts(clock),
        now = { clock.now },
        onPickerOpen = {},
        onPickerClose = { true },
    )

    private fun show(store: Store = Store()) {
        val model = VaultListModel(store, appTxt())
        val pro = ProModel(FakePurchases(), emptyMap(), txt = txt)
        val vault = VaultSeams(clipboard = Copier { _, _ -> }, isPro = { pro.isPro }, clock = clock)
        rule.setContent {
            LgkTheme {
                RootScaffold(
                    model, settings, vault, DetailSeams(clipboard, toast), EditorSeams(store, Counting()), pro = pro,
                    settingsSeams = seams(), backup = backupSeams(store),
                )
            }
        }
        rule.waitForIdle()
    }

    private fun scrollTo(tag: String) {
        rule.onNodeWithTag("settings-list").performScrollToNode(hasTestTag(tag))
    }

    private fun note(k: Int): Obj = Obj(
        mapOf(
            "id" to Str("00000000-0000-4000-8000-%012d".format(k)), "kind" to Str("note"), "title" to Str("Note $k"),
            "created_at" to JsonValue.Int(10), "updated_at" to JsonValue.Int(20L + k), "payload" to Obj(mapOf("body" to Str("b"))),
        ),
    )

    private fun backupFile(): ByteArray {
        val states = (1..3).map { k -> ItemState(note(k).fields["id"].let { (it as Str).v }, mapOf(otherPhone to 1L), false, null, Wrapper.make(Namespace.ITEM, note(k))) }
        return PhoneBackupFormat.write(states, good, otherPhone, "android", "1.0.0", clock.now, false, Counting(), kdf)
    }

    @Test fun settings_shows_every_section_with_the_iphone_copy() {
        show()
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithTag("settings").assertIsDisplayed()
        for (text in listOf("Security", "Auto-lock after leaving the app", "Lock when idle", "Clear clipboard after",
            "Hide passwords until tapped", "Show 2FA codes in the Codes row", "Lock now")) {
            rule.onNodeWithText(text).assertIsDisplayed()
        }
        scrollTo("settings-autofill")
        rule.onNodeWithText("Autofill service").assertIsDisplayed()
        rule.onNodeWithText("Off").assertIsDisplayed()
        rule.onNodeWithTag("settings-open-autofill").performClick()
        rule.onNodeWithText(txt.s(app.localgatekeys.android.R.string.autofill_open_failed)).assertExists()
        scrollTo("settings-backup")
        rule.onNodeWithText(BackupText(txt).export).assertExists()
        rule.onNodeWithText(BackupText(txt).restore).assertExists()
        scrollTo("settings-sync")
        rule.onNodeWithText("Not set up").assertExists()
        scrollTo("settings-pro")
        rule.onNodeWithText("Free (up to 4 items)").assertExists()
        rule.onNodeWithText("Upgrade").assertExists()
        rule.onNodeWithText("Restore purchases").assertExists()
        scrollTo("settings-about")
        rule.onNodeWithText("0.1.0 (1)").assertExists()
        rule.onNodeWithText(SettingsText(txt).dataNotCollected).assertExists()
        rule.onNodeWithTag("settings-privacy").performClick()
        rule.onNodeWithTag("settings-licence").performClick()
        assertEquals(listOf(SettingsText.PRIVACY_POLICY_URL, SettingsText.LICENCE_AGREEMENT_URL), urls)
        rule.onNodeWithTag("settings-acknowledgements").performClick()
        rule.onNodeWithText("ZXing").performClick()
        rule.onNodeWithText("Apache License text").assertIsDisplayed()
        rule.onNodeWithTag("licence-text-done").performClick()
        rule.onNodeWithTag("acknowledgements-done").performClick()
        scrollTo("settings-erase")
        rule.onNodeWithText(SettingsText(txt).eraseFooter).assertExists()
    }

    @Test fun choices_are_saved_and_initials_are_stored_on_done() {
        show()
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithContentDescription("Auto-lock after leaving the app: Immediately").performClick()
        rule.onNodeWithText("After 5 minutes").performClick()
        assertEquals(AutoLockDelay.FIVE_MINUTES, settings.autoLockDelay)
        rule.onNodeWithText("Hide passwords until tapped").performClick()
        assertEquals(false, settings.concealSecretsInDetail)
        scrollTo("settings-appearance")
        rule.onNodeWithTag("appearance-dark").performClick()
        assertEquals(Appearance.DARK, settings.appearance)
        assertEquals(Appearance.DARK, applied)
        rule.onNodeWithTag("settings-initials").performTextInput("John Doe")
        assertEquals("nothing stored while typing", "", settings.initials)
        rule.onNodeWithTag("settings-initials").performImeAction()
        assertEquals("JD", settings.initials)
        rule.onNodeWithTag("settings-done").performClick()
        rule.onNodeWithText("JD").assertIsDisplayed() // the avatar button
        rule.onNodeWithText("Lock now").assertDoesNotExist()
    }

    @Test fun lock_now_and_erase_after_two_confirmations() {
        show()
        rule.onNodeWithContentDescription("Settings").performClick()
        scrollTo("settings-erase")
        rule.onNodeWithTag("settings-erase-button").performClick()
        rule.onNodeWithText(appTxt().s(app.localgatekeys.android.unlock.VaultEraser.CONFIRM_TEXT_1)).assertIsDisplayed()
        rule.onNodeWithTag("erase-confirm").performClick()
        rule.onNodeWithText(appTxt().s(app.localgatekeys.android.unlock.VaultEraser.CONFIRM_TEXT_2)).assertIsDisplayed()
        assertEquals(0, erased)
        rule.onNodeWithTag("erase-confirm").performClick()
        rule.waitForIdle()
        assertEquals(1, erased)
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithText("Lock now").performClick()
        assertEquals(1, locked)
    }

    @Test fun sync_row_opens_the_sync_tab_where_leave_and_reset_live() {
        show()
        rule.onNodeWithContentDescription("Settings").performClick()
        scrollTo("settings-sync")
        rule.onNodeWithTag("settings-sync-row").performClick()
        rule.onNodeWithText("Sync with your PC.").assertIsDisplayed() // the Sync tab (no coordinator in this test)
        assertTrue(rule.onAllNodesWithTag("settings").fetchSemanticsNodes().isEmpty())
    }

    @Test fun export_asks_for_a_fresh_unlock_first() {
        show()
        rule.onNodeWithContentDescription("Settings").performClick()
        scrollTo("settings-backup")
        owner = false
        rule.onNodeWithTag("settings-export").performClick()
        rule.waitForIdle()
        assertTrue(rule.onAllNodesWithTag("export-backup").fetchSemanticsNodes().isEmpty())
        owner = true
        rule.onNodeWithTag("settings-export").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("export-backup").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithText(BackupText(txt).exportHint).assertIsDisplayed()
        rule.onNodeWithTag("export-backup-close").performClick()
        rule.onNodeWithTag("settings").assertIsDisplayed()
    }

    @Test fun the_empty_vault_offers_restore_from_a_backup() {
        show()
        rule.onNodeWithTag("empty-vault-restore").performClick()
        rule.onNodeWithTag("restore-backup").assertIsDisplayed()
        rule.onNodeWithText(BackupText(txt).choose).assertIsDisplayed()
        rule.onNodeWithTag("restore-backup-close").performClick()
        rule.onNodeWithTag("empty-vault").assertIsDisplayed()
    }

    @Test fun restore_page_previews_then_restores() {
        val store = Store()
        val docs = FakeDocuments(backupFile())
        val restore = PhoneRestore(store, { false }, clock, installId = { "0123456789abcdef0123456789abcdef" })
        val flow = RestoreFlow(RestoreAttempts(clock), { restore }, Dispatchers.IO, txt)
        var restored = 0
        rule.setContent { LgkTheme { RestoreBackupScreen(flow, docs, onRestored = { restored++ }, onClose = {}) } }
        rule.onNodeWithTag("restore-choose").performClick()
        rule.onNodeWithText("Made on an Android phone on 2027-01-15.").assertIsDisplayed()
        rule.onNodeWithTag("restore-password").performTextInput("wrong")
        rule.onNodeWithTag("restore-backup-action").performClick()
        rule.waitUntil(20_000) { rule.onAllNodesWithText("Wrong password, or the file is damaged.").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithTag("restore-password").performTextInput(good)
        rule.onNodeWithTag("restore-backup-action").performClick()
        rule.waitUntil(20_000) { rule.onAllNodesWithText(BackupText(txt).previewReady).fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithText("3 new items").assertIsDisplayed()
        assertEquals(0, store.commits)
        rule.onNodeWithText(BackupText(txt).restoreButton).performClick()
        rule.waitUntil(20_000) { rule.onAllNodesWithText("Phone backup restored.").fetchSemanticsNodes().isNotEmpty() }
        assertEquals(1, store.commits)
        assertEquals(3, store.snapshot.records.size)
        assertEquals(1, restored)
    }

    @Test fun export_page_checks_the_password_and_saves_through_the_picker() {
        val store = Store(StoreSnapshot(mapOf((note(1).fields["id"] as Str).v to Wrapper.make(Namespace.ITEM, note(1)))))
        val docs = FakeDocuments()
        val exporter = app.localgatekeys.android.backup.BackupExporter(
            store, clock, Counting(), "0.1.0", installId = { "0123456789abcdef0123456789abcdef" }, kdf = kdf,
        )
        val flow = ExportFlow({ pw -> app.localgatekeys.android.backup.BackupExport(exporter.export(pw)) }, Dispatchers.IO, txt)
        rule.setContent { LgkTheme { ExportBackupScreen(flow, docs, fileName = { BackupText.fileName(clock.now) }, onClose = {}) } }
        rule.onNodeWithTag("export-password").performTextInput("short")
        rule.onNodeWithTag("export-confirm").performTextInput("short")
        rule.onNodeWithTag("export-backup-action").performClick()
        rule.onNodeWithText("Use at least 12 characters.").assertIsDisplayed()
        assertEquals(null, docs.savedBytes)
        rule.onNodeWithTag("export-password").performTextInput(" and more words 42")
        rule.onNodeWithTag("export-confirm").performTextInput(" and more words 42")
        rule.onNodeWithTag("export-backup-action").performClick()
        rule.waitUntil(20_000) { rule.onAllNodesWithText(BackupText(txt).saved).fetchSemanticsNodes().isNotEmpty() }
        assertTrue(docs.savedName!!.matches(Regex("LocalGateKeys-Backup-\\d{4}-\\d{2}-\\d{2}\\.lgkm")))
        val back = PhoneBackupFormat.read(docs.savedBytes!!, "short and more words 42")
        assertEquals(listOf((note(1).fields["id"] as Str).v), back.states.map { it.itemId })
        assertTrue(rule.onAllNodesWithTag("export-password").fetchSemanticsNodes().isEmpty())
        assertTrue(rule.onAllNodes(hasText("short and more words 42")).fetchSemanticsNodes().isEmpty())
    }
}
