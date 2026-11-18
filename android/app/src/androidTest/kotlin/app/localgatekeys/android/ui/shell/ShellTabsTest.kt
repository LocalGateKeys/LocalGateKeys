package app.localgatekeys.android.ui.shell

import android.os.Build
import android.view.View
import androidx.activity.findViewTreeOnBackPressedDispatcherOwner
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsFocused
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performImeAction
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import app.localgatekeys.android.detail.ClipboardSink
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.android.i18n.appTxt
import app.localgatekeys.android.security.SecurityCheckModel
import app.localgatekeys.android.security.SecurityPrefs
import app.localgatekeys.android.settings.Acknowledgement
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.AutofillStatusModel
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.trash.InMemoryLocalData
import app.localgatekeys.android.trash.PhoneTrash
import app.localgatekeys.android.trash.UndoToast
import app.localgatekeys.android.ui.detail.CopyToast
import app.localgatekeys.android.ui.detail.DetailSeams
import app.localgatekeys.android.ui.editor.EditorSeams
import app.localgatekeys.android.ui.settings.SettingsSeams
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.trash.UndoToastHost
import app.localgatekeys.android.ui.vault.VaultSeams
import app.localgatekeys.android.unlock.LockScheduler
import app.localgatekeys.android.unlock.LockTimer
import app.localgatekeys.android.vault.Copier
import app.localgatekeys.android.vault.VaultListModel
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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * The iPhone shell on the device (UX workstream 1): four tabs, the Vault tab's search button and its search page, Back,
 * the `>` actions that leave the Vault tab, and a reminder tap opening its item. Over fakes (no real vault).
 */
class ShellTabsTest {
    @get:Rule val rule = createComposeRule()

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

    private class Store(var snapshot: StoreSnapshot) : ItemStore {
        override fun load() = snapshot
        override fun commit(change: StoreChange) {
            check(change.baseRevision == snapshot.revision)
            snapshot = StoreSnapshot(change.records, change.meta, change.sync, snapshot.revision + 1)
        }
    }

    private val txt = appTxt()
    private val clock = FixedClock(1_800_000_000)
    private val settings = AppSettings(MemoryStore())
    private val clipboard = SecretClipboard(MemorySink(), settings, NoTimers, clock).also { it.focusChanged(true) }
    private val toast = CopyToast(CopyToast.showsOwnMessage(Build.VERSION.SDK_INT))
    private var locked = 0

    private fun note(n: Int, title: String) = Obj(
        mapOf(
            "id" to Str("00000000-0000-4000-8000-00000000000$n"), "kind" to Str("note"), "title" to Str(title),
            "created_at" to JsonValue.Int(1), "updated_at" to JsonValue.Int(2L + n), "favorite" to JsonValue.Bool(false),
            "tags" to JsonValue.Arr(emptyList()), "payload" to Obj(mapOf("body" to Str("b"))),
        ),
    )

    private fun store() = Store(
        StoreSnapshot(listOf(note(1, "Example note"), note(2, "Garage code")).associate { (it.fields["id"] as Str).v to Wrapper.make(Namespace.ITEM, it) }),
    )

    private fun settingsSeams() = SettingsSeams(
        lockNow = { locked++ },
        noteActivity = {},
        appearance = {},
        erase = {},
        autofill = AutofillStatusModel(isEnabled = { false }, open = {}, t = txt),
        acknowledgements = { listOf(Acknowledgement("ZXing", "Apache-2.0", "text")) },
        version = "0.1.0 (1)",
        openUrl = {},
        confirmOwner = { true },
    )

    private var view: View? = null

    private fun show(store: Store = store(), openItems: Flow<String>? = null) {
        val model = VaultListModel(store, txt)
        val seams = VaultSeams(clipboard = Copier { _, _ -> }, clock = clock)
        val undo = UndoToast()
        val trash = PhoneTrash(InMemoryLocalData(), store, isPro = { true }, clock = clock, t = txt, attachments = null)
        val security = SecurityCheckModel(store, SecurityPrefs(MemoryStore()), clock, CoroutineScope(SupervisorJob()), { 4 })
        rule.setContent {
            view = LocalView.current
            LgkTheme {
                UndoToastHost(undo) {
                    RootScaffold(
                        model, settings, seams, DetailSeams(clipboard, toast),
                        EditorSeams(store, Counting(), trash = trash, undo = undo),
                        settingsSeams = settingsSeams(),
                        security = security, securityPrefs = SecurityPrefs(MemoryStore()),
                        openItemRequests = openItems,
                    )
                }
            }
        }
        rule.waitUntil(5_000) { !gone("vault-row") || !gone("item-detail") }
    }

    /** System back, through the activity's dispatcher (what the back gesture or key calls). */
    private fun systemBack() {
        rule.runOnUiThread { view!!.findViewTreeOnBackPressedDispatcherOwner()!!.onBackPressedDispatcher.onBackPressed() }
        rule.waitForIdle()
    }

    private fun gone(tag: String) = rule.onAllNodesWithTag(tag).fetchSemanticsNodes().isEmpty()

    @Test fun four_tabs_and_back_on_another_tab_returns_to_the_vault() {
        show()
        for (name in listOf("Vault", "Sync", "Security", "Settings")) rule.onNodeWithContentDescription(name).assertIsDisplayed()
        rule.onNodeWithTag("tab-vault").assertIsSelected()
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithTag("settings-list").assertIsDisplayed()
        // No avatar or gear in the header any more: Settings is only the tab.
        assertTrue(gone("vault-search-button"))
        rule.onNodeWithContentDescription("Security").performClick()
        rule.onNodeWithTag("security-check").assertIsDisplayed()
        systemBack()
        rule.onNodeWithTag("tab-vault").assertIsSelected()
        rule.onNodeWithTag("vault-search-button").assertIsDisplayed()
    }

    /**
     * Release check 2026-11-01: a Security row opened a list whose glass back arrow sat inside the tabs' glass backdrop
     * (it sampled the layer it was drawn into) and the RenderThread crashed. Every row must open, draw and close.
     */
    @Test fun every_security_row_opens_its_list_and_draws() {
        show()
        rule.onNodeWithContentDescription("Security").performClick()
        for (row in listOf("breached", "reused", "weak", "old", "noTwoFactor")) {
            rule.onNodeWithTag("security-row-$row").performClick()
            rule.onNodeWithTag("security-back").assertIsDisplayed()
            // Let the RenderThread draw the list a few times (the crash came on the first frames).
            rule.mainClock.advanceTimeBy(500)
            rule.waitForIdle()
            rule.onNodeWithTag("security-back").performClick()
            rule.onNodeWithTag("security-row-$row").assertIsDisplayed()
        }
    }

    @Test fun the_search_button_opens_the_search_focused_and_back_or_the_arrow_closes_it() {
        show()
        rule.onNodeWithTag("vault-search-button").performClick()
        rule.onNodeWithTag("search-page").assertIsDisplayed()
        rule.waitUntil(5_000) { runCatching { rule.onNodeWithTag("search-field").assertIsFocused() }.isSuccess }
        assertTrue("no tab bar over the search", gone("tab-bar"))
        // While empty: the recently changed items.
        rule.onNodeWithText(txt.s(app.localgatekeys.android.R.string.search_recent_items)).assertIsDisplayed()
        rule.onNodeWithTag("search-field").performTextInput("garage")
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().size == 1 }
        systemBack()
        assertTrue(gone("search-page"))
        rule.onNodeWithTag("tab-bar").assertIsDisplayed()
        // Opened again: an empty field, and the last search listed as a recent search.
        rule.onNodeWithTag("vault-search-button").performClick()
        rule.onNodeWithTag("search-field").assertTextEquals("")
        rule.onNodeWithText("garage").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().size == 1 }
        rule.onNodeWithTag("search-back").performClick()
        assertTrue(gone("search-page"))
    }

    @Test fun an_item_opened_from_the_search_returns_to_the_search() {
        show()
        rule.onNodeWithTag("vault-search-button").performClick()
        rule.onNodeWithTag("search-field").performTextInput("garage")
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().size == 1 }
        rule.onNodeWithTag("vault-row").performClick()
        rule.onNodeWithTag("item-detail").assertIsDisplayed()
        systemBack()
        rule.onNodeWithTag("search-page").assertIsDisplayed()
        rule.onNodeWithTag("search-field").assertTextEquals("garage")
    }

    @Test fun actions_open_the_security_tab_recently_deleted_and_settings() {
        show()
        rule.onNodeWithTag("vault-search-button").performClick()
        rule.onNodeWithTag("search-field").performTextInput(">security")
        rule.onNodeWithText("Security check").performClick()
        rule.onNodeWithTag("security-check").assertIsDisplayed()
        assertTrue(gone("search-page"))

        rule.onNodeWithContentDescription("Vault").performClick()
        rule.onNodeWithTag("vault-search-button").performClick()
        rule.onNodeWithTag("search-field").performTextInput(">deleted")
        rule.onNodeWithText(txt.s(app.localgatekeys.android.R.string.trash_title)).performClick()
        rule.onNodeWithTag("recently-deleted").assertIsDisplayed()
        systemBack()
        assertTrue(gone("recently-deleted"))

        rule.onNodeWithTag("vault-search-button").performClick()
        rule.onNodeWithTag("search-field").performTextInput(">")
        // Return runs the first listed action (New website login): the editor opens.
        rule.onNodeWithTag("search-field").performImeAction()
        rule.onNodeWithTag("editor").assertIsDisplayed()
    }

    @Test fun lock_now_and_settings_from_the_actions() {
        show()
        rule.onNodeWithTag("vault-search-button").performClick()
        rule.onNodeWithTag("search-field").performTextInput(">preferences")
        rule.onNodeWithText("Settings").performClick()
        rule.onNodeWithTag("settings-list").assertIsDisplayed()
        // Settings opens on its categories; Lock now is on the Lock & security page.
        rule.onNodeWithTag("settings-category-lock").performClick()
        rule.onNodeWithTag("settings-list").performScrollToNode(hasText("Lock now"))
        rule.onNodeWithText("Lock now").performClick()
        assertEquals(1, locked)
    }

    @Test fun a_reminder_tap_opens_its_item() {
        val requests = MutableSharedFlow<String>(replay = 1)
        requests.tryEmit("00000000-0000-4000-8000-000000000002")
        show(openItems = requests)
        rule.waitUntil(5_000) { !gone("item-detail") }
        rule.onAllNodesWithText("Garage code").onFirst().assertIsDisplayed()
        systemBack()
        rule.onNodeWithTag("tab-vault").assertIsSelected()
    }

    @Test fun recently_deleted_is_a_settings_row() {
        show()
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithTag("settings-category-sync").performClick()
        rule.onNodeWithTag("settings-list").performScrollToNode(hasTestTag("settings-recently-deleted"))
        rule.onNodeWithTag("settings-recently-deleted").performClick()
        rule.onNodeWithTag("recently-deleted").assertIsDisplayed()
        rule.onNodeWithTag("recently-deleted-done").performClick()
        rule.onNodeWithTag("settings-list").assertIsDisplayed()
    }
}
