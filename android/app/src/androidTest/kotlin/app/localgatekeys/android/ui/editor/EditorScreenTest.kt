package app.localgatekeys.android.ui.editor

import android.os.Build
import android.text.InputType
import android.view.View
import android.view.inputmethod.EditorInfo
import androidx.activity.findViewTreeOnBackPressedDispatcherOwner
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertContentDescriptionEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.text.TextLayoutResult
import app.localgatekeys.android.detail.ClipboardSink
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.ui.detail.CopyToast
import app.localgatekeys.android.ui.detail.DetailSeams
import app.localgatekeys.android.ui.input.NoPersonalisedLearning
import app.localgatekeys.android.ui.shell.RootScaffold
import app.localgatekeys.android.ui.theme.LgkTheme
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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** The editor through RootScaffold: open from the detail, masked secrets, save and delete through the store, autofill off. */
class EditorScreenTest {
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
        var commits = 0
        override fun load() = snapshot
        override fun commit(change: StoreChange) {
            check(change.baseRevision == snapshot.revision)
            snapshot = StoreSnapshot(change.records, change.meta, change.sync, snapshot.revision + 1)
            commits++
        }
    }

    private fun obj(vararg f: Pair<String, JsonValue>) = Obj(mapOf(*f))

    private val web = obj(
        "id" to Str("w1"), "kind" to Str("web"), "label" to Str("Example account"), "username" to Str("sam@example.com"),
        "password" to Str("Maple-Orbit-7731"), "scope" to obj("origin" to Str("https://accounts.example.com")),
        "created_at" to JsonValue.Int(10), "updated_at" to JsonValue.Int(20),
    )
    private val desk = obj(
        "id" to Str("d1"), "kind" to Str("desktop"), "label" to Str("Mail client"), "username" to Str("sam"),
        "password" to Str("desk-pass"), "scope" to obj("exe_path" to Str("C:/Mail/mail.exe")), "updated_at" to JsonValue.Int(15),
    )
    private val clock = FixedClock(1_800_000_000)
    private val settings = AppSettings(MemoryStore())
    private val sink = MemorySink()
    private val clipboard = SecretClipboard(sink, settings, NoTimers, clock).also { it.focusChanged(true) }
    private val toast = CopyToast(CopyToast.showsOwnMessage(Build.VERSION.SDK_INT))

    private fun show(store: Store, captureView: ((View) -> Unit)? = null) {
        val model = VaultListModel(store)
        val seams = VaultSeams(clipboard = Copier { _, _ -> }, clock = clock)
        val editor = EditorSeams(store, Counting())
        rule.setContent {
            LgkTheme {
                val view = LocalView.current
                captureView?.invoke(view)
                NoPersonalisedLearning { RootScaffold(model, settings, seams, DetailSeams(clipboard, toast), editor) }
            }
        }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().isNotEmpty() }
    }

    /** The text as laid out on screen (after any visual transformation). */
    private fun shown(tag: String): String {
        val results = mutableListOf<TextLayoutResult>()
        rule.onNodeWithTag(tag).fetchSemanticsNode().config[SemanticsActions.GetTextLayoutResult].action?.invoke(results)
        return results.first().layoutInput.text.text
    }

    private fun stored(store: Store, id: String): Map<String, JsonValue> =
        ((store.snapshot.records.getValue(id) as Obj).fields["record"] as Obj).fields

    @Test fun edit_from_the_detail_masks_the_password_and_saves_through_the_store() {
        val store = Store(StoreSnapshot(mapOf("w1" to Wrapper.make(Namespace.ENTRY, web))))
        show(store)
        rule.onNodeWithTag("vault-row").performClick()
        rule.onNodeWithText("Edit").performClick()
        rule.onNodeWithTag("editor").assertIsDisplayed()
        rule.onNodeWithText("Edit website login").assertIsDisplayed()
        // The password shows as dots until revealed.
        val dots = "•".repeat("Maple-Orbit-7731".length)
        assertEquals(dots, shown("editor-value-password"))
        rule.onNodeWithTag("editor-reveal-password").assertContentDescriptionEquals("Reveal").performClick()
        assertEquals("Maple-Orbit-7731", shown("editor-value-password"))
        rule.onNodeWithTag("editor-reveal-password").assertContentDescriptionEquals("Hide").performClick()
        assertEquals(dots, shown("editor-value-password"))
        rule.onNodeWithTag("editor-value-label").performTextClearance()
        rule.onNodeWithTag("editor-value-label").performTextInput("Renamed")
        rule.onNodeWithText("Save").performClick()
        rule.waitUntil(5_000) { store.commits == 1 }
        assertEquals(Str("Renamed"), stored(store, "w1")["label"])
        assertEquals(JsonValue.Int(clock.now), stored(store, "w1")["updated_at"])
        // Saved: the editor and the detail close, back to the list.
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("editor").fetchSemanticsNodes().isEmpty() }
        rule.onNodeWithTag("item-detail").assertDoesNotExist()
        rule.waitUntil(5_000) { rule.onAllNodesWithText("Renamed").fetchSemanticsNodes().isNotEmpty() }
    }

    /**
     * Ruling 15: a focused field asks the keyboard not to learn. Read the EditorInfo the focused field produces by asking
     * the Compose view for its input connection, as the system does when the keyboard attaches.
     */
    @Test fun focused_fields_ask_the_keyboard_not_to_learn() {
        val store = Store(StoreSnapshot(mapOf("w1" to Wrapper.make(Namespace.ENTRY, web))))
        var view: View? = null
        show(store) { view = it }
        rule.onNodeWithTag("vault-row").performClick()
        rule.onNodeWithText("Edit").performClick()
        for (tag in listOf("editor-value-label", "editor-value-password")) {
            rule.onNodeWithTag(tag).performClick()
            rule.waitForIdle()
            val info = EditorInfo()
            rule.runOnUiThread { assertNotNull(tag, view!!.onCreateInputConnection(info)) }
            assertTrue(tag, info.imeOptions and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0)
        }
        // The password field also takes the password keyboard.
        val info = EditorInfo()
        rule.runOnUiThread { view!!.onCreateInputConnection(info) }
        assertEquals(InputType.TYPE_TEXT_VARIATION_PASSWORD, info.inputType and InputType.TYPE_MASK_VARIATION)
    }

    @Test fun a_bad_website_shows_the_inline_error_and_writes_nothing() {
        val store = Store(StoreSnapshot(mapOf("w1" to Wrapper.make(Namespace.ENTRY, web))))
        show(store)
        rule.onNodeWithTag("vault-row").performClick()
        rule.onNodeWithText("Edit").performClick()
        rule.onNodeWithTag("editor-value-origin").performTextClearance()
        rule.onNodeWithTag("editor-value-origin").performTextInput("not a site")
        rule.onNodeWithText("Save").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("editor-website-error").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithText("Enter a website like github.com").assertIsDisplayed()
        rule.onNodeWithTag("editor-error").performScrollTo().assertTextEquals("Check the website.")
        assertEquals(0, store.commits)
    }

    @Test fun delete_item_asks_then_removes_it() {
        val store = Store(StoreSnapshot(mapOf("w1" to Wrapper.make(Namespace.ENTRY, web))))
        show(store)
        rule.onNodeWithTag("vault-row").performClick()
        rule.onNodeWithText("Edit").performClick()
        rule.onNodeWithText("Delete item").performScrollTo().performClick()
        rule.onNodeWithText("Delete this item?").assertIsDisplayed()
        rule.onNodeWithText("It is removed from this phone and from your other devices at the next sync.").assertIsDisplayed()
        rule.onNodeWithTag("confirm-delete").performClick()
        rule.waitUntil(5_000) { store.commits == 1 }
        assertNull(store.snapshot.records["w1"])
        rule.waitUntil(5_000) { rule.onAllNodesWithText("No items yet. Tap + to add one.").fetchSemanticsNodes().isNotEmpty() }
    }

    @Test fun a_desktop_login_offers_delete_only() {
        val store = Store(StoreSnapshot(mapOf("d1" to Wrapper.make(Namespace.ENTRY, desk))))
        show(store)
        rule.onNodeWithTag("vault-row").performClick()
        rule.onNodeWithText("Edit").assertDoesNotExist()
        rule.onNodeWithText("Delete").performClick()
        rule.onNodeWithText(
            "It is removed from this phone and from your other devices at the next sync. It can only be edited on your PC.",
        ).assertIsDisplayed()
        rule.onNodeWithTag("confirm-delete").performClick()
        rule.waitUntil(5_000) { store.commits == 1 }
        assertTrue(store.snapshot.records.isEmpty())
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("item-detail").fetchSemanticsNodes().isEmpty() }
    }

    @Test fun the_plus_menu_opens_a_new_note_and_saves_it() {
        val store = Store(StoreSnapshot(mapOf("w1" to Wrapper.make(Namespace.ENTRY, web))))
        show(store)
        rule.onNodeWithContentDescription("New item").performClick()
        rule.onNodeWithText("Note").performClick()
        rule.onNodeWithText("New note").assertIsDisplayed()
        rule.onNodeWithTag("editor-value-title").performTextInput("Groceries")
        rule.onNodeWithTag("editor-value-body").performTextInput("milk")
        rule.onNodeWithText("Save").performClick()
        rule.waitUntil(5_000) { store.commits == 1 }
        rule.waitUntil(5_000) { rule.onAllNodesWithText("Groceries").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithTag("editor").assertDoesNotExist()
    }

    /** The value as the generator's hero card shows it. */
    private fun generated(): String = rule.onNodeWithTag("generator-value", useUnmergedTree = true).fetchSemanticsNode()
        .config[androidx.compose.ui.semantics.SemanticsProperties.Text].joinToString("") { it.text }

    @Test fun the_wand_opens_the_generator_and_use_puts_the_value_in_the_password_field() {
        val store = Store(StoreSnapshot(mapOf("w1" to Wrapper.make(Namespace.ENTRY, web))))
        show(store)
        rule.onNodeWithTag("vault-row").performClick()
        rule.onNodeWithText("Edit").performClick()
        rule.onNodeWithContentDescription("Generate password").performClick()
        rule.onNodeWithTag("generator").assertIsDisplayed()
        rule.onNodeWithText("Generator").assertIsDisplayed()
        rule.waitUntil(5_000) { generated().isNotEmpty() }
        assertEquals(20, generated().length)
        rule.onNodeWithContentDescription("Strength: Very strong").assertIsDisplayed()
        // Passphrase mode: six words joined by dashes, and the choice is saved for next time.
        rule.onNodeWithTag("generator-mode-passphrase").performClick()
        rule.waitUntil(5_000) { generated().split("-").size == 6 }
        assertTrue(settings.generatorOptions!!.contains("\"mode\":\"passphrase\""))
        rule.onNodeWithTag("generator-mode-password").performClick()
        rule.waitUntil(5_000) { generated().length == 20 }
        val value = generated()
        rule.onNodeWithTag("generator-use").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("generator").fetchSemanticsNodes().isEmpty() }
        // Back in the editor, with the draft kept and the password replaced; nothing went through the clipboard.
        rule.onNodeWithTag("editor").assertIsDisplayed()
        rule.onNodeWithTag("editor-reveal-password").performClick()
        rule.waitUntil(5_000) { shown("editor-value-password") == value }
        assertNull(sink.text)
        rule.onNodeWithText("Save").performClick()
        rule.waitUntil(5_000) { store.commits == 1 }
        assertEquals(Str(value), stored(store, "w1")["password"])
    }

    @Test fun cancel_closes_the_generator_and_keeps_the_password() {
        val store = Store(StoreSnapshot(mapOf("w1" to Wrapper.make(Namespace.ENTRY, web))))
        show(store)
        rule.onNodeWithTag("vault-row").performClick()
        rule.onNodeWithText("Edit").performClick()
        rule.onNodeWithContentDescription("Generate password").performClick()
        rule.waitUntil(5_000) { generated().isNotEmpty() }
        // Copy is the only way onto the clipboard, and it is the secret clipboard.
        rule.onNodeWithContentDescription("Copy").performClick()
        assertEquals(generated(), sink.text)
        rule.onNodeWithText("Cancel").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("generator").fetchSemanticsNodes().isEmpty() }
        rule.onNodeWithTag("editor-reveal-password").performClick()
        assertEquals("Maple-Orbit-7731", shown("editor-value-password"))
    }

    @Test fun system_back_closes_the_generator_and_keeps_the_editor_draft() {
        val store = Store(StoreSnapshot(mapOf("w1" to Wrapper.make(Namespace.ENTRY, web))))
        var view: View? = null
        show(store) { view = it }
        rule.onNodeWithTag("vault-row").performClick()
        rule.onNodeWithText("Edit").performClick()
        rule.onNodeWithTag("editor-value-label").performTextClearance()
        rule.onNodeWithTag("editor-value-label").performTextInput("Draft title")
        rule.onNodeWithContentDescription("Generate password").performClick()
        rule.waitUntil(5_000) { generated().isNotEmpty() }
        rule.waitForIdle()
        // System back, through the activity's dispatcher (what the back gesture or key calls).
        rule.runOnUiThread {
            view!!.findViewTreeOnBackPressedDispatcherOwner()!!.onBackPressedDispatcher.onBackPressed()
        }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("generator").fetchSemanticsNodes().isEmpty() }
        rule.onNodeWithTag("editor").assertIsDisplayed()
        rule.onNodeWithText("Edit website login").assertIsDisplayed()
        rule.onNodeWithTag("editor-value-label").assertTextEquals("Draft title")
        rule.onNodeWithTag("editor-reveal-password").performClick()
        assertEquals("Maple-Orbit-7731", shown("editor-value-password"))
        assertEquals(0, store.commits)
    }
}
