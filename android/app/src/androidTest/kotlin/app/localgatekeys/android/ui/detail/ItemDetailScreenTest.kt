package app.localgatekeys.android.ui.detail

import android.os.Build
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import app.localgatekeys.android.detail.ClipboardSink
import app.localgatekeys.android.detail.ItemDetailModel
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.ClipboardExpiry
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.ui.shell.RootScaffold
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.vault.VaultSeams
import app.localgatekeys.android.unlock.LockScheduler
import app.localgatekeys.android.unlock.LockTimer
import app.localgatekeys.android.vault.Copier
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.VaultListModel
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.json.JsonValue.Obj
import app.localgatekeys.core.json.JsonValue.Str
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.totp.Totp
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/** The detail screen over a fake clipboard: masked fields, reveal, copy with its footnote, the code, opening from the list. */
class ItemDetailScreenTest {
    @get:Rule val rule = createComposeRule()

    private class FixedClock(override var now: Long) : UnixClock

    private class MemorySink : ClipboardSink {
        var text: String? = null
        override fun set(text: String, sensitive: Boolean) { this.text = text }
        override fun current(): String? = text
        override fun clear() { text = null }
    }

    private object NoTimers : LockScheduler {
        override fun schedule(afterSeconds: Long, action: () -> Unit): LockTimer = object : LockTimer { override fun cancel() {} }
    }

    private fun obj(vararg f: Pair<String, JsonValue>) = Obj(mapOf(*f))

    private val secret = "JBSWY3DPEHPK3PXP"
    private val web = obj(
        "id" to Str("w1"), "kind" to Str("web"), "label" to Str("Example account"), "username" to Str("sam@example.com"),
        "password" to Str("Maple-Orbit-7731"), "scope" to obj("origin" to Str("https://accounts.example.com")),
        "totp" to obj("secret" to Str(secret)), "updated_at" to JsonValue.Int(20),
    )
    private val clock = FixedClock(1_790_000_500)
    private val sink = MemorySink()
    private val settings = AppSettings(MemoryStore())
    private val clipboard = SecretClipboard(sink, settings, NoTimers, clock).also { it.focusChanged(true) }
    private val toast = CopyToast(CopyToast.showsOwnMessage(Build.VERSION.SDK_INT))
    private val item = VaultItem.of("w1", web)!!

    private fun show(conceal: Boolean = true) {
        rule.setContent {
            LgkTheme {
                CopyToastHost(toast) {
                    ItemDetailScreen(item, clock, conceal, ClipboardExpiry.SIXTY_SECONDS, DetailSeams(clipboard, toast), onBack = {})
                }
            }
        }
    }

    @Test fun the_password_is_masked_until_revealed() {
        show()
        rule.onNodeWithTag("value-username").assertTextEquals("sam@example.com")
        rule.onNodeWithTag("value-password").assertTextEquals(ItemDetailModel.MASK)
        rule.onNodeWithContentDescription("Reveal").performClick()
        rule.onNodeWithTag("value-password").assertTextEquals("Maple-Orbit-7731")
        rule.onNodeWithContentDescription("Hide").performClick()
        rule.onNodeWithTag("value-password").assertTextEquals(ItemDetailModel.MASK)
    }

    /** iOS ItemDetailView: the estimated strength of the saved password sits under it, masked or not. */
    @Test fun the_password_shows_its_estimated_strength() {
        show()
        rule.onNodeWithTag("strength-meter", useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithContentDescription("Strength: Very strong").assertIsDisplayed()
        assertEquals(1, rule.onAllNodesWithTag("strength-meter", useUnmergedTree = true).fetchSemanticsNodes().size)
    }

    @Test fun with_conceal_off_the_password_shows_at_once() {
        show(conceal = false)
        rule.onNodeWithTag("value-password").assertTextEquals("Maple-Orbit-7731")
    }

    @Test fun copy_puts_the_value_on_the_clipboard_and_says_when_it_clears() {
        show()
        rule.onNodeWithContentDescription("Copy Password").performClick()
        assertEquals("Maple-Orbit-7731", sink.text)
        rule.onNodeWithText("Password copied. It clears from the clipboard in 60 seconds.").assertIsDisplayed()
        // Android 13 and later confirm a copy themselves; below that the app's own capsule shows.
        val toasts = rule.onAllNodesWithTag("copy-toast").fetchSemanticsNodes().size
        assertEquals(if (Build.VERSION.SDK_INT < 33) 1 else 0, toasts)
    }

    @Test fun the_one_time_code_shows_and_copies() {
        show()
        val code = Totp.code(secret, "SHA1", 6, 30, clock.now)
        rule.onNodeWithTag("detail-code").assertTextEquals(code)
        rule.onNodeWithContentDescription("20 seconds left").assertIsDisplayed()
        rule.onNodeWithContentDescription("Copy code").performClick()
        assertEquals(code, sink.text)
        rule.onNodeWithText("Code copied. It clears from the clipboard in 60 seconds.").assertIsDisplayed()
    }

    private class FakeStore(val snapshot: StoreSnapshot) : ItemStore {
        override fun load() = snapshot
        override fun commit(change: StoreChange) = error("read only")
    }

    @Test fun tapping_a_row_opens_the_detail_and_back_returns_to_the_list() {
        val model = VaultListModel(FakeStore(StoreSnapshot(mapOf("w1" to Wrapper.make(Namespace.ENTRY, web)))))
        val copied = mutableListOf<String>()
        val seams = VaultSeams(clipboard = Copier { text, _ -> copied.add(text) }, clock = clock)
        rule.setContent { LgkTheme { RootScaffold(model, settings, seams, DetailSeams(clipboard, toast)) } }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithTag("vault-row").performClick()
        rule.onNodeWithTag("item-detail").assertIsDisplayed()
        rule.onNodeWithTag("value-password").assertTextEquals(ItemDetailModel.MASK)
        rule.onNodeWithContentDescription("Back").performClick()
        rule.onNodeWithTag("vault-row").assertIsDisplayed()
        rule.onNodeWithTag("item-detail").assertDoesNotExist()
    }
}
