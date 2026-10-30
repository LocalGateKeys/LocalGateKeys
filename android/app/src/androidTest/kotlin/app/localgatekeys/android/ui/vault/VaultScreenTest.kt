package app.localgatekeys.android.ui.vault

import app.localgatekeys.android.i18n.appTxt
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.longClick
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.vault.Copier
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
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** The Vault and Search screens over a fake store: groups, the Codes row, row actions, search. */
class VaultScreenTest {
    @get:Rule val rule = createComposeRule()

    private class FakeStore(var snapshot: StoreSnapshot) : ItemStore {
        override fun load() = snapshot
        override fun commit(change: StoreChange) = error("read only")
    }

    private class FixedClock(override var now: Long) : UnixClock

    private fun obj(vararg f: Pair<String, JsonValue>) = Obj(mapOf(*f))

    private val secret = "JBSWY3DPEHPK3PXP"
    private val totp = obj("secret" to Str(secret))
    private val web = obj(
        "id" to Str("w1"), "kind" to Str("web"), "label" to Str("Example account"), "username" to Str("sam@example.com"),
        "password" to Str("pw-1"), "scope" to obj("origin" to Str("https://accounts.example.com")), "totp" to totp,
        "updated_at" to JsonValue.Int(20),
    )
    private val authenticator = obj(
        "id" to Str("t1"), "kind" to Str("note"), "title" to Str("Bank token"), "totp" to totp, "updated_at" to JsonValue.Int(10),
    )

    private fun store(vararg records: Obj): FakeStore {
        val rs = records.associate {
            val id = (it.fields["id"] as Str).v
            val kind = (it.fields["kind"] as Str).v
            id to Wrapper.make(if (kind == "web") Namespace.ENTRY else Namespace.ITEM, it)
        }
        return FakeStore(StoreSnapshot(rs))
    }

    private val clock = FixedClock(1_700_000_000)
    private val copied = mutableListOf<Pair<String, String>>()
    private val opened = mutableListOf<String>()
    private val seams = VaultSeams(
        clipboard = Copier { text, confirmation -> copied.add(text to confirmation) },
        onOpenItem = { opened.add(it) },
        clock = clock,
    )

    private fun expectedCode(): String {
        val c = Totp.code(secret, "SHA1", 6, 30, clock.now)
        return c.substring(0, 3) + " " + c.substring(3)
    }

    @Test fun a_web_login_and_a_two_factor_item_show_the_logins_group_and_the_codes_row() {
        val model = VaultListModel(store(web, authenticator), appTxt())
        rule.setContent { LgkTheme { VaultScreen(model, showCodesRow = true, seams = seams) } }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithText("Logins").assertIsDisplayed()
        rule.onNodeWithText("Cards and notes").assertIsDisplayed()
        rule.onAllNodesWithText("Example account").onFirst().assertIsDisplayed()
        rule.onNodeWithTag("codes-row").assertIsDisplayed()
        rule.onAllNodesWithText("Codes").onFirst().assertIsDisplayed()
        rule.onAllNodesWithTag("code-tile").assertCountEquals(2)
        rule.onAllNodesWithTag("code-text", useUnmergedTree = true)[0].assertTextEquals(expectedCode())
    }

    @Test fun the_codes_row_is_hidden_when_the_setting_is_off() {
        val model = VaultListModel(store(web, authenticator), appTxt())
        rule.setContent { LgkTheme { VaultScreen(model, showCodesRow = false, seams = seams) } }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithTag("codes-row").assertDoesNotExist()
    }

    @Test fun tapping_a_tile_copies_the_code_and_tapping_a_row_opens_the_item() {
        val model = VaultListModel(store(web), appTxt())
        rule.setContent { LgkTheme { VaultScreen(model, showCodesRow = true, seams = seams) } }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithTag("code-tile").performClick()
        assertEquals(listOf(Totp.code(secret, "SHA1", 6, 30, clock.now) to "Code copied"), copied)
        rule.onNodeWithTag("vault-row").performClick()
        assertEquals(listOf("w1"), opened)
    }

    @Test fun a_long_press_shows_the_quick_actions_and_copy_username_copies() {
        val model = VaultListModel(store(web), appTxt())
        rule.setContent { LgkTheme { VaultScreen(model, showCodesRow = false, seams = seams) } }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithTag("vault-row").performTouchInput { longClick() }
        rule.onNodeWithText("Copy password").assertIsDisplayed()
        rule.onNodeWithText("Copy 2FA code").assertIsDisplayed()
        rule.onNodeWithText("Open website").assertIsDisplayed()
        rule.onNodeWithText("Copy username").performClick()
        assertEquals(listOf("sam@example.com" to "Username copied"), copied)
    }

    @Test fun an_empty_vault_shows_the_empty_state() {
        val model = VaultListModel(store(), appTxt())
        rule.setContent { LgkTheme { VaultScreen(model, showCodesRow = true, seams = seams) } }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("empty-vault").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithText("No items yet. Tap + to add one.").assertIsDisplayed()
    }

    @Test fun an_empty_vault_offers_import_until_not_now() {
        val model = VaultListModel(store(), appTxt())
        var imports = 0
        var dismissed = false
        val withCard = seams.copy(showImportCard = { !dismissed }, onImport = { imports++ }, onDismissImportCard = { dismissed = true })
        rule.setContent { LgkTheme { VaultScreen(model, showCodesRow = true, seams = withCard) } }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("import-card").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithText("Import your passwords").assertIsDisplayed()
        rule.onNodeWithTag("import-card-import").performClick()
        assertEquals(1, imports)
        rule.onNodeWithTag("import-card-not-now").performClick()
        assertTrue(dismissed)
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("import-card").fetchSemanticsNodes().isEmpty() }
    }

    @Test fun search_filters_and_reports_no_matches() {
        val model = VaultListModel(store(web, authenticator), appTxt())
        rule.setContent { LgkTheme { SearchScreen(model, seams) } }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().size == 2 }
        rule.onNodeWithTag("search-field").performTextInput("bank")
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().size == 1 }
        rule.onNodeWithText("Bank token").assertIsDisplayed()
        rule.onNodeWithTag("search-field").performTextInput("zzzzqq")
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("search-empty").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithText("No matches.").assertIsDisplayed()
    }
}
