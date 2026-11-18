package app.localgatekeys.android.ui.security

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import app.localgatekeys.android.security.BreachTransport
import app.localgatekeys.android.security.SecurityCheckModel
import app.localgatekeys.android.security.SiteFeatures
import app.localgatekeys.core.records.PublicSuffixRules
import app.localgatekeys.core.records.UrlMatcher
import app.localgatekeys.android.security.SecurityPrefs
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.json.JsonValue.Obj
import app.localgatekeys.core.json.JsonValue.Str
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import java.security.MessageDigest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** The Security check over a fake store, a fake strength function and a fake breach transport (no network). */
class SecurityCheckScreenTest {
    @get:Rule val rule = createComposeRule()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @After fun stop() { scope.coroutineContext[kotlinx.coroutines.Job]?.cancel() }

    private class FakeStore(var snapshot: StoreSnapshot) : ItemStore {
        override fun load() = snapshot
        override fun commit(change: StoreChange) = error("read only")
    }

    private class FixedClock(override var now: Long) : UnixClock

    private class FakeTransport : BreachTransport {
        @Volatile var requests = 0
        override suspend fun get(url: String, headers: Map<String, String>): ByteArray {
            requests++
            val hex = MessageDigest.getInstance("SHA-1").digest("password".toByteArray()).joinToString("") { "%02X".format(it) }
            return (hex.substring(5) + ":42\r\n").toByteArray()
        }
    }

    private fun login(id: String, password: String, totp: Boolean) = Obj(
        buildMap {
            put("id", Str(id)); put("kind", Str("web")); put("label", Str("Site $id")); put("username", Str("u"))
            put("password", Str(password)); put("scope", Obj(mapOf("origin" to Str("https://$id.example.com"))))
            put("updated_at", JsonValue.Int(1_790_000_000L))
            if (totp) put("totp", Obj(mapOf("secret" to Str("JBSWY3DPEHPK3PXP"))))
        },
    )

    private fun snapshot(vararg records: Obj) =
        StoreSnapshot(records.associate { (it.fields["id"] as Str).v to Wrapper.make(Namespace.ENTRY, it) })

    private fun show(prefs: SecurityPrefs, transport: BreachTransport = FakeTransport(), opened: MutableList<String> = mutableListOf(), changed: MutableList<String> = mutableListOf()): SecurityCheckModel {
        val model = SecurityCheckModel(
            FakeStore(snapshot(login("a", "password", false), login("b", "Unique-Lantern-Quartz-9921", true))),
            prefs, FixedClock(1_800_000_000L), scope, { if (it == "password") 0 else 4 }, transport, "test", pauseMillis = 0,
            // Every test login lives on <id>.example.com, a site that offers 2FA codes (a one-rule suffix list: "com").
            featuresSource = { SiteFeatures(mapOf("example.com" to setOf("totp")), UrlMatcher(PublicSuffixRules.parse(listOf("com")))) },
        )
        rule.setContent {
            LgkTheme {
                SecurityCheckScreen(model, onOpenItem = { opened += it.id }, onChangePassword = { changed += it.id })
            }
        }
        return model
    }

    @Test fun the_overview_shows_the_score_and_the_five_counts() {
        show(SecurityPrefs(MemoryStore()))
        rule.waitForIdle()
        rule.onNodeWithTag("security-score").assertIsDisplayed()
        rule.onNodeWithTag("security-count-weak", useUnmergedTree = true).assertTextEquals("1")
        rule.onNodeWithTag("security-count-noTwoFactor", useUnmergedTree = true).assertTextEquals("1")
        rule.onNodeWithTag("security-count-breached", useUnmergedTree = true).assertTextEquals("0")
        rule.onNodeWithTag("security-count-reused", useUnmergedTree = true).assertTextEquals("0")
        rule.onNodeWithTag("security-count-old", useUnmergedTree = true).assertTextEquals("0")
    }

    @Test fun a_row_opens_its_list_and_back_returns() {
        val opened = mutableListOf<String>()
        show(SecurityPrefs(MemoryStore()), opened = opened)
        rule.onNodeWithTag("security-row-weak").performClick()
        rule.onAllNodesWithTag("security-item").assertCountEquals(1)
        rule.onNodeWithTag("security-item").performClick()
        assertEquals(listOf("a"), opened)
        rule.onNodeWithTag("security-back").performClick()
        rule.onNodeWithTag("security-row-weak").assertIsDisplayed()
    }

    @Test fun change_password_and_dismiss_come_from_the_row_menu_and_the_2fa_row_has_no_change() {
        val changed = mutableListOf<String>()
        val model = show(SecurityPrefs(MemoryStore()), changed = changed)
        rule.onNodeWithTag("security-row-weak").performClick()
        rule.onNodeWithTag("security-item-menu").performClick()
        rule.onNodeWithTag("security-menu-change").performClick()
        assertEquals(listOf("a"), changed)
        rule.onNodeWithTag("security-item-menu").performClick()
        rule.onNodeWithTag("security-menu-dismiss").performClick()
        rule.onNodeWithTag("security-empty").assertIsDisplayed()
        assertEquals(0, model.state.value.count(app.localgatekeys.android.security.SecurityCategory.WEAK))
        rule.onNodeWithTag("security-back").performClick()
        rule.onNodeWithTag("security-show-dismissed").assertIsDisplayed()
        rule.onNodeWithTag("security-row-noTwoFactor").performClick()
        rule.onNodeWithTag("security-item-menu").performClick()
        assertEquals(0, rule.onAllNodesWithTag("security-menu-change").fetchSemanticsNodes().size)
        rule.onNodeWithTag("security-menu-dismiss").assertIsDisplayed()
    }

    @Test fun breach_checks_are_blocked_until_allowed_and_ask_before_sending() {
        val transport = FakeTransport()
        val prefs = SecurityPrefs(MemoryStore())
        show(prefs, transport)
        rule.onNodeWithTag("security-breach-blocked").assertIsDisplayed()
        assertEquals(0, rule.onAllNodesWithTag("security-breach-start").fetchSemanticsNodes().size)
        assertEquals(0, transport.requests)
    }

    @Test fun an_allowed_breach_check_asks_first_then_reports() {
        val transport = FakeTransport()
        val prefs = SecurityPrefs(MemoryStore()).also { it.strictOfflineMode = false; it.breachCheckEnabled = true }
        show(prefs, transport)
        rule.onNodeWithTag("security-breach-start").performClick()
        // Cancelling the confirmation sends nothing.
        rule.onNodeWithTag("security-confirm-cancel").performClick()
        assertEquals(0, transport.requests)
        rule.onNodeWithTag("security-breach-start").performClick()
        rule.onNodeWithTag("security-confirm").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("security-breach-status").fetchSemanticsNodes().isNotEmpty() }
        assertTrue(transport.requests >= 1)
        rule.onNodeWithTag("security-count-breached", useUnmergedTree = true).assertTextEquals("1")
    }
}
