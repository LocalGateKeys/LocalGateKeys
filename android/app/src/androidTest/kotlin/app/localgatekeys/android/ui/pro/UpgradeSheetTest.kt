package app.localgatekeys.android.ui.pro

import app.localgatekeys.android.i18n.appTxt
import app.localgatekeys.android.i18n.AndroidTxt
import android.os.Build
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import app.localgatekeys.android.detail.ClipboardSink
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.android.pro.ProModel
import app.localgatekeys.android.pro.ProOffer
import app.localgatekeys.android.pro.ProPurchasing
import app.localgatekeys.android.pro.PurchaseOutcome
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.ui.detail.CopyToast
import app.localgatekeys.android.ui.detail.DetailSeams
import app.localgatekeys.android.ui.editor.EditorSeams
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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** The upgrade sheet through RootScaffold, over a fake purchasing seam (nothing here talks to Google Play). */
class UpgradeSheetTest {
    @get:Rule val rule = createComposeRule()

    private class FakePurchases(var offer: ProOffer = ProOffer.Available("$4.99")) : ProPurchasing {
        @Volatile var entitled = false
        @Volatile var purchaseCalls = 0
        override suspend fun isEntitled() = entitled
        override suspend fun offer() = offer
        override suspend fun purchase(): PurchaseOutcome {
            purchaseCalls++
            entitled = true
            return PurchaseOutcome.PURCHASED
        }
        override suspend fun restore() = entitled
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

    private fun note(k: Int) = obj(
        "id" to Str("00000000-0000-4000-8000-%012d".format(k)), "kind" to Str("note"), "title" to Str("Note $k"),
        "created_at" to JsonValue.Int(10), "updated_at" to JsonValue.Int(20L + k), "payload" to obj("body" to Str("b")),
    )

    private val web = obj(
        "id" to Str("w1"), "kind" to Str("web"), "label" to Str("Example account"), "username" to Str("sam@example.com"),
        "password" to Str("Maple-Orbit-7731"), "scope" to obj("origin" to Str("https://accounts.example.com")),
        "created_at" to JsonValue.Int(10), "updated_at" to JsonValue.Int(20),
    )

    private val clock = FixedClock(1_800_000_000)
    private val settings = AppSettings(MemoryStore())
    private val clipboard = SecretClipboard(MemorySink(), settings, NoTimers, clock).also { it.focusChanged(true) }
    private val toast = CopyToast(CopyToast.showsOwnMessage(Build.VERSION.SDK_INT))

    private fun records(vararg rs: Obj) = rs.associate { r ->
        val id = (r.fields["id"] as Str).v
        id to Wrapper.make(if ((r.fields["kind"] as Str).v == "web") Namespace.ENTRY else Namespace.ITEM, r)
    }

    private fun show(store: Store, pro: ProModel) {
        val model = VaultListModel(store, appTxt(), onLoad = pro::update)
        val seams = VaultSeams(clipboard = Copier { _, _ -> }, isPro = { pro.isPro }, clock = clock)
        rule.setContent {
            LgkTheme { RootScaffold(model, settings, seams, DetailSeams(clipboard, toast), EditorSeams(store, Counting()), pro = pro) }
        }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().isNotEmpty() }
    }

    @Test fun a_full_free_plan_opens_the_sheet_and_buying_opens_the_editor() {
        val store = Store(StoreSnapshot(records(note(0), note(1), note(2), note(3))))
        val play = FakePurchases()
        val pro = ProModel(play, emptyMap(), txt = AndroidTxt(androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext.resources))
        show(store, pro)
        rule.onNodeWithContentDescription("New item").performClick()
        rule.onNodeWithText("Payment card").performClick()
        rule.onNodeWithTag("upgrade").assertIsDisplayed()
        rule.onNodeWithText("LocalGateKeys Pro").assertIsDisplayed()
        rule.onNodeWithText("Pay once for unlimited items and two‑factor codes.").assertIsDisplayed()
        rule.onNodeWithContentDescription("4 of 4 free items used. Pro: no limit.").assertIsDisplayed()
        rule.onNodeWithText("Sync with your PC needs Pro on the PC as well.").performScrollTo().assertIsDisplayed()
        // The stand-in notice of the earlier tasks is gone; there are no links out of the app.
        assertTrue(rule.onAllNodesWithText("Free plan is full").fetchSemanticsNodes().isEmpty())
        assertTrue(rule.onAllNodesWithText("Privacy Policy").fetchSemanticsNodes().isEmpty())
        rule.waitUntil(5_000) { rule.onAllNodesWithText("Buy for $4.99").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithText("One-time purchase, no subscription.").assertIsDisplayed()
        rule.onNodeWithTag("upgrade-buy").assertIsEnabled().performClick()
        // Bought: the sheet closes by itself and the plus menu now opens the editor.
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("upgrade").fetchSemanticsNodes().isEmpty() }
        assertEquals(1, play.purchaseCalls)
        assertTrue(pro.isPro)
        rule.onNodeWithContentDescription("New item").performClick()
        rule.onNodeWithText("Payment card").performClick()
        rule.onNodeWithText("New payment card").assertIsDisplayed()
    }

    @Test fun no_product_says_not_available_and_disables_buy_and_close_returns() {
        val store = Store(StoreSnapshot(records(note(0), note(1), note(2), note(3))))
        val play = FakePurchases(ProOffer.Unavailable)
        show(store, ProModel(play, emptyMap(), txt = AndroidTxt(androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext.resources)))
        rule.onNodeWithContentDescription("New item").performClick()
        rule.onNodeWithText("Payment card").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithText("Pro isn't available yet").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithText("Buy Pro").assertExists()
        rule.onNodeWithTag("upgrade-buy").assertIsNotEnabled()
        rule.onNodeWithTag("upgrade-restore").assertIsEnabled()
        rule.onNodeWithText("Close").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("upgrade").fetchSemanticsNodes().isEmpty() }
        assertEquals(0, play.purchaseCalls)
        rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().let { assertEquals(4, it.size) }
    }

    @Test fun adding_a_two_factor_code_without_pro_opens_the_sheet_over_the_editor() {
        val store = Store(StoreSnapshot(records(web)))
        val pro = ProModel(FakePurchases(), emptyMap(), txt = AndroidTxt(androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext.resources))
        show(store, pro)
        rule.onNodeWithTag("vault-row").performClick()
        rule.onNodeWithText("Edit").performClick()
        rule.onNodeWithTag("editor-value-totp").performScrollTo().performTextInput("JBSWY3DPEHPK3PXP")
        rule.onNodeWithText("Save").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("upgrade").fetchSemanticsNodes().isNotEmpty() }
        // Opened from the editor: no item count.
        rule.onNodeWithContentDescription("Free: 4 items. Pro: no limit.").assertIsDisplayed()
        assertEquals(0, store.commits)
        rule.waitUntil(5_000) { rule.onAllNodesWithText("Buy for $4.99").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithTag("upgrade-buy").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("upgrade").fetchSemanticsNodes().isEmpty() }
        // The editor kept its draft underneath: saving now goes through.
        rule.onNodeWithText("Save").performClick()
        rule.waitUntil(5_000) { store.commits == 1 }
    }
}
