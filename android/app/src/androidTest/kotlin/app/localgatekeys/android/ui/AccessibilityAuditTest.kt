package app.localgatekeys.android.ui

import app.localgatekeys.android.i18n.appTxt
import androidx.compose.ui.test.junit4.accessibility.enableAccessibilityChecks
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.tryPerformAccessibilityChecks
import app.localgatekeys.android.settings.Appearance
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.vault.SearchScreen
import app.localgatekeys.android.ui.vault.VaultScreen
import app.localgatekeys.android.ui.vault.VaultSeams
import app.localgatekeys.android.vault.Copier
import app.localgatekeys.android.vault.SearchCommand
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
import org.junit.Rule
import org.junit.Test

/**
 * UX workstream 13: the Accessibility Test Framework (the checks Espresso's AccessibilityChecks run) over the vault,
 * search and `>` action screens, in light and dark. Any error (touch target, missing label, contrast) fails the test.
 */
class AccessibilityAuditTest {
    @get:Rule val rule = createComposeRule()

    private class FakeStore(val snapshot: StoreSnapshot) : ItemStore {
        override fun load() = snapshot
        override fun commit(change: StoreChange) = error("read only")
    }

    private class FixedClock(override val now: Long) : UnixClock

    private fun obj(vararg f: Pair<String, JsonValue>) = Obj(mapOf(*f))

    private fun model(): VaultListModel {
        val web = obj(
            "id" to Str("w1"), "kind" to Str("web"), "label" to Str("Example account"), "username" to Str("sam@example.com"),
            "password" to Str("pw-1"), "scope" to obj("origin" to Str("https://accounts.example.com")),
            "totp" to obj("secret" to Str("JBSWY3DPEHPK3PXP")), "updated_at" to JsonValue.Int(20),
        )
        val note = obj("id" to Str("n1"), "kind" to Str("note"), "title" to Str("Alarm code"), "updated_at" to JsonValue.Int(10))
        return VaultListModel(
            FakeStore(StoreSnapshot(mapOf("w1" to Wrapper.make(Namespace.ENTRY, web), "n1" to Wrapper.make(Namespace.ITEM, note)))),
            appTxt(),
        )
    }

    private val seams = VaultSeams(
        clipboard = Copier { _, _ -> },
        clock = FixedClock(1_700_000_000),
        setupCardText = "Finish setting up · 2 of 5",
        commands = SearchCommand.all,
    )

    private fun audit(
        appearance: Appearance, tag: String, query: String = "",
        content: @androidx.compose.runtime.Composable (VaultListModel) -> Unit,
    ) {
        val m = model().also { it.query.value = query }
        rule.enableAccessibilityChecks()
        // The app's own backdrop behind the screen, so contrast is measured against what people see.
        rule.setContent {
            LgkTheme(appearance) {
                Box(Modifier.fillMaxSize()) { AuroraBackground(Modifier.fillMaxSize()); content(m) }
            }
        }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }
        rule.onRoot().tryPerformAccessibilityChecks()
    }

    @Test fun vault_light() = audit(Appearance.LIGHT, "vault-row") { VaultScreen(it, showCodesRow = true, seams = seams) }

    @Test fun vault_dark() = audit(Appearance.DARK, "vault-row") { VaultScreen(it, showCodesRow = true, seams = seams) }

    @Test fun search_light() = audit(Appearance.LIGHT, "vault-row") { SearchScreen(it, seams) }

    @Test fun search_dark() = audit(Appearance.DARK, "vault-row") { SearchScreen(it, seams) }

    @Test fun actions_light() = audit(Appearance.LIGHT, "command-row", query = ">") { SearchScreen(it, seams) }

    @Test fun actions_dark() = audit(Appearance.DARK, "command-row", query = ">") { SearchScreen(it, seams) }
}
