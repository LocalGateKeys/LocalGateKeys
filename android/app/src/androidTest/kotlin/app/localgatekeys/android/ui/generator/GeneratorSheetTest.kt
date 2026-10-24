package app.localgatekeys.android.ui.generator

import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.Density
import app.localgatekeys.android.detail.ClipboardSink
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.android.generator.GeneratorDefaults
import app.localgatekeys.android.generator.GeneratorModel
import app.localgatekeys.android.generator.PassphraseWordlist
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.unlock.LockScheduler
import app.localgatekeys.android.unlock.LockTimer
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.primitives.UnixClock
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** The generator sheet on its own: the mode labels are never cut, at any text size (iOS ViewThatFits). */
class GeneratorSheetTest {
    @get:Rule val rule = createComposeRule()

    private object NoSink : ClipboardSink {
        override fun set(text: String, sensitive: Boolean) {}
        override fun current(): String? = null
        override fun clear() {}
    }

    private object NoTimers : LockScheduler {
        override fun schedule(afterSeconds: Long, action: () -> Unit): LockTimer = object : LockTimer { override fun cancel() {} }
    }

    private fun show(fontScale: Float) {
        val settings = AppSettings(MemoryStore())
        val clock = object : UnixClock { override val now = 1_800_000_000L }
        val model = GeneratorModel(
            GeneratorDefaults(settings), SystemRandomSource(), SecretClipboard(NoSink, settings, NoTimers, clock),
            PassphraseWordlist.FALLBACK, post = { it() },
        )
        rule.setContent {
            LgkTheme {
                CompositionLocalProvider(LocalDensity provides Density(LocalDensity.current.density, fontScale)) {
                    GeneratorSheet(model, onCancel = {}, onUse = {})
                }
            }
        }
    }

    private fun ellipsized(text: String): Boolean {
        val results = mutableListOf<TextLayoutResult>()
        // The label inside the mode picker's tab (the hero card also says "Password").
        rule.onNode(hasText(text) and hasAnyAncestor(hasTestTag("generator-mode-${text.lowercase()}")), useUnmergedTree = true)
            .fetchSemanticsNode()
            .config[SemanticsActions.GetTextLayoutResult].action?.invoke(results)
        val r = results.first()
        // One line, no ellipsis, and the line ends inside the laid-out text (width only).
        return r.lineCount != 1 || r.isLineEllipsized(0) || r.getLineRight(0) > r.size.width
    }

    private fun stacked(): Boolean {
        val picker = rule.onNodeWithTag("generator-mode-passphrase").getUnclippedBoundsInRoot()
        val button = rule.onNodeWithContentDescription("Generate again").getUnclippedBoundsInRoot()
        return button.top >= picker.bottom
    }

    @Test fun at_the_default_text_size_the_picker_and_buttons_share_a_row() {
        show(fontScale = 1f)
        assertFalse(ellipsized("Passphrase"))
        assertFalse(stacked())
    }

    @Test fun at_twice_the_text_size_the_picker_stacks_above_the_buttons_and_shows_passphrase_in_full() {
        show(fontScale = 2f)
        assertFalse(ellipsized("Passphrase"))
        assertFalse(ellipsized("Password"))
        assertTrue(stacked())
    }
}
