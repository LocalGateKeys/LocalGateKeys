package app.localgatekeys.android.ui.unlock

import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry
import androidx.lifecycle.compose.LocalLifecycleOwner
import app.localgatekeys.android.ui.theme.LgkTheme
import org.junit.Rule
import org.junit.Test

/** The opaque cover is drawn while the lifecycle is not RESUMED (paused or stopped) and removed on RESUMED. */
class PrivacyCoverHostTest {
    @get:Rule val rule = createComposeRule()

    private class Owner : LifecycleOwner {
        val registry = LifecycleRegistry(this)
        override val lifecycle: Lifecycle get() = registry
    }

    private val owner = Owner()

    private fun move(to: Lifecycle.State) = rule.runOnUiThread { owner.registry.currentState = to }

    @Test fun cover_while_started_but_not_resumed_and_gone_on_resumed() {
        move(Lifecycle.State.STARTED)
        rule.setContent {
            CompositionLocalProvider(LocalLifecycleOwner provides owner) {
                LgkTheme { PrivacyCoverHost { Text("secret item") } }
            }
        }
        rule.onNodeWithTag("privacyCover").assertIsDisplayed()

        move(Lifecycle.State.RESUMED)
        rule.onNodeWithTag("privacyCover").assertDoesNotExist()
        rule.onNodeWithText("secret item").assertIsDisplayed()

        move(Lifecycle.State.STARTED) // paused again: a dialog or the recents screen in front
        rule.onNodeWithTag("privacyCover").assertIsDisplayed()
        move(Lifecycle.State.CREATED) // stopped
        rule.onNodeWithTag("privacyCover").assertIsDisplayed()
    }
}
