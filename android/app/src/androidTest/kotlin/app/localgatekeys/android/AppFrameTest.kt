package app.localgatekeys.android

import android.view.View
import android.view.inputmethod.EditorInfo
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import app.localgatekeys.android.unlock.ActivityMonitor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Ruling 15 at the app root: MainActivity puts every screen inside [AppFrame], and a text field inside it asks the
 * keyboard not to learn (the EditorInfo the focused field produces, read as the system does when the keyboard attaches).
 * Without the frame the flag is absent, so the check is not vacuous.
 */
class AppFrameTest {
    @get:Rule val rule = createComposeRule()

    private fun imeOptions(framed: Boolean): Int {
        var view: View? = null
        rule.setContent {
            view = LocalView.current
            val field = @androidx.compose.runtime.Composable {
                var text by remember { mutableStateOf("") }
                BasicTextField(text, { text = it }, Modifier.testTag("field"))
            }
            if (framed) AppFrame(ActivityMonitor {}) { field() } else field()
        }
        rule.onNodeWithTag("field").performClick()
        rule.waitForIdle()
        val info = EditorInfo()
        rule.runOnUiThread { assertNotNull(view!!.onCreateInputConnection(info)) }
        return info.imeOptions
    }

    @Test fun a_field_in_the_app_frame_asks_the_keyboard_not_to_learn() {
        assertTrue(imeOptions(framed = true) and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0)
    }

    @Test fun a_field_outside_the_frame_does_not() {
        assertEquals(0, imeOptions(framed = false) and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING)
    }
}
