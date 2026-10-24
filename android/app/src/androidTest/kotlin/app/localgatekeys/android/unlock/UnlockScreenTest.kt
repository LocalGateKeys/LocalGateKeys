package app.localgatekeys.android.unlock

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.unlock.UnlockContent
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/** The Unlock screen: brand, title, Unlock button, and the two-step Start fresh dialogs with the iPhone copy. */
class UnlockScreenTest {
    @get:Rule val rule = createComposeRule()

    private var unlocks = 0
    private var freshStarts = 0
    private var unlocking by mutableStateOf(false)
    private var message by mutableStateOf<String?>(null)
    private var offers by mutableStateOf(false)

    private fun show() {
        rule.setContent {
            LgkTheme {
                UnlockContent(unlocking, message, offers, onUnlock = { unlocks++ }, onStartFresh = { freshStarts++ })
            }
        }
    }

    @Test fun shows_the_brand_the_title_and_the_unlock_button() {
        show()
        rule.onNodeWithTag("brandMark").assertIsDisplayed()
        rule.onNodeWithText("LocalGateKeys").assertIsDisplayed()
        rule.onNodeWithText("Unlock").assertIsDisplayed().assertIsEnabled().performClick()
        assertEquals(1, unlocks)
        rule.onNodeWithText("Start fresh anyway").assertDoesNotExist()
    }

    @Test fun unlock_is_disabled_while_unlocking_and_the_error_shows() {
        show()
        unlocking = true
        message = AppLockModel.VAULT_WITHOUT_KEY_MESSAGE
        offers = true
        rule.onNodeWithText("Unlock").assertIsNotEnabled()
        rule.onNodeWithText("Start fresh anyway").assertIsNotEnabled()
        rule.onNodeWithText(AppLockModel.VAULT_WITHOUT_KEY_MESSAGE).assertIsDisplayed()
    }

    @Test fun start_fresh_asks_twice_then_runs() {
        offers = true
        show()
        rule.onNodeWithText("Start fresh anyway").assertIsEnabled().performClick()
        rule.onNodeWithText(AppLockModel.START_FRESH_CONFIRM_1).assertIsDisplayed()
        rule.onNodeWithText("Cancel").assertIsDisplayed()
        rule.onNodeWithText("Start fresh").performClick()
        rule.onNodeWithText(AppLockModel.START_FRESH_CONFIRM_1).assertDoesNotExist()
        rule.onNodeWithText(AppLockModel.START_FRESH_CONFIRM_2).assertIsDisplayed()
        assertEquals("nothing runs before the second confirmation", 0, freshStarts)
        rule.onNodeWithText("Start fresh now").performClick()
        rule.onNodeWithText(AppLockModel.START_FRESH_CONFIRM_2).assertDoesNotExist()
        rule.waitForIdle()
        assertEquals(1, freshStarts)
    }

    @Test fun cancel_at_either_step_runs_nothing() {
        offers = true
        show()
        rule.onNodeWithText("Start fresh anyway").performClick()
        rule.onNodeWithText("Cancel").performClick()
        rule.onNodeWithText(AppLockModel.START_FRESH_CONFIRM_1).assertDoesNotExist()
        rule.onNodeWithText("Start fresh anyway").performClick()
        rule.onNodeWithText("Start fresh").performClick()
        rule.onNodeWithText("Cancel").performClick()
        rule.onNodeWithText(AppLockModel.START_FRESH_CONFIRM_2).assertDoesNotExist()
        rule.waitForIdle()
        assertEquals(0, freshStarts)
    }
}
