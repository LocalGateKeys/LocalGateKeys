package app.localgatekeys.android.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.AndroidTxt
import app.localgatekeys.android.ui.settings.FactorSection
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.unlock.KeyFileRef
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Rule
import org.junit.Test

/** Settings › Key file and YubiKey on the device (KeePass unlocking Task 9), over fake seams. */
class FactorSettingsTest {
    @get:Rule val rule = createComposeRule()

    private val txt get() = AndroidTxt(androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext.resources)

    private fun seams(state: FactorState) = FactorSeams(
        state = { state },
        addKeyFile = { _, _, _, _ -> },
        createKeyFile = { _, _, _, _ -> },
        addYubiKey = { _, _, _ -> },
        removeKeyFile = { _, _ -> },
        removeYubiKey = { _, _ -> },
        setAlwaysAsk = {},
        setRemember = {},
        yubiKeyPrompt = MutableStateFlow(null),
        cancelYubiKey = {},
        willOpenPicker = {},
        pickerClosed = { true },
        describe = { uri -> KeyFileRef(uri.toString(), "k.keyx") },
        discard = {},
    )

    @Test fun rows_hidden_without_the_app_password() {
        rule.setContent { LgkTheme { Column { FactorSection(seams(FactorState(passwordOn = false)), 0) } } }
        rule.onNodeWithText(txt.s(R.string.factors_needs_app_password)).assertIsDisplayed()
        rule.onNodeWithTag("factors-add-keyfile").assertDoesNotExist()
        rule.onNodeWithTag("factors-add-yubikey").assertDoesNotExist()
        rule.onNodeWithTag("factors-always-ask").assertDoesNotExist()
    }

    @Test fun rows_shown_with_the_app_password() {
        rule.setContent { LgkTheme { Column { FactorSection(seams(FactorState(passwordOn = true, yubiKeySlot = 2)), 0) } } }
        rule.onNodeWithTag("factors-needs-app-password").assertDoesNotExist()
        rule.onNodeWithTag("factors-add-keyfile").assertIsDisplayed()
        rule.onNodeWithTag("factors-create-keyfile").assertIsDisplayed()
        rule.onNodeWithTag("factors-remove-yubikey").assertIsDisplayed()
        rule.onNodeWithText(txt.s(R.string.factors_yubikey_set, 2)).assertIsDisplayed()
        rule.onNodeWithTag("factors-always-ask").assertIsDisplayed()
    }
}
