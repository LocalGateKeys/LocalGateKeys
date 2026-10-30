package app.localgatekeys.android.ui.unlock
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.settings.AppPasswordText
import app.localgatekeys.android.ui.theme.LgkTheme

/** A masked password field (no autocorrect, no suggestions, no autofill save). */
@Composable
internal fun AppPasswordField(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    tag: String,
    imeAction: ImeAction = ImeAction.Done,
    onDone: () -> Unit = {},
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false, imeAction = imeAction),
        keyboardActions = KeyboardActions(onDone = { onDone() }, onGo = { onDone() }),
        modifier = Modifier.fillMaxWidth().testTag(tag),
    )
}

/**
 * Task 7: the unlock screen's app-password part. The password field and Unlock; "Use fingerprint" when the shortcut
 * is set up; "Forgot app password?" opens the recovery form (24 words + a new password, checked like Settings).
 * The typed text lives only in this composition and is cleared after each try.
 */
@Composable
fun AppPasswordUnlockPanel(
    unlocking: Boolean,
    biometric: Boolean,
    onPassword: (String) -> Unit,
    onBiometric: () -> Unit,
    onRecover: (phrase: String, newPassword: String) -> Unit,
) {
    val c = LgkTheme.colors
    val appPw = AppPasswordText(rememberTxt())
    var recovering by remember { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    var phrase by remember { mutableStateOf("") }
    var newPassword by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var problem by remember { mutableStateOf<String?>(null) }
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 32.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (!recovering) {
            val submit = {
                if (password.isNotEmpty() && !unlocking) {
                    onPassword(password)
                    password = ""
                }
            }
            AppPasswordField(password, { password = it }, stringResource(R.string.app_password_field), "unlock-app-password", ImeAction.Go, submit)
            Button(
                onClick = submit,
                enabled = !unlocking && password.isNotEmpty(),
                colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
                modifier = Modifier.fillMaxWidth().testTag("unlock-app-password-button"),
            ) { Text(stringResource(R.string.unlock_button), modifier = Modifier.padding(vertical = 6.dp)) }
            if (biometric) {
                TextButton(onClick = onBiometric, enabled = !unlocking, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.app_password_use_biometric), color = c.accentText)
                }
            }
            TextButton(onClick = { recovering = true }, enabled = !unlocking, modifier = Modifier.fillMaxWidth().testTag("unlock-forgot")) {
                Text(stringResource(R.string.app_password_forgot), color = c.accentText)
            }
        } else {
            Text(stringResource(R.string.app_password_recover_blurb), color = c.secondaryText)
            OutlinedTextField(
                value = phrase,
                onValueChange = { phrase = it },
                label = { Text(stringResource(R.string.app_password_recovery_phrase)) },
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password, capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false,
                ),
                modifier = Modifier.fillMaxWidth().heightIn(min = 96.dp).testTag("unlock-recovery-phrase"),
            )
            AppPasswordField(newPassword, { newPassword = it; problem = null }, stringResource(R.string.app_password_new), "unlock-recovery-new", ImeAction.Next)
            AppPasswordField(confirm, { confirm = it; problem = null }, stringResource(R.string.app_password_confirm_new), "unlock-recovery-confirm")
            problem?.let { Text(it, color = c.danger) }
            Button(
                onClick = {
                    val p = appPw.problem(newPassword, confirm)
                    if (p != null) {
                        problem = p
                    } else {
                        onRecover(phrase, newPassword)
                        phrase = ""; newPassword = ""; confirm = ""
                    }
                },
                enabled = !unlocking && phrase.isNotBlank() && newPassword.isNotEmpty(),
                colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
                modifier = Modifier.fillMaxWidth().testTag("unlock-recovery-button"),
            ) { Text(stringResource(R.string.app_password_unlock_and_set), modifier = Modifier.padding(vertical = 6.dp)) }
            TextButton(onClick = { recovering = false; problem = null }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.common_back), color = c.accentText)
            }
        }
    }
}
