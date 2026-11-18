package app.localgatekeys.android.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.R
import app.localgatekeys.android.duress.DuressException
import app.localgatekeys.android.duress.DuressSeams
import app.localgatekeys.android.duress.DuressStatus
import app.localgatekeys.android.duress.DuressText
import app.localgatekeys.android.duress.DuressVault
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.unlock.AppPasswordField
import app.localgatekeys.android.unlock.AppLockModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/**
 * Settings > Security > Duress password (sub-plan 08): a second app password that opens a separate vault and holds this
 * one for the chosen hours. Needs Pro and the app password. [refresh] bumps when the app password changes.
 */
@Composable
internal fun DuressSection(seams: DuressSeams, refresh: Int) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf<DuressStatus?>(null) }
    var reload by remember { mutableIntStateOf(0) }
    var dialog by remember { mutableStateOf<String?>(null) } // "setup" or "remove"
    var message by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(refresh, reload) { status = try { seams.status() } catch (e: Exception) { null } }
    val s = status ?: return
    val footer = message ?: when {
        !s.pro -> stringResource(R.string.duress_pro_only)
        !s.appPasswordOn -> stringResource(R.string.duress_needs_app_password)
        s.on -> pluralStringResource(R.plurals.duress_status_on, s.hours, s.hours)
        else -> stringResource(R.string.duress_status_off)
    }
    Section(stringResource(R.string.duress_section), footer = footer, tag = "settings-duress") {
        Text(stringResource(R.string.duress_note), color = c.secondaryText, modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp))
        if (s.on) {
            RowButton(stringResource(R.string.duress_remove), "settings-duress-remove", destructive = true) { dialog = "remove" }
        } else {
            RowButton(stringResource(R.string.duress_set_up), "settings-duress-setup", enabled = s.pro && s.appPasswordOn) { dialog = "setup" }
        }
    }
    when (dialog) {
        "setup" -> DuressSetupDialog(onDismiss = { dialog = null }) { current, password, confirm, hours ->
            try {
                seams.setUp(current, password, confirm, hours)
                dialog = null
                message = null
                reload++
                null
            } catch (e: CancellationException) {
                throw e
            } catch (e: DuressException) {
                DuressText.message(e, txt)
            } catch (e: Exception) {
                AppLockModel.message(e, txt) ?: txt.s(R.string.duress_err_generic)
            }
        }
        "remove" -> AlertDialog(
            onDismissRequest = { dialog = null },
            title = { Text(stringResource(R.string.duress_remove_title)) },
            text = { Text(stringResource(R.string.duress_remove_text)) },
            confirmButton = {
                TextButton(onClick = {
                    dialog = null
                    scope.launch {
                        message = try {
                            seams.remove(); txt.s(R.string.duress_removed)
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: DuressException) {
                            DuressText.message(e, txt)
                        } catch (e: Exception) {
                            txt.s(R.string.duress_err_generic)
                        }
                        reload++
                    }
                }, modifier = Modifier.testTag("duress-remove-confirm")) { Text(stringResource(R.string.duress_remove), color = c.danger) }
            },
            dismissButton = { TextButton({ dialog = null }) { Text(stringResource(R.string.common_cancel), color = c.accentText) } },
        )
    }
}

/** The current app password, the duress password twice and the hours. [submit] returns the problem, null when done. */
@Composable
private fun DuressSetupDialog(onDismiss: () -> Unit, submit: suspend (String, String, String, Int) -> String?) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    val scope = rememberCoroutineScope()
    var current by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var hours by remember { mutableIntStateOf(DuressVault.DEFAULT_HOURS) }
    var open by remember { mutableStateOf(false) }
    var problem by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(stringResource(R.string.duress_section)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                AppPasswordField(current, { current = it; problem = null }, stringResource(R.string.app_password_current), "duress-current")
                AppPasswordField(password, { password = it; problem = null }, stringResource(R.string.duress_password), "duress-password")
                AppPasswordField(confirm, { confirm = it; problem = null }, stringResource(R.string.duress_confirm), "duress-confirm")
                Box {
                    TextButton({ open = true }, modifier = Modifier.testTag("duress-hours")) {
                        Text(stringResource(R.string.common_label_value, stringResource(R.string.duress_hours), hours.toString()), color = c.accentText)
                    }
                    DropdownMenu(open, onDismissRequest = { open = false }) {
                        for (h in DuressText.HOURS) DropdownMenuItem(text = { Text(h.toString()) }, onClick = { hours = h; open = false })
                    }
                }
                if (busy) CircularProgressIndicator()
                problem?.let { Text(it, color = c.danger) }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy && current.isNotEmpty() && password.isNotEmpty(),
                onClick = {
                    busy = true
                    scope.launch {
                        problem = submit(current, password, confirm, hours)
                        current = ""
                        busy = false
                    }
                },
                modifier = Modifier.testTag("duress-setup-confirm"),
            ) { Text(stringResource(R.string.duress_set_up), color = c.accentText) }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onDismiss) { Text(txt.s(R.string.common_cancel), color = c.accentText) } },
    )
}
