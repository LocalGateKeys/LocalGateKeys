package app.localgatekeys.android.ui.settings

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.settings.FactorSeams
import app.localgatekeys.android.settings.FactorState
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.unlock.AppPasswordField
import app.localgatekeys.android.unlock.AppLockModel
import app.localgatekeys.android.unlock.KeyFileRef
import app.localgatekeys.android.unlock.OpenKeyFile
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/** A factor change waiting for the app password (Settings › Key file and YubiKey). */
private sealed class FactorAction {
    class AddFile(val file: KeyFileRef, val created: Boolean) : FactorAction()
    class AddYubiKey(val slot: Int) : FactorAction()
    object RemoveFile : FactorAction()
    object RemoveYubiKey : FactorAction()
}

private fun failure(e: Exception, t: Txt): String = AppLockModel.message(e, t) ?: t.s(R.string.factors_failed)

/** The name "Create key file…" suggests (KeePass's own extension for XML 2.0 key files). */
private const val NEW_KEY_FILE_NAME = "LocalGateKeys.keyx"

/**
 * Settings › Key file and YubiKey (Task 9). Without the app password only "Turn on the app password to add a key file
 * or YubiKey" shows; with it, the key file and YubiKey rows (add, create, remove), "Always ask for the key file /
 * YubiKey" and "Remember the key file location on this phone". [refresh] bumps when the app password changed.
 */
@Composable
internal fun FactorSection(seams: FactorSeams, refresh: Int) {
    val txt = rememberTxt()
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf(FactorState()) }
    var reload by remember { mutableIntStateOf(0) }
    var message by remember { mutableStateOf<String?>(null) }
    var action by remember { mutableStateOf<FactorAction?>(null) }
    var slot by remember { mutableIntStateOf(2) }
    LaunchedEffect(refresh, reload) { state = seams.state() }
    val opener = rememberLauncherForActivityResult(OpenKeyFile()) { uri ->
        if (!seams.pickerClosed() || uri == null) return@rememberLauncherForActivityResult
        action = FactorAction.AddFile(seams.describe(uri), created = false)
    }
    val creator = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (!seams.pickerClosed() || uri == null) return@rememberLauncherForActivityResult
        action = FactorAction.AddFile(seams.describe(uri), created = true)
    }
    fun toggle(block: suspend () -> Unit) {
        scope.launch {
            message = try {
                block(); null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                failure(e, txt)
            }
            reload++
        }
    }
    Section(
        stringResource(R.string.factors_section),
        footer = message ?: if (state.passwordOn) stringResource(R.string.factors_footer) else null,
        tag = "settings-factors",
    ) {
        if (!state.passwordOn) {
            Text(
                stringResource(R.string.factors_needs_app_password),
                color = LgkTheme.colors.secondaryText,
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(vertical = 12.dp).testTag("factors-needs-app-password"),
            )
            return@Section
        }
        Status(stringResource(R.string.factors_keyfile), stringResource(if (state.keyFile) R.string.factors_keyfile_set else R.string.factors_keyfile_none), divider = false)
        RowButton(stringResource(R.string.factors_add_keyfile), "factors-add-keyfile") {
            seams.willOpenPicker()
            opener.launch(arrayOf("*/*"))
        }
        if (!state.keyFile) {
            RowButton(stringResource(R.string.factors_create_keyfile), "factors-create-keyfile") {
                seams.willOpenPicker()
                creator.launch(NEW_KEY_FILE_NAME)
            }
        } else {
            RowButton(stringResource(R.string.factors_remove_keyfile), "factors-remove-keyfile", destructive = true) { action = FactorAction.RemoveFile }
        }
        val ykSlot = state.yubiKeySlot
        Status(
            stringResource(R.string.factors_yubikey),
            if (ykSlot != null) stringResource(R.string.factors_yubikey_set, ykSlot) else stringResource(R.string.factors_yubikey_none),
        )
        if (ykSlot == null) {
            Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.factors_slot), color = LgkTheme.colors.text, modifier = Modifier.weight(1f))
                SingleChoiceSegmentedButtonRow {
                    listOf(1, 2).forEachIndexed { i, n ->
                        SegmentedButton(
                            selected = slot == n,
                            onClick = { slot = n },
                            shape = SegmentedButtonDefaults.itemShape(i, 2),
                            modifier = Modifier.testTag("factors-slot-$n"),
                        ) { Text("$n") }
                    }
                }
            }
            RowButton(stringResource(R.string.factors_add_yubikey), "factors-add-yubikey") { action = FactorAction.AddYubiKey(slot) }
        } else {
            RowButton(stringResource(R.string.factors_remove_yubikey), "factors-remove-yubikey", destructive = true) { action = FactorAction.RemoveYubiKey }
        }
        Toggle(
            stringResource(R.string.factors_always_ask), state.alwaysAsk,
            description = stringResource(R.string.factors_always_ask_note), enabled = state.any || state.alwaysAsk, tag = "factors-always-ask",
        ) { on -> toggle { seams.setAlwaysAsk(on) } }
        Toggle(stringResource(R.string.factors_remember), state.remember, tag = "factors-remember") { on -> toggle { seams.setRemember(on) } }
    }
    action?.let { a ->
        FactorPasswordDialog(seams, state, a, onDismiss = {
            (a as? FactorAction.AddFile)?.let { seams.discard(it.file) }
            action = null
        }) { done ->
            action = null
            message = done
            reload++
        }
    }
}

@Composable
private fun Status(label: String, value: String, divider: Boolean = true) {
    val c = LgkTheme.colors
    if (divider) androidx.compose.material3.HorizontalDivider(thickness = 0.5.dp, color = c.separator)
    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Text(value, color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
    }
}

/**
 * The app password for [action] (and, when a key file is set but not remembered, that key file). [onDone] gets the
 * message to show; a failure stays in the dialog.
 */
@Composable
private fun FactorPasswordDialog(seams: FactorSeams, state: FactorState, action: FactorAction, onDismiss: () -> Unit, onDone: (String) -> Unit) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var current by remember { mutableStateOf<KeyFileRef?>(null) }
    var problem by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val needsCurrent = state.keyFile && state.rememberedKeyFile == null
    val chooser = rememberLauncherForActivityResult(OpenKeyFile()) { uri ->
        if (!seams.pickerClosed() || uri == null) return@rememberLauncherForActivityResult
        current = seams.describe(uri)
    }
    val title = when (action) {
        is FactorAction.AddFile -> stringResource(if (action.created) R.string.factors_create_keyfile else R.string.factors_add_keyfile).trimEnd('…', '.')
        is FactorAction.AddYubiKey -> stringResource(R.string.factors_add_yubikey)
        FactorAction.RemoveFile -> stringResource(R.string.factors_remove_keyfile)
        FactorAction.RemoveYubiKey -> stringResource(R.string.factors_remove_yubikey)
    }
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                when (action) {
                    is FactorAction.AddFile -> {
                        Text(stringResource(R.string.factors_prompt_keyfile, action.file.name), color = c.text)
                        Text(stringResource(R.string.factors_add_confirm), color = c.secondaryText)
                    }
                    is FactorAction.AddYubiKey -> {
                        Text(stringResource(R.string.factors_yubikey_setup), color = c.secondaryText)
                        Text(stringResource(R.string.factors_add_confirm), color = c.secondaryText)
                    }
                    else -> Text(stringResource(R.string.factors_remove_confirm), color = c.secondaryText)
                }
                Text(stringResource(R.string.factors_password_text), color = c.text)
                AppPasswordField(password, { password = it; problem = null }, stringResource(R.string.app_password_current), "factors-password")
                if (needsCurrent) {
                    val name = current?.name
                    Text(
                        if (name != null) stringResource(R.string.factors_prompt_keyfile, name) else stringResource(R.string.factors_prompt_no_keyfile),
                        color = c.secondaryText,
                    )
                    TextButton(enabled = !busy, onClick = { seams.willOpenPicker(); chooser.launch(arrayOf("*/*")) }, modifier = Modifier.testTag("factors-choose-current")) {
                        Text(stringResource(R.string.factors_prompt_choose), color = c.accentText)
                    }
                }
                if (busy) CircularProgressIndicator()
                problem?.let { Text(it, color = c.danger) }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy && password.isNotEmpty(),
                modifier = Modifier.testTag("factors-confirm"),
                onClick = {
                    busy = true
                    scope.launch {
                        try {
                            val done = when (action) {
                                is FactorAction.AddFile -> {
                                    if (action.created) {
                                        seams.createKeyFile(password, action.file, state.remember, current)
                                        txt.s(R.string.factors_keyfile_created, action.file.name)
                                    } else {
                                        seams.addKeyFile(password, action.file, state.remember, current)
                                        txt.s(R.string.factors_keyfile_added, action.file.name)
                                    }
                                }
                                is FactorAction.AddYubiKey -> {
                                    seams.addYubiKey(password, action.slot, current)
                                    txt.s(R.string.factors_yubikey_added, action.slot)
                                }
                                FactorAction.RemoveFile -> {
                                    seams.removeKeyFile(password, current)
                                    txt.s(R.string.factors_keyfile_removed)
                                }
                                FactorAction.RemoveYubiKey -> {
                                    seams.removeYubiKey(password, current)
                                    txt.s(R.string.factors_yubikey_removed_done)
                                }
                            }
                            password = ""
                            onDone(done)
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            problem = failure(e, txt)
                        } finally {
                            busy = false
                        }
                    }
                },
            ) { Text(stringResource(R.string.common_continue), color = c.accentText) }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onDismiss) { Text(stringResource(R.string.common_cancel), color = c.accentText) } },
    )
}

/** "Touch your YubiKey" while Settings waits for one ([FactorSeams.yubiKeyPrompt]), with Cancel. */
@Composable
internal fun YubiKeyTouchDialog(seams: FactorSeams) {
    val slot by seams.yubiKeyPrompt.collectAsStateWithLifecycle()
    val waiting = slot ?: return
    AlertDialog(
        onDismissRequest = {},
        title = { Text(stringResource(R.string.factors_touch_title)) },
        text = { Text(stringResource(R.string.factors_prompt_yubikey, waiting)) },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = seams.cancelYubiKey, modifier = Modifier.testTag("factors-touch-cancel")) {
                Text(stringResource(R.string.common_cancel), color = LgkTheme.colors.accentText)
            }
        },
    )
}
