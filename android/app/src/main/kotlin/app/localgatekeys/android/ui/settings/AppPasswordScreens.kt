package app.localgatekeys.android.ui.settings

import app.localgatekeys.android.i18n.Txt
import androidx.compose.ui.res.stringResource
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.rememberTxt
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.settings.AppPasswordSeams
import app.localgatekeys.android.settings.AppPasswordText
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.unlock.AppPasswordField
import app.localgatekeys.android.unlock.AppLockModel
import app.localgatekeys.core.crypto.AppPasswordRecord
import app.localgatekeys.core.primitives.SystemRandomSource
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/** What a failed app-password action says (never the password). */
private fun failure(e: Exception, t: Txt): String = AppLockModel.message(e, t) ?: t.s(R.string.error_cancelled)

/**
 * Settings > Security > App password (Task 7): the switch (on opens [onSetup]; off asks for the current password),
 * the fingerprint shortcut and Change app password. [refresh] bumps after the setup page closes.
 */
@Composable
internal fun AppPasswordSection(seams: AppPasswordSeams, refresh: Int, onSetup: () -> Unit) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val appPw = AppPasswordText(rememberTxt())
    val scope = rememberCoroutineScope()
    var on by remember { mutableStateOf(false) }
    var bio by remember { mutableStateOf(false) }
    var dialog by remember { mutableStateOf<String?>(null) } // "off" or "change"
    var message by remember { mutableStateOf<String?>(null) }
    var reload by remember { mutableIntStateOf(0) }
    LaunchedEffect(refresh, reload) {
        on = seams.isOn()
        bio = on && seams.biometricOn()
    }
    Section(appPw.section, footer = message ?: if (on) appPw.footerOn else appPw.footerOff, tag = "settings-app-password") {
        Toggle(appPw.toggle, on) { want -> if (want) onSetup() else dialog = "off" }
        if (on) {
            if (seams.biometricAvailable() || bio) {
                Toggle(appPw.biometricToggle, bio) { want ->
                    scope.launch {
                        message = try {
                            seams.setBiometric(want); null
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            failure(e, txt)
                        }
                        reload++
                    }
                }
            }
            RowButton(appPw.change, "settings-app-password-change") { dialog = "change" }
        }
    }
    when (dialog) {
        "off" -> PasswordDialog(
            title = txt.s(R.string.app_password_turn_off_title),
            text = txt.s(R.string.app_password_turn_off_text),
            confirmLabel = txt.s(R.string.app_password_turn_off_confirm),
            withNew = false,
            onDismiss = { dialog = null },
        ) { current, _ ->
            try {
                seams.turnOff(current); dialog = null; message = null; reload++; null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                failure(e, txt)
            }
        }
        "change" -> PasswordDialog(
            title = appPw.change,
            text = txt.s(R.string.app_password_change_text),
            confirmLabel = txt.s(R.string.common_change),
            withNew = true,
            onDismiss = { dialog = null },
        ) { current, new ->
            try {
                seams.change(current, new); dialog = null; message = txt.s(R.string.app_password_changed); null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                failure(e, txt)
            }
        }
    }
}

/** The current password (and with [withNew] a new one twice). [submit] returns the problem to show, null when done. */
@Composable
private fun PasswordDialog(
    title: String,
    text: String,
    confirmLabel: String,
    withNew: Boolean,
    onDismiss: () -> Unit,
    submit: suspend (current: String, new: String) -> String?,
) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    val appPw = AppPasswordText(txt)
    val scope = rememberCoroutineScope()
    var current by remember { mutableStateOf("") }
    var new by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var problem by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text)
                AppPasswordField(current, { current = it; problem = null }, stringResource(R.string.app_password_current), "app-password-current")
                if (withNew) {
                    AppPasswordField(new, { new = it; problem = null }, stringResource(R.string.app_password_new), "app-password-new")
                    AppPasswordField(confirm, { confirm = it; problem = null }, stringResource(R.string.app_password_confirm_new), "app-password-confirm")
                    if (new.isNotEmpty()) Text(stringResource(R.string.backup_strength, appPw.label(new)), color = c.secondaryText)
                }
                if (busy) CircularProgressIndicator()
                problem?.let { Text(it, color = c.danger) }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy && current.isNotEmpty(),
                onClick = {
                    if (withNew) appPw.problem(new, confirm)?.let { problem = it; return@TextButton }
                    busy = true
                    scope.launch {
                        problem = submit(current, new)
                        current = ""
                        busy = false
                    }
                },
            ) { Text(confirmLabel, color = c.accentText) }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onDismiss) { Text(stringResource(R.string.common_cancel), color = c.accentText) } },
    )
}

/**
 * Turning the app password on: the password twice with the strength check, the 24 words with the warning, then three
 * of them typed back. Nothing changes on disk until the last step ([AppPasswordSeams.commit]).
 */
@Composable
internal fun AppPasswordSetup(seams: AppPasswordSeams, onDone: () -> Unit) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    val appPw = AppPasswordText(txt)
    val scope = rememberCoroutineScope()
    var step by remember { mutableIntStateOf(0) }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var biometric by remember { mutableStateOf(seams.biometricAvailable()) }
    var created by remember { mutableStateOf<AppPasswordRecord.Created?>(null) }
    val positions = remember { AppPasswordText.confirmPositions(SystemRandomSource()) }
    val typed = remember { mutableStateOf(listOf("", "", "")) }
    var problem by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val cancel = { created = null; password = ""; confirm = ""; onDone() }
    BackHandler(enabled = !busy) { if (step == 0) cancel() else step -= 1 }
    Page(txt.s(R.string.app_password_title), "app-password-setup", onBack = { if (!busy) cancel() }, doneLabel = txt.s(R.string.common_cancel)) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).imePadding().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            when (step) {
                0 -> {
                    Text(
                        stringResource(R.string.app_password_choose_text),
                        color = c.text,
                    )
                    AppPasswordField(password, { password = it; problem = null }, stringResource(R.string.app_password_field), "setup-password")
                    AppPasswordField(confirm, { confirm = it; problem = null }, stringResource(R.string.app_password_confirm), "setup-confirm")
                    if (password.isNotEmpty()) Text(stringResource(R.string.backup_strength, appPw.label(password)), color = c.secondaryText)
                    if (seams.biometricAvailable()) {
                        Toggle(appPw.biometricToggle, biometric) { biometric = it }
                    }
                    Next(txt.s(R.string.common_continue), enabled = !busy) {
                        val p = appPw.problem(password, confirm)
                        if (p != null) { problem = p; return@Next }
                        busy = true
                        scope.launch {
                            try {
                                created = seams.prepare(password)
                                password = ""; confirm = ""
                                step = 1
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                problem = failure(e, txt)
                            } finally {
                                busy = false
                            }
                        }
                    }
                }
                1 -> {
                    Text(stringResource(R.string.app_password_phrase_title), color = c.text, style = MaterialTheme.typography.titleMedium)
                    Text(appPw.phraseWarning, color = c.danger)
                    val words = created?.phrase?.split(" ").orEmpty()
                    Text(
                        words.mapIndexed { i, w -> "${i + 1}. $w" }.chunked(3).joinToString("\n") { it.joinToString("    ") },
                        color = c.text,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.testTag("setup-phrase"),
                    )
                    Next(txt.s(R.string.app_password_wrote_down)) { step = 2 }
                }
                else -> {
                    Text(stringResource(R.string.app_password_phrase_confirm), color = c.text)
                    positions.forEachIndexed { i, pos ->
                        OutlinedTextField(
                            value = typed.value[i],
                            onValueChange = { v -> typed.value = typed.value.toMutableList().also { it[i] = v }; problem = null },
                            label = { Text(stringResource(R.string.app_password_word_n, pos + 1)) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth().testTag("setup-word-$i"),
                        )
                    }
                    Next(txt.s(R.string.app_password_turn_on), enabled = !busy) {
                        val made = created ?: return@Next
                        if (!AppPasswordText.confirms(made.phrase, positions, typed.value)) {
                            problem = txt.s(R.string.app_password_words_mismatch)
                            return@Next
                        }
                        busy = true
                        scope.launch {
                            try {
                                val bioOk = seams.commit(made, biometric)
                                created = null
                                if (!bioOk) problem = txt.s(R.string.app_password_bio_not_set)
                                onDone()
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                problem = failure(e, txt)
                            } finally {
                                busy = false
                            }
                        }
                    }
                }
            }
            if (busy) CircularProgressIndicator()
            problem?.let { Text(it, color = c.danger) }
        }
    }
}

@Composable
private fun Next(label: String, enabled: Boolean = true, onClick: () -> Unit) {
    val c = LgkTheme.colors
    Button(
        onClick = onClick,
        enabled = enabled,
        colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
        modifier = Modifier.fillMaxWidth().testTag("setup-next"),
    ) { Text(label, modifier = Modifier.padding(vertical = 6.dp)) }
}
