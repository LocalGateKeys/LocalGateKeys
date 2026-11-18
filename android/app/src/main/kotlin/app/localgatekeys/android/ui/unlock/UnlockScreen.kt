package app.localgatekeys.android.ui.unlock
import androidx.compose.ui.res.stringResource

import app.localgatekeys.android.i18n.rememberTxt
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.Checkbox
import androidx.compose.runtime.mutableStateOf
import app.localgatekeys.android.R
import app.localgatekeys.android.unlock.AppLockModel
import app.localgatekeys.android.unlock.KeyFileRef
import app.localgatekeys.android.unlock.OpenKeyFile
import app.localgatekeys.core.crypto.FactorKind
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.LgkTheme

/** The unlock screen for [model]; [onUnlock] and [onStartFresh] launch the model's suspend calls. */
@Composable
fun UnlockScreen(
    model: AppLockModel,
    onUnlock: () -> Unit,
    onStartFresh: () -> Unit,
    onPassword: (String) -> Unit = {},
    onRecover: (String, String) -> Unit = { _, _ -> },
    biometricShortcut: () -> Boolean = { false },
    /** Task 9: a picked key file's name (no grant is persisted here: only after it worked); null: no picker here. */
    describeKeyFile: ((uri: android.net.Uri) -> KeyFileRef)? = null,
) {
    val needsPassword by model.needsPassword.collectAsStateWithLifecycle()
    val factorSpecs by model.factorSpecs.collectAsStateWithLifecycle()
    val keyFile by model.keyFile.collectAsStateWithLifecycle()
    val yubiKeyPrompt by model.yubiKeyPrompt.collectAsStateWithLifecycle()
    // Follows Settings: with "Don't remember" the box is not offered and nothing is remembered.
    val canRemember = model.remembersKeyFile()
    var rememberKeyFile by rememberSaveable { mutableStateOf(canRemember) }
    val picker = rememberLauncherForActivityResult(OpenKeyFile()) { uri ->
        val describe = describeKeyFile
        if (uri != null && describe != null) model.chooseKeyFile(describe(uri), rememberKeyFile && canRemember)
    }
    val state by model.state.collectAsStateWithLifecycle()
    val errorMessage by model.errorMessage.collectAsStateWithLifecycle()
    val offersStartFresh by model.offersStartFresh.collectAsStateWithLifecycle()
    UnlockContent(
        unlocking = state == AppLockModel.State.UNLOCKING,
        errorMessage = errorMessage,
        offersStartFresh = offersStartFresh,
        onUnlock = onUnlock,
        onStartFresh = onStartFresh,
        passwordPanel = if (!needsPassword) null else {
            {
                AppPasswordUnlockPanel(
                    unlocking = state == AppLockModel.State.UNLOCKING,
                    biometric = biometricShortcut(),
                    onPassword = onPassword,
                    onBiometric = onUnlock,
                    onRecover = onRecover,
                    factorRows = if (factorSpecs.isEmpty()) null else {
                        {
                            FactorUnlockRows(
                                needsKeyFile = factorSpecs.any { it.kind == FactorKind.KEYFILE },
                                keyFile = keyFile,
                                remember = rememberKeyFile,
                                onRemember = if (canRemember) ({ rememberKeyFile = it }) else null,
                                canPick = describeKeyFile != null && state != AppLockModel.State.UNLOCKING,
                                onPick = {
                                    model.willOpenLockedPicker()
                                    picker.launch(arrayOf("*/*"))
                                },
                                yubiKeyPrompt = yubiKeyPrompt,
                                onCancelYubiKey = { model.cancelYubiKey() },
                            )
                        }
                    },
                )
            }
        },
    )
}

/**
 * Port of `ios/App/Unlock/UnlockView.swift`: aurora, brand mark, title, the last error, "Start fresh anyway" when
 * offered (two confirmations), and the Unlock button. Both buttons are disabled while unlocking.
 */
@Composable
fun UnlockContent(
    unlocking: Boolean,
    errorMessage: String?,
    offersStartFresh: Boolean,
    onUnlock: () -> Unit,
    onStartFresh: () -> Unit,
    /** Task 7: shown instead of the Unlock button while the app password is needed. */
    passwordPanel: (@Composable () -> Unit)? = null,
) {
    val txt = rememberTxt()
    val colors = LgkTheme.colors
    // "Start fresh anyway": 0 none, 1 first confirmation, 2 second.
    var freshStep by rememberSaveable { mutableIntStateOf(0) }
    Box(Modifier.fillMaxSize()) {
        AuroraBackground()
        Column(
            Modifier.fillMaxSize().systemBarsPadding(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            Spacer(Modifier.weight(1f))
            Image(
                painterResource(R.drawable.brand_mark),
                contentDescription = null,
                modifier = Modifier
                    .size(96.dp)
                    .shadow(16.dp, RoundedCornerShape(22.dp), ambientColor = Color.Black.copy(alpha = 0.25f), spotColor = Color.Black.copy(alpha = 0.25f))
                    .testTag("brandMark"),
            )
            Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("LocalGateKeys", color = colors.text, fontSize = 28.sp, fontWeight = FontWeight.Bold)
                // The Windows unlock screen's tagline (unlock.tagline).
                Text(
                    stringResource(R.string.unlock_tagline),
                    color = colors.secondaryText,
                    fontSize = 17.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 32.dp),
                )
            }
            if (errorMessage != null) {
                Text(
                    errorMessage,
                    color = colors.secondaryText,
                    fontSize = 16.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 32.dp),
                )
            }
            if (offersStartFresh) {
                TextButton(onClick = { freshStep = 1 }, enabled = !unlocking) {
                    Text(stringResource(R.string.unlock_start_fresh_anyway), color = if (unlocking) colors.secondaryText else colors.danger)
                }
            }
            Spacer(Modifier.weight(1f))
            if (passwordPanel != null) {
                Box(Modifier.padding(bottom = 32.dp).imePadding()) { passwordPanel() }
            } else Button(
                onClick = onUnlock,
                enabled = !unlocking,
                colors = ButtonDefaults.buttonColors(containerColor = colors.accent, contentColor = Color.White),
                modifier = Modifier.fillMaxWidth().padding(start = 32.dp, end = 32.dp, bottom = 48.dp),
            ) {
                Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.unlock_button), modifier = Modifier.padding(vertical = 6.dp))
            }
        }
    }
    if (freshStep == 1) {
        AlertDialog(
            onDismissRequest = { freshStep = 0 },
            text = { Text(txt.s(AppLockModel.START_FRESH_CONFIRM_1)) },
            confirmButton = { TextButton(onClick = { freshStep = 2 }) { Text(stringResource(R.string.unlock_start_fresh), color = colors.danger) } },
            dismissButton = { TextButton(onClick = { freshStep = 0 }) { Text(stringResource(R.string.common_cancel)) } },
        )
    }
    if (freshStep == 2) {
        AlertDialog(
            onDismissRequest = { freshStep = 0 },
            text = { Text(txt.s(AppLockModel.START_FRESH_CONFIRM_2)) },
            confirmButton = {
                TextButton(onClick = {
                    freshStep = 0
                    onStartFresh()
                }) { Text(stringResource(R.string.unlock_start_fresh_now), color = colors.danger) }
            },
            dismissButton = { TextButton(onClick = { freshStep = 0 }) { Text(stringResource(R.string.common_cancel)) } },
        )
    }
}

/**
 * Task 9: under the app password field, the key file ("Key file: name" or "No key file chosen", Choose key file… and
 * Remember this key file on this phone) and, while a YubiKey is awaited, what to do with it and Cancel.
 */
@Composable
private fun FactorUnlockRows(
    needsKeyFile: Boolean,
    keyFile: KeyFileRef?,
    remember: Boolean,
    /** Null with "Don't remember" (no box). */
    onRemember: ((Boolean) -> Unit)?,
    canPick: Boolean,
    onPick: () -> Unit,
    yubiKeyPrompt: AppLockModel.YubiKeyPrompt?,
    onCancelYubiKey: () -> Unit,
) {
    val colors = LgkTheme.colors
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        if (needsKeyFile) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (keyFile != null) stringResource(R.string.factors_prompt_keyfile, keyFile.name) else stringResource(R.string.factors_prompt_no_keyfile),
                    color = colors.secondaryText,
                    modifier = Modifier.weight(1f).testTag("unlock-keyfile-name"),
                )
                TextButton(onClick = onPick, enabled = canPick, modifier = Modifier.testTag("unlock-keyfile-choose")) {
                    Text(stringResource(R.string.factors_prompt_choose), color = colors.accentText)
                }
            }
            if (onRemember != null) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = remember, onCheckedChange = onRemember, modifier = Modifier.testTag("unlock-keyfile-remember"))
                    Text(stringResource(R.string.factors_prompt_remember), color = colors.secondaryText)
                }
            }
        }
        if (yubiKeyPrompt != null) {
            Text(
                if (yubiKeyPrompt.again) stringResource(R.string.factors_yubikey_removed)
                else stringResource(R.string.factors_prompt_yubikey, yubiKeyPrompt.slot),
                color = colors.text,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().testTag("unlock-yubikey-prompt"),
            )
            TextButton(onClick = onCancelYubiKey, modifier = Modifier.fillMaxWidth().testTag("unlock-yubikey-cancel")) {
                Text(stringResource(R.string.common_cancel), color = colors.accentText)
            }
        }
    }
}
