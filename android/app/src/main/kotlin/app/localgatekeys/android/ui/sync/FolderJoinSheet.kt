package app.localgatekeys.android.ui.sync
import androidx.annotation.StringRes
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.sync.SafFolderOpener
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.unlock.LocalActivityMonitor
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow

/** The folder sheet's copy (iPhone `SyncScreen.swift` password sheet; the Google Drive notice is Android-only). */
object FolderJoinText {
    @StringRes val TITLE = R.string.folder_sync_password
    @StringRes val FIELD = R.string.folder_sync_password
    @StringRes val FOOTER = R.string.folder_password_footer

    /** Spec section 3: Google Drive's Android app offers no folder to other apps; said plainly, with what to do instead. */
    @StringRes val GOOGLE_DRIVE_NOTICE = R.string.folder_google_drive_notice
}

/**
 * "Sync password" for the picked folder (the iPhone's password sheet): a masked password field (password keyboard, no
 * suggestions; Ruling 15's no-learning flag comes from the app-wide wrapper), Cancel and Join; Join is disabled while
 * the field is empty. The password stays in [form] (memory only) and is cleared once used.
 */
@Composable
fun FolderPasswordSheet(form: FolderPasswordForm, onCancel: () -> Unit, onJoin: () -> Unit) {
    val c = LgkTheme.colors
    val monitor = LocalActivityMonitor.current
    val password by form.password.collectAsStateWithLifecycle()
    val focus = remember { FocusRequester() }
    val fieldLabel = stringResource(FolderJoinText.FIELD)
    BackHandler(onBack = onCancel)
    LaunchedEffect(form) { runCatching { focus.requestFocus() } }
    Box(Modifier.fillMaxSize().pointerInput(Unit) { awaitPointerEventScope { while (true) awaitPointerEvent() } }.testTag("folder-password")) {
        GlassBackdropHost(Modifier.fillMaxSize()) { AuroraBackground() }
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            Row(Modifier.fillMaxWidth().height(64.dp).padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                TextButton(onCancel) { Text(stringResource(R.string.common_cancel), color = c.accentText) }
                Text(
                    stringResource(FolderJoinText.TITLE), color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    textAlign = TextAlign.Center, modifier = Modifier.weight(1f).semantics { heading() },
                )
                Button(
                    onJoin,
                    enabled = password.isNotEmpty(),
                    colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
                    modifier = Modifier.padding(end = 4.dp).testTag("folder-join"),
                ) { Text(stringResource(R.string.sync_join), fontWeight = FontWeight.SemiBold) }
            }
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).navigationBarsPadding().imePadding().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Column(Modifier.fillMaxWidth().lgkGroupSurface().padding(16.dp)) {
                    BasicTextField(
                        value = password,
                        onValueChange = { monitor?.textChanged(); form.update(it) },
                        textStyle = MaterialTheme.typography.bodyLarge.copy(color = c.text),
                        cursorBrush = SolidColor(c.accent),
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done,
                        ),
                        keyboardActions = KeyboardActions(onDone = { if (form.canJoin) onJoin() }),
                        modifier = Modifier.fillMaxWidth().focusRequester(focus).testTag("folder-password-field")
                            .semantics { contentDescription = fieldLabel },
                        decorationBox = { inner ->
                            Box {
                                if (password.isEmpty()) Text(stringResource(FolderJoinText.FIELD), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
                                inner()
                            }
                        },
                    )
                }
                Text(
                    stringResource(FolderJoinText.FOOTER), color = c.secondaryText, style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(horizontal = 4.dp),
                )
            }
        }
    }
}

/**
 * The system folder picker (`ACTION_OPEN_DOCUMENT_TREE`) for the Sync tab. [onOpen] runs just before the picker opens;
 * [onClose] when its result comes back and answers whether the vault is still unlocked (the lock's system-screen
 * allowance, Ruling 21: the picker is another app's screen and stops this one). A pick that returns after the vault
 * locked is dropped without persisting anything; otherwise the folder's read and write permission is persisted through
 * [opener] before the pick is handed on. Results go to a buffered channel: one redelivered after the activity was
 * recreated reaches the new screen. A second [FolderPicking.pick] while the picker is open is ignored.
 */
@Composable
fun rememberSafFolderPicker(opener: SafFolderOpener, onOpen: () -> Unit = {}, onClose: () -> Boolean = { true }): FolderPicking {
    val open by rememberUpdatedState(onOpen)
    val close by rememberUpdatedState(onClose)
    val sink = remember { Channel<FolderPick>(Channel.BUFFERED) }
    val pending = remember { booleanArrayOf(false) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        pending[0] = false
        val stillUnlocked = close()
        FolderPickResults.decide(uri, stillUnlocked) { opener.persist(it) }?.let { sink.trySend(it) }
    }
    return remember(launcher) {
        object : FolderPicking {
            override val results: Flow<FolderPick> = sink.receiveAsFlow()

            override fun pick() {
                if (pending[0]) return // a double tap while the picker opens
                pending[0] = true
                open()
                try {
                    launcher.launch(null)
                } catch (e: Exception) {
                    pending[0] = false
                    close()
                    sink.trySend(FolderPick.Failed)
                }
            }

            override fun toString(): String = "SafFolderPicker"
        }
    }
}
