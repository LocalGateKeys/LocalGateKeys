package app.localgatekeys.android.ui.editor
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource

import app.localgatekeys.android.editor.EditorScreenText
import app.localgatekeys.android.i18n.rememberTxt
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.editor.PasskeyRenameModel
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.unlock.LocalActivityMonitor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Rename or delete a passkey (port of `PasskeyEditView` in `ios/App/Editor/PasskeyEditor.swift`). [onDone] gets SAVED
 * when the store changed (reload and close) or UNCHANGED (close).
 */
@Composable
fun PasskeyEditScreen(model: PasskeyRenameModel, onDone: (SaveResult) -> Unit, onCancel: () -> Unit) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val title by model.title.collectAsStateWithLifecycle()
    val error by model.errorFlow.collectAsStateWithLifecycle()
    val alreadyRemoved by model.alreadyRemovedFlow.collectAsStateWithLifecycle()
    val monitor = LocalActivityMonitor.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    val nameLabel = stringResource(R.string.passkey_editor_name)
    var confirmDelete by remember { mutableStateOf(false) }
    BackHandler(onBack = onCancel)

    fun run(action: () -> SaveResult, then: (SaveResult) -> Unit) {
        if (busy) return
        busy = true
        scope.launch {
            val r = withContext(Dispatchers.IO) { action() }
            busy = false
            then(r)
        }
    }

    Box(Modifier.fillMaxSize().testTag("passkey-editor")) {
        AuroraBackground()
        Column(Modifier.fillMaxSize().statusBarsPadding().imePadding()) {
            SheetHeader(txt.s(PasskeyRenameModel.TITLE), onCancel, saveEnabled = !busy, onSave = {
                run(model::save) { r -> if (r == SaveResult.SAVED || r == SaveResult.UNCHANGED) onDone(r) }
            })
            Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Column {
                    Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface).padding(16.dp)) {
                        BasicTextField(
                            value = title,
                            onValueChange = { monitor?.textChanged(); model.setTitle(it) },
                            singleLine = true,
                            textStyle = MaterialTheme.typography.bodyLarge.copy(color = c.text),
                            cursorBrush = SolidColor(c.accent),
                            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words),
                            modifier = Modifier.fillMaxWidth().testTag("passkey-name").semantics { contentDescription = nameLabel },
                            decorationBox = { inner ->
                                Box {
                                    if (title.isEmpty()) Text(stringResource(R.string.passkey_editor_name), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
                                    inner()
                                }
                            },
                        )
                    }
                    Text(
                        txt.s(PasskeyRenameModel.FOOTER), color = c.secondaryText, style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(start = 4.dp, top = 6.dp),
                    )
                }
                error?.let { Text(it, color = c.danger, style = MaterialTheme.typography.bodyMedium) }
                TextButton(
                    { confirmDelete = true }, enabled = !busy,
                    modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface),
                ) { Text(txt.s(PasskeyRenameModel.DELETE), color = c.danger) }
            }
        }
    }
    if (confirmDelete) {
        ConfirmDelete(txt.s(PasskeyRenameModel.DELETE_TITLE), txt.s(PasskeyRenameModel.DELETE_MESSAGE), onDismiss = { confirmDelete = false }) {
            confirmDelete = false
            run(model::delete) { r -> if (r == SaveResult.SAVED) onDone(SaveResult.SAVED) }
        }
    }
    if (alreadyRemoved) {
        AlertDialog(
            onDismissRequest = { model.clearAlreadyRemoved(); onDone(SaveResult.SAVED) },
            // The list reloads (the passkey is gone) and the screen closes.
            confirmButton = { TextButton({ model.clearAlreadyRemoved(); onDone(SaveResult.SAVED) }) { Text(stringResource(R.string.common_ok)) } },
            title = { Text(txt.s(EditorScreenText.ALREADY_REMOVED)) },
        )
    }
}
