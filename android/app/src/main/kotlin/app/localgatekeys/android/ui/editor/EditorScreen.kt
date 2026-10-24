package app.localgatekeys.android.ui.editor

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.editor.EditorScreenText
import app.localgatekeys.android.editor.IsoDate
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.pro.ProFeatures
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkSwitchColors
import app.localgatekeys.android.unlock.LocalActivityMonitor
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.sync.ItemStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** What the editor screens need from the rest of the app (per unlock: the open vault's store). */
class EditorSeams(
    val store: ItemStore,
    val random: RandomSource = SystemRandomSource(),
    /** After a save or delete changed the store (sync's noteLocalEdit, Task 10); the list reload is RootScaffold's. */
    val onLocalEdit: () -> Unit = {},
    /**
     * Opens the password generator and hands back the chosen password. Null here: RootScaffold supplies its generator
     * sheet ([withGenerate]); a screen shown without one has no wand button.
     */
    val onGenerate: ((onPassword: (String) -> Unit) -> Unit)? = null,
    /**
     * Opens the 2FA QR scanner: the scanned text, or null when the camera is unavailable. Null here: RootScaffold supplies
     * its scanner ([withScanTotp]); a screen shown without one has no scan button.
     */
    val onScanTotp: ((onResult: (String?) -> Unit) -> Unit)? = null,
) {
    /** The same seams with [onGenerate] set (unless one was already given). */
    fun withGenerate(open: (onPassword: (String) -> Unit) -> Unit): EditorSeams =
        if (onGenerate != null) this else EditorSeams(store, random, onLocalEdit, open, onScanTotp)

    /** The same seams with [onScanTotp] set (unless one was already given): RootScaffold's QR scanner. */
    fun withScanTotp(open: (onResult: (String?) -> Unit) -> Unit): EditorSeams =
        if (onScanTotp != null) this else EditorSeams(store, random, onLocalEdit, onGenerate, open)

    override fun toString(): String = "EditorSeams"
}

/**
 * Create or edit one item (port of `ios/App/Editor/EditorView.swift`): the kind's fields with masked secrets, inline
 * errors, Delete item when editing. [onDone] gets SAVED (the store changed: reload and close) or UNCHANGED (close);
 * [onUpgrade] runs when saving needs Pro (`totp` true: the 2FA rule, false: the item limit).
 */
@Composable
fun EditorScreen(
    model: EditorModel,
    clock: UnixClock,
    seams: EditorSeams,
    onDone: (SaveResult) -> Unit,
    onCancel: () -> Unit,
    onUpgrade: (totp: Boolean) -> Unit,
) {
    val c = LgkTheme.colors
    val state by model.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    BackHandler(onBack = onCancel)

    fun save() {
        if (busy) return
        busy = true
        scope.launch {
            val r = withContext(Dispatchers.IO) { model.save() }
            busy = false
            when (r) {
                SaveResult.SAVED, SaveResult.UNCHANGED -> onDone(r)
                SaveResult.NEEDS_PRO -> if (model.showUpgrade) {
                    model.dismissUpgrade()
                    onUpgrade(model.totpError == ProFeatures.totpMessage)
                }
                else -> Unit
            }
        }
    }

    fun delete() {
        if (busy) return
        busy = true
        scope.launch {
            val r = withContext(Dispatchers.IO) { model.delete() }
            busy = false
            if (r == SaveResult.SAVED) onDone(SaveResult.SAVED)
        }
    }

    Box(Modifier.fillMaxSize().testTag("editor")) {
        AuroraBackground()
        Column(Modifier.fillMaxSize().statusBarsPadding().imePadding()) {
            SheetHeader(EditorScreenText.title(model.kind, model.isNew), onCancel, ::save, saveEnabled = !busy)
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).navigationBarsPadding()
                    .padding(start = 16.dp, end = 16.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface)) {
                    val fields = model.kind.fields
                    fields.forEachIndexed { index, field ->
                        FieldRow(model, field, state.values[field.key] ?: "", clock, seams)
                        if (index != fields.lastIndex) Separator()
                    }
                }
                state.error?.let { error ->
                    Text(
                        error, color = c.danger, style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface)
                            .padding(16.dp).testTag("editor-error"),
                    )
                }
                if (!model.isNew) {
                    TextButton(
                        { confirmDelete = true }, enabled = !busy,
                        modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface),
                    ) { Text(EditorScreenText.DELETE_ITEM, color = c.danger) }
                }
            }
        }
    }
    if (confirmDelete) {
        ConfirmDelete(EditorScreenText.DELETE_TITLE, EditorScreenText.DELETE_MESSAGE, onDismiss = { confirmDelete = false }) {
            confirmDelete = false
            delete()
        }
    }
    if (state.alreadyRemoved) {
        AlertDialog(
            onDismissRequest = { model.clearAlreadyRemoved(); onDone(SaveResult.SAVED) },
            // The list reloads (the item is gone) and the editor closes.
            confirmButton = { TextButton({ model.clearAlreadyRemoved(); onDone(SaveResult.SAVED) }) { Text("OK") } },
            title = { Text(EditorModel.ALREADY_REMOVED_MESSAGE) },
        )
    }
}

@Composable
internal fun SheetHeader(title: String, onCancel: () -> Unit, onSave: () -> Unit, saveEnabled: Boolean) {
    val c = LgkTheme.colors
    Row(Modifier.fillMaxWidth().height(64.dp).padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        TextButton(onCancel) { Text("Cancel", color = c.accentText) }
        Text(
            title, color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
            maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center,
            modifier = Modifier.weight(1f).semantics { heading() },
        )
        TextButton(onSave, enabled = saveEnabled) { Text("Save", color = c.accentText, fontWeight = FontWeight.SemiBold) }
    }
}

@Composable
internal fun ConfirmDelete(title: String, message: String, onDismiss: () -> Unit, onDelete: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onDelete, Modifier.testTag("confirm-delete")) { Text("Delete", color = LgkTheme.colors.danger) } },
        dismissButton = { TextButton(onDismiss) { Text("Cancel") } },
        title = { Text(title) },
        text = { Text(message) },
    )
}

@Composable
private fun Separator() {
    Box(Modifier.padding(start = 16.dp).fillMaxWidth().height(1.dp).background(LgkTheme.colors.separator))
}

@Composable
private fun FieldRow(model: EditorModel, field: EditorKind.Field, value: String, clock: UnixClock, seams: EditorSeams) {
    val c = LgkTheme.colors
    val monitor = LocalActivityMonitor.current
    val set: (String) -> Unit = { monitor?.textChanged(); model.set(field.key, it) }
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp).testTag("editor-field-${field.key}")) {
        when (val control = field.control) {
            EditorKind.Control.Toggle -> Row(verticalAlignment = Alignment.CenterVertically) {
                Text(field.label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                Switch(
                    value == "true", { set(if (it) "true" else "false") },
                    colors = lgkSwitchColors(),
                    modifier = Modifier.semantics { contentDescription = field.label },
                )
            }
            is EditorKind.Control.Choice -> ChoiceRow(field.label, value, control.options, set)
            EditorKind.Control.Date -> DateRow(field.label, value, clock, set)
            EditorKind.Control.Text, EditorKind.Control.Amount -> TextRow(model, field, value, seams, set)
        }
    }
}

@Composable
private fun Caption(text: String) {
    Text(text, color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.labelMedium)
}

@Composable
private fun Footnote(text: String, tag: String, color: androidx.compose.ui.graphics.Color = LgkTheme.colors.secondaryText) {
    Text(text, color = color, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 4.dp).testTag(tag))
}

@Composable
private fun TextRow(model: EditorModel, field: EditorKind.Field, value: String, seams: EditorSeams, set: (String) -> Unit) {
    val c = LgkTheme.colors
    val state by model.state.collectAsStateWithLifecycle()
    var revealed by remember { mutableStateOf(false) }
    Caption(field.label)
    Spacer(Modifier.height(2.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.weight(1f)) {
            if (field.secret && field.multiline && !revealed) {
                Text(
                    if (value.isEmpty()) EditorScreenText.SECRET_EMPTY else EditorScreenText.hiddenLines(value),
                    color = c.secondaryText, style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.testTag("editor-value-${field.key}"),
                )
            } else {
                val mono = field.secret
                BasicTextField(
                    value = value,
                    onValueChange = set,
                    singleLine = !field.multiline,
                    minLines = if (field.multiline) 3 else 1,
                    maxLines = if (field.multiline) (if (field.secret) 12 else 10) else 1,
                    textStyle = MaterialTheme.typography.bodyLarge.copy(
                        color = c.text, fontFamily = if (mono) FontFamily.Monospace else null,
                    ),
                    cursorBrush = SolidColor(c.accent),
                    visualTransformation =
                        if (field.secret && !field.multiline && !revealed) PasswordVisualTransformation() else VisualTransformation.None,
                    keyboardOptions = EditorKeyboard.options(field),
                    modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp).testTag("editor-value-${field.key}")
                        .semantics { contentDescription = field.label },
                    decorationBox = { inner ->
                        Box {
                            if (value.isEmpty()) Text(field.label, color = c.secondaryText.copy(alpha = 0.6f), style = MaterialTheme.typography.bodyLarge)
                            inner()
                        }
                    },
                )
            }
        }
        if (field.secret) {
            IconButton(
                { revealed = !revealed },
                Modifier.testTag("editor-reveal-${field.key}").semantics { contentDescription = if (revealed) "Hide" else "Reveal" },
            ) {
                Icon(if (revealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility, null, tint = c.accentText)
            }
        }
        val generate = seams.onGenerate
        if (field.key == "password" && generate != null) {
            IconButton({ generate { model.set(field.key, it) } }, Modifier.semantics { contentDescription = "Generate password" }) {
                Icon(Icons.Filled.AutoFixHigh, null, tint = c.accentText)
            }
        }
        val scan = seams.onScanTotp
        if (field.key == "totp" && scan != null) {
            IconButton(
                { scan { code -> if (code == null) model.totpCameraUnavailable() else model.scanTotp(code) } },
                Modifier.semantics { contentDescription = "Scan QR code" },
            ) { Icon(Icons.Filled.QrCodeScanner, null, tint = c.accentText) }
        }
    }
    field.hint?.let { Footnote(it, "editor-hint-${field.key}") }
    if (field.control == EditorKind.Control.Amount) state.amountError?.let { Footnote(it, "editor-amount-error", c.danger) }
    if (field.key == "url" && state.needsPunycode) Footnote(EditorScreenText.URL_PUNYCODE, "editor-url-punycode", c.warning)
    if (field.key == "totp") {
        val totpError = state.totpError
        if (totpError != null) {
            Footnote(totpError, "editor-totp-error", c.danger)
        } else if (model.totpNeedsPro) {
            Footnote(ProFeatures.totpMessage, "editor-totp-pro")
        }
    }
    if (field.key == "origin") {
        state.websiteError?.let { Footnote(it, "editor-website-error", c.danger) }
        if (state.needsPunycode) Footnote(EditorScreenText.ORIGIN_PUNYCODE, "editor-origin-punycode", c.warning)
    }
}

@Composable
private fun ChoiceRow(label: String, value: String, options: List<String>, set: (String) -> Unit) {
    val c = LgkTheme.colors
    var open by remember { mutableStateOf(false) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Box {
            TextButton({ open = true }, Modifier.semantics { contentDescription = "$label: ${EditorKind.choiceLabel(value)}" }) {
                Text(EditorKind.choiceLabel(value), color = c.accentText)
            }
            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                for (option in options) {
                    DropdownMenuItem(text = { Text(EditorKind.choiceLabel(option)) }, onClick = { open = false; set(option) })
                }
            }
        }
    }
}

/**
 * An optional ISO date: "Add" sets today, tapping the date opens the picker, the cross clears it. A stored value in
 * another ISO form (a week date from the desktop, say) stays editable as text.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DateRow(label: String, value: String, clock: UnixClock, set: (String) -> Unit) {
    val c = LgkTheme.colors
    val day = IsoDate.parse(value)
    var picking by remember { mutableStateOf(false) }
    when {
        value.isEmpty() -> Row(verticalAlignment = Alignment.CenterVertically) {
            Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            TextButton({ set(IsoDate.today(clock)) }, Modifier.semantics { contentDescription = "Add ${label.lowercase()}" }) {
                Text("Add", color = c.accentText)
            }
        }
        day != null -> Row(verticalAlignment = Alignment.CenterVertically) {
            Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            TextButton({ picking = true }) { Text(value, color = c.accentText) }
            IconButton({ set("") }, Modifier.semantics { contentDescription = "Clear ${label.lowercase()}" }) {
                Icon(Icons.Filled.Cancel, null, tint = c.secondaryText)
            }
        }
        else -> {
            Caption(label)
            BasicTextField(
                value = value, onValueChange = set, singleLine = true,
                textStyle = MaterialTheme.typography.bodyLarge.copy(color = c.text),
                cursorBrush = SolidColor(c.accent),
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Ascii),
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp).semantics { contentDescription = label },
                decorationBox = { inner ->
                    Box {
                        if (value.isEmpty()) Text("YYYY-MM-DD", color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
                        inner()
                    }
                },
            )
        }
    }
    if (picking && day != null) {
        val pickerState = rememberDatePickerState(initialSelectedDateMillis = IsoDate.utcMillis(day))
        DatePickerDialog(
            onDismissRequest = { picking = false },
            confirmButton = {
                TextButton({
                    pickerState.selectedDateMillis?.let { set(IsoDate.fromUtcMillis(it)) }
                    picking = false
                }) { Text("OK") }
            },
            dismissButton = { TextButton({ picking = false }) { Text("Cancel") } },
        ) { DatePicker(pickerState) }
    }
}
