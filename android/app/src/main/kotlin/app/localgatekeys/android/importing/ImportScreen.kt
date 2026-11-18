package app.localgatekeys.android.importing
import androidx.compose.ui.res.stringResource

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.i18n.rememberTxt
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.ui.settings.RowButton
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.unlock.LocalActivityMonitor
import app.localgatekeys.core.importing.GenericCsvMapping
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The system "open" picker for an export file (`ACTION_OPEN_DOCUMENT`): its bytes ([ImportRead]: 8 MiB + 1 for text
 * exports, 64 MB + 1 for zip archives) and display name.
 */
fun interface ImportDocuments {
    fun open(done: (ByteArray?, String) -> Unit)
}

/**
 * The real [ImportDocuments]. [onOpen] runs just before the picker opens and [onClose] when it returns, answering
 * whether the vault is still unlocked (the lock's system-screen allowance); a pick that returns after a lock is dropped
 * unread. Only the chosen document is read, never written.
 */
@Composable
fun rememberImportDocuments(onOpen: () -> Unit, onClose: () -> Boolean): ImportDocuments {
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    val open by rememberUpdatedState(onOpen)
    val close by rememberUpdatedState(onClose)
    val pending = remember { arrayOfNulls<(ByteArray?, String) -> Unit>(1) }
    val opener = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val done = pending[0]
        pending[0] = null
        val stillUnlocked = close()
        if (done == null || !stillUnlocked || uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val (bytes, name) = withContext(Dispatchers.IO) { read(context, uri) }
            done(bytes, name)
        }
    }
    return remember(opener) {
        ImportDocuments { done ->
            if (pending[0] != null) return@ImportDocuments
            pending[0] = done
            open()
            try {
                opener.launch(arrayOf("*/*"))
            } catch (e: Exception) {
                pending[0] = null
                close()
            }
        }
    }
}

private fun read(context: Context, uri: Uri): Pair<ByteArray?, String> {
    val name = try {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    } catch (e: Exception) {
        null
    } ?: ""
    val bytes = try {
        context.contentResolver.openInputStream(uri)?.use { input -> ImportRead.read(input) }
    } catch (e: Exception) {
        null
    }
    return bytes to name
}

/** Import from a file: choose, password or columns where needed, review, Import; the result shows what was done. */
@Composable
fun ImportScreen(flow: ImportFlow, documents: ImportDocuments, onClose: () -> Unit) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val state by flow.state.collectAsStateWithLifecycle()
    val password by flow.password.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val close: () -> Unit = { flow.reset(); onClose() }
    // The journal may have expired (or been used) since this page was last open.
    androidx.compose.runtime.LaunchedEffect(flow) { flow.refreshUndo() }
    val choose: () -> Unit = { documents.open { bytes, name -> scope.launch { flow.chose(bytes, name) } } }
    val openIt: () -> Unit = { scope.launch { flow.open() } }
    val action: Pair<String, () -> Unit>? = when (state.step) {
        ImportFlow.Step.PASSWORD -> txt.s(ImportText.CONTINUE) to openIt
        ImportFlow.Step.MAPPING -> txt.s(ImportText.CONTINUE) to { scope.launch { flow.applyMapping() } }
        ImportFlow.Step.REVIEW -> txt.s(ImportText.IMPORT) to { scope.launch { flow.commit() } }
        else -> null
    }
    val enabled = !state.working && (state.step != ImportFlow.Step.REVIEW || state.canImport)
    Page(txt.s(ImportText.TITLE), "import", close, action, enabled) {
        state.format?.let { if (state.step != ImportFlow.Step.CHOOSE) Footnote(ImportText.detected(it, txt)) }
        when (state.step) {
            ImportFlow.Step.CHOOSE -> {
                Footnote(txt.s(ImportText.CHOOSE_HINT))
                Group { RowButton(txt.s(ImportText.CHOOSE), "import-choose", divider = false, onClick = choose) }
                Footnote(txt.s(ImportText.FOOTER))
                // The last import stays undoable from here for 7 days after leaving its Done page (contract section 6.1).
                if (state.canUndo) {
                    Group { RowButton(stringResource(R.string.import_undo), "import-undo-last", divider = false, onClick = { scope.launch { flow.undo() } }) }
                }
                state.undone?.let { Text(it, color = c.success, modifier = Modifier.testTag("import-undone")) }
            }
            ImportFlow.Step.PASSWORD -> {
                state.format?.let { Footnote(ImportText.passwordPrompt(it, txt)) }
                Group { PasswordField(password, stringResource(R.string.import_export_password), "import-password", flow::updatePassword, onDone = openIt) }
            }
            ImportFlow.Step.MAPPING -> {
                Footnote(txt.s(ImportText.MAPPING_HINT))
                Group { Mapping(state.header, state.mapping, flow::choose) }
            }
            ImportFlow.Step.REVIEW -> Review(state, flow)
            ImportFlow.Step.DONE -> {
                val report = state.report
                if (report != null) {
                    Text(report.summary(txt), color = c.success, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.testTag("import-done"))
                    Report(report, state.issues)
                } else {
                    state.outcome?.let {
                        Text(it.notice(txt), color = c.success, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.testTag("import-done"))
                    }
                }
                Footnote(stringResource(R.string.import_report_check_hint))
                Footnote(stringResource(R.string.import_delete_export_note))
                if (state.canUndo) {
                    val scope = androidx.compose.runtime.rememberCoroutineScope()
                    TextButton({ scope.launch { flow.undo() } }, Modifier.testTag("import-undo")) { Text(stringResource(R.string.import_undo), color = c.accentText) }
                }
                state.undone?.let { Text(it, color = c.success, modifier = Modifier.testTag("import-undone")) }
            }
        }
        if (state.working) Working(if (state.step == ImportFlow.Step.REVIEW) txt.s(ImportText.SAVING) else txt.s(ImportText.OPENING))
        state.error?.let { Text(it, color = c.danger, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("import-error")) }
    }
}

@Composable
private fun Review(state: ImportFlow.State, flow: ImportFlow) {
    val c = LgkTheme.colors
    Text(state.summary, color = c.text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("import-summary"))
    if (state.rows.any { it.base == ImportRowStatus.CONFLICT || it.base == ImportRowStatus.DUPLICATE && it.targetId != null }) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton({ flow.setAllExisting(ImportDecision.SKIP) }, Modifier.testTag("import-skip-existing")) { Text(stringResource(R.string.import_skip_duplicates), color = c.accentText) }
            TextButton({ flow.setAllExisting(ImportDecision.REPLACE) }, Modifier.testTag("import-replace-existing")) { Text(stringResource(R.string.import_replace_all), color = c.accentText) }
        }
    }
    Group(Modifier.testTag("import-rows")) {
        state.rows.forEachIndexed { i, row ->
            if (i > 0) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
            ReviewRow(row) { flow.set(it, row.id) }
        }
    }
    if (state.issues.isNotEmpty()) {
        Group(Modifier.testTag("import-issues")) {
            state.issues.forEach { Text(it, color = c.secondaryText, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp)) }
        }
    }
}

/** The switch report (contract section 6.1, Windows `SwitchReport.svelte`): kinds, updated, passkeys, fields, duplicates, not imported. */
@Composable
private fun Report(report: SwitchReport, notes: List<String>) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    @Composable
    fun Line(label: String, value: String?, tag: String) {
        Row(Modifier.fillMaxWidth().padding(vertical = 6.dp).testTag(tag), verticalAlignment = Alignment.CenterVertically) {
            Text(label, color = c.text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            if (value != null) Text(value, color = c.text, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
        }
    }
    Text(
        stringResource(R.string.import_report_title), color = c.secondaryText, style = MaterialTheme.typography.labelLarge,
        modifier = Modifier.padding(start = 4.dp).semantics { heading() },
    )
    Group(Modifier.testTag("import-report-kinds")) {
        if (report.kinds.isEmpty()) Line(stringResource(R.string.import_report_nothing_added), null, "import-report-nothing")
        report.kinds.forEach { Line(SwitchReport.countLine(it, txt), null, "import-report-kind-${it.kind}") }
        if (report.updated > 0) Line(stringResource(R.string.import_report_updated), report.updated.toString(), "import-report-updated")
    }
    Group(Modifier.testTag("import-report-details")) {
        if (report.passkeys.total > 0) {
            Line(stringResource(R.string.import_report_passkeys), stringResource(R.string.import_report_passkeys_counts, report.passkeys.imported, report.passkeys.skipped), "import-report-passkeys")
        }
        Line(stringResource(R.string.import_report_fields), report.fieldsKept.toString(), "import-report-fields")
        Line(stringResource(R.string.import_report_duplicates), report.duplicates.toString(), "import-report-duplicates")
    }
    if (report.skipped > 0) {
        Text(
            androidx.compose.ui.res.pluralStringResource(R.plurals.import_report_skipped, report.skipped, report.skipped), color = c.secondaryText,
            style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(start = 4.dp).semantics { heading() }.testTag("import-report-skipped"),
        )
        Group(Modifier.testTag("import-report-not-carried")) {
            report.notCarried.forEachIndexed { i, row ->
                if (i > 0) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
                Row(Modifier.fillMaxWidth().padding(vertical = 6.dp).testTag("import-report-row-${row.row}"), verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        row.name.ifEmpty { stringResource(R.string.import_row_n, row.row) }, color = c.text, style = MaterialTheme.typography.bodyMedium,
                        maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f),
                    )
                    Text(SwitchReport.reasonText(row.reason, txt), color = c.secondaryText, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 8.dp))
                }
            }
            if (report.unreadableRows > 0) {
                if (report.notCarried.isNotEmpty()) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
                Line(SwitchReport.reasonText(SwitchReport.SkipReason.UNREADABLE, txt), report.unreadableRows.toString(), "import-report-unreadable")
            }
        }
    }
    if (notes.isNotEmpty()) {
        Group(Modifier.testTag("import-report-notes")) {
            notes.forEach { Text(it, color = c.secondaryText, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp)) }
        }
    }
}

private fun kindLabel(k: ImportDraft.Kind, t: Txt) = t.s(
    when (k) {
        ImportDraft.Kind.LOGIN -> R.string.import_kind_login
        ImportDraft.Kind.NOTE -> R.string.import_kind_note
        ImportDraft.Kind.CARD -> R.string.import_kind_card
        ImportDraft.Kind.IDENTITY -> R.string.import_kind_identity
        ImportDraft.Kind.PASSKEY -> R.string.new_item_passkey
    },
)

private fun statusLabel(r: ImportRow, t: Txt) = t.s(
    when (r.base) {
        ImportRowStatus.NEW -> R.string.import_status_new
        ImportRowStatus.DUPLICATE -> if (r.targetId == null) R.string.import_status_repeated else R.string.import_status_saved
        ImportRowStatus.CONFLICT -> R.string.import_status_conflict
        ImportRowStatus.SKIPPED_SOURCE -> R.string.import_status_cannot
    },
)

/** Title, what it is and where it goes; the decision button opens the row's choices. Never shows a password. */
@Composable
private fun ReviewRow(row: ImportRow, onDecide: (ImportDecision) -> Unit) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    var menu by remember { mutableStateOf(false) }
    Row(Modifier.fillMaxWidth().heightIn(min = 56.dp).padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(row.title, color = c.text, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            val detail = listOf(kindLabel(row.kind, txt), row.origin.removePrefix("https://"), row.draft.username).filter { it.isNotEmpty() }.joinToString(" · ")
            Text(detail, color = c.secondaryText, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(row.reason ?: statusLabel(row, txt), color = c.secondaryText, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        Box {
            val choices = row.choices
            Text(
                row.stateLabel(txt),
                color = if (row.limited) c.danger else c.accentText,
                style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold,
                modifier = Modifier.clickable(enabled = choices.size > 1, role = Role.Button) { menu = true }
                    .padding(horizontal = 8.dp, vertical = 10.dp).testTag("import-row-${row.id}"),
            )
            DropdownMenu(menu, onDismissRequest = { menu = false }) {
                for (d in choices) DropdownMenuItem(text = { Text(txt.s(d.label)) }, onClick = { menu = false; onDecide(d) })
            }
        }
    }
}

private data class MapTarget(val tag: String, @androidx.annotation.StringRes val label: Int, val value: Int?, val set: (Int?) -> GenericCsvMapping)

@Composable
private fun Mapping(header: List<String>, mapping: GenericCsvMapping, onChange: (GenericCsvMapping) -> Unit) {
    val c = LgkTheme.colors
    // The tag keeps the fixed English name (an id); only the shown label is localized.
    val targets: List<MapTarget> = listOf(
        MapTarget("Title", R.string.import_map_title, mapping.title) { v -> mapping.copy(title = v) },
        MapTarget("Website", R.string.import_map_website, mapping.url) { v -> mapping.copy(url = v) },
        MapTarget("Username", R.string.import_map_username, mapping.username) { v -> mapping.copy(username = v) },
        MapTarget("Password", R.string.import_map_password, mapping.password) { v -> mapping.copy(password = v) },
        MapTarget("Notes", R.string.import_map_notes, mapping.notes) { v -> mapping.copy(notes = v) },
        MapTarget("2FA secret", R.string.import_map_totp, mapping.totp) { v -> mapping.copy(totp = v) },
    )
    targets.forEachIndexed { i, (tagName, labelRes, value, set) ->
        if (i > 0) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
        var menu by remember { mutableStateOf(false) }
        Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(labelRes), color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Box {
                Text(
                    value?.let { header.getOrNull(it)?.ifEmpty { stringResource(R.string.import_column_n, it + 1) } } ?: stringResource(R.string.common_none),
                    color = c.accentText, style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.clickable(role = Role.Button) { menu = true }.padding(8.dp).testTag("import-map-$tagName"),
                )
                DropdownMenu(menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(text = { Text(stringResource(R.string.common_none)) }, onClick = { menu = false; onChange(set(null)) })
                    header.forEachIndexed { k, h ->
                        DropdownMenuItem(text = { Text(h.ifEmpty { stringResource(R.string.import_column_n, k + 1) }) }, onClick = { menu = false; onChange(set(k)) })
                    }
                }
            }
        }
    }
}

@Composable
private fun Page(
    title: String,
    tag: String,
    onClose: () -> Unit,
    action: Pair<String, () -> Unit>?,
    actionEnabled: Boolean,
    content: @Composable () -> Unit,
) {
    val c = LgkTheme.colors
    BackHandler(onBack = onClose)
    Box(Modifier.fillMaxSize().pointerInput(Unit) { awaitPointerEventScope { while (true) awaitPointerEvent() } }.testTag(tag)) {
        GlassBackdropHost(Modifier.fillMaxSize()) { AuroraBackground() }
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            Row(Modifier.fillMaxWidth().height(64.dp).padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClose, modifier = Modifier.testTag("$tag-close")) { Text(stringResource(if (action == null) R.string.common_done else R.string.common_cancel), color = c.accentText) }
                Text(
                    title, color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    textAlign = TextAlign.Center, modifier = Modifier.weight(1f).semantics { heading() },
                )
                if (action != null) {
                    Button(
                        action.second,
                        enabled = actionEnabled,
                        colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
                        modifier = Modifier.padding(end = 4.dp).testTag("$tag-action"),
                    ) { Text(action.first, fontWeight = FontWeight.SemiBold) }
                } else {
                    Spacer(Modifier.width(72.dp))
                }
            }
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).navigationBarsPadding().imePadding().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) { content() }
        }
    }
}

@Composable
private fun Group(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Column(modifier.fillMaxWidth().lgkGroupSurface().padding(horizontal = 16.dp, vertical = 6.dp)) { content() }
}

@Composable
private fun Footnote(text: String) {
    Text(text, color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(horizontal = 4.dp))
}

@Composable
private fun Working(text: String) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 4.dp)) {
        CircularProgressIndicator(Modifier.size(18.dp), color = LgkTheme.colors.secondaryText, strokeWidth = 2.dp)
        Spacer(Modifier.width(10.dp))
        Text(text, color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.bodyMedium)
    }
}

/** A masked password field: password keyboard, no capitals, no autocorrect or suggestions; the value only in memory. */
@Composable
private fun PasswordField(value: String, label: String, tag: String, onChange: (String) -> Unit, onDone: (() -> Unit)?) {
    val c = LgkTheme.colors
    val monitor = LocalActivityMonitor.current
    BasicTextField(
        value = value,
        onValueChange = { monitor?.textChanged(); onChange(it) },
        textStyle = MaterialTheme.typography.bodyLarge.copy(color = c.text),
        cursorBrush = SolidColor(c.accent),
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(
            KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = KeyboardType.Password,
            imeAction = if (onDone != null) ImeAction.Done else ImeAction.Next,
        ),
        keyboardActions = KeyboardActions(onDone = { onDone?.invoke() }),
        modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp).testTag(tag).semantics { contentDescription = label },
        decorationBox = { inner ->
            Box {
                if (value.isEmpty()) Text(label, color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
                inner()
            }
        },
    )
}
