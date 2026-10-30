package app.localgatekeys.android.ui.settings
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource

import app.localgatekeys.android.i18n.rememberTxt
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
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
import app.localgatekeys.android.backup.BackupText
import app.localgatekeys.android.backup.ExportFlow
import app.localgatekeys.android.backup.RestoreFlow
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.unlock.LocalActivityMonitor
import app.localgatekeys.core.backup.PhoneBackupFormat
import java.io.InputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * What the backup screens need from the app: the open vault's [exporter] and [restorer] (over the sync coordinator's
 * gated store), the process-wide wrong-password [attempts], and the lock's system-screen allowance around each picker
 * trip ([onPickerOpen] / [onPickerClose], Ruling 21).
 */
class BackupSeams(
    val exporter: () -> app.localgatekeys.android.backup.BackupExporter,
    val restorer: () -> app.localgatekeys.android.backup.PhoneRestore,
    val attempts: app.localgatekeys.android.backup.RestoreAttempts,
    val now: () -> Long,
    val onPickerOpen: () -> Unit,
    val onPickerClose: () -> Boolean,
) {
    override fun toString(): String = "BackupSeams"
}

/** The system "save as" and "open" pickers for backup files (`ACTION_CREATE_DOCUMENT` / `ACTION_OPEN_DOCUMENT`). */
interface BackupDocuments {
    /** Asks where to save [bytes] as [name]; [done] gets true once written, false when cancelled or failed, null when dropped. */
    fun save(name: String, bytes: ByteArray, done: (Boolean?) -> Unit)

    /** Asks for a backup file; [done] gets its bytes (read up to the format's limit + 1), null when it could not be read. */
    fun open(done: (ByteArray?) -> Unit)
}

/** Reads at most [limit] bytes of [input] (a larger file reads as [limit] bytes, which the format refuses as too large). */
fun readLimited(input: InputStream, limit: Int): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(64 * 1024)
    var total = 0
    while (total < limit) {
        val n = input.read(buf, 0, minOf(buf.size, limit - total))
        if (n < 0) break
        out.write(buf, 0, n)
        total += n
    }
    return out.toByteArray()
}

/**
 * The real [BackupDocuments]. [onOpen] runs just before a picker opens and [onClose] when it returns, answering
 * whether the vault is still unlocked (the folder picker's system-screen allowance, Ruling 21: the picker stops this
 * app; 120 s cap; the screen turning off locks). A result that returns after a lock is dropped: nothing is written
 * (the empty document the picker made is deleted, best effort) and nothing is read. Nothing is written anywhere but
 * the document the person chose (a write that fails, or a result no request is waiting for, deletes it, best
 * effort); the read is limited to the format's 64 MiB (+1 to tell a larger file).
 */
@Composable
fun rememberBackupDocuments(onOpen: () -> Unit, onClose: () -> Boolean): BackupDocuments {
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    val open by rememberUpdatedState(onOpen)
    val close by rememberUpdatedState(onClose)
    val pending = remember { arrayOfNulls<Any>(2) } // [0]: save (bytes, done); [1]: open done
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(MIME)) { uri ->
        @Suppress("UNCHECKED_CAST")
        val job = pending[0] as? Pair<ByteArray, (Boolean?) -> Unit>
        pending[0] = null
        val stillUnlocked = close()
        if (job == null) {
            // A result for a request this screen no longer holds (the activity was recreated): the picker made an empty
            // document that nothing will fill.
            if (uri != null) scope.launch(Dispatchers.IO) { deleteQuietly(context, uri) }
            return@rememberLauncherForActivityResult
        }
        val (bytes, done) = job
        when {
            !stillUnlocked -> {
                if (uri != null) scope.launch(Dispatchers.IO) { deleteQuietly(context, uri) }
                done(null)
            }
            uri == null -> done(false)
            else -> scope.launch {
                val ok = withContext(Dispatchers.IO) { write(context, uri, bytes).also { if (!it) deleteQuietly(context, uri) } }
                done(ok)
            }
        }
    }
    val opener = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        @Suppress("UNCHECKED_CAST")
        val done = pending[1] as? (ByteArray?) -> Unit
        pending[1] = null
        val stillUnlocked = close()
        if (done == null || !stillUnlocked || uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val bytes = withContext(Dispatchers.IO) {
                try {
                    context.contentResolver.openInputStream(uri)?.use { readLimited(it, PhoneBackupFormat.MAX_FILE_BYTES + 1) }
                } catch (e: Exception) {
                    null
                }
            }
            done(bytes)
        }
    }
    return remember(saver, opener) {
        object : BackupDocuments {
            override fun save(name: String, bytes: ByteArray, done: (Boolean?) -> Unit) {
                if (pending[0] != null) return
                pending[0] = bytes to done
                open()
                try {
                    saver.launch(name)
                } catch (e: Exception) {
                    pending[0] = null
                    close()
                    done(false)
                }
            }

            override fun open(done: (ByteArray?) -> Unit) {
                if (pending[1] != null) return
                pending[1] = done
                open()
                try {
                    opener.launch(arrayOf("*/*"))
                } catch (e: Exception) {
                    pending[1] = null
                    close()
                    done(null)
                }
            }

            override fun toString(): String = "BackupDocuments"
        }
    }
}

private const val MIME = "application/octet-stream"

private fun write(context: Context, uri: Uri, bytes: ByteArray): Boolean = try {
    val out = try {
        context.contentResolver.openOutputStream(uri, "wt")
    } catch (e: IllegalArgumentException) {
        context.contentResolver.openOutputStream(uri, "w") // a provider without "wt": the document is new and empty
    }
    out?.use { it.write(bytes); it.flush() } != null
} catch (e: Exception) {
    false
}

private fun deleteQuietly(context: Context, uri: Uri) {
    try {
        DocumentsContract.deleteDocument(context.contentResolver, uri)
    } catch (e: Exception) {
        // best effort: the document is empty
    }
}

/**
 * Export backup (after the fresh unlock): the password twice with its strength, then the system "save as" picker
 * for `LocalGateKeys-Backup-YYYY-MM-DD.lgkm`. Password fields: password keyboard, masked, no suggestions (Ruling 15's
 * no-learning flag comes from the app-wide wrapper); never saved.
 */
@Composable
fun ExportBackupScreen(flow: ExportFlow, documents: BackupDocuments, fileName: () -> String, onClose: () -> Unit) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    val text = BackupText(txt)
    val password by flow.password.collectAsStateWithLifecycle()
    val confirm by flow.confirm.collectAsStateWithLifecycle()
    val working by flow.working.collectAsStateWithLifecycle()
    val message by flow.message.collectAsStateWithLifecycle()
    val saved by flow.saved.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val export: () -> Unit = {
        scope.launch {
            val bytes = flow.make() ?: return@launch
            documents.save(fileName(), bytes) { ok -> if (ok != null) flow.written(ok) }
        }
    }
    BackupPage(text.exportTitle, "export-backup", onClose, action = if (saved) null else text.exportButton to export, actionEnabled = !working) {
        if (!saved) {
            Footnote(text.exportHint)
            Group {
                PasswordField(password, text.password, "export-password", flow::updatePassword, onDone = null)
                HorizontalDivider(thickness = 0.5.dp, color = c.separator)
                PasswordField(confirm, text.confirm, "export-confirm", flow::updateConfirm, onDone = export)
            }
            // The desktop's label (its sync-password check); computed off the main thread.
            val strength by produceState<String?>(null, password) { value = withContext(Dispatchers.Default) { flow.strengthText() } }
            strength?.let { Footnote(it) }
        }
        if (working) Working(text.working)
        message?.let { Text(it, color = if (saved) c.success else c.danger, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("export-message")) }
    }
}

/** Restore from a backup: choose the file, its password, the preview, then Restore; the result shows its lines. */
@Composable
fun RestoreBackupScreen(flow: RestoreFlow, documents: BackupDocuments, onRestored: () -> Unit, onClose: () -> Unit) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    val text = BackupText(txt)
    val step by flow.step.collectAsStateWithLifecycle()
    val password by flow.password.collectAsStateWithLifecycle()
    val working by flow.working.collectAsStateWithLifecycle()
    val error by flow.error.collectAsStateWithLifecycle()
    val lines by flow.lines.collectAsStateWithLifecycle()
    val status by flow.status.collectAsStateWithLifecycle()
    val from by flow.from.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val choose: () -> Unit = { documents.open { flow.chose(it) } }
    val openIt: () -> Unit = { scope.launch { flow.open() } }
    val action: Pair<String, () -> Unit>? = when (step) {
        RestoreFlow.Step.PASSWORD -> text.openButton to openIt
        RestoreFlow.Step.PREVIEW -> text.restoreButton to { scope.launch { if (flow.restore()) onRestored() } }
        else -> null
    }
    BackupPage(text.restoreTitle, "restore-backup", onClose, action = action, actionEnabled = !working) {
        when (step) {
            RestoreFlow.Step.CHOOSE -> {
                Footnote(text.chooseHint)
                Group { RowButton(text.choose, "restore-choose", divider = false, onClick = choose) }
            }
            RestoreFlow.Step.PASSWORD -> {
                from?.let { Footnote(it) }
                Group { PasswordField(password, text.password, "restore-password", flow::updatePassword, onDone = openIt) }
            }
            RestoreFlow.Step.PREVIEW, RestoreFlow.Step.DONE -> {
                Group(Modifier.testTag("restore-summary")) {
                    lines.forEachIndexed { i, line ->
                        if (i > 0) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
                        Text(line, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(vertical = 10.dp))
                    }
                }
                status?.let {
                    Text(
                        it, color = if (step == RestoreFlow.Step.DONE) c.success else c.secondaryText,
                        style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("restore-status"),
                    )
                }
            }
        }
        if (working) Working(text.opening)
        error?.let { Text(it, color = c.danger, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("restore-error")) }
    }
}

@Composable
private fun BackupPage(
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
