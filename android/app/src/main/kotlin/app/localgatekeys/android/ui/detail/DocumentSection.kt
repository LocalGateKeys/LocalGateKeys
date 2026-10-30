package app.localgatekeys.android.ui.detail
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource

import app.localgatekeys.android.i18n.rememberTxt
import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.pdf.PdfRenderer
import android.net.Uri
import android.os.ParcelFileDescriptor
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.DisableSelection
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import app.localgatekeys.android.attachments.DocumentInfo
import app.localgatekeys.android.attachments.DocumentStore
import app.localgatekeys.android.attachments.DocumentTemp
import app.localgatekeys.android.attachments.DocumentText
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.ui.settings.readLimited
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.sync.AttachmentSync
import app.localgatekeys.core.sync.AttachmentSyncException
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * What the document screens need (Task 12). [confirmOwner] is the fingerprint, face or screen lock asked before a file
 * is shown, saved or shared (documents are passports and contracts: every open is treated as sensitive). The system
 * pickers and the share sheet stop this app: [willOpenSystemScreen] / [systemScreenClosed] are the lock's one-trip
 * allowance (Ruling 21); a result that returns after a lock is dropped.
 */
class DocumentSeams(
    val store: DocumentStore,
    val temp: DocumentTemp,
    val isPro: () -> Boolean,
    val confirmOwner: suspend () -> Boolean,
    val willOpenSystemScreen: () -> Unit,
    val systemScreenClosed: () -> Boolean,
    /** Called after a change the list must show (add, rename). */
    val onChanged: () -> Unit = {},
) {
    override fun toString(): String = "DocumentSeams"

    companion object {
        /** The FileProvider authority for shared copies (manifest `${applicationId}.documents`). */
        fun authority(context: Context): String = context.packageName + ".documents"
    }
}

/** The detail screen's File section: name, type and size, then Preview, Save, Share and Rename. */
@Composable
fun DocumentSection(item: VaultItem, seams: DocumentSeams) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var info by remember(item) { mutableStateOf<DocumentInfo?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var preview by remember { mutableStateOf<Pair<DocumentInfo, ByteArray>?>(null) }
    var renaming by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    LaunchedEffect(item) { info = withContext(Dispatchers.IO) { seams.store.info(item) } }

    // Save to Files: the system "save as" picker; the bytes are held only while it is open.
    var pendingSave by remember { mutableStateOf<ByteArray?>(null) }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        val bytes = pendingSave
        pendingSave = null
        val stillUnlocked = seams.systemScreenClosed()
        if (bytes == null) return@rememberLauncherForActivityResult
        if (uri == null || !stillUnlocked) {
            bytes.fill(0)
            return@rememberLauncherForActivityResult
        }
        scope.launch {
            val ok = withContext(Dispatchers.IO) {
                try {
                    context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) } != null
                } catch (e: Exception) {
                    false
                } finally {
                    bytes.fill(0)
                }
            }
            message = txt.s(if (ok) R.string.document_saved else R.string.document_save_failed)
        }
    }
    // Share: a temp copy behind a content URI, deleted when the share sheet returns (and at every lock).
    var shared by remember { mutableStateOf<File?>(null) }
    val sharer = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        seams.systemScreenClosed()
        shared?.let { f -> scope.launch(Dispatchers.IO) { seams.temp.delete(f) } }
        shared = null
    }

    /** Owner check, then the verified bytes, or a message. */
    suspend fun bytes(): Pair<DocumentInfo, ByteArray>? {
        val i = info ?: return null
        if (!seams.confirmOwner()) return null
        return try {
            i to withContext(Dispatchers.IO) { seams.store.read(item.id) }
        } catch (e: AttachmentSyncException) {
            message = if (e.reason == "missing") txt.s(DocumentText.MISSING) else txt.s(DocumentText.REFUSED)
            null
        } catch (e: Exception) {
            message = txt.s(DocumentText.READ_FAILED)
            null
        }
    }

    Column {
        SectionTitle(stringResource(R.string.document_section_file))
        Column(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface).padding(16.dp).testTag("document-file"),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            val i = info
            if (i == null) {
                Text(stringResource(R.string.document_none_attached), color = c.secondaryText)
            } else {
                DisableSelection { Text(i.name, color = c.text, style = MaterialTheme.typography.bodyLarge) }
                Text("${i.mimeType} · ${i.sizeText(txt)}", color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
                if (!i.stored) Text(txt.s(DocumentText.MISSING), color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton({
                        if (busy) return@OutlinedButton
                        busy = true
                        scope.launch { preview = bytes(); busy = false }
                    }, enabled = i.stored, modifier = Modifier.testTag("document-preview")) { Text(stringResource(R.string.common_preview)) }
                    OutlinedButton({
                        if (busy) return@OutlinedButton
                        busy = true
                        scope.launch {
                            val b = bytes()
                            busy = false
                            if (b != null) {
                                pendingSave = b.second
                                seams.willOpenSystemScreen()
                                try {
                                    saver.launch(b.first.name)
                                } catch (e: Exception) {
                                    seams.systemScreenClosed()
                                    pendingSave = null
                                    b.second.fill(0)
                                }
                            }
                        }
                    }, enabled = i.stored, modifier = Modifier.testTag("document-save")) { Text(stringResource(R.string.common_save)) }
                    OutlinedButton({
                        if (busy) return@OutlinedButton
                        busy = true
                        scope.launch {
                            val b = bytes()
                            busy = false
                            if (b != null) {
                                val f = withContext(Dispatchers.IO) { seams.temp.write(b.first.name, b.second).also { b.second.fill(0) } }
                                shared = f
                                val uri: Uri = FileProvider.getUriForFile(context, DocumentSeams.authority(context), f)
                                val send = Intent(Intent.ACTION_SEND).setType(b.first.mimeType).putExtra(Intent.EXTRA_STREAM, uri)
                                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                seams.willOpenSystemScreen()
                                try {
                                    sharer.launch(Intent.createChooser(send, null))
                                } catch (e: Exception) {
                                    seams.systemScreenClosed()
                                    withContext(Dispatchers.IO) { seams.temp.delete(f) }
                                    shared = null
                                }
                            }
                        }
                    }, enabled = i.stored, modifier = Modifier.testTag("document-share")) { Text(stringResource(R.string.detail_pane_share)) }
                }
                TextButton({ renaming = item.title }, Modifier.testTag("document-rename")) { Text(stringResource(R.string.common_rename), color = c.accentText) }
            }
        }
    }

    preview?.let { (i, data) ->
        DocumentPreview(i, data, seams.temp, onClose = { data.fill(0); preview = null })
    }
    renaming?.let { current ->
        var text by remember { mutableStateOf(current) }
        AlertDialog(
            onDismissRequest = { renaming = null },
            title = { Text(stringResource(R.string.common_rename)) },
            text = {
                Column {
                    OutlinedTextField(text, { text = it }, singleLine = true, modifier = Modifier.testTag("document-rename-field"))
                    Text(stringResource(R.string.document_rename_footer), style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                TextButton({
                    val t = text
                    renaming = null
                    scope.launch {
                        when (withContext(Dispatchers.IO) { seams.store.rename(item.id, t) }) {
                            SaveResult.SAVED -> seams.onChanged()
                            SaveResult.INVALID -> message = txt.s(R.string.document_name_required)
                            SaveResult.FAILED -> message = txt.s(R.string.document_rename_failed)
                            else -> {}
                        }
                    }
                }, Modifier.testTag("document-rename-save")) { Text(stringResource(R.string.common_save)) }
            },
            dismissButton = { TextButton({ renaming = null }) { Text(stringResource(R.string.common_cancel)) } },
        )
    }
    message?.let { m ->
        AlertDialog(
            onDismissRequest = { message = null },
            confirmButton = { TextButton({ message = null }) { Text(stringResource(R.string.common_ok)) } },
            text = { Text(m) },
        )
    }
}

/**
 * The in-app preview: images and text decoded from memory, PDFs rendered page by page from a temp copy that is deleted
 * as soon as the pages are drawn. Nothing is cached; closing drops the bytes.
 */
@Composable
private fun DocumentPreview(info: DocumentInfo, data: ByteArray, temp: DocumentTemp, onClose: () -> Unit) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    var pages by remember { mutableStateOf<List<Bitmap>?>(null) }
    var failed by remember { mutableStateOf(false) }
    val kind = DocumentText.preview(info.mimeType)
    LaunchedEffect(data) {
        val out = withContext(Dispatchers.IO) {
            try {
                when (kind) {
                    DocumentText.Preview.IMAGE -> listOfNotNull(decodeImage(data))
                    DocumentText.Preview.PDF -> renderPdf(temp, info.name, data)
                    else -> emptyList()
                }
            } catch (e: Exception) {
                null
            }
        }
        if (out == null || (kind != DocumentText.Preview.TEXT && kind != DocumentText.Preview.NONE && out.isEmpty())) failed = true
        pages = out
    }
    DisposableEffect(Unit) { onDispose { pages?.forEach { it.recycle() } } }
    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Column(Modifier.fillMaxSize().background(c.groupSurface).padding(16.dp).testTag("document-preview-dialog")) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(info.name, color = c.text, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                TextButton(onClose) { Text(stringResource(R.string.common_done), color = c.accentText) }
            }
            when {
                failed -> Text(txt.s(DocumentText.READ_FAILED), color = c.secondaryText)
                kind == DocumentText.Preview.TEXT -> Text(
                    String(data, Charsets.UTF_8).take(200_000), color = c.text,
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                )
                kind == DocumentText.Preview.NONE -> Text(txt.s(DocumentText.NO_PREVIEW), color = c.secondaryText)
                else -> LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(pages ?: emptyList()) { bmp ->
                        Image(bmp.asImageBitmap(), null, Modifier.fillMaxWidth(), contentScale = ContentScale.FillWidth)
                    }
                }
            }
        }
    }
}

private fun decodeImage(data: ByteArray): Bitmap? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(data, 0, data.size, bounds)
    var sample = 1
    while (bounds.outWidth / sample > 2048 || bounds.outHeight / sample > 2048) sample *= 2
    return BitmapFactory.decodeByteArray(data, 0, data.size, BitmapFactory.Options().apply { inSampleSize = sample })
}

/** At most 50 pages, 1080 px wide. The temp copy PdfRenderer needs is deleted before this returns. */
private fun renderPdf(temp: DocumentTemp, name: String, data: ByteArray): List<Bitmap> {
    val f = temp.write(name, data)
    try {
        ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY).use { fd ->
            PdfRenderer(fd).use { r ->
                return (0 until minOf(r.pageCount, 50)).map { i ->
                    r.openPage(i).use { p ->
                        val w = 1080
                        val h = (w.toFloat() * p.height / maxOf(1, p.width)).toInt().coerceIn(1, 4096)
                        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
                        bmp.eraseColor(android.graphics.Color.WHITE)
                        p.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                        bmp
                    }
                }
            }
        }
    } finally {
        temp.delete(f)
    }
}

/** Where the new file comes from. */
enum class FileSource { FILES, PHOTOS, CAMERA }

/**
 * The "File or photo" flow of the plus menu: a choice of Files, Photos or Camera, the system picker, then the file is
 * read (25 MB + 1 at most), sealed and saved as a new document titled by its name. Pro only: without Pro [onNeedsPro]
 * runs before any picker opens.
 */
@Composable
fun AddFileHost(open: Boolean, seams: DocumentSeams, onDismiss: () -> Unit, onNeedsPro: () -> Unit, onAdded: (String) -> Unit) {
    val txt = rememberTxt()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var message by remember { mutableStateOf<String?>(null) }
    var cameraFile by remember { mutableStateOf<File?>(null) }

    fun add(bytes: ByteArray?, name: String, mime: String?) {
        if (bytes == null) {
            message = txt.s(DocumentText.READ_FAILED)
            return
        }
        scope.launch {
            val (r, id) = withContext(Dispatchers.IO) {
                seams.store.add(bytes, name, mime, "", seams.isPro()).also { bytes.fill(0) }
            }
            when (r) {
                DocumentStore.AddResult.ADDED -> {
                    seams.onChanged()
                    if (id != null) onAdded(id)
                }
                DocumentStore.AddResult.PRO_REQUIRED -> onNeedsPro()
                DocumentStore.AddResult.TOO_LARGE -> message = txt.s(DocumentText.TOO_LARGE)
                DocumentStore.AddResult.FAILED -> message = txt.s(DocumentText.ADD_FAILED)
            }
        }
    }

    fun readUri(uri: Uri) {
        scope.launch {
            val (bytes, name, mime) = withContext(Dispatchers.IO) {
                val n = displayName(context, uri) ?: "document"
                val m = try { context.contentResolver.getType(uri) } catch (e: Exception) { null }
                val b = try {
                    context.contentResolver.openInputStream(uri)?.use { readLimited(it, AttachmentSync.MAX_FILE_BYTES + 1) }
                } catch (e: Exception) {
                    null
                }
                Triple(b, n, m)
            }
            if (bytes != null && bytes.size > AttachmentSync.MAX_FILE_BYTES) {
                bytes.fill(0)
                message = txt.s(DocumentText.TOO_LARGE)
            } else {
                add(bytes, name, mime)
            }
        }
    }

    val files = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val ok = seams.systemScreenClosed()
        if (uri != null && ok) readUri(uri)
    }
    val photos = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        val ok = seams.systemScreenClosed()
        if (uri != null && ok) readUri(uri)
    }
    val camera = rememberLauncherForActivityResult(ActivityResultContracts.TakePicture()) { taken ->
        val ok = seams.systemScreenClosed()
        val f = cameraFile
        cameraFile = null
        if (f == null) return@rememberLauncherForActivityResult
        if (taken && ok) {
            scope.launch {
                val bytes = withContext(Dispatchers.IO) {
                    try { readLimited(f.inputStream(), AttachmentSync.MAX_FILE_BYTES + 1) } catch (e: Exception) { null } finally { seams.temp.delete(f) }
                }
                if (bytes != null && bytes.size > AttachmentSync.MAX_FILE_BYTES) message = txt.s(DocumentText.TOO_LARGE) else add(bytes, f.name, "image/jpeg")
            }
        } else {
            scope.launch(Dispatchers.IO) { seams.temp.delete(f) }
        }
    }

    fun launchCamera() {
        scope.launch {
            val f = withContext(Dispatchers.IO) { seams.temp.write("Photo ${java.time.LocalDate.now()}.jpg", ByteArray(0)) }
            cameraFile = f
            seams.willOpenSystemScreen()
            try {
                camera.launch(FileProvider.getUriForFile(context, DocumentSeams.authority(context), f))
            } catch (e: Exception) {
                seams.systemScreenClosed()
                cameraFile = null
                withContext(Dispatchers.IO) { seams.temp.delete(f) }
                message = txt.s(R.string.document_camera_unavailable)
            }
        }
    }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        seams.systemScreenClosed()
        if (granted) launchCamera() else message = txt.s(R.string.document_camera_permission)
    }

    fun start(source: FileSource) {
        onDismiss()
        if (!seams.isPro()) {
            onNeedsPro()
            return
        }
        seams.willOpenSystemScreen()
        try {
            when (source) {
                FileSource.FILES -> files.launch(arrayOf("*/*"))
                FileSource.PHOTOS -> photos.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
                FileSource.CAMERA -> {
                    if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                        seams.systemScreenClosed()
                        launchCamera()
                    } else {
                        permission.launch(Manifest.permission.CAMERA)
                    }
                }
            }
        } catch (e: Exception) {
            seams.systemScreenClosed()
            message = txt.s(R.string.document_no_provider)
        }
    }

    if (open) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(R.string.document_add_title)) },
            text = {
                Column {
                    Text(stringResource(R.string.document_add_blurb))
                    TextButton({ start(FileSource.FILES) }, Modifier.testTag("add-file-files")) { Text(stringResource(R.string.document_choose_file)) }
                    TextButton({ start(FileSource.PHOTOS) }, Modifier.testTag("add-file-photos")) { Text(stringResource(R.string.document_choose_photo)) }
                    TextButton({ start(FileSource.CAMERA) }, Modifier.testTag("add-file-camera")) { Text(stringResource(R.string.document_take_photo)) }
                }
            },
            confirmButton = {},
            dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.common_cancel)) } },
        )
    }
    message?.let { m ->
        AlertDialog(onDismissRequest = { message = null }, confirmButton = { TextButton({ message = null }) { Text(stringResource(R.string.common_ok)) } }, text = { Text(m) })
    }
}

private fun displayName(context: Context, uri: Uri): String? = try {
    context.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
        if (c.moveToFirst()) c.getString(0) else null
    }
} catch (e: Exception) {
    null
}
