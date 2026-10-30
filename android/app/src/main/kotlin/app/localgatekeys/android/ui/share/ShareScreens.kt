package app.localgatekeys.android.ui.share
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource

import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.i18n.rememberTxt
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import app.localgatekeys.android.attachments.DocumentTemp
import app.localgatekeys.android.importing.ImportDocuments
import app.localgatekeys.android.share.ItemSharing
import app.localgatekeys.android.share.OutgoingShare
import app.localgatekeys.android.share.ShareInbox
import app.localgatekeys.android.share.ShareText
import app.localgatekeys.android.ui.detail.DocumentSeams
import app.localgatekeys.android.ui.sync.QrScanner
import app.localgatekeys.android.ui.sync.QrScannerScreen
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.share.OpenedShare
import app.localgatekeys.core.share.Share
import app.localgatekeys.core.share.ShareException
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * What sharing needs (UX workstream 9). [temp] holds the file copy behind the share sheet (cacheDir/open-documents,
 * deleted when the sheet returns and at every lock). [willOpenSystemScreen]/[systemScreenClosed]: the lock's one-trip
 * allowance (Ruling 21). [save] adds an opened item off the main thread.
 */
class ShareSeams(
    val clock: UnixClock,
    val random: RandomSource,
    val temp: DocumentTemp,
    val inbox: ShareInbox,
    val willOpenSystemScreen: () -> Unit,
    val systemScreenClosed: () -> Boolean,
    val save: suspend (OpenedShare) -> ItemSharing.SaveOutcome,
) {
    override fun toString(): String = "ShareSeams"
}

/** A QR bitmap of [text] (byte mode, error correction L, so a 2048-byte package still fits). */
internal fun qrBitmap(text: String, size: Int = 720): ImageBitmap? = try {
    val hints = mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L, EncodeHintType.MARGIN to 2, EncodeHintType.CHARACTER_SET to "UTF-8")
    val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
    val px = IntArray(m.width * m.height) { i -> if (m.get(i % m.width, i / m.width)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt() }
    Bitmap.createBitmap(px, m.width, m.height, Bitmap.Config.ARGB_8888).asImageBitmap()
} catch (e: Exception) {
    null
}

@Composable
private fun Page(title: String, onClose: () -> Unit, content: @Composable () -> Unit) {
    val c = LgkTheme.colors
    BackHandler(onBack = onClose)
    Column(
        Modifier.fillMaxSize().background(c.background).statusBarsPadding().navigationBarsPadding()
            .verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                title, color = c.text, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f).semantics { heading() },
            )
            TextButton(onClose, Modifier.testTag("share-close")) { Text(stringResource(R.string.common_close), color = c.accentText) }
        }
        content()
    }
}

/** Share on an item: the six-word code, then Send as a file (the share sheet) or Show as a QR code (small items). */
@Composable
fun ShareItemScreen(item: VaultItem, seams: ShareSeams, onClose: () -> Unit) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var outgoing by remember(item) { mutableStateOf<OutgoingShare?>(null) }
    var error by remember(item) { mutableStateOf<String?>(null) }
    var showQr by remember(item) { mutableStateOf(false) }
    var shared by remember { mutableStateOf<File?>(null) }
    LaunchedEffect(item) {
        try {
            outgoing = withContext(Dispatchers.Default) { ItemSharing.prepare(item, seams.clock, seams.random) }
        } catch (e: ShareException) {
            error = if (e.reason == "not-shareable") txt.s(ShareText.NOT_SHAREABLE) else txt.s(ShareText.FAILED)
        } catch (e: Exception) {
            error = txt.s(ShareText.FAILED)
        }
    }
    val sharer = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        seams.systemScreenClosed()
        shared?.let { f -> scope.launch(Dispatchers.IO) { seams.temp.delete(f) } }
        shared = null
    }
    Page(txt.s(ShareText.SHEET_TITLE), onClose) {
        Text(item.title.ifEmpty { item.kindLabel(txt) }, color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
        error?.let { Text(it, color = c.danger, modifier = Modifier.testTag("share-error")) }
        val qrDescription = txt.s(R.string.share_qr_description)
        val out = outgoing
        if (out == null && error == null) Text(stringResource(R.string.share_preparing), color = c.secondaryText)
        if (out != null) {
            Text(txt.s(ShareText.CODE_TITLE), color = c.text, style = MaterialTheme.typography.titleMedium)
            Text(
                out.code, color = c.text,
                style = MaterialTheme.typography.headlineSmall.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold),
                modifier = Modifier.testTag("share-code"),
            )
            Text(txt.s(ShareText.CODE_HINT), color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
            Button({
                scope.launch {
                    val f = try {
                        withContext(Dispatchers.IO) { seams.temp.write(out.fileName, out.bytes) }
                    } catch (e: Exception) {
                        error = txt.s(ShareText.FAILED)
                        return@launch
                    }
                    shared = f
                    val uri: Uri = FileProvider.getUriForFile(context, DocumentSeams.authority(context), f)
                    val send = Intent(Intent.ACTION_SEND).setType(ItemSharing.MIME).putExtra(Intent.EXTRA_STREAM, uri)
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
            }, Modifier.fillMaxWidth().testTag("share-file")) { Text(txt.s(ShareText.SEND_FILE)) }
            if (out.fitsQr) {
                OutlinedButton({ showQr = !showQr }, Modifier.fillMaxWidth().testTag("share-qr")) { Text(txt.s(ShareText.SHOW_QR)) }
            } else {
                Text(txt.s(ShareText.QR_TOO_LARGE), color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
            }
            if (showQr && out.fitsQr) {
                val bmp = remember(out) { qrBitmap(out.qrText) }
                if (bmp != null) {
                    Box(Modifier.fillMaxWidth().background(Color.White).padding(8.dp), contentAlignment = Alignment.Center) {
                        Image(
                            bmp, null, filterQuality = FilterQuality.None,
                            modifier = Modifier.size(300.dp).testTag("share-qr-image").semantics { contentDescription = qrDescription },
                        )
                    }
                    Text(txt.s(ShareText.QR_HINT), color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
                } else {
                    Text(txt.s(ShareText.QR_TOO_LARGE), color = c.secondaryText)
                }
            }
        }
    }
}

/** The words a refusal shows (the core's messages hold no item content). */
internal fun refusalText(e: ShareException, t: Txt): String = ShareText.refusal(e, t)

/**
 * Receive: choose a file or scan a QR, then the code, the preview (kind, title, user name, field names; no secrets),
 * and Add to vault or Reject. A delivered file (opened from another app) arrives here through [ShareInbox.pending].
 */
@Composable
fun ReceiveShareScreen(seams: ShareSeams, files: ImportDocuments?, onUpgrade: () -> Unit, onDone: () -> Unit, onClose: () -> Unit) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val scope = rememberCoroutineScope()
    val pending by seams.inbox.pending.collectAsState()
    var scanning by remember { mutableStateOf(false) }
    var code by remember { mutableStateOf("") }
    var message by remember { mutableStateOf<String?>(null) }
    var opened by remember { mutableStateOf<OpenedShare?>(null) }
    var working by remember { mutableStateOf(false) }
    val accept: (ByteArray, Boolean) -> Unit = { bytes, keep ->
        scope.launch {
            message = try {
                withContext(Dispatchers.IO) { seams.inbox.accept(bytes, keep) }
                code = ""; opened = null
                null
            } catch (e: ShareException) {
                refusalText(e, txt)
            } catch (e: Exception) {
                txt.s(ShareText.FAILED)
            } finally {
                bytes.fill(0)
            }
        }
    }
    val close: () -> Unit = {
        // Leaving without Add or Reject keeps a delivered file for later (it is deleted a day after it arrived).
        opened = null; code = ""
        onClose()
    }
    if (scanning) {
        QrScannerScreen(
            txt.s(ShareText.SCAN), txt.s(QrScanner.SYNC_DENIED_TEXT),
            onCode = { text ->
                scanning = false
                if (Share.looksLikePackage(text)) accept(text.toByteArray(Charsets.UTF_8), false) else message = txt.s(ShareText.NOT_A_SHARE_QR)
            },
            onUnavailable = { scanning = false; message = txt.s(R.string.share_camera_unavailable) },
            onCancel = { scanning = false },
        )
        return
    }
    Page(txt.s(ShareText.RECEIVE), close) {
        message?.let { Text(it, color = c.danger, modifier = Modifier.testTag("receive-message")) }
        val p = pending
        val o = opened
        when {
            o != null && p != null -> {
                Text("${txt.s(ShareText.FROM)} ${o.sender}", color = c.secondaryText)
                Text(ItemSharing.kindLabel(o.item, txt), color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
                Text(ItemSharing.previewTitle(o.item, txt), color = c.text, style = MaterialTheme.typography.titleMedium, modifier = Modifier.testTag("receive-title"))
                ItemSharing.previewUser(o.item)?.let { Text(it, color = c.text) }
                Button({
                    if (working) return@Button
                    working = true
                    scope.launch {
                        val r = try {
                            seams.save(o)
                        } catch (e: Exception) {
                            ItemSharing.SaveOutcome.INVALID
                        }
                        working = false
                        when (r) {
                            ItemSharing.SaveOutcome.SAVED -> {
                                withContext(Dispatchers.IO) { seams.inbox.opened(p) }
                                opened = null
                                onDone()
                            }
                            ItemSharing.SaveOutcome.NEEDS_PRO -> { message = ShareText.needsPro(txt); onUpgrade() }
                            ItemSharing.SaveOutcome.INVALID -> message = txt.s(ShareText.CANNOT_SAVE)
                        }
                    }
                }, Modifier.fillMaxWidth().testTag("receive-add"), enabled = !working) { Text(txt.s(ShareText.ADD)) }
                OutlinedButton({
                    seams.inbox.discard(p); opened = null; message = null
                }, Modifier.fillMaxWidth().testTag("receive-reject")) { Text(txt.s(ShareText.REJECT), color = c.danger) }
            }
            p != null -> {
                Text("${txt.s(ShareText.FROM)} ${p.header.sender}", color = c.text, style = MaterialTheme.typography.bodyLarge)
                OutlinedTextField(
                    code, { code = it }, label = { Text(txt.s(ShareText.CODE_LABEL)) }, singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false,
                        keyboardType = KeyboardType.Password, imeAction = ImeAction.Done,
                    ),
                    modifier = Modifier.fillMaxWidth().testTag("receive-code"),
                )
                Button({
                    if (working) return@Button
                    working = true
                    val typed = code
                    scope.launch {
                        try {
                            opened = withContext(Dispatchers.Default) { seams.inbox.open(p, typed) }
                            message = null
                        } catch (e: ShareException) {
                            message = when {
                                e.reason == "wrong-code" && p.wrongCodes >= ShareInbox.MAX_WRONG_CODES -> txt.s(ShareText.TOO_MANY)
                                e.reason == "wrong-code" -> refusalText(e, txt) + " " + ShareText.attemptsLeft(ShareInbox.MAX_WRONG_CODES - p.wrongCodes, txt)
                                else -> refusalText(e, txt)
                            }
                        } finally {
                            working = false
                        }
                    }
                }, Modifier.fillMaxWidth().testTag("receive-open"), enabled = !working && code.isNotBlank()) { Text(txt.s(ShareText.OPEN)) }
                OutlinedButton({ seams.inbox.discard(p); code = "" }, Modifier.fillMaxWidth()) { Text(txt.s(ShareText.REJECT), color = c.danger) }
            }
            else -> {
                Text(txt.s(ShareText.RECEIVE_FOOTER), color = c.secondaryText)
                Button({ message = null; scanning = true }, Modifier.fillMaxWidth().testTag("receive-scan")) { Text(txt.s(ShareText.SCAN)) }
                if (files != null) {
                    OutlinedButton({
                        message = null
                        files.open { bytes, _ ->
                            if (bytes == null) {
                                message = txt.s(ShareText.FAILED)
                            } else if (bytes.size > Share.MAX_PACKAGE) {
                                bytes.fill(0); message = txt.s(R.string.share_not_a_share)
                            } else {
                                accept(bytes, true)
                            }
                        }
                    }, Modifier.fillMaxWidth().testTag("receive-file")) { Text(txt.s(ShareText.OPEN_FILE)) }
                }
            }
        }
    }
}
