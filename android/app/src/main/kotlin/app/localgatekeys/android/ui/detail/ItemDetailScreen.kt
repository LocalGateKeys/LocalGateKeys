package app.localgatekeys.android.ui.detail

import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.snap
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.detail.DetailField
import app.localgatekeys.android.detail.ItemDetailModel
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.editor.EditorScreenText
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.settings.ClipboardExpiry
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGlass
import app.localgatekeys.android.ui.vault.ItemAvatar
import app.localgatekeys.android.ui.vault.rememberSecondTick
import app.localgatekeys.android.generator.GeneratorStrength
import app.localgatekeys.android.ui.generator.StrengthMeter
import app.localgatekeys.android.vault.CodeTileModel
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.primitives.UnixClock
import kotlinx.coroutines.launch

/** What the detail screen needs from the rest of the app. */
class DetailSeams(
    /** The shared secret clipboard (also cleared on lock). */
    val clipboard: SecretClipboard,
    /** The shared copy confirmation. */
    val toast: CopyToast,
    /** Opens the editor (or, for a passkey, the rename screen) for this item; null: no Edit button. */
    val onEdit: ((VaultItem) -> Unit)? = null,
    /**
     * Deletes an item the phone cannot edit (desktop logins, documents) through the store, off the main thread, and
     * reloads the list when it changed. Null: no Delete button.
     */
    val onDelete: (suspend (VaultItem) -> SaveResult)? = null,
) {
    fun copy(onEdit: ((VaultItem) -> Unit)? = this.onEdit, onDelete: (suspend (VaultItem) -> SaveResult)? = this.onDelete) =
        DetailSeams(clipboard, toast, onEdit, onDelete)

    override fun toString(): String = "DetailSeams(edit=${onEdit != null}, delete=${onDelete != null})"
}

/** Which action the detail toolbar offers for a kind. */
enum class DetailAction {
    /** The field editor ([EditorKind]) or, for a passkey, the rename screen. */
    EDIT,

    /** Kinds the phone cannot edit (`ItemDetailModel.offersDeleteOnly`): Delete only. */
    DELETE,
    ;

    companion object {
        fun of(kind: String): DetailAction = if (ItemDetailModel.offersDeleteOnly(kind)) DELETE else EDIT
    }
}

/**
 * Item detail (port of `ios/App/Detail/ItemDetailView.swift`): the big icon, name and Open website; the one-time code
 * with its ring; the fields with reveal and copy; a footnote after a copy saying when it leaves the clipboard. Values
 * are not selectable, so copies always go through the secret clipboard. The toolbar offers Edit for the kinds the phone
 * edits (and the passkey rename) and Delete for the kinds it cannot edit. A saved password shows its estimated strength.
 */
@Composable
fun ItemDetailScreen(
    item: VaultItem,
    clock: UnixClock,
    concealSecrets: Boolean,
    clipboardExpiry: ClipboardExpiry,
    seams: DetailSeams,
    onBack: () -> Unit,
) {
    val model = remember(item, seams.clipboard, clock) { ItemDetailModel(item, clock, seams.clipboard, concealSecrets) }
    val tick = rememberSecondTick(clock)
    LaunchedEffect(tick, model) { model.tick() }
    val totp by model.totp.collectAsStateWithLifecycle()
    val revealed by model.revealed.collectAsStateWithLifecycle()
    val lastCopied by model.lastCopied.collectAsStateWithLifecycle()
    val c = LgkTheme.colors
    val uriHandler = LocalUriHandler.current
    val title = item.title.ifEmpty { item.kindLabel }
    val scope = rememberCoroutineScope()
    var confirmDelete by remember { mutableStateOf(false) }
    var deleteResult by remember { mutableStateOf<SaveResult?>(null) }
    var deleting by remember { mutableStateOf(false) }
    BackHandler(onBack = onBack)

    Box(Modifier.fillMaxSize().testTag("item-detail")) {
        AuroraBackground()
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            Row(
                Modifier.fillMaxWidth().height(64.dp).padding(horizontal = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    Modifier
                        .size(48.dp)
                        .lgkGlass(CircleShape)
                        .clip(CircleShape)
                        .clickable(role = Role.Button, onClick = onBack)
                        .semantics { contentDescription = "Back" },
                    contentAlignment = Alignment.Center,
                ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = c.text) }
                Text(
                    title, color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center,
                    modifier = Modifier.weight(1f).padding(horizontal = 12.dp).semantics { heading() },
                )
                val edit = seams.onEdit
                val delete = seams.onDelete
                when {
                    DetailAction.of(item.kind) == DetailAction.EDIT && edit != null ->
                        TextButton({ edit(item) }) { Text("Edit", color = c.accentText, fontWeight = FontWeight.SemiBold) }
                    DetailAction.of(item.kind) == DetailAction.DELETE && delete != null ->
                        TextButton({ confirmDelete = true }, enabled = !deleting) {
                            Text("Delete", color = c.danger, fontWeight = FontWeight.SemiBold)
                        }
                    else -> Spacer(Modifier.width(48.dp))
                }
            }
            LazyColumn(
                Modifier.fillMaxSize().navigationBarsPadding(),
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                item(key = "header") {
                    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        ItemAvatar(item, 72.dp)
                        Spacer(Modifier.height(10.dp))
                        Text(
                            title, color = c.text, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold,
                            textAlign = TextAlign.Center,
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            if (item.isLogin) item.target.ifEmpty { item.kindLabel } else item.kindLabel,
                            color = c.secondaryText, style = MaterialTheme.typography.bodyMedium, maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        item.openableUrl?.let { url ->
                            Spacer(Modifier.height(10.dp))
                            OutlinedButton(
                                {
                                    // No browser (or none that takes the link): nothing happens.
                                    try { uriHandler.openUri(url) } catch (_: Exception) {}
                                },
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = c.accentText),
                            ) {
                                Icon(Icons.Filled.OpenInBrowser, null, Modifier.size(18.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Open website")
                            }
                        }
                    }
                }
                totp?.let { t ->
                    item(key = "totp") {
                        Column {
                            SectionTitle("One-time code")
                            Row(
                                Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface)
                                    .padding(horizontal = 16.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                TotpRing(t.fractionRemaining.toFloat(), t.secondsRemaining)
                                Spacer(Modifier.width(16.dp))
                                Text(
                                    t.code, color = c.text, fontFamily = FontFamily.Monospace, fontSize = 28.sp,
                                    modifier = Modifier.weight(1f).testTag("detail-code"),
                                )
                                CopyButton("Copy code") { if (model.copyTotp()) seams.toast.show("Code copied") }
                            }
                        }
                    }
                }
                if (model.fields.isNotEmpty()) {
                    item(key = "fields") {
                        Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface)) {
                            model.fields.forEachIndexed { index, field ->
                                FieldRow(
                                    field, if (field.isSecret && field.id !in revealed) ItemDetailModel.MASK else field.value,
                                    field.id in revealed,
                                    onToggle = { model.toggleReveal(field) },
                                    onCopy = { model.copy(field); seams.toast.show("${field.label} copied") },
                                )
                                if (index != model.fields.lastIndex) {
                                    Box(Modifier.padding(start = 16.dp).fillMaxWidth().height(1.dp).background(c.separator))
                                }
                            }
                        }
                    }
                }
                lastCopied?.let { copied ->
                    item(key = "footnote") {
                        Text(
                            "$copied copied. It clears from the clipboard in ${clipboardExpiry.label}.",
                            color = c.secondaryText, style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(horizontal = 4.dp).testTag("copy-footnote"),
                        )
                    }
                }
            }
        }
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            confirmButton = {
                TextButton({
                    confirmDelete = false
                    val delete = seams.onDelete ?: return@TextButton
                    deleting = true
                    scope.launch {
                        // A delete-only kind (desktop login, document): tombstone, like every delete.
                        val r = delete(item)
                        deleting = false
                        if (r == SaveResult.SAVED) onBack() else deleteResult = r
                    }
                }, Modifier.testTag("confirm-delete")) { Text("Delete", color = c.danger) }
            },
            dismissButton = { TextButton({ confirmDelete = false }) { Text("Cancel") } },
            title = { Text(EditorScreenText.DELETE_TITLE) },
            text = { Text(EditorScreenText.DELETE_ONLY_MESSAGE) },
        )
    }
    deleteResult?.let { r ->
        val close = {
            deleteResult = null
            if (r == SaveResult.UNCHANGED) onBack()
        }
        AlertDialog(
            onDismissRequest = close,
            confirmButton = { TextButton(close) { Text("OK") } },
            title = {
                Text(if (r == SaveResult.UNCHANGED) EditorModel.ALREADY_REMOVED_MESSAGE else EditorScreenText.DELETE_FAILED)
            },
        )
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text, color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.titleSmall,
        modifier = Modifier.padding(start = 4.dp, bottom = 6.dp).semantics { heading() },
    )
}

@Composable
private fun FieldRow(field: DetailField, shown: String, revealed: Boolean, onToggle: () -> Unit, onCopy: () -> Unit) {
    val c = LgkTheme.colors
    Row(
        Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 10.dp, bottom = 10.dp).testTag("field-${field.id}"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(field.label, color = c.secondaryText, style = MaterialTheme.typography.labelMedium)
            Spacer(Modifier.height(2.dp))
            Text(
                shown, color = c.text,
                style = MaterialTheme.typography.bodyLarge,
                fontFamily = if (field.isSecret) FontFamily.Monospace else null,
                modifier = Modifier.testTag("value-${field.id}"),
            )
            if (field.id == "password") {
                StrengthMeter(GeneratorStrength.estimate(field.value), Modifier.padding(top = 6.dp))
            }
        }
        if (field.isSecret) {
            IconButton(onToggle, Modifier.semantics { contentDescription = if (revealed) "Hide" else "Reveal" }) {
                Icon(if (revealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility, null, tint = c.accentText)
            }
        }
        CopyButton("Copy ${field.label}", onCopy)
    }
}

@Composable
private fun CopyButton(description: String, onClick: () -> Unit) {
    IconButton(onClick, Modifier.semantics { contentDescription = description }) {
        Icon(Icons.Filled.ContentCopy, null, tint = LgkTheme.colors.accentText)
    }
}

/** Shows the time left in the current period: a 36 dp ring with the seconds, orange in the last seven. */
@Composable
fun TotpRing(fraction: Float, seconds: Int) {
    val c = LgkTheme.colors
    val target = fraction.coerceIn(0f, 1f)
    val previous = remember { floatArrayOf(target) }
    val spec = if (target > previous[0]) snap() else tween<Float>(1000, easing = LinearEasing)
    SideEffect { previous[0] = target }
    val f by animateFloatAsState(target, spec, label = "ring")
    val tint: Color = if (CodeTileModel.isUrgent(seconds)) c.glowOrange else c.accent
    val track = c.separator
    Box(
        Modifier.size(36.dp).clearAndSetSemantics { contentDescription = "$seconds seconds left" },
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.size(36.dp)) {
            val w = 4.dp.toPx()
            val inset = w / 2
            val arcSize = Size(size.width - w, size.height - w)
            drawArc(track, 0f, 360f, false, Offset(inset, inset), arcSize, style = Stroke(w))
            drawArc(tint, -90f, 360f * f, false, Offset(inset, inset), arcSize, style = Stroke(w, cap = StrokeCap.Round))
        }
        Text("$seconds", color = c.secondaryText, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
    }
}
