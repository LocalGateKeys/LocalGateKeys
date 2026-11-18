package app.localgatekeys.android.ui.detail
import app.localgatekeys.android.access.CopyOnceLedger
import app.localgatekeys.android.access.AccessGate
import androidx.compose.ui.res.pluralStringResource
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource

import app.localgatekeys.android.i18n.rememberTxt
import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.snap
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
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
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
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
import androidx.compose.ui.graphics.FilterQuality
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
import androidx.annotation.StringRes
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.detail.DetailField
import app.localgatekeys.android.detail.ItemDetailModel
import app.localgatekeys.android.detail.PasswordHistoryModel
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.editor.EditorScreenText
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.settings.ClipboardExpiry
import app.localgatekeys.android.ui.common.qrBitmap
import app.localgatekeys.android.ui.settings.Toggle
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGlass
import app.localgatekeys.android.ui.vault.ItemAvatar
import app.localgatekeys.android.ui.vault.rememberSecondTick
import app.localgatekeys.android.generator.GeneratorStrength
import app.localgatekeys.android.ui.generator.StrengthMeter
import app.localgatekeys.android.codes.PinResult
import app.localgatekeys.android.codes.PinnedCodes
import app.localgatekeys.android.vault.CodeTileModel
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.JwtInfo
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
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
    /**
     * Marks or unmarks the item as a favorite through the store (`VaultListModel.setFavorite`), off the main thread,
     * and reloads the list when it changed. Null: no star.
     */
    val onSetFavorite: (suspend (VaultItem, Boolean) -> SaveResult)? = null,
    /**
     * "Restore this password" on a login's history entry (`VaultListModel.restorePassword`), off the main thread, and
     * reloads the list when it changed. Null: no Restore button.
     */
    val onRestorePassword: (suspend (VaultItem, Int) -> SaveResult)? = null,
    /** The owner's fingerprint, face or screen lock before past passwords are shown. Null: they cannot be revealed. */
    val confirmOwner: (suspend () -> Boolean)? = null,
    /** Task 12: the File section of a document (preview, save, share, rename). Null: not shown. */
    val documents: DocumentSeams? = null,
    /** UX workstream 9: opens the Share sheet for an item that can be shared. Null: no Share button. */
    val onShare: ((VaultItem) -> Unit)? = null,
    /** More sections under the fields (the Reminder section, workstream 10). Null: none. */
    val below: (@Composable (VaultItem) -> Unit)? = null,
    /** "Set expiry from token": writes the API key's `expires` (`YYYY-MM-DD`) through the editor's save. Null: no button. */
    val onSetExpiry: (suspend (VaultItem, String) -> SaveResult)? = null,
    /** Sub-plan 06: "Show in widget" under the one-time code. Null: no switch. */
    val pins: CodePinSeams? = null,
    /**
     * Sub-plan 07: the item's collections by name and whether it is view only here (read off the main thread when the
     * screen opens). Null: no Collections section.
     */
    val collections: (suspend (VaultItem) -> ItemCollections)? = null,
    /** Copy-once access rule: the logins copied once in this unlock (the app's, cleared at lock). */
    val copyOnce: CopyOnceLedger = CopyOnceLedger(),
    /** Feature pack 2026-11-15: opens the login's Access rules sheet. Null: no Access rules row. */
    val onAccess: ((VaultItem) -> Unit)? = null,
    /** Feature pack 2026-11-15: opens the item's History (this phone only). Null: no History row. */
    val onHistory: ((VaultItem) -> Unit)? = null,
    /** Feature pack 2026-11-15 section 6.3: the passkey upgrade prompt on a login. Null: never shown. */
    val passkeyUpgrade: PasskeyUpgradeSeams? = null,
    /** Access rules: the owner's check titled with the action's own reason. Null: falls back to [confirmOwner]. */
    val confirmOwnerFor: (suspend (String) -> Boolean)? = null,
) {
    fun copy(
        onEdit: ((VaultItem) -> Unit)? = this.onEdit,
        onDelete: (suspend (VaultItem) -> SaveResult)? = this.onDelete,
        onSetFavorite: (suspend (VaultItem, Boolean) -> SaveResult)? = this.onSetFavorite,
        onRestorePassword: (suspend (VaultItem, Int) -> SaveResult)? = this.onRestorePassword,
        documents: DocumentSeams? = this.documents,
        onShare: ((VaultItem) -> Unit)? = this.onShare,
        below: (@Composable (VaultItem) -> Unit)? = this.below,
        onSetExpiry: (suspend (VaultItem, String) -> SaveResult)? = this.onSetExpiry,
        pins: CodePinSeams? = this.pins,
        collections: (suspend (VaultItem) -> ItemCollections)? = this.collections,
        onAccess: ((VaultItem) -> Unit)? = this.onAccess,
        onHistory: ((VaultItem) -> Unit)? = this.onHistory,
        passkeyUpgrade: PasskeyUpgradeSeams? = this.passkeyUpgrade,
    ) = DetailSeams(
        clipboard, toast, onEdit, onDelete, onSetFavorite, onRestorePassword, confirmOwner, documents, onShare, below, onSetExpiry, pins,
        collections, copyOnce, onAccess, onHistory, passkeyUpgrade, confirmOwnerFor,
    )

    override fun toString(): String =
        "DetailSeams(edit=${onEdit != null}, delete=${onDelete != null}, favorite=${onSetFavorite != null}, " +
            "restore=${onRestorePassword != null})"
}

/**
 * An item's collections as the detail shows them (sub-plan 07): their names, and whether the item is in a collection
 * shared with this vault as view only (no Edit, Delete or star then).
 */
data class ItemCollections(val names: List<String>, val readOnly: Boolean) {
    companion object {
        val NONE = ItemCollections(emptyList(), false)

        fun of(itemId: String, snapshot: app.localgatekeys.core.sync.StoreSnapshot): ItemCollections {
            val ids = app.localgatekeys.core.sync.CollectionCatalog.memberships(itemId, snapshot).toSet()
            if (ids.isEmpty()) return NONE
            val names = app.localgatekeys.core.sync.CollectionCatalog.collections(snapshot).filter { it.id in ids }.map { it.name }
            return ItemCollections(names, app.localgatekeys.android.collections.CollectionsModel.itemIsReadOnly(itemId, snapshot))
        }
    }
}

/**
 * The passkey upgrade prompt (contract section 6.3): [domainFor] reads the vault off the main thread and gives the
 * registrable domain to offer (null: no prompt, or dismissed less than 90 days ago); [dismiss] records "Not now" on this
 * phone. "Open site" opens the login's website; the password is never touched.
 */
class PasskeyUpgradeSeams(
    val domainFor: suspend (VaultItem) -> String?,
    val dismiss: suspend (String) -> Unit,
)

/** Sub-plan 06: pinning an item's code to the home-screen widget. Pinning is Pro; unpinning never is. */
class CodePinSeams(
    val isPinned: (String) -> Boolean,
    /** Pins or unpins the item (and refreshes the widget). */
    val toggle: (String) -> PinResult,
    /** Opens the Pro sheet (the shell sets it). */
    val onNeedsPro: () -> Unit = {},
    /** Auto-lock is "Immediately": the note says the widget then shows codes only while the app is open. */
    val lockImmediately: () -> Boolean = { false },
) {
    fun withUpgrade(onNeedsPro: () -> Unit) = CodePinSeams(isPinned, toggle, onNeedsPro, lockImmediately)

    companion object {
        /** The note under "Show in widget". */
        @StringRes fun noteRes(lockImmediately: Boolean): Int =
            if (lockImmediately) R.string.detail_pin_code_note_immediately else R.string.detail_pin_code_note
    }
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
    showFormatting: Boolean = true,
    onShowFormattingChange: (Boolean) -> Unit = {},
) {
    val txt = rememberTxt()
    val backLabel = txt.s(R.string.common_back)
    val model = remember(item, seams.clipboard, clock) { ItemDetailModel(item, clock, seams.clipboard, txt, concealSecrets, seams.copyOnce) }
    val scopeAccess = rememberCoroutineScope()
    // Access rules (contract section 4.3): runs [action] when [need] allows it, after the owner's check when asked.
    // [reason] is the toast; [ask] titles the owner's check after the action it allows.
    val guarded: (AccessGate.Need, String, String, () -> Unit) -> Unit = { need, reason, ask, action ->
        when (need) {
            AccessGate.Need.NOTHING -> action()
            AccessGate.Need.REFUSED -> seams.toast.show(txt.s(R.string.access_refused_phone))
            AccessGate.Need.OWNER -> scopeAccess.launch {
                seams.toast.show(reason)
                val ok = seams.confirmOwnerFor?.invoke(ask) ?: seams.confirmOwner?.invoke()
                if (ok == true) action()
            }
        }
    }
    val copyReason = if (model.access.copyOnce && !model.access.reauth) txt.s(R.string.access_copy_again) else txt.s(R.string.access_reauth)
    val copyAsk = if (model.access.copyOnce && !model.access.reauth) txt.s(R.string.access_copy_again) else txt.s(R.string.access_owner_copy)
    val tick = rememberSecondTick(clock)
    LaunchedEffect(tick, model) { model.tick() }
    val totp by model.totp.collectAsStateWithLifecycle()
    val revealed by model.revealed.collectAsStateWithLifecycle()
    val codeRevealed by model.codeRevealed.collectAsStateWithLifecycle()
    val lastCopied by model.lastCopied.collectAsStateWithLifecycle()
    val c = LgkTheme.colors
    val uriHandler = LocalUriHandler.current
    val title = item.title.ifEmpty { item.kindLabel(txt) }
    val scope = rememberCoroutineScope()
    var formattingOn by remember { mutableStateOf(showFormatting) }
    var confirmDelete by remember { mutableStateOf(false) }
    var wifiQrOpen by remember(item) { mutableStateOf(false) }
    val wifiQrReady = remember(model, revealed) { model.wifiQrText() != null }
    var deleteResult by remember { mutableStateOf<SaveResult?>(null) }
    var deleting by remember { mutableStateOf(false) }
    // Shown at once; the reloaded item confirms it (a failed write puts the star back).
    var favorite by remember(item) { mutableStateOf(item.favorite) }
    val history = remember(item, seams.clipboard) { PasswordHistoryModel(item, seams.clipboard, seams.confirmOwner) }
    val historyRevealed by history.revealed.collectAsStateWithLifecycle()
    var historyOpen by remember { mutableStateOf(false) }
    var restoreIndex by remember(item) { mutableStateOf<Int?>(null) }
    var restoreFailed by remember { mutableStateOf(false) }
    // Sub-plan 07: the item's collections, read once when the screen opens (not on every tick).
    var collections by remember(item) { mutableStateOf(ItemCollections.NONE) }
    LaunchedEffect(item, seams.collections) { seams.collections?.let { read -> collections = read(item) } }
    // Feature pack section 6.3: the passkey upgrade prompt's domain, read once when the screen opens.
    var upgradeDomain by remember(item) { mutableStateOf<String?>(null) }
    LaunchedEffect(item, seams.passkeyUpgrade) {
        upgradeDomain = if (item.kind == "web") seams.passkeyUpgrade?.let { p -> try { p.domainFor(item) } catch (e: Exception) { null } } else null
    }
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
                        .semantics { contentDescription = backLabel },
                    contentAlignment = Alignment.Center,
                ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = c.text) }
                Text(
                    title, color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center,
                    modifier = Modifier.weight(1f).padding(horizontal = 12.dp).semantics { heading() },
                )
                // In a collection shared with this vault as view only: no Edit, Delete or star (the section says why).
                val edit = seams.onEdit?.takeIf { !collections.readOnly }
                val delete = seams.onDelete?.takeIf { !collections.readOnly }
                seams.onSetFavorite?.takeIf { !collections.readOnly }?.let { setFavorite ->
                    IconButton(
                        onClick = {
                            val want = !favorite
                            favorite = want
                            scope.launch { val r = setFavorite(item, want); if (r == SaveResult.FAILED || r == SaveResult.INVALID) favorite = !want }
                        },
                        modifier = Modifier.testTag("detail-favorite"),
                    ) {
                        Icon(
                            if (favorite) Icons.Filled.Star else Icons.Filled.StarBorder,
                            stringResource(if (favorite) R.string.detail_favorite_remove else R.string.detail_favorite_add),
                            tint = if (favorite) c.warning else c.text,
                        )
                    }
                }
                seams.onShare?.takeIf { app.localgatekeys.android.share.ItemSharing.canShare(item) }?.let { share ->
                    // View only on phones: the share flow is refused (contract section 4.3).
                    IconButton({ if (model.access.phoneView) seams.toast.show(txt.s(R.string.access_refused_phone)) else share(item) }, Modifier.testTag("detail-share")) {
                        Icon(Icons.Filled.Share, txt.s(app.localgatekeys.android.share.ShareText.SHARE), tint = c.text)
                    }
                }
                when {
                    DetailAction.of(item.kind) == DetailAction.EDIT && edit != null ->
                        TextButton({ guarded(AccessGate.edit(model.access), txt.s(R.string.access_reauth), txt.s(R.string.access_owner_edit)) { edit(item) } }) { Text(stringResource(R.string.common_edit), color = c.accentText, fontWeight = FontWeight.SemiBold) }
                    DetailAction.of(item.kind) == DetailAction.DELETE && delete != null ->
                        TextButton({ confirmDelete = true }, enabled = !deleting) {
                            Text(stringResource(R.string.common_delete), color = c.danger, fontWeight = FontWeight.SemiBold)
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
                            if (item.isLogin) item.target.ifEmpty { item.kindLabel(txt) } else item.kindLabel(txt),
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
                                Text(stringResource(R.string.detail_open_website))
                            }
                        }
                    }
                }
                upgradeDomain?.let { domain ->
                    item(key = "passkey-upgrade") {
                        Column(
                            Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface)
                                .padding(horizontal = 16.dp, vertical = 12.dp).testTag("detail-passkey-upgrade"),
                        ) {
                            Text(stringResource(R.string.passkey_upgrade_title), color = c.text, fontWeight = FontWeight.SemiBold)
                            Spacer(Modifier.height(4.dp))
                            Text(stringResource(R.string.passkey_upgrade_body), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium)
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                                TextButton({
                                    upgradeDomain = null
                                    scope.launch { try { seams.passkeyUpgrade?.dismiss?.invoke(domain) } catch (e: Exception) {} }
                                }, Modifier.testTag("passkey-upgrade-not-now")) { Text(stringResource(R.string.passkey_upgrade_not_now), color = c.accentText) }
                                item.openableUrl?.let { url ->
                                    TextButton({
                                        try { uriHandler.openUri(url) } catch (_: Exception) {}
                                    }, Modifier.testTag("passkey-upgrade-open")) { Text(stringResource(R.string.passkey_upgrade_open), color = c.accentText) }
                                }
                            }
                        }
                    }
                }
                if (collections.names.isNotEmpty() || collections.readOnly) {
                    item(key = "collections") { CollectionsSection(collections) }
                }
                val docs = seams.documents
                if (item.kind == "document" && docs != null) {
                    item(key = "document") { DocumentSection(item, docs) }
                }
                totp?.let { t ->
                    item(key = "totp") {
                        Column {
                            SectionTitle(stringResource(R.string.detail_one_time_code))
                            Row(
                                Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface)
                                    .padding(horizontal = 16.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                TotpRing(t.fractionRemaining.toFloat(), t.secondsRemaining)
                                Spacer(Modifier.width(16.dp))
                                // Access rules: hidden like the password until the owner's check (re-authenticate, view only on phones, unknown rule).
                                Text(
                                    if (codeRevealed) t.code else ItemDetailModel.MASK, color = c.text, fontFamily = FontFamily.Monospace, fontSize = 28.sp,
                                    modifier = Modifier.weight(1f).testTag("detail-code"),
                                )
                                if (AccessGate.reveal(model.access) != AccessGate.Need.NOTHING) {
                                    val codeToggleLabel = stringResource(if (codeRevealed) R.string.common_hide else R.string.common_reveal)
                                    IconButton(
                                        { guarded(model.codeRevealNeed(), txt.s(R.string.access_reauth), txt.s(R.string.access_owner_show)) { model.toggleCodeReveal() } },
                                        Modifier.testTag("detail-code-reveal").semantics { contentDescription = codeToggleLabel },
                                    ) {
                                        Icon(if (codeRevealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility, null, tint = c.accentText)
                                    }
                                }
                                CopyButton(stringResource(R.string.detail_copy_code)) {
                                    guarded(model.copyNeed(), copyReason, copyAsk) { if (model.copyTotp()) seams.toast.show(txt.s(R.string.detail_code_copied)) }
                                }
                            }
                            seams.pins?.let { pins ->
                                var pinned by remember(item.id, pins) { mutableStateOf(pins.isPinned(item.id)) }
                                Spacer(Modifier.height(8.dp))
                                Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface).padding(horizontal = 16.dp)) {
                                    Toggle(
                                        stringResource(R.string.detail_pin_code), pinned,
                                        description = stringResource(CodePinSeams.noteRes(pins.lockImmediately())), divider = false, tag = "detail-pin-code",
                                    ) {
                                        when (pins.toggle(item.id)) {
                                            PinResult.PINNED -> pinned = true
                                            PinResult.UNPINNED -> pinned = false
                                            PinResult.NEEDS_PRO -> pins.onNeedsPro()
                                            PinResult.FULL -> seams.toast.show(txt.s(R.string.detail_pin_full, PinnedCodes.MAX_PINS))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // Feature pack 2026-11-15: the access-rule banners and the Access rules and History rows.
                if (model.access.expired || model.access.unknownRule || seams.onAccess != null || seams.onHistory != null) {
                    item(key = "access") {
                        Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface).padding(horizontal = 16.dp, vertical = 8.dp)) {
                            if (model.access.expired) {
                                Text(
                                    stringResource(R.string.access_expired, model.access.expiresOn), color = c.danger,
                                    modifier = Modifier.padding(vertical = 6.dp).testTag("detail-access-expired"),
                                )
                            }
                            if (model.access.unknownRule) {
                                Text(stringResource(R.string.access_unknown_rule), color = c.warning, modifier = Modifier.padding(vertical = 6.dp).testTag("detail-access-unknown"))
                            }
                            if (item.kind == "web") seams.onAccess?.let { open ->
                                TextButton({ open(item) }, Modifier.testTag("detail-access")) { Text(stringResource(R.string.access_title), color = c.accentText) }
                            }
                            seams.onHistory?.let { open ->
                                TextButton({ open(item) }, Modifier.testTag("detail-history")) { Text(stringResource(R.string.history_title), color = c.accentText) }
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
                                    formatted = formattingOn && formatsAsMarkdown(item.kind, field.id),
                                    onToggle = { guarded(model.revealNeed(field), txt.s(R.string.access_reauth), txt.s(R.string.access_owner_show)) { model.toggleReveal(field) } },
                                    onCopy = {
                                        val need = when {
                                            field.isSecret -> model.copyNeed()
                                            model.access.phoneView -> AccessGate.Need.REFUSED
                                            else -> AccessGate.Need.NOTHING
                                        }
                                        guarded(need, copyReason, copyAsk) { model.copy(field); seams.toast.show(txt.s(R.string.detail_field_copied, field.label)) }
                                    },
                                )
                                if (formatsAsMarkdown(item.kind, field.id)) {
                                    Box(Modifier.padding(horizontal = 16.dp)) {
                                        Toggle(
                                            stringResource(R.string.notes_show_formatting), formattingOn, divider = false, tag = "detail-show-formatting",
                                        ) { formattingOn = it; onShowFormattingChange(it) }
                                    }
                                }
                                if (index != model.fields.lastIndex) {
                                    Box(Modifier.padding(start = 16.dp).fillMaxWidth().height(1.dp).background(c.separator))
                                }
                            }
                        }
                    }
                }
                model.fields.forEach { field ->
                    val info = model.token(field) ?: return@forEach
                    item(key = "token-${field.id}") {
                        TokenSection(info, field.label.takeIf { model.fields.count { model.token(it) != null } > 1 }, model, seams.onSetExpiry != null && model.canSetExpiryFrom(info)) { date ->
                            scope.launch {
                                val r = seams.onSetExpiry?.invoke(item, date)
                                seams.toast.show(txt.s(if (r == SaveResult.SAVED) R.string.jwt_expirySet else R.string.jwt_notSaved, date))
                            }
                        }
                    }
                }
                if (model.offersWifiQr) {
                    item(key = "wifi-qr") {
                        OutlinedButton(
                            { wifiQrOpen = true }, enabled = wifiQrReady,
                            modifier = Modifier.fillMaxWidth().testTag("wifi-qr-button"),
                        ) { Text(stringResource(R.string.detail_wifi_show_qr), color = c.accentText) }
                    }
                } else if (model.isWifiEnterprise) {
                    item(key = "wifi-qr-note") {
                        Text(
                            stringResource(R.string.detail_wifi_enterprise_no_qr), color = c.secondaryText,
                            style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(horizontal = 4.dp).testTag("wifi-qr-note"),
                        )
                    }
                }
                if (history.entries.isNotEmpty()) {
                    item(key = "history") {
                        PasswordHistorySection(
                            history, historyOpen, historyRevealed,
                            onOpen = { historyOpen = !historyOpen },
                            onReveal = { scope.launch { history.toggleReveal() } },
                            // Old passwords follow the login's access rules like the current one (view only, re-auth, copy once).
                            onCopy = { i -> guarded(model.copyNeed(), copyReason, copyAsk) { if (model.copyHistoryPassword(i)) seams.toast.show(txt.s(R.string.detail_password_copied)) } },
                            onRestore = if (seams.onRestorePassword != null) { i -> restoreIndex = i } else null,
                        )
                    }
                }
                seams.below?.let { extra -> item(key = "below") { extra(item) } }
                lastCopied?.let { copied ->
                    item(key = "footnote") {
                        Text(
                            txt.s(R.string.detail_copied_footnote, copied, clipboardExpiry.label(txt)),
                            color = c.secondaryText, style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(horizontal = 4.dp).testTag("copy-footnote"),
                        )
                    }
                }
            }
        }
    }
    // Keyed on `revealed`: hiding the password drops the QR and closes the dialog.
    val wifiQr = remember(wifiQrOpen, revealed) { if (wifiQrOpen) model.wifiQrText() else null }
    LaunchedEffect(wifiQrOpen, wifiQr) { if (wifiQrOpen && wifiQr == null) wifiQrOpen = false }
    wifiQr?.let { WifiQrDialog(it) { wifiQrOpen = false } }
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
                }, Modifier.testTag("confirm-delete")) { Text(stringResource(R.string.common_delete), color = c.danger) }
            },
            dismissButton = { TextButton({ confirmDelete = false }) { Text(stringResource(R.string.common_cancel)) } },
            title = { Text(txt.s(EditorScreenText.DELETE_TITLE)) },
            text = { Text(txt.s(EditorScreenText.DELETE_ONLY_MESSAGE)) },
        )
    }
    restoreIndex?.let { index ->
        AlertDialog(
            onDismissRequest = { restoreIndex = null },
            confirmButton = {
                TextButton({
                    restoreIndex = null
                    val restore = seams.onRestorePassword ?: return@TextButton
                    scope.launch { if (restore(item, index) == SaveResult.FAILED) restoreFailed = true }
                }, Modifier.testTag("confirm-restore")) { Text(stringResource(R.string.common_restore), color = c.accentText) }
            },
            dismissButton = { TextButton({ restoreIndex = null }) { Text(stringResource(R.string.common_cancel)) } },
            title = { Text(txt.s(PasswordHistoryModel.RESTORE_TITLE)) },
            text = { Text(txt.s(PasswordHistoryModel.RESTORE_TEXT)) },
        )
    }
    if (restoreFailed) {
        AlertDialog(
            onDismissRequest = { restoreFailed = false },
            confirmButton = { TextButton({ restoreFailed = false }) { Text(stringResource(R.string.common_ok)) } },
            title = { Text(txt.s(PasswordHistoryModel.RESTORE_FAILED)) },
        )
    }
    deleteResult?.let { r ->
        val close = {
            deleteResult = null
            if (r == SaveResult.UNCHANGED) onBack()
        }
        AlertDialog(
            onDismissRequest = close,
            confirmButton = { TextButton(close) { Text(stringResource(R.string.common_ok)) } },
            title = {
                Text(
                    when (r) {
                        SaveResult.UNCHANGED -> txt.s(EditorScreenText.ALREADY_REMOVED)
                        // In a collection shared with this vault as view only (sub-plan 07).
                        SaveResult.INVALID -> txt.s(R.string.collections_read_only_item)
                        else -> txt.s(EditorScreenText.DELETE_FAILED)
                    },
                )
            },
        )
    }
}

/**
 * The Wi-Fi network's QR code, shown only while the password is revealed. The image is made when the dialog opens and
 * dropped when it leaves the screen, so it never outlives the dialog.
 */
@Composable
private fun WifiQrDialog(text: String, onClose: () -> Unit) {
    val c = LgkTheme.colors
    val image = remember(text) { qrBitmap(text, 560, ErrorCorrectionLevel.M) }
    AlertDialog(
        onDismissRequest = onClose,
        confirmButton = { TextButton(onClose) { Text(stringResource(R.string.common_close), color = c.accentText) } },
        title = { Text(stringResource(R.string.detail_wifi_show_qr)) },
        text = {
            Column(Modifier.testTag("wifi-qr-dialog"), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (image != null) {
                    Image(
                        image, null, filterQuality = FilterQuality.None,
                        modifier = Modifier.size(240.dp).background(Color.White).padding(8.dp).testTag("wifi-qr-image"),
                    )
                }
                Text(stringResource(R.string.detail_wifi_qr_hint), color = c.secondaryText, style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
                Text(
                    stringResource(R.string.wifi_qr_no_expiry), color = c.secondaryText, style = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center, modifier = Modifier.testTag("wifi-qr-no-expiry"),
                )
            }
        },
    )
}

/** The read-only decode of a revealed token: claims, local dates, an Expired badge, and "Set expiry from token". */
@Composable
private fun TokenSection(info: JwtInfo, fieldLabel: String?, model: ItemDetailModel, canSetExpiry: Boolean, onSetExpiry: (String) -> Unit) {
    val c = LgkTheme.colors
    val header = info.header.obj().fields
    val claims = info.claims.obj().fields
    fun text(v: JsonValue?): String = (v as? JsonValue.Str)?.v?.take(200) ?: ""
    val audience = (claims["aud"] as? JsonValue.Arr)?.items?.map { text(it) } ?: listOf(text(claims["aud"]))
    val rows = listOf(
        R.string.jwt_alg to listOf(info.alg ?: "", text(header["typ"])).filter { it.isNotEmpty() }.joinToString(" · "),
        R.string.jwt_iss to text(claims["iss"]),
        R.string.jwt_sub to text(claims["sub"]),
        R.string.jwt_aud to audience.filter { it.isNotEmpty() }.take(10).joinToString(", "),
        R.string.jwt_iat to (info.issued?.let { model.tokenTime(it) } ?: ""),
        R.string.jwt_nbf to (info.notBefore?.let { model.tokenTime(it) } ?: ""),
        R.string.jwt_exp to (info.expires?.let { model.tokenTime(it) } ?: ""),
    ).filter { it.second.isNotEmpty() }
    Column(Modifier.testTag("token-section")) {
        SectionTitle(stringResource(R.string.jwt_title) + (fieldLabel?.let { " · $it" } ?: ""))
        Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface).padding(horizontal = 16.dp, vertical = 8.dp)) {
            for ((label, value) in rows) {
                Column(Modifier.padding(vertical = 6.dp)) {
                    Text(stringResource(label), color = c.secondaryText, style = MaterialTheme.typography.labelMedium)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(value, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f, fill = false))
                        if (label == R.string.jwt_exp && model.tokenExpired(info)) {
                            Spacer(Modifier.width(8.dp))
                            Text(
                                stringResource(R.string.jwt_expired), color = c.danger, style = MaterialTheme.typography.labelMedium,
                                modifier = Modifier.testTag("token-expired"),
                            )
                        }
                    }
                }
            }
            Text(
                stringResource(R.string.jwt_unchecked), color = c.secondaryText, style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(vertical = 6.dp),
            )
            val date = model.expiryDate(info)
            if (canSetExpiry && date != null) {
                OutlinedButton({ onSetExpiry(date) }, Modifier.fillMaxWidth().testTag("token-set-expiry")) {
                    Text(stringResource(R.string.jwt_setExpiry), color = c.accentText)
                }
            }
        }
    }
}

@Composable
internal fun SectionTitle(text: String) {
    Text(
        text, color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.titleSmall,
        modifier = Modifier.padding(start = 4.dp, bottom = 6.dp).semantics { heading() },
    )
}

@Composable
private fun FieldRow(field: DetailField, shown: String, revealed: Boolean, formatted: Boolean, onToggle: () -> Unit, onCopy: () -> Unit) {
    val c = LgkTheme.colors
    Row(
        Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 10.dp, bottom = 10.dp).testTag("field-${field.id}"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(field.label, color = c.secondaryText, style = MaterialTheme.typography.labelMedium)
            Spacer(Modifier.height(2.dp))
            // A note that needs Reveal is formatted only once `shown` is the real text (never the mask).
            if (formatted && shown == field.value) {
                MarkdownNote(shown, Modifier.testTag("value-${field.id}"))
            } else {
                Text(
                    shown, color = c.text,
                    style = MaterialTheme.typography.bodyLarge,
                    fontFamily = if (field.isSecret) FontFamily.Monospace else null,
                    modifier = Modifier.testTag("value-${field.id}"),
                )
            }
            if (field.id == "password") {
                StrengthMeter(GeneratorStrength.estimate(field.value), Modifier.padding(top = 6.dp))
            }
        }
        if (field.isSecret) {
            val toggleLabel = stringResource(if (revealed) R.string.common_hide else R.string.common_reveal)
            IconButton(onToggle, Modifier.semantics { contentDescription = toggleLabel }) {
                Icon(if (revealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility, null, tint = c.accentText)
            }
        }
        CopyButton(stringResource(R.string.detail_copy_field, field.label), onCopy)
    }
}

/** "Password history (n)": a row that opens the past passwords (masked; Reveal asks the owner), with Copy and Restore. */
@Composable
private fun PasswordHistorySection(
    model: PasswordHistoryModel,
    open: Boolean,
    revealed: Boolean,
    onOpen: () -> Unit,
    onReveal: () -> Unit,
    onCopy: (Int) -> Unit,
    onRestore: ((Int) -> Unit)?,
) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface).testTag("password-history")) {
        Row(
            Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Button, onClick = onOpen)
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                PasswordHistoryModel.rowLabel(model.entries.size, txt), color = c.text, style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.weight(1f),
            )
            Icon(
                if (open) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                stringResource(if (open) R.string.detail_history_hide else R.string.detail_history_show), tint = c.secondaryText,
            )
        }
        if (!open) return@Column
        if (model.canReveal) {
            TextButton(onReveal, Modifier.padding(start = 4.dp).testTag("history-reveal")) {
                Text(stringResource(if (revealed) R.string.detail_history_hide_passwords else R.string.detail_history_reveal_passwords), color = c.accentText)
            }
        }
        model.entries.forEachIndexed { i, e ->
            Box(Modifier.padding(start = 16.dp).fillMaxWidth().height(1.dp).background(c.separator))
            Row(
                Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 8.dp, bottom = 8.dp).testTag("history-$i"),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text(model.display(i), color = c.text, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge)
                    Text(PasswordHistoryModel.changedText(e.changedAt, txt), color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
                    if (onRestore != null) {
                        TextButton({ onRestore(i) }, Modifier.testTag("history-restore-$i")) {
                            Text(txt.s(PasswordHistoryModel.RESTORE), color = c.accentText)
                        }
                    }
                }
                CopyButton(stringResource(R.string.detail_copy_past_password, i + 1)) { onCopy(i) }
            }
        }
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
    val secondsLeft = pluralStringResource(R.plurals.detail_seconds_left, seconds, seconds)
    Box(
        Modifier.size(36.dp).clearAndSetSemantics { contentDescription = secondsLeft },
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

/** The item's collections as chips, and why a view-only shared item cannot be changed here (sub-plan 07). */
@Composable
private fun CollectionsSection(collections: ItemCollections) {
    val c = LgkTheme.colors
    Column(Modifier.testTag("detail-collections")) {
        SectionTitle(stringResource(R.string.collections_title))
        Column(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(c.groupSurface).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (collections.names.isNotEmpty()) {
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    for (name in collections.names) {
                        Row(
                            Modifier.clip(RoundedCornerShape(50)).background(c.innerTile).padding(horizontal = 10.dp, vertical = 5.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(Icons.Filled.Folder, null, Modifier.size(16.dp), tint = c.accentText)
                            Spacer(Modifier.width(4.dp))
                            Text(app.localgatekeys.android.collections.collectionDisplayName(name), color = c.text, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
            if (collections.readOnly) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Lock, null, Modifier.size(16.dp), tint = c.secondaryText)
                    Spacer(Modifier.width(6.dp))
                    Text(
                        stringResource(R.string.collections_read_only_item), color = c.secondaryText, style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.testTag("detail-read-only"),
                    )
                }
            }
        }
    }
}
