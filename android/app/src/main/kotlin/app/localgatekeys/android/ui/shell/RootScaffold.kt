package app.localgatekeys.android.ui.shell
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource

import app.localgatekeys.android.ui.detail.AddFileHost
import android.os.Handler
import android.os.Looper
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.TextButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.editor.EditorDraft
import app.localgatekeys.android.editor.EditorDraftText
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.editor.PasskeyRenameModel
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.generator.GeneratorDefaults
import app.localgatekeys.android.generator.GeneratorModel
import app.localgatekeys.android.generator.PassphraseWordlist
import app.localgatekeys.android.pro.ProModel
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.AvatarInitials
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.settings.Onboarding
import app.localgatekeys.android.settings.SetupStep
import app.localgatekeys.android.ui.onboarding.OnboardingScreen
import app.localgatekeys.android.sync.SyncStatusSummary
import app.localgatekeys.android.ui.sync.SyncStatusSheet
import app.localgatekeys.android.ui.vault.rememberSecondTick
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.ui.sync.FolderPicking
import app.localgatekeys.android.ui.sync.SyncScreen
import app.localgatekeys.android.ui.detail.DetailSeams
import app.localgatekeys.android.ui.detail.ItemDetailScreen
import app.localgatekeys.android.ui.editor.EditorScreen
import app.localgatekeys.android.ui.editor.EditorSeams
import app.localgatekeys.android.ui.editor.PasskeyEditScreen
import app.localgatekeys.android.ui.generator.GeneratorSheet
import app.localgatekeys.android.ui.pro.UpgradeSheet
import app.localgatekeys.android.ui.sync.QrScanner
import app.localgatekeys.android.ui.sync.QrScannerScreen
import app.localgatekeys.android.ui.vault.NewItemMenu
import app.localgatekeys.android.ui.vault.SearchScreen
import app.localgatekeys.android.ui.vault.VaultScreen
import app.localgatekeys.android.ui.vault.VaultSeams
import app.localgatekeys.android.backup.BackupText
import app.localgatekeys.android.backup.ExportFlow
import app.localgatekeys.android.backup.RestoreFlow
import app.localgatekeys.android.importing.ImportFlow
import app.localgatekeys.android.importing.ImportScreen
import app.localgatekeys.android.ui.share.ReceiveShareScreen
import app.localgatekeys.android.ui.share.ShareItemScreen
import app.localgatekeys.android.ui.share.ShareSeams
import app.localgatekeys.android.importing.rememberImportDocuments
import app.localgatekeys.android.ui.settings.BackupSeams
import app.localgatekeys.android.ui.settings.ExportBackupScreen
import app.localgatekeys.android.ui.settings.RestoreBackupScreen
import app.localgatekeys.android.ui.settings.SettingsScreen
import app.localgatekeys.android.ui.settings.SettingsSeams
import app.localgatekeys.android.ui.settings.rememberBackupDocuments
import app.localgatekeys.android.vault.NewItemGate
import app.localgatekeys.android.vault.SearchCommand
import kotlinx.coroutines.flow.Flow
import androidx.compose.runtime.mutableIntStateOf
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.VaultListModel
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGlass
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val HeaderHeight = 64.dp

/**
 * Aurora behind everything, the Vault, Search and Sync screens ([sync] null: a placeholder), the plus and avatar glass buttons
 * and the floating tab bar. The plus button opens the kind menu; choosing a kind checks the free plan's limit first and
 * opens the editor. Tapping an item opens its detail in place of the tabs (back returns, with the list where it was);
 * an item that is gone after a reload closes its detail. Edit on the detail opens the editor (or the passkey rename
 * screen) in place of the detail; a save or delete reloads the list and closes both. The editor's wand opens the
 * password generator over it, and its 2FA scan button the QR scanner. [editor] null: no editing. [folderPicker]: the Sync
 * tab's cloud-folder picker (null: no folder buttons). [pro]: the upgrade sheet, opened when a new item needs a free slot
 * (with the live item count) or a save needs Pro (the item limit or the 2FA rule; null: nothing opens).
 * [settingsSeams]: the avatar button opens Settings (null: nothing opens); [backup]: its Export and Restore pages, and
 * the empty vault's "Restore from a backup" (null: none). Settings › Sync switches to the Sync tab (Leave and Reset).
 * [confirmRollback]: the owner check before the Sync tab acknowledges a vault rollback (null: not offered).
 * [onboarding]: the setup pages over everything until finished or skipped, then the vault's "Finish setting up" card
 * and Settings › Show setup again (null: no setup).
 */
@Composable
fun RootScaffold(
    model: VaultListModel,
    settings: AppSettings,
    seams: VaultSeams,
    detail: DetailSeams,
    editor: EditorSeams? = null,
    sync: SyncCoordinator? = null,
    folderPicker: FolderPicking? = null,
    pro: ProModel? = null,
    settingsSeams: SettingsSeams? = null,
    backup: BackupSeams? = null,
    confirmRollback: (suspend () -> Boolean)? = null,
    onboarding: Onboarding? = null,
    share: ShareSeams? = null,
    searchShortcut: Flow<Unit>? = null,
) {
    val txt = rememberTxt()
    var detailId by rememberSaveable { mutableStateOf<String?>(null) }
    // The open page over the tabs: Settings, or a backup page (never anything typed: the forms live in memory only).
    var page by rememberSaveable { mutableStateOf<String?>(null) }
    var tab by rememberSaveable { mutableStateOf(RootTab.VAULT) }
    var route by rememberSaveable { mutableStateOf<String?>(null) }
    // The open upgrade sheet and the item count its capacity strip shows (null count: opened from the editor).
    var upgrade by remember { mutableStateOf<UpgradeRequest?>(null) }
    // Task 12: the "Add a file" choice (Files, Photos, Camera).
    var addFileOpen by remember { mutableStateOf(false) }
    // The open generator: where its value goes (the editor field that asked). Never saved: it holds a callback.
    var generatorFor by remember { mutableStateOf<((String) -> Unit)?>(null) }
    // The open 2FA scanner: where the scanned text goes (null text: the camera is not available).
    var scannerFor by remember { mutableStateOf<((String?) -> Unit)?>(null) }
    // Workstream 5: the generator opened from a `>` search (no editor underneath; Use copies the value).
    var generatorStandalone by remember { mutableStateOf(false) }
    // Ctrl+K: each press bumps this, and the Search tab focuses its field.
    var searchFocus by remember { mutableIntStateOf(0) }
    val mainHandler = remember { Handler(Looper.getMainLooper()) }
    val editorSeams = remember(editor) {
        editor?.withGenerate { deliver -> generatorFor = deliver }?.withScanTotp { deliver -> scannerFor = deliver }
    }
    val items by model.items.collectAsStateWithLifecycle()
    // Task 6: an unsaved editor draft from before the lock is offered once per unlock (never while an editor is open).
    var draftOffer by remember(editor) { mutableStateOf<EditorDraft?>(null) }
    // The draft being continued: the editor opens with its form (consumed when the editor's model is made).
    var restoring by remember(editor) { mutableStateOf<EditorDraft?>(null) }
    LaunchedEffect(editor) {
        val drafts = editor?.drafts
        if (drafts != null && route == null) draftOffer = withContext(Dispatchers.IO) { drafts.load() }
    }
    val scope = rememberCoroutineScope()
    // UX workstream 9: the item being shared, and a delivered package waiting for its code (opens the Receive page).
    var sharing by remember { mutableStateOf<VaultItem?>(null) }
    val incoming = share?.inbox?.pending?.collectAsStateWithLifecycle()?.value
    LaunchedEffect(incoming) { if (incoming != null && page != PAGE_RECEIVE) page = PAGE_RECEIVE }
    val open = detailId?.let { id -> items.firstOrNull { it.id == id } }
    // The list's sort is a per-phone setting.
    remember(model, settings) { model.useSettings(settings) }
    val tabs = rememberSaveableStateHolder()
    // A loaded list without the item (deleted by sync, even the last one): forget it, so it never reopens by itself.
    val kept = DetailRoute.keep(detailId, items, loaded = model.snapshot != null)
    if (kept != detailId) SideEffect { detailId = kept }
    // The store changed here: reload the list and tell sync.
    val changed: () -> Unit = {
        editor?.onLocalEdit?.invoke()
        scope.launch { withContext(Dispatchers.IO) { model.reload() } }
    }
    // A star or a row's favorite action: written like an edit, so it syncs.
    val setFavorite: suspend (VaultItem, Boolean) -> SaveResult = { item, fav ->
        val r = withContext(Dispatchers.IO) { model.setFavorite(item.id, fav, seams.clock) }
        if (r == SaveResult.SAVED) changed()
        r
    }
    // Workstream 6: the vault's sync pill and its status sheet (recomputed once a minute).
    var syncSheet by remember { mutableStateOf(false) }
    val syncSummary: SyncStatusSummary? = if (sync == null) null else {
        val membership by sync.membership.collectAsStateWithLifecycle()
        val issues by sync.issues.collectAsStateWithLifecycle()
        val last by sync.lastSyncedAt.collectAsStateWithLifecycle()
        val minute = rememberSecondTick(seams.clock) / 60
        remember(membership, issues, last, minute) { SyncStatusSummary.of(membership, issues, last, minute * 60, txt) }
    }
    val setupPagesOpen =onboarding?.pagesOpen?.collectAsStateWithLifecycle()?.value ?: false
    val setupDone = onboarding?.done?.collectAsStateWithLifecycle()?.value
    val setupHidden = onboarding?.cardHidden?.collectAsStateWithLifecycle()?.value
    val setupCardText = remember(setupPagesOpen, setupDone, setupHidden) { onboarding?.cardText() }
    val importPage: (() -> Unit)? = when {
        editor != null && backup != null -> { { page = PAGE_IMPORT } }
        settingsSeams != null -> { { page = PAGE_SETTINGS } }
        else -> null
    }
    // A setup step's action (the pages have closed): the screen that does it.
    val setupAction: (SetupStep) -> Unit = { step ->
        when (step) {
            SetupStep.IMPORT -> importPage?.invoke()
            SetupStep.APP_PASSWORD -> if (settingsSeams != null) page = PAGE_SETTINGS
            SetupStep.AUTOFILL -> settingsSeams?.let { s -> scope.launch { s.autofill.openSettings() } }
            SetupStep.CREATE, SetupStep.UNLOCK -> Unit
        }
    }
    // Workstream 5: Ctrl+K on a hardware keyboard opens the vault search (not over an open editor).
    LaunchedEffect(searchShortcut) {
        searchShortcut?.collect {
            if (route == null && generatorFor == null && scannerFor == null) {
                detailId = null
                page = null
                syncSheet = false
                tab = RootTab.SEARCH
                searchFocus++
            }
        }
    }
    // From the editor, for the item limit and the 2FA rule alike (the iPhone shows the sheet without a count there).
    val upgradeFromEditor: (Boolean) -> Unit = { if (pro != null) upgrade = UpgradeRequest(null) }
    val closeEditor: (SaveResult) -> Unit = { r ->
        route = null
        // Editing and deleting are never limited, even over the free plan's item count.
        if (r == SaveResult.SAVED) {
            detailId = null
            changed()
        }
    }
    Box(Modifier.fillMaxSize()) {
        // While the generator is open the editor stays composed underneath but out of the accessibility tree.
        val covered = generatorFor != null || scannerFor != null || upgrade != null || setupPagesOpen || syncSheet
        Box(Modifier.fillMaxSize().then(if (covered) Modifier.clearAndSetSemantics {} else Modifier)) {
            val editing = if (editor != null) route?.let { EditorRoute.parse(it) } else null
            // The item as it was when the editor opened: a sync that removes it meanwhile does not close the editor.
            val routeItem = remember(route) { (editing as? EditorRoute.ForItem)?.let { r -> items.firstOrNull { it.id == r.id } } }
            val editingItem = routeItem.takeIf { editing is EditorRoute.Edit }
            val renaming = routeItem.takeIf { editing is EditorRoute.Passkey }
            when {
                editor != null && (editing is EditorRoute.New || editingItem != null) -> {
                    val kind = (editing as? EditorRoute.New)?.kind ?: EditorKind.NOTE
                    val m = remember(route) {
                        EditorModel(editor.store, editingItem, kind, seams.isPro, seams.clock, editor.random, txt, initialValues = restoring?.values)
                    }
                    if (restoring != null) SideEffect { restoring = null }
                    EditorScreen(m, seams.clock, editorSeams ?: editor, onDone = closeEditor, onCancel = { route = null }, onUpgrade = upgradeFromEditor)
                }
                editor != null && renaming != null -> {
                    val m = remember(route) { PasskeyRenameModel(editor.store, renaming, seams.clock, txt) }
                    PasskeyEditScreen(m, onDone = closeEditor, onCancel = { route = null })
                }
                page != null && (settingsSeams != null || backup != null) -> {
                    if (route != null) SideEffect { route = null }
                    Pages(page!!, settings, settingsSeams, backup, sync, pro, scope, share = share,
                        onPage = { page = it },
                        onUpgrade = { if (pro != null) upgrade = UpgradeRequest(model.liveCount.value) },
                        onOpenSync = { page = null; tab = RootTab.SYNC },
                        onRestored = changed,
                        onShowSetup = onboarding?.let { o -> { page = null; tab = RootTab.VAULT; o.showAgain() } },
                        importer = if (editor != null) {
                            { ImportFlow({ editor.store }, seams.isPro, seams.clock, editor.random, Dispatchers.IO, txt, onChanged = changed) }
                        } else {
                            null
                        },
                    )
                }
                open != null -> {
                    // A route whose item is gone (removed by a sync before the editor opened) is dropped.
                    if (route != null) SideEffect { route = null }
                    val local = remember(detail, editor) {
                        if (editor == null) {
                            detail.copy(onSetFavorite = setFavorite)
                        } else {
                            detail.copy(
                                onEdit = { item -> route = EditorRoute.forItem(item)?.key },
                                onDelete = { item ->
                                    val r = withContext(Dispatchers.IO) { EditorModel.delete(item.id, editor.store, seams.clock) }
                                    if (r != SaveResult.FAILED) changed()
                                    r
                                },
                                onSetFavorite = setFavorite,
                                onShare = if (share != null) { item -> sharing = item } else null,
                                onRestorePassword = { item, index ->
                                    val r = withContext(Dispatchers.IO) {
                                        VaultListModel.restorePassword(editor.store, item.id, index, seams.clock)
                                    }
                                    if (r == SaveResult.SAVED) changed()
                                    r
                                },
                            )
                        }
                    }
                    ItemDetailScreen(
                        open, seams.clock, settings.concealSecretsInDetail, settings.clipboardExpiry, local,
                        onBack = { detailId = null },
                    )
                }
                else -> {
                    if (route != null) SideEffect { route = null }
                    val local = remember(seams, editor, setupCardText, syncSummary) {
                        seams.copy(
                            syncStatus = syncSummary,
                            onOpenSyncStatus = { syncSheet = true },
                            commands = SearchCommand.all.filter { cmd ->
                                when (cmd) {
                                    is SearchCommand.NewItem -> editor != null
                                    SearchCommand.GeneratePassword -> editor != null
                                    SearchCommand.ScanQr, SearchCommand.SyncNow, SearchCommand.SyncStatus -> sync != null
                                    SearchCommand.Lock, SearchCommand.Settings -> settingsSeams != null
                                    SearchCommand.Import -> editor != null && backup != null
                                    SearchCommand.ExportBackup -> backup != null && settingsSeams != null
                                    SearchCommand.RestoreBackup -> backup != null
                                    SearchCommand.ReceiveShare -> share != null
                                    SearchCommand.ShowSetup -> onboarding != null
                                }
                            },
                            onCommand = { cmd ->
                                when (cmd) {
                                    is SearchCommand.NewItem -> when (NewItemGate.decide(model.snapshot, seams.isPro())) {
                                        NewItemGate.Decision.OPEN_EDITOR -> route = EditorRoute.New(cmd.kind).key
                                        NewItemGate.Decision.UPGRADE -> if (pro != null) upgrade = UpgradeRequest(model.liveCount.value)
                                    }
                                    SearchCommand.GeneratePassword -> {
                                        generatorStandalone = true
                                        generatorFor = { value -> detail.clipboard.copy(value) }
                                    }
                                    SearchCommand.ScanQr -> tab = RootTab.SYNC
                                    SearchCommand.Lock -> settingsSeams?.lockNow?.invoke()
                                    SearchCommand.SyncNow -> sync?.let { s -> scope.launch { s.sync(SyncCoordinator.Trigger.MANUAL) } }
                                    SearchCommand.SyncStatus -> syncSheet = true
                                    SearchCommand.Settings -> page = PAGE_SETTINGS
                                    SearchCommand.Import -> page = PAGE_IMPORT
                                    SearchCommand.ExportBackup -> settingsSeams?.let { s ->
                                        scope.launch { if (s.confirmOwner()) page = PAGE_EXPORT }
                                    }
                                    SearchCommand.RestoreBackup -> page = PAGE_RESTORE_FROM_VAULT
                                    SearchCommand.ReceiveShare -> page = PAGE_RECEIVE
                                    SearchCommand.ShowSetup -> { tab = RootTab.VAULT; onboarding?.showAgain() }
                                }
                            },
                            setupCardText = setupCardText,
                            onOpenSetup = { onboarding?.showAgain() },
                            onHideSetup = { onboarding?.hideCard() },
                            onOpenItem = { detailId = it },
                            onSetFavorite = { item, fav -> setFavorite(item, fav) },
                            onNewItem = if (editor != null) { kind -> route = EditorRoute.New(kind).key } else seams.onNewItem,
                            onOpenSettings = if (settingsSeams != null) { { page = PAGE_SETTINGS } } else seams.onOpenSettings,
                            onRestoreBackup = if (backup != null) { { page = PAGE_RESTORE_FROM_VAULT } } else seams.onRestoreBackup,
                            showImportCard = { !settings.importCardDismissed },
                            onDismissImportCard = { settings.importCardDismissed = true },
                            // The import page needs the editor (it saves through EditorSeams.store) and backup seams;
                            // without them Settings is the closest place.
                            onImport = when {
                                editor != null && backup != null -> { { page = PAGE_IMPORT } }
                                settingsSeams != null -> { { page = PAGE_SETTINGS } }
                                else -> seams.onOpenSettings
                            },
                        )
                    }
                    tabs.SaveableStateProvider("tabs") {
                        Tabs(
                            model, settings, local, sync, folderPicker, tab, { tab = it },
                            onLimit = { used -> if (pro != null) upgrade = UpgradeRequest(used) }, confirmRollback,
                            onAddFile = if (detail.documents != null) { { addFileOpen = true } } else null,
                            searchFocus = searchFocus,
                        )
                    }
                }
            }
        }
        val offer = draftOffer
        if (offer != null && editor != null && model.snapshot != null) {
            val status = offer.status(items)
            AlertDialog(
                onDismissRequest = {},
                title = { Text(txt.s(EditorDraftText.TITLE)) },
                text = { Text(EditorDraftText.message(status, offer.kind, txt)) },
                confirmButton = {
                    TextButton({
                        draftOffer = null
                        restoring = offer
                        val item = items.firstOrNull { it.id == offer.itemId }
                        route = if (status == EditorDraft.Status.SAME_ITEM && item != null) {
                            EditorRoute.Edit(item.id).key
                        } else {
                            EditorRoute.New(offer.kind).key
                        }
                    }) { Text(txt.s(EditorDraftText.CONTINUE)) }
                },
                dismissButton = {
                    TextButton({ draftOffer = null; editor.drafts?.delete() }) { Text(txt.s(EditorDraftText.DISCARD)) }
                },
            )
        }
        val deliver = generatorFor
        if (deliver != null && editor != null && (route != null || generatorStandalone)) {
            // The passphrase list is read off the main thread (normally already cached by LgkApp's warm-up).
            val wordlist by produceState<List<String>?>(null) {
                value = withContext(Dispatchers.IO) { PassphraseWordlist.packaged }
            }
            val list = wordlist
            if (list != null) {
                // Over the editor, which stays composed (and keeps its draft) underneath; the value goes into the field
                // that opened it, never through the clipboard unless the person taps copy.
                val g = remember(deliver) {
                    GeneratorModel(GeneratorDefaults(settings), editor.random, detail.clipboard, list, post = { mainHandler.post(it) }, t = txt)
                }
                GeneratorSheet(g, onCancel = { generatorFor = null; generatorStandalone = false }, onUse = deliver)
            }
        } else if (deliver != null) {
            // The editor closed underneath (its item went away): the generator goes with it.
            SideEffect { generatorFor = null; generatorStandalone = false }
        }
        val scanned = scannerFor
        if (scanned != null && editor != null && route != null) {
            // Over the editor (kept composed underneath with its draft); the text goes to the 2FA field only.
            QrScannerScreen(
                txt.s(R.string.root_scan_totp), txt.s(QrScanner.TOTP_DENIED_TEXT),
                onCode = { scannerFor = null; scanned(it) },
                onUnavailable = { scannerFor = null; scanned(null) },
                onCancel = { scannerFor = null },
            )
        } else if (scanned != null) {
            SideEffect { scannerFor = null }
        }
        detail.documents?.let { docs ->
            AddFileHost(
                addFileOpen, docs, onDismiss = { addFileOpen = false },
                onNeedsPro = { if (pro != null) upgrade = UpgradeRequest(null) },
                onAdded = { id -> detailId = id },
            )
        }
        val sheet = upgrade
        if (sheet != null && pro != null) {
            // Over everything (the editor keeps its draft underneath); buying or restoring Pro closes it.
            UpgradeSheet(pro, sheet.itemsUsed, onClose = { upgrade = null })
        }
        if (syncSheet && sync != null && syncSummary != null) {
            val phase by sync.phase.collectAsStateWithLifecycle()
            SyncStatusSheet(
                syncSummary, seams.clock.now, busy = phase != SyncCoordinator.Phase.IDLE,
                onSyncNow = { scope.launch { sync.sync(SyncCoordinator.Trigger.MANUAL) } },
                onOpenSettings = { syncSheet = false; detailId = null; tab = RootTab.SYNC },
                onClose = { syncSheet = false },
            )
        } else if (syncSheet && syncSummary == null) {
            SideEffect { syncSheet = false }
        }
        val shared = sharing
        if (shared != null && share != null) {
            Overlay { ShareItemScreen(shared, share, onClose = { sharing = null }) }
        }
        if (onboarding != null && setupPagesOpen) OnboardingScreen(onboarding, setupAction)
    }
}

private const val PAGE_SETTINGS = "settings"
private const val PAGE_EXPORT = "export"
private const val PAGE_RESTORE = "restore"
/** Restore opened from the empty vault: closing it returns to the vault, not to Settings. */
private const val PAGE_RESTORE_FROM_VAULT = "restore-vault"
/** Settings › Import from a file (another password manager's export). */
private const val PAGE_IMPORT = "import"
/** Settings › Receive a shared item, or a delivered .lgkshare file. */
private const val PAGE_RECEIVE = "receive"

/**
 * Settings and its backup pages. Export first asks for a fresh unlock (the owner's fingerprint, face or screen lock);
 * each page's form lives only as long as the page. A restore that wrote something reloads the list and tells sync.
 */
@Composable
private fun Pages(
    page: String,
    settings: AppSettings,
    seams: SettingsSeams?,
    backup: BackupSeams?,
    sync: SyncCoordinator?,
    pro: ProModel?,
    scope: kotlinx.coroutines.CoroutineScope,
    onPage: (String?) -> Unit,
    onUpgrade: () -> Unit,
    onOpenSync: () -> Unit,
    onRestored: () -> Unit,
    onShowSetup: (() -> Unit)? = null,
    importer: (() -> ImportFlow)? = null,
    share: ShareSeams? = null,
) {
    val documents = if (backup != null) rememberBackupDocuments(backup.onPickerOpen, backup.onPickerClose) else null
    val back = if (seams != null) PAGE_SETTINGS else null
    when {
        page == PAGE_SETTINGS && seams != null -> SettingsScreen(
            settings, seams, sync, pro, onUpgrade,
            onExport = { if (backup != null) scope.launch { if (seams.confirmOwner()) onPage(PAGE_EXPORT) } },
            onRestore = { if (backup != null) onPage(PAGE_RESTORE) },
            onOpenSync = onOpenSync,
            onClose = { onPage(null) },
            onImport = if (importer != null && backup != null) { { onPage(PAGE_IMPORT) } } else null,
            onShowSetup = onShowSetup,
            onReceiveShare = if (share != null) { { onPage(PAGE_RECEIVE) } } else null,
        )
        page == PAGE_RECEIVE && share != null -> {
            val files = if (backup != null) rememberImportDocuments(backup.onPickerOpen, backup.onPickerClose) else null
            ReceiveShareScreen(share, files, onUpgrade = onUpgrade, onDone = { onPage(null) }, onClose = { onPage(back) })
        }
        page == PAGE_IMPORT && importer != null && backup != null -> {
            val flow = remember { importer() }
            val files = rememberImportDocuments(backup.onPickerOpen, backup.onPickerClose)
            ImportScreen(flow, files, onClose = { onPage(back) })
        }
        page == PAGE_EXPORT && backup != null && documents != null -> {
            val txt = rememberTxt()
            val flow = remember { ExportFlow({ pw -> backup.exporter().exportWithFiles(pw) }, Dispatchers.IO, txt) }
            ExportBackupScreen(flow, documents, fileName = { BackupText.fileName(backup.now()) }, onClose = { onPage(back) })
        }
        (page == PAGE_RESTORE || page == PAGE_RESTORE_FROM_VAULT) && backup != null && documents != null -> {
            val txt = rememberTxt()
            val flow = remember { RestoreFlow(backup.attempts, backup.restorer, Dispatchers.IO, txt) }
            RestoreBackupScreen(flow, documents, onRestored = onRestored, onClose = { onPage(if (page == PAGE_RESTORE) back else null) })
        }
        else -> SideEffect { onPage(null) }
    }
}

/** An open upgrade sheet: the live item count for its capacity strip, or null. */
internal data class UpgradeRequest(val itemsUsed: Int?)

/** Which item's detail stays open. */
internal object DetailRoute {
    /** [id] while the item is in [items]; null once a load ([loaded]) no longer has it. Before the first load, kept. */
    fun keep(id: String?, items: List<VaultItem>, loaded: Boolean): String? =
        if (id == null || items.any { it.id == id } || !loaded) id else null
}

/** The open editor, saved across recomposition as a short [key] (a kind or an id, never field values). */
internal sealed interface EditorRoute {
    val key: String

    data class New(val kind: EditorKind) : EditorRoute {
        override val key: String get() = "new:${kind.raw}"
    }

    sealed interface ForItem : EditorRoute {
        val id: String
    }

    data class Edit(override val id: String) : ForItem {
        override val key: String get() = "edit:$id"
    }

    data class Passkey(override val id: String) : ForItem {
        override val key: String get() = "passkey:$id"
    }

    companion object {
        fun parse(key: String): EditorRoute? {
            val tag = key.substringBefore(':')
            val rest = key.substringAfter(':', "")
            return when (tag) {
                "new" -> EditorKind.entries.firstOrNull { it.raw == rest }?.let { New(it) }
                "edit" -> rest.takeIf { it.isNotEmpty() }?.let { Edit(it) }
                "passkey" -> rest.takeIf { it.isNotEmpty() }?.let { Passkey(it) }
                else -> null
            }
        }

        /** Edit for the kinds the phone edits, the rename screen for a passkey, nothing for the rest. */
        fun forItem(item: VaultItem): EditorRoute? = when {
            EditorKind.of(item.kind) != null -> Edit(item.id)
            item.kind == "passkey" -> Passkey(item.id)
            else -> null
        }
    }
}

@Composable
private fun Tabs(
    model: VaultListModel,
    settings: AppSettings,
    seams: VaultSeams,
    sync: SyncCoordinator?,
    folderPicker: FolderPicking?,
    tab: RootTab,
    onTab: (RootTab) -> Unit,
    onLimit: (itemsUsed: Int) -> Unit,
    confirmRollback: (suspend () -> Boolean)? = null,
    onAddFile: (() -> Unit)? = null,
    searchFocus: Int = 0,
) {
    // The Sync tab's sheets (scanner, paste) cover the header and the tab bar, in this window.
    val overlay = remember { OverlayHost() }
    var menuOpen by remember { mutableStateOf(false) }
    val liveCount by model.liveCount.collectAsStateWithLifecycle()
    CompositionLocalProvider(LocalOverlayHost provides overlay) { Box(Modifier.fillMaxSize()) {
        // Under an open sheet, the tabs are out of the accessibility tree.
        Box(Modifier.fillMaxSize().then(if (overlay.content != null) Modifier.clearAndSetSemantics {} else Modifier)) {
        // What the glass controls blur: the aurora and the page. The controls themselves sit above, outside it.
        GlassBackdropHost(Modifier.fillMaxSize()) {
            AuroraBackground()
            Column(Modifier.fillMaxSize().statusBarsPadding()) {
                Spacer(Modifier.height(HeaderHeight))
                Box(Modifier.weight(1f).fillMaxWidth()) {
                    when (tab) {
                        RootTab.VAULT -> VaultScreen(model, settings.showCodesRow, seams)
                        RootTab.SEARCH -> SearchScreen(model, seams, searchFocus)
                        RootTab.SYNC -> if (sync != null) SyncScreen(sync, folderPicker, confirmRollback) else PlaceholderScreen(stringResource(R.string.root_sync_placeholder))
                    }
                }
            }
        }
        Row(
            Modifier.fillMaxWidth().statusBarsPadding().height(HeaderHeight).padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                when (tab) {
                    RootTab.VAULT -> stringResource(R.string.tab_vault)
                    RootTab.SEARCH -> stringResource(R.string.tab_search)
                    RootTab.SYNC -> stringResource(R.string.tab_sync)
                },
                color = LgkTheme.colors.text,
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Box {
                    GlassCircleButton(stringResource(R.string.root_new_item), { menuOpen = true }) { Icon(Icons.Filled.Add, null, tint = LgkTheme.colors.text) }
                    NewItemMenu(menuOpen, { menuOpen = false }, onAddFile = onAddFile?.let { add -> { menuOpen = false; add() } }) { kind ->
                        menuOpen = false
                        // Creating needs a free slot or Pro; existing items are never blocked.
                        when (NewItemGate.decide(model.snapshot, seams.isPro())) {
                            NewItemGate.Decision.OPEN_EDITOR -> seams.onNewItem(kind)
                            NewItemGate.Decision.UPGRADE -> onLimit(liveCount)
                        }
                    }
                }
                GlassCircleButton(stringResource(R.string.root_settings), seams.onOpenSettings) {
                    val initials = AvatarInitials.from(settings.initials)
                    if (initials != null) {
                        Text(initials, color = LgkTheme.colors.text, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleMedium)
                    } else {
                        Icon(Icons.Filled.Person, null, tint = LgkTheme.colors.text)
                    }
                }
            }
        }
        FloatingTabBar(
            tab, onTab,
            Modifier.align(Alignment.BottomCenter).navigationBarsPadding().padding(bottom = FloatingTabBarBottomGap),
        )
        }
        OverlayHostContent(overlay)
    } }
}

@Composable
private fun GlassCircleButton(description: String, onClick: () -> Unit = {}, content: @Composable () -> Unit) {
    Box(
        Modifier
            .size(48.dp)
            .lgkGlass(CircleShape)
            .clip(CircleShape)
            .clickable(role = Role.Button, onClick = onClick)
            .semantics { contentDescription = description },
        contentAlignment = Alignment.Center,
    ) { content() }
}

@Composable
private fun PlaceholderScreen(text: String) {
    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp, vertical = 8.dp)) {
        Column(Modifier.fillMaxWidth().lgkGroupSurface().padding(20.dp)) {
            Text(text, color = LgkTheme.colors.text, style = MaterialTheme.typography.bodyLarge)
            Spacer(Modifier.height(6.dp))
            Text(stringResource(R.string.placeholder_coming_soon), color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.bodyMedium)
        }
    }
}
