package app.localgatekeys.android.ui.shell
import app.localgatekeys.android.ui.features.proofFileName
import app.localgatekeys.android.ui.features.PasskeyDoctorDialog
import app.localgatekeys.android.ui.features.PrivacyProofDialog
import app.localgatekeys.android.ui.features.CleanUpDialog
import app.localgatekeys.android.history.PhoneProof
import app.localgatekeys.android.history.CleanUpModel
import app.localgatekeys.core.sync.TravelMode
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.android.ui.features.TravelModeDialog
import app.localgatekeys.android.ui.features.HistoryDialog
import app.localgatekeys.android.ui.features.AccessRulesDialog
import app.localgatekeys.android.access.AccessRulesModel
import app.localgatekeys.android.history.FeatureSeams
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.background
import app.localgatekeys.android.ui.vault.VaultMoreMenu
import androidx.compose.material.icons.filled.MoreHoriz
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource

import app.localgatekeys.android.security.PasskeyUpgrade
import app.localgatekeys.android.ui.detail.PasskeyUpgradeSeams
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
import androidx.activity.compose.BackHandler
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Search
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
import androidx.compose.ui.platform.testTag
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
import app.localgatekeys.android.reminders.ReminderPrefs
import app.localgatekeys.android.reminders.Reminders
import app.localgatekeys.android.security.SecurityCheckModel
import app.localgatekeys.android.security.SecurityPrefs
import app.localgatekeys.android.collections.CollectionsModel
import app.localgatekeys.android.trash.PhoneTrash
import app.localgatekeys.android.ui.collections.CollectionShareSeams
import app.localgatekeys.android.ui.collections.CollectionsScreen
import app.localgatekeys.android.ui.detail.ItemCollections
import app.localgatekeys.android.trash.UndoToast
import app.localgatekeys.android.ui.reminders.ItemReminderSection
import app.localgatekeys.android.ui.reminders.UpcomingRemindersSection
import app.localgatekeys.android.ui.security.SecurityCheckScreen
import app.localgatekeys.android.ui.settings.ReminderSettings
import app.localgatekeys.android.ui.trash.RecentlyDeletedScreen
import app.localgatekeys.android.ui.vault.tabBarClearance
import androidx.compose.ui.semantics.heading
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.settings.Onboarding
import app.localgatekeys.android.settings.SetupStep
import app.localgatekeys.android.settings.AutofillBanner
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
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
import app.localgatekeys.android.ui.settings.CxfExportScreen
import app.localgatekeys.android.ui.settings.ExportBackupScreen
import app.localgatekeys.android.backup.CxfExportFlow
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
 * Aurora behind everything, the four tabs of the iPhone (`ios/App/RootTabs.swift`): Vault, Sync ([sync] null: a
 * placeholder), Security ([security]) and Settings ([settingsSeams]), in the floating glass tab bar. The Vault tab's
 * header has the search and plus glass buttons: search opens the vault search in place of the tabs (Back or its back
 * arrow closes it, an item opened from it returns to it), plus opens the kind menu; choosing a kind checks the free
 * plan's limit first and opens the editor. Back on another tab returns to the Vault tab. Tapping an item opens its detail in place of the tabs (back returns, with the list where it was);
 * an item that is gone after a reload closes its detail. Edit on the detail opens the editor (or the passkey rename
 * screen) in place of the detail; a save or delete reloads the list and closes both. The editor's wand opens the
 * password generator over it, and its 2FA scan button the QR scanner. [editor] null: no editing. [folderPicker]: the Sync
 * tab's cloud-folder picker (null: no folder buttons). [pro]: the upgrade sheet, opened when a new item needs a free slot
 * (with the live item count) or a save needs Pro (the item limit or the 2FA rule; null: nothing opens).
 * [settingsSeams]: the Settings tab (null: an empty tab); [backup]: its Export and Restore pages, and the empty vault's
 * "Restore from a backup" (null: none). Settings › Sync switches to the Sync tab (Leave and Reset); "open Import" (the
 * empty vault's card, setup, `>`) switches to the Settings tab with the Import page over it.
 * [confirmRollback]: the owner check before the Sync tab acknowledges a vault rollback (null: not offered).
 * [onboarding]: the setup pages over everything until finished or skipped, then the vault's "Finish setting up" card
 * and Settings › Show setup again (null: no setup).
 * [security] / [securityPrefs]: the Security tab and Settings › Breach checks; [reminders] / [reminderPrefs]: the item's
 * Reminder section, the Security tab's Upcoming list and Settings › Reminders; Recently deleted and its Undo toast come
 * through [editor] (`EditorSeams.trash` / `undo`). [openItemRequests]: item ids to open (a reminder notification's tap).
 * [showCodesRequests]: the Quick Settings tile's long press, which shows the Vault tab (its Codes row).
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
    security: SecurityCheckModel? = null,
    securityPrefs: SecurityPrefs? = null,
    reminders: Reminders? = null,
    reminderPrefs: ReminderPrefs? = null,
    openItemRequests: Flow<String>? = null,
    showCodesRequests: Flow<Unit>? = null,
    sharePicker: FolderPicking? = null,
    shareFolderName: (String) -> String? = { null },
    confirmShare: (suspend () -> Boolean)? = null,
    /** Feature pack 2026-11-15 (history, travel mode, clean up, privacy proof); null: none of their rows. */
    featurePack: FeatureSeams? = null,
) {
    val txt = rememberTxt()
    // Feature pack 2026-11-15 dialogs (never saved: they hold the open item).
    var accessFor by remember { mutableStateOf<VaultItem?>(null) }
    var historyFor by remember { mutableStateOf<VaultItem?>(null) }
    var featureDialog by remember { mutableStateOf<String?>(null) }
    var detailId by rememberSaveable { mutableStateOf<String?>(null) }
    // The open page over the tabs: a backup, import, share or Recently deleted page (never anything typed: the forms
    // live in memory only).
    var page by rememberSaveable { mutableStateOf<String?>(null) }
    var tab by rememberSaveable { mutableStateOf(RootTab.VAULT) }
    // The vault search, pushed from the Vault tab (the iPhone's search route).
    var searching by rememberSaveable { mutableStateOf(false) }
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
    // Each opening of the search (and Ctrl+K) bumps this, and the search focuses its field.
    var searchFocus by remember { mutableIntStateOf(0) }
    val mainHandler = remember { Handler(Looper.getMainLooper()) }
    val editorSeams = remember(editor) {
        editor?.withGenerate { deliver -> generatorFor = deliver }?.withScanTotp { deliver -> scannerFor = deliver }
    }
    val items by model.items.collectAsStateWithLifecycle()
    // Sub-plan 07: Vault › Collections (over the store the editor writes, with Recently deleted's local data).
    val collectionsModel = remember(editor) { editor?.let { e -> CollectionsModel(e.store, e.trash?.local, seams.clock, txt) } }
    // Feature pack: travel mode hides collections (and does not count hidden items) on the Collections page.
    SideEffect { collectionsModel?.travel = { featurePack?.travel ?: TravelMode.Setting.OFF } }
    // Sub-plan 07 Task 5m: share a collection or join a shared one (Pro; the owner check before a share).
    val collectionShare = remember(sync, sharePicker, confirmShare) {
        if (sync == null || confirmShare == null) {
            null
        } else {
            CollectionShareSeams(sync, sharePicker, shareFolderName, confirmShare, onUpgrade = { if (pro != null) upgrade = UpgradeRequest(null) })
        }
    }
    // Task 6: an unsaved editor draft from before the lock is offered once per unlock (never while an editor is open).
    var draftOffer by remember(editor) { mutableStateOf<EditorDraft?>(null) }
    // The draft being continued: the editor opens with its form (consumed when the editor's model is made).
    var restoring by remember(editor) { mutableStateOf<EditorDraft?>(null) }
    // Review 2026-11-15 bugs 1-2: an editor route restored after the activity was recreated (dark mode, language, font
    // or display size) or the process was killed reopens with the draft its ON_STOP wrote. The editor waits for that
    // read ([routeDraftChecked]) so its model is built once, with the typed form.
    var routeDraft by remember(editor) { mutableStateOf<EditorDraft?>(null) }
    var routeDraftChecked by remember(editor) { mutableStateOf(route == null || editor?.drafts == null) }
    LaunchedEffect(editor) {
        val drafts = editor?.drafts ?: return@LaunchedEffect
        val restored = route != null
        val loaded = withContext(Dispatchers.IO) { drafts.load() }
        if (restored) routeDraft = loaded else if (route == null) draftOffer = loaded
        routeDraftChecked = true
    }
    // A restored route that could not reopen (its item is gone): its draft is offered as after a lock.
    LaunchedEffect(route, routeDraft) {
        val d = routeDraft
        if (route == null && d != null) {
            draftOffer = d
            routeDraft = null
        }
    }
    val scope = rememberCoroutineScope()
    // UX workstream 9: the item being shared, and a delivered package waiting for its code (opens the Receive page).
    var sharing by remember { mutableStateOf<VaultItem?>(null) }
    val incoming = share?.inbox?.pending?.collectAsStateWithLifecycle()?.value
    LaunchedEffect(incoming) { if (incoming != null && page != PAGE_RECEIVE) page = PAGE_RECEIVE }
    val refusedShare = share?.inbox?.refused?.collectAsStateWithLifecycle()?.value
    LaunchedEffect(refusedShare) { if (refusedShare != null && page != PAGE_RECEIVE) page = PAGE_RECEIVE }
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
        // In a collection shared with this vault as view only (sub-plan 07): refused, and said so.
        if (r == SaveResult.INVALID) detail.toast.show(txt.s(R.string.collections_read_only_item))
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
    // Review 2026-11-15 UX 3: the autofill service status, checked now and each time the app comes back (the system
    // picker returns here). On completes the setup step; off shows the Vault list's banner until its Not now.
    val autofillStatus = settingsSeams?.autofill
    val autofillOn = autofillStatus?.enabled?.collectAsStateWithLifecycle()?.value
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner, autofillStatus) {
        val observer = LifecycleEventObserver { _, e ->
            if (e == Lifecycle.Event.ON_RESUME && autofillStatus != null) scope.launch { autofillStatus.refresh() }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    LaunchedEffect(autofillOn, onboarding) { onboarding?.autofillStatus(autofillOn) }
    var autofillBannerDismissed by remember(settings) { mutableStateOf(settings.autofillBannerDismissed) }
    val autofillBanner = autofillStatus != null && AutofillBanner.shows(autofillOn, autofillBannerDismissed, setupPagesOpen)
    // A Settings page shown over the Settings tab (closing it lands there), as the iPhone pushes them in that tab.
    val openSettingsPage: (String) -> Unit = { p ->
        searching = false
        detailId = null
        tab = RootTab.SETTINGS
        page = p
    }
    // "Open Import" (the empty vault's card, setup, `>`): the Settings tab with Import over it (just the tab when the
    // page cannot open here).
    val openImport: () -> Unit = {
        if (editor != null && backup != null) openSettingsPage(PAGE_IMPORT) else { searching = false; detailId = null; tab = RootTab.SETTINGS }
    }
    // A setup step's action (the pages have closed): the screen that does it.
    val setupAction: (SetupStep) -> Unit = { step ->
        when (step) {
            SetupStep.IMPORT -> openImport()
            SetupStep.APP_PASSWORD -> { searching = false; detailId = null; tab = RootTab.SETTINGS }
            SetupStep.AUTOFILL -> settingsSeams?.let { s -> scope.launch { s.autofill.openSettings() } }
            SetupStep.CREATE, SetupStep.UNLOCK -> Unit
        }
    }
    val openSearch: (String?) -> Unit = { prefill ->
        detailId = null
        page = null
        syncSheet = false
        tab = RootTab.VAULT
        if (prefill != null) model.query.value = prefill
        searching = true
        searchFocus++
    }
    // Closing the search keeps an item search as a recent search and empties the field (the iPhone's onDisappear).
    val closeSearch: () -> Unit = {
        if (!SearchCommand.isCommandQuery(model.query.value)) model.noteSearch()
        model.query.value = ""
        searching = false
    }
    // Workstream 5: Ctrl+K on a hardware keyboard opens the vault search listing the actions (not over an open editor).
    LaunchedEffect(searchShortcut) {
        searchShortcut?.collect {
            if (route == null && generatorFor == null && scannerFor == null) openSearch("> ")
        }
    }
    // The Quick Settings tile's long press (after the unlock): the Vault tab with its Codes row, nothing over it.
    LaunchedEffect(showCodesRequests) {
        showCodesRequests?.collect {
            page = null
            searching = false
            syncSheet = false
            detailId = null
            tab = RootTab.VAULT
        }
    }
    // A reminder notification's tap (after the unlock): that item's detail, over whatever tab is open.
    LaunchedEffect(openItemRequests) {
        openItemRequests?.collect { id ->
            page = null
            searching = false
            syncSheet = false
            detailId = id
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
    val vaultSeams = remember(seams, detail, editor, sync, pro, setupCardText, syncSummary, settingsSeams, backup, share, onboarding, security, autofillBanner) {
        seams.copy(
            autofillBanner = autofillBanner,
            onTurnOnAutofill = { autofillStatus?.let { s -> scope.launch { s.openSettings() } } },
            onDismissAutofillBanner = { settings.autofillBannerDismissed = true; autofillBannerDismissed = true },
            syncStatus = syncSummary,
            onOpenSyncStatus = { syncSheet = true },
            commands = SearchCommand.all.filter { cmd ->
                when (cmd) {
                    is SearchCommand.NewItem -> editor != null
                    SearchCommand.GeneratePassword -> editor != null
                    SearchCommand.ScanQr, SearchCommand.SyncNow, SearchCommand.SyncStatus, SearchCommand.SyncSettings -> sync != null
                    SearchCommand.Lock, SearchCommand.Settings, SearchCommand.AutofillSettings -> settingsSeams != null
                    SearchCommand.SecurityCheck -> security != null
                    SearchCommand.RecentlyDeleted -> editor?.trash != null
                    SearchCommand.Import -> editor != null && backup != null
                    SearchCommand.ExportBackup -> backup != null && settingsSeams != null
                    SearchCommand.RestoreBackup -> backup != null
                    SearchCommand.ReceiveShare -> share != null
                    SearchCommand.ShowSetup -> onboarding != null
                }
            },
            onCommand = { cmd ->
                // The search closes, then the action runs (the iPhone's order).
                searching = false
                when (cmd) {
                    is SearchCommand.NewItem -> when (NewItemGate.decide(model.snapshot, seams.isPro())) {
                        NewItemGate.Decision.OPEN_EDITOR -> route = EditorRoute.New(cmd.kind).key
                        NewItemGate.Decision.UPGRADE -> if (pro != null) upgrade = UpgradeRequest(model.liveCount.value)
                    }
                    SearchCommand.GeneratePassword -> {
                        generatorStandalone = true
                        generatorFor = { value -> detail.clipboard.copy(value) }
                    }
                    SearchCommand.ScanQr, SearchCommand.SyncSettings -> tab = RootTab.SYNC
                    SearchCommand.Lock -> settingsSeams?.lockNow?.invoke()
                    SearchCommand.SyncNow -> sync?.let { s -> scope.launch { s.sync(SyncCoordinator.Trigger.MANUAL) } }
                    SearchCommand.SyncStatus -> syncSheet = true
                    SearchCommand.SecurityCheck -> tab = RootTab.SECURITY
                    SearchCommand.RecentlyDeleted -> page = PAGE_TRASH
                    SearchCommand.Settings -> tab = RootTab.SETTINGS
                    SearchCommand.Import -> openImport()
                    SearchCommand.ExportBackup -> settingsSeams?.let { s ->
                        scope.launch { if (s.confirmOwner()) openSettingsPage(PAGE_EXPORT) }
                    }
                    SearchCommand.RestoreBackup -> openSettingsPage(PAGE_RESTORE)
                    SearchCommand.ReceiveShare -> openSettingsPage(PAGE_RECEIVE)
                    SearchCommand.AutofillSettings -> settingsSeams?.let { s -> scope.launch { s.autofill.openSettings() } }
                    SearchCommand.ShowSetup -> { tab = RootTab.VAULT; onboarding?.showAgain() }
                }
            },
            setupCardText = setupCardText,
            onOpenSetup = { onboarding?.showAgain() },
            onHideSetup = { onboarding?.hideCard() },
            onOpenItem = { detailId = it },
            onSetFavorite = { item, fav -> setFavorite(item, fav) },
            onNewItem = if (editor != null) { kind -> route = EditorRoute.New(kind).key } else seams.onNewItem,
            onOpenSettings = if (settingsSeams != null) { { tab = RootTab.SETTINGS } } else seams.onOpenSettings,
            onRestoreBackup = if (backup != null) { { page = PAGE_RESTORE } } else seams.onRestoreBackup,
            showImportCard = { !settings.importCardDismissed },
            onDismissImportCard = { settings.importCardDismissed = true },
            // The import page needs the editor (it saves through EditorSeams.store) and backup seams; without them
            // the Settings tab is the closest place.
            onImport = if (editor != null || backup != null || settingsSeams != null) openImport else seams.onOpenSettings,
            onOpenCollections = if (collectionsModel != null) { { page = PAGE_COLLECTIONS } } else seams.onOpenCollections,
        )
    }
    Box(Modifier.fillMaxSize()) {
        // While the generator is open the editor stays composed underneath but out of the accessibility tree.
        val covered = generatorFor != null || scannerFor != null || upgrade != null || setupPagesOpen || syncSheet
        Box(Modifier.fillMaxSize().then(if (covered) Modifier.clearAndSetSemantics {} else Modifier)) {
            val editing = if (editor != null) route?.let { EditorRoute.parse(it) } else null
            // The item as it was when the editor opened: a sync that removes it meanwhile does not close the editor.
            // Read again once the list has loaded: an editor route restored after the process was killed comes back
            // before the items do.
            val listLoaded = model.snapshot != null
            val routeItem = remember(route, listLoaded) { (editing as? EditorRoute.ForItem)?.let { r -> items.firstOrNull { it.id == r.id } } }
            val editingItem = routeItem.takeIf { editing is EditorRoute.Edit }
            val renaming = routeItem.takeIf { editing is EditorRoute.Passkey }
            when {
                // A restored item route waits for the list instead of being dropped as "item gone".
                editor != null && editing is EditorRoute.ForItem && routeItem == null && !listLoaded -> Unit
                editor != null && (editing is EditorRoute.New || editingItem != null) && !routeDraftChecked -> Unit // the draft read is quick
                editor != null && (editing is EditorRoute.New || editingItem != null) -> {
                    val newKind = (editing as? EditorRoute.New)?.kind
                    val kind = newKind ?: EditorKind.NOTE
                    val resumed = routeDraft?.takeIf { it.resumes(newKind, editingItem) }
                    val m = remember(route) {
                        EditorModel(
                            editor.store, editingItem, kind, seams.isPro, seams.clock, editor.random, txt,
                            initialValues = restoring?.values ?: resumed?.values,
                        )
                    }
                    if (restoring != null || routeDraft != null) {
                        SideEffect {
                            // A draft that is not this editor's (another item, or the item changed meanwhile) is offered.
                            if (routeDraft != null && resumed == null && restoring == null) draftOffer = routeDraft
                            restoring = null
                            routeDraft = null
                        }
                    }
                    EditorScreen(m, seams.clock, editorSeams ?: editor, onDone = closeEditor, onCancel = { route = null }, onUpgrade = upgradeFromEditor)
                }
                editor != null && renaming != null -> {
                    val m = remember(route) { PasskeyRenameModel(editor.store, renaming, seams.clock, txt) }
                    PasskeyEditScreen(m, onDone = closeEditor, onCancel = { route = null }, trash = editor.trash, undo = editor.undo)
                }
                page != null -> {
                    if (route != null) SideEffect { route = null }
                    Pages(page!!, backup, pro, share = share, trash = editor?.trash, undo = editor?.undo, collections = collectionsModel,
                        collectionShare = collectionShare,
                        onPage = { page = it },
                        onUpgrade = { if (pro != null) upgrade = UpgradeRequest(model.liveCount.value) },
                        onRestored = changed,
                        importer = if (editor != null) {
                            { ImportFlow({ editor.store }, seams.isPro, seams.clock, editor.random, Dispatchers.IO, txt, onChanged = changed, local = featurePack?.local, trash = editor.trash) }
                        } else {
                            null
                        },
                        cxfExporter = if (editor != null && settingsSeams != null) {
                            {
                                val reason = txt.s(R.string.cxf_export_reason)
                                CxfExportFlow(
                                    { editor.store }, { settingsSeams.confirmOwnerFor(reason) }, seams.clock, editor.random, Dispatchers.IO, txt,
                                    hidden = { featurePack?.let { fp -> TravelMode.hiddenIds(editor.store.load(), fp.travel) } ?: emptySet() },
                                )
                            }
                        } else {
                            null
                        },
                    )
                }
                open != null -> {
                    // A route whose item is gone (removed by a sync before the editor opened) is dropped.
                    if (route != null) SideEffect { route = null }
                    val siteFeaturesApp = androidx.compose.ui.platform.LocalContext.current.applicationContext as? app.localgatekeys.android.LgkApp
                    val local = remember(detail, editor, reminders, featurePack) {
                        val below: (@Composable (VaultItem) -> Unit)? = reminders?.let { r -> { item -> ItemReminderSection(r, item) } }
                        val pins = detail.pins?.withUpgrade { if (pro != null) upgrade = UpgradeRequest(null) }
                        if (editor == null) {
                            detail.copy(onSetFavorite = setFavorite, below = below, pins = pins)
                        } else {
                            detail.copy(
                                collections = { item ->
                                    withContext(Dispatchers.IO) {
                                        try { ItemCollections.of(item.id, editor.store.load()) } catch (e: Exception) { ItemCollections.NONE }
                                    }
                                },
                                pins = pins,
                                onEdit = { item -> route = EditorRoute.forItem(item)?.key },
                                onDelete = { item ->
                                    // Through Recently deleted when this phone has it; the Undo toast offers it back.
                                    val r = withContext(Dispatchers.IO) { PhoneTrash.deleteItem(item.id, editor.store, seams.clock, editor.trash) }
                                    if (r == SaveResult.SAVED) editor.offerUndo()
                                    // INVALID (view only): the detail's dialog says why; nothing changed.
                                    if (r != SaveResult.FAILED && r != SaveResult.INVALID) changed()
                                    r
                                },
                                onSetFavorite = setFavorite,
                                onSetExpiry = { item, date ->
                                    // The editor's own save, so the change is normalised, stamped and synced like an edit.
                                    val r = withContext(Dispatchers.IO) {
                                        EditorModel(editor.store, item, EditorKind.API_KEY, seams.isPro, seams.clock, editor.random, txt)
                                            .apply { set("expires", date) }.save()
                                    }
                                    if (r == SaveResult.SAVED) changed()
                                    r
                                },
                                onShare = if (share != null) { item -> sharing = item } else null,
                                below = below,
                                onAccess = { item -> accessFor = item },
                                onHistory = if (featurePack != null) { item -> historyFor = item } else null,
                                passkeyUpgrade = featurePack?.takeIf { siteFeaturesApp != null }?.let { fp ->
                                    PasskeyUpgradeSeams(
                                        domainFor = { item ->
                                            withContext(Dispatchers.IO) {
                                                PasskeyUpgrade.domain(item, VaultItem.items(editor.store.load()), siteFeaturesApp!!.siteFeatures)?.takeIf { d ->
                                                    PasskeyUpgrade.shows(d, fp.local.localData?.passkeyUpgradeDismissed ?: emptyMap(), seams.clock.now)
                                                }
                                            }
                                        },
                                        dismiss = { domain ->
                                            withContext(Dispatchers.IO) {
                                                synchronized(fp.local) {
                                                    fp.local.localData?.let { fp.local.commitLocalData(it.withPasskeyDismissed(domain, seams.clock.now)) }
                                                }
                                            }
                                        },
                                    )
                                },
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
                        onBack = { detailId = null }, showFormatting = settings.notesShowFormatting,
                        onShowFormattingChange = { settings.notesShowFormatting = it },
                    )
                }
                searching -> {
                    if (route != null) SideEffect { route = null }
                    VaultSearchPage(model, vaultSeams, searchFocus, onBack = closeSearch)
                }
                else -> {
                    if (route != null) SideEffect { route = null }
                    tabs.SaveableStateProvider("tabs") {
                        Tabs(
                            model, settings, vaultSeams, sync, folderPicker, tab, { tab = it },
                            onLimit = { used -> if (pro != null) upgrade = UpgradeRequest(used) }, confirmRollback,
                            onAddFile = if (detail.documents != null) { { addFileOpen = true } } else null,
                            onSearch = { openSearch(null) },
                            security = {
                                if (security != null) {
                                    SecurityCheckScreen(
                                        security,
                                        onOpenItem = { detailId = it.id },
                                        onChangePassword = { item ->
                                            // The iPhone's Change password: the site, and the editor to save the new one.
                                            item.openableUrl?.let { url -> settingsSeams?.openUrl?.invoke(url) }
                                            if (editor != null) EditorRoute.forItem(item)?.let { route = it.key }
                                        },
                                        below = {
                                            reminders?.let { r -> UpcomingRemindersSection(r) }
                                            app.localgatekeys.android.ui.security.BackupChecksSection(
                                                appPassword = settingsSeams?.appPassword,
                                                factors = settingsSeams?.factors,
                                                onPickerOpen = backup?.onPickerOpen ?: {},
                                                onPickerClose = backup?.onPickerClose ?: { true },
                                            )
                                        },
                                    )
                                }
                            },
                            settingsTab = {
                                if (settingsSeams != null) {
                                    SettingsScreen(
                                        settings, settingsSeams, sync, pro,
                                        onUpgrade = { if (pro != null) upgrade = UpgradeRequest(model.liveCount.value) },
                                        onExport = { if (backup != null) scope.launch { if (settingsSeams.confirmOwner()) page = PAGE_EXPORT } },
                                        onRestore = { if (backup != null) page = PAGE_RESTORE },
                                        onOpenSync = { tab = RootTab.SYNC },
                                        onImport = if (editor != null && backup != null) { { page = PAGE_IMPORT } } else null,
                                        onExportCxf = if (editor != null && backup != null) { { page = PAGE_EXPORT_CXF } } else null,
                                        onReceiveShare = if (share != null) { { page = PAGE_RECEIVE } } else null,
                                        onShowSetup = onboarding?.let { o -> { tab = RootTab.VAULT; o.showAgain() } },
                                        security = securityPrefs,
                                        reminders = reminderPrefs?.let { ReminderSettings(it, reminders) },
                                        onRecentlyDeleted = editor?.trash?.let { { page = PAGE_TRASH } },
                                        onGenerate = if (editor != null) {
                                            {
                                                generatorStandalone = true
                                                generatorFor = { value -> detail.clipboard.copy(value) }
                                            }
                                        } else null,
                                        generatorOpen = generatorFor != null,
                                        featureRows = featureRows(featurePack, txt) { featureDialog = it },
                                        bottomPadding = tabBarClearance(),
                                    )
                                }
                            },
                        )
                    }
                }
            }
        }
        accessFor?.let { item ->
            if (editor != null) {
                AccessRulesDialog(
                    item,
                    save = { form ->
                        // Loosening or removing a rule asks the owner first (scan A-M2); a cancelled check saves nothing.
                        val needs = withContext(Dispatchers.IO) { AccessRulesModel.needsOwner(editor.store, item.id, form) }
                        val ok = !needs || settingsSeams?.confirmOwnerFor?.invoke(txt.s(R.string.access_loosen_confirm)) == true
                        if (!ok) SaveResult.FAILED
                        else withContext(Dispatchers.IO) { AccessRulesModel.save(editor.store, item.id, form, seams.isPro(), seams.clock, ownerConfirmed = needs) }
                    },
                    onNeedsPro = { if (pro != null) upgrade = UpgradeRequest(null) },
                    onDone = { saved -> accessFor = null; if (saved) changed() },
                )
            }
        }
        historyFor?.let { item ->
            val fp = featurePack
            if (fp != null && editor != null) {
                val rows = remember(item) { fp.history.rows(item.id) }
                HistoryDialog(
                    item, rows,
                    restore = { row, path ->
                        // A restore that loosens an access rule asks the owner first (scan A-M2).
                        val needs = withContext(Dispatchers.IO) { FeatureSeams.restoreLoosens(editor.store, item.id, row, path, seams.clock) }
                        val ok = !needs || settingsSeams?.confirmOwnerFor?.invoke(txt.s(R.string.access_loosen_confirm)) == true
                        if (!ok) SaveResult.FAILED
                        else withContext(Dispatchers.IO) { FeatureSeams.restoreField(editor.store, item.id, row, path, seams.clock, ownerConfirmed = needs) }
                    },
                    onDone = { saved -> historyFor = null; if (saved) changed() },
                )
            }
        }
        // One clean-up model per unlock (this screen lives while the vault is open): the Undo of the last bulk action
        // stays until the vault locks or the next bulk action, not only while the dialog is open (scan A-L10).
        val cleanUpContext = androidx.compose.ui.platform.LocalContext.current
        val featurePackNow by androidx.compose.runtime.rememberUpdatedState(featurePack)
        val cleanUpModel = remember(editor) {
            editor?.let { e ->
                val app = cleanUpContext.applicationContext as app.localgatekeys.android.LgkApp
                CleanUpModel(e.store, e.trash, seams.clock, seams.isPro, app.urlMatcher::baseDomainOf) { featurePackNow?.travel ?: TravelMode.Setting.OFF }
            }
        }
        val cleanUp = cleanUpModel
        if (featureDialog == FEATURE_CLEAN_UP && cleanUp != null) {
            CleanUpDialog(
                cleanUp, title = { id -> items.firstOrNull { it.id == id }?.let { it.title.ifEmpty { it.username } } ?: id },
                onNeedsPro = { if (pro != null) upgrade = UpgradeRequest(null) }, onChanged = changed, onDone = { featureDialog = null },
            )
        }
        if (featureDialog == FEATURE_PROOF && editor != null) {
            val context = androidx.compose.ui.platform.LocalContext.current
            PrivacyProofDialog(
                make = {
                    val snap = editor.store.load()
                    PhoneProof.build(
                        snap, app.localgatekeys.android.BuildConfig.VERSION_NAME, securityPrefs?.breachCheckEnabled == true, securityPrefs?.strictOfflineMode == true,
                        travel = featurePack?.travel ?: TravelMode.Setting.OFF,
                    ) to
                        PhoneProof.fingerprint(snap)
                },
                fileName = proofFileName(java.time.LocalDate.now().toString()),
                onPickerOpen = backup?.onPickerOpen ?: {}, onPickerClose = { backup?.onPickerClose?.invoke() },
                onDone = { featureDialog = null },
            )
        }
        if (featureDialog == FEATURE_DOCTOR) PasskeyDoctorDialog(
            onPickerOpen = { featurePack?.willOpenSystemScreen?.invoke() },
            onPickerFailed = { featurePack?.systemScreenClosed?.invoke() },
            onDone = { featureDialog = null },
        )
        if (featureDialog == FEATURE_TRAVEL) {
            featurePack?.let { fp ->
                val snap = model.snapshot
                val cols = remember(snap) { snap?.let { CollectionCatalog.collections(it) } ?: emptyList() }
                val tags = remember(snap) {
                    snap?.let { s -> VaultItem.items(s).flatMap { it.tags }.distinctBy { TravelMode.fold(it) }.filter { TravelMode.fold(it).isNotEmpty() }.sortedBy { TravelMode.fold(it) } } ?: emptyList()
                }
                TravelModeDialog(fp, cols, tags, now = { seams.clock.now }, onNeedsPro = { if (pro != null) upgrade = UpgradeRequest(null) }, onDone = { featureDialog = null })
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

private const val PAGE_EXPORT = "export"
/** Restore from a backup: Settings, or the empty vault (closing it returns to the tab it came from). */
private const val PAGE_RESTORE = "restore"
/** Settings › Import from a file (another password manager's export). */
private const val PAGE_IMPORT = "import"
/** Settings › Export to a CXF file (the owner check comes with Export, once the items are chosen). */
private const val PAGE_EXPORT_CXF = "export-cxf"
/** Settings › Receive a shared item, or a delivered .lgkshare file. */
private const val PAGE_RECEIVE = "receive"
/** Settings › Recently deleted, or its `>` action. */
private const val PAGE_TRASH = "trash"
/** Vault › Collections (the Collections filter's "Manage collections"). */
private const val PAGE_COLLECTIONS = "collections"

/**
 * The pages over the tabs: Export, Restore, Import, Receive a shared item and Recently deleted. Export first asks for a
 * fresh unlock (the owner's fingerprint, face or screen lock); each page's form lives only as long as the page. A
 * restore that wrote something reloads the list and tells sync. Closing a page returns to the tab under it.
 */
@Composable
private fun Pages(
    page: String,
    backup: BackupSeams?,
    pro: ProModel?,
    onPage: (String?) -> Unit,
    onUpgrade: () -> Unit,
    onRestored: () -> Unit,
    importer: (() -> ImportFlow)? = null,
    cxfExporter: (() -> CxfExportFlow)? = null,
    share: ShareSeams? = null,
    trash: PhoneTrash? = null,
    undo: UndoToast? = null,
    collections: CollectionsModel? = null,
    collectionShare: CollectionShareSeams? = null,
) {
    val documents = if (backup != null) rememberBackupDocuments(backup.onPickerOpen, backup.onPickerClose) else null
    when {
        page == PAGE_RECEIVE && share != null -> {
            val files = if (backup != null) rememberImportDocuments(backup.onPickerOpen, backup.onPickerClose) else null
            ReceiveShareScreen(share, files, onUpgrade = onUpgrade, onDone = { onPage(null) }, onClose = { onPage(null) })
        }
        page == PAGE_IMPORT && importer != null && backup != null -> {
            val flow = remember { importer() }
            val files = rememberImportDocuments(backup.onPickerOpen, backup.onPickerClose)
            ImportScreen(flow, files, onClose = { onPage(null) })
        }
        page == PAGE_EXPORT && backup != null && documents != null -> {
            val txt = rememberTxt()
            val flow = remember { ExportFlow({ pw -> backup.exporter().exportWithFiles(pw) }, Dispatchers.IO, txt) }
            ExportBackupScreen(flow, documents, fileName = { BackupText.fileName(backup.now()) }, onClose = { onPage(null) })
        }
        page == PAGE_EXPORT_CXF && cxfExporter != null && backup != null && documents != null -> {
            val flow = remember { cxfExporter() }
            CxfExportScreen(flow, documents, fileName = { CxfExportFlow.fileName(backup.now()) }, onClose = { onPage(null) })
        }
        page == PAGE_RESTORE && backup != null && documents != null -> {
            val txt = rememberTxt()
            val flow = remember { RestoreFlow(backup.attempts, backup.restorer, Dispatchers.IO, txt) }
            RestoreBackupScreen(flow, documents, onRestored = onRestored, onClose = { onPage(null) })
        }
        page == PAGE_COLLECTIONS && collections != null -> CollectionsScreen(collections, onChange = onRestored, onBack = { onPage(null) }, share = collectionShare)
        page == PAGE_TRASH && trash != null -> RecentlyDeletedScreen(
            trash, isPro = { pro?.isPro == true }, onUpgrade = onUpgrade, onRestored = trash.onRestored, toast = undo,
            onBack = { onPage(null) },
        )
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
    onSearch: () -> Unit = {},
    security: @Composable () -> Unit = {},
    settingsTab: @Composable () -> Unit = {},
) {
    // The Sync tab's sheets (scanner, paste) and Settings' own pages cover the header and the tab bar, in this window.
    val overlay = remember { OverlayHost() }
    var menuOpen by remember { mutableStateOf(false) }
    var moreOpen by remember { mutableStateOf(false) }
    val newItemLabel = stringResource(R.string.root_new_item)
    val liveCount by model.liveCount.collectAsStateWithLifecycle()
    // Back on another tab returns to the Vault tab (a screen's own Back, registered later, comes first).
    BackHandler(enabled = tab != RootTab.VAULT) { onTab(RootTab.VAULT) }
    CompositionLocalProvider(LocalOverlayHost provides overlay) { Box(Modifier.fillMaxSize()) {
        // Under an open sheet, the tabs are out of the accessibility tree.
        Box(Modifier.fillMaxSize().then(if (overlay.content != null) Modifier.clearAndSetSemantics {} else Modifier)) {
        // What the glass controls blur: the aurora and the page. The controls themselves sit above, outside it.
        GlassBackdropHost(Modifier.fillMaxSize()) {
            AuroraBackground()
            if (tab == RootTab.SECURITY) {
                // The Security check draws its own title (and a back arrow inside a check's list: inside the host's content
                // there is no backdrop, so that glass draws its solid fill).
                Box(Modifier.fillMaxSize()) { security() }
            } else {
                Column(Modifier.fillMaxSize().statusBarsPadding()) {
                    Spacer(Modifier.height(HeaderHeight))
                    Box(Modifier.weight(1f).fillMaxWidth()) {
                        when (tab) {
                            RootTab.VAULT -> VaultScreen(model, settings.showCodesRow, seams.copy(onSearch = onSearch))
                            RootTab.SYNC -> if (sync != null) SyncScreen(sync, folderPicker, confirmRollback) else PlaceholderScreen(stringResource(R.string.root_sync_placeholder))
                            RootTab.SETTINGS -> settingsTab()
                            RootTab.SECURITY -> Unit
                        }
                    }
                }
            }
        }
        if (tab != RootTab.SECURITY) {
            Row(
                Modifier.fillMaxWidth().statusBarsPadding().height(HeaderHeight).padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    when (tab) {
                        RootTab.VAULT -> stringResource(R.string.tab_vault)
                        RootTab.SYNC -> stringResource(R.string.tab_sync)
                        RootTab.SECURITY -> stringResource(R.string.security_title)
                        RootTab.SETTINGS -> stringResource(R.string.settings_title)
                    },
                    color = LgkTheme.colors.text,
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    modifier = Modifier.weight(1f, fill = false).semantics { heading() },
                )
                if (tab == RootTab.VAULT) {
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        // UX refresh §4, as on the iPhone: one "more" menu (Sort, Collections) and the + button, the only
                        // accent-filled control. The search is a field under the title (VaultScreen).
                        Box {
                            GlassCircleButton(stringResource(R.string.vault_more), { moreOpen = true }, tag = "vault-more-menu") {
                                Icon(Icons.Filled.MoreHoriz, null, tint = LgkTheme.colors.text)
                            }
                            val sort by model.sort.collectAsStateWithLifecycle()
                            val collections by model.collections.collectAsStateWithLifecycle()
                            val collectionFilter by model.collectionFilter.collectAsStateWithLifecycle()
                            VaultMoreMenu(
                                moreOpen, { moreOpen = false }, sort, model::setSort,
                                collections, collectionFilter, model::setCollectionFilter, seams.onOpenCollections,
                            )
                        }
                        Box {
                            Box(
                                Modifier.size(48.dp).clip(CircleShape).background(LgkTheme.colors.accent)
                                    .clickable(role = Role.Button) { menuOpen = true }
                                    .semantics { contentDescription = newItemLabel },
                                contentAlignment = Alignment.Center,
                            ) { Icon(Icons.Filled.Add, null, tint = Color.White) }
                            NewItemMenu(menuOpen, { menuOpen = false }, onAddFile = onAddFile?.let { add -> { menuOpen = false; add() } }) { kind ->
                                menuOpen = false
                                // Creating needs a free slot or Pro; existing items are never blocked.
                                when (NewItemGate.decide(model.snapshot, seams.isPro())) {
                                    NewItemGate.Decision.OPEN_EDITOR -> seams.onNewItem(kind)
                                    NewItemGate.Decision.UPGRADE -> onLimit(liveCount)
                                }
                            }
                        }
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

/**
 * The vault search as a page over the tabs (the iPhone pushes it on the Vault tab's stack): a back arrow and the title,
 * then [SearchScreen]. System Back and the arrow close it ([onBack]).
 */
@Composable
internal fun VaultSearchPage(model: VaultListModel, seams: VaultSeams, focusKey: Int, onBack: () -> Unit) {
    BackHandler(onBack = onBack)
    Box(Modifier.fillMaxSize().testTag("search-page")) {
        GlassBackdropHost(Modifier.fillMaxSize()) {
            AuroraBackground()
            Column(Modifier.fillMaxSize().statusBarsPadding()) {
                Spacer(Modifier.height(HeaderHeight))
                Box(Modifier.weight(1f).fillMaxWidth()) { SearchScreen(model, seams, focusKey) }
            }
        }
        Row(
            Modifier.fillMaxWidth().statusBarsPadding().height(HeaderHeight).padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            GlassCircleButton(stringResource(R.string.common_back), onBack, tag = "search-back") {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = LgkTheme.colors.text)
            }
            Text(
                stringResource(R.string.search_hint),
                color = LgkTheme.colors.text,
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                modifier = Modifier.semantics { heading() },
            )
        }
    }
}

@Composable
private fun GlassCircleButton(description: String, onClick: () -> Unit = {}, tag: String? = null, content: @Composable () -> Unit) {
    Box(
        Modifier
            .size(48.dp)
            .lgkGlass(CircleShape)
            .clip(CircleShape)
            .clickable(role = Role.Button, onClick = onClick)
            .semantics { contentDescription = description }
            .then(if (tag != null) Modifier.testTag(tag) else Modifier),
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

internal const val FEATURE_TRAVEL = "travel"
internal const val FEATURE_CLEAN_UP = "clean-up"
internal const val FEATURE_PROOF = "privacy-proof"
internal const val FEATURE_DOCTOR = "passkey-doctor"

/** Settings rows of the feature pack: Travel mode (not in a duress session), Clean up, Privacy proof, Passkey check. */
internal fun featureRows(fp: FeatureSeams?, txt: app.localgatekeys.android.i18n.Txt, open: (String) -> Unit): List<Triple<String, String, () -> Unit>> {
    if (fp == null) return emptyList()
    val rows = ArrayList<Triple<String, String, () -> Unit>>()
    if (!fp.duress) rows.add(Triple(txt.s(R.string.travel_title), "settings-travel") { open(FEATURE_TRAVEL) })
    rows.add(Triple(txt.s(R.string.hygiene_title), "settings-clean-up") { open(FEATURE_CLEAN_UP) })
    rows.add(Triple(txt.s(R.string.privacy_title), "settings-privacy-proof") { open(FEATURE_PROOF) })
    rows.add(Triple(txt.s(R.string.passkey_doctor_title), "settings-passkey-doctor") { open(FEATURE_DOCTOR) })
    return rows
}
