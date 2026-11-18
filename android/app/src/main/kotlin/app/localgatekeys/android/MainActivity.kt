package app.localgatekeys.android

import app.localgatekeys.core.sync.TravelMode
import app.localgatekeys.android.vault.LocalStore
import app.localgatekeys.android.history.HistoryRecorder
import app.localgatekeys.android.history.FeatureSeams
import app.localgatekeys.android.vault.LocalStoreException
import android.widget.Toast
import app.localgatekeys.core.recovery.HeirFlow
import app.localgatekeys.android.ui.recovery.EmergencySeams
import app.localgatekeys.android.recovery.EmergencyAccess
import app.localgatekeys.android.attachments.DocumentStore
import app.localgatekeys.android.attachments.DocumentText
import app.localgatekeys.android.ui.detail.DocumentSeams
import app.localgatekeys.android.autofill.hideOverlays
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.service.quicksettings.TileService
import android.graphics.Color
import android.net.Uri
import android.provider.Settings
import android.view.autofill.AutofillManager
import android.os.Bundle
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.annotation.VisibleForTesting
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.backup.BackupExporter
import app.localgatekeys.android.backup.PhoneRestore
import app.localgatekeys.android.i18n.AndroidTxt
import app.localgatekeys.android.settings.Acknowledgement
import app.localgatekeys.android.settings.Appearance
import app.localgatekeys.android.settings.AutoLockDelay
import app.localgatekeys.android.settings.AutofillStatusModel
import app.localgatekeys.android.settings.SettingsText
import app.localgatekeys.android.settings.isDark
import app.localgatekeys.android.ui.settings.BackupSeams
import app.localgatekeys.android.ui.settings.SettingsSeams
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.ui.shell.RootScaffold
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.unlock.PrivacyCoverHost
import app.localgatekeys.android.ui.vault.VaultSeams
import app.localgatekeys.android.ui.detail.CopyToastHost
import app.localgatekeys.android.ui.detail.CodePinSeams
import app.localgatekeys.android.ui.detail.DetailSeams
import app.localgatekeys.android.editor.EditorDraftStore
import app.localgatekeys.android.editor.EditorKind as LgkEstateKind
import app.localgatekeys.android.editor.EditorModel as LgkEstateModel
import app.localgatekeys.android.editor.SaveResult as LgkEstateSaved
import app.localgatekeys.android.ui.editor.EditorSeams
import app.localgatekeys.android.ui.input.NoPersonalisedLearning
import app.localgatekeys.android.vault.Copier
import app.localgatekeys.android.vault.VaultListModel
import app.localgatekeys.android.ui.unlock.UnlockScreen
import app.localgatekeys.android.ui.sync.LocalProModel
import app.localgatekeys.android.ui.sync.SyncScreenText
import app.localgatekeys.android.ui.unlock.DeviceErasedNotice
import app.localgatekeys.android.detail.PasswordHistoryModel
import app.localgatekeys.android.settings.Onboarding
import app.localgatekeys.android.ui.sync.rememberSafFolderPicker
import app.localgatekeys.android.unlock.ActivityMonitor
import app.localgatekeys.android.unlock.AppLockModel
import app.localgatekeys.android.unlock.AndroidFactorSource
import app.localgatekeys.android.unlock.KeyFileRef
import app.localgatekeys.android.unlock.LocalActivityMonitor
import app.localgatekeys.android.share.ItemSharing
import app.localgatekeys.android.ui.share.ShareSeams
import app.localgatekeys.core.share.Share
import app.localgatekeys.android.vault.SearchShortcut
import app.localgatekeys.android.backup.BackupPasswordCheck
import app.localgatekeys.android.reminders.LegacyReminderFile
import app.localgatekeys.android.reminders.LocalReminderStore
import app.localgatekeys.android.reminders.ReminderSystem
import app.localgatekeys.android.reminders.ReminderTap
import app.localgatekeys.android.reminders.Reminders
import app.localgatekeys.android.security.SecurityCheckModel
import app.localgatekeys.android.collections.CollectionsModel
import app.localgatekeys.android.trash.PhoneLocalData
import app.localgatekeys.android.trash.PhoneTrash
import app.localgatekeys.android.trash.UndoToast
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.trash.UndoToastHost
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.produceState
import androidx.compose.ui.Modifier
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The frame MainActivity puts around every screen: Ruling 15 (no text field lets the keyboard learn what is typed), the
 * idle-lock activity monitor and the privacy cover. A device test checks a text field inside it.
 */
@Composable
internal fun AppFrame(activityMonitor: ActivityMonitor, content: @Composable () -> Unit) {
    NoPersonalisedLearning {
        CompositionLocalProvider(LocalActivityMonitor provides activityMonitor) {
            PrivacyCoverHost(content)
        }
    }
}

/** This unlock's local data once read ([ready]); [data] null when it could not be opened (no trash, no reminders). */
private class LocalOpen(val data: PhoneLocalData?, val ready: Boolean)

/** An AppCompatActivity (a FragmentActivity, as BiometricPrompt needs) so the per-app language applies below Android 13. */
class MainActivity : AppCompatActivity() {
    private var monitor: ActivityMonitor? = null
    /** Ctrl+K presses on a hardware keyboard (workstream 5): RootScaffold opens the vault search. */
    private val searchShortcut = kotlinx.coroutines.flow.MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    /**
     * A reminder notification's tap (workstream 10): the reminder id, kept while the vault is locked; after the unlock
     * its item opens. Only a request (the activity is exported): an unknown id opens nothing.
     */
    private val pendingReminder = MutableStateFlow<String?>(null)
    /**
     * Sub-plan 06: a long press on the Quick Settings tile. Kept while the vault is locked; after the unlock the Vault
     * tab (its Codes row) shows. Only a request: it opens nothing else.
     */
    private val showCodesRequests = Channel<Unit>(Channel.CONFLATED)

    /** What a touch or key press reports: the lock model's noteActivity (device tests observe it). */
    @VisibleForTesting
    internal var userActivity: () -> Unit = {}

    override fun onCreate(savedInstanceState: Bundle?) {
        // Debug builds only (BuildConfig.DEBUG is a compile-time constant, so R8 removes this from release):
        // extras for emulator screenshots. lgk.debug.insecure leaves FLAG_SECURE off, lgk.debug.appearance forces the theme.
        val debugInsecure = BuildConfig.DEBUG && intent?.getBooleanExtra("lgk.debug.insecure", false) == true
        val forced = if (BuildConfig.DEBUG) intent?.getStringExtra("lgk.debug.appearance") else null
        val forcedAppearance = Appearance.entries.firstOrNull { it.name.equals(forced, ignoreCase = true) }
        // Ruling D, debug builds only: a pairing code joined as if scanned (once per activity, after the unlock).
        var debugPairing = if (BuildConfig.DEBUG) DebugPairing.textFrom(intent) else null

        // Nothing of the vault may show in screenshots or the recents screen.
        if (!debugInsecure) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        super.onCreate(savedInstanceState)
        // Ruling 15: no third-party autofill service sees (or offers to save) anything in this window.
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        // The app password and recovery phrase are typed here: no other app's overlay sits on top.
        window.hideOverlays()
        val app = application as LgkApp
        // The Appearance setting (a debug extra may force one for screenshots); Settings changes it at once.
        val appearanceNow = { forcedAppearance ?: app.appearance.value }
        // Transparent system bars (no scrim) so the aurora shows behind them; icon colours follow the theme.
        val dark = {
            appearanceNow().isDark(
                resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK ==
                    android.content.res.Configuration.UI_MODE_NIGHT_YES,
            )
        }
        val edgeToEdge = {
            enableEdgeToEdge(
                statusBarStyle = SystemBarStyle.auto(Color.TRANSPARENT, Color.TRANSPARENT) { dark() },
                navigationBarStyle = SystemBarStyle.auto(Color.TRANSPARENT, Color.TRANSPARENT) { dark() },
            )
        }
        edgeToEdge()
        app.attach(this)
        // UX workstream 9: a .lgkshare file opened from another app (only on a fresh start, not a recreation).
        if (savedInstanceState == null) receiveShare(intent)
        if (savedInstanceState == null) pendingReminder.value = ReminderSystem.reminderIdOf(intent)
        if (savedInstanceState == null) receiveShowCodes(intent)
        // Ruling B: UI text comes from this Activity's resources (so it follows the per-app language), not the Application's.
        val txt = AndroidTxt(resources)
        app.txt.use(txt)
        val lock = app.lock
        userActivity = { lock.noteActivity() }
        val activityMonitor = ActivityMonitor { userActivity() }
        // Every copy goes through the one secret clipboard (sensitive, expires, cleared on lock) and is confirmed.
        val copier = Copier { text, confirmation ->
            app.clipboard.copy(text)
            if (confirmation.isNotEmpty()) app.copyToast.show(confirmation)
        }
        val detailSeams = DetailSeams(
            app.clipboard, app.copyToast, confirmOwner = { app.confirmOwner(txt.s(PasswordHistoryModel.REVEAL_REASON)) },
            confirmOwnerFor = { reason -> app.confirmOwner(reason) },
            // Sub-plan 06: pinning a code to the home-screen widget is Pro (the shell adds the Pro sheet).
            pins = CodePinSeams(
                isPinned = { app.pinnedCodes.isPinned(it) },
                toggle = { id -> app.pinnedCodes.pin(id, app.pro.isPro).also { app.codesWidget.request() } },
                lockImmediately = { app.settings.autoLockDelay == AutoLockDelay.IMMEDIATELY },
            ),
        )
        monitor = activityMonitor
        // Pro at launch: the entitlement only (Play's purchase cache), never a product lookup; then every purchase update
        // that arrives outside a purchase (a pending purchase completed) re-reads it.
        val pro = app.pro
        pro.startObserving(app.appScope)
        app.appScope.launch { pro.refresh() }
        val autofill = AutofillStatusModel(isEnabled = { autofillEnabled(this) }, open = { openAutofillSettings(this) }, t = txt)
        setContent {
            val chosen by app.appearance.collectAsStateWithLifecycle()
            val appearance = forcedAppearance ?: chosen
            LaunchedEffect(appearance) { edgeToEdge() }
            LgkTheme(appearance) {
                AppFrame(activityMonitor) {
                    val state by lock.state.collectAsStateWithLifecycle()
                    // Unlock and lock: handle a clipboard copy whose expiry passed while the app could not look.
                    LaunchedEffect(state) {
                        app.clipboard.checkDue()
                        if (state != AppLockModel.State.UNLOCKED) app.copyOnce.clear()
                        // Task 12: a lock deletes every plain document copy (preview, share, camera).
                        if (state != AppLockModel.State.UNLOCKED) withContext(Dispatchers.IO) { app.documentTemp.clear() }
                    }
                    val vault by lock.vault.collectAsStateWithLifecycle()
                    val open = vault
                    if (state == AppLockModel.State.UNLOCKED && open != null) {
                        // One list model per unlock: locking drops the vault, and with it every decoded record.
                        // Every load also re-reads the synced licence states for Pro.
                        // Task 12: this unlock's document files; files no record names any more (a delete that came by
                        // sync, an add that never committed) are removed after every load.
                        // Sub-plan 08: a duress session keeps its documents, local data and draft in its own folder.
                        val attachments = remember(open) { app.attachmentsFor(open) }
                        val documentStore = remember(open) { DocumentStore(open.store, attachments, SystemRandomSource(), SystemClock()) }
                        val model = remember(open) {
                            VaultListModel(open.store, txt, onLoad = { snap ->
                                pro.update(snap)
                                app.appScope.launch(Dispatchers.IO) {
                                    // A duress session offers no autofill: the fill index is never written from it.
                                    if (!open.decoy) app.fillIndex.rebuild(snap, pro.isPro)
                                    documentStore.collectGarbage()
                                }
                            })
                        }
                        // This unlock's sync (the lock shuts it down through app.syncSessions).
                        val sync = remember(open) { app.syncSessions.forVault(open) }
                        // What the features below write through (a duress session: its own store; it never syncs).
                        val features = remember(open) { app.syncSessions.featureStore(open) }
                        // Task 9: once Play says purchased (launch refresh, buy, restore), claim the desktop licence in the
                        // background; it lands as a licence state and syncs to the PC. Silent either way.
                        val proState by pro.state.collectAsStateWithLifecycle()
                        // The locked provider's "free plan full" flag in the fill index follows Pro at once (a purchase,
                        // a restore), not only the next load. Pro is read when writing, so a late write is never stale.
                        LaunchedEffect(open, proState.isPro) {
                            // The vault may lock while this runs: a closed store has nothing to rebuild (no crash).
                            if (!open.decoy) withContext(Dispatchers.IO) {
                                try {
                                    app.fillIndex.rebuild(open.store.load(), pro.isPro)
                                } catch (e: LocalStoreException) {
                                    if (e.kind != LocalStoreException.Kind.BAD_LOCAL_KEY || e.detail != "closed") throw e
                                }
                            }
                        }
                        LaunchedEffect(open, proState.purchased) {
                            if (proState.purchased) {
                                withContext(Dispatchers.IO) { pro.claimIfNeeded(open.store) { app.appScope.launch(Dispatchers.Main) { sync.noteLocalEdit() } } }
                            }
                        }
                        // Pull-to-refresh syncs (VaultScreen reloads afterwards).
                        val seams = remember(sync) {
                            VaultSeams(
                                clipboard = copier,
                                isPro = { pro.isPro },
                                onRefresh = { sync.sync(SyncCoordinator.Trigger.PULL_TO_REFRESH) },
                            )
                        }
                        // The editor writes through this unlock's store and tells sync (2 s debounce); RootScaffold adds
                        // the generator and the 2FA QR scanner.
                        // Task 6: the unsaved-draft file, sealed with a key derived from this unlock's local key.
                        // Workstreams 3 and 10: this phone's never-synced data (Recently deleted, reminders), sealed with the
                        // vault key; read off the main thread once per unlock (the shell waits for it). The first unlock
                        // after the update carries the old plain reminder file over and deletes it.
                        // Sub-plan 07: collections an older local copy still holds move into the store once (the store
                        // commit carries the "done" marker); nothing is seeded (starters only on request).
                        val local by produceState(LocalOpen(null, ready = false), open) {
                            var moved = false
                            value = withContext(Dispatchers.IO) {
                                val data = try {
                                    PhoneLocalData(app.vaultDirFor(open), open.localKey, SystemRandomSource())
                                } catch (e: Exception) {
                                    null
                                }
                                if (data != null) LegacyReminderFile.migrate(ReminderSystem.legacyRowsFile(app), LocalReminderStore(data))
                                if (data != null) moved = CollectionsModel.migrate(sync.store, data)
                                if (moved) model.reload()
                                LocalOpen(data, ready = true)
                            }
                            if (moved) sync.noteLocalEdit()
                        }
                        val localData = local.data
                        // Writes go through this unlock's gated store: nothing is written after a lock.
                        val trash = remember(localData) {
                            localData?.let { l ->
                                PhoneTrash(l, features, isPro = { pro.isPro }, clock = SystemClock(), t = txt, attachments = attachments).also {
                                    it.onRestored = {
                                        sync.noteLocalEdit()
                                        app.appScope.launch(Dispatchers.IO) { model.reload() }
                                    }
                                }
                            }
                        }
                        // Feature pack 2026-11-15: item history (this phone only) and travel mode, over this unlock's local data.
                        val featureSeams = remember(localData) {
                            localData?.let { l ->
                                FeatureSeams(
                                    l, HistoryRecorder(l, { pro.isPro }, SystemClock()), isPro = { pro.isPro }, duress = open.decoy,
                                    willOpenSystemScreen = { lock.willOpenSystemScreen() }, systemScreenClosed = { lock.systemScreenClosed() },
                                    confirmOwner = { app.confirmOwner(txt.s(R.string.travel_turn_off_confirm)) },
                                    onTravelChanged = { setting ->
                                        app.appScope.launch(Dispatchers.IO) {
                                            if (!open.decoy) runCatching { app.fillIndex.rebuild(open.store.load(), pro.isPro, setting) }
                                            model.reload()
                                            trash?.relist()
                                            app.codesWidget.request()
                                        }
                                    },
                                )
                            }
                        }
                        DisposableEffect(featureSeams) {
                            val store = open.store as? LocalStore
                            if (featureSeams != null) {
                                store?.onHistory = featureSeams.history::record
                                model.travel = { featureSeams.travel }
                                trash?.travel = { featureSeams.travel }
                                app.appScope.launch(Dispatchers.IO) {
                                    if (!open.decoy) runCatching { app.fillIndex.rebuild(open.store.load(), pro.isPro, featureSeams.travel) }
                                    model.reload()
                                }
                            }
                            onDispose {
                                store?.onHistory = null
                                model.travel = { TravelMode.Setting.OFF }
                                trash?.travel = { TravelMode.Setting.OFF }
                            }
                        }
                        // Expired Recently deleted rows go at every unlock.
                        LaunchedEffect(trash) { trash?.let { t -> withContext(Dispatchers.IO) { t.purgeExpired() } } }
                        val undo = remember(open) { UndoToast() }
                        DisposableEffect(undo) { onDispose { undo.dismiss() } }
                        val reminderPrefs = remember { ReminderSystem.prefs(app) }
                        val reminders = remember(localData) {
                            localData?.let { Reminders(LocalReminderStore(it), app.reminderAlarmsFor(open), reminderPrefs, txt) }
                        }
                        // The live items re-plan the notifications (only once loaded: an empty list would cancel them all);
                        // the first load of the unlock re-plans even when nothing changed (a new day, notifications sent
                        // while locked).
                        LaunchedEffect(reminders) {
                            val r = reminders ?: return@LaunchedEffect
                            var planned = false
                            model.loads.collect { n ->
                                if (n == 0) return@collect
                                withContext(Dispatchers.IO) {
                                    val items = model.items.value
                                    val changed = r.items != items
                                    r.items = items
                                    if (!planned && !changed) r.reschedule()
                                }
                                planned = true
                            }
                        }
                        // Workstream 2: the Security tab's model; a lock forgets its results.
                        val security = remember(open, sync) {
                            SecurityCheckModel(
                                features, app.securityPrefs, SystemClock(), app.appScope,
                                { BackupPasswordCheck.estimator.estimate(it).score }, appVersion = BuildConfig.VERSION_NAME,
                                featuresSource = { app.siteFeatures },
                            )
                        }
                        DisposableEffect(security) { onDispose { security.clear() } }
                        SideEffect { security.travel = { featureSeams?.travel ?: TravelMode.Setting.OFF } }
                        // A reminder tap opens its item once the list has loaded (the rows say which item).
                        val openRequests = remember(open) { Channel<String>(Channel.CONFLATED) }
                        val openRequestFlow = remember(openRequests) { openRequests.receiveAsFlow() }
                        val showCodesFlow = remember { showCodesRequests.receiveAsFlow() }
                        val pendingId by pendingReminder.collectAsStateWithLifecycle()
                        val loads by model.loads.collectAsStateWithLifecycle()
                        LaunchedEffect(pendingId, reminders, loads) {
                            if (pendingId == null) return@LaunchedEffect
                            val r = reminders ?: return@LaunchedEffect
                            if (loads == 0) return@LaunchedEffect
                            ReminderTap.deliver(
                                pendingReminder,
                                find = { id -> withContext(Dispatchers.IO) { r.itemIdForReminder(id) } },
                                open = { openRequests.trySend(it) },
                            )
                        }
                        val editorSeams = remember(open, sync, trash) {
                            EditorSeams(
                                open.store, onLocalEdit = { sync.noteLocalEdit() },
                                drafts = EditorDraftStore(app.draftFileFor(open), open.localKey, SystemRandomSource(), SystemClock()),
                                trash = trash, undo = undo,
                            )
                        }
                        // Sub-plan 08: emergency access over this unlock (the plan arrives by sync; shards and keys in the slots).
                        val emergency = remember(open, sync) {
                            EmergencyAccess(
                                features, open.slots, openFolder = { uri -> app.heirFolder(uri) }, clock = SystemClock(),
                                random = SystemRandomSource(), onLocalEdit = { app.appScope.launch(Dispatchers.Main) { sync.noteLocalEdit() } },
                            )
                        }
                        // On every owner device: a look at the heir folder after unlock and after each sync run shows new
                        // requests once and writes a refused request's lost deny again.
                        LaunchedEffect(emergency) {
                            if (open.decoy) return@LaunchedEffect
                            sync.completedRuns.collect {
                                val notes = withContext(Dispatchers.IO) { app.heirNotices.check(emergency, txt) }
                                for (n in notes) Toast.makeText(this@MainActivity, n, Toast.LENGTH_LONG).show()
                            }
                        }
                        // Leave and Reset of the sync profile delete the draft too (joined -> not joined).
                        LaunchedEffect(sync) {
                            var wasJoined = false
                            sync.membership.collect { m ->
                                if (wasJoined && !m.joined) withContext(Dispatchers.IO) { EditorDraftStore.deleteFile(app.draftFileFor(open)) }
                                wasJoined = m.joined
                            }
                        }
                        LaunchedEffect(open) {
                            // Debug builds only (a no-op in release): fill an empty emulator vault for screenshots.
                            withContext(Dispatchers.IO) { DemoSeed.seedIfRequested(intent, open.store) }
                            withContext(Dispatchers.IO) { model.reload() }
                            // Unlock is a sync trigger (once per unlock, not per activity).
                            app.syncSessions.appOpen(open)
                            debugPairing?.let { code ->
                                debugPairing = null
                                sync.joinByQr(code)
                            }
                        }
                        // After every run the list reloads (serialized, off the main thread).
                        LaunchedEffect(sync) {
                            sync.completedRuns.collect { if (it > 0) withContext(Dispatchers.IO) { model.reload() } }
                        }
                        // The cloud folder's system picker stops this app: the lock allows that one trip (Ruling 21);
                        // a pick that returns after the vault locked is dropped.
                        val folderPicker = rememberSafFolderPicker(
                            app.folderOpener, onOpen = { lock.willOpenSystemScreen() }, onClose = { lock.systemScreenClosed() },
                        )
                        // Sub-plan 07 Task 5m: shared collections. Their own folder picker (never the Sync tab's), the owner
                        // check before a share, and the Pro state and Recently deleted the share runs need (no share runs
                        // until this unlock's local data is open: a share's deletes go there).
                        val sharePicker = rememberSafFolderPicker(
                            app.folderOpener, onOpen = { lock.willOpenSystemScreen() }, onClose = { lock.systemScreenClosed() },
                        )
                        val confirmShare: suspend () -> Boolean = remember { { app.confirmOwner(txt.s(R.string.collection_share_confirm_to_share)) } }
                        LaunchedEffect(sync, localData) {
                            sync.isPro = { pro.isPro }
                            sync.shareTrash = localData
                            // The unlock's first run may have come before Recently deleted opened: the shares run now.
                            val hasShares = localData != null && withContext(Dispatchers.IO) { runCatching { sync.store.load().shares != null }.getOrDefault(false) }
                            if (hasShares) sync.sync(SyncCoordinator.Trigger.APP_OPEN)
                        }
                        val settingsSeams = remember(sync) {
                            SettingsSeams(
                                lockNow = { lock.lock() },
                                noteActivity = { lock.noteActivity() },
                                appearance = { app.appearance.value = it },
                                erase = {
                                    // Locks first; waits for this unlock's sync work, then deletes.
                                    app.appScope.launch { app.eraseFromSettings() }
                                },
                                autofill = autofill,
                                acknowledgements = {
                                    Acknowledgement.all { path -> assets.open(path).use { it.readBytes().toString(Charsets.UTF_8) } }
                                },
                                version = SettingsText(txt).version(BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE.toString()),
                                openUrl = { url -> openLink(url) },
                                confirmOwner = { app.confirmOwner() },
                                confirmOwnerFor = { reason -> app.confirmOwner(reason) },
                                copyKey = { key -> copier.copy(key, SettingsText(txt).keyCopied) },
                                appPassword = app.appPasswordSeams { lock.vault.value?.localKey },
                                factors = app.factorSeams { lock.vault.value?.localKey },
                                duress = app.duressSeams { lock.vault.value },
                                emergency = EmergencySeams(
                                    model = { emergency },
                                    confirmOwner = { reason -> app.confirmOwner(reason) },
                                    persistFolder = { uri -> app.keepHeirFolder(uri, decoy = lock.vault.value?.decoy == true) },
                                    readFile = { uri -> withContext(Dispatchers.IO) { app.readSmallFile(uri, HeirFlow.MAX_FILE) } },
                                    willOpenSystemScreen = { lock.willOpenSystemScreen() },
                                    systemScreenClosed = { lock.systemScreenClosed() },
                                    createEstate = { body ->
                                        // Sub-plan 12: the estate pack note, saved like a new note from the editor.
                                        val kind = LgkEstateKind.NOTE
                                        val values = kind.defaults() + mapOf("title" to txt.s(R.string.estate_pack), "body" to body)
                                        val saved = LgkEstateModel(
                                            open.store, null, kind, { pro.isPro }, SystemClock(), SystemRandomSource(), txt, initialValues = values,
                                        ).save() == LgkEstateSaved.SAVED
                                        if (saved) app.appScope.launch(Dispatchers.Main) { sync.noteLocalEdit() }
                                        saved
                                    },
                                ),
                            )
                        }
                        // Backups go through this unlock's gated store: after a lock nothing is read or written.
                        val backupSeams = remember(open, sync) {
                            BackupSeams(
                                exporter = {
                                    BackupExporter(
                                        features, SystemClock(), SystemRandomSource(), BuildConfig.VERSION_NAME,
                                        installId = { open.slots.installId() }, isPro = { pro.isPro },
                                        attachments = attachments,
                                    )
                                },
                                restorer = {
                                    PhoneRestore(
                                        features, { pro.isPro }, SystemClock(), installId = { open.slots.installId() },
                                        pairedPeerId = { open.slots.pairedPeer()?.deviceId },
                                        attachments = attachments,
                                        onRestored = { app.removalWatch.delete() },
                                    )
                                },
                                attempts = app.restoreAttempts,
                                now = { System.currentTimeMillis() / 1000 },
                                onPickerOpen = { lock.willOpenSystemScreen() },
                                onPickerClose = { lock.systemScreenClosed() },
                            )
                        }
                        val onboarding = remember { Onboarding(app.settings, txt) }
                        // UX workstream 9: sharing writes through this unlock's gated store (nothing after a lock).
                        val shareSeams = remember(open, sync) {
                            ShareSeams(
                                SystemClock(), SystemRandomSource(), app.documentTemp, app.shareInboxFor(open),
                                willOpenSystemScreen = { lock.willOpenSystemScreen() },
                                systemScreenClosed = { lock.systemScreenClosed() },
                                save = { opened ->
                                    val r = withContext(Dispatchers.IO) {
                                        ItemSharing.save(opened, features, pro.isPro, SystemClock(), SystemRandomSource())
                                    }
                                    if (r == ItemSharing.SaveOutcome.SAVED) {
                                        sync.noteLocalEdit()
                                        withContext(Dispatchers.IO) { model.reload() }
                                    }
                                    r
                                },
                            )
                        }
                        if (!local.ready) {
                            // The local data is being read (a moment): the aurora, then the vault.
                            Box(Modifier.fillMaxSize()) { AuroraBackground() }
                        } else CopyToastHost(app.copyToast) {
                            // Said once after the unlock (a phrase reset removed the key file / YubiKey).
                            val notice by lock.notice.collectAsStateWithLifecycle()
                            LaunchedEffect(notice) {
                                notice?.let { app.copyToast.show(it); lock.noticeShown() }
                            }
                            val withDocuments = remember(open, sync) {
                                detailSeams.copy(
                                    documents = DocumentSeams(
                                        documentStore, app.documentTemp, isPro = { pro.isPro },
                                        confirmOwner = { app.confirmOwner(txt.s(DocumentText.OPEN_REASON)) },
                                        willOpenSystemScreen = { lock.willOpenSystemScreen() },
                                        systemScreenClosed = { lock.systemScreenClosed() },
                                        onChanged = {
                                            sync.noteLocalEdit()
                                            app.appScope.launch(Dispatchers.IO) { model.reload() }
                                        },
                                    ),
                                )
                            }
                            // The Sync screen reads Pro from here (Remove a device is Pro only; it opens the upgrade sheet).
                            CompositionLocalProvider(LocalProModel provides pro) {
                                // The Undo toast floats over every tab and page, above the tab bar.
                                UndoToastHost(undo) {
                                    RootScaffold(
                                        model, app.settings, seams, withDocuments, editorSeams, sync, folderPicker, pro,
                                        settingsSeams = settingsSeams, backup = backupSeams,
                                        confirmRollback = { app.confirmOwner(txt.s(SyncScreenText.ROLLBACK_REASON)) },
                                        onboarding = onboarding,
                                        share = shareSeams,
                                        searchShortcut = searchShortcut,
                                        security = security,
                                        securityPrefs = app.securityPrefs,
                                        reminders = reminders,
                                        reminderPrefs = reminderPrefs,
                                        openItemRequests = openRequestFlow,
                                        showCodesRequests = showCodesFlow,
                                        sharePicker = sharePicker,
                                        shareFolderName = { uri -> app.folderOpener.displayName(uri) },
                                        confirmShare = confirmShare,
                                        featurePack = featureSeams,
                                    )
                                }
                            }
                        }
                    } else {
                        UnlockScreen(
                            lock,
                            onUnlock = { app.appScope.launch { lock.unlock() } },
                            onStartFresh = { app.appScope.launch { lock.startFreshAnyway() } },
                            onPassword = { pw -> app.appScope.launch { lock.unlockWithPassword(pw) } },
                            onRecover = { phrase, pw -> app.appScope.launch { lock.recover(phrase, pw) } },
                            biometricShortcut = { app.appPasswordLock.biometricOn() && !(app.settings.factorsAlwaysAsk && lock.factorSpecs.value.isNotEmpty()) },
                            describeKeyFile = { uri -> KeyFileRef(uri.toString(), AndroidFactorSource.displayName(this, uri)) },
                        )
                        // After an erase on removal (set before the erase): said once on the screen that follows it.
                        DeviceErasedNotice(app.settings, app.removalGuard.erasures.collectAsStateWithLifecycle().value)
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        receiveShare(intent)
        ReminderSystem.reminderIdOf(intent)?.let { pendingReminder.value = it }
        receiveShowCodes(intent)
    }

    /** The Quick Settings tile's long press (its preferences action) asks for the Vault tab's Codes row. */
    private fun receiveShowCodes(intent: Intent?) {
        if (intent?.action == TileService.ACTION_QS_TILE_PREFERENCES) showCodesRequests.trySend(Unit)
    }

    /**
     * Copies a delivered `.lgkshare` (content URI only) into private storage; the Receive page opens after the unlock.
     * Anything that is not a package is ignored. The delivered file is deleted only when it is this app's own copy (its
     * FileProvider): a URI another app names is never deleted with this app's rights. A delivery never replaces a
     * package that is still waiting (Receive says so instead).
     */
    private fun receiveShare(intent: Intent?) {
        if (intent?.action != Intent.ACTION_VIEW) return
        val uri = intent.data ?: return
        if (uri.scheme != "content") return
        val app = application as LgkApp
        app.appScope.launch(Dispatchers.IO) {
            val bytes = try {
                contentResolver.openInputStream(uri)?.use { input ->
                    val limit = Share.MAX_PACKAGE + 1
                    val out = java.io.ByteArrayOutputStream()
                    val buf = ByteArray(16 * 1024)
                    var total = 0
                    while (total < limit) {
                        val n = input.read(buf, 0, minOf(buf.size, limit - total))
                        if (n < 0) break
                        out.write(buf, 0, n)
                        total += n
                    }
                    out.toByteArray()
                }
            } catch (e: Exception) {
                null
            } ?: return@launch
            val inbox = app.incomingShareInbox()
            try {
                inbox.accept(bytes, keepFile = true, replacePending = false)
                if (uri.authority == DocumentSeams.authority(this@MainActivity)) {
                    try { contentResolver.delete(uri, null, null) } catch (e: Exception) { /* already gone: nothing to do */ }
                }
            } catch (e: app.localgatekeys.core.share.ShareException) {
                // Opened or burned here before, or another package still waits: Receive says so (no code asked again).
                if (e.reason == "already-opened" || e.code == "pending-waiting") inbox.refuse(e)
            } catch (e: Exception) {
                // not a package (or no space): nothing kept
            } finally {
                bytes.fill(0)
            }
        }
    }

    /** A website link (Settings › About) in the browser; nothing happens when no browser is installed. */
    private fun openLink(url: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (e: ActivityNotFoundException) {
            // no browser
        }
    }

    /** The clipboard can be checked only with window focus: a deferred or overdue expiry runs when it returns. */
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        (application as LgkApp).clipboard.focusChanged(hasFocus)
    }

    override fun onResume() {
        super.onResume()
        (application as LgkApp).clipboard.checkDue()
    }

    /** Touches count as idle-lock activity; the event always goes on to the window unchanged. */
    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        val m = monitor ?: return super.dispatchTouchEvent(ev)
        return m.dispatchTouch(ev.actionMasked) { super.dispatchTouchEvent(ev) }
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        if (SearchShortcut.matches(event.keyCode, event.action, event.isCtrlPressed, event.isAltPressed, event.isShiftPressed, event.repeatCount)) {
            monitor?.dispatchKey(event.action) { true }
            if (searchShortcut.tryEmit(Unit)) return true
        }
        val m = monitor ?: return super.dispatchKeyEvent(event)
        return m.dispatchKey(event.action) { super.dispatchKeyEvent(event) }
    }

    private companion object {
        /** Settings › Autofill: whether this app is the enabled autofill service (Part C provides the service). */
        fun autofillEnabled(context: Context): Boolean = try {
            context.getSystemService(AutofillManager::class.java)?.hasEnabledAutofillServices() == true
        } catch (e: Exception) {
            false
        }

        /** The system's "choose the autofill service" screen for this app; throws when it cannot be opened. */
        fun openAutofillSettings(context: Context) {
            context.startActivity(
                Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(Uri.parse("package:" + context.packageName)),
            )
        }
    }

    override fun onDestroy() {
        (application as LgkApp).detach(this)
        super.onDestroy()
    }
}
