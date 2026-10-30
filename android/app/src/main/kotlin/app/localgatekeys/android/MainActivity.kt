package app.localgatekeys.android

import app.localgatekeys.android.attachments.DocumentStore
import app.localgatekeys.android.attachments.DocumentText
import app.localgatekeys.android.ui.detail.DocumentSeams
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
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
import app.localgatekeys.android.ui.detail.DetailSeams
import app.localgatekeys.android.editor.EditorDraftStore
import app.localgatekeys.android.ui.editor.EditorSeams
import app.localgatekeys.android.ui.input.NoPersonalisedLearning
import app.localgatekeys.android.vault.Copier
import app.localgatekeys.android.vault.VaultListModel
import app.localgatekeys.android.ui.unlock.UnlockScreen
import app.localgatekeys.android.ui.sync.SyncScreenText
import app.localgatekeys.android.detail.PasswordHistoryModel
import app.localgatekeys.android.settings.Onboarding
import app.localgatekeys.android.ui.sync.rememberSafFolderPicker
import app.localgatekeys.android.unlock.ActivityMonitor
import app.localgatekeys.android.unlock.AppLockModel
import app.localgatekeys.android.unlock.LocalActivityMonitor
import app.localgatekeys.android.share.ItemSharing
import app.localgatekeys.android.ui.share.ShareSeams
import app.localgatekeys.core.share.Share
import app.localgatekeys.android.vault.SearchShortcut
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

/** An AppCompatActivity (a FragmentActivity, as BiometricPrompt needs) so the per-app language applies below Android 13. */
class MainActivity : AppCompatActivity() {
    private var monitor: ActivityMonitor? = null
    /** Ctrl+K presses on a hardware keyboard (workstream 5): RootScaffold opens the vault search. */
    private val searchShortcut = kotlinx.coroutines.flow.MutableSharedFlow<Unit>(extraBufferCapacity = 1)

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
                        val documentStore = remember(open) { DocumentStore(open.store, app.attachments, SystemRandomSource(), SystemClock()) }
                        val model = remember(open) {
                            VaultListModel(open.store, txt, onLoad = { snap ->
                                pro.update(snap)
                                app.appScope.launch(Dispatchers.IO) { app.fillIndex.rebuild(snap); documentStore.collectGarbage() }
                            })
                        }
                        // This unlock's sync (the lock shuts it down through app.syncSessions).
                        val sync = remember(open) { app.syncSessions.forVault(open) }
                        // Task 9: once Play says purchased (launch refresh, buy, restore), claim the desktop licence in the
                        // background; it lands as a licence state and syncs to the PC. Silent either way.
                        val proState by pro.state.collectAsStateWithLifecycle()
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
                        val editorSeams = remember(open, sync) {
                            EditorSeams(
                                open.store, onLocalEdit = { sync.noteLocalEdit() },
                                drafts = EditorDraftStore(app.draftFile, open.localKey, SystemRandomSource(), SystemClock()),
                            )
                        }
                        // Leave and Reset of the sync profile delete the draft too (joined -> not joined).
                        LaunchedEffect(sync) {
                            var wasJoined = false
                            sync.membership.collect { m ->
                                if (wasJoined && !m.joined) withContext(Dispatchers.IO) { EditorDraftStore.deleteFile(app.draftFile) }
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
                        val settingsSeams = remember(sync) {
                            SettingsSeams(
                                lockNow = { lock.lock() },
                                noteActivity = { lock.noteActivity() },
                                appearance = { app.appearance.value = it },
                                erase = {
                                    app.appScope.launch {
                                        // Locks first; waits for this unlock's sync work, then deletes.
                                        lock.eraseAndLock { app.syncSessions.endAndWait() }
                                        withContext(Dispatchers.IO) { app.shareInbox.clear() }
                                        app.appearance.value = app.settings.appearance
                                    }
                                },
                                autofill = autofill,
                                acknowledgements = {
                                    Acknowledgement.all { path -> assets.open(path).use { it.readBytes().toString(Charsets.UTF_8) } }
                                },
                                version = SettingsText(txt).version(BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE.toString()),
                                openUrl = { url -> openLink(url) },
                                confirmOwner = { app.confirmOwner() },
                                copyKey = { key -> copier.copy(key, SettingsText(txt).keyCopied) },
                                appPassword = app.appPasswordSeams { lock.vault.value?.localKey },
                            )
                        }
                        // Backups go through this unlock's gated store: after a lock nothing is read or written.
                        val backupSeams = remember(open, sync) {
                            BackupSeams(
                                exporter = {
                                    BackupExporter(
                                        sync.store, SystemClock(), SystemRandomSource(), BuildConfig.VERSION_NAME,
                                        installId = { open.slots.installId() }, isPro = { pro.isPro },
                                        attachments = app.attachments,
                                    )
                                },
                                restorer = {
                                    PhoneRestore(
                                        sync.store, { pro.isPro }, SystemClock(), installId = { open.slots.installId() },
                                        pairedPeerId = { open.slots.pairedPeer()?.deviceId },
                                        attachments = app.attachments,
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
                                SystemClock(), SystemRandomSource(), app.documentTemp, app.shareInbox,
                                willOpenSystemScreen = { lock.willOpenSystemScreen() },
                                systemScreenClosed = { lock.systemScreenClosed() },
                                save = { opened ->
                                    val r = withContext(Dispatchers.IO) {
                                        ItemSharing.save(opened, sync.store, pro.isPro, SystemClock(), SystemRandomSource())
                                    }
                                    if (r == ItemSharing.SaveOutcome.SAVED) {
                                        sync.noteLocalEdit()
                                        withContext(Dispatchers.IO) { model.reload() }
                                    }
                                    r
                                },
                            )
                        }
                        CopyToastHost(app.copyToast) {
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
                            RootScaffold(
                                model, app.settings, seams, withDocuments, editorSeams, sync, folderPicker, pro,
                                settingsSeams = settingsSeams, backup = backupSeams,
                                confirmRollback = { app.confirmOwner(txt.s(SyncScreenText.ROLLBACK_REASON)) },
                                onboarding = onboarding,
                                share = shareSeams,
                                searchShortcut = searchShortcut,
                            )
                        }
                    } else {
                        UnlockScreen(
                            lock,
                            onUnlock = { app.appScope.launch { lock.unlock() } },
                            onStartFresh = { app.appScope.launch { lock.startFreshAnyway() } },
                            onPassword = { pw -> app.appScope.launch { lock.unlockWithPassword(pw) } },
                            onRecover = { phrase, pw -> app.appScope.launch { lock.recover(phrase, pw) } },
                            biometricShortcut = { app.appPasswordLock.biometricOn() },
                        )
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        receiveShare(intent)
    }

    /**
     * Copies a delivered `.lgkshare` (content URI only) into private storage and tries to delete the delivered copy;
     * the Receive page opens after the unlock. Anything that is not a package is ignored.
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
            try {
                app.shareInbox.accept(bytes, keepFile = true)
                try { contentResolver.delete(uri, null, null) } catch (e: Exception) { /* read-only source: it stays there */ }
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
