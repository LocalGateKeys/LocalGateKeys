package app.localgatekeys.android

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
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.backup.BackupExporter
import app.localgatekeys.android.backup.PhoneRestore
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
import app.localgatekeys.android.ui.editor.EditorSeams
import app.localgatekeys.android.ui.input.NoPersonalisedLearning
import app.localgatekeys.android.vault.Copier
import app.localgatekeys.android.vault.VaultListModel
import app.localgatekeys.android.ui.unlock.UnlockScreen
import app.localgatekeys.android.ui.sync.rememberSafFolderPicker
import app.localgatekeys.android.unlock.ActivityMonitor
import app.localgatekeys.android.unlock.AppLockModel
import app.localgatekeys.android.unlock.LocalActivityMonitor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A FragmentActivity because androidx BiometricPrompt needs one. */
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

class MainActivity : FragmentActivity() {
    private var monitor: ActivityMonitor? = null

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
        val lock = app.lock
        userActivity = { lock.noteActivity() }
        val activityMonitor = ActivityMonitor { userActivity() }
        // Every copy goes through the one secret clipboard (sensitive, expires, cleared on lock) and is confirmed.
        val copier = Copier { text, confirmation ->
            app.clipboard.copy(text)
            if (confirmation.isNotEmpty()) app.copyToast.show(confirmation)
        }
        val detailSeams = DetailSeams(app.clipboard, app.copyToast)
        monitor = activityMonitor
        // Pro at launch: the entitlement only (Play's purchase cache), never a product lookup; then every purchase update
        // that arrives outside a purchase (a pending purchase completed) re-reads it.
        val pro = app.pro
        pro.startObserving(app.appScope)
        app.appScope.launch { pro.refresh() }
        val autofill = AutofillStatusModel(isEnabled = { autofillEnabled(this) }, open = { openAutofillSettings(this) })
        setContent {
            val chosen by app.appearance.collectAsStateWithLifecycle()
            val appearance = forcedAppearance ?: chosen
            LaunchedEffect(appearance) { edgeToEdge() }
            LgkTheme(appearance) {
                AppFrame(activityMonitor) {
                    val state by lock.state.collectAsStateWithLifecycle()
                    // Unlock and lock: handle a clipboard copy whose expiry passed while the app could not look.
                    LaunchedEffect(state) { app.clipboard.checkDue() }
                    val vault by lock.vault.collectAsStateWithLifecycle()
                    val open = vault
                    if (state == AppLockModel.State.UNLOCKED && open != null) {
                        // One list model per unlock: locking drops the vault, and with it every decoded record.
                        // Every load also re-reads the synced licence states for Pro.
                        val model = remember(open) { VaultListModel(open.store, onLoad = pro::update) }
                        // This unlock's sync (the lock shuts it down through app.syncSessions).
                        val sync = remember(open) { app.syncSessions.forVault(open) }
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
                        val editorSeams = remember(open, sync) { EditorSeams(open.store, onLocalEdit = { sync.noteLocalEdit() }) }
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
                                        app.appearance.value = app.settings.appearance
                                    }
                                },
                                autofill = autofill,
                                acknowledgements = {
                                    Acknowledgement.all { path -> assets.open(path).use { it.readBytes().toString(Charsets.UTF_8) } }
                                },
                                version = SettingsText.version(BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE.toString()),
                                openUrl = { url -> openLink(url) },
                                confirmOwner = { app.confirmOwner() },
                            )
                        }
                        // Backups go through this unlock's gated store: after a lock nothing is read or written.
                        val backupSeams = remember(open, sync) {
                            BackupSeams(
                                exporter = {
                                    BackupExporter(
                                        sync.store, SystemClock(), SystemRandomSource(), BuildConfig.VERSION_NAME,
                                        installId = { open.slots.installId() }, isPro = { pro.isPro },
                                    )
                                },
                                restorer = {
                                    PhoneRestore(
                                        sync.store, { pro.isPro }, SystemClock(), installId = { open.slots.installId() },
                                        pairedPeerId = { open.slots.pairedPeer()?.deviceId },
                                    )
                                },
                                attempts = app.restoreAttempts,
                                now = { System.currentTimeMillis() / 1000 },
                                onPickerOpen = { lock.willOpenSystemScreen() },
                                onPickerClose = { lock.systemScreenClosed() },
                            )
                        }
                        CopyToastHost(app.copyToast) {
                            RootScaffold(
                                model, app.settings, seams, detailSeams, editorSeams, sync, folderPicker, pro,
                                settingsSeams = settingsSeams, backup = backupSeams,
                            )
                        }
                    } else {
                        UnlockScreen(
                            lock,
                            onUnlock = { app.appScope.launch { lock.unlock() } },
                            onStartFresh = { app.appScope.launch { lock.startFreshAnyway() } },
                        )
                    }
                }
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
