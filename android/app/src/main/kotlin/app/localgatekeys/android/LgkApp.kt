package app.localgatekeys.android

import android.app.Application
import android.os.Build
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.ProcessLifecycleOwner
import app.localgatekeys.android.backup.BackupText
import app.localgatekeys.android.backup.RestoreAttempts
import app.localgatekeys.android.crypto.Argon2KtAdapter
import app.localgatekeys.android.detail.ElapsedClock
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.android.detail.SystemClipboardSink
import app.localgatekeys.android.generator.PassphraseWordlist
import app.localgatekeys.android.pro.PlayBillingPurchases
import app.localgatekeys.android.pro.ProModel
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.Appearance
import app.localgatekeys.android.settings.SharedPrefsStore
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncDependencies
import app.localgatekeys.android.sync.SafFolderOpener
import app.localgatekeys.android.sync.SyncSessions
import app.localgatekeys.android.sync.ChannelLanDialer
import app.localgatekeys.android.sync.LanDiagnostics
import app.localgatekeys.android.sync.SocketLanTransport
import app.localgatekeys.android.sync.WifiNetworkBinder
import app.localgatekeys.android.ui.detail.CopyToast
import app.localgatekeys.android.unlock.AppLockModel
import app.localgatekeys.android.unlock.AuthenticationException
import app.localgatekeys.android.unlock.BiometricAuthenticator
import app.localgatekeys.android.unlock.HandlerLockScheduler
import app.localgatekeys.android.unlock.ScreenOffReceiver
import app.localgatekeys.android.unlock.SystemUnlocker
import app.localgatekeys.android.unlock.VaultDirs
import app.localgatekeys.android.unlock.VaultEraser
import app.localgatekeys.android.vault.KeystoreVaultKey
import app.localgatekeys.android.vault.SiteLogos
import app.localgatekeys.core.crypto.Argon2
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import java.lang.ref.WeakReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class LgkApp : Application() {
    /** App-wide main-thread scope for the lock model's suspend calls (they outlive an activity). */
    val appScope = MainScope()

    val settings: AppSettings by lazy { AppSettings(SharedPrefsStore(this)) }
    val dirs: VaultDirs by lazy { VaultDirs.under(filesDir) }

    /** The Appearance setting the theme follows; Settings updates it as soon as a choice is made. */
    val appearance: MutableStateFlow<Appearance> by lazy { MutableStateFlow(settings.appearance) }

    /** Backup passwords: five wrong ones, then 30 s (for the whole process, so closing the screen does not reset it). */
    val restoreAttempts: RestoreAttempts by lazy { RestoreAttempts(ElapsedClock()) }

    /** The fresh unlock before a backup export: only the owner check, no vault key. */
    private val ownerCheck: BiometricAuthenticator by lazy { BiometricAuthenticator { activityRef?.get() } }

    /**
     * Asks for the owner's fingerprint, face or screen lock (Export backup). Below API 30 the screen lock is its own
     * activity and stops the app, so that trip uses the system-screen allowance (Ruling 21); from API 30 the prompt is
     * a system dialog. True only when it succeeded and the vault is still unlocked.
     */
    suspend fun confirmOwner(): Boolean {
        val trip = Build.VERSION.SDK_INT < 30
        if (trip) lock.willOpenSystemScreen()
        val ok = try {
            ownerCheck.authenticate(BackupText.EXPORT_REASON, null)
            true
        } catch (e: AuthenticationException) {
            false
        }
        val stillUnlocked = if (trip) lock.systemScreenClosed() else lock.state.value == AppLockModel.State.UNLOCKED
        return ok && stillUnlocked
    }

    /** The one secret clipboard: the detail screen and the Codes row copy through it, locking clears it. */
    val clipboard: SecretClipboard by lazy {
        SecretClipboard(SystemClipboardSink(this), settings, HandlerLockScheduler(), ElapsedClock())
    }

    /** The one copy confirmation (its own message only below Android 13, which confirms copies itself). */
    val copyToast: CopyToast by lazy { CopyToast(CopyToast.showsOwnMessage(Build.VERSION.SDK_INT)) }

    private var activityRef: WeakReference<FragmentActivity>? = null

    /**
     * Pro for the process: the `pro_unlimited` Google Play purchase (its sheet shows over the attached activity) or a
     * synced desktop licence (each vault load hands its snapshot to [ProModel.update]).
     */
    val pro: ProModel by lazy { ProModel(PlayBillingPurchases(this) { activityRef?.get() }) }

    /**
     * Sync for the open vault: one coordinator per unlock, on the main thread. The lock ends it (gate closed, work in
     * flight cancelled) before the unlocker shuts the vault's own write gates.
     */
    private val wifiBinder: WifiNetworkBinder by lazy { WifiNetworkBinder(this) }

    /** The cloud folder: a tree URI picked with the system picker, its permission persisted. */
    val folderOpener: SafFolderOpener by lazy { SafFolderOpener(this) }

    val syncSessions: SyncSessions by lazy {
        SyncSessions { vault ->
            val deps = SyncDependencies.live(
                vault.slots,
                folders = folderOpener,
                // Wi-Fi sync: plain TCP to the paired PC's LAN address, bound to the Wi-Fi network.
                lan = { counters, random, clock ->
                    SocketLanTransport(counters, random, clock, dialer = ChannelLanDialer(bind = wifiBinder::bind))
                },
                localSubnet = { LanDiagnostics.currentWiFiSubnet() },
            )
            SyncCoordinator(vault.store, deps, appScope)
        }
    }

    /**
     * The app's lock state, created with the first activity. It lives as long as the process (like the iPhone app
     * state): process ON_STOP -> didEnterBackground, process ON_START -> sceneBecameActive (ProcessLifecycleOwner, so
     * a configuration change is not a trip to the background).
     */
    val lock: AppLockModel by lazy {
        val key = KeystoreVaultKey.production(this)
        val model = AppLockModel(
            unlocker = syncSessions.wrap(SystemUnlocker({ activityRef?.get() }, key, dirs, SystemRandomSource(), settings)),
            clock = SystemClock(),
            scheduler = HandlerLockScheduler(),
            settings = settings,
            clipboard = clipboard,
            eraser = VaultEraser(dirs, key, settings, folders = folderOpener),
            credentialScreenStopsApp = Build.VERSION.SDK_INT < 30,
            screenOff = ScreenOffReceiver(this),
            elapsedMillis = { android.os.SystemClock.elapsedRealtime() },
        )
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            LifecycleEventObserver { _, event ->
                when (event) {
                    Lifecycle.Event.ON_START -> appScope.launch { model.sceneBecameActive() }
                    Lifecycle.Event.ON_STOP -> model.didEnterBackground()
                    else -> {}
                }
            },
        )
        model
    }

    /** The activity the unlock prompt and Play's purchase sheet show in. */
    fun attach(activity: FragmentActivity) {
        activityRef = WeakReference(activity)
    }

    fun detach(activity: FragmentActivity) {
        if (activityRef?.get() === activity) activityRef = null
    }

    override fun onCreate() {
        super.onCreate()
        Argon2.default = Argon2KtAdapter()
        // Parse the bundled site logo table now, off the main thread, so no row has to.
        appScope.launch(Dispatchers.IO) { SiteLogos.shared(this@LgkApp) }
        // The passphrase list ships as an asset (the desktop's file, byte for byte); read and parsed once, off main.
        PassphraseWordlist.install { assets.open(PassphraseWordlist.ASSET).use { it.readBytes().toString(Charsets.UTF_8) } }
        appScope.launch(Dispatchers.IO) { PassphraseWordlist.packaged }
    }
}
