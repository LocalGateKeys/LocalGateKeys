package app.localgatekeys.android

import app.localgatekeys.android.R
import android.app.Application
import android.os.Build
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.ProcessLifecycleOwner
import app.localgatekeys.android.autofill.FillIndexStore
import app.localgatekeys.android.backup.BackupText
import app.localgatekeys.android.passkey.PrivilegedBrowsers
import app.localgatekeys.core.records.PublicSuffixRules
import app.localgatekeys.core.sync.DirectoryAttachmentVault
import app.localgatekeys.android.attachments.DocumentTemp
import app.localgatekeys.core.records.UrlMatcher
import app.localgatekeys.android.backup.RestoreAttempts
import app.localgatekeys.android.crypto.Argon2KtAdapter
import app.localgatekeys.android.detail.ElapsedClock
import app.localgatekeys.android.detail.SecretClipboard
import app.localgatekeys.android.detail.SystemClipboardSink
import app.localgatekeys.android.generator.PassphraseWordlist
import app.localgatekeys.android.pro.HttpLicenceClaim
import app.localgatekeys.android.pro.PlayBillingPurchases
import app.localgatekeys.android.pro.PrefsClaimFlags
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
import app.localgatekeys.android.sync.NsdServiceBrowser
import app.localgatekeys.android.sync.SocketLanTransport
import app.localgatekeys.android.sync.WifiNetworkBinder
import app.localgatekeys.android.ui.detail.CopyToast
import app.localgatekeys.android.unlock.AppLockModel
import app.localgatekeys.android.i18n.AndroidTxt
import app.localgatekeys.android.i18n.SwitchableTxt
import app.localgatekeys.android.unlock.AuthenticationException
import app.localgatekeys.android.unlock.BiometricAuthenticator
import app.localgatekeys.android.unlock.HandlerLockScheduler
import app.localgatekeys.android.unlock.ScreenOffReceiver
import app.localgatekeys.android.unlock.SystemUnlocker
import app.localgatekeys.android.unlock.VaultDirs
import app.localgatekeys.android.unlock.VaultEraser
import app.localgatekeys.android.editor.EditorDraftStore
import java.io.File
import app.localgatekeys.android.vault.AppPasswordAttempts
import app.localgatekeys.android.vault.AppPasswordFiles
import app.localgatekeys.android.vault.AppPasswordLock
import app.localgatekeys.android.vault.BootClock
import app.localgatekeys.android.vault.KeystoreVaultKey
import app.localgatekeys.android.unlock.AppPasswordController
import app.localgatekeys.android.vault.SiteLogos
import app.localgatekeys.core.crypto.Argon2
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.crypto.AppPasswordRecord
import app.localgatekeys.android.settings.AppPasswordSeams
import androidx.biometric.BiometricManager
import app.localgatekeys.core.primitives.SystemRandomSource
import java.lang.ref.WeakReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class LgkApp : Application() {
    /** App-wide main-thread scope for the lock model's suspend calls (they outlive an activity). */
    val appScope = MainScope()

    /** UI text for process-wide models; the running Activity attaches its own resources (see [SwitchableTxt.use]). */
    val txt: SwitchableTxt by lazy { SwitchableTxt(AndroidTxt(resources)) }

    val settings: AppSettings by lazy { AppSettings(SharedPrefsStore(this)) }
    val dirs: VaultDirs by lazy { VaultDirs.under(filesDir) }

    /** The one unsaved editor draft (Task 6), encrypted; out of every backup. */
    val draftFile: File by lazy { EditorDraftStore.file(noBackupFilesDir) }

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
    suspend fun confirmOwner(reason: String = BackupText(txt).exportReason): Boolean {
        val trip = Build.VERSION.SDK_INT < 30
        if (trip) lock.willOpenSystemScreen()
        val ok = try {
            ownerCheck.authenticate(reason, null)
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
    val pro: ProModel by lazy {
        ProModel(
            PlayBillingPurchases(this) { activityRef?.get() },
            claimer = HttpLicenceClaim(), claimFlags = PrefsClaimFlags(this), txt = txt,
        )
    }

    /**
     * Sync for the open vault: one coordinator per unlock, on the main thread. The lock ends it (gate closed, work in
     * flight cancelled) before the unlocker shuts the vault's own write gates.
     */
    private val wifiBinder: WifiNetworkBinder by lazy { WifiNetworkBinder(this) }

    /**
     * Document files (attachments, Task 12): `Vault/attachments/<id>.<blob>.lgkblob`, each sealed under its own key,
     * which only the encrypted vault record holds. Inside the vault directory, so Erase and Start fresh remove them too.
     */
    val attachments: DirectoryAttachmentVault by lazy { DirectoryAttachmentVault(File(dirs.vault, "attachments")) }

    /** Plain copies for preview, save and share (cache only): cleared at start and at every lock. */
    val documentTemp: DocumentTemp by lazy { DocumentTemp(cacheDir) }

    /** UX workstream 9: received `.lgkshare` packages and the open-once list (no-backup storage, never in a backup). */
    val shareInbox: app.localgatekeys.android.share.ShareInbox by lazy {
        app.localgatekeys.android.share.ShareInbox(File(noBackupFilesDir, "share-inbox"), File(noBackupFilesDir, "share-opened.json"), SystemClock())
    }

    /** The cloud folder: a tree URI picked with the system picker, its permission persisted. */
    val folderOpener: SafFolderOpener by lazy { SafFolderOpener(this) }

    val syncSessions: SyncSessions by lazy {
        SyncSessions { vault ->
            val deps = SyncDependencies.live(
                vault.slots,
                folders = folderOpener,
                // Wi-Fi sync: plain TCP to the paired PC's LAN address, bound to the Wi-Fi network; when that address
                // does not answer, the PC is found again by its Bonjour announcement.
                lan = { counters, random, clock ->
                    SocketLanTransport(
                        counters, random, clock, dialer = ChannelLanDialer(bind = wifiBinder::bind),
                        browser = NsdServiceBrowser(this, wifiBinder::localNetwork),
                    )
                },
                localSubnet = { LanDiagnostics.currentWiFiSubnet() },
                attachments = attachments,
            )
            SyncCoordinator(vault.store, deps, appScope, txt)
        }
    }

    /**
     * The app's lock state, created with the first activity. It lives as long as the process (like the iPhone app
     * state): process ON_STOP -> didEnterBackground, process ON_START -> sceneBecameActive (ProcessLifecycleOwner, so
     * a configuration change is not a trip to the background).
     */
    /** Task 7: the optional app password (off unless app-password.bin exists). */
    val appPasswordLock: AppPasswordLock by lazy {
        AppPasswordLock(
            AppPasswordFiles.under(filesDir), KeystoreVaultKey.biometricOnly(this), SystemRandomSource(),
            AppPasswordAttempts.of(settings), SystemClock(), bootClock = object : BootClock {
                override val elapsed: Long get() = android.os.SystemClock.elapsedRealtime() / 1000
                override val boot: Long get() = try {
                    android.provider.Settings.Global.getInt(contentResolver, android.provider.Settings.Global.BOOT_COUNT).toLong()
                } catch (e: android.provider.Settings.SettingNotFoundException) {
                    -1L
                }
            },
        )
    }

    /** Task 7: Settings > Security turns the app password on, off, changes it and sets the fingerprint shortcut. */
    val appPassword: AppPasswordController by lazy {
        AppPasswordController(
            dirs, KeystoreVaultKey.production(this), appPasswordLock, SystemRandomSource(),
            BiometricAuthenticator { activityRef?.get() }, cryptoBound = Build.VERSION.SDK_INT >= 30, t = txt,
        )
    }

    /**
     * Settings > Security > App password over [appPassword]. [localKey] is the open vault's key (null once locked);
     * each action works on a copy that is zeroed afterwards.
     */
    fun appPasswordSeams(localKey: () -> ByteArray?): AppPasswordSeams {
        suspend fun <T> withKey(block: suspend (ByteArray) -> T): T {
            val key = localKey()?.copyOf()?.takeIf { k -> k.any { it != 0.toByte() } }
                ?: throw IllegalStateException("locked")
            try {
                return block(key)
            } finally {
                key.fill(0)
            }
        }
        return AppPasswordSeams(
            isOn = { appPassword.isOn() },
            biometricOn = { appPassword.biometricOn() },
            biometricAvailable = {
                BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
            },
            prepare = { pw -> withKey { appPassword.prepare(it, AppPasswordRecord.passwordBytes(pw)) } },
            commit = { created, bio -> withKey { appPassword.commit(created, it, bio) } },
            change = { cur, new -> withKey { appPassword.change(it, AppPasswordRecord.passwordBytes(cur), AppPasswordRecord.passwordBytes(new)) } },
            turnOff = { cur ->
                // Below API 30 the screen-lock prompt is its own activity: that trip must not lock (Ruling 21).
                val trip = Build.VERSION.SDK_INT < 30
                if (trip) lock.willOpenSystemScreen()
                try {
                    withKey { appPassword.turnOff(it, AppPasswordRecord.passwordBytes(cur), txt.s(R.string.unlock_use_screen_lock)) }
                } finally {
                    if (trip) lock.systemScreenClosed()
                }
            },
            setBiometric = { on -> withKey { appPassword.setBiometric(it, on) } },
        )
    }

    val lock: AppLockModel by lazy {
        val key = KeystoreVaultKey.production(this)
        val model = AppLockModel(
            unlocker = syncSessions.wrap(SystemUnlocker({ activityRef?.get() }, key, dirs, SystemRandomSource(), settings, appPasswordLock)),
            clock = SystemClock(),
            scheduler = HandlerLockScheduler(),
            settings = settings,
            clipboard = clipboard,
            eraser = VaultEraser(dirs, key, settings, folders = folderOpener, draftFile = draftFile, appPassword = appPasswordLock, fillIndex = { fillIndex.erase() }),
            credentialScreenStopsApp = Build.VERSION.SDK_INT < 30,
            screenOff = ScreenOffReceiver(this),
            elapsedMillis = { android.os.SystemClock.elapsedRealtime() },
            passwordOn = { appPasswordLock.isOn() },
            biometricShortcut = { appPasswordLock.biometricOn() },
            t = txt,
        )
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            LifecycleEventObserver { _, event ->
                when (event) {
                    Lifecycle.Event.ON_START -> appScope.launch { model.sceneBecameActive() }
                    Lifecycle.Event.ON_STOP -> {
                        model.didEnterBackground()
                    }
                    else -> {}
                }
            },
        )
        model
    }

    /** Part C: the sealed fill index (titles, usernames, URL rows; no secrets) the autofill service reads while locked. */
    val fillIndex: FillIndexStore by lazy { FillIndexStore(File(noBackupFilesDir, "fill-index.bin")) }

    /** The desktop's matcher over the bundled public suffix list (null rules = base-domain rows match the exact host). */
    val urlMatcher: UrlMatcher by lazy {
        UrlMatcher(
            try {
                PublicSuffixRules.load(assets.open("public_suffix_list.dat").use { it.readBytes().toString(Charsets.UTF_8) })
            } catch (e: Exception) {
                null
            },
        )
    }

    /** The bundled privileged-browser allowlist (passkey origins; autofill browser certificates). */
    val privilegedBrowsers: PrivilegedBrowsers by lazy {
        try {
            PrivilegedBrowsers.parse(assets.open("privileged_browsers.json").use { it.readBytes().toString(Charsets.UTF_8) })
        } catch (e: Exception) {
            PrivilegedBrowsers.EMPTY
        }
    }

    /** The activity prompts currently show in (an autofill or passkey sheet puts it back when it closes). */
    fun currentActivity(): FragmentActivity? = activityRef?.get()

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
        // Task 7: an interrupted turn-on leaves vault-key.bin and the passcode-capable key; remove them before any
        // prompt can use them (the password file decides the mode).
        try { appPassword.finishTurnOn() } catch (e: Exception) { /* retried at the next unlock */ }
        // Task 12: no plain document copy outlives the process that made it.
        appScope.launch(Dispatchers.IO) { documentTemp.clear() }
        // Received packages older than a day have expired: their copies go.
        appScope.launch(Dispatchers.IO) { try { shareInbox.purge(); shareInbox.restore() } catch (e: Exception) { } }
        // Parse the bundled site logo table now, off the main thread, so no row has to.
        appScope.launch(Dispatchers.IO) { SiteLogos.shared(this@LgkApp) }
        // The passphrase list ships as an asset (the desktop's file, byte for byte); read and parsed once, off main.
        PassphraseWordlist.install { assets.open(PassphraseWordlist.ASSET).use { it.readBytes().toString(Charsets.UTF_8) } }
        appScope.launch(Dispatchers.IO) { PassphraseWordlist.packaged }
    }
}
