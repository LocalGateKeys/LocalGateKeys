package app.localgatekeys.android

import app.localgatekeys.android.access.CopyOnceLedger
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
import app.localgatekeys.android.settings.AutoLockDelay
import app.localgatekeys.android.settings.Appearance
import app.localgatekeys.android.settings.SharedPrefsStore
import app.localgatekeys.android.security.SecurityPrefs
import app.localgatekeys.android.security.SiteFeatures
import app.localgatekeys.android.reminders.ReminderAlarms
import app.localgatekeys.android.reminders.ReminderSystem
import app.localgatekeys.android.share.ShareInbox
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncDependencies
import app.localgatekeys.android.sync.SafFolderOpener
import app.localgatekeys.android.sync.SyncSessions
import app.localgatekeys.android.sync.RemovalGuard
import app.localgatekeys.android.sync.RemovalWatchFile
import app.localgatekeys.android.sync.ChannelLanDialer
import app.localgatekeys.android.sync.LanDiagnostics
import app.localgatekeys.android.sync.NsdServiceBrowser
import app.localgatekeys.android.sync.SocketLanTransport
import app.localgatekeys.android.sync.AndroidHostPlatform
import app.localgatekeys.android.sync.WifiHost
import app.localgatekeys.android.sync.WifiNetworkBinder
import app.localgatekeys.android.ui.detail.CopyToast
import app.localgatekeys.android.unlock.AppLockModel
import app.localgatekeys.android.i18n.AndroidTxt
import app.localgatekeys.android.i18n.SwitchableTxt
import app.localgatekeys.android.unlock.AuthenticationException
import app.localgatekeys.android.unlock.OwnerGate
import app.localgatekeys.android.unlock.OwnerPasswordDialog
import app.localgatekeys.android.unlock.BiometricAuthenticator
import app.localgatekeys.android.unlock.HandlerLockScheduler
import app.localgatekeys.android.unlock.ScreenOffReceiver
import app.localgatekeys.android.unlock.SystemUnlocker
import app.localgatekeys.android.unlock.VaultDirs
import app.localgatekeys.android.unlock.VaultEraser
import app.localgatekeys.android.editor.EditorDraftStore
import java.io.File
import android.net.Uri
import android.provider.DocumentsContract
import app.localgatekeys.android.recovery.HeirNotices
import app.localgatekeys.core.recovery.HeirFolder
import app.localgatekeys.android.duress.DuressException
import app.localgatekeys.android.duress.DuressFiles
import app.localgatekeys.android.duress.DuressPlaces
import app.localgatekeys.android.duress.DuressRouting
import app.localgatekeys.android.duress.DuressSamples
import app.localgatekeys.android.duress.DuressSeams
import app.localgatekeys.android.duress.DuressStatus
import app.localgatekeys.android.duress.DuressVault
import app.localgatekeys.android.unlock.UnlockedVault
import app.localgatekeys.android.vault.AppPasswordAttempts
import app.localgatekeys.android.vault.AppPasswordFiles
import app.localgatekeys.android.vault.AppPasswordLock
import app.localgatekeys.android.vault.BootClock
import app.localgatekeys.android.vault.KeystoreVaultKey
import app.localgatekeys.android.vault.LocalStore
import app.localgatekeys.android.codes.PinnedCodes
import app.localgatekeys.android.codes.StoreSnapshotProvider
import app.localgatekeys.android.widget.CodesWidgetUpdates
import app.localgatekeys.android.widget.CopyCodeTileService
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.android.unlock.AppPasswordController
import app.localgatekeys.android.vault.SiteLogos
import app.localgatekeys.core.crypto.Argon2
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.crypto.AppPasswordRecord
import app.localgatekeys.android.settings.AppPasswordSeams
import app.localgatekeys.android.settings.FactorSeams
import app.localgatekeys.android.settings.FactorState
import app.localgatekeys.android.unlock.AndroidFactorSource
import app.localgatekeys.android.unlock.AppPasswordController.FactorChange
import app.localgatekeys.android.unlock.FactorInput
import app.localgatekeys.android.unlock.KeyFileRef
import app.localgatekeys.android.unlock.YubiKeyReader
import app.localgatekeys.android.unlock.askYubiKeyWithRetries
import app.localgatekeys.core.crypto.FactorKind
import app.localgatekeys.core.crypto.KeyFile
import androidx.biometric.BiometricManager
import app.localgatekeys.core.primitives.SystemRandomSource
import java.lang.ref.WeakReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class LgkApp : Application() {
    /** App-wide main-thread scope for the lock model's suspend calls (they outlive an activity). */
    val appScope = MainScope()

    /** UI text for process-wide models; the running Activity attaches its own resources (see [SwitchableTxt.use]). */
    val txt: SwitchableTxt by lazy { SwitchableTxt(AndroidTxt(resources)) }

    val settings: AppSettings by lazy { AppSettings(SharedPrefsStore(this)) }
    val dirs: VaultDirs by lazy { VaultDirs.under(filesDir) }
    /** The Security check's settings (breach checks, strict offline, dismissed ids), in the app's settings file. */
    val securityPrefs: SecurityPrefs by lazy { SecurityPrefs(SharedPrefsStore(this)) }

    /** Device removal: `filesDir/Vault.sync-watch.json`, what a locked check needs to find a signed removal notice. */
    val removalWatch: RemovalWatchFile by lazy { RemovalWatchFile.beside(dirs.vault) }

    /**
     * Erase on removal: checks the watch file at start, whenever the app comes to the front (at most every 5 minutes)
     * and at once after a folder run reported a verified notice; erases when "Erase this device if it is removed from
     * sync" is on.
     */
    private var removalChecks: Job? = null

    val removalGuard: RemovalGuard by lazy {
        RemovalGuard(settings, removalWatch, folderOpener, erase = { eraseVault() }, clock = SystemClock())
    }

    /**
     * Settings > "Erase this phone's vault". Inside a duress session (Ruling T5a-b) it erases only the second vault's
     * data and never the real vault: lock, wait for this unlock's work, then [DuressVault.eraseSecondVault]. Otherwise
     * [eraseVault]. (A verified removal notice always runs [eraseVault]: it is about the real vault's sync group.)
     */
    suspend fun eraseFromSettings(): Boolean {
        return duressRouting.erase(lockAndWait = { lock.lock(); syncSessions.endAndWait() }, real = { eraseVault() })
    }

    /**
     * "Erase this phone's vault" (Settings, or a verified removal notice): locks first, waits for this unlock's sync
     * work, then deletes; the received share packages go too. Exported files are never touched.
     */
    suspend fun eraseVault(): Boolean {
        val finished = lock.eraseAndLock { syncSessions.endAndWait() }
        withContext(Dispatchers.IO) { shareInbox.clear() }
        codesWidget.request() // the pins went with the settings
        CopyCodeTileService.requestRefresh(this)
        appearance.value = settings.appearance
        return finished
    }

    /**
     * Sub-plan 08: the duress password (a second app password) and its own folder `filesDir/.lgk-d`. While its vault is
     * open, every file path below that belongs to a vault ([attachmentsFor], [vaultDirFor], [draftFileFor]) points into
     * that folder, so nothing it writes touches the real vault's files.
     */
    val duress: DuressVault by lazy { DuressVault(DuressFiles.under(filesDir), SystemRandomSource(), SystemClock(), bootClock = systemBootClock) }

    private val decoyAttachments: DirectoryAttachmentVault by lazy { DirectoryAttachmentVault(duress.files.attachments) }

    /** The documents folder of [vault] (the second vault keeps its own). */
    fun attachmentsFor(vault: UnlockedVault): DirectoryAttachmentVault = if (vault.decoy) decoyAttachments else attachments

    /** The store folder of [vault] (its never-synced local data lives beside the store). */
    fun vaultDirFor(vault: UnlockedVault): File = if (vault.decoy) duress.files.vault else dirs.vault

    /**
     * Travel mode of the open [vault], read from its own local data (not the fill index, which can be missing): null
     * when it cannot be read, which every caller treats as "everything hidden" (scan A-M4). Blocking.
     */
    fun travelFor(vault: UnlockedVault): app.localgatekeys.core.sync.TravelMode.Setting? = try {
        app.localgatekeys.android.trash.PhoneLocalData.readTravelMode(vaultDirFor(vault), vault.localKey)
    } catch (e: Exception) {
        null
    }

    /** The unsaved-draft file of [vault]. */
    fun draftFileFor(vault: UnlockedVault): File = if (vault.decoy) duress.files.draft else draftFile

    /** Sub-plan 08: the heir folder of a stored tree URI ([folderOpener]), or null when its permission is gone. */
    fun heirFolder(uri: String): HeirFolder? = try {
        if (!folderOpener.isAvailable(uri)) null else HeirFolder(folderOpener.open(uri), treeName(Uri.parse(uri)))
    } catch (e: Exception) {
        null
    }

    /** The display name of a picked tree's root (picking `LocalGateKeys Emergency` itself also works). */
    private fun treeName(tree: Uri): String? = try {
        val doc = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
        contentResolver.query(doc, arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    } catch (e: Exception) {
        null
    }

    /**
     * Keeps a picked heir folder's permission across restarts and sync folder changes; returns the URI to store. In a
     * duress session ([decoy]) the global list is left as it is (the permission is taken, not remembered there).
     */
    fun keepHeirFolder(tree: Uri, decoy: Boolean = false): String =
        folderOpener.persist(tree).also { if (!decoy) settings.heirFolders = settings.heirFolders + it }

    /** Sub-plan 08: the reminders' alarms of [vault] (a duress session plans into its own book and arms nothing). */
    fun reminderAlarmsFor(vault: UnlockedVault): ReminderAlarms =
        if (vault.decoy) DuressPlaces.reminderAlarms(duress.files) else ReminderSystem.alarms(this)

    private val decoyShareInbox: ShareInbox by lazy {
        DuressPlaces.shareInbox(duress.files, SystemClock()).also { try { it.purge(); it.restore() } catch (e: Exception) { } }
    }

    /** Sub-plan 08: the received-share inbox of [vault] (the second vault keeps its own). */
    fun shareInboxFor(vault: UnlockedVault): ShareInbox = if (vault.decoy) decoyShareInbox else shareInbox

    /** Where a package received now goes: the open duress session's inbox, else the real one (also while locked). */
    fun incomingShareInbox(): ShareInbox = if (lock.vault.value?.decoy == true) decoyShareInbox else shareInbox

    /** At most [limit] bytes of a picked document, or null (missing, unreadable or larger). */
    fun readSmallFile(uri: Uri, limit: Int): ByteArray? = try {
        contentResolver.openInputStream(uri)?.use { input ->
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(4096)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                out.write(buf, 0, n)
                if (out.size() > limit) return@use null
            }
            out.toByteArray()
        }
    } catch (e: Exception) {
        null
    }

    /** Sub-plan 08: which access requests this process already announced. */
    val heirNotices: HeirNotices by lazy { HeirNotices() }

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
     * a system dialog. True only when it succeeded and the vault is still unlocked. With the app password on, the
     * screen lock does not count (audit A1, [OwnerGate]): the fingerprint shortcut or the app password.
     */
    suspend fun confirmOwner(reason: String = BackupText(txt).exportReason): Boolean = ownerGate.confirm(reason)

    private val ownerGate: OwnerGate by lazy {
        OwnerGate(
            passwordOn = { appPasswordLock.isOn() },
            deviceCheck = { reason -> confirmWithScreenLock(reason) },
            biometricShortcut = {
                appPasswordLock.biometricOn() && lock.vault.value?.decoy != true && !duress.servicesBlocked() &&
                    !(settings.factorsAlwaysAsk && appPasswordLock.factors().isNotEmpty())
            },
            biometric = { reason -> ownerBiometric(reason) },
            askPassword = { reason, problem -> OwnerPasswordDialog.ask(activityRef?.get(), txt, reason, problem) },
            verifyPassword = { password -> verifyOwnerPassword(password) },
            stillUnlocked = { lock.state.value == AppLockModel.State.UNLOCKED },
            problem = { e -> AppLockModel.message(e, txt) },
            wrongPassword = txt.s(AppLockModel.WRONG_PASSWORD_MESSAGE),
        )
    }

    private suspend fun confirmWithScreenLock(reason: String): Boolean {
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

    /** The fingerprint shortcut: a strong biometric releases `vault-key-bio.bin`, which must be the open vault's key. */
    private suspend fun ownerBiometric(reason: String): OwnerGate.BiometricAnswer {
        val (wrapped, cipher) = try {
            withContext(Dispatchers.IO) { appPasswordLock.bioCipherForUnwrap() }
        } catch (e: Exception) {
            return OwnerGate.BiometricAnswer.USE_PASSWORD
        }
        val authorised = try {
            ownerCheck.authenticateBiometric(reason, cipher) ?: cipher
        } catch (e: AuthenticationException) {
            return when (e.code) {
                androidx.biometric.BiometricPrompt.ERROR_USER_CANCELED, androidx.biometric.BiometricPrompt.ERROR_CANCELED ->
                    OwnerGate.BiometricAnswer.CANCELLED
                else -> OwnerGate.BiometricAnswer.USE_PASSWORD
            }
        }
        val key = try {
            withContext(Dispatchers.IO) { appPasswordLock.bioKey.unwrap(wrapped, authorised) }
        } catch (e: Exception) {
            return OwnerGate.BiometricAnswer.USE_PASSWORD
        }
        val open = lock.vault.value?.localKey?.copyOf()
        try {
            val same = open != null && open.isNotEmpty() && java.security.MessageDigest.isEqual(open, key)
            return if (same) OwnerGate.BiometricAnswer.CONFIRMED else OwnerGate.BiometricAnswer.USE_PASSWORD
        } finally {
            key.fill(0)
            open?.fill(0)
        }
    }

    /**
     * The app password, checked as Settings checks it: the open vault's own password (inside a duress session the
     * second vault's), with the wrong-try delay, count and today's factors.
     */
    private suspend fun verifyOwnerPassword(password: ByteArray) = withContext(Dispatchers.IO) {
        val v = lock.vault.value ?: throw IllegalStateException("locked")
        if (v.decoy) {
            val wait = appPasswordLock.waitSeconds()
            if (wait > 0) throw app.localgatekeys.android.vault.AppPasswordWaitException(wait)
            val key = duress.tryOpen(password)
            if (key == null) {
                appPasswordLock.noteWrongTry()
                throw app.localgatekeys.core.crypto.AppPasswordException(app.localgatekeys.core.crypto.AppPasswordException.Kind.WRONG_PASSWORD)
            }
            key.fill(0)
        } else {
            val secrets = app.localgatekeys.android.unlock.FactorSecrets.collect(appPasswordLock.record().factors, settingsFactors(null))
            try {
                appPasswordLock.unwrapPassword(password, secrets).fill(0)
            } finally {
                secrets.forEach { it.fill(0) }
            }
        }
    }

    /** The one secret clipboard: the detail screen and the Codes row copy through it, locking clears it. */
    val clipboard: SecretClipboard by lazy {
        SecretClipboard(SystemClipboardSink(this), settings, HandlerLockScheduler(), ElapsedClock())
    }

    /** Copy-once access rule (contract section 4.2): the logins copied once in this unlock; a lock clears it. */
    val copyOnce: CopyOnceLedger = CopyOnceLedger()

    /** The one copy confirmation (its own message only below Android 13, which confirms copies itself). */
    val copyToast: CopyToast by lazy { CopyToast(CopyToast.showsOwnMessage(Build.VERSION.SDK_INT)) }

    private var activityRef: WeakReference<FragmentActivity>? = null

    /**
     * Pro for the process: the `pro_unlimited` Google Play purchase (its sheet shows over the attached activity) or a
     * synced desktop licence (each vault load hands its snapshot to [ProModel.update]).
     */
    val pro: ProModel by lazy {
        ProModel(
            app.localgatekeys.android.pro.DebugProOverride.wrapIfDebug(
                BuildConfig.DEBUG, PlayBillingPurchases(this) { activityRef?.get() }, filesDir,
            ),
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
        app.localgatekeys.android.share.ShareInbox(
            File(noBackupFilesDir, "share-inbox"), File(noBackupFilesDir, "share-opened.json"), SystemClock(),
        ) {
            // LGKSHARE v1.1 revoke notices in the cloud folder, signed by a member this phone trusts (the watch file's
            // signers: the trusted keyring's member signing keys, as for removal notices). No sync: none.
            val w = removalWatch.load() ?: return@ShareInbox emptySet()
            app.localgatekeys.core.share.ShareRevoke.collect(folderOpener.open(w.folder), w.signers)
        }
    }

    /** The cloud folder: a tree URI picked with the system picker, its permission persisted. */
    val folderOpener: SafFolderOpener by lazy { SafFolderOpener(this) { settings.heirFolders } }

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
                removalWatch = removalWatch,
                // Never awaited here: the erase ends this coordinator first.
                onRemovalNotice = { appScope.launch { removalGuard.check(force = true) } },
                autoSync = { settings.autoSync },
            )
            SyncCoordinator(vault.store, deps, appScope, txt).also { coordinator ->
                // Wi-Fi host mode (off by default): this phone listens for its paired devices while in front and unlocked.
                val counters = deps.counters ?: return@also
                coordinator.host = WifiHost(
                    coordinator, counters, AndroidHostPlatform(this, wifiBinder::localNetwork), appScope,
                    readEnabled = { settings.wifiHostOn }, writeEnabled = { settings.wifiHostOn = it },
                    readPort = { settings.wifiHostPort }, writePort = { settings.wifiHostPort = it },
                ).also { host ->
                    host.isPro = { pro.isPro }
                    host.copy = { text -> clipboard.copy(text) }
                    host.foreground = appInFront
                }
            }
        }
    }

    /** The app is in front (process lifecycle): the Wi-Fi host listens only then. Main thread. */
    private var appInFront = false

    private fun setAppInFront(front: Boolean) {
        appInFront = front
        syncSessions.current?.host?.foreground = front
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
            AppPasswordAttempts.of(settings), SystemClock(), bootClock = systemBootClock,
        )
    }

    /** Seconds since boot and which boot: the wrong-try delay and the duress hold count on it (date changes don't move it). */
    private val systemBootClock: BootClock by lazy {
        object : BootClock {
            override val elapsed: Long get() = android.os.SystemClock.elapsedRealtime() / 1000
            override val boot: Long get() = try {
                android.provider.Settings.Global.getInt(contentResolver, android.provider.Settings.Global.BOOT_COUNT).toLong()
            } catch (e: android.provider.Settings.SettingNotFoundException) {
                -1L
            }
        }
    }

    /** Task 9: the app password's key file (persisted document permission) and YubiKey (NFC or USB). */
    val factorSource: AndroidFactorSource by lazy {
        AndroidFactorSource(this, settings, YubiKeyReader(this) { activityRef?.get() })
    }

    /** The YubiKey slot Settings is waiting for (its touch dialog); null when none. */
    private val settingsYubiKeyPrompt = MutableStateFlow<Int?>(null)

    /**
     * The factors for a Settings change: [keyFile] (picked in the dialog) or the remembered key file, and the YubiKey
     * with the touch dialog (asked again when it leaves the reader mid-answer).
     */
    private fun settingsFactors(keyFile: KeyFileRef?): FactorInput = FactorInput(
        keyFile = { (keyFile ?: factorSource.rememberedKeyFile())?.let { factorSource.readKeyFile(it) } },
        yubiKey = { slot, challenge ->
            try {
                askYubiKeyWithRetries(AppLockModel.YUBIKEY_TRIES, { settingsYubiKeyPrompt.value = slot }) {
                    factorSource.yubiKey(slot, challenge)
                }
            } finally {
                settingsYubiKeyPrompt.value = null
            }
        },
    )

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
    /** The real vault's app-password change ([key]: the session key copy, zeroed by the caller). */
    private suspend fun realChange(key: ByteArray, cur: String, new: String) {
        // Sub-plan 08: never the duress password or one edit from it (checked in the real vault only).
        val next = AppPasswordRecord.passwordBytes(new)
        try {
            withContext(Dispatchers.IO) { duress.checkNewPassword(key, next, decoySession = false) }
        } finally {
            next.fill(0)
        }
        appPassword.change(key, AppPasswordRecord.passwordBytes(cur), AppPasswordRecord.passwordBytes(new), settingsFactors(null))
    }

    /** Sub-plan 08: the Settings actions that take the duress path in a duress session. */
    val duressRouting: DuressRouting by lazy { DuressRouting({ lock.vault.value?.decoy == true }, duress, appPasswordLock) }

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
            change = { cur, new ->
                // Ruling T5a-b: in a duress session the change is the second vault's own password, as on the desktop
                // (nothing is checked against or changed in the real vault).
                withKey { key -> duressRouting.changePassword(key, cur, new) { realChange(key, cur, new) } }
            },
            turnOff = { cur ->
                if (lock.vault.value?.decoy == true) throw DuressException("unavailable")
                // Below API 30 the screen-lock prompt is its own activity: that trip must not lock (Ruling 21).
                val trip = Build.VERSION.SDK_INT < 30
                if (trip) lock.willOpenSystemScreen()
                try {
                    withKey {
                        appPassword.turnOff(it, AppPasswordRecord.passwordBytes(cur), txt.s(R.string.unlock_use_screen_lock), settingsFactors(null))
                    }
                    factorSource.forget()
                    settings.factorsAlwaysAsk = false
                    // The duress password is a second app password: without the app password it goes too.
                    withContext(Dispatchers.IO) { duress.remove(decoySession = false) }
                } finally {
                    if (trip) lock.systemScreenClosed()
                }
            },
            setBiometric = { on ->
                // In a duress session the shortcut would wrap the second vault's key over the real one's: refused.
                if (lock.vault.value?.decoy == true) throw DuressException("unavailable")
                withKey { appPassword.setBiometric(it, on, alwaysAsk = settings.factorsAlwaysAsk) }
            },
        )
    }

    /**
     * Sub-plan 08: Settings > Security > Duress password over [duress] and the open vault ([vault]). The current app
     * password is checked against the open vault's own password: inside a duress session that is the second vault's,
     * so nothing there tests the real one; setup and removal there end with the plain "couldn't save" and write nothing.
     */
    fun duressSeams(vault: () -> UnlockedVault?): DuressSeams = DuressSeams(
        status = {
            withContext(Dispatchers.IO) {
                val v = vault()
                val decoy = v?.decoy == true
                val key = v?.localKey?.copyOf()
                try {
                    val on = !decoy && duress.configured()
                    val hours = if (on && key != null) duress.realHours(key) ?: DuressVault.DEFAULT_HOURS else DuressVault.DEFAULT_HOURS
                    DuressStatus(pro = pro.isPro, appPasswordOn = appPasswordLock.isOn(), on = on, hours = hours)
                } finally {
                    key?.fill(0)
                }
            }
        },
        setUp = { current, password, confirm, hours ->
            withContext(Dispatchers.IO) {
                val v = vault() ?: throw IllegalStateException("locked")
                if (!pro.isPro) throw DuressException("pro")
                if (!appPasswordLock.isOn()) throw DuressException("needs_password")
                if (password != confirm) throw DuressException("mismatch")
                val cur = AppPasswordRecord.passwordBytes(current)
                val next = AppPasswordRecord.passwordBytes(password)
                val key = v.localKey.copyOf()
                try {
                    if (v.decoy) {
                        duress.tryOpen(cur)?.fill(0)
                            ?: throw app.localgatekeys.core.crypto.AppPasswordException(app.localgatekeys.core.crypto.AppPasswordException.Kind.WRONG_PASSWORD)
                    } else {
                        val secrets = app.localgatekeys.android.unlock.FactorSecrets.collect(appPasswordLock.record().factors, settingsFactors(null))
                        try {
                            appPasswordLock.unwrapPassword(cur, secrets).fill(0)
                        } finally {
                            secrets.forEach { it.fill(0) }
                        }
                    }
                    val real = v.store.load()
                    duress.setup(key, cur, next, hours, v.decoy) { store ->
                        DuressSamples.seed(store, real, txt, SystemRandomSource(), SystemClock().now)
                    }
                } finally {
                    cur.fill(0)
                    next.fill(0)
                    key.fill(0)
                }
            }
        },
        remove = {
            withContext(Dispatchers.IO) {
                val v = vault() ?: throw IllegalStateException("locked")
                duress.remove(v.decoy)
            }
        },
    )

    /**
     * Task 9: Settings > Key file and YubiKey over [appPassword]. [localKey] as in [appPasswordSeams]. Each change asks
     * for the current app password (and today's factors); the key file is never copied into app storage.
     */
    fun factorSeams(localKey: () -> ByteArray?): FactorSeams {
        suspend fun change(password: String, keyFile: KeyFileRef?, change: FactorChange) {
            if (lock.vault.value?.decoy == true) throw DuressException("unavailable")
            val key = localKey()?.copyOf()?.takeIf { k -> k.any { it != 0.toByte() } } ?: throw IllegalStateException("locked")
            try {
                appPassword.changeFactors(key, AppPasswordRecord.passwordBytes(password), settingsFactors(keyFile), change)
            } finally {
                key.fill(0)
            }
        }
        suspend fun addFile(password: String, file: KeyFileRef, remember: Boolean, keyFile: KeyFileRef?, bytes: ByteArray) {
            try {
                change(password, keyFile, FactorChange.AddKeyFile(bytes))
            } catch (e: Exception) {
                factorSource.releaseKeyFile(file) // the change failed: nothing is kept
                throw e
            } finally {
                bytes.fill(0)
            }
            // The old key file is no longer one; the new one's grant is persisted only now, and only when remembered.
            if (factorSource.rememberedKeyFile()?.uri != file.uri) factorSource.forget()
            if (remember && factorSource.remembers()) factorSource.rememberKeyFile(file) else factorSource.releaseKeyFile(file)
        }
        return FactorSeams(
            state = {
                withContext(Dispatchers.IO) {
                    val specs = appPasswordLock.factors()
                    FactorState(
                        passwordOn = appPasswordLock.isOn(),
                        keyFile = specs.any { it.kind == FactorKind.KEYFILE },
                        yubiKeySlot = specs.firstOrNull { it.kind == FactorKind.YUBIKEY_HMAC }?.slot,
                        alwaysAsk = settings.factorsAlwaysAsk,
                        remember = factorSource.remembers(),
                        rememberedKeyFile = factorSource.rememberedKeyFile()?.name,
                    )
                }
            },
            addKeyFile = { password, file, remember, keyFile ->
                addFile(password, file, remember, keyFile, factorSource.readKeyFile(file))
            },
            createKeyFile = { password, file, remember, keyFile ->
                val bytes = KeyFile.newKeepassXmlV2(SystemRandomSource())
                try {
                    // Written (and read back) before the app password needs it.
                    withContext(Dispatchers.IO) {
                        contentResolver.openOutputStream(android.net.Uri.parse(file.uri), "wt")?.use { it.write(bytes) }
                            ?: throw java.io.IOException("no output stream")
                    }
                    val back = factorSource.readKeyFile(file)
                    val same = back.contentEquals(bytes)
                    back.fill(0)
                    if (!same) throw java.io.IOException("key file not written")
                } catch (e: java.io.IOException) {
                    bytes.fill(0)
                    throw app.localgatekeys.android.unlock.KeyFileUnreadableException(file.name)
                }
                addFile(password, file, remember, keyFile, bytes)
            },
            addYubiKey = { password, slot, keyFile -> change(password, keyFile, FactorChange.AddYubiKey(slot)) },
            removeKeyFile = { password, keyFile ->
                change(password, keyFile, FactorChange.RemoveKeyFile)
                factorSource.forget()
                if (appPasswordLock.factors().isEmpty()) settings.factorsAlwaysAsk = false
            },
            removeYubiKey = { password, keyFile ->
                change(password, keyFile, FactorChange.RemoveYubiKey)
                if (appPasswordLock.factors().isEmpty()) settings.factorsAlwaysAsk = false
            },
            setAlwaysAsk = { on -> appPassword.setAlwaysAsk(on) { settings.factorsAlwaysAsk = it } },
            setRemember = { on -> withContext(Dispatchers.IO) { factorSource.setRemember(on) } },
            yubiKeyPrompt = settingsYubiKeyPrompt,
            cancelYubiKey = { factorSource.cancelYubiKey() },
            willOpenPicker = { lock.willOpenSystemScreen() },
            pickerClosed = { lock.systemScreenClosed() },
            describe = { uri -> KeyFileRef(uri.toString(), AndroidFactorSource.displayName(this, uri)) },
            discard = { factorSource.releaseKeyFile(it) },
        )
    }

    /** The lock model once created (with the first activity); null before, and in a process started for the widget. */
    @Volatile private var lockModel: AppLockModel? = null

    /**
     * Sub-plan 06: the widget's pinned codes. Only item ids are stored; codes and titles are read from the open vault
     * through the key this process holds, and only before the vault's auto-lock deadline. Locked: nothing to read.
     */
    val pinnedCodes: PinnedCodes by lazy {
        PinnedCodes(settings, object : StoreSnapshotProvider {
            override fun snapshot(): StoreSnapshot? {
                val model = lockModel ?: return null
                val store = model.vault.value?.store ?: return null
                val deadline = model.lockDeadline() ?: return null
                return if (System.currentTimeMillis() / 1000 >= deadline) null else store.load()
            }
        }, frozen = { lockModel?.vault?.value?.decoy == true || duress.sessionOpen }, travel = {
            // The open vault's own travel setting; unreadable (or locked) hides every code (fail closed, scan A-M4).
            lockModel?.vault?.value?.let { travelFor(it) }
        })
    }

    /**
     * The open vault's auto-lock deadline (Unix seconds, `AppLockModel.lockDeadline`); null while locked and in a process
     * started for the widget or the Quick Settings tile (no lock model, no vault key). Pinned codes are read only before it.
     */
    fun vaultLockDeadline(): Long? = lockModel?.lockDeadline()

    /** Sub-plan 06: keeps the home-screen codes widget current (see [CodesWidgetUpdates]). */
    val codesWidget: CodesWidgetUpdates by lazy {
        CodesWidgetUpdates(
            this, pinnedCodes, appScope, lockDeadline = { vaultLockDeadline() },
            lockImmediately = { settings.autoLockDelay == AutoLockDelay.IMMEDIATELY },
        )
    }

    val lock: AppLockModel by lazy {
        val key = KeystoreVaultKey.production(this)
        val model = AppLockModel(
            unlocker = syncSessions.wrap(
                SystemUnlocker({ activityRef?.get() }, key, dirs, SystemRandomSource(), settings, appPasswordLock, duress),
            ),
            clock = SystemClock(),
            scheduler = HandlerLockScheduler(),
            settings = settings,
            clipboard = clipboard,
            eraser = VaultEraser(
                dirs, key, settings, folders = folderOpener, draftFile = draftFile, appPassword = appPasswordLock,
                fillIndex = { fillIndex.erase() }, watchFile = removalWatch.file,
                extraSteps = listOf(
                    "reminders" to { ReminderSystem.wipe(this) },
                    "security-settings" to { securityPrefs.wipe() },
                    "duress" to { duress.eraseAll() },
                ),
            ),
            credentialScreenStopsApp = Build.VERSION.SDK_INT < 30,
            screenOff = ScreenOffReceiver(this),
            elapsedMillis = { android.os.SystemClock.elapsedRealtime() },
            passwordOn = { appPasswordLock.isOn() },
            biometricShortcut = {
                appPasswordLock.biometricOn() && !(settings.factorsAlwaysAsk && appPasswordLock.factors().isNotEmpty()) &&
                    !duress.held()
            },
            t = txt,
            factorSource = factorSource,
            factors = { appPasswordLock.factors() },
            onFactorsDropped = {
                settings.factorsAlwaysAsk = false
                factorSource.forget()
            },
        )
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            LifecycleEventObserver { _, event ->
                when (event) {
                    Lifecycle.Event.ON_START -> {
                        val open = syncSessions.current
                        appScope.launch {
                            model.sceneBecameActive()
                            syncSessions.foreground(open)
                        }
                        setAppInFront(true)
                        // Locked or not: a signed removal notice in the folder erases this phone (setting on). Checked now
                        // and then every 5 minutes while the app stays in front (like the desktop).
                        removalChecks?.cancel()
                        removalChecks = appScope.launch {
                            while (true) {
                                removalGuard.check()
                                delay((RemovalGuard.INTERVAL_SECONDS + 1) * 1000)
                            }
                        }
                    }
                    Lifecycle.Event.ON_STOP -> {
                        setAppInFront(false)
                        removalChecks?.cancel(); removalChecks = null
                        model.didEnterBackground()
                        // The widget's codes now stop at the auto-lock deadline (or are gone after an immediate lock).
                        codesWidget.request()
                    }
                    else -> {}
                }
            },
        )
        // Audit A2: the lock limits run on monotonic time; a wall-clock change re-checks them now and re-renders the
        // widget (whose deadline is worked out afresh), so setting the date back never keeps codes on screen.
        val timeChanged = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: android.content.Context, intent: android.content.Intent) {
                model.wallClockChanged()
                codesWidget.request()
            }
        }
        val timeFilter = android.content.IntentFilter(android.content.Intent.ACTION_TIME_CHANGED)
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(timeChanged, timeFilter, android.content.Context.RECEIVER_NOT_EXPORTED)
        else registerReceiver(timeChanged, timeFilter)
        lockModel = model
        // Sub-plan 06: every unlock and lock re-renders the codes widget, and so does every commit of the open vault
        // (an edit or a sync run), which also drops pins whose item or two-factor secret is gone.
        appScope.launch {
            model.vault.collect { open ->
                (open?.store as? LocalStore)?.onCommit = { codesWidget.request() }
                codesWidget.request()
                // A lock re-renders the Quick Settings tile too (locked state, no title).
                if (open == null) CopyCodeTileService.requestRefresh(this@LgkApp)
                // A lock or a duress session drops typed passwords still waiting for the save sheet.
                if (open == null || open.decoy) app.localgatekeys.android.autofill.PendingSaves.clear()
            }
        }
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

    /** The phishing shield's lookalike classifier over the same bundled public suffix list (sub-plan 09). */
    val lookalike: app.localgatekeys.core.security.Lookalike by lazy { app.localgatekeys.core.security.Lookalike(urlMatcher.rules) }


    /** Which sites offer TOTP and passkeys (`site_features.json`), read once on first use; empty if the file is missing. */
    val siteFeatures: SiteFeatures by lazy {
        try {
            SiteFeatures.parse(assets.open("site_features.json").use { it.readBytes() }, urlMatcher)
        } catch (e: Exception) {
            SiteFeatures.EMPTY
        }
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
        // Sub-plan 06: a new process has no vault key, so the widget is re-rendered locked at once (no vault read):
        // after a force-stop, a boot or an update, an old code does not stay on screen until the next unlock.
        codesWidget.request()
    }
}
