package app.localgatekeys.android.unlock

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import androidx.biometric.BiometricPrompt
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.AutoLockDelay
import app.localgatekeys.android.vault.AppPasswordRequiredException
import app.localgatekeys.android.vault.AppPasswordWaitException
import app.localgatekeys.android.vault.BiometricChangedException
import app.localgatekeys.android.vault.LocalStoreException
import app.localgatekeys.core.crypto.AppPasswordException
import app.localgatekeys.core.crypto.AppPasswordRecord
import app.localgatekeys.core.crypto.FactorKind
import app.localgatekeys.core.crypto.FactorMismatchException
import app.localgatekeys.core.crypto.FactorRequiredException
import app.localgatekeys.core.crypto.FactorSpec
import app.localgatekeys.core.crypto.KeyFileException
import app.localgatekeys.core.crypto.RecoveryPhraseException
import app.localgatekeys.android.vault.VaultKeyException
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.sync.ItemStore
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** The part of the secret clipboard a lock needs: clear what we copied, unless something else was copied since. */
interface OwnedClipboard {
    fun clearIfOwned()
}

/**
 * Lock state for the whole app: unlock, lock on background after the chosen delay, lock after the chosen idle time
 * without activity (both from [AppSettings]). A port of `ios/App/Unlock/AppLockModel.swift`.
 *
 * Main thread only (like the iPhone's @MainActor): every call, including the suspend ones, runs on the main thread.
 * Lifecycle mapping: ON_START -> [sceneBecameActive], ON_STOP -> [didEnterBackground].
 *
 * [credentialScreenStopsApp]: true below API 30, where the screen-lock prompt is its own activity (Settings'
 * ConfirmDeviceCredentialActivity) and stops the app while an unlock is in flight; see [didEnterBackground].
 */
class AppLockModel(
    private val unlocker: Unlocker,
    private val clock: UnixClock,
    private val scheduler: LockScheduler,
    private val settings: AppSettings,
    private val clipboard: OwnedClipboard?,
    private val eraser: VaultErasing,
    private val credentialScreenStopsApp: Boolean = false,
    /** Watches for the screen turning off while a system-screen allowance lasts (Ruling 21). */
    private val screenOff: ScreenOffWatching = ScreenOffWatching.NONE,
    /** Time that keeps counting in deep sleep, in ms (the app: `SystemClock.elapsedRealtime`); tests follow [clock]. */
    private val elapsedMillis: () -> Long = { clock.now * 1000 },
    /** Task 7: the app password is on (`app-password.bin` exists). Off: today's unlock, unchanged. */
    private val passwordOn: () -> Boolean = { false },
    /** Task 7: the biometric-only shortcut is set up. */
    private val biometricShortcut: () -> Boolean = { false },
    private val t: Txt,
    /** Task 9: the key file and YubiKey for an app password that needs them (null: none on this build or test). */
    private val factorSource: FactorSource? = null,
    /** Task 9: the factors the app password needs (empty: none). */
    private val factors: () -> List<FactorSpec> = { emptyList() },
    /** Task 9: a recovery-phrase reset dropped the factors (the app turns "Always ask" off). */
    private val onFactorsDropped: () -> Unit = {},
) {
    enum class State { LOCKED, UNLOCKING, UNLOCKED }

    /** The unlock screen asks for a YubiKey in [slot]; [again] after it left the reader mid-answer. */
    data class YubiKeyPrompt(val slot: Int, val again: Boolean)

    private val _state = MutableStateFlow(State.LOCKED)
    val state: StateFlow<State> = _state.asStateFlow()

    private val _vault = MutableStateFlow<UnlockedVault?>(null)
    /** The open vault while unlocked; null otherwise. */
    val vault: StateFlow<UnlockedVault?> = _vault.asStateFlow()
    val store: ItemStore? get() = _vault.value?.store

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    private val _needsPassword = MutableStateFlow(false)
    /** Task 7: the unlock screen shows the app password field (and "Forgot app password?"). */
    val needsPassword: StateFlow<Boolean> = _needsPassword.asStateFlow()

    private val _factorSpecs = MutableStateFlow<List<FactorSpec>>(emptyList())
    /** Task 9: the key file / YubiKey the app password needs; the unlock screen shows their rows. */
    val factorSpecs: StateFlow<List<FactorSpec>> = _factorSpecs.asStateFlow()

    private val _keyFile = MutableStateFlow<KeyFileRef?>(null)
    /** Task 9: the key file the next password try reads (picked, or remembered); null: none chosen. */
    val keyFile: StateFlow<KeyFileRef?> = _keyFile.asStateFlow()

    private val _yubiKeyPrompt = MutableStateFlow<YubiKeyPrompt?>(null)
    /** Task 9: non-null while a YubiKey is awaited (the screen offers Cancel). */
    val yubiKeyPrompt: StateFlow<YubiKeyPrompt?> = _yubiKeyPrompt.asStateFlow()

    private val _notice = MutableStateFlow<String?>(null)
    /** Said once after an unlock (a phrase reset removed the key file / YubiKey); [noticeShown] clears it. */
    val notice: StateFlow<String?> = _notice.asStateFlow()

    /** A key file picked on the unlock screen, remembered after an unlock that used it when [rememberPicked]. */
    private var pickedKeyFile: KeyFileRef? = null
    /** The key-file picker opened from the unlock screen ([willOpenLockedPicker]); consumed by the next background trip. */
    private var lockedPickerTrip = false
    private var rememberPicked = true

    private val _offersStartFresh = MutableStateFlow(false)
    /** The unlock screen shows "Start fresh anyway" (`eraseFailed || vaultUnreadable`). */
    val offersStartFresh: StateFlow<Boolean> = _offersStartFresh.asStateFlow()

    /** The pending erase failed: the unlock screen offers "Start fresh anyway" so no one is locked out for good. */
    var eraseFailed = false
        private set(v) { field = v; _offersStartFresh.value = v || vaultUnreadable }

    /** The vault's files are here but their key is not (or it was invalidated): only Start fresh can help. */
    var vaultUnreadable = false
        private set(v) { field = v; _offersStartFresh.value = eraseFailed || v }

    private var idleTimer: LockTimer? = null
    // Volatile: [lockDeadline] reads them from the widget's background thread. Both are [elapsedMillis] stamps (ms,
    // monotonic in the app), so setting the date back cannot keep the vault open (audit A2).
    @Volatile private var lastActivity = 0L
    @Volatile private var backgroundedAt: Long? = null
    /** Bumped by every lock, so an unlock that was in flight when the lock happened is discarded. */
    private var generation = 0
    /** True while an erase runs: [unlock] returns early so no second erase starts and no vault opens. */
    private var isErasing = false
    /** Prompt the next time the activity starts: at launch and after a real trip to the background. */
    private var promptOnActive = true
    /** [elapsedMillis] when the app opened a system screen of its own (the folder picker), while that allowance lasts. */
    private var systemScreenSince: Long? = null
    private var systemScreenTimer: LockTimer? = null

    suspend fun unlock() {
        if (_state.value != State.LOCKED || isErasing) return
        // An erase that did not finish (failed, or the app was killed during it): finish it first, so a half-wiped
        // vault never opens. The flag is a durable preference, so it survives a relaunch.
        // eraseFailed also covers an erase whose final "done" flag could not be written.
        if (settings.erasePending || eraseFailed) {
            _state.value = State.UNLOCKING; _errorMessage.value = null
            runErase()
            _state.value = State.LOCKED
            if (settings.erasePending || eraseFailed) return
        }
        if (passwordOn()) {
            _needsPassword.value = true
            refreshFactors()
            // No shortcut: no prompt at all, the password field is the only way in (never the screen lock).
            if (!biometricShortcut()) return
        } else {
            _needsPassword.value = false
        }
        attempt(UnlockCredential.System)
    }

    /** Task 7: unlock with the typed app password (Task 9: plus the key file and YubiKey it needs). */
    suspend fun unlockWithPassword(password: String) {
        if (_state.value != State.LOCKED || isErasing || settings.erasePending || eraseFailed) return
        refreshFactors()
        val source = factorSource
        val input = if (_factorSpecs.value.isEmpty() || source == null) null else FactorInput(
            keyFile = { _keyFile.value?.let { source.readKeyFile(it) } },
            yubiKey = { slot, challenge -> askYubiKey(source, slot, challenge) },
        )
        val used = _keyFile.value
        attempt(UnlockCredential.Password(AppPasswordRecord.passwordBytes(password), input)) {
            val picked = pickedKeyFile
            if (source != null && picked != null && picked == used) {
                // Only now, after it worked, is a picked file's grant persisted (and only when it is remembered).
                if (rememberPicked && source.remembers()) source.rememberKeyFile(picked) else source.releaseKeyFile(picked)
            }
            pickedKeyFile = null
        }
    }

    /** Task 9: "Don't remember" is off, so the unlock screen offers "Remember this key file on this phone". */
    fun remembersKeyFile(): Boolean = factorSource?.remembers() ?: false

    /** Task 7: "Forgot app password?": the 24 words and a new app password (already strength-checked by the screen). */
    suspend fun recover(phrase: String, newPassword: String) {
        if (_state.value != State.LOCKED || isErasing || settings.erasePending || eraseFailed) return
        // The phrase opens without the factors and the new password has none (as on Windows): say so once.
        val hadFactors = factors().isNotEmpty()
        attempt(UnlockCredential.Recovery(phrase, AppPasswordRecord.passwordBytes(newPassword))) {
            _factorSpecs.value = emptyList()
            pickedKeyFile?.let { factorSource?.releaseKeyFile(it) }
            pickedKeyFile = null
            _keyFile.value = null
            if (hadFactors) {
                onFactorsDropped()
                _notice.value = t.s(R.string.factors_removed_by_phrase)
            }
        }
    }

    /** Task 9: the key file chosen on the unlock screen for the next try; [remember] keeps it for the next unlocks. */
    fun chooseKeyFile(ref: KeyFileRef, remember: Boolean) {
        pickedKeyFile?.takeIf { it != ref }?.let { factorSource?.releaseKeyFile(it) }
        pickedKeyFile = ref
        rememberPicked = remember
        _keyFile.value = ref
    }

    /** Task 9: stop waiting for the YubiKey (the try ends without a message and is not counted). */
    fun cancelYubiKey() {
        factorSource?.cancelYubiKey()
    }

    /**
     * Task 9: the unlock screen opens the system file picker for the key file. That trip to the background must not
     * prompt again on return (a fingerprint prompt over the screen the person is typing on); the next real trip does.
     */
    fun willOpenLockedPicker() {
        if (_state.value == State.LOCKED) lockedPickerTrip = true
    }

    /** The notice was shown. */
    fun noticeShown() {
        _notice.value = null
    }

    /**
     * Task 9: an autofill or passkey sheet must not unlock by itself when the app password needs a key file or YubiKey
     * (the picker and the NFC reader belong to the app): it says "Open LocalGateKeys to unlock" instead.
     */
    fun sheetDefersToApp(): Boolean = _state.value != State.UNLOCKED && passwordOn() && factors().isNotEmpty()

    private fun refreshFactors() {
        _factorSpecs.value = factors()
        if (_factorSpecs.value.none { it.kind == FactorKind.KEYFILE }) {
            _keyFile.value = null
            pickedKeyFile?.let { factorSource?.releaseKeyFile(it) }
            pickedKeyFile = null
        } else if (_keyFile.value == null) {
            _keyFile.value = factorSource?.rememberedKeyFile()
        }
    }

    /** The YubiKey's answer; a key that left the reader mid-answer is asked again ("Touch your YubiKey again"). */
    private suspend fun askYubiKey(source: FactorSource, slot: Int, challenge: ByteArray): ByteArray = try {
        askYubiKeyWithRetries(YUBIKEY_TRIES, { again -> _yubiKeyPrompt.value = YubiKeyPrompt(slot, again) }) {
            source.yubiKey(slot, challenge)
        }
    } finally {
        _yubiKeyPrompt.value = null
    }

    private suspend fun attempt(credential: UnlockCredential, onSuccess: () -> Unit = {}) {
        _state.value = State.UNLOCKING; _errorMessage.value = null; vaultUnreadable = false
        val started = generation
        val opened = try {
            if (credential == UnlockCredential.System) unlocker.unlock(t.s(R.string.unlock_reason)) else unlocker.unlock(t.s(R.string.unlock_reason), credential)
        } catch (e: CancellationException) {
            if (generation == started && _state.value == State.UNLOCKING) _state.value = State.LOCKED
            throw e
        } catch (e: Exception) {
            if (generation != started) return
            _state.value = State.LOCKED; _vault.value = null
            _errorMessage.value = message(e, t)
            vaultUnreadable = isVaultWithoutKey(e)
            if (e is AppPasswordRequiredException || e is BiometricChangedException || e is AppPasswordException ||
                e is AppPasswordWaitException || e is RecoveryPhraseException || passwordOn()
            ) {
                _needsPassword.value = true
            }
            return
        }
        if (generation != started || _state.value != State.UNLOCKING) { // a lock won: shut only this late vault
            unlocker.discard(opened)
            return
        }
        _vault.value = opened
        _state.value = State.UNLOCKED
        _needsPassword.value = false
        onSuccess()
        noteActivity()
    }

    /** The activity started. Prompts only at launch and on return from the background; checks the deadlines first. */
    suspend fun sceneBecameActive() {
        willEnterForeground()
        if (!promptOnActive) return
        promptOnActive = false
        if (_state.value == State.LOCKED) unlock()
    }

    /**
     * Dropping the vault is what drops the decoded records: screens that hold them exist only while unlocked.
     *
     * [clearClipboard] false: a lock because the app left the screen keeps what was just copied, since the person
     * left to paste it somewhere else. The copy still expires on its own timer.
     */
    fun lock(clearClipboard: Boolean = true) {
        factorSource?.cancelYubiKey()
        idleTimer?.cancel(); idleTimer = null; backgroundedAt = null
        endSystemScreen()
        if (_state.value == State.LOCKED) return
        generation += 1
        _vault.value = null; _state.value = State.LOCKED
        if (clearClipboard) clipboard?.clearIfOwned()
        unlocker.lock()
    }

    /**
     * "Erase this phone's vault": locks first (whatever happens next), waits for work that could still write
     * ([afterLock]: sync), then erases. A failure shows on the unlock screen and is retried before the next unlock.
     */
    suspend fun eraseAndLock(afterLock: suspend () -> Unit = {}): Boolean {
        isErasing = true
        try {
            lock()
            // Before anything is deleted: a crash mid-erase leaves it set. Not known to be on disk: erase nothing.
            if (!markErasePending()) return false
            afterLock()
            return runErase()
        } finally {
            isErasing = false
        }
    }

    /** Durably sets the erase flag; false (and a message) when the preference could not be written. */
    private fun markErasePending(): Boolean = try {
        settings.erasePending = true
        true
    } catch (e: Exception) {
        _errorMessage.value = t.s(ERASE_NOT_STARTED_MESSAGE)
        false
    }

    private suspend fun runErase(): Boolean {
        try {
            eraser.erase()
            settings.erasePending = false // cleared only on success (a failed write is a failed erase: retried)
            _errorMessage.value = null; eraseFailed = false
            return true
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            _errorMessage.value = (e as? VaultEraseFailure)?.text(t) ?: t.s(ERASE_FAILED_MESSAGE)
            eraseFailed = true
            return false
        }
    }

    /**
     * "Start fresh anyway" (after two confirmations): one more erase attempt, then the pending flag is cleared
     * whatever it left behind, so the next unlock is a first run.
     *
     * For a vault whose key is missing ([vaultUnreadable]) it is a normal erase instead: pending until it succeeds,
     * so a failure continues in the erase flow above (retry on Unlock, then Start fresh anyway).
     */
    suspend fun startFreshAnyway() {
        if (vaultUnreadable && !settings.erasePending && _state.value == State.LOCKED && !isErasing) {
            isErasing = true
            try {
                _state.value = State.UNLOCKING
                // vaultUnreadable is cleared only by an erase that ran and succeeded.
                if (markErasePending()) {
                    runErase()
                    if (!eraseFailed) vaultUnreadable = false
                }
                _state.value = State.LOCKED
            } finally {
                isErasing = false
            }
            return
        }
        if (_state.value != State.LOCKED || isErasing || !(settings.erasePending || eraseFailed)) return
        isErasing = true
        try {
            _state.value = State.UNLOCKING
            try {
                eraser.erase()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // Whatever could not be deleted stays but is no longer used.
            }
            try {
                settings.erasePending = false
                _errorMessage.value = null; eraseFailed = false; vaultUnreadable = false
            } catch (e: Exception) {
                _errorMessage.value = t.s(ERASE_FAILED_MESSAGE); eraseFailed = true
            }
            _state.value = State.LOCKED
        } finally {
            isErasing = false
        }
    }

    /**
     * While unlocked: the Unix second at which the vault counts as locked for anything shown outside the app (the
     * pinned-codes widget): the background auto-lock deadline or the idle limit, whichever comes first;
     * [Long.MAX_VALUE] when neither applies. Null while locked. The lock itself is checked only when the app returns
     * to the front, so what is shown outside it must stop at this time on its own.
     */
    fun lockDeadline(): Long? {
        if (_state.value != State.UNLOCKED) return null
        // Worked out afresh on every call from monotonic time left, then put on today's wall clock; 0 once expired
        // (or when the elapsed time cannot be trusted), so callers comparing "now < deadline" show nothing.
        val now = elapsedMillis()
        var left = Long.MAX_VALUE
        backgroundedAt?.let { left = minOf(left, remainingSeconds(it, settings.autoLockDelay.seconds, now)) }
        settings.idleLock.limit?.let { left = minOf(left, remainingSeconds(lastActivity, it, now)) }
        if (left == Long.MAX_VALUE) return Long.MAX_VALUE
        return if (left <= 0) 0L else clock.now + left
    }

    /** Whole seconds of [limitSeconds] left since the [since] stamp; 0 when past it or when time ran backwards. */
    private fun remainingSeconds(since: Long, limitSeconds: Long, now: Long): Long {
        val gone = now - since
        if (gone < 0) return 0
        return maxOf(0L, limitSeconds - gone / 1000)
    }

    /** True when [limitSeconds] have passed since the [since] stamp, or the difference is negative (unknown: expired). */
    private fun expiredSince(since: Long, limitSeconds: Long): Boolean {
        val gone = elapsedMillis() - since
        return gone < 0 || gone >= limitSeconds * 1000
    }

    /**
     * The wall clock was changed (`ACTION_TIME_CHANGED`): the limits run on monotonic time and are unaffected, but a
     * background limit already passed locks now rather than at the next return.
     */
    fun wallClockChanged() {
        if (_state.value != State.UNLOCKED) return
        val since = backgroundedAt
        if (since != null && expiredSince(since, settings.autoLockDelay.seconds)) lock(clearClipboard = false)
        else if (idleExpired) lock()
    }

    /** Any touch or edit. Restarts the idle timer (none when the setting is Never). */
    fun noteActivity() {
        if (_state.value != State.UNLOCKED) return
        lastActivity = elapsedMillis()
        idleTimer?.cancel(); idleTimer = null
        val timeout = settings.idleLock.limit ?: return
        idleTimer = scheduler.schedule(timeout) { idleTimerFired() }
    }

    private val idleExpired: Boolean
        get() {
            val timeout = settings.idleLock.limit ?: return false
            return expiredSince(lastActivity, timeout)
        }

    private fun idleTimerFired() {
        if (_state.value == State.UNLOCKED && idleExpired) lock()
    }

    /**
     * Ruling 21: the app is about to open a system screen of its own on top (the system folder picker). That screen
     * stops the app, but the trip does not count for the "Immediately" auto-lock (the iPhone's picker is in-app); every
     * other auto-lock delay, the idle limit and manual lock still apply. The allowance is single-use and ends at the
     * return ([systemScreenClosed] / foreground), on a lock, or after [SYSTEM_SCREEN_LIMIT_SECONDS] of elapsed time
     * (then the vault locks and prompts on return). The screen turning off during the trip locks at once.
     */
    fun willOpenSystemScreen() {
        if (_state.value != State.UNLOCKED) return
        endSystemScreen()
        systemScreenSince = elapsedMillis()
        // A Handler timer stops in deep sleep: it only locks earlier while awake; the elapsed check on return decides.
        systemScreenTimer = scheduler.schedule(SYSTEM_SCREEN_LIMIT_SECONDS) { if (systemScreenExpired()) lockFromTrip() }
        screenOff.start { if (systemScreenSince != null && _state.value == State.UNLOCKED) lockFromTrip() }
    }

    /**
     * The system screen handed its result back (possibly before the activity is active again). Ends the allowance and
     * checks it, and the auto-lock delay, at once. True when the vault is still unlocked, so the result may be used;
     * false (locked, prompting on return): the caller drops the result.
     */
    fun systemScreenClosed(): Boolean {
        if (_state.value != State.UNLOCKED) {
            endSystemScreen()
            return false
        }
        if (systemScreenSince != null) {
            val expired = systemScreenExpired()
            endSystemScreen()
            if (expired) {
                lockFromTrip()
                return false
            }
        }
        val since = backgroundedAt
        if (since != null && expiredSince(since, settings.autoLockDelay.seconds)) {
            lockFromTrip()
            return false
        }
        return true
    }

    private fun systemScreenExpired(): Boolean {
        val since = systemScreenSince ?: return false
        return elapsedMillis() - since >= SYSTEM_SCREEN_LIMIT_SECONDS * 1000
    }

    /** A lock during or at the end of a system-screen trip: the next activity start prompts. */
    private fun lockFromTrip() {
        promptOnActive = true
        lock(clearClipboard = false)
    }

    private fun endSystemScreen() {
        systemScreenTimer?.cancel(); systemScreenTimer = null
        if (systemScreenSince != null) screenOff.stop()
        systemScreenSince = null
    }

    fun didEnterBackground() {
        if (lockedPickerTrip) {
            lockedPickerTrip = false
            if (_state.value == State.LOCKED) return
        }
        // A system screen the app opened itself (folder picker) is exempt from the "Immediately" rule only (Ruling 21);
        // other delays count the trip as usual.
        if (systemScreenSince != null && _state.value == State.UNLOCKED && settings.autoLockDelay == AutoLockDelay.IMMEDIATELY) return
        // Below API 30 the screen-lock screen is its own activity and stops the app during the prompt; that trip
        // must not prompt again on return, or a cancel would loop. (A real trip during the prompt cancels it, and
        // the Unlock button stays.) From API 30 the prompt is a system dialog: the iPhone rule applies as is.
        if (!(credentialScreenStopsApp && _state.value == State.UNLOCKING)) promptOnActive = true
        if (_state.value != State.UNLOCKED) return
        if (settings.autoLockDelay == AutoLockDelay.IMMEDIATELY) {
            lock(clearClipboard = false)
            return
        }
        backgroundedAt = elapsedMillis()
    }

    /** Timers do not run while the app is stopped (or the process sleeps): checks both limits here. */
    fun willEnterForeground() {
        if (_state.value != State.UNLOCKED) return
        if (systemScreenSince != null) {
            val expired = systemScreenExpired()
            endSystemScreen() // one trip only
            if (expired) {
                lockFromTrip()
                return
            }
        }
        val since = backgroundedAt
        if (since != null && expiredSince(since, settings.autoLockDelay.seconds)) {
            lock(clearClipboard = false)
            return
        }
        if (idleExpired) {
            lock()
            return
        }
        backgroundedAt = null
        noteActivity()
    }

    companion object {
        /** Ruling 21: how long a system screen the app opened (the folder picker) may stay on top before the vault locks. */
        const val SYSTEM_SCREEN_LIMIT_SECONDS = 120L

        /** A YubiKey that leaves the reader mid-answer is asked this many times in one try. */
        const val YUBIKEY_TRIES = 3

        @StringRes val VAULT_WITHOUT_KEY_MESSAGE = R.string.unlock_vault_without_key
        @StringRes val BIOMETRY_LOCKOUT_MESSAGE = R.string.unlock_biometry_lockout
        @StringRes val START_FRESH_CONFIRM_1 = R.string.unlock_start_fresh_1
        @StringRes val START_FRESH_CONFIRM_2 = R.string.unlock_start_fresh_2

        /** The erase flag could not be saved, so nothing was deleted (Android only: durable preference writes can fail). */
        @StringRes val ERASE_NOT_STARTED_MESSAGE = R.string.unlock_erase_not_started
        @StringRes val ERASE_FAILED_MESSAGE = R.string.unlock_erase_failed
        @StringRes val WRONG_PASSWORD_MESSAGE = R.string.unlock_wrong_password

        /** The recovery phrase opens the same damaged file, so it cannot help here. */
        @StringRes val MALFORMED_MESSAGE = R.string.unlock_password_file_damaged
        @StringRes val WRONG_PHRASE_MESSAGE = R.string.unlock_wrong_phrase
        @StringRes val BIOMETRIC_CHANGED_MESSAGE = R.string.unlock_biometric_changed

        fun waitMessage(seconds: Long, t: Txt): String =
            if (seconds >= 120) {
                val minutes = ((seconds + 59) / 60).toInt()
                t.plural(R.plurals.unlock_wait_minutes, minutes, minutes)
            } else {
                t.plural(R.plurals.unlock_wait_seconds, seconds.toInt(), seconds)
            }

        @StringRes private val PASSCODE_NOT_SET = R.string.unlock_no_screen_lock
        @StringRes private val GENERIC = R.string.unlock_generic

        /** The vault's files cannot be opened with any key this phone still has: offer Start fresh. */
        fun isVaultWithoutKey(e: Throwable): Boolean = when (e) {
            is LocalStoreException -> e.kind == LocalStoreException.Kind.VAULT_WITHOUT_KEY
            is VaultKeyException -> e.kind == VaultKeyException.Kind.INVALIDATED || e.kind == VaultKeyException.Kind.MISSING
            // A damaged app password file: neither the password nor the phrase can open it.
            is AppPasswordException -> e.kind == AppPasswordException.Kind.MALFORMED
            else -> false
        }

        /** What the unlock screen says after a failed unlock; null when the person cancelled (the Unlock button stays). */
        fun message(e: Throwable, t: Txt): String? = when (e) {
            is AppPasswordRequiredException -> null
            is app.localgatekeys.android.duress.DuressException -> app.localgatekeys.android.duress.DuressText.message(e, t)
            is FactorRequiredException -> t.s(
                when {
                    FactorKind.KEYFILE in e.kinds && FactorKind.YUBIKEY_HMAC in e.kinds -> R.string.factors_required_both
                    FactorKind.KEYFILE in e.kinds -> R.string.factors_required_keyfile
                    else -> R.string.factors_required_yubikey
                },
            )
            is FactorMismatchException -> t.s(
                if (e.kind == FactorKind.KEYFILE) R.string.factors_keyfile_mismatch else R.string.factors_yubikey_mismatch,
            )
            is KeyFileException -> t.s(R.string.factors_keyfile_invalid)
            is FactorSettingsException -> t.s(
                when (e.reason) {
                    FactorSettingsException.Reason.NEEDS_FACTOR -> R.string.factors_always_ask_needs_factor
                    FactorSettingsException.Reason.ALWAYS_ASK_ON -> R.string.factors_shortcuts_off
                },
            )
            is KeyFileUnreadableException ->
                if (e.tooLarge) t.s(R.string.factors_keyfile_too_large) else t.s(R.string.factors_keyfile_unreadable, e.name)
            is YubiKeyException -> when (e.code) {
                YubiKeyException.Code.CANCELLED -> null
                YubiKeyException.Code.REMOVED -> t.s(R.string.factors_yubikey_removed)
                YubiKeyException.Code.TIMEOUT -> t.s(R.string.factors_yubikey_timeout)
                YubiKeyException.Code.SLOT_NOT_CONFIGURED -> t.s(R.string.factors_yubikey_slot_not_configured, e.slot)
                YubiKeyException.Code.BAD_ANSWER -> t.s(R.string.factors_yubikey_bad_answer, e.slot)
                YubiKeyException.Code.NO_TRANSPORT -> t.s(R.string.factors_yubikey_no_transport)
            }
            is BiometricChangedException -> t.s(BIOMETRIC_CHANGED_MESSAGE)
            is AppPasswordWaitException -> waitMessage(e.seconds, t)
            is AppPasswordException -> when (e.kind) {
                AppPasswordException.Kind.WRONG_PASSWORD -> t.s(WRONG_PASSWORD_MESSAGE)
                AppPasswordException.Kind.WRONG_PHRASE -> t.s(WRONG_PHRASE_MESSAGE)
                AppPasswordException.Kind.MALFORMED -> t.s(MALFORMED_MESSAGE)
            }
            is RecoveryPhraseException -> t.s(
                when (e.reason) {
                    RecoveryPhraseException.Reason.WORD_LIST_MISSING -> R.string.recovery_word_list_missing
                    RecoveryPhraseException.Reason.WORD_LIST_DAMAGED -> R.string.recovery_word_list_damaged
                    RecoveryPhraseException.Reason.BAD_ENTROPY -> R.string.recovery_bad_entropy
                    RecoveryPhraseException.Reason.MALFORMED -> R.string.recovery_malformed
                    RecoveryPhraseException.Reason.WRONG_WORD_COUNT -> R.string.recovery_wrong_word_count
                    RecoveryPhraseException.Reason.UNKNOWN_WORD -> R.string.recovery_unknown_word
                    RecoveryPhraseException.Reason.CHECKSUM -> R.string.recovery_checksum
                },
            )
            is AuthenticationException -> when (e.code) {
                BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_CANCELED -> null
                BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> t.s(PASSCODE_NOT_SET)
                BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> t.s(BIOMETRY_LOCKOUT_MESSAGE)
                else -> t.s(R.string.unlock_auth_error, e.code)
            }
            is VaultKeyException -> when (e.kind) {
                VaultKeyException.Kind.NO_SCREEN_LOCK -> t.s(PASSCODE_NOT_SET)
                VaultKeyException.Kind.INVALIDATED, VaultKeyException.Kind.MISSING -> t.s(VAULT_WITHOUT_KEY_MESSAGE)
                VaultKeyException.Kind.AUTH_REQUIRED, VaultKeyException.Kind.FAILED -> t.s(R.string.unlock_key_read_failed)
            }
            is LocalStoreException -> when (e.kind) {
                LocalStoreException.Kind.NO_LOCAL_KEY -> t.s(R.string.unlock_local_key_missing)
                LocalStoreException.Kind.BAD_LOCAL_KEY -> t.s(R.string.unlock_local_key_damaged)
                LocalStoreException.Kind.VAULT_WITHOUT_KEY -> t.s(VAULT_WITHOUT_KEY_MESSAGE)
                LocalStoreException.Kind.CORRUPT -> t.s(R.string.unlock_vault_damaged)
                LocalStoreException.Kind.IO -> t.s(R.string.unlock_vault_io)
                LocalStoreException.Kind.STALE -> t.s(GENERIC)
            }
            else -> t.s(GENERIC)
        }
    }
}
