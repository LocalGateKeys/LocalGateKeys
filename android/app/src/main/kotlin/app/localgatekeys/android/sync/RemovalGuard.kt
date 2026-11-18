package app.localgatekeys.android.sync

import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.sync.Removal
import app.localgatekeys.core.sync.RemovalNotice
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Erase on removal (desktop `app/device_removal.RemovalGuard`): when another member removed this phone from the cloud
 * folder group and signed that (a verified removal notice, core [Removal.check]), the vault is erased if "Erase this
 * device if it is removed from sync" is on. The inferred issues (`removed-or-conflict`, `rejoin-required`...) never
 * get here.
 *
 * It reads the watch file, so it works while the vault is locked: at app start and whenever the app comes to the
 * front (at most every [INTERVAL_SECONDS]), and at once after a folder run reported `removal-notice`. While locked the
 * sealed install id cannot be read, so the watch's own install id is used: the watch file lives in this installation's
 * private storage (no Android backup or device transfer copies it, an uninstall deletes it), and a folder run on
 * another installation never writes it (`install-mismatch` stops before).
 *
 * Exported backups (files saved through the system picker, phone backups) are never touched: [erase] is the vault
 * erase, which removes only this app's own data.
 */
class RemovalGuard(
    private val settings: AppSettings,
    private val watch: RemovalWatchFile,
    private val folders: FolderOpening,
    /** The app: lock, end this unlock's sync work, erase (`AppLockModel.eraseAndLock`); true only when the erase finished. */
    private val erase: suspend () -> Boolean,
    private val clock: UnixClock,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) {
    enum class Outcome {
        /** No verified notice (or not checked: too soon after the last check). */
        NONE,

        /** Verified; the setting is on and the erase ran. */
        ERASED,

        /** Verified, but the setting is off: the vault stays (the Sync screen says the phone was removed). */
        KEPT,

        /** Verified and the setting is on, but the erase did not finish (retried at the next check). */
        FAILED,
    }

    private val mutex = Mutex()
    private val _erasures = MutableStateFlow(0)

    /** Counts the erases this guard ran (the one-time notice re-reads its flag when it changes). */
    val erasures: StateFlow<Int> = _erasures.asStateFlow()
    private var lastCheck: Long? = null

    /** The verified notice for this phone, or null. Never throws. [opened] is set once the folder could be opened. */
    internal fun verified(installId: String?, opened: BooleanArray? = null): RemovalNotice? = try {
        val w = watch.load()
        if (w == null) {
            opened?.set(0, true)
            null
        } else {
            val folder = folders.open(w.folder)
            opened?.set(0, true)
            Removal.check(w, installId ?: w.installId, folder)
        }
    } catch (e: Exception) {
        null
    }

    /**
     * Checks the watch file and erases on a verified notice when the setting is on. [force]: check even if the last
     * check was less than [INTERVAL_SECONDS] ago (a folder run just reported `removal-notice`). [installId]: the sealed
     * install id when the vault is open.
     */
    suspend fun check(force: Boolean = false, installId: String? = null): Outcome = mutex.withLock {
        val now = clock.now
        val last = lastCheck
        if (!force && last != null && now >= last && now - last < INTERVAL_SECONDS) return@withLock Outcome.NONE
        val opened = BooleanArray(1)
        val notice = withContext(io) { verified(installId, opened) }
        // Only a check that got as far as the folder counts: a transient provider error is retried at the next one.
        lastCheck = if (opened[0]) now else null
        if (notice == null) return@withLock Outcome.NONE
        if (!settings.eraseOnSyncRemoval) return@withLock Outcome.KEPT
        if (!erase()) {
            lastCheck = null // keep retrying at the next check
            return@withLock Outcome.FAILED
        }
        try {
            // shown once after the erase (it survives the erase); information only
            withContext(io) { settings.deviceErasedNotice = true }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // the notice is information only
        }
        _erasures.value += 1
        Outcome.ERASED
    }

    companion object {
        /** Desktop: every 5 minutes. */
        const val INTERVAL_SECONDS = 300L
    }
}
