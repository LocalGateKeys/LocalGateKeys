package app.localgatekeys.android.sync

import app.localgatekeys.android.unlock.UnlockedVault
import app.localgatekeys.android.unlock.Unlocker

/**
 * One [SyncCoordinator] per unlock (the iPhone's `UnlockedRoot` keeps one per unlocked store). It outlives
 * recompositions and a recreated activity, and the lock shuts it down before the vault's own write gates close:
 * [wrap] puts that step in front of the real unlocker's `lock()`. Main thread only.
 */
class SyncSessions(private val factory: (UnlockedVault) -> SyncCoordinator) {
    private var session: Pair<UnlockedVault, SyncCoordinator>? = null
    private var appOpened = false

    /** The coordinator of the open session, if any. */
    val current: SyncCoordinator? get() = session?.second

    /**
     * The coordinator for [vault]; another vault's session is shut down first. A vault whose session [end] closed (the
     * lock came between the unlock's IO hops and this call) only ever gets that shut-down coordinator back, never a new
     * one: nothing reads, syncs or commits for a closed vault.
     */
    fun forVault(vault: UnlockedVault): SyncCoordinator {
        session?.let { (v, c) -> if (v === vault) return c else c.shutdown() }
        ended?.let { (v, c) -> if (v === vault) return c }
        appOpened = false
        ending = null
        ended = null
        return factory(vault).also { session = vault to it }
    }

    /** The unlock's sync (trigger APP_OPEN), once per session: a recreated activity does not run it again. */
    suspend fun appOpen(vault: UnlockedVault) {
        val c = forVault(vault)
        if (appOpened || session?.second !== c) return // ended: the lock came first
        appOpened = true
        c.sync(SyncCoordinator.Trigger.APP_OPEN)
    }

    /** The coordinator [end] shut down last, until [endAndWait] has waited for it. */
    private var ending: SyncCoordinator? = null

    /** The last ended session, kept until the next vault's: [forVault] gives that vault its shut-down coordinator. */
    private var ended: Pair<UnlockedVault, SyncCoordinator>? = null

    /** The vault locked (or is being erased): nothing syncs after this. */
    fun end() {
        session?.let { (v, c) ->
            c.shutdown()
            ending = c
            ended = v to c
        }
        session = null
    }

    /**
     * [end], then waits for the sync work that was in flight (a run, join, leave or reset still finishing its blocking
     * step) to stop: "Erase this phone's vault" deletes the files only after this (the iPhone's `shutdownAndWait`).
     * The lock that comes first already ended the session; this waits for that coordinator.
     */
    suspend fun endAndWait() {
        val c = session?.second ?: ending
        session = null
        ending = null
        c?.shutdownAndWait()
    }

    /** [inner] with the session ended first on every lock. */
    fun wrap(inner: Unlocker): Unlocker = object : Unlocker by inner {
        override fun lock() {
            end()
            inner.lock()
        }
    }
}
