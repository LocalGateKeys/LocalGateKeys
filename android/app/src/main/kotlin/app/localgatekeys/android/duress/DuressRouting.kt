package app.localgatekeys.android.duress

import app.localgatekeys.android.vault.AppPasswordLock
import app.localgatekeys.core.crypto.AppPasswordRecord
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The Settings actions that take the duress path inside a duress session (Ruling T5a-b), apart from the app so the
 * choice is tested: [inDuressSession] is read when the action runs (the open vault is the second one).
 */
class DuressRouting(
    private val inDuressSession: () -> Boolean,
    private val duress: DuressVault,
    private val throttle: AppPasswordLock,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) {
    /**
     * "Change app password": in a duress session only the second vault's password changes ([localKey] is the session's
     * key; throttled like the real change); otherwise [real] runs (the real app password, with its duress checks).
     */
    suspend fun changePassword(localKey: ByteArray, current: String, new: String, real: suspend () -> Unit) {
        if (!inDuressSession()) return real()
        val c = AppPasswordRecord.passwordBytes(current)
        val n = AppPasswordRecord.passwordBytes(new)
        try {
            withContext(io) { duress.changeSecondPassword(localKey, c, n, throttle) }
        } finally {
            c.fill(0); n.fill(0)
        }
    }

    /**
     * Settings > "Erase this phone's vault": in a duress session [lockAndWait] (lock, then this unlock's sync work) and
     * only the second vault's data goes ([DuressVault.eraseSecondVault]); otherwise [real] (the full erase).
     */
    suspend fun erase(lockAndWait: suspend () -> Unit, real: suspend () -> Boolean): Boolean {
        if (!inDuressSession()) return real()
        lockAndWait()
        return withContext(io) { duress.eraseSecondVault() }
    }
}
