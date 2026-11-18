package app.localgatekeys.android.unlock

import kotlinx.coroutines.CancellationException

/**
 * The owner check before an action that gives the vault's secrets away (export, earlier passwords, emergency access,
 * the sync rollback, collection sharing, documents, passkey user verification). Audit A1, the same rule as the
 * iPhone's `AppPasswordGate`: with the app password on, the phone's screen lock never passes it. Then only the
 * fingerprint shortcut ([biometric]: a strong biometric that releases the open vault's own key) or the app password
 * ([verifyPassword]: the unlock's wrong-try delay, count and factors) confirms. With the app password off,
 * [deviceCheck] (fingerprint, face or screen lock) decides as before.
 */
class OwnerGate(
    private val passwordOn: () -> Boolean,
    private val deviceCheck: suspend (String) -> Boolean,
    private val biometricShortcut: () -> Boolean,
    private val biometric: suspend (String) -> BiometricAnswer,
    /** Asks for the app password over the screen; null when cancelled or nothing can show it. The gate zeroes it. */
    private val askPassword: suspend (reason: String, problem: String?) -> ByteArray?,
    /** Throws when the password is wrong, the delay runs or a factor is missing; counted like an unlock try. */
    private val verifyPassword: suspend (ByteArray) -> Unit,
    private val stillUnlocked: () -> Boolean,
    /** The message for a failed try; null when the person cancelled (a YubiKey touch). */
    private val problem: (Throwable) -> String?,
    private val wrongPassword: String,
) {
    enum class BiometricAnswer { CONFIRMED, CANCELLED, USE_PASSWORD }

    suspend fun confirm(reason: String): Boolean {
        if (!passwordOn()) return deviceCheck(reason)
        if (!stillUnlocked()) return false
        if (biometricShortcut()) {
            when (biometric(reason)) {
                BiometricAnswer.CONFIRMED -> return stillUnlocked()
                BiometricAnswer.CANCELLED -> return false
                BiometricAnswer.USE_PASSWORD -> {}
            }
        }
        var message: String? = null
        while (true) {
            val password = askPassword(reason, message) ?: return false
            try {
                if (password.isEmpty()) {
                    message = wrongPassword
                    continue
                }
                if (!stillUnlocked()) return false
                verifyPassword(password)
                return stillUnlocked()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                message = problem(e) ?: return false
            } finally {
                password.fill(0)
            }
        }
    }
}
