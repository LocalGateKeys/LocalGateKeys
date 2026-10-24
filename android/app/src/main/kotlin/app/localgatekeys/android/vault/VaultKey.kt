package app.localgatekeys.android.vault

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import javax.crypto.Cipher

/** Why a [VaultKey] operation failed. */
class VaultKeyException(val kind: Kind, message: String = kind.name, cause: Throwable? = null) :
    Exception(message, cause) {
    enum class Kind {
        /** The key was permanently invalidated (screen lock removed or changed). */
        INVALIDATED,

        /** There is no key under the alias. */
        MISSING,

        /** The user has not authenticated (or the 30 s window on API 29 is over). */
        AUTH_REQUIRED,

        /** The device has no secure lock screen, so a key that needs authentication cannot be made. */
        NO_SCREEN_LOCK,

        /** Anything else: malformed wrapped bytes, a Keystore fault. */
        FAILED,
    }
}

/**
 * The hardware-backed key that wraps the 32-byte local key. `wrapped` is `12-byte IV || ciphertext+tag`.
 * On API 30+ the ciphers are what a `BiometricPrompt.CryptoObject` authenticates; on API 29 the prompt runs
 * first and the cipher is used inside the 30 s window.
 */
interface VaultKey {
    fun exists(): Boolean

    /** Generates the key. Throws [VaultKeyException] (FAILED) when one already exists: it is never replaced silently. */
    fun create()

    /** A cipher ready to wrap (ENCRYPT; the Keystore picks the IV). */
    fun cipherForWrap(): Cipher

    /** A cipher ready to unwrap [wrapped] (DECRYPT with the IV in its first 12 bytes). */
    fun cipherForUnwrap(wrapped: ByteArray): Cipher

    /** `IV || ciphertext+tag` of [localKey] (32 bytes) using [cipher] from [cipherForWrap]. The caller keeps and zeroes [localKey]. */
    fun wrap(localKey: ByteArray, cipher: Cipher): ByteArray

    /** The 32-byte local key. The caller owns the returned array and should zero it after use. */
    fun unwrap(wrapped: ByteArray, cipher: Cipher): ByteArray

    fun delete()
}

internal const val WRAP_IV_BYTES = 12
internal const val WRAP_TAG_BITS = 128

/** Maps any Keystore/cipher failure to a [VaultKeyException], looking through the whole cause chain. */
internal object VaultKeyErrors {
    fun map(e: Throwable, what: String): VaultKeyException {
        if (e is VaultKeyException) return e
        var t: Throwable? = e
        var depth = 0
        while (t != null && depth++ < 16) {
            if (t is KeyPermanentlyInvalidatedException) {
                return VaultKeyException(VaultKeyException.Kind.INVALIDATED, "vault key invalidated", e)
            }
            if (t is UserNotAuthenticatedException || isKeystoreUserNotAuthenticated(t)) {
                return VaultKeyException(VaultKeyException.Kind.AUTH_REQUIRED, "authentication required", e)
            }
            if (t is IllegalStateException && t.message?.contains("lock screen", ignoreCase = true) == true) {
                return VaultKeyException(VaultKeyException.Kind.NO_SCREEN_LOCK, "no secure lock screen", e)
            }
            t = if (t.cause === t) null else t.cause
        }
        return VaultKeyException(VaultKeyException.Kind.FAILED, what, e)
    }

    /** `android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED` (public from API 33). */
    private const val ERROR_USER_AUTHENTICATION_REQUIRED = 2

    /** Keymaster/KeyMint `KEY_USER_NOT_AUTHENTICATED`, the raw code of the hidden API 31-32 class. */
    private const val KM_ERROR_KEY_USER_NOT_AUTHENTICATED = -26

    /**
     * API 31+: a `doFinal` on a per-use key without authentication throws `IllegalBlockSizeException` caused by
     * `android.security.KeyStoreException` (KM_ERROR_KEY_USER_NOT_AUTHENTICATED), not UserNotAuthenticatedException.
     * Detected without linking to the class (hidden before API 33): by simple name, then the public
     * `getNumericErrorCode()` (API 33+), the hidden `getErrorCode()` (API 31-32; when reflection is refused it is
     * skipped), and finally the framework's message text.
     */
    internal fun isKeystoreUserNotAuthenticated(t: Throwable): Boolean {
        if (t is java.security.KeyStoreException || t.javaClass.simpleName != "KeyStoreException") return false
        intGetter(t, "getNumericErrorCode")?.let { if (it == ERROR_USER_AUTHENTICATION_REQUIRED) return true }
        intGetter(t, "getErrorCode")?.let { if (it == KM_ERROR_KEY_USER_NOT_AUTHENTICATED) return true }
        return t.message?.contains("user not authenticated", ignoreCase = true) == true
    }

    private fun intGetter(t: Throwable, name: String): Int? = try {
        t.javaClass.getMethod(name).invoke(t) as? Int
    } catch (e: Throwable) {
        null
    }

    /** Runs [block]; any Exception (GeneralSecurityException, ProviderException, ...) becomes a [VaultKeyException]. */
    inline fun <T> translate(what: String, block: () -> T): T = try {
        block()
    } catch (e: Exception) {
        throw map(e, what)
    }
}

/** Shared wrap/unwrap byte handling for [VaultKey] implementations. */
internal object WrapFormat {
    fun wrap(localKey: ByteArray, cipher: Cipher): ByteArray {
        if (localKey.size != 32) throw VaultKeyException(VaultKeyException.Kind.FAILED, "local key must be 32 bytes")
        return VaultKeyErrors.translate("wrap failed") {
            val iv = cipher.iv ?: throw VaultKeyException(VaultKeyException.Kind.FAILED, "cipher has no IV")
            if (iv.size != WRAP_IV_BYTES) throw VaultKeyException(VaultKeyException.Kind.FAILED, "unexpected IV size")
            iv + cipher.doFinal(localKey)
        }
    }

    fun split(wrapped: ByteArray): Pair<ByteArray, ByteArray> {
        if (wrapped.size < WRAP_IV_BYTES + 16) throw VaultKeyException(VaultKeyException.Kind.FAILED, "wrapped key too short")
        return wrapped.copyOfRange(0, WRAP_IV_BYTES) to wrapped.copyOfRange(WRAP_IV_BYTES, wrapped.size)
    }

    fun unwrap(wrapped: ByteArray, cipher: Cipher): ByteArray {
        val (_, ct) = split(wrapped)
        val out = VaultKeyErrors.translate("unwrap failed") { cipher.doFinal(ct) }
        if (out.size != 32) {
            out.fill(0)
            throw VaultKeyException(VaultKeyException.Kind.FAILED, "unwrapped key is not 32 bytes")
        }
        return out
    }
}
