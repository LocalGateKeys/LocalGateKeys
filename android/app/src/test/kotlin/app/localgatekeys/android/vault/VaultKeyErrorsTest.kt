package app.localgatekeys.android.vault

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.ProviderException
import javax.crypto.IllegalBlockSizeException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The Keystore failure mapping, with synthetic exception chains (the real ones come from the framework). */
class VaultKeyErrorsTest {
    private fun kind(e: Throwable) = VaultKeyErrors.map(e, "x").kind

    @Test fun invalidation_is_found_anywhere_in_the_chain() {
        assertEquals(VaultKeyException.Kind.INVALIDATED, kind(KeyPermanentlyInvalidatedException()))
        assertEquals(
            VaultKeyException.Kind.INVALIDATED,
            kind(IllegalBlockSizeException("x").initCause(KeyPermanentlyInvalidatedException())),
        )
        assertEquals(
            VaultKeyException.Kind.INVALIDATED,
            kind(GeneralSecurityException("a", IllegalBlockSizeException("b").also { it.initCause(KeyPermanentlyInvalidatedException()) })),
        )
    }

    @Test fun missing_authentication_is_found_anywhere_in_the_chain() {
        assertEquals(VaultKeyException.Kind.AUTH_REQUIRED, kind(UserNotAuthenticatedException()))
        assertEquals(
            VaultKeyException.Kind.AUTH_REQUIRED,
            kind(IllegalBlockSizeException("x").initCause(UserNotAuthenticatedException())),
        )
        assertEquals(
            VaultKeyException.Kind.AUTH_REQUIRED,
            kind(ProviderException("p", GeneralSecurityException("g", UserNotAuthenticatedException()))),
        )
    }

    @Test fun lock_screen_state_error_wrapped_in_invalid_algorithm_parameters_is_no_screen_lock() {
        val ise = IllegalStateException("Secure lock screen must be enabled to create keys requiring user authentication")
        val wrapped = InvalidAlgorithmParameterException(ise)
        assertEquals(VaultKeyException.Kind.NO_SCREEN_LOCK, kind(wrapped))
        assertEquals(VaultKeyException.Kind.NO_SCREEN_LOCK, kind(ise))
        assertEquals(VaultKeyException.Kind.FAILED, kind(IllegalStateException("something else")))
    }

    @Test fun provider_and_other_runtime_exceptions_are_failed_never_escaping() {
        assertEquals(VaultKeyException.Kind.FAILED, kind(ProviderException("Keystore key generation failed")))
        assertEquals(VaultKeyException.Kind.FAILED, kind(RuntimeException("boom")))
        assertEquals(VaultKeyException.Kind.FAILED, kind(GeneralSecurityException("bad tag")))
        try {
            VaultKeyErrors.translate("op") { throw ProviderException("Keystore key generation failed") }
            fail()
        } catch (e: VaultKeyException) {
            assertEquals(VaultKeyException.Kind.FAILED, e.kind)
            assertTrue(e.cause is ProviderException)
        }
    }

    @Test fun a_vault_key_exception_passes_through_unchanged_and_cycles_terminate() {
        val v = VaultKeyException(VaultKeyException.Kind.MISSING)
        assertSame(v, VaultKeyErrors.map(v, "x"))
        val a = RuntimeException("a")
        val b = RuntimeException("b", a)
        a.initCause(b)
        assertEquals(VaultKeyException.Kind.FAILED, kind(b))
    }

    /**
     * API 31+: a doFinal without authentication throws IllegalBlockSizeException caused by
     * android.security.KeyStoreException (KM_ERROR_KEY_USER_NOT_AUTHENTICATED); API 33 made the class public with
     * getNumericErrorCode() == ERROR_USER_AUTHENTICATION_REQUIRED (2). Synthetic stand-ins with the same simple name.
     */
    @Test fun keystore_exception_user_not_authenticated_is_auth_required() {
        assertEquals(
            VaultKeyException.Kind.AUTH_REQUIRED,
            kind(IllegalBlockSizeException("x").initCause(Api33.KeyStoreException(2, "Key user not authenticated"))),
        )
        assertEquals(
            VaultKeyException.Kind.AUTH_REQUIRED,
            kind(IllegalBlockSizeException("x").initCause(Api31.KeyStoreException(-26, "internal Keystore code: -26"))),
        )
        // Hidden getter unavailable: the framework message still says so.
        assertEquals(
            VaultKeyException.Kind.AUTH_REQUIRED,
            kind(IllegalBlockSizeException("x").initCause(Bare.KeyStoreException("Key user not authenticated (internal Keystore code: -26)"))),
        )
    }

    @Test fun other_keystore_exceptions_stay_failed() {
        assertEquals(VaultKeyException.Kind.FAILED, kind(IllegalBlockSizeException("x").initCause(Api33.KeyStoreException(4, "internal"))))
        assertEquals(VaultKeyException.Kind.FAILED, kind(IllegalBlockSizeException("x").initCause(Api31.KeyStoreException(-30, "other"))))
        assertEquals(VaultKeyException.Kind.FAILED, kind(java.security.KeyStoreException("user not authenticated")))
        assertEquals(VaultKeyException.Kind.FAILED, kind(Bare.KeyStoreException("Keystore operation failed")))
    }

    @Test fun debuggable_flag_detection() {
        assertTrue(KeystoreVaultKey.isDebuggable(2))
        assertTrue(KeystoreVaultKey.isDebuggable(0x1003))
        assertFalse(KeystoreVaultKey.isDebuggable(0))
        assertFalse(KeystoreVaultKey.isDebuggable(0x1001))
    }
}

/** API 33+ shape of android.security.KeyStoreException. */
object Api33 {
    class KeyStoreException(private val code: Int, message: String) : Exception(message) {
        fun getNumericErrorCode(): Int = code
    }
}

/** API 31-32 shape (hidden class, raw Keystore error code). */
object Api31 {
    class KeyStoreException(private val code: Int, message: String) : Exception(message) {
        fun getErrorCode(): Int = code
    }
}

/** No readable code at all. */
object Bare {
    class KeyStoreException(message: String) : Exception(message)
}
