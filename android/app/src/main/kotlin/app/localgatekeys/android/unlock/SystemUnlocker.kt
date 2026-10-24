package app.localgatekeys.android.unlock

import android.os.Build
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.vault.VaultKey
import app.localgatekeys.core.primitives.RandomSource
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

/**
 * The real [Unlocker]: the screen-lock prompt (fingerprint, face or screen lock) through `BiometricPrompt`, then
 * [VaultOpener] with the Keystore key. API 30+: the per-use key's cipher is authorised by the prompt as a
 * CryptoObject; API 29: the prompt runs first and the time-bound key is used inside its 30 s window.
 *
 * [activity] returns the activity to show the prompt in (the app keeps the current one; null when none is started).
 */
class SystemUnlocker private constructor(inner: VaultUnlocker) : Unlocker by inner {
    constructor(activity: () -> FragmentActivity?, vaultKey: VaultKey, dirs: VaultDirs, random: RandomSource, settings: AppSettings?) :
        this(
            VaultUnlocker(
                VaultOpener(dirs, vaultKey, random, settings, cryptoBound = Build.VERSION.SDK_INT >= 30),
                BiometricAuthenticator(activity),
            ),
        )
}

/**
 * [Authenticator] over androidx `BiometricPrompt`: `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` on API 30+. On API 29
 * that combination is not supported by the library (and a CryptoObject cannot be used with the screen lock), so it
 * asks for `BIOMETRIC_WEAK or DEVICE_CREDENTIAL` without a CryptoObject; the Keystore key itself still only accepts
 * a strong biometric or the screen lock within its 30 s window.
 */
class BiometricAuthenticator(private val activity: () -> FragmentActivity?) : Authenticator {
    private var prompt: BiometricPrompt? = null

    override suspend fun authenticate(reason: String, cipher: Cipher?): Cipher? = withContext(Dispatchers.Main.immediate) {
        val act = activity()?.takeIf { it.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) }
            ?: throw AuthenticationException(BiometricPrompt.ERROR_CANCELED, "no started activity to prompt in")
        suspendCancellableCoroutine { cont ->
            val executor = ContextCompat.getMainExecutor(act)
            var observer: LifecycleEventObserver? = null
            var self: BiometricPrompt? = null
            fun finish(block: () -> Unit) {
                if (prompt === self) prompt = null // never forget a newer unlock's prompt
                observer?.let { act.lifecycle.removeObserver(it) }
                observer = null
                if (cont.isActive) block()
            }
            val p = BiometricPrompt(act, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) =
                    finish { cont.resume(result.cryptoObject?.cipher) }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) =
                    finish { cont.resumeWithException(AuthenticationException(errorCode)) }
                // onAuthenticationFailed: one rejected attempt; the prompt stays up for another.
            })
            self = p
            // The activity going away for good ends the prompt (a configuration change does not recreate it: see the manifest).
            observer = LifecycleEventObserver { _, e ->
                if (e == Lifecycle.Event.ON_DESTROY) {
                    p.cancelAuthentication()
                    finish { cont.resumeWithException(AuthenticationException(BiometricPrompt.ERROR_CANCELED)) }
                }
            }.also { act.lifecycle.addObserver(it) }
            prompt = p
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(reason)
                .setAllowedAuthenticators(AUTHENTICATORS)
                .build()
            if (cipher != null) p.authenticate(info, BiometricPrompt.CryptoObject(cipher)) else p.authenticate(info)
            cont.invokeOnCancellation { executor.execute { p.cancelAuthentication() } }
        }
    }

    override fun cancel() {
        prompt?.cancelAuthentication()
    }

    companion object {
        val AUTHENTICATORS: Int =
            if (Build.VERSION.SDK_INT >= 30) BIOMETRIC_STRONG or DEVICE_CREDENTIAL else BIOMETRIC_WEAK or DEVICE_CREDENTIAL
    }
}
