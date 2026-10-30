package app.localgatekeys.android.autofill

import android.app.Activity
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import app.localgatekeys.android.LgkApp
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.unlock.UnlockScreen
import app.localgatekeys.android.unlock.AppLockModel
import app.localgatekeys.android.unlock.UnlockedVault
import kotlinx.coroutines.launch

/**
 * The autofill, save and passkey sheets: the app's own unlock (fingerprint, screen lock or app password, the same
 * [AppLockModel]) and then [Unlocked] for the open vault. Nothing is read before the unlock; a locked vault never
 * fills. "Start fresh" is never offered here (that is an erase). The window is secure and excluded from autofill.
 */
abstract class VaultGateActivity : FragmentActivity() {
    protected val app: LgkApp get() = application as LgkApp

    /** True when the vault was already open as this sheet started (passkeys then ask for a fresh owner check). */
    protected var wasUnlockedAtStart = false
        private set

    private var previous: FragmentActivity? = null

    @Composable
    protected abstract fun Unlocked(vault: UnlockedVault)

    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        setResult(Activity.RESULT_CANCELED)
        previous = app.currentActivity()?.takeIf { it !== this }
        app.attach(this)
        val lock = app.lock
        wasUnlockedAtStart = lock.state.value == AppLockModel.State.UNLOCKED
        var asked = false
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                if (!asked) {
                    asked = true
                    lock.unlock()
                }
            }
        }
        setContent {
            val appearance by app.appearance.collectAsStateWithLifecycle()
            LgkTheme(appearance) {
                val state by lock.state.collectAsStateWithLifecycle()
                val vault by lock.vault.collectAsStateWithLifecycle()
                val open = vault
                if (state == AppLockModel.State.UNLOCKED && open != null) {
                    Unlocked(open)
                } else {
                    UnlockScreen(
                        lock,
                        onUnlock = { app.appScope.launch { lock.unlock() } },
                        onStartFresh = { finish() },
                        onPassword = { pw -> app.appScope.launch { lock.unlockWithPassword(pw) } },
                        onRecover = { phrase, pw -> app.appScope.launch { lock.recover(phrase, pw) } },
                        biometricShortcut = { app.appPasswordLock.biometricOn() },
                    )
                }
            }
        }
    }

    override fun onDestroy() {
        val back = previous?.takeIf { !it.isDestroyed }
        if (back != null) app.attach(back) else app.detach(this)
        super.onDestroy()
    }
}
