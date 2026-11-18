package app.localgatekeys.android.autofill

import android.app.Activity
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.MainActivity
import app.localgatekeys.android.R
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.Window
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
 * fills. "Start fresh" is never offered here (that is an erase). The window is secure and excluded from autofill, and
 * other apps' overlays are hidden while it shows ([hideOverlays]): the app password is typed here.
 *
 * Task 9: when the app password needs a key file or YubiKey, the sheet does not unlock by itself (the file picker and
 * the NFC reader belong to the app, as on the iPhone): it says "Open LocalGateKeys to unlock" and opens the app.
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
        window.hideOverlays()
        setResult(Activity.RESULT_CANCELED)
        // Sub-plan 08: no fill, save or passkey sheet while a duress session is open or the vault is held after one.
        if (app.duress.servicesBlocked()) {
            finish()
            return
        }
        previous = app.currentActivity()?.takeIf { it !== this }
        app.attach(this)
        val lock = app.lock
        wasUnlockedAtStart = lock.state.value == AppLockModel.State.UNLOCKED
        val defers = lock.sheetDefersToApp()
        var asked = defers
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
                    if (open.decoy) LaunchedEffect(open) { finish() } else Unlocked(open)
                } else if (defers) {
                    OpenAppToUnlock(onOpen = {
                        startActivity(
                            Intent(this@VaultGateActivity, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        )
                        finish()
                    }, onCancel = { finish() })
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

/**
 * For windows where the app password or recovery phrase is typed: on Android 12+ other apps' overlay windows are
 * hidden (`HIDE_OVERLAY_WINDOWS`), so a fake sheet drawn over this one cannot collect or steer what is typed.
 * Touches are deliberately not filtered on the whole window (`filterTouchesWhenObscured`): on Android 10/11 a screen
 * dimmer, blue-light filter or chat head would make the entire app silently ignore every touch. The Compose input
 * fields offer no simple per-field touch filter, so on Android 10/11 these windows stay unfiltered.
 */
internal fun Window.hideOverlays() {
    if (Build.VERSION.SDK_INT >= 31) setHideOverlayWindows(true)
}

/** Task 9: "Open LocalGateKeys to unlock" (the app password needs its key file or YubiKey). */
@Composable
private fun OpenAppToUnlock(onOpen: () -> Unit, onCancel: () -> Unit) {
    val c = LgkTheme.colors
    Column(
        Modifier.fillMaxSize().safeDrawingPadding().padding(32.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(stringResource(R.string.factors_sheet_title), color = c.text, style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
        Text(stringResource(R.string.factors_sheet_text), color = c.secondaryText, textAlign = TextAlign.Center)
        Button(
            onClick = onOpen,
            colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
            modifier = Modifier.fillMaxWidth().testTag("sheet-open-app"),
        ) { Text(stringResource(R.string.factors_sheet_open)) }
        TextButton(onClick = onCancel) { Text(stringResource(R.string.common_cancel), color = c.accentText) }
    }
}
