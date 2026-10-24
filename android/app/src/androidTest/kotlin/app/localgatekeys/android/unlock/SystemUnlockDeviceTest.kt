package app.localgatekeys.android.unlock

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import app.localgatekeys.android.LgkApp
import app.localgatekeys.android.MainActivity
import app.localgatekeys.android.unlock.AppLockModel.State
import app.localgatekeys.android.vault.KeystoreVaultKey
import app.localgatekeys.android.vault.VaultKeyException
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.Test

/**
 * The real auth-required path (Ruling 7): the production Keystore key (`lgk.vault`, user authentication required),
 * the system BiometricPrompt answered with the screen-lock PIN through UiAutomator, first run then second run.
 * API 30+: per-use key authorised as a CryptoObject; API 29: the 30 s window after the prompt.
 *
 * Sets PIN 1234 itself (refuses to run on a device that already has a screen lock) and removes it afterwards.
 * Uses the debug app's own vault paths on the emulator, erased before and after.
 */
class SystemUnlockDeviceTest {
    private val inst = InstrumentationRegistry.getInstrumentation()
    private val device = UiDevice.getInstance(inst)
    private val context: Context = inst.targetContext
    private val app = context.applicationContext as LgkApp
    private var pinSet = false
    /** The test passed its assumption and owns the debug app's vault until tearDown. */
    private var owned = false

    private fun keyguardSecure() = (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure

    private fun erase() = runBlocking { VaultEraser(app.dirs, KeystoreVaultKey.production(context), app.settings).erase() }

    @Before fun setUp() {
        assumeFalse("this device already has a screen lock: not touching it", keyguardSecure())
        owned = true
        device.executeShellCommand("locksettings set-pin $PIN")
        pinSet = true
        waitFor("screen lock set") { keyguardSecure() }
        device.wakeUp()
        erase()
    }

    @After fun tearDown() {
        try {
            if (owned) {
                inst.runOnMainSync { app.lock.lock() }
                erase()
            }
        } finally {
            if (pinSet) device.executeShellCommand("locksettings clear --old $PIN")
            device.pressHome()
        }
    }

    @Test fun first_run_then_second_run_through_the_real_prompt() {
        context.startActivity(Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        device.wait(Until.hasObject(By.pkg(context.packageName)), 10_000)
        // First run: the activity start prompts (an earlier test in this process may have used up the launch
        // prompt, so ask explicitly as well; a second unlock() while one is in flight returns at once).
        inst.runOnMainSync { app.appScope.launch { app.lock.unlock() } }
        enterPin()
        waitFor("vault opened (first run)", ::lockDetail) { app.lock.state.value == State.UNLOCKED }
        assertTrue(app.dirs.wrappedKey.isFile)
        assertTrue(KeystoreVaultKey.production(context).exists())
        val first = app.lock.vault.value
        assertNotNull(first)
        assertEquals(0L, first!!.store.load().revision)
        val k1 = first.localKey.copyOf()

        // Without a prompt the key refuses to unwrap (API 30+ at once; API 29 once its 30 s window is over).
        inst.runOnMainSync { app.lock.lock() }
        assertNull(app.lock.vault.value)
        assertTrue("lock zeroed the key copy", first.localKey.all { it == 0.toByte() })
        assertUnwrapNeedsAuthentication()

        // Second run: unwrap through the prompt; same local key, same store.
        inst.runOnMainSync { app.appScope.launch { app.lock.unlock() } }
        enterPin()
        waitFor("vault opened (second run)", ::lockDetail) { app.lock.state.value == State.UNLOCKED }
        assertArrayEquals(k1, app.lock.vault.value!!.localKey)
        assertEquals(0L, app.lock.vault.value!!.store.load().revision)

        // The screen lock is removed: the platform invalidates or deletes the key, and the next unlock must end in
        // the vault-without-key outcome (Start fresh offered) or the screen-lock message, never a crash or a new key.
        inst.runOnMainSync { app.lock.lock() }
        device.executeShellCommand("locksettings clear --old $PIN")
        pinSet = false
        waitFor("screen lock removed") { !keyguardSecure() }
        inst.runOnMainSync { app.appScope.launch { app.lock.unlock() } }
        waitFor("unlock finished", ::lockDetail) { app.lock.state.value == State.LOCKED && app.lock.errorMessage.value != null }
        val keyLeft = KeystoreVaultKey.production(context).exists()
        Log.i(TAG, "after removing the screen lock (API ${Build.VERSION.SDK_INT}): keyExists=$keyLeft " +
            "vaultUnreadable=${app.lock.vaultUnreadable} message=${app.lock.errorMessage.value}")
        val unreadable = app.lock.vaultUnreadable
        assertTrue(
            lockDetail(),
            (unreadable && app.lock.errorMessage.value == AppLockModel.VAULT_WITHOUT_KEY_MESSAGE && app.lock.offersStartFresh.value) ||
                app.lock.errorMessage.value == "Set a screen lock in Settings to use LocalGateKeys.",
        )
        assertTrue("the wrapped key is never replaced", app.dirs.wrappedKey.isFile)
        if (unreadable) {
            // Start fresh: erases everything; the next unlock would be a first run.
            runBlocking(kotlinx.coroutines.Dispatchers.Main) { app.lock.startFreshAnyway() }
            assertFalse(app.settings.erasePending)
            assertFalse(app.lock.offersStartFresh.value)
            assertFalse(app.dirs.wrappedKey.exists())
            assertFalse(app.dirs.vault.exists())
        } else {
            // The key could not be checked without a screen lock (API 29 asks the prompt first). Erasing must
            // still succeed although the platform already dropped the key's blob.
            erase()
            assertFalse(app.dirs.wrappedKey.exists())
            assertFalse(KeystoreVaultKey.production(context).exists())
        }
    }

    private fun assertUnwrapNeedsAuthentication() {
        if (Build.VERSION.SDK_INT < 30) SystemClock.sleep(31_000)
        val key = KeystoreVaultKey.production(context)
        val wrapped = app.dirs.wrappedKey.readBytes()
        try {
            val out = key.unwrap(wrapped, key.cipherForUnwrap(wrapped))
            out.fill(0)
            fail("unwrapped without authentication")
        } catch (e: VaultKeyException) {
            assertEquals(e.cause.toString(), VaultKeyException.Kind.AUTH_REQUIRED, e.kind)
        }
    }

    /** The system credential screen (SystemUI on API 30+, Settings on API 29): type the PIN and confirm. */
    private fun enterPin() {
        val field = device.wait(Until.findObject(By.clazz("android.widget.EditText")), 20_000)
            ?: fail("no PIN field appeared; window: ${device.currentPackageName}").let { return }
        val owner = field.applicationPackage
        assertNotEquals("the PIN field must be the system's, not ours", context.packageName, owner)
        assertTrue("system credential UI: $owner", owner in SYSTEM_CREDENTIAL_PACKAGES)
        Log.i(TAG, "PIN field in $owner")
        field.click()
        device.executeShellCommand("input text $PIN")
        device.pressEnter()
    }

    private fun waitFor(what: String, detail: () -> String = { "" }, condition: () -> Boolean) {
        val deadline = SystemClock.uptimeMillis() + 20_000
        while (!condition()) {
            if (SystemClock.uptimeMillis() > deadline) fail("timed out: $what ${detail()}")
            SystemClock.sleep(100)
        }
    }

    private fun lockDetail() = "(state ${app.lock.state.value}, error ${app.lock.errorMessage.value})"

    private companion object {
        const val PIN = "1234"
        const val TAG = "SystemUnlockDeviceTest"
        val SYSTEM_CREDENTIAL_PACKAGES = setOf("com.android.systemui", "com.android.settings")
    }
}
