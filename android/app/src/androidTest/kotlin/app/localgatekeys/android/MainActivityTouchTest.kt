package app.localgatekeys.android

import android.app.KeyguardManager
import android.content.Context
import android.os.SystemClock
import android.view.MotionEvent
import android.view.View
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Test

/** Every touch that begins reaches the lock model's noteActivity through MainActivity.dispatchTouchEvent. */
class MainActivityTouchTest {
    /** Ruling 15: the whole window is out of third-party autofill, whatever screen shows. */
    @Test fun the_window_is_excluded_from_autofill() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { a ->
                assertEquals(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS, a.window.decorView.importantForAutofill)
            }
        }
    }

    @Test fun touches_report_activity_and_still_reach_the_window() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        // Without a screen lock the launch unlock stops at "no screen lock": no system prompt covers the activity.
        assumeFalse((ctx.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure)
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var reported = 0
            scenario.onActivity { a ->
                val noteActivity = a.userActivity
                a.userActivity = { reported++; noteActivity() }
            }
            scenario.onActivity { a ->
                val t = SystemClock.uptimeMillis()
                val down = MotionEvent.obtain(t, t, MotionEvent.ACTION_DOWN, 10f, 10f, 0)
                val up = MotionEvent.obtain(t, t + 10, MotionEvent.ACTION_UP, 10f, 10f, 0)
                a.dispatchTouchEvent(down)
                a.dispatchTouchEvent(up)
                down.recycle(); up.recycle()
            }
            assertEquals("one touch began", 1, reported)
            // A real tap through the input system.
            val device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
            device.click(device.displayWidth / 2, device.displayHeight / 3)
            device.waitForIdle()
            assertTrue("a real tap counts: $reported", reported >= 2)
        }
    }
}
