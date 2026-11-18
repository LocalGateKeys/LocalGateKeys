package app.localgatekeys.android.widget

import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The widget's alarm fallback (a killed app's widget must turn locked even when JobScheduler holds the WorkManager job
 * for quota, as Android 10 did after a few minutes of codes on screen).
 */
class CodesWidgetAlarmTest {
    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext

    @After fun tearDown() = CodesWidgetAlarm.cancel(ctx)

    @Test fun arm_then_cancel() {
        CodesWidgetAlarm.arm(ctx, 60_000)
        assertTrue(CodesWidgetAlarm.isArmed(ctx))
        CodesWidgetAlarm.cancel(ctx)
        assertFalse(CodesWidgetAlarm.isArmed(ctx))
    }

    @Test fun the_alarm_reaches_the_widget_receiver_which_refreshes() {
        // No widget is placed in the test: the refresh the receiver runs finds none and stops every timer, the alarm
        // included. So the alarm being gone proves it was delivered to the private receiver and the refresh ran.
        CodesWidgetAlarm.arm(ctx, 500)
        assertTrue(CodesWidgetAlarm.isArmed(ctx))
        val until = SystemClock.elapsedRealtime() + 30_000
        while (CodesWidgetAlarm.isArmed(ctx) && SystemClock.elapsedRealtime() < until) SystemClock.sleep(250)
        assertFalse("the alarm fired and the refresh cancelled it", CodesWidgetAlarm.isArmed(ctx))
    }
}
