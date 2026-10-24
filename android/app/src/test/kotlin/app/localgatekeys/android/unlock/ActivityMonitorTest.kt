package app.localgatekeys.android.unlock

import android.view.KeyEvent
import android.view.MotionEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Port of ios/LocalGateKeysTests/ActivityMonitorTests.swift. Android: touches come through
 * Activity.dispatchTouchEvent (the monitor only looks, then passes the event on), typing through the text fields'
 * value callbacks (soft-keyboard input never reaches the activity's dispatch).
 */
class ActivityMonitorTest {
    @Test fun text_changes_count_as_activity() {
        var count = 0
        val monitor = ActivityMonitor { count++ }
        monitor.textChanged()
        var forwarded: String? = null
        val onValueChange = monitor.reporting<String> { forwarded = it }
        onValueChange("abc")
        assertEquals(2, count)
        assertEquals("the field still gets its value", "abc", forwarded)
    }

    @Test fun unrelated_events_are_ignored() {
        var count = 0
        val monitor = ActivityMonitor { count++ }
        for (a in listOf(MotionEvent.ACTION_MOVE, MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL, MotionEvent.ACTION_HOVER_MOVE)) {
            monitor.dispatchTouch(a) { true }
        }
        monitor.dispatchKey(KeyEvent.ACTION_UP) { false }
        assertEquals(0, count)
    }

    @Test fun touch_began_counts_and_never_claims_the_touch() {
        var count = 0
        var passed = 0
        val monitor = ActivityMonitor { count++ }
        assertTrue(monitor.dispatchTouch(MotionEvent.ACTION_DOWN) { passed++; true })
        assertFalse("the result is the activity's own, never consumed by the monitor", monitor.dispatchTouch(MotionEvent.ACTION_DOWN) { passed++; false })
        assertTrue(monitor.dispatchTouch(MotionEvent.ACTION_POINTER_DOWN) { passed++; true })
        assertEquals(3, count)
        assertEquals("every event is passed on", 3, passed)
        assertTrue(monitor.dispatchTouch(MotionEvent.ACTION_UP) { passed++; true })
        assertEquals(4, passed)
    }

    @Test fun hardware_key_presses_count() {
        var count = 0
        val monitor = ActivityMonitor { count++ }
        assertFalse(monitor.dispatchKey(KeyEvent.ACTION_DOWN) { false })
        assertEquals(1, count)
    }
}
