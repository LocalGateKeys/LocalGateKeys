package app.localgatekeys.android.autofill

import app.localgatekeys.android.unlock.ManualScheduler
import app.localgatekeys.android.unlock.TestClock
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/** A typed password waits for the save sheet in memory only: taken once, dropped by a timer, and dropped on lock. */
class PendingSavesTest {
    private val clock = TestClock(1_000)
    private val timers = ManualScheduler(clock)
    private val web = FillTarget.Web("https://accounts.example.com", "com.android.chrome")

    @Before fun seams() {
        PendingSaves.now = { clock.now * 1000 }
        PendingSaves.scheduler = timers
    }

    @After fun reset() {
        PendingSaves.clear()
        PendingSaves.now = { android.os.SystemClock.elapsedRealtime() }
        PendingSaves.scheduler = null
    }

    @Test fun taken_once() {
        val token = PendingSaves.put(web, "me", "pw")
        assertEquals("pw", PendingSaves.take(token)?.password)
        assertNull(PendingSaves.take(token))
        assertNull(PendingSaves.take(null))
    }

    @Test fun a_dismissed_prompt_is_dropped_by_the_timer() {
        val token = PendingSaves.put(web, "me", "pw")
        assertEquals(1, timers.pending)
        timers.advance(119)
        val kept = PendingSaves.put(web, "me", "pw2")
        timers.advance(1)
        assertNull(PendingSaves.take(token))
        assertEquals("pw2", PendingSaves.take(kept)?.password)
    }

    @Test fun an_overdue_entry_is_never_handed_out() {
        val token = PendingSaves.put(web, "me", "pw")
        clock.now += 121 // the timer did not run (a frozen process)
        assertNull(PendingSaves.take(token))
    }

    @Test fun a_lock_drops_everything() {
        val a = PendingSaves.put(web, "me", "pw")
        val b = PendingSaves.put(FillTarget.App("com.bank", "aa"), "me", "pw")
        PendingSaves.clear()
        assertNull(PendingSaves.take(a))
        assertNull(PendingSaves.take(b))
    }
}
