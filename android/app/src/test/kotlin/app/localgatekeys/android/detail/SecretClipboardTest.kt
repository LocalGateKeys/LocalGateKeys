package app.localgatekeys.android.detail

import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.ClipboardExpiry
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.unlock.ManualScheduler
import app.localgatekeys.android.unlock.TestClock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The secret clipboard: sensitive copies that expire after the setting, cleared only while they are still ours. */
class SecretClipboardTest {
    private val clock = TestClock(1_790_000_000)
    private val scheduler = ManualScheduler(clock)
    private val settings = AppSettings(MemoryStore())
    private val sink = FakeClipboardSink()
    private val clip = SecretClipboard(sink, settings, scheduler, clock).also { it.focusChanged(true) }

    @Test fun a_copy_is_marked_sensitive() {
        clip.copy("s3cret")
        assertEquals(listOf(FakeClipboardSink.Write("s3cret", true)), sink.history)
        assertEquals("s3cret", sink.text)
    }

    @Test fun our_copy_is_cleared_after_the_default_60_seconds() {
        assertEquals(ClipboardExpiry.SIXTY_SECONDS, settings.clipboardExpiry)
        clip.copy("s3cret")
        scheduler.advance(59); assertEquals("s3cret", sink.text)
        scheduler.advance(1); assertNull(sink.text)
        assertEquals(0, scheduler.pending)
    }

    @Test fun the_expiry_follows_the_setting_at_copy_time() {
        settings.clipboardExpiry = ClipboardExpiry.TWO_MINUTES
        clip.copy("s3cret")
        assertEquals(clock.now + 120, scheduler.timers.single { !it.cancelled }.due)
        scheduler.advance(119); assertEquals("s3cret", sink.text)
        scheduler.advance(1); assertNull(sink.text)
    }

    @Test fun the_expiry_leaves_a_later_foreign_copy_alone() {
        clip.copy("s3cret")
        sink.foreignCopy("user text")
        scheduler.advance(60)
        assertEquals("user text", sink.text)
        assertEquals(0, sink.clears)
    }

    @Test fun clear_if_owned_clears_only_our_copy_and_stops_the_timer() {
        clip.copy("s3cret")
        clip.clearIfOwned()
        assertNull(sink.text); assertEquals(1, sink.clears); assertEquals(0, scheduler.pending)
        clip.clearIfOwned() // nothing held any more: no second clear
        assertEquals(1, sink.clears)

        clip.copy("again")
        sink.foreignCopy("user text")
        clip.clearIfOwned()
        assertEquals("user text", sink.text); assertEquals(1, sink.clears)
    }

    @Test fun a_new_copy_restarts_the_expiry() {
        clip.copy("first")
        scheduler.advance(30)
        clip.copy("second")
        scheduler.advance(30); assertEquals("second", sink.text)
        scheduler.advance(30); assertNull(sink.text)
        assertEquals(1, sink.clears)
    }

    @Test fun nothing_copied_means_nothing_cleared() {
        sink.foreignCopy("user text")
        clip.clearIfOwned()
        assertEquals("user text", sink.text); assertEquals(0, sink.clears)
    }

    @Test fun a_deadline_passed_in_deep_sleep_is_handled_on_the_next_focus() {
        clip.copy("s3cret")
        clip.focusChanged(false)
        clock.now += 600 // asleep: elapsed time moved, the uptime timer did not fire
        assertEquals("s3cret", sink.text)
        clip.focusChanged(true)
        assertNull(sink.text)
    }

    @Test fun an_overdue_copy_is_handled_by_check_due_at_resume_unlock_or_lock() {
        clip.copy("s3cret")
        clock.now += 61
        clip.checkDue()
        assertNull(sink.text)
    }

    @Test fun check_due_before_the_deadline_keeps_the_copy() {
        clip.copy("s3cret")
        clock.now += 59
        clip.checkDue()
        assertEquals("s3cret", sink.text)
    }

    @Test fun an_expiry_without_focus_waits_for_focus() {
        clip.copy("s3cret")
        clip.focusChanged(false)
        scheduler.advance(60)
        assertEquals("cannot check without focus: never a blind clear", "s3cret", sink.text)
        assertTrue(clip.isDue)
        clip.focusChanged(true)
        assertNull(sink.text); assertFalse(clip.isDue)
    }

    @Test fun a_lock_without_focus_waits_for_focus_and_spares_a_foreign_copy() {
        clip.copy("s3cret")
        clip.focusChanged(false)
        clip.clearIfOwned()
        assertEquals("s3cret", sink.text)
        sink.foreignCopy("user text")
        clip.focusChanged(true)
        assertEquals("user text", sink.text); assertEquals(0, sink.clears); assertFalse(clip.isDue)
    }

    @Test fun to_string_never_shows_the_copy() {
        clip.copy("s3cret-Maple")
        assertFalse(clip.toString().contains("s3cret"))
        assertTrue(clip.toString().startsWith("SecretClipboard("))
    }
}
