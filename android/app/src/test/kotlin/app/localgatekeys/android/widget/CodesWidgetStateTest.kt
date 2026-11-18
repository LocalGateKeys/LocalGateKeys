package app.localgatekeys.android.widget

import app.localgatekeys.android.R
import app.localgatekeys.android.codes.PinnedCode
import app.localgatekeys.android.ui.detail.CodePinSeams
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class CodesWidgetStateTest {
    private fun code(id: String, code: String?, left: Int) = PinnedCode(id, "Site $id", code, left)

    @Test fun nothing_pinned_is_the_empty_state() {
        assertSame(CodesWidgetState.Empty, CodesWidgetState.of(emptyList(), visible = true))
        assertSame(CodesWidgetState.Empty, CodesWidgetState.of(emptyList(), visible = false))
    }

    @Test fun a_locked_vault_or_a_hidden_screen_shows_no_digits() {
        assertSame(CodesWidgetState.Locked, CodesWidgetState.of(listOf(code("a", null, 0)), visible = true))
        assertSame(CodesWidgetState.Locked, CodesWidgetState.of(listOf(code("a", "123456", 10)), visible = false))
    }

    @Test fun with_auto_lock_immediately_the_locked_widget_says_how_to_see_codes() {
        val locked = listOf(code("a", null, 0))
        assertSame(CodesWidgetState.LockedImmediately, CodesWidgetState.of(locked, visible = true, lockImmediately = true))
        assertSame(CodesWidgetState.LockedImmediately, CodesWidgetState.of(listOf(code("a", "123456", 10)), visible = false, lockImmediately = true))
        // Nothing pinned stays the empty state; open codes still show (the app itself is on screen).
        assertSame(CodesWidgetState.Empty, CodesWidgetState.of(emptyList(), visible = true, lockImmediately = true))
        assertTrue(CodesWidgetState.of(listOf(code("a", "123456", 10)), visible = true, lockImmediately = true) is CodesWidgetState.Codes)
    }

    @Test fun the_switch_note_follows_auto_lock_immediately() {
        assertEquals(R.string.detail_pin_code_note_immediately, CodePinSeams.noteRes(lockImmediately = true))
        assertEquals(R.string.detail_pin_code_note, CodePinSeams.noteRes(lockImmediately = false))
    }

    @Test fun open_codes_are_grouped_and_an_unusable_one_is_a_dash() {
        val s = CodesWidgetState.of(listOf(code("a", "123456", 10), code("b", "", 0)), visible = true) as CodesWidgetState.Codes
        assertEquals(listOf("123 456", "—"), s.rows.map { it.code })
        assertFalse(s.toString().contains("123"))
        assertFalse(s.rows[0].toString().contains("123"))
    }

    @Test fun the_next_refresh_is_the_first_period_boundary_or_the_lock_deadline() {
        val nowMillis = 1_790_000_010_400L // 10.4 s into a 30 s period
        val codes = listOf(code("a", "123456", 20), code("b", "654321", 50))
        // The boundary at ...030 s, just after it.
        assertEquals(19_600L + 100, CodesWidgetState.nextRefreshDelay(codes, Long.MAX_VALUE, nowMillis))
        // An earlier lock deadline wins.
        assertEquals(4_600L + 100, CodesWidgetState.nextRefreshDelay(codes, 1_790_000_015L, nowMillis))
        // A deadline already passed refreshes at once.
        assertEquals(100L, CodesWidgetState.nextRefreshDelay(codes, 1_790_000_000L, nowMillis))
        // Nothing time-bound: no timer.
        assertNull(CodesWidgetState.nextRefreshDelay(listOf(code("a", "", 0)), Long.MAX_VALUE, nowMillis))
        assertTrue(CodesWidgetState.nextRefreshDelay(listOf(code("a", "", 0)), 1_790_000_020L, nowMillis)!! > 0)
    }
}
