package app.localgatekeys.android.ui.detail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The in-app copy confirmation: shown below API 33 only; every copy counts (haptic) and restarts the timer. */
class CopyToastTest {
    @Test fun each_show_replaces_the_message_and_restarts_its_timer() {
        val t = CopyToast(showsMessage = true)
        t.show("Code copied")
        val first = t.current.value!!
        assertEquals("Code copied", first.message)
        t.show("Password copied")
        val second = t.current.value!!
        assertEquals("Password copied", second.message)
        t.hide(first.serial) // the first copy's timer ends: the newer message stays
        assertEquals(second, t.current.value)
        t.hide(second.serial)
        assertNull(t.current.value)
        assertEquals(2, t.count.value)
    }

    @Test fun on_android_13_and_later_only_the_haptic_count_moves() {
        val t = CopyToast(showsMessage = false)
        t.show("Code copied")
        assertNull("the system shows its own copy confirmation", t.current.value)
        assertEquals(1, t.count.value)
    }

    @Test fun the_message_shows_for_1_6_seconds() {
        assertEquals(1600L, CopyToast.VISIBLE_MILLIS)
    }

    @Test fun shows_its_own_message_only_below_api_33() {
        assertEquals(true, CopyToast.showsOwnMessage(32))
        assertEquals(false, CopyToast.showsOwnMessage(33))
        assertEquals(false, CopyToast.showsOwnMessage(36))
    }
}
