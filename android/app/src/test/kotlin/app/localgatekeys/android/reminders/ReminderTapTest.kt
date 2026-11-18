package app.localgatekeys.android.reminders

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A reminder notification's tap reaches its item even when the run delivering it is cancelled and restarted. */
class ReminderTapTest {
    @Test fun the_item_opens_and_the_request_is_cleared() = runBlocking {
        val pending = MutableStateFlow<String?>("r1")
        val opened = mutableListOf<String>()
        ReminderTap.deliver(pending, { if (it == "r1") "item-1" else null }, { opened += it })
        assertEquals(listOf("item-1"), opened)
        assertNull(pending.value)
    }

    /** Release check 2026-11-01: the request was cleared before the lookup, the effect restarted and the tap was lost. */
    @Test fun the_request_stays_pending_during_the_lookup_and_a_cancelled_run_leaves_it_for_the_next() = runBlocking {
        val pending = MutableStateFlow<String?>("r1")
        val opened = mutableListOf<String>()
        val gate = CompletableDeferred<String?>()
        val first = launch(start = CoroutineStart.UNDISPATCHED) { ReminderTap.deliver(pending, { gate.await() }, { opened += it }) }
        assertEquals("r1", pending.value)
        first.cancel()
        first.join()
        assertTrue(opened.isEmpty())
        assertEquals("r1", pending.value)
        ReminderTap.deliver(pending, { "item-1" }, { opened += it })
        assertEquals(listOf("item-1"), opened)
        assertNull(pending.value)
    }

    @Test fun a_newer_tap_during_the_lookup_is_kept_and_an_unknown_reminder_opens_nothing() = runBlocking {
        val pending = MutableStateFlow<String?>("gone")
        val opened = mutableListOf<String>()
        ReminderTap.deliver(pending, { pending.value = "r2"; yield(); null }, { opened += it })
        assertTrue(opened.isEmpty())
        assertEquals("r2", pending.value)
    }
}
