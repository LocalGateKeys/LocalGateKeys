package app.localgatekeys.android.trash

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UndoToastTest {
    @Test fun undo_runs_once_and_hides_the_toast() = runBlocking {
        val toast = UndoToast()
        var runs = 0
        toast.show("Moved") { runs++ }
        assertTrue(toast.current.value!!.hasUndo)
        toast.undo()
        toast.undo()
        assertEquals(1, runs)
        assertNull(toast.current.value)
    }

    @Test fun an_old_timer_never_hides_a_newer_message() {
        val toast = UndoToast()
        toast.show("First") {}
        val first = toast.current.value!!.serial
        toast.info("Item restored")
        toast.hide(first)
        assertEquals("Item restored", toast.current.value!!.message)
        assertFalse(toast.current.value!!.hasUndo)
        assertEquals(UndoToast.SHORT_MILLIS, toast.current.value!!.millis)
        toast.hide(toast.current.value!!.serial)
        assertNull(toast.current.value)
    }

    @Test fun dismiss_drops_the_undo_without_running_it() = runBlocking {
        val toast = UndoToast()
        var runs = 0
        toast.show("Moved") { runs++ }
        toast.dismiss()
        toast.undo()
        assertEquals(0, runs)
    }
}
