package app.localgatekeys.android.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Review 2026-11-15 UX 2: keyboard chips for every dataset while "Show in keyboard" is on and the keyboard asks. */
class InlineChipsTest {
    @Test fun each_dataset_gets_a_chip_up_to_the_keyboard_limit() {
        assertEquals(0, InlineChips.specIndex(enabled = true, specCount = 3, maxChips = 2, index = 0))
        assertEquals(1, InlineChips.specIndex(true, 3, 2, 1))
        assertNull("past the keyboard's limit", InlineChips.specIndex(true, 3, 2, 2))
    }

    @Test fun the_last_spec_is_reused() {
        assertEquals(0, InlineChips.specIndex(true, 1, 5, 3))
    }

    @Test fun no_chip_when_off_or_not_asked() {
        assertNull("Show in keyboard off", InlineChips.specIndex(false, 3, 5, 0))
        assertNull("the keyboard asked for none", InlineChips.specIndex(true, 0, 5, 0))
        assertNull(InlineChips.specIndex(true, 3, 0, 0))
    }
}
