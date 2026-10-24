package app.localgatekeys.android.ui.generator

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The generator's mode picker and buttons share a row only when the picker's labels fit (iOS ViewThatFits). */
class ControlsFitTest {
    @Test fun one_row_when_everything_fits() {
        assertFalse(ControlsFit.stacks(pickerWidth = 600, buttonsWidth = 300, gap = 30, width = 1000))
        assertFalse("exactly fits", ControlsFit.stacks(pickerWidth = 670, buttonsWidth = 300, gap = 30, width = 1000))
    }

    @Test fun stacks_when_the_picker_would_be_squeezed() {
        assertTrue(ControlsFit.stacks(pickerWidth = 671, buttonsWidth = 300, gap = 30, width = 1000))
        assertTrue(ControlsFit.stacks(pickerWidth = 1400, buttonsWidth = 600, gap = 30, width = 1000))
    }
}
