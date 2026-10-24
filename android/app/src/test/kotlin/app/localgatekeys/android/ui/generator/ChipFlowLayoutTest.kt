package app.localgatekeys.android.ui.generator

import app.localgatekeys.android.ui.generator.ChipFlow.Size
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Port of `ios/LocalGateKeysTests/ChipFlowLayoutTests.swift`: the separator chips wrap instead of being clipped. */
class ChipFlowLayoutTest {
    private fun inside(r: ChipFlow.Result, sizes: List<Size>, width: Float): Boolean =
        r.origins.zip(sizes).all { (o, s) -> o.x >= 0 && o.x + s.width <= width + 0.001f }

    private fun sizes(widths: List<Int>, height: Int) = widths.map { Size(it.toFloat(), height.toFloat()) }

    @Test fun five_chips_fit_on_one_row_when_there_is_room() {
        val sizes = sizes(listOf(60, 70, 50, 100, 60), 34)
        val r = ChipFlow.arrange(sizes, width = 400f, spacing = 8f)
        assertTrue(r.origins.all { it.y == 0f })
        assertEquals(34f, r.size.height)
        assertTrue(inside(r, sizes, 400f))
    }

    @Test fun narrow_card_wraps_and_none_is_fully_visible() {
        // About the default text size on a phone card (≈ 320 dp of content).
        val sizes = sizes(listOf(64, 76, 54, 108, 62), 34)
        val r = ChipFlow.arrange(sizes, width = 320f, spacing = 8f)
        assertTrue("no chip crosses the card edge", inside(r, sizes, 320f))
        assertTrue("None moves to the next row", r.origins[4].y > 0)
        assertEquals(34f + 8 + 34, r.size.height)
    }

    @Test fun accessibility_text_sizes_stack_rows_and_never_overflow() {
        val sizes = sizes(listOf(150, 170, 120, 250, 140), 60)
        val r = ChipFlow.arrange(sizes, width = 300f, spacing = 8f)
        assertTrue(inside(r, sizes, 300f))
        val rows = r.origins.map { it.y }.toSet().size
        assertEquals(4, rows) // rows: 150 | 170 120 | 250 | 140
        assertEquals(rows * 60f + (rows - 1) * 8f, r.size.height)
    }

    @Test fun empty() {
        assertEquals(Size(0f, 0f), ChipFlow.arrange(emptyList(), width = 300f, spacing = 8f).size)
    }
}
