package app.localgatekeys.android.ui.theme

import androidx.compose.ui.graphics.Color
import kotlin.math.pow
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Workstream 13 (accessibility): every text colour reaches 4.5:1 (WCAG AA body text) on the solid surfaces it is
 * drawn on, in light and dark. The glass itself is not measured here: fixes change text colours, never the glass.
 */
class PaletteContrastTest {
    private fun channel(v: Float): Double = if (v <= 0.03928f) v / 12.92 else ((v + 0.055) / 1.055).pow(2.4)

    private fun luminance(c: Color): Double = 0.2126 * channel(c.red) + 0.7152 * channel(c.green) + 0.0722 * channel(c.blue)

    fun ratio(a: Color, b: Color): Double {
        val (hi, lo) = listOf(luminance(a), luminance(b)).sortedDescending()
        return (hi + 0.05) / (lo + 0.05)
    }

    @Test fun text_colours_reach_aa_on_every_solid_surface() {
        val failures = mutableListOf<String>()
        for ((theme, t) in listOf("light" to Palette.light, "dark" to Palette.dark)) {
            val texts = mapOf(
                "text" to t.text, "secondaryText" to t.secondaryText, "accentText" to t.accentText,
                "success" to t.success, "danger" to t.danger,
            )
            val surfaces = mapOf("background" to t.background, "groupSurface" to t.groupSurface, "innerTile" to t.innerTile)
            for ((tn, tc) in texts) for ((sn, sc) in surfaces) {
                val r = ratio(tc, sc)
                if (r < 4.5) failures.add("$theme $tn on $sn: ${"%.2f".format(r)}")
            }
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    /**
     * The spec's light `warning` (0xC27C0E, shared verbatim with the iPhone) is 3.0:1 on the light background: enough
     * for icons and dots (non-text, 3:1), not for body text. Text uses [warningTextOn] instead.
     */
    @Test fun warning_is_an_icon_colour_and_its_text_form_reaches_aa() {
        for (t in listOf(Palette.light, Palette.dark)) {
            for (s in listOf(t.background, t.groupSurface, t.innerTile)) {
                assertTrue(ratio(t.warning, s) >= 3.0)
                assertTrue(ratio(warningTextOn(t), s) >= 4.5)
            }
        }
    }

    @Test fun white_on_the_accent_fill_reaches_large_text_contrast() {
        // Primary buttons draw white semibold labels on the accent fill.
        assertTrue(ratio(Color.White, Palette.light.accent) >= 3.0)
    }
}
