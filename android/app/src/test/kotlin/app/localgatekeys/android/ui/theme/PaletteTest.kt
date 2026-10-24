package app.localgatekeys.android.ui.theme

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import org.junit.Assert.assertEquals
import org.junit.Test

/** The spec's "Glass skin" palette table (light / dark), verbatim; port of PaletteTests.swift. */
class PaletteTest {
    private fun rgb(c: Color): Long = c.toArgb().toLong() and 0xFFFFFF
    private fun alpha(c: Color): Int = (c.toArgb() ushr 24)

    private val spec: List<Triple<String, Long, Long>> = listOf(
        Triple("background", 0xEEF2F8, 0x0F1727),
        Triple("groupSurface", 0xFFFFFF, 0x18233A),
        Triple("innerTile", 0xF3F7FD, 0x22304A),
        Triple("separator", 0xE3E8F0, 0x2A3650),
        Triple("text", 0x101828, 0xF4F6FB),
        Triple("secondaryText", 0x5B6678, 0xA9B3C5),
        Triple("accent", 0x2B6FE0, 0x5AA0FF),
        Triple("accentText", 0x1F57B8, 0x7FB2FF),
        Triple("glassFill", 0xFFFFFF, 0x242C3B),
        Triple("glassBorder", 0xD7E1EE, 0x3F4552),
        Triple("success", 0x1F7A4A, 0x7EE0A8),
        Triple("warning", 0xC27C0E, 0xFFCF80),
        Triple("danger", 0xC8372D, 0xFF7A70),
        Triple("glowBlue", 0x5B8CFF, 0x2B6FE0),
        Triple("glowOrange", 0xFF9F5A, 0xE8732A),
        Triple("identityTint", 0x7C5CE0, 0xB9A4FF),
    )

    private fun tokenMap(t: Palette.Tokens): Map<String, Color> = mapOf(
        "background" to t.background, "groupSurface" to t.groupSurface, "innerTile" to t.innerTile,
        "separator" to t.separator, "text" to t.text, "secondaryText" to t.secondaryText,
        "accent" to t.accent, "accentText" to t.accentText, "glassFill" to t.glassFill,
        "glassBorder" to t.glassBorder, "success" to t.success, "warning" to t.warning,
        "danger" to t.danger, "glowBlue" to t.glowBlue, "glowOrange" to t.glowOrange,
        "identityTint" to t.identityTint,
    )

    @Test fun palette_matches_spec_tokens() {
        val light = tokenMap(Palette.light)
        val dark = tokenMap(Palette.dark)
        assertEquals("every token is in the spec table", spec.map { it.first }.toSet(), light.keys)
        assertEquals(16, light.size)
        for ((name, l, d) in spec) {
            assertEquals("$name light", l, rgb(light.getValue(name)))
            assertEquals("$name dark", d, rgb(dark.getValue(name)))
            assertEquals("$name light opaque", 255, alpha(light.getValue(name)))
            assertEquals("$name dark opaque", 255, alpha(dark.getValue(name)))
        }
    }
}
