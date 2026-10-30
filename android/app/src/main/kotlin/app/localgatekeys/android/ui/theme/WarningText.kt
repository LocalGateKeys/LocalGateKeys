package app.localgatekeys.android.ui.theme

import androidx.compose.ui.graphics.Color

/**
 * Accessibility pass (workstream 13): the spec's light `warning` (0xC27C0E) is 3.0:1 on the light background, fine for
 * icons and dots but below 4.5:1 for text. Warning TEXT uses this darker amber in light mode (5:1+ on every light
 * surface); dark mode keeps the spec colour. The palette table itself stays verbatim.
 */
const val WARNING_TEXT_LIGHT: Long = 0xFF8F5600

fun warningTextOn(t: Palette.Tokens): Color = if (t == Palette.light) Color(WARNING_TEXT_LIGHT) else t.warning

/** The warning colour for text in this theme. */
val Palette.Tokens.warningText: Color get() = warningTextOn(this)
