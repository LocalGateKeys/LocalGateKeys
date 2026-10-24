package app.localgatekeys.android.ui.theme

import androidx.compose.ui.graphics.Color

/** The Glass skin palette (iOS spec Part 2), light and dark. */
object Palette {
    data class Tokens(
        /** Screen background. */
        val background: Color,
        /** Solid grouped sections: lists, the Codes row, item detail. */
        val groupSurface: Color,
        /** Tiles and icon wells inside a group. */
        val innerTile: Color,
        val separator: Color,
        val text: Color,
        val secondaryText: Color,
        /** Fills and the selected tab. Never plain text on glass: use accentText. */
        val accent: Color,
        val accentText: Color,
        /** Glass under reduced transparency. */
        val glassFill: Color,
        val glassBorder: Color,
        val success: Color,
        val warning: Color,
        val danger: Color,
        /** Aurora glows (behind content only; never under text). */
        val glowBlue: Color,
        val glowOrange: Color,
        /** Identity item tiles. */
        val identityTint: Color,
    )

    val light = Tokens(
        background = Color(0xFFEEF2F8), groupSurface = Color(0xFFFFFFFF), innerTile = Color(0xFFF3F7FD),
        separator = Color(0xFFE3E8F0), text = Color(0xFF101828), secondaryText = Color(0xFF5B6678),
        accent = Color(0xFF2B6FE0), accentText = Color(0xFF1F57B8), glassFill = Color(0xFFFFFFFF),
        glassBorder = Color(0xFFD7E1EE), success = Color(0xFF1F7A4A), warning = Color(0xFFC27C0E),
        danger = Color(0xFFC8372D), glowBlue = Color(0xFF5B8CFF), glowOrange = Color(0xFFFF9F5A),
        identityTint = Color(0xFF7C5CE0),
    )

    val dark = Tokens(
        background = Color(0xFF0F1727), groupSurface = Color(0xFF18233A), innerTile = Color(0xFF22304A),
        separator = Color(0xFF2A3650), text = Color(0xFFF4F6FB), secondaryText = Color(0xFFA9B3C5),
        accent = Color(0xFF5AA0FF), accentText = Color(0xFF7FB2FF), glassFill = Color(0xFF242C3B),
        glassBorder = Color(0xFF3F4552), success = Color(0xFF7EE0A8), warning = Color(0xFFFFCF80),
        danger = Color(0xFFFF7A70), glowBlue = Color(0xFF2B6FE0), glowOrange = Color(0xFFE8732A),
        identityTint = Color(0xFFB9A4FF),
    )
}
