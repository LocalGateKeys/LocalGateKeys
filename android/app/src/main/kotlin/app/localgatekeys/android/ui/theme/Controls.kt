package app.localgatekeys.android.ui.theme

import androidx.compose.material3.SwitchColors
import androidx.compose.material3.SwitchDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * Every switch in the app: the accent track with a white thumb when on, as on the iPhone (Material's default thumb is
 * onPrimary, the dark background colour in dark mode). Off: the iPhone's grey track with the same white thumb, so an
 * off switch stays visible on a dark card.
 */
@Composable
fun lgkSwitchColors(): SwitchColors {
    val c = LgkTheme.colors
    return SwitchDefaults.colors(
        checkedTrackColor = c.accent,
        checkedThumbColor = Color.White,
        checkedIconColor = c.accent,
        checkedBorderColor = c.accent,
        uncheckedTrackColor = if (LgkTheme.isDark) Color(0xFF4A4A50) else Color(0xFFE2E2E6),
        uncheckedThumbColor = Color.White,
        uncheckedBorderColor = Color.Transparent,
    )
}
