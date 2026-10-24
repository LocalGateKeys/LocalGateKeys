package app.localgatekeys.android.ui.theme

import androidx.compose.material3.SwitchColors
import androidx.compose.material3.SwitchDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * Every switch in the app: the accent track with a white thumb when on, as on the iPhone (Material's default thumb is
 * onPrimary, the dark background colour in dark mode).
 */
@Composable
fun lgkSwitchColors(): SwitchColors {
    val c = LgkTheme.colors
    return SwitchDefaults.colors(
        checkedTrackColor = c.accent,
        checkedThumbColor = Color.White,
        checkedIconColor = c.accent,
        checkedBorderColor = c.accent,
    )
}
