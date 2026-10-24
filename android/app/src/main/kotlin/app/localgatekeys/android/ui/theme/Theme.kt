package app.localgatekeys.android.ui.theme

import android.app.UiModeManager
import android.content.Context
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import app.localgatekeys.android.settings.Appearance

private val LocalTokens = compositionLocalOf { Palette.light }
private val LocalDark = compositionLocalOf { false }
private val LocalReduceTransparency = compositionLocalOf { false }
private val LocalIncreasedContrast = compositionLocalOf { false }

/** Accessors for the current glass-skin tokens and accessibility flags. */
object LgkTheme {
    val colors: Palette.Tokens @Composable @ReadOnlyComposable get() = LocalTokens.current
    val isDark: Boolean @Composable @ReadOnlyComposable get() = LocalDark.current
    val reduceTransparency: Boolean @Composable @ReadOnlyComposable get() = LocalReduceTransparency.current
    val increasedContrast: Boolean @Composable @ReadOnlyComposable get() = LocalIncreasedContrast.current
}

@Composable
fun LgkTheme(
    appearance: Appearance = Appearance.SYSTEM,
    reduceTransparency: Boolean = false,
    content: @Composable () -> Unit,
) {
    val dark = when (appearance) {
        Appearance.SYSTEM -> isSystemInDarkTheme()
        Appearance.LIGHT -> false
        Appearance.DARK -> true
    }
    val context = LocalContext.current
    // Android 14 and later expose the system contrast setting; below that there is no signal.
    val increasedContrast = remember(context) {
        Build.VERSION.SDK_INT >= 34 &&
            ((context.getSystemService(Context.UI_MODE_SERVICE) as? UiModeManager)?.contrast ?: 0f) >= 0.5f
    }
    val tokens = if (dark) Palette.dark else Palette.light
    CompositionLocalProvider(
        LocalTokens provides tokens,
        LocalDark provides dark,
        LocalReduceTransparency provides reduceTransparency,
        LocalIncreasedContrast provides increasedContrast,
    ) {
        MaterialTheme(colorScheme = materialScheme(tokens, dark), content = content)
    }
}

private fun materialScheme(t: Palette.Tokens, dark: Boolean): ColorScheme {
    val base = if (dark) darkColorScheme() else lightColorScheme()
    return base.copy(
        primary = t.accent, onPrimary = if (dark) t.background else t.groupSurface,
        background = t.background, onBackground = t.text,
        surface = t.groupSurface, onSurface = t.text,
        surfaceVariant = t.innerTile, onSurfaceVariant = t.secondaryText,
        outline = t.separator, error = t.danger,
    )
}
