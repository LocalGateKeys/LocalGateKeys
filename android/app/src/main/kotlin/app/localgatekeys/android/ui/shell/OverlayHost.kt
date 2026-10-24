package app.localgatekeys.android.ui.shell

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier

/**
 * Where a screen shows a full-screen sheet (the iPhone's `.sheet`) above the header and the tab bar, in the same window:
 * a dialog window would sit outside FLAG_SECURE's autofill exclusion (Ruling 15) and the keyboard opt-out. RootScaffold
 * owns one and draws [content] on top of everything.
 */
class OverlayHost {
    var content by mutableStateOf<(@Composable () -> Unit)?>(null)
        internal set
}

val LocalOverlayHost = staticCompositionLocalOf<OverlayHost?> { null }

/** Shows [content] as the overlay while this is composed; without a host (a screen tested alone), in place, full size. */
@Composable
fun Overlay(content: @Composable () -> Unit) {
    val host = LocalOverlayHost.current
    val latest by rememberUpdatedState(content)
    if (host == null) {
        Box(Modifier.fillMaxSize()) { latest() }
        return
    }
    DisposableEffect(host) {
        val shown: @Composable () -> Unit = { latest() }
        host.content = shown
        onDispose { if (host.content === shown) host.content = null }
    }
}

/** Draws the host's overlay, if any (RootScaffold, last, so it covers the header and the tab bar). */
@Composable
fun OverlayHostContent(host: OverlayHost) {
    host.content?.let { Box(Modifier.fillMaxSize()) { it() } }
}
