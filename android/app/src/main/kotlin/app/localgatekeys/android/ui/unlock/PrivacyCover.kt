package app.localgatekeys.android.ui.unlock

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.currentStateAsState
import app.localgatekeys.android.R
import app.localgatekeys.android.ui.theme.LgkTheme

/**
 * The privacy cover (the iPhone's PrivacyCover): `FLAG_SECURE` already keeps the window out of screenshots and the
 * recents thumbnail; on top of that the content is replaced by an opaque brand cover whenever the activity is not
 * RESUMED (a dialog or the recents screen in front, or stopped). Dialogs are their own windows and inherit
 * `FLAG_SECURE` (Compose `SecureFlagPolicy.Inherit`).
 */
object PrivacyCover {
    fun covers(state: Lifecycle.State): Boolean = !state.isAtLeast(Lifecycle.State.RESUMED)
}

/** Draws [content], and the cover above it while the activity is not resumed. */
@Composable
fun PrivacyCoverHost(content: @Composable () -> Unit) {
    val state by LocalLifecycleOwner.current.lifecycle.currentStateAsState()
    Box(Modifier.fillMaxSize()) {
        content()
        if (PrivacyCover.covers(state)) PrivacyCoverView()
    }
}

/** Palette background, full bleed, with the brand mark centred. */
@Composable
fun PrivacyCoverView() {
    Box(Modifier.fillMaxSize().background(LgkTheme.colors.background).testTag("privacyCover"), contentAlignment = Alignment.Center) {
        Image(painterResource(R.drawable.brand_mark), contentDescription = null, modifier = Modifier.size(96.dp))
    }
}
