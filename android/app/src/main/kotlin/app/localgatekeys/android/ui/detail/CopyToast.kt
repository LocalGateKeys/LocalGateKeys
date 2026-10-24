package app.localgatekeys.android.ui.detail

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGlass
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The copy confirmation (port of `ios/App/Detail/CopyToast.swift`). One shared instance; [CopyToastHost] shows it over
 * the vault list and the detail screen alike. Each new copy restarts the timer and gives a confirm haptic.
 *
 * Android 13 and later show their own clipboard confirmation for every copy, so there [showsMessage] is false and only
 * the haptic fires: two confirmations for one copy would be noise ([showsOwnMessage]).
 */
class CopyToast(private val showsMessage: Boolean) {
    /** [serial] tells two shows of the same message apart, so each one restarts the timer. */
    data class Shown(val message: String, val serial: Int)

    private val _current = MutableStateFlow<Shown?>(null)
    val current: StateFlow<Shown?> = _current.asStateFlow()

    private val _count = MutableStateFlow(0)
    /** Bumped on every copy, so a repeat copy still gives the haptic. */
    val count: StateFlow<Int> = _count.asStateFlow()

    fun show(message: String) {
        val n = _count.value + 1
        _count.value = n
        if (showsMessage) _current.value = Shown(message, n)
    }

    /** The timer of show [serial] ran out; a newer message stays. */
    fun hide(serial: Int) {
        if (_current.value?.serial == serial) _current.value = null
    }

    companion object {
        const val VISIBLE_MILLIS = 1600L

        /** API 33+ confirms a copy itself (the clipboard overlay). */
        fun showsOwnMessage(sdkInt: Int): Boolean = sdkInt < 33
    }
}

/** Hosts [toast] at the top of [content]: a glass capsule with a check and the message, announced politely. */
@Composable
fun CopyToastHost(toast: CopyToast, content: @Composable BoxScope.() -> Unit) {
    val shown by toast.current.collectAsStateWithLifecycle()
    val count by toast.count.collectAsStateWithLifecycle()
    val haptic = LocalHapticFeedback.current
    val initialCount = remember { count }
    LaunchedEffect(count) { if (count != initialCount) haptic.performHapticFeedback(HapticFeedbackType.Confirm) }
    LaunchedEffect(shown?.serial) {
        val s = shown ?: return@LaunchedEffect
        delay(CopyToast.VISIBLE_MILLIS)
        toast.hide(s.serial)
    }
    Box(Modifier.fillMaxSize()) {
        content()
        val last = remember { arrayOfNulls<String>(1) }
        shown?.let { last[0] = it.message }
        AnimatedVisibility(
            visible = shown != null,
            enter = slideInVertically { -it } + fadeIn(),
            exit = slideOutVertically { -it } + fadeOut(),
            modifier = Modifier.align(Alignment.TopCenter).statusBarsPadding().padding(top = 6.dp),
        ) {
            val c = LgkTheme.colors
            Row(
                Modifier
                    .lgkGlass(CircleShape)
                    .semantics { liveRegion = LiveRegionMode.Polite }
                    .testTag("copy-toast")
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Filled.CheckCircle, null, Modifier.size(18.dp), tint = c.success)
                Spacer(Modifier.width(8.dp))
                Text(last[0] ?: "", color = c.text, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            }
        }
    }
}
