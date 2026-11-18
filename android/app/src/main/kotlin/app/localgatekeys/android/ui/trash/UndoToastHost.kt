package app.localgatekeys.android.ui.trash

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
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.R
import app.localgatekeys.android.trash.UndoToast
import app.localgatekeys.android.ui.shell.FloatingTabBarBottomGap
import app.localgatekeys.android.ui.shell.FloatingTabBarHeight
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkToastSurface
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Hosts [toast] at the bottom of [content], above the tab bar ([bottomPadding]): a solid capsule with a trash icon, the
 * message and, after a delete, Undo. Its live region reads the message (with "Undo is available") and stays [UndoToast.Shown.millis].
 */
@Composable
fun UndoToastHost(
    toast: UndoToast,
    bottomPadding: Dp = FloatingTabBarHeight + FloatingTabBarBottomGap + 8.dp,
    content: @Composable BoxScope.() -> Unit,
) {
    val shown by toast.current.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    LaunchedEffect(shown?.serial) {
        val s = shown ?: return@LaunchedEffect
        delay(s.millis)
        toast.hide(s.serial)
    }
    Box(Modifier.fillMaxSize()) {
        content()
        // The last message stays drawn while the capsule slides out.
        val last = remember { arrayOfNulls<UndoToast.Shown>(1) }
        shown?.let { last[0] = it }
        AnimatedVisibility(
            visible = shown != null,
            enter = slideInVertically { it } + fadeIn(),
            exit = slideOutVertically { it } + fadeOut(),
            modifier = Modifier.align(Alignment.BottomCenter).navigationBarsPadding().padding(start = 16.dp, end = 16.dp, bottom = bottomPadding),
        ) {
            val s = last[0]
            val c = LgkTheme.colors
            val undoLabel = stringResource(R.string.trash_undo)
            val undoHint = stringResource(R.string.trash_undo_hint)
            Row(
                Modifier
                    .lgkToastSurface(CircleShape)
                    .semantics { liveRegion = LiveRegionMode.Polite; s?.let { contentDescription = it.announcement } }
                    .testTag("undo-toast")
                    .padding(start = 16.dp, end = if (s?.hasUndo == true) 4.dp else 16.dp, top = 4.dp, bottom = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (s?.hasUndo == true) {
                    Icon(Icons.Filled.Delete, null, Modifier.size(18.dp), tint = c.secondaryText)
                    Spacer(Modifier.width(10.dp))
                }
                Text(
                    s?.message ?: "", color = c.text, style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(vertical = 8.dp),
                )
                if (s?.hasUndo == true) {
                    Spacer(Modifier.width(4.dp))
                    TextButton(
                        { scope.launch { toast.undo() } },
                        modifier = Modifier.testTag("undo-button").semantics { onClick(label = undoHint) { scope.launch { toast.undo() }; true } },
                    ) { Text(undoLabel, color = c.accentText, fontWeight = FontWeight.SemiBold) }
                }
            }
        }
    }
}
