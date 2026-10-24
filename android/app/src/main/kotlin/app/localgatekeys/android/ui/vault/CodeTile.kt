package app.localgatekeys.android.ui.vault

import androidx.compose.animation.core.AnimationSpec
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.snap
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.vault.Copier
import app.localgatekeys.android.vault.CodeTileModel
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.primitives.UnixClock
import kotlinx.coroutines.delay

/** The clock's seconds, updated once a second (on the second boundary) while the screen is started. */
@Composable
fun rememberSecondTick(clock: UnixClock): Long {
    var now by remember(clock) { mutableLongStateOf(clock.now) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(clock, lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                now = clock.now
                delay(1000L - System.currentTimeMillis() % 1000L)
            }
        }
    }
    return now
}

/**
 * One tile of the Codes row (160 dp): the item's avatar and title, its code as "123 456", a countdown bar that turns
 * orange in the last seven seconds, or a dash when there is no code. Tapping copies the code. The model is recreated
 * when the item changes, so an edited secret never shows or copies the old code.
 */
@Composable
fun CodeTile(item: VaultItem, clock: UnixClock, tick: Long, clipboard: Copier) {
    val c = LgkTheme.colors
    // Keyed on the item: an edited item gets a new model, so the old code is never shown or copied.
    val current = remember(item, clock) { CodeTileModel.modelFor(item, null, clock) }
    // A new tick (every second) or a new model recomputes the code from the clock.
    val state = remember(tick, current) { current.state }
    val title = item.title.ifEmpty { item.kindLabel }
    Column(
        Modifier
            .width(160.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(c.innerTile)
            .clickable(role = Role.Button) { current.copy { clipboard.copy(it, "Code copied") } }
            .semantics(mergeDescendants = true) {
                contentDescription = if (state != null) "$title, code ${state.code}. Copies the code" else "$title, no code"
            }
            .testTag("code-tile")
            .padding(14.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            ItemAvatar(item, 20.dp)
            Spacer(Modifier.width(6.dp))
            Text(
                title, color = c.secondaryText, style = MaterialTheme.typography.bodyMedium,
                maxLines = 1, overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.height(6.dp))
        if (state != null) {
            Text(
                CodeTileModel.grouped(state.code), color = c.accentText,
                fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, fontSize = 22.sp,
                modifier = Modifier.testTag("code-text"),
            )
            Spacer(Modifier.height(6.dp))
            CountdownBar(
                state.fractionRemaining.toFloat(),
                if (CodeTileModel.isUrgent(state.secondsRemaining)) c.glowOrange else c.accent,
            )
        } else {
            Text("—", color = c.secondaryText, fontSize = 22.sp, modifier = Modifier.testTag("code-text"))
            Spacer(Modifier.height(6.dp))
            Spacer(Modifier.height(5.dp))
        }
    }
}

/** The 2FA countdown: a 5 dp rounded bar. */
@Composable
fun CountdownBar(fraction: Float, tint: androidx.compose.ui.graphics.Color) {
    val c = LgkTheme.colors
    val target = fraction.coerceIn(0f, 1f)
    val previous = remember { floatArrayOf(target) }
    // The bar runs down smoothly; when it goes up (a new period) it jumps instead of sweeping back.
    val spec: AnimationSpec<Float> = if (target > previous[0]) snap() else tween(1000, easing = LinearEasing)
    SideEffect { previous[0] = target }
    val f by animateFloatAsState(target, spec, label = "countdown")
    Box(Modifier.fillMaxWidth().height(5.dp).clip(CircleShape).background(c.separator)) {
        Box(Modifier.fillMaxWidth(maxOf(f, 0.03f)).fillMaxHeight().clip(CircleShape).background(tint))
    }
}
