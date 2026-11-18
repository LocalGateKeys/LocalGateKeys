package app.localgatekeys.android.ui.theme

import android.os.Build
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.BlurEffect
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.TileMode
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.layer.GraphicsLayer
import androidx.compose.ui.graphics.layer.drawLayer
import androidx.compose.ui.graphics.rememberGraphicsLayer
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * What the glass blurs: the screen content below the controls (aurora and pages), recorded once into a layer and
 * blurred with a RenderEffect (Android 12 and later). Null where there is no blur (older Android, previews, tests).
 */
val LocalGlassBackdrop = compositionLocalOf<GraphicsLayer?> { null }

/** Blur radius of the glass backdrop. */
val GlassBlurRadius = 24.dp

/**
 * Records [content] into a layer for the glass above it, blurred on Android 12 and later. Glass controls must be drawn
 * outside [content] (as siblings above it), never inside, or they would blur themselves.
 *
 * Inside [content] there is never a backdrop: [LocalGlassBackdrop] is null there, so an [lgkGlass] placed in the content
 * by mistake draws the solid fill. Sampling the layer it is being recorded into made a render-node cycle and crashed
 * the RenderThread (Security check's back arrow, release check 2026-11-01).
 */
@Composable
fun GlassBackdropHost(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    val raw = rememberGraphicsLayer()
    val blurred = rememberGraphicsLayer()
    val canBlur = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    Box(
        modifier.drawWithContent {
            raw.record { this@drawWithContent.drawContent() }
            if (canBlur) {
                val r = GlassBlurRadius.toPx()
                blurred.renderEffect = BlurEffect(r, r, TileMode.Clamp)
                blurred.record { drawLayer(raw) }
            }
            drawLayer(raw)
        },
    ) {
        CompositionLocalProvider(LocalGlassBackdrop provides null) { content() }
    }
}

/**
 * Glass for controls only (tab bar, plus and avatar buttons). Content never sits on glass.
 * Android 12 and later: a real backdrop blur (see [GlassBackdropHost]) under a translucent fill; below: the fill made
 * opaque (without blur, anything translucent lets text behind it through). Always a 0.5 dp highlight border. Reduced transparency: the solid glass fill; increased contrast: a 1.5 dp border.
 */
fun Modifier.lgkGlass(shape: Shape): Modifier = composed {
    val colors = LgkTheme.colors
    val strong = LgkTheme.increasedContrast
    val backdrop = LocalGlassBackdrop.current
    var origin by remember { mutableStateOf(Offset.Zero) }
    if (LgkTheme.reduceTransparency) {
        background(colors.glassFill, shape)
            .border(BorderStroke(if (strong) 1.5.dp else 0.5.dp, colors.glassBorder), shape)
    } else {
        val highlight = if (strong) colors.glassBorder else Color.White.copy(alpha = if (LgkTheme.isDark) 0.18f else 0.6f)
        val fillAlpha = if (backdrop != null) {
            if (LgkTheme.isDark) 0.45f else 0.5f
        } else {
            // No blur below Android 12: opaque, or list text scrolling under the tab bar shows through.
            1f
        }
        onGloballyPositioned { origin = it.positionInRoot() }
            .clip(shape)
            .drawBehind {
                if (backdrop != null) {
                    translate(-origin.x, -origin.y) { drawLayer(backdrop) }
                }
            }
            .background(colors.glassFill.copy(alpha = fillAlpha), shape)
            .border(BorderStroke(if (strong) 1.5.dp else 0.5.dp, highlight), shape)
    }
}

/**
 * A toast capsule (copy, Undo): it carries text, so it is solid like a group, never glass. The group surface, a hairline
 * border and a soft shadow so it lifts off the list below.
 */
fun Modifier.lgkToastSurface(shape: Shape): Modifier = composed {
    val dark = LgkTheme.isDark
    val shadowColor = Color.Black.copy(alpha = if (dark) 0.40f else 0.14f)
    shadow(12.dp, shape, ambientColor = shadowColor, spotColor = shadowColor)
        .background(LgkTheme.colors.groupSurface, shape)
        .border(BorderStroke(if (LgkTheme.increasedContrast) 1.5.dp else 0.5.dp, LgkTheme.colors.glassBorder), shape)
}

/** A solid content group: group surface, a 1 dp top highlight and a soft shadow so it lifts off the glow. */
fun Modifier.lgkGroupSurface(cornerRadius: Dp = 22.dp): Modifier = composed {
    val shape = RoundedCornerShape(cornerRadius)
    val dark = LgkTheme.isDark
    val shadowColor = Color.Black.copy(alpha = if (dark) 0.30f else 0.08f)
    shadow(18.dp, shape, ambientColor = shadowColor, spotColor = shadowColor)
        .background(LgkTheme.colors.groupSurface, shape)
        .border(
            1.dp,
            Brush.verticalGradient(
                0f to Color.White.copy(alpha = if (dark) 0.12f else 0.9f),
                0.08f to Color.Transparent,
                1f to Color.Transparent,
            ),
            shape,
        )
}
