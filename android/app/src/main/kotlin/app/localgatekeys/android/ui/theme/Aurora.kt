package app.localgatekeys.android.ui.theme

import android.os.Build
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.unit.dp

/** The aurora's numbers, kept apart from the view so they are testable. */
object AuroraStyle {
    /** Blob opacity; null means no blobs (reduced transparency: the plain background). */
    fun blobOpacity(dark: Boolean, reduceTransparency: Boolean, increasedContrast: Boolean): Float? {
        if (reduceTransparency) return null
        val base = if (dark) 0.45f else 0.35f
        return if (increasedContrast) base / 2 else base
    }

    /** Blur radius of the glow blobs, in dp. */
    const val BLUR_DP = 100
}

/**
 * The background colour plus large, heavily blurred blue and orange glows (blue top-leading, orange bottom-trailing,
 * a blue/orange mix mid-right). Static: nothing animates. Content groups stay opaque on top of it.
 * Below Android 12 (no render-effect blur) the same blobs are drawn as soft radial gradients.
 */
@Composable
fun AuroraBackground(modifier: Modifier = Modifier) {
    val colors = LgkTheme.colors
    val opacity = AuroraStyle.blobOpacity(LgkTheme.isDark, LgkTheme.reduceTransparency, LgkTheme.increasedContrast)
    Box(modifier.fillMaxSize().background(colors.background).clearAndSetSemantics { }) {
        if (opacity != null) {
            BoxWithConstraints(Modifier.fillMaxSize()) {
                val w = constraints.maxWidth.toFloat()
                val h = constraints.maxHeight.toFloat()
                val blobs = Modifier.fillMaxSize().alpha(opacity)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    Canvas(blobs.blur(AuroraStyle.BLUR_DP.dp)) { drawGlows(colors, w, h, solid = true) }
                } else {
                    Canvas(blobs) { drawGlows(colors, w, h, solid = false) }
                }
            }
        }
    }
}

private fun DrawScope.drawGlows(colors: Palette.Tokens, w: Float, h: Float, solid: Boolean) {
    drawBlob(colors.glowBlue, Offset(w * 0.05f, h * 0.08f), w * 1.1f / 2, solid)
    drawBlob(colors.glowOrange, Offset(w * 0.98f, h * 0.92f), w * 1.05f / 2, solid)
    if (!solid) {
        // No blur below Android 12: a soft blue-to-orange mix instead of the hard-edged ellipse.
        val mix = lerp(colors.glowBlue, colors.glowOrange, 0.5f)
        drawBlob(mix, Offset(w * 0.92f, h * 0.48f), w * 0.6f, solid = false)
        return
    }
    val size = Size(w * 0.7f, w * 0.85f)
    val topLeft = Offset(w * 0.92f - size.width / 2, h * 0.48f - size.height / 2)
    drawOval(
        Brush.verticalGradient(listOf(colors.glowBlue, colors.glowOrange), startY = topLeft.y, endY = topLeft.y + size.height),
        topLeft,
        size,
    )
}

private fun DrawScope.drawBlob(color: Color, center: Offset, radius: Float, solid: Boolean) {
    if (solid) {
        drawCircle(color, radius, center)
    } else {
        drawCircle(Brush.radialGradient(listOf(color, color.copy(alpha = 0f)), center, radius), radius, center)
    }
}
