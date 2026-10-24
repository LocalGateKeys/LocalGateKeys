package app.localgatekeys.android.ui.generator

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import kotlin.math.ceil
import kotlin.math.roundToInt

/** Left-aligned rows that wrap (port of the iOS `ChipFlowLayout.arrange`): a new row when the next item would not fit. */
object ChipFlow {
    data class Size(val width: Float, val height: Float)
    data class Point(val x: Float, val y: Float)
    data class Result(val origins: List<Point>, val size: Size)

    /** The origin of each item within [width], and the total size. An item wider than [width] gets a row of its own. */
    fun arrange(sizes: List<Size>, width: Float, spacing: Float): Result {
        val origins = ArrayList<Point>(sizes.size)
        var x = 0f
        var y = 0f
        var rowHeight = 0f
        var widest = 0f
        for (size in sizes) {
            if (x > 0 && x + size.width > width) {
                x = 0f; y += rowHeight + spacing; rowHeight = 0f
            }
            origins.add(Point(x, y))
            x += size.width + spacing
            rowHeight = maxOf(rowHeight, size.height)
            widest = maxOf(widest, x - spacing)
        }
        return Result(origins, Size(widest, if (sizes.isEmpty()) 0f else y + rowHeight))
    }
}

/** Chips at their natural width (at most the full width, then their text wraps), wrapping onto further rows. */
@Composable
fun ChipFlowLayout(modifier: Modifier = Modifier, spacing: Dp = 8.dp, content: @Composable () -> Unit) {
    Layout(content, modifier) { measurables, constraints ->
        val width = constraints.maxWidth
        val placeables = measurables.map { it.measure(Constraints(maxWidth = width)) }
        val gap = spacing.toPx()
        val r = ChipFlow.arrange(
            placeables.map { ChipFlow.Size(it.width.toFloat(), it.height.toFloat()) }, width.toFloat(), gap,
        )
        val layoutWidth = if (constraints.hasBoundedWidth) width else ceil(r.size.width).toInt()
        layout(layoutWidth, ceil(r.size.height).toInt().coerceAtLeast(constraints.minHeight)) {
            placeables.forEachIndexed { i, p -> p.place(r.origins[i].x.roundToInt(), r.origins[i].y.roundToInt()) }
        }
    }
}
