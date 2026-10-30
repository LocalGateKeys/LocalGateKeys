package app.localgatekeys.android.ui.pro
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.R

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AllInclusive
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.ui.theme.LgkTheme

/**
 * The free plan's slots, one tile each, filled for every item saved (all filled once Pro is active), then the wider
 * unlimited tile. With no count ([used] null), the slots are drawn empty and the caption gives the free limit.
 */
@Composable
fun CapacityStrip(used: Int?, isPro: Boolean, modifier: Modifier = Modifier) {
    val c = LgkTheme.colors
    val caption = CapacityStrip.caption(used, isPro, rememberTxt())
    val shape = RoundedCornerShape(10.dp)
    Column(
        modifier.fillMaxWidth().clearAndSetSemantics { contentDescription = caption }.testTag("capacity"),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            for (slot in 0 until ItemLimit.FREE_ITEMS) {
                val filled = CapacityStrip.filled(slot, used, isPro)
                Box(
                    Modifier.size(46.dp)
                        .background(if (filled) c.accent.copy(alpha = 0.85f) else c.groupSurface, shape)
                        .border(1.5.dp, c.accent.copy(alpha = if (filled) 0f else 0.35f), shape),
                )
            }
            Box(
                Modifier.weight(1f).height(46.dp).background(Brush.horizontalGradient(listOf(c.accent, c.glowBlue)), shape),
                contentAlignment = Alignment.Center,
            ) { Icon(Icons.Filled.AllInclusive, null, tint = Color.White, modifier = Modifier.size(24.dp)) }
        }
        Text(
            caption, color = c.secondaryText, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium,
            textAlign = TextAlign.Center,
        )
    }
}

/** The strip's rules, for tests. */
object CapacityStrip {
    fun filled(slot: Int, used: Int?, isPro: Boolean): Boolean = isPro || slot < minOf(used ?: 0, ItemLimit.FREE_ITEMS)

    fun caption(used: Int?, isPro: Boolean, txt: Txt): String {
        val free = ItemLimit.FREE_ITEMS
        if (isPro) return txt.s(R.string.capacity_no_limit)
        if (used == null) return txt.plural(R.plurals.capacity_free_limit, free, free)
        return txt.plural(R.plurals.capacity_used, free, minOf(used, free), free)
    }
}
