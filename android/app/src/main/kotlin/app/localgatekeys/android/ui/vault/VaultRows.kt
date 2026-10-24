package app.localgatekeys.android.ui.vault

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.vault.Copier
import app.localgatekeys.android.vault.CodeTileModel
import app.localgatekeys.android.vault.QuickAction
import app.localgatekeys.android.vault.QuickActions
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.primitives.UnixClock

/** A section title above a group of rows. */
@Composable
fun SectionHeader(title: String) {
    Text(
        title,
        color = LgkTheme.colors.secondaryText,
        style = MaterialTheme.typography.titleSmall,
        modifier = Modifier.padding(start = 12.dp, end = 12.dp, top = 14.dp, bottom = 4.dp).semantics { heading() },
    )
}

/**
 * One row of a solid grouped section. [first] and [last] round the section's corners and drop the separator.
 * Tapping opens the item; a long press shows the quick actions.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun VaultRow(
    item: VaultItem,
    first: Boolean,
    last: Boolean,
    onOpen: (String) -> Unit,
    clipboard: Copier,
    clock: UnixClock,
) {
    val c = LgkTheme.colors
    val radius = 22.dp
    val shape = RoundedCornerShape(
        topStart = if (first) radius else 0.dp, topEnd = if (first) radius else 0.dp,
        bottomStart = if (last) radius else 0.dp, bottomEnd = if (last) radius else 0.dp,
    )
    var menuOpen by remember { mutableStateOf(false) }
    val actions = remember(item) { QuickActions.forItem(item) }
    val haptic = LocalHapticFeedback.current
    val uriHandler = LocalUriHandler.current
    val run: (QuickAction) -> Unit = { a ->
        menuOpen = false
        when (a.kind) {
            QuickAction.Kind.COPY_USERNAME -> clipboard.copy(item.username, a.confirmation ?: "")
            QuickAction.Kind.COPY_PASSWORD -> item.copyablePassword?.let { clipboard.copy(it, a.confirmation ?: "") }
            QuickAction.Kind.COPY_CODE -> CodeTileModel(item, clock).copy { clipboard.copy(it, a.confirmation ?: "") }
            QuickAction.Kind.OPEN_WEBSITE -> item.openableUrl?.let {
                // No browser (or none that takes the link): nothing happens.
                try { uriHandler.openUri(it) } catch (_: Exception) {}
            }
        }
    }
    Box(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth().clip(shape).background(c.groupSurface)) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .combinedClickable(
                        onClick = { onOpen(item.id) },
                        onLongClick = {
                            if (actions.isNotEmpty()) {
                                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                menuOpen = true
                            }
                        },
                    )
                    .semantics {
                        customActions = actions.map { a -> CustomAccessibilityAction(a.label) { run(a); true } }
                    }
                    .testTag("vault-row")
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                ItemAvatar(item)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        item.title.ifEmpty { item.kindLabel }, color = c.text, style = MaterialTheme.typography.titleMedium,
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        item.listSubtitle, color = c.secondaryText, style = MaterialTheme.typography.bodyMedium,
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                }
                if (item.favorite) {
                    Icon(Icons.Filled.Star, "Favorite", Modifier.size(16.dp), tint = c.warning)
                    Spacer(Modifier.width(6.dp))
                }
                Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null, Modifier.size(20.dp), tint = c.secondaryText)
            }
            if (!last) Box(Modifier.padding(start = 70.dp).fillMaxWidth().height(1.dp).background(c.separator))
        }
        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
            for (a in actions) DropdownMenuItem(text = { Text(a.label) }, onClick = { run(a) })
        }
    }
}
