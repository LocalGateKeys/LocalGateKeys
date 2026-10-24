package app.localgatekeys.android.ui.vault

import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.ui.theme.LgkTheme

/** The plus button's menu: the kinds of new item in three sections (`EditorKind.menuSections`). */
@Composable
fun NewItemMenu(expanded: Boolean, onDismiss: () -> Unit, onPick: (kind: EditorKind) -> Unit) {
    val c = LgkTheme.colors
    DropdownMenu(expanded = expanded, onDismissRequest = onDismiss) {
        for ((i, section) in EditorKind.menuSections.withIndex()) {
            if (i > 0) HorizontalDivider()
            for (kind in section) {
                DropdownMenuItem(
                    text = { Text(kind.label) },
                    leadingIcon = { Icon(KindStyle.icon(kind.raw), null, tint = KindStyle.tint(kind.raw, c)) },
                    onClick = { onPick(kind) },
                )
            }
        }
    }
}
