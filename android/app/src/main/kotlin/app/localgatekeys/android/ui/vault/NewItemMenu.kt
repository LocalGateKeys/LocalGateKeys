package app.localgatekeys.android.ui.vault

import app.localgatekeys.android.i18n.rememberTxt
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.ui.theme.LgkTheme

/** The plus button's menu: the kinds of new item in three sections (`EditorKind.menuSections`). */
@Composable
fun NewItemMenu(expanded: Boolean, onDismiss: () -> Unit, onAddFile: (() -> Unit)? = null, onPick: (kind: EditorKind) -> Unit) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    DropdownMenu(expanded = expanded, onDismissRequest = onDismiss) {
        // Task 12: a document with an encrypted file (Files, Photos or the camera).
        if (onAddFile != null) {
            DropdownMenuItem(
                text = { Text(txt.s(app.localgatekeys.android.attachments.DocumentText.ADD)) },
                leadingIcon = { Icon(KindStyle.icon("document"), null, tint = KindStyle.tint("document", c)) },
                onClick = onAddFile,
                modifier = Modifier.testTag("new-file"),
            )
            HorizontalDivider()
        }
        for ((i, section) in EditorKind.menuSections.withIndex()) {
            if (i > 0) HorizontalDivider()
            for (kind in section) {
                DropdownMenuItem(
                    text = { Text(kind.label(txt)) },
                    leadingIcon = { Icon(KindStyle.icon(kind.raw), null, tint = KindStyle.tint(kind.raw, c)) },
                    onClick = { onPick(kind) },
                )
            }
        }
    }
}
