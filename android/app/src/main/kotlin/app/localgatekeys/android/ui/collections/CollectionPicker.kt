package app.localgatekeys.android.ui.collections

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.R
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.core.sync.CollectionStates

/**
 * Which collections an item is in (the editor's Collections row; typed items only, never logins). At most 20: a
 * collection past that cannot be ticked. View-only collections show a lock and are never ticked or unticked here. Ids of
 * collections this phone does not know stay in the selection untouched. [onDone] gets the new selection.
 */
@Composable
fun CollectionPicker(
    collections: List<CollectionCatalog.Collection>,
    readOnly: Set<String>,
    selection: Set<String>,
    onDone: (Set<String>) -> Unit,
    onDismiss: () -> Unit,
) {
    val c = LgkTheme.colors
    var picked by remember { mutableStateOf(selection) }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton({ onDone(picked) }, Modifier.testTag("collection-picker-done")) { Text(stringResource(R.string.common_done)) } },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.common_cancel)) } },
        title = { Text(stringResource(R.string.collections_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()).testTag("collection-picker")) {
                if (collections.isEmpty()) {
                    Text(stringResource(R.string.collections_none), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
                }
                for (collection in collections) {
                    val on = collection.id in picked
                    val locked = collection.id in readOnly
                    val enabled = !locked && (on || picked.size < CollectionStates.MAX_MEMBERSHIPS)
                    Row(
                        Modifier.fillMaxWidth().heightIn(min = 48.dp)
                            .clickable(enabled = enabled, role = Role.Checkbox) {
                                picked = if (on) picked - collection.id else picked + collection.id
                            }
                            .testTag("collection-picker-row"),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(on, null, enabled = enabled)
                        Spacer(Modifier.width(8.dp))
                        Text(app.localgatekeys.android.collections.collectionDisplayName(collection.name), color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                        if (locked) Icon(Icons.Filled.Lock, stringResource(R.string.collections_view_only), Modifier.size(18.dp), tint = c.secondaryText)
                    }
                }
                Text(
                    stringResource(R.string.collections_picker_footer), color = c.secondaryText, style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
        },
    )
}
