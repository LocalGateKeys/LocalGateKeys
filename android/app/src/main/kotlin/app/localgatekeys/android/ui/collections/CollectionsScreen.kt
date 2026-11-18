package app.localgatekeys.android.ui.collections

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.R
import app.localgatekeys.android.collections.CollectionsModel
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.ui.settings.Page
import app.localgatekeys.android.ui.settings.RowButton
import app.localgatekeys.android.ui.settings.Section
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.core.sync.CollectionCatalog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Vault › Collections (sub-plan 07 Task 5l, the iPhone's `CollectionsView`): every collection with its item count; New
 * collection creates one; each row's menu renames or deletes it (after a confirmation; its items stay). The starters can
 * be added while any is missing (never automatically). Shared collections show a people icon and a Shared badge and are
 * never deleted here; view-only ones show a lock and are not renamed. [onChange] runs after every change (the Vault
 * list reloads and a sync is scheduled).
 */
@Composable
fun CollectionsScreen(model: CollectionsModel, onChange: () -> Unit, onBack: () -> Unit, share: CollectionShareSeams? = null) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val scope = rememberCoroutineScope()
    val state by model.state.collectAsStateWithLifecycle()
    // Sub-plan 07 Task 5m: collections this phone was removed from since unlock (their items went to Recently deleted).
    val removedShares = share?.sync?.removedShares?.collectAsStateWithLifecycle()?.value ?: emptyMap()
    // The open share sheet: a collection's id, or JOIN for "Join a shared collection".
    var sharing by remember { mutableStateOf<String?>(null) }
    var creating by remember { mutableStateOf(false) }
    var renaming by remember { mutableStateOf<CollectionsModel.Row?>(null) }
    var deleting by remember { mutableStateOf<CollectionsModel.Row?>(null) }
    var busy by remember { mutableStateOf(false) }
    BackHandler(onBack = onBack)
    LaunchedEffect(model) { withContext(Dispatchers.IO) { model.reload() } }

    fun run(action: () -> Boolean) {
        if (busy) return
        busy = true
        scope.launch {
            val changed = withContext(Dispatchers.IO) { action() }
            busy = false
            if (changed) onChange()
        }
    }

    Page(txt.s(R.string.collections_title), "collections", onBack = onBack, doneLabel = stringResource(R.string.common_back)) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(start = 16.dp, end = 16.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            Section(null, footer = txt.s(R.string.collections_footer), tag = "collections-rows") {
                if (state.rows.isEmpty()) {
                    Text(
                        stringResource(R.string.collections_none), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.padding(vertical = 14.dp).testTag("collections-empty"),
                    )
                }
                state.rows.forEachIndexed { index, row ->
                    if (index > 0) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
                    CollectionRow(
                        row, enabled = !busy, removed = row.id in removedShares && !row.isShared,
                        onRename = { renaming = row }, onDelete = { deleting = row },
                        onShare = share?.let { { model.clearMessage(); sharing = row.id } },
                    )
                }
                RowButton(stringResource(R.string.collections_new), "collections-new", enabled = !busy, divider = state.rows.isNotEmpty()) {
                    model.clearMessage()
                    creating = true
                }
            }
            if (state.missingStarters) {
                Section(null, footer = CollectionCatalog.STARTER_NAMES.map { app.localgatekeys.android.collections.collectionDisplayName(it) }.joinToString(", "), tag = "collections-starters") {
                    RowButton(stringResource(R.string.collections_add_starters), "collections-add-starters", enabled = !busy, divider = false) {
                        run { model.addStarters() }
                    }
                }
            }
            if (share != null) {
                Section(null, footer = txt.s(R.string.collection_share_join_intro), tag = "collections-join") {
                    RowButton(stringResource(R.string.collection_share_join_title), "collections-join-share", enabled = !busy, divider = false) {
                        model.clearMessage()
                        sharing = JOIN
                    }
                }
            }
            state.message?.let { message ->
                Text(message, color = c.danger, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(horizontal = 4.dp).testTag("collections-message"))
            }
        }
    }
    if (creating) {
        NameDialog(
            title = stringResource(R.string.collections_new), initial = "", confirm = stringResource(R.string.collections_create),
            onDismiss = { creating = false },
        ) { name ->
            creating = false
            run { model.create(name) != null }
        }
    }
    renaming?.let { row ->
        NameDialog(
            title = stringResource(R.string.common_rename), initial = row.name, confirm = stringResource(R.string.common_save),
            onDismiss = { renaming = null },
        ) { name ->
            renaming = null
            run { model.rename(row.id, name) }
        }
    }
    val shown = sharing
    if (share != null && shown != null) {
        CollectionShareSheet(
            if (shown == JOIN) null else shown, share,
            onChange = {
                scope.launch { withContext(Dispatchers.IO) { model.reload() } }
                onChange()
            },
            onClose = {
                sharing = null
                // A folder picked but not used is given up (the shared collections' folders stay).
                scope.launch { share.sync.releaseUnusedFolders() }
                scope.launch { withContext(Dispatchers.IO) { model.reload() } }
            },
        )
    }
    deleting?.let { row ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            confirmButton = {
                TextButton({ deleting = null; run { model.delete(row.id) } }, Modifier.testTag("collections-confirm-delete")) {
                    Text(stringResource(R.string.common_delete), color = c.danger)
                }
            },
            dismissButton = { TextButton({ deleting = null }) { Text(stringResource(R.string.common_cancel)) } },
            title = { Text(stringResource(R.string.collections_delete_title)) },
            text = { Text(stringResource(R.string.collections_delete_message)) },
        )
    }
}

/** [sharing]'s value for the Join sheet (no collection yet; never a collection id, which is a UUID). */
private const val JOIN = "join"

@Composable
private fun CollectionRow(
    row: CollectionsModel.Row,
    enabled: Boolean,
    removed: Boolean,
    onRename: () -> Unit,
    onDelete: () -> Unit,
    onShare: (() -> Unit)?,
) {
    val c = LgkTheme.colors
    var menu by remember { mutableStateOf(false) }
    val countDescription = stringResource(R.string.collections_item_count, app.localgatekeys.android.collections.collectionDisplayName(row.name), row.count)
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("collection-row"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(if (row.isShared) Icons.Filled.Group else Icons.Filled.Folder, null, Modifier.size(22.dp), tint = c.accentText)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f).padding(vertical = 8.dp).semantics(mergeDescendants = true) { contentDescription = countDescription }) {
            Text(app.localgatekeys.android.collections.collectionDisplayName(row.name), color = c.text, style = MaterialTheme.typography.bodyLarge)
            if (removed) {
                Text(
                    stringResource(R.string.collection_share_removed_badge), color = c.secondaryText, style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier.testTag("collection-removed-badge"),
                )
            }
            if (row.isShared || row.isReadOnly) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (row.isShared) {
                        Text(
                            stringResource(R.string.collections_shared), color = c.accentText, style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.background(c.innerTile, RoundedCornerShape(50)).padding(horizontal = 6.dp, vertical = 1.dp),
                        )
                    }
                    if (row.isReadOnly) {
                        Icon(Icons.Filled.Lock, null, Modifier.size(14.dp), tint = c.secondaryText)
                        Text(stringResource(R.string.collections_view_only), color = c.secondaryText, style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }
        Text(row.count.toString(), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
        if (onShare != null || !row.isReadOnly || !row.isShared) {
            IconButton({ menu = true }, enabled = enabled, modifier = Modifier.testTag("collection-row-menu")) {
                Icon(Icons.Filled.MoreVert, stringResource(R.string.collections_manage), tint = c.text)
            }
            DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                if (onShare != null) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.collection_share_share)) },
                        leadingIcon = { Icon(Icons.Filled.Group, null) },
                        onClick = { menu = false; onShare() },
                        modifier = Modifier.testTag("collection-share"),
                    )
                }
                if (!row.isReadOnly) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.common_rename)) },
                        leadingIcon = { Icon(Icons.Filled.Edit, null) },
                        onClick = { menu = false; onRename() },
                        modifier = Modifier.testTag("collection-rename"),
                    )
                }
                if (!row.isShared) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.common_delete), color = c.danger) },
                        onClick = { menu = false; onDelete() },
                        modifier = Modifier.testTag("collection-delete"),
                    )
                }
            }
        } else {
            Spacer(Modifier.width(48.dp))
        }
    }
}

/** A name field with [confirm] and Cancel (New collection, Rename). */
@Composable
private fun NameDialog(title: String, initial: String, confirm: String, onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var name by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton({ onConfirm(name) }, enabled = name.isNotBlank(), modifier = Modifier.testTag("collections-name-confirm")) { Text(confirm) }
        },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.common_cancel)) } },
        title = { Text(title) },
        text = {
            OutlinedTextField(
                name, { name = it }, singleLine = true, label = { Text(stringResource(R.string.collections_name)) },
                modifier = Modifier.fillMaxWidth().testTag("collections-name"),
            )
        },
    )
}
