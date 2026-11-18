package app.localgatekeys.android.ui.trash

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.trash.PhoneTrash
import app.localgatekeys.android.trash.UndoToast
import app.localgatekeys.android.ui.settings.Page
import app.localgatekeys.android.ui.settings.RowButton
import app.localgatekeys.android.ui.settings.Section
import app.localgatekeys.android.ui.theme.LgkTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Settings › Recently deleted (port of `ios/App/Trash/TrashView.swift`): rows with days left, Restore, Delete forever
 * (each confirmed), Empty Recently deleted (confirmed), and how long items are kept.
 *
 * [isPro] is read at each restore; over the free limit [onUpgrade] opens the upgrade sheet. [onRestored] runs after a
 * restore (the vault list reloads and a sync is scheduled); [toast] shows "Item restored" (null: nothing is shown).
 */
@Composable
fun RecentlyDeletedScreen(
    trash: PhoneTrash,
    isPro: () -> Boolean,
    onUpgrade: () -> Unit,
    onRestored: () -> Unit,
    toast: UndoToast?,
    onBack: () -> Unit,
) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val scope = rememberCoroutineScope()
    val rows by trash.rows.collectAsStateWithLifecycle()
    var message by remember { mutableStateOf<String?>(null) }
    var confirmEmpty by remember { mutableStateOf(false) }
    var purgeRow by remember { mutableStateOf<PhoneTrash.Row?>(null) }
    var retention by remember { mutableIntStateOf(30) }
    var busy by remember { mutableStateOf(false) }
    val saveFailed = stringResource(R.string.trash_save_failed)
    BackHandler(onBack = onBack)
    LaunchedEffect(trash) {
        withContext(Dispatchers.IO) { trash.purgeExpired() }
        val days = trash.retentionDays
        retention = if (days in PhoneTrash.RETENTION_CHOICES) days else 30
    }

    fun restore(row: PhoneTrash.Row) {
        if (busy) return
        busy = true
        scope.launch {
            val r = withContext(Dispatchers.IO) { trash.restore(row.id, isPro()) }
            busy = false
            when (r) {
                PhoneTrash.RestoreOutcome.Restored -> {
                    message = null
                    onRestored()
                    toast?.info(txt.s(R.string.trash_item_restored))
                }
                PhoneTrash.RestoreOutcome.Limit -> onUpgrade()
                is PhoneTrash.RestoreOutcome.Failed -> message = r.message
            }
        }
    }

    fun change(block: () -> Unit) {
        scope.launch {
            message = try {
                withContext(Dispatchers.IO) { block() }
                null
            } catch (e: Exception) {
                saveFailed
            }
        }
    }

    Page(txt.s(R.string.trash_title), "recently-deleted", onBack = onBack, doneLabel = stringResource(R.string.common_back)) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(start = 16.dp, end = 16.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            val reset = if (trash.local.wasReset) stringResource(R.string.trash_reset) else null
            Section(null, footer = message ?: reset, tag = "trash-rows") {
                if (rows.isEmpty()) {
                    Text(
                        stringResource(R.string.trash_empty), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.padding(vertical = 14.dp).testTag("trash-empty"),
                    )
                }
                rows.forEachIndexed { index, row ->
                    if (index > 0) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
                    TrashRowView(
                        row, trash.daysLeftText(row), enabled = !busy,
                        onRestore = { restore(row) }, onDeleteForever = { purgeRow = row },
                    )
                }
            }
            Section(null, footer = txt.s(R.string.trash_footer), tag = "trash-settings") {
                RetentionPicker(retention) { days ->
                    retention = days
                    change { trash.setRetentionDays(days) }
                }
                RowButton(
                    txt.s(R.string.trash_empty_all), "trash-empty-all", enabled = rows.isNotEmpty(), destructive = true,
                ) { confirmEmpty = true }
            }
        }
    }
    if (confirmEmpty) {
        AlertDialog(
            onDismissRequest = { confirmEmpty = false },
            confirmButton = {
                TextButton({ confirmEmpty = false; change { trash.emptyAll() } }, Modifier.testTag("confirm-empty")) {
                    Text(stringResource(R.string.trash_delete_forever), color = c.danger)
                }
            },
            dismissButton = { TextButton({ confirmEmpty = false }) { Text(stringResource(R.string.common_cancel)) } },
            title = { Text(stringResource(R.string.trash_empty_all_title)) },
            text = { Text(stringResource(R.string.trash_empty_all_message)) },
        )
    }
    purgeRow?.let { row ->
        AlertDialog(
            onDismissRequest = { purgeRow = null },
            confirmButton = {
                TextButton({ purgeRow = null; change { trash.purge(setOf(row.id)) } }, Modifier.testTag("confirm-delete-forever")) {
                    Text(stringResource(R.string.trash_delete_forever), color = c.danger)
                }
            },
            dismissButton = { TextButton({ purgeRow = null }) { Text(stringResource(R.string.common_cancel)) } },
            title = { Text(stringResource(R.string.trash_delete_forever_title)) },
            text = { Text(stringResource(R.string.trash_delete_forever_message, row.title)) },
        )
    }
}

@Composable
private fun TrashRowView(row: PhoneTrash.Row, daysLeft: String, enabled: Boolean, onRestore: () -> Unit, onDeleteForever: () -> Unit) {
    val c = LgkTheme.colors
    val restoreLabel = stringResource(R.string.common_restore)
    val deleteLabel = stringResource(R.string.trash_delete_forever)
    val second = stringResource(R.string.trash_join, row.detail, daysLeft)
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("trash-row")
            .semantics {
                customActions = listOf(
                    CustomAccessibilityAction(restoreLabel) { onRestore(); true },
                    CustomAccessibilityAction(deleteLabel) { onDeleteForever(); true },
                )
            },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).padding(vertical = 8.dp)) {
            Text(row.title, color = c.text, style = MaterialTheme.typography.bodyLarge)
            Text(second, color = c.secondaryText, style = MaterialTheme.typography.bodyMedium)
        }
        OutlinedButton(
            onRestore, enabled = enabled, modifier = Modifier.testTag("trash-restore"),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = c.accentText),
        ) { Text(restoreLabel) }
        IconButton(onDeleteForever, enabled = enabled, modifier = Modifier.testTag("trash-delete-forever")) {
            Icon(Icons.Filled.Delete, deleteLabel, tint = c.danger)
        }
    }
}

/** "Keep deleted items for" with the iPhone's choices (1, 7, 14, 30, 60, 90, 180, 365 days). */
@Composable
private fun RetentionPicker(selected: Int, onPick: (Int) -> Unit) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    var open by remember { mutableStateOf(false) }
    val label = stringResource(R.string.trash_keep_for)
    val value = PhoneTrash.daysText(selected, txt)
    val description = stringResource(R.string.common_label_value, label, value)
    Box {
        Row(
            Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.DropdownList) { open = true }
                .semantics { contentDescription = description }.testTag("trash-retention"),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Text(value, color = c.accentText, style = MaterialTheme.typography.bodyLarge)
        }
        DropdownMenu(open, onDismissRequest = { open = false }) {
            for (days in PhoneTrash.RETENTION_CHOICES) {
                DropdownMenuItem(text = { Text(PhoneTrash.daysText(days, txt)) }, onClick = { open = false; onPick(days) })
            }
        }
    }
}
