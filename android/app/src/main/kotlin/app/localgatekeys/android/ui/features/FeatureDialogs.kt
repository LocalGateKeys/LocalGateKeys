package app.localgatekeys.android.ui.features

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.R
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.history.FeatureSeams
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.history.ItemHistory
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.core.sync.TravelMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

private fun shown(v: JsonValue?): String = when (v) {
    null, JsonValue.Null -> "-"
    is JsonValue.Str -> v.v
    is JsonValue.Bool -> v.v.toString()
    is JsonValue.Int -> v.v.toString()
    else -> "..."
}

/**
 * An item's History on this phone (contract section 1.5): the kept versions, newest first, each with what changed
 * since it (secrets shown as protected), and Restore for one field.
 */
@Composable
fun HistoryDialog(
    item: VaultItem,
    rows: List<ItemHistory.Row>,
    restore: suspend (ItemHistory.Row, String) -> SaveResult,
    onDone: (Boolean) -> Unit,
) {
    val scope = rememberCoroutineScope()
    var error by remember { mutableStateOf<String?>(null) }
    val notRestorable = stringResource(R.string.history_not_restorable)
    val invalidHere = stringResource(R.string.history_invalid_here)
    val protectedText = stringResource(R.string.history_protected)
    AlertDialog(
        onDismissRequest = { onDone(false) },
        title = { Text(stringResource(R.string.history_title)) },
        text = {
            Column {
                Text(stringResource(R.string.history_device_only))
                Text(stringResource(R.string.history_free_window), Modifier.padding(top = 4.dp))
                if (rows.isEmpty()) Text(stringResource(R.string.history_empty), Modifier.padding(top = 8.dp))
                error?.let { Text(it) }
                LazyColumn(Modifier.heightIn(max = 420.dp).testTag("history-list")) {
                    items(rows, key = { it.snapshotId }) { row ->
                        val changes = remember(row) { ItemHistory.diff(row.record, item.record, item.kind, reveal = false) }
                        Column(Modifier.padding(vertical = 8.dp)) {
                            Text(
                                DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(row.createdAt * 1000)),
                                fontWeight = FontWeight.SemiBold,
                            )
                            for (c in changes) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    val before = if (c.secret) protectedText else shown(c.before)
                                    Text("${c.field}: $before", Modifier.weight(1f))
                                    val label = stringResource(R.string.history_restore_field) + ": " + c.field
                                    TextButton(
                                        {
                                            scope.launch {
                                                when (restore(row, c.field)) {
                                                    SaveResult.SAVED -> onDone(true)
                                                    SaveResult.INVALID -> error = invalidHere
                                                    else -> error = notRestorable
                                                }
                                            }
                                        },
                                        Modifier.semantics { contentDescription = label },
                                    ) { Text(stringResource(R.string.history_restore_field)) }
                                }
                            }
                            HorizontalDivider(Modifier.padding(top = 8.dp))
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton({ onDone(false) }) { Text(stringResource(R.string.common_done)) } },
    )
}

/**
 * The travel-mode dialog's choices (scan A-L4): saved collections and tags that are not in the vault right now (a
 * collection not synced yet, a tag no item carries today) are kept, never dropped by saving the dialog.
 */
internal object TravelChoice {
    /** The tags to offer: the vault's, then the saved ones no item carries right now (so they can still be unticked). */
    fun tags(present: List<String>, old: TravelMode.Setting): List<String> {
        val folds = present.mapTo(HashSet()) { TravelMode.fold(it) }
        return present + old.tags.filter { TravelMode.fold(it) !in folds }
    }

    /**
     * The setting to save: the chosen collections among [present] plus the saved ones not present now (they have no
     * name to list), and the chosen tags among [shownTags] (folded in [chosenTags]).
     */
    fun setting(
        on: Boolean, old: TravelMode.Setting, present: List<String>, chosenCollections: Set<String>,
        shownTags: List<String>, chosenTags: Set<String>, now: Long,
    ): TravelMode.Setting {
        val presentIds = present.mapTo(HashSet()) { it.lowercase() }
        val kept = old.collections.filter { it.lowercase() !in presentIds }
        return TravelMode.Setting(
            on, TravelMode.cleanCollections(present.filter { it in chosenCollections } + kept),
            TravelMode.cleanTags(shownTags.filter { TravelMode.fold(it) in chosenTags }),
            if (on) (if (old.on) old.since else now) else 0,
        )
    }
}

/**
 * Settings > Travel mode (contract section 2.4): this phone only; hide by collection and by tag. Turning it off asks
 * for the owner; turning it on or changing the set needs Pro ([onNeedsPro]). Never removes anything or stops sync.
 */
@Composable
fun TravelModeDialog(
    seams: FeatureSeams,
    collections: List<CollectionCatalog.Collection>,
    tags: List<String>,
    now: () -> Long,
    onNeedsPro: () -> Unit,
    onDone: () -> Unit,
) {
    val old = remember { seams.travel }
    // Saved tags no item carries right now are still listed, so they stay hidden unless unticked (scan A-L4).
    val shownTags = remember(tags, old) { TravelChoice.tags(tags, old) }
    var on by remember { mutableStateOf(old.on) }
    var chosenCollections by remember { mutableStateOf(old.collections.toSet()) }
    var chosenTags by remember { mutableStateOf(old.tags.map { TravelMode.fold(it) }.toSet()) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val needsPro = stringResource(R.string.travel_needs_pro)
    val failed = stringResource(R.string.travel_failed)
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(stringResource(R.string.travel_title)) },
        text = {
            LazyColumn(Modifier.heightIn(max = 460.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                item {
                    Text(stringResource(R.string.travel_summary))
                    Text(stringResource(R.string.travel_device_only), Modifier.padding(top = 6.dp))
                    Text(stringResource(R.string.travel_not_removed), Modifier.padding(vertical = 6.dp))
                    val label = stringResource(R.string.travel_title)
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text(label, Modifier.weight(1f))
                        Switch(on, { on = it }, Modifier.testTag("travel-on").semantics { contentDescription = label })
                    }
                }
                if (collections.isNotEmpty()) item { Text(stringResource(R.string.travel_choose_collections), fontWeight = FontWeight.SemiBold) }
                items(collections, key = { "c" + it.id }) { c ->
                    Choice(c.name, c.id in chosenCollections) { chosenCollections = if (it) chosenCollections + c.id else chosenCollections - c.id }
                }
                if (shownTags.isNotEmpty()) item { Text(stringResource(R.string.travel_choose_tags), fontWeight = FontWeight.SemiBold) }
                items(shownTags, key = { "t$it" }) { t ->
                    val f = TravelMode.fold(t)
                    Choice(t, f in chosenTags) { chosenTags = if (it) chosenTags + f else chosenTags - f }
                }
                error?.let { e -> item { Text(e) } }
            }
        },
        confirmButton = {
            TextButton(
                {
                    val wanted = TravelChoice.setting(on, old, collections.map { it.id }, chosenCollections, shownTags, chosenTags, now())
                    scope.launch {
                        when (FeatureSeams.travelCheck(old, wanted, seams.isPro())) {
                            FeatureSeams.TravelCheck.UNCHANGED -> { onDone(); return@launch }
                            FeatureSeams.TravelCheck.NEEDS_PRO -> { error = needsPro; onNeedsPro(); return@launch }
                            FeatureSeams.TravelCheck.OWNER -> if (!seams.confirmOwner()) return@launch
                            FeatureSeams.TravelCheck.OK -> Unit
                        }
                        try {
                            withContext(Dispatchers.IO) {
                                // The local data's one lock (as Recently deleted and History hold it).
                                synchronized(seams.local) {
                                    val data = seams.local.localData ?: throw IllegalStateException("closed")
                                    seams.local.commitLocalData(data.withTravelMode(wanted))
                                }
                            }
                            seams.onTravelChanged(wanted)
                            onDone()
                        } catch (e: Exception) {
                            error = failed
                        }
                    }
                },
                Modifier.testTag("travel-save"),
            ) { Text(stringResource(R.string.common_save)) }
        },
        dismissButton = { TextButton(onDone) { Text(stringResource(R.string.common_cancel)) } },
    )
}

@Composable
private fun Choice(label: String, on: Boolean, set: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Checkbox(on, set, Modifier.semantics { contentDescription = label })
        Text(label)
    }
}
