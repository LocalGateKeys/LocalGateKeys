package app.localgatekeys.android.ui.vault
import androidx.annotation.StringRes
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource

import app.localgatekeys.android.i18n.rememberTxt
import androidx.compose.foundation.layout.Arrangement
import app.localgatekeys.android.ui.theme.lgkGlass
import androidx.compose.material.icons.filled.Search
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.Role
import androidx.compose.foundation.clickable
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material3.Icon
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.ui.unit.Dp
import app.localgatekeys.android.sync.SyncStatusSummary
import app.localgatekeys.android.ui.onboarding.SetupChip
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import app.localgatekeys.android.ui.sync.SyncStatusPill
import app.localgatekeys.android.ui.shell.FloatingTabBarBottomGap
import app.localgatekeys.android.ui.shell.FloatingTabBarHeight
import kotlinx.coroutines.CancellationException
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.vault.Copier
import app.localgatekeys.android.vault.CodesRow
import app.localgatekeys.android.vault.VaultGroup
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.VaultListModel
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.UnixClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * What the vault and search screens need from the rest of the app. Each later task provides its part (editor Task 8,
 * sync Task 10, Pro and the upgrade sheet Task 13); until then MainActivity passes the defaults. RootScaffold replaces
 * [onOpenItem] with the item detail screen.
 */
data class VaultSeams(
    /** Copies through the shared secret clipboard and confirms the copy. */
    val clipboard: Copier,
    /** Pro state (ProModel.isPro: safe on any thread). */
    val isPro: () -> Boolean = { false },
    /** The editor for a new item of this kind (RootScaffold opens the editor). */
    val onNewItem: (kind: EditorKind) -> Unit = {},
    /** Opens the item's detail (RootScaffold shows ItemDetailScreen). */
    val onOpenItem: (id: String) -> Unit = {},
    /** Pull to refresh: sync with the PC (Task 10). */
    val onRefresh: suspend () -> Unit = {},
    /**
     * Marks or unmarks a favorite through the store, off the main thread, then reloads the list and tells sync
     * (RootScaffold). Null: the rows offer no favorite action.
     */
    val onSetFavorite: (suspend (item: VaultItem, favorite: Boolean) -> Unit)? = null,
    /** The settings screen (Task 14). */
    val onOpenSettings: () -> Unit = {},
    /** The empty vault's "Restore from a backup" (first launch); null: not offered. */
    val onRestoreBackup: (() -> Unit)? = null,
    /** The empty vault shows the "Import your passwords" card (AppSettings.importCardDismissed is off). */
    val showImportCard: () -> Boolean = { false },
    /** The card's "Not now": hides it on this phone. */
    val onDismissImportCard: () -> Unit = {},
    /** The card's "Import": opens the import page (Settings when it isn't available). */
    val onImport: () -> Unit = {},
    val clock: UnixClock = SystemClock(),
    /** "Finish setting up · n of 5" (workstream 4); null: no card. */
    val setupCardText: String? = null,
    /** The card's tap: the setup pages open again. */
    val onOpenSetup: () -> Unit = {},
    /** The card's Hide. */
    val onHideSetup: () -> Unit = {},
    /** The sync pill at the top of the vault (workstream 6); null: this phone does not sync. */
    val syncStatus: SyncStatusSummary? = null,
    /** The pill's tap: the Sync status sheet. */
    val onOpenSyncStatus: () -> Unit = {},
    /** Workstream 5: the actions a `>` search lists (only the ones this screen can run). */
    val commands: List<app.localgatekeys.android.vault.SearchCommand> = emptyList(),
    /** Runs a listed action (RootScaffold). */
    val onCommand: (app.localgatekeys.android.vault.SearchCommand) -> Unit = {},
    /** Sub-plan 07: the Collections filter's "Manage collections" (Vault › Collections). Null: not offered. */
    val onOpenCollections: (() -> Unit)? = null,
    /** The "Search your vault" field under the title: opens the search page (RootScaffold). */
    val onSearch: () -> Unit = {},
    /** Review 2026-11-15 UX 3: the "Autofill is off" banner shows ([settings.AutofillBanner]). */
    val autofillBanner: Boolean = false,
    /** The banner's Turn on: the system's autofill service picker. */
    val onTurnOnAutofill: () -> Unit = {},
    /** The banner's Not now: hides it on this phone. */
    val onDismissAutofillBanner: () -> Unit = {},
)

/** The rows' favorite action over [VaultSeams.onSetFavorite] (null when there is none). */
internal fun VaultSeams.favoriteToggle(scope: kotlinx.coroutines.CoroutineScope): ((VaultItem) -> Unit)? =
    onSetFavorite?.let { set -> { item: VaultItem -> scope.launch { set(item, !item.favorite) }; Unit } }

/** Room under the last row for the floating tab bar: its height, its gaps and the navigation bar inset. */
@Composable
internal fun tabBarClearance(): Dp =
    FloatingTabBarHeight + FloatingTabBarBottomGap + 16.dp + WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()

/** The Vault tab: a pinned Codes row, then grouped solid sections. The title and the plus and avatar buttons are in the scaffold header. */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun VaultScreen(model: VaultListModel, showCodesRow: Boolean, seams: VaultSeams) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val items by model.items.collectAsStateWithLifecycle()
    val loadError by model.loadError.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var refreshing by remember { mutableStateOf(false) }
    LaunchedEffect(model) { withContext(Dispatchers.IO) { model.reload() } }
    val codeItems = remember(items, showCodesRow) { CodesRow.items(items, showCodesRow, txt) }
    val sort by model.sort.collectAsStateWithLifecycle()
    // Sub-plan 07: the Collections filter (the Codes row above stays every code).
    val collections by model.collections.collectAsStateWithLifecycle()
    val collectionFilter by model.collectionFilter.collectAsStateWithLifecycle()
    val collectionIds by model.collectionItemIds.collectAsStateWithLifecycle()
    val listed = remember(items, collectionIds) { VaultListModel.inCollection(items, collectionIds) }
    val groups = remember(listed, sort) { VaultGroup.groups(listed, sort) }
    val toggleFavorite = seams.favoriteToggle(scope)
    val tick = rememberSecondTick(seams.clock)
    var importCard by remember(seams) { mutableStateOf(seams.showImportCard()) }

    PullToRefreshBox(
        isRefreshing = refreshing,
        onRefresh = {
            refreshing = true
            scope.launch {
                try {
                    seams.onRefresh()
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    // A failed sync reports itself (Task 10); the list just stops spinning and reloads.
                } finally {
                    withContext(Dispatchers.IO) { model.reload() }
                    refreshing = false
                }
            }
        },
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(
            Modifier.fillMaxSize().testTag("vault-list"),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = tabBarClearance()),
        ) {
            loadError?.let { item { Text(it, color = c.danger, modifier = Modifier.padding(horizontal = 4.dp, vertical = 8.dp)) } }
            // UX refresh §4, as on the iPhone: the search field under the title, then the sync status and the setup
            // progress on one line. Sort and Collections are in the header's "more" menu.
            item(key = "search-field") { SearchField(seams.onSearch) }
            if (seams.syncStatus != null || seams.setupCardText != null) {
                item(key = "status-line") {
                    FlowRow(
                        Modifier.fillMaxWidth().padding(top = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        seams.syncStatus?.let { SyncStatusPill(it, seams.onOpenSyncStatus) }
                        seams.setupCardText?.let { SetupChip(it, seams.onOpenSetup, seams.onHideSetup) }
                    }
                }
            }
            if (seams.autofillBanner) {
                item(key = "autofill-banner") { AutofillBannerCard(seams.onTurnOnAutofill, seams.onDismissAutofillBanner) }
            }
            val filterName = collectionFilter?.let { id -> collections.firstOrNull { it.id == id }?.name }
            if (filterName != null) {
                item(key = "collection-filter") {
                    // The Collections filter in use: a tap shows All items again.
                    TextButton({ model.setCollectionFilter(null) }, modifier = Modifier.testTag("collection-filter-chip")) {
                        Icon(Icons.Filled.Cancel, stringResource(R.string.collections_filter_clear), Modifier.size(18.dp), tint = c.accentText)
                        Spacer(Modifier.width(6.dp))
                        Text(stringResource(R.string.collections_filter, app.localgatekeys.android.collections.collectionDisplayName(filterName)), color = c.accentText, style = MaterialTheme.typography.bodyMedium)
                    }
                }
                if (listed.isEmpty() && items.isNotEmpty()) {
                    item(key = "collection-empty") {
                        Text(
                            stringResource(R.string.collections_filter_empty), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge,
                            textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth().padding(top = 24.dp).testTag("collection-empty"),
                        )
                    }
                }
            }
            if (codeItems.isNotEmpty()) {
                item(key = "codes") {
                    Column(Modifier.testTag("codes-row")) {
                        SectionHeader(stringResource(R.string.vault_codes))
                        Box(Modifier.fillMaxWidth().lgkGroupSurface()) {
                            LazyRow(
                                contentPadding = PaddingValues(14.dp),
                                horizontalArrangement = Arrangement.spacedBy(12.dp),
                            ) {
                                items(codeItems, key = { it.id }) { CodeTile(it, seams.clock, tick, seams.clipboard) }
                            }
                        }
                    }
                }
            }
            for ((title, group) in groups) {
                item(key = "header-$title") { SectionHeader(txt.s(title)) }
                itemsIndexed(group, key = { _, it -> it.id }) { index, it ->
                    VaultRow(it, index == 0, index == group.lastIndex, seams.onOpenItem, seams.clipboard, seams.clock, toggleFavorite)
                }
            }
            if (items.isEmpty() && loadError == null && importCard) {
                item(key = "import-card") {
                    ImportCard(onImport = seams.onImport, onNotNow = { seams.onDismissImportCard(); importCard = false })
                }
            }
            if (items.isEmpty() && loadError == null) {
                item {
                    Text(
                        stringResource(EMPTY_VAULT), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth().padding(top = 24.dp).testTag("empty-vault"),
                    )
                }
                // Spec section 6: on first launch the vault can come from a backup file.
                seams.onRestoreBackup?.let { restore ->
                    item {
                        Box(Modifier.fillMaxWidth().padding(top = 8.dp), contentAlignment = Alignment.Center) {
                            TextButton(restore, modifier = Modifier.testTag("empty-vault-restore")) {
                                Text(stringResource(RESTORE_FROM_BACKUP), color = c.accentText, style = MaterialTheme.typography.bodyLarge)
                            }
                        }
                    }
                }
            }
        }
    }
}

/** The empty vault's "Import your passwords" card; it goes away once the vault has an item. */
@Composable
private fun ImportCard(onImport: () -> Unit, onNotNow: () -> Unit) {
    val c = LgkTheme.colors
    Column(Modifier.fillMaxWidth().padding(top = 16.dp).lgkGroupSurface().padding(16.dp).testTag("import-card")) {
        Text(stringResource(IMPORT_CARD_TITLE), color = c.text, style = MaterialTheme.typography.titleMedium)
        Text(stringResource(IMPORT_CARD_TEXT), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(top = 4.dp))
        Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onImport, modifier = Modifier.testTag("import-card-import")) { Text(stringResource(R.string.home_import), color = c.accentText) }
            TextButton(onNotNow, modifier = Modifier.testTag("import-card-not-now")) { Text(stringResource(R.string.common_not_now), color = c.secondaryText) }
        }
    }
}

/** "Autofill is off" with Turn on (the system picker) and Not now (review 2026-11-15 UX 3). */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AutofillBannerCard(onTurnOn: () -> Unit, onNotNow: () -> Unit) {
    val c = LgkTheme.colors
    Column(Modifier.fillMaxWidth().padding(top = 8.dp).lgkGroupSurface().padding(16.dp).testTag("autofill-banner")) {
        Text(stringResource(R.string.vault_autofill_banner_title), color = c.text, style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.vault_autofill_banner_text), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(top = 4.dp))
        FlowRow(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onTurnOn, modifier = Modifier.testTag("autofill-banner-turn-on")) {
                Text(stringResource(R.string.vault_autofill_banner_action), color = c.accentText)
            }
            TextButton(onNotNow, modifier = Modifier.testTag("autofill-banner-not-now")) {
                Text(stringResource(R.string.common_not_now), color = c.secondaryText)
            }
        }
    }
}

@StringRes val IMPORT_CARD_TITLE = R.string.vault_import_card_title
@StringRes val IMPORT_CARD_TEXT = R.string.vault_import_card_text
@StringRes val EMPTY_VAULT = R.string.vault_empty
@StringRes val RESTORE_FROM_BACKUP = R.string.vault_restore_from_backup

/** A field-shaped button that opens the search page (its filters and `>` actions are unchanged). */
@Composable
private fun SearchField(onSearch: () -> Unit) {
    val c = LgkTheme.colors
    val label = stringResource(R.string.search_hint)
    Row(
        Modifier.fillMaxWidth().padding(top = 4.dp).heightIn(min = 48.dp).lgkGlass(RoundedCornerShape(24.dp))
            .clip(RoundedCornerShape(24.dp)).clickable(role = Role.Button, onClick = onSearch)
            .semantics(mergeDescendants = true) { contentDescription = label }
            .testTag("vault-search-button").padding(horizontal = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Filled.Search, null, Modifier.size(20.dp), tint = c.secondaryText)
        Spacer(Modifier.width(10.dp))
        Text(stringResource(R.string.vault_search_field), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge, maxLines = 1)
    }
}
