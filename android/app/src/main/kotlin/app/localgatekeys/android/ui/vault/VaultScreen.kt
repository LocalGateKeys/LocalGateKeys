package app.localgatekeys.android.ui.vault

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.ui.unit.Dp
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
    /** The settings screen (Task 14). */
    val onOpenSettings: () -> Unit = {},
    /** The empty vault's "Restore from a backup" (first launch); null: not offered. */
    val onRestoreBackup: (() -> Unit)? = null,
    val clock: UnixClock = SystemClock(),
)

/** Room under the last row for the floating tab bar: its height, its gaps and the navigation bar inset. */
@Composable
internal fun tabBarClearance(): Dp =
    FloatingTabBarHeight + FloatingTabBarBottomGap + 16.dp + WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()

/** The Vault tab: a pinned Codes row, then grouped solid sections. The title and the plus and avatar buttons are in the scaffold header. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultScreen(model: VaultListModel, showCodesRow: Boolean, seams: VaultSeams) {
    val c = LgkTheme.colors
    val items by model.items.collectAsStateWithLifecycle()
    val loadError by model.loadError.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var refreshing by remember { mutableStateOf(false) }
    LaunchedEffect(model) { withContext(Dispatchers.IO) { model.reload() } }
    val codeItems = remember(items, showCodesRow) { CodesRow.items(items, showCodesRow) }
    val groups = remember(items) { VaultGroup.groups(items) }
    val tick = rememberSecondTick(seams.clock)

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
            if (codeItems.isNotEmpty()) {
                item(key = "codes") {
                    Column(Modifier.testTag("codes-row")) {
                        SectionHeader("Codes")
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
                item(key = "header-$title") { SectionHeader(title) }
                itemsIndexed(group, key = { _, it -> it.id }) { index, it ->
                    VaultRow(it, index == 0, index == group.lastIndex, seams.onOpenItem, seams.clipboard, seams.clock)
                }
            }
            if (items.isEmpty() && loadError == null) {
                item {
                    Text(
                        EMPTY_VAULT, color = c.secondaryText, style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth().padding(top = 24.dp).testTag("empty-vault"),
                    )
                }
                // Spec section 6: on first launch the vault can come from a backup file.
                seams.onRestoreBackup?.let { restore ->
                    item {
                        Box(Modifier.fillMaxWidth().padding(top = 8.dp), contentAlignment = Alignment.Center) {
                            TextButton(restore, modifier = Modifier.testTag("empty-vault-restore")) {
                                Text(RESTORE_FROM_BACKUP, color = c.accentText, style = MaterialTheme.typography.bodyLarge)
                            }
                        }
                    }
                }
            }
        }
    }
}

const val EMPTY_VAULT = "No items yet. Tap + to add one."
const val RESTORE_FROM_BACKUP = "Restore from a backup"
