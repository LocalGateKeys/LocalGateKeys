package app.localgatekeys.android.ui.vault
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource
import androidx.annotation.StringRes

import app.localgatekeys.android.i18n.rememberTxt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.clickable
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.unlock.LocalActivityMonitor
import app.localgatekeys.android.vault.VaultListModel
import app.localgatekeys.android.vault.VaultSearch
import app.localgatekeys.android.vault.SearchCommand
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@StringRes val NO_ITEMS = R.string.vault_no_items
@StringRes val NO_MATCHES = R.string.vault_no_matches
@StringRes val NO_ACTIONS = R.string.vault_no_actions

/**
 * The vault search (pushed from the Vault tab's search button, as on the iPhone's `VaultSearchView`): a search field, a
 * type filter menu and the matches as one solid group, over the same list model. While the field is empty it shows the
 * recent searches of this unlock (tap searches again) and the recently changed items. A query starting with `>` lists
 * actions instead (workstream 5, [SearchCommand]); Return runs the first action, or keeps an item search as a recent
 * search. [focusKey] above 0 focuses the field (on arrival and Ctrl+K), again each time it changes.
 */
@Composable
fun SearchScreen(model: VaultListModel, seams: VaultSeams, focusKey: Int = 0) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val items by model.items.collectAsStateWithLifecycle()
    val query by model.query.collectAsStateWithLifecycle()
    val filter by model.filter.collectAsStateWithLifecycle()
    val monitor = LocalActivityMonitor.current
    LaunchedEffect(model) { withContext(Dispatchers.IO) { model.reload() } }
    val sort by model.sort.collectAsStateWithLifecycle()
    val visible = remember(items, query, filter, sort) { VaultListModel.visible(items, query, filter, sort, txt) }
    val scope = rememberCoroutineScope()
    val toggleFavorite = seams.favoriteToggle(scope)
    val options = remember(items) { VaultSearch.filterOptions(items, txt) }
    val tickClock = seams.clock
    val commands = remember(query, seams.commands) { SearchCommand.parse(query, txt, seams.commands) }
    val recentSearches by model.recentSearches.collectAsStateWithLifecycle()
    val recentItems = remember(items) { VaultListModel.recentItems(items) }
    val submit: () -> Unit = {
        val found = commands
        if (found != null) {
            found.firstOrNull()?.let { cmd -> model.query.value = ""; seams.onCommand(cmd) }
        } else {
            model.noteSearch()
        }
    }
    val focus = remember { FocusRequester() }
    // The field's own value (text and cursor); a query set from outside (Ctrl+K's "> ", a recent search) puts the cursor
    // at its end.
    var field by remember { mutableStateOf(TextFieldValue(query, TextRange(query.length))) }
    val searchLabel = txt.s(R.string.search_hint)
    LaunchedEffect(focusKey) { if (focusKey > 0) runCatching { focus.requestFocus() } }

    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(
                Modifier.weight(1f).height(48.dp).lgkGroupSurface(16.dp).padding(horizontal = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Filled.Search, null, Modifier.size(20.dp), tint = c.secondaryText)
                Spacer(Modifier.width(8.dp))
                Box(Modifier.weight(1f), contentAlignment = Alignment.CenterStart) {
                    if (query.isEmpty()) Text(stringResource(if (seams.commands.isEmpty()) R.string.search_hint else R.string.search_hint_actions), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
                    BasicTextField(
                        value = syncedSearchField(field, query),
                        onValueChange = {
                            monitor?.textChanged()
                            field = it
                            model.query.value = it.text
                        },
                        singleLine = true,
                        textStyle = MaterialTheme.typography.bodyLarge.copy(color = c.text),
                        cursorBrush = SolidColor(c.accent),
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                        keyboardActions = KeyboardActions(onSearch = { submit() }),
                        modifier = Modifier.fillMaxWidth().focusRequester(focus).testTag("search-field").semantics { contentDescription = searchLabel },
                    )
                }
            }
            // Sorting orders the plain list; a typed search stays in relevance order.
            SortMenu(sort, model::setSort, showLabel = false)
            TypeFilterMenu(filter.label(txt), options.map { it to (it == filter) }) { model.filter.value = it }
        }
        Spacer(Modifier.height(8.dp))
        LazyColumn(Modifier.fillMaxSize().testTag("search-results"), contentPadding = PaddingValues(bottom = tabBarClearance())) {
            if (commands != null) {
                if (commands.isEmpty()) {
                    item {
                        Text(
                            stringResource(NO_ACTIONS), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth().padding(top = 24.dp).testTag("search-empty"),
                        )
                    }
                } else {
                    item(key = "commands") {
                        Column(Modifier.fillMaxWidth().lgkGroupSurface().testTag("command-list")) {
                            for (cmd in commands) {
                                CommandRow(cmd) {
                                    model.query.value = ""
                                    seams.onCommand(cmd)
                                }
                            }
                        }
                    }
                }
            } else if (query.isEmpty()) {
                if (recentSearches.isNotEmpty()) {
                    item(key = "recent-searches") {
                        Column(Modifier.fillMaxWidth()) {
                            SectionHeader(stringResource(R.string.search_recent_searches))
                            Column(Modifier.fillMaxWidth().lgkGroupSurface().testTag("recent-searches")) {
                                for (q in recentSearches) RecentSearchRow(q) { model.query.value = q }
                            }
                        }
                    }
                }
                if (recentItems.isNotEmpty()) {
                    item(key = "recent-items-header") { SectionHeader(stringResource(R.string.search_recent_items)) }
                    itemsIndexed(recentItems, key = { _, it -> "recent:" + it.id }) { index, it ->
                        VaultRow(it, index == 0, index == recentItems.lastIndex, seams.onOpenItem, seams.clipboard, tickClock, toggleFavorite)
                    }
                } else if (recentSearches.isEmpty()) {
                    item {
                        Text(
                            stringResource(NO_ITEMS), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth().padding(top = 24.dp).testTag("search-empty"),
                        )
                    }
                }
            } else if (visible.isEmpty()) {
                item {
                    Text(
                        stringResource(NO_MATCHES),
                        color = c.secondaryText, style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth().padding(top = 24.dp).testTag("search-empty"),
                    )
                }
            }
            if (commands == null && query.isNotEmpty()) {
                itemsIndexed(visible, key = { _, it -> it.id }) { index, it ->
                    VaultRow(it, index == 0, index == visible.lastIndex, seams.onOpenItem, seams.clipboard, tickClock, toggleFavorite)
                }
            }
        }
    }
}

@Composable
private fun TypeFilterMenu(
    label: String,
    options: List<Pair<app.localgatekeys.android.vault.VaultFilter, Boolean>>,
    onPick: (app.localgatekeys.android.vault.VaultFilter) -> Unit,
) {
    val txt = rememberTxt()
    val typeDescription = txt.s(R.string.search_type_description, label)
    val c = LgkTheme.colors
    var open by remember { mutableStateOf(false) }
    Box {
        Row(
            Modifier
                .height(48.dp)
                .clip(RoundedCornerShape(16.dp))
                .clickable(role = Role.Button) { open = true }
                .semantics { contentDescription = typeDescription }
                .testTag("type-filter")
                .padding(horizontal = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Filled.FilterList, null, Modifier.size(20.dp), tint = c.accentText)
            Spacer(Modifier.width(4.dp))
            Text(label, color = c.accentText, style = MaterialTheme.typography.labelLarge, maxLines = 1)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            for ((option, selected) in options) {
                DropdownMenuItem(
                    text = { Text(option.label(txt)) },
                    trailingIcon = { if (selected) Icon(Icons.Filled.Check, stringResource(R.string.common_selected)) },
                    onClick = { open = false; onPick(option) },
                )
            }
        }
    }
}

/** One recent search: tapping it searches again. */
@Composable
private fun RecentSearchRow(query: String, onClick: () -> Unit) {
    val c = LgkTheme.colors
    val hint = stringResource(R.string.search_again_hint)
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClickLabel = hint, onClick = onClick)
            .heightIn(min = 48.dp)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag("recent-search"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Filled.History, null, Modifier.size(20.dp), tint = c.secondaryText)
        Spacer(Modifier.width(12.dp))
        Text(query, color = c.text, style = MaterialTheme.typography.bodyLarge, maxLines = 1)
    }
}

/** One action row of a `>` search. */
@Composable
private fun CommandRow(cmd: SearchCommand, onClick: () -> Unit) {
    val txt = rememberTxt()
    Text(
        cmd.title(txt),
        color = LgkTheme.colors.text,
        style = MaterialTheme.typography.bodyLarge,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClick = onClick)
            .heightIn(min = 48.dp)
            .padding(horizontal = 16.dp, vertical = 14.dp)
            .testTag("command-row"),
    )
}

/**
 * What the search field shows: [field] while it holds [query] (typing, with its cursor and selection), otherwise [query]
 * with the cursor at the end. A query set from outside (Ctrl+K's "> ", a recent search, a cleared field) would
 * otherwise keep the old cursor, and Ctrl+K then typing gave "sec> " instead of "> sec" (release check 2026-11-01).
 */
internal fun syncedSearchField(field: TextFieldValue, query: String): TextFieldValue =
    if (field.text == query) field else TextFieldValue(query, TextRange(query.length))
