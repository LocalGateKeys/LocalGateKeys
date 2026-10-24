package app.localgatekeys.android.ui.vault

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.clickable
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.FilterList
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.unlock.LocalActivityMonitor
import app.localgatekeys.android.vault.VaultListModel
import app.localgatekeys.android.vault.VaultSearch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

const val NO_ITEMS = "No items."
const val NO_MATCHES = "No matches."

/** The Search tab: a search field, a type filter menu and the matches as one solid group, over the same list model. */
@Composable
fun SearchScreen(model: VaultListModel, seams: VaultSeams) {
    val c = LgkTheme.colors
    val items by model.items.collectAsStateWithLifecycle()
    val query by model.query.collectAsStateWithLifecycle()
    val filter by model.filter.collectAsStateWithLifecycle()
    val monitor = LocalActivityMonitor.current
    LaunchedEffect(model) { withContext(Dispatchers.IO) { model.reload() } }
    val visible = remember(items, query, filter) { VaultSearch.apply(items, query, filter) }
    val options = remember(items) { VaultSearch.filterOptions(items) }
    val tickClock = seams.clock

    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(
                Modifier.weight(1f).height(48.dp).lgkGroupSurface(16.dp).padding(horizontal = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Filled.Search, null, Modifier.size(20.dp), tint = c.secondaryText)
                Spacer(Modifier.width(8.dp))
                Box(Modifier.weight(1f), contentAlignment = Alignment.CenterStart) {
                    if (query.isEmpty()) Text("Search", color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
                    BasicTextField(
                        value = query,
                        onValueChange = {
                            monitor?.textChanged()
                            model.query.value = it
                        },
                        singleLine = true,
                        textStyle = MaterialTheme.typography.bodyLarge.copy(color = c.text),
                        cursorBrush = SolidColor(c.accent),
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                        modifier = Modifier.fillMaxWidth().testTag("search-field").semantics { contentDescription = "Search" },
                    )
                }
            }
            TypeFilterMenu(filter.label, options.map { it to (it == filter) }) { model.filter.value = it }
        }
        Spacer(Modifier.height(8.dp))
        LazyColumn(Modifier.fillMaxSize().testTag("search-results"), contentPadding = PaddingValues(bottom = tabBarClearance())) {
            if (visible.isEmpty()) {
                item {
                    Text(
                        if (query.isEmpty()) NO_ITEMS else NO_MATCHES,
                        color = c.secondaryText, style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth().padding(top = 24.dp).testTag("search-empty"),
                    )
                }
            }
            itemsIndexed(visible, key = { _, it -> it.id }) { index, it ->
                VaultRow(it, index == 0, index == visible.lastIndex, seams.onOpenItem, seams.clipboard, tickClock)
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
    val c = LgkTheme.colors
    var open by remember { mutableStateOf(false) }
    Box {
        Row(
            Modifier
                .height(48.dp)
                .clip(RoundedCornerShape(16.dp))
                .clickable(role = Role.Button) { open = true }
                .semantics { contentDescription = "Type: $label" }
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
                    text = { Text(option.label) },
                    trailingIcon = { if (selected) Icon(Icons.Filled.Check, "Selected") },
                    onClick = { open = false; onPick(option) },
                )
            }
        }
    }
}
