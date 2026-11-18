package app.localgatekeys.android.ui.vault
import app.localgatekeys.android.ui.theme.lgkSwitchColors
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource

import app.localgatekeys.android.i18n.rememberTxt
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Sort
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.vault.VaultSort
import app.localgatekeys.android.vault.VaultSortOption
import app.localgatekeys.core.sync.CollectionCatalog

/** The list's sort button: the four orders and the "Favorites first" switch (this phone only). */
@Composable
fun SortMenu(sort: VaultSort, onPick: (VaultSort) -> Unit, showLabel: Boolean = true) {
    val txt = rememberTxt()
    val sortDescription = txt.s(R.string.sort_description, txt.s(sort.option.label))
    val c = LgkTheme.colors
    var open by remember { mutableStateOf(false) }
    Box {
        Row(
            Modifier
                .height(48.dp)
                .clip(RoundedCornerShape(16.dp))
                .clickable(role = Role.Button) { open = true }
                .semantics { contentDescription = sortDescription }
                .testTag("sort-menu")
                .padding(horizontal = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.AutoMirrored.Filled.Sort, null, Modifier.size(20.dp), tint = c.accentText)
            if (showLabel) {
                Spacer(Modifier.width(4.dp))
                Text(txt.s(sort.option.label), color = c.accentText, style = MaterialTheme.typography.labelLarge, maxLines = 1)
            }
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            for (option in VaultSortOption.entries) {
                DropdownMenuItem(
                    text = { Text(txt.s(option.label)) },
                    trailingIcon = { if (option == sort.option) Icon(Icons.Filled.Check, stringResource(R.string.common_selected)) },
                    onClick = { open = false; onPick(sort.copy(option = option)) },
                )
            }
            HorizontalDivider()
            DropdownMenuItem(
                text = { Text(stringResource(R.string.sort_favorites_first)) },
                trailingIcon = { Switch(sort.favoritesFirst, null, colors = lgkSwitchColors()) },
                onClick = { onPick(sort.copy(favoritesFirst = !sort.favoritesFirst)) },
                modifier = Modifier.testTag("sort-favorites-first"),
            )
        }
    }
}

/**
 * The Vault list's Collections filter (sub-plan 07, next to Sort): All items (the default) or one collection, remembered
 * on this phone; Manage collections opens Vault › Collections ([onManage]; null: not offered).
 */
@Composable
fun CollectionsMenu(
    collections: List<CollectionCatalog.Collection>,
    chosen: String?,
    onPick: (String?) -> Unit,
    onManage: (() -> Unit)?,
) {
    val c = LgkTheme.colors
    val label = stringResource(R.string.collections_title)
    var open by remember { mutableStateOf(false) }
    Box {
        Box(
            Modifier
                .size(48.dp)
                .clip(RoundedCornerShape(16.dp))
                .clickable(role = Role.Button) { open = true }
                .semantics { contentDescription = label }
                .testTag("collections-menu"),
            contentAlignment = Alignment.Center,
        ) {
            Icon(if (chosen == null) Icons.Outlined.Folder else Icons.Filled.Folder, null, Modifier.size(20.dp), tint = c.accentText)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            DropdownMenuItem(
                text = { Text(stringResource(R.string.collections_all_items)) },
                trailingIcon = { if (chosen == null) Icon(Icons.Filled.Check, stringResource(R.string.common_selected)) },
                onClick = { open = false; onPick(null) },
                modifier = Modifier.testTag("collections-menu-all"),
            )
            for (collection in collections) {
                DropdownMenuItem(
                    text = { Text(app.localgatekeys.android.collections.collectionDisplayName(collection.name)) },
                    trailingIcon = { if (chosen == collection.id) Icon(Icons.Filled.Check, stringResource(R.string.common_selected)) },
                    onClick = { open = false; onPick(collection.id) },
                    modifier = Modifier.testTag("collections-menu-item"),
                )
            }
            if (onManage != null) {
                HorizontalDivider()
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.collections_manage)) },
                    onClick = { open = false; onManage() },
                    modifier = Modifier.testTag("collections-menu-manage"),
                )
            }
        }
    }
}

/**
 * The Vault header's one "more" menu (UX refresh §4, as on the iPhone): the four orders and "Favorites first"
 * (this phone only), then the Collections filter (All items or one collection) and Manage collections ([onManage];
 * null: not offered). [open] and [onDismiss] belong to the header's ⋯ button.
 */
@Composable
fun VaultMoreMenu(
    open: Boolean,
    onDismiss: () -> Unit,
    sort: VaultSort,
    onPickSort: (VaultSort) -> Unit,
    collections: List<CollectionCatalog.Collection>,
    chosen: String?,
    onPickCollection: (String?) -> Unit,
    onManage: (() -> Unit)?,
) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    DropdownMenu(expanded = open, onDismissRequest = onDismiss) {
        Text(
            stringResource(R.string.sort_title), color = c.secondaryText, style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
        )
        for (option in VaultSortOption.entries) {
            DropdownMenuItem(
                text = { Text(txt.s(option.label)) },
                leadingIcon = { Icon(Icons.AutoMirrored.Filled.Sort, null, Modifier.size(20.dp)) },
                trailingIcon = { if (option == sort.option) Icon(Icons.Filled.Check, stringResource(R.string.common_selected)) },
                onClick = { onDismiss(); onPickSort(sort.copy(option = option)) },
            )
        }
        DropdownMenuItem(
            text = { Text(stringResource(R.string.sort_favorites_first)) },
            trailingIcon = { Switch(sort.favoritesFirst, null, colors = lgkSwitchColors()) },
            onClick = { onPickSort(sort.copy(favoritesFirst = !sort.favoritesFirst)) },
            modifier = Modifier.testTag("sort-favorites-first"),
        )
        HorizontalDivider()
        Text(
            stringResource(R.string.collections_title), color = c.secondaryText, style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
        )
        DropdownMenuItem(
            text = { Text(stringResource(R.string.collections_all_items)) },
            leadingIcon = { Icon(Icons.Outlined.Folder, null, Modifier.size(20.dp)) },
            trailingIcon = { if (chosen == null) Icon(Icons.Filled.Check, stringResource(R.string.common_selected)) },
            onClick = { onDismiss(); onPickCollection(null) },
            modifier = Modifier.testTag("collections-menu-all"),
        )
        for (collection in collections) {
            DropdownMenuItem(
                text = { Text(app.localgatekeys.android.collections.collectionDisplayName(collection.name)) },
                leadingIcon = { Icon(Icons.Filled.Folder, null, Modifier.size(20.dp)) },
                trailingIcon = { if (chosen == collection.id) Icon(Icons.Filled.Check, stringResource(R.string.common_selected)) },
                onClick = { onDismiss(); onPickCollection(collection.id) },
                modifier = Modifier.testTag("collections-menu-item"),
            )
        }
        if (onManage != null) {
            DropdownMenuItem(
                text = { Text(stringResource(R.string.collections_manage)) },
                onClick = { onDismiss(); onManage() },
                modifier = Modifier.testTag("collections-menu-manage"),
            )
        }
    }
}
