package app.localgatekeys.android.ui.vault
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
                trailingIcon = { Switch(sort.favoritesFirst, null) },
                onClick = { onPick(sort.copy(favoritesFirst = !sort.favoritesFirst)) },
                modifier = Modifier.testTag("sort-favorites-first"),
            )
        }
    }
}
