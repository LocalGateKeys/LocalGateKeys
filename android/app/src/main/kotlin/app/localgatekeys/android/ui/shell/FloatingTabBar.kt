package app.localgatekeys.android.ui.shell

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGlass

enum class RootTab { VAULT, SEARCH, SYNC }

/** Height of the bar (50 dp tabs plus 6 dp padding each side) and its gap above the navigation bar. */
val FloatingTabBarHeight = 62.dp
val FloatingTabBarBottomGap = 4.dp

/** A centred capsule of glass with the three tabs. The selected tab gets an accent-tinted pill. */
@Composable
fun FloatingTabBar(selection: RootTab, onSelect: (RootTab) -> Unit, modifier: Modifier = Modifier) {
    val shadow = Color.Black.copy(alpha = 0.12f)
    Row(
        modifier
            .shadow(16.dp, CircleShape, ambientColor = shadow, spotColor = shadow)
            .lgkGlass(CircleShape)
            .padding(6.dp)
            .selectableGroup(),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        TabItem(RootTab.VAULT, "Vault", Icons.Filled.Lock, selection, onSelect)
        TabItem(RootTab.SEARCH, "Search", Icons.Filled.Search, selection, onSelect)
        TabItem(RootTab.SYNC, "Sync", Icons.Filled.Refresh, selection, onSelect)
    }
}

@Composable
private fun TabItem(tab: RootTab, title: String, icon: ImageVector, selection: RootTab, onSelect: (RootTab) -> Unit) {
    val selected = selection == tab
    val colors = LgkTheme.colors
    val tint = if (selected) colors.accentText else colors.text
    Column(
        Modifier
            .width(84.dp)
            .height(50.dp)
            .clip(CircleShape)
            .background(if (selected) colors.accent.copy(alpha = 0.18f) else Color.Transparent)
            .selectable(selected = selected, role = Role.Tab, onClick = { onSelect(tab) })
            .semantics { contentDescription = title },
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(20.dp))
        Text(title, color = tint, style = MaterialTheme.typography.labelSmall)
    }
}
