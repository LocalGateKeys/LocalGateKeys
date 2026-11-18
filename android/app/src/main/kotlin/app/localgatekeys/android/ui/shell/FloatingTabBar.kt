package app.localgatekeys.android.ui.shell
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource

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
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGlass

/** The four tabs, as on the iPhone (`ios/App/RootTabs.swift`). Search is a button on the Vault tab. */
enum class RootTab { VAULT, SYNC, SECURITY, SETTINGS }

/** Height of the bar (50 dp tabs plus 6 dp padding each side) and its gap above the navigation bar. */
val FloatingTabBarHeight = 62.dp
val FloatingTabBarBottomGap = 4.dp

/** From this font scale on the capsule shows icons only (the iPhone does the same at accessibility text sizes). */
internal const val ICONS_ONLY_FONT_SCALE = 1.5f

/**
 * A centred capsule of glass with the four tabs (lock, arrows, checkmark shield, gear: the iPhone's symbols). The
 * selected tab gets an accent-tinted pill. At large font scales the labels go (each tab still reads its name).
 */
@Composable
fun FloatingTabBar(selection: RootTab, onSelect: (RootTab) -> Unit, modifier: Modifier = Modifier) {
    val shadow = Color.Black.copy(alpha = 0.12f)
    val iconsOnly = LocalDensity.current.fontScale >= ICONS_ONLY_FONT_SCALE
    Row(
        modifier
            .shadow(16.dp, CircleShape, ambientColor = shadow, spotColor = shadow)
            .lgkGlass(CircleShape)
            .padding(6.dp)
            .selectableGroup()
            .testTag("tab-bar"),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        TabItem(RootTab.VAULT, stringResource(R.string.tab_vault), Icons.Filled.Lock, selection, onSelect, iconsOnly)
        TabItem(RootTab.SYNC, stringResource(R.string.tab_sync), Icons.Filled.Sync, selection, onSelect, iconsOnly)
        TabItem(RootTab.SECURITY, stringResource(R.string.security_title), Icons.Filled.VerifiedUser, selection, onSelect, iconsOnly)
        TabItem(RootTab.SETTINGS, stringResource(R.string.settings_title), Icons.Filled.Settings, selection, onSelect, iconsOnly)
    }
}

@Composable
private fun TabItem(tab: RootTab, title: String, icon: ImageVector, selection: RootTab, onSelect: (RootTab) -> Unit, iconsOnly: Boolean) {
    val selected = selection == tab
    val colors = LgkTheme.colors
    val tint = if (selected) colors.accentText else colors.text
    Column(
        Modifier
            .width(76.dp)
            .height(50.dp)
            .clip(CircleShape)
            .background(if (selected) colors.accent.copy(alpha = 0.18f) else Color.Transparent)
            .selectable(selected = selected, role = Role.Tab, onClick = { onSelect(tab) })
            .semantics { contentDescription = title }
            .testTag("tab-${tab.name.lowercase()}"),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(if (iconsOnly) 24.dp else 20.dp))
        if (!iconsOnly) {
            // Long labels (Einstellungen, Bezpieczeństwo) shrink to fit, as the iPhone's minimumScaleFactor does.
            val style = MaterialTheme.typography.labelSmall
            BasicText(
                title, style = style.copy(color = tint), maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis,
                autoSize = TextAutoSize.StepBased(minFontSize = style.fontSize * 0.75f, maxFontSize = style.fontSize),
                modifier = Modifier.padding(horizontal = 2.dp),
            )
        }
    }
}
