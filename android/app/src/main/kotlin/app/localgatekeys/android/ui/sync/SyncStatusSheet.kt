package app.localgatekeys.android.ui.sync
import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource

import app.localgatekeys.android.i18n.rememberTxt
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.sync.SyncStatusSummary
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.warningText
import app.localgatekeys.android.ui.theme.lgkGroupSurface

@Composable
private fun dotColor(dot: SyncStatusSummary.Dot): Color = when (dot) {
    SyncStatusSummary.Dot.GREEN -> LgkTheme.colors.success
    SyncStatusSummary.Dot.ORANGE -> LgkTheme.colors.warning
    SyncStatusSummary.Dot.RED -> LgkTheme.colors.danger
}

/** The vault header's sync pill: a coloured dot and "Synced 2 min ago · 3 devices"; tap opens the status sheet. */
@Composable
fun SyncStatusPill(summary: SyncStatusSummary, onOpen: () -> Unit, modifier: Modifier = Modifier) {
    val txt = rememberTxt()
    val pillDescription = txt.s(R.string.sync_pill_description, SyncStatusSummary.dotDescription(summary.dot, txt), summary.pill)
    val c = LgkTheme.colors
    Row(
        modifier.heightIn(min = 48.dp).lgkGroupSurface().clickable(role = Role.Button, onClick = onOpen)
            .semantics { contentDescription = pillDescription }
            .padding(horizontal = 14.dp, vertical = 8.dp).testTag("sync-pill"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(10.dp).background(dotColor(summary.dot), CircleShape))
        Spacer(Modifier.width(8.dp))
        Text(summary.pill, color = c.text, style = MaterialTheme.typography.bodyMedium)
    }
}

/** Sync status: this phone, then each other device (route, last sync, warnings); Sync now and Open sync settings. */
@Composable
fun SyncStatusSheet(
    summary: SyncStatusSummary,
    now: Long,
    busy: Boolean,
    onSyncNow: () -> Unit,
    onOpenSettings: () -> Unit,
    onClose: () -> Unit,
) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    BackHandler(onBack = onClose)
    Box(Modifier.fillMaxSize().pointerInput(Unit) { awaitPointerEventScope { while (true) awaitPointerEvent() } }.testTag("sync-status-sheet")) {
        GlassBackdropHost(Modifier.fillMaxSize()) { AuroraBackground() }
        Column(
            Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    txt.s(SyncStatusSummary.TITLE), color = c.text, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f).semantics { heading() },
                )
                TextButton(onClose, Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.common_done), color = c.accentText, fontWeight = FontWeight.SemiBold) }
            }
            Column(Modifier.fillMaxWidth().lgkGroupSurface().padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(10.dp).background(dotColor(summary.dot), CircleShape))
                    Spacer(Modifier.width(8.dp))
                    Text(txt.s(SyncStatusSummary.THIS_DEVICE), color = c.text, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold)
                }
                Text(summary.pill, color = c.secondaryText, style = MaterialTheme.typography.bodyMedium)
            }
            for (d in summary.devices) {
                Column(
                    Modifier.fillMaxWidth().lgkGroupSurface().padding(16.dp).testTag("sync-device-${d.id}"),
                    verticalArrangement = Arrangement.spacedBy(2.dp),
                ) {
                    Text(d.name, color = c.text, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold)
                    Text(txt.s(d.route.label), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium)
                    Text(SyncStatusSummary.lastSyncedText(d.lastSynced, now, txt), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium)
                    d.warning?.let { Text(it, color = c.warningText, style = MaterialTheme.typography.bodyMedium) }
                }
            }
            Column(Modifier.fillMaxWidth().lgkGroupSurface()) {
                TextButton(onSyncNow, enabled = !busy, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("sync-status-now")) {
                    Text(txt.s(SyncStatusSummary.SYNC_NOW), color = if (busy) c.secondaryText else c.accentText, fontWeight = FontWeight.SemiBold)
                }
                TextButton(onOpenSettings, Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("sync-status-settings")) {
                    Text(txt.s(SyncStatusSummary.OPEN_SETTINGS), color = c.accentText)
                }
            }
        }
    }
}
