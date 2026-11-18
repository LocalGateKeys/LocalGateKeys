package app.localgatekeys.android.ui.security

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Http
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Pin
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.security.BreachStatus
import app.localgatekeys.android.security.SecurityCategory
import app.localgatekeys.android.security.SecurityCheckModel
import app.localgatekeys.android.security.SecurityState
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGlass
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.ui.vault.ItemAvatar
import app.localgatekeys.android.vault.VaultItem

private fun SecurityCategory.icon(): ImageVector = when (this) {
    SecurityCategory.BREACHED -> Icons.Filled.Warning
    SecurityCategory.REUSED -> Icons.Filled.ContentCopy
    SecurityCategory.WEAK -> Icons.Filled.LockOpen
    SecurityCategory.OLD -> Icons.Filled.Schedule
    SecurityCategory.NO_TWO_FACTOR -> Icons.Filled.Pin
    SecurityCategory.HTTP -> Icons.Filled.Http
    SecurityCategory.PASSKEY -> Icons.Filled.Key
}

/**
 * The Security check: a score ring, then Breached, Reused, Weak, Old and 2FA available, each opening its list; the
 * breach-check section below (iPhone `SecurityCheckView`). No knowledge of the shell: every way out is a seam.
 *
 * - [onOpenItem]: a tapped login opens its detail screen.
 * - [onChangePassword]: "Change password" on a row; the shell opens the site (`item.openableUrl`) and the editor so the
 *   new password can be saved, and calls [SecurityCheckModel.refresh] when the editor saved.
 * - [below]: optional extra sections under the breach check (the Upcoming reminders section, Task 4).
 *
 * The model is refreshed whenever the screen is shown; the shell calls [SecurityCheckModel.clear] on lock.
 */
@Composable
fun SecurityCheckScreen(
    model: SecurityCheckModel,
    onOpenItem: (VaultItem) -> Unit,
    onChangePassword: (VaultItem) -> Unit,
    modifier: Modifier = Modifier,
    below: (@Composable () -> Unit)? = null,
) {
    val state by model.state.collectAsStateWithLifecycle()
    var selected by rememberSaveable { mutableStateOf<String?>(null) }
    val category = SecurityCategory.entries.firstOrNull { it.raw == selected }
    // Decrypting the vault and scoring every password is too slow for the main thread on a large vault.
    LaunchedEffect(model) { withContext(Dispatchers.Default) { model.refresh() } }
    BackHandler(enabled = category != null) { selected = null }
    Box(modifier.fillMaxSize().testTag("security-check")) {
        AuroraBackground()
        if (category == null) {
            Overview(model, state, onOpen = { selected = it.raw }, below = below)
        } else {
            IssueList(model, state, category, onBack = { selected = null }, onOpenItem, onChangePassword)
        }
    }
}

@Composable
private fun Overview(model: SecurityCheckModel, state: SecurityState, onOpen: (SecurityCategory) -> Unit, below: (@Composable () -> Unit)?) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    var confirm by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().statusBarsPadding().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp)) {
        Text(
            stringResource(R.string.security_title), color = c.text, style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 16.dp, bottom = 8.dp).semantics { heading() },
        )
        Column(
            Modifier.fillMaxWidth().padding(vertical = 12.dp).testTag("security-header"),
            horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            ScoreRing(state.score)
            Text(
                if (state.score == null) stringResource(R.string.security_empty_hint) else stringResource(state.band.label),
                color = c.text, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center,
                modifier = Modifier.testTag("security-band"),
            )
        }
        SectionTitle(stringResource(R.string.security_checks_header))
        Column(Modifier.fillMaxWidth().lgkGroupSurface()) {
            SecurityCategory.entries.forEachIndexed { index, category ->
                val count = state.count(category)
                val label = stringResource(category.label)
                val description = stringResource(R.string.security_row_description, label, count)
                Row(
                    Modifier.fillMaxWidth().defaultMinSize(minHeight = 56.dp)
                        .clickable(role = Role.Button) { onOpen(category) }
                        .semantics(mergeDescendants = true) { contentDescription = description }
                        .testTag("security-row-${category.raw}")
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(category.icon(), null, Modifier.size(28.dp), tint = tint(category, count))
                    Spacer(Modifier.width(12.dp))
                    Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                    Text(count.toString(), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.testTag("security-count-${category.raw}"))
                    Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null, Modifier.size(20.dp), tint = c.secondaryText)
                }
                if (index < SecurityCategory.entries.lastIndex) {
                    Box(Modifier.padding(start = 56.dp).fillMaxWidth().height(1.dp).background(c.separator))
                }
            }
        }
        Footnote(stringResource(R.string.security_checks_footer))

        SectionTitle(stringResource(R.string.security_breach_header))
        val blocked = model.breachBlocked
        Column(Modifier.fillMaxWidth().lgkGroupSurface().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            when {
                blocked != null -> Text(blocked.text(txt), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("security-breach-blocked"))
                state.running -> Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    CircularProgressIndicator(Modifier.size(24.dp), color = c.accent, strokeWidth = 2.dp)
                    Text((state.status ?: BreachStatus.Running).text(txt), color = c.secondaryText, modifier = Modifier.weight(1f))
                    TextButton(onClick = { model.cancelBreachCheck() }, modifier = Modifier.testTag("security-breach-cancel")) {
                        Text(stringResource(R.string.security_cancel), color = c.accentText)
                    }
                }
                else -> TextButton(onClick = { confirm = true }, modifier = Modifier.testTag("security-breach-start")) {
                    Text(stringResource(R.string.security_breach_start), color = c.accentText)
                }
            }
            val status = state.status
            if (!state.running && blocked == null && status != null) {
                Text(status.text(txt), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("security-breach-status"))
            }
            if (state.dismissed.isNotEmpty()) {
                TextButton(onClick = { model.restoreDismissed() }, modifier = Modifier.testTag("security-show-dismissed")) {
                    Text(stringResource(R.string.security_show_dismissed), color = c.accentText)
                }
            }
        }
        below?.let { Spacer(Modifier.height(16.dp)); it() }
        Spacer(Modifier.height(96.dp))
    }
    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text(stringResource(R.string.security_confirm_title)) },
            text = { Text(stringResource(R.string.security_consent)) },
            confirmButton = {
                TextButton(onClick = { confirm = false; model.checkBreaches() }, modifier = Modifier.testTag("security-confirm")) {
                    Text(stringResource(R.string.security_confirm_action))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirm = false }, modifier = Modifier.testTag("security-confirm-cancel")) {
                    Text(stringResource(R.string.security_cancel))
                }
            },
        )
    }
}

@Composable
private fun IssueList(
    model: SecurityCheckModel,
    state: SecurityState,
    category: SecurityCategory,
    onBack: () -> Unit,
    onOpenItem: (VaultItem) -> Unit,
    onChangePassword: (VaultItem) -> Unit,
) {
    val c = LgkTheme.colors
    val rows = state.items(category)
    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        Row(Modifier.fillMaxWidth().height(64.dp).padding(horizontal = 16.dp), verticalAlignment = Alignment.CenterVertically) {
            val backLabel = stringResource(R.string.common_back)
            Box(
                Modifier.size(48.dp).lgkGlass(CircleShape).clickable(role = Role.Button, onClick = onBack)
                    .semantics { contentDescription = backLabel }.testTag("security-back"),
                contentAlignment = Alignment.Center,
            ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = c.text) }
            Text(
                stringResource(category.label), color = c.text, style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center,
                modifier = Modifier.weight(1f).padding(horizontal = 12.dp).semantics { heading() },
            )
            Spacer(Modifier.width(48.dp))
        }
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp)) {
            if (rows.isEmpty()) {
                Text(
                    stringResource(R.string.security_nothing_to_fix), color = c.secondaryText,
                    modifier = Modifier.padding(vertical = 16.dp).testTag("security-empty"),
                )
            } else {
                Column(Modifier.fillMaxWidth().lgkGroupSurface()) {
                    rows.forEachIndexed { index, item ->
                        IssueRow(
                            item, category,
                            onOpen = { onOpenItem(item) },
                            onChangePassword = { onChangePassword(item) },
                            onDismiss = { model.dismiss(category, item.id) },
                        )
                        if (index < rows.lastIndex) {
                            Box(Modifier.padding(start = 72.dp).fillMaxWidth().height(1.dp).background(c.separator))
                        }
                    }
                }
            }
            Footnote(stringResource(R.string.security_issue_footer, stringResource(category.explanation)))
            Spacer(Modifier.height(96.dp))
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun IssueRow(
    item: VaultItem,
    category: SecurityCategory,
    onOpen: () -> Unit,
    onChangePassword: () -> Unit,
    onDismiss: () -> Unit,
) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    var menu by remember { mutableStateOf(false) }
    val haptic = LocalHapticFeedback.current
    val title = item.title.ifEmpty { stringResource(R.string.security_untitled) }
    val changeLabel = stringResource(R.string.security_change_password)
    val dismissLabel = stringResource(R.string.security_dismiss_item)
    val moreLabel = stringResource(R.string.security_row_menu, title)
    Box(Modifier.fillMaxWidth()) {
        Row(
            Modifier.fillMaxWidth().defaultMinSize(minHeight = 64.dp)
                .combinedClickable(
                    onClick = onOpen,
                    onLongClick = { haptic.performHapticFeedback(HapticFeedbackType.LongPress); menu = true },
                )
                .semantics {
                    customActions = listOfNotNull(
                        if (category.offersChangePassword) CustomAccessibilityAction(changeLabel) { onChangePassword(); true } else null,
                        CustomAccessibilityAction(dismissLabel) { onDismiss(); true },
                    )
                }
                .testTag("security-item")
                .padding(start = 14.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            ItemAvatar(item)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(title, color = c.text, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    item.listSubtitle(txt), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium,
                    maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
            }
            // The row's own accessibility actions above cover screen readers; this button is for touch.
            IconButton(onClick = { menu = true }, modifier = Modifier.testTag("security-item-menu")) {
                Icon(Icons.Filled.MoreVert, moreLabel, tint = c.secondaryText)
            }
        }
        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
            if (category.offersChangePassword) {
                DropdownMenuItem(
                    text = { Text(changeLabel) },
                    onClick = { menu = false; onChangePassword() },
                    modifier = Modifier.testTag("security-menu-change"),
                )
            }
            DropdownMenuItem(
                text = { Text(dismissLabel) },
                onClick = { menu = false; onDismiss() },
                modifier = Modifier.testTag("security-menu-dismiss"),
            )
        }
    }
}

/** The score, 0-100, as a ring. */
@Composable
fun ScoreRing(score: Int?, modifier: Modifier = Modifier) {
    val c = LgkTheme.colors
    val description = if (score == null) stringResource(R.string.security_no_score) else stringResource(R.string.security_score_description, score)
    val color = when {
        score == null -> c.separator
        score >= 80 -> c.success
        score >= 50 -> c.warning
        else -> c.danger
    }
    val track = c.separator
    Box(
        modifier.size(120.dp).testTag("security-score").semantics(mergeDescendants = true) { contentDescription = description },
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val stroke = 12.dp.toPx()
            val inset = stroke / 2
            val arcSize = Size(size.width - stroke, size.height - stroke)
            drawArc(track, 0f, 360f, false, Offset(inset, inset), arcSize, style = Stroke(stroke))
            drawArc(color, -90f, 360f * ((score ?: 0) / 100f), false, Offset(inset, inset), arcSize, style = Stroke(stroke, cap = StrokeCap.Round))
        }
        Text(
            score?.toString() ?: "—", color = c.text, style = MaterialTheme.typography.headlineLarge,
            fontWeight = FontWeight.Bold, modifier = Modifier.clearAndSetSemantics { },
        )
    }
}

@Composable
private fun SectionTitle(title: String) {
    Text(
        title, color = LgkTheme.colors.text, style = MaterialTheme.typography.titleSmall,
        modifier = Modifier.padding(start = 12.dp, end = 12.dp, top = 14.dp, bottom = 4.dp).semantics { heading() },
    )
}

@Composable
private fun Footnote(text: String) {
    Text(
        text, color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.bodySmall,
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
    )
}

@Composable
private fun tint(category: SecurityCategory, count: Int): Color {
    val c = LgkTheme.colors
    return when {
        count == 0 -> c.success
        category == SecurityCategory.BREACHED || category == SecurityCategory.WEAK -> c.danger
        else -> c.warning
    }
}
