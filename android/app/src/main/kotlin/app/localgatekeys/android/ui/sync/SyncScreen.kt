package app.localgatekeys.android.ui.sync

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Cancel
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncStatus
import app.localgatekeys.android.sync.SyncWording
import app.localgatekeys.android.ui.shell.Overlay
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.ui.vault.tabBarClearance
import app.localgatekeys.android.unlock.LocalActivityMonitor
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.launch

/** The Sync screen's copy that is not desktop wording (from `ios/App/Sync/SyncScreen.swift`, platform words adapted). */
object SyncScreenText {
    const val WIFI_PAIRED_HINT = "Syncs when both are on the same Wi-Fi and LocalGateKeys is unlocked on the other device."
    const val WIFI_NOT_JOINED = "On your PC choose Show QR code on the Wi-Fi card, then scan it here within 120 seconds."
    val WIFI_FOLDER_ONLY = SyncWording.onPhone("This PC syncs through the cloud folder only.")
    const val FOLDER_SYNCING = "Syncing through the cloud folder."
    const val FOLDER_PICK_AGAIN = "Choose the sync folder again on this phone."
    val FOLDER_JOINED = SyncWording.onPhone(
        "To sync through a cloud folder too, use the folder another device in this group already added. Your Wi-Fi pairings stay as they are.",
    )
    /** Ruling 20 (amended): Google Drive offers no folder on Android, so it is named only in the Drive notice. */
    const val FOLDER_NOT_JOINED =
        "Choose the folder your cloud app syncs (OneDrive, Dropbox, Nextcloud), the one that holds LocalGateKeys Sync, and enter the sync password."
    const val CAMERA_UNAVAILABLE = "The camera is not available. Use Paste code text instead."
    const val PASTE_FOOTER = "On your PC choose Copy code text, then paste it here."
    const val PASTE_PLACEHOLDER = "lgk-pair:…"
    const val RESET_BUTTON = "Reset sync on this phone…"
    const val RESET_TITLE = "Reset sync on this phone"

    fun pairedWith(deviceId: String): String = "Paired with ${SyncWording.shortID(deviceId)}"
}

private enum class Sheet { SCANNER, PASTE }

private enum class Confirm { LEAVE1, LEAVE2, RESET1, RESET2 }

/**
 * The Sync tab (from `ios/App/Sync/SyncScreen.swift`): status (spinner, status line, conflict copies, Cancel while a QR
 * join connects, the last action's error or result, Sync now), the Wi-Fi card (pair by QR: scan or paste), the cloud
 * folder card, the messages in the desktop's wording, and Leave / Reset (two confirmations each). Pull to refresh syncs.
 * [folderPicker]: the system folder picker; a picked folder goes on to the password sheet (join or attach), or straight
 * to the coordinator when this phone already syncs through the group's folder (choose it again). null: no folder buttons.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncScreen(sync: SyncCoordinator, folderPicker: FolderPicking? = null) {
    val c = LgkTheme.colors
    val phase by sync.phase.collectAsStateWithLifecycle()
    val membership by sync.membership.collectAsStateWithLifecycle()
    val issues by sync.issues.collectAsStateWithLifecycle()
    val lastSyncedAt by sync.lastSyncedAt.collectAsStateWithLifecycle()
    val conflicts by sync.conflictCopies.collectAsStateWithLifecycle()
    val actionError by sync.actionError.collectAsStateWithLifecycle()
    val actionInfo by sync.actionInfo.collectAsStateWithLifecycle()
    val connecting by sync.connecting.collectAsStateWithLifecycle()
    val verificationCode by sync.verificationCode.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var refreshing by remember { mutableStateOf(false) }
    var sheet by remember { mutableStateOf<Sheet?>(null) }
    var confirm by remember { mutableStateOf<Confirm?>(null) }
    var localError by remember { mutableStateOf<String?>(null) }
    val folderFlow = remember(sync) { FolderJoinFlow(sync) }
    val folderForm by folderFlow.form.collectAsStateWithLifecycle()
    val folderError by folderFlow.error.collectAsStateWithLifecycle()
    val list = rememberLazyListState()
    LaunchedEffect(sync) { sync.refreshMembership() }
    // A refused join (often reported after the scanner closes) is always brought into view.
    LaunchedEffect(actionError, localError, folderError) {
        if (actionError != null || localError != null || folderError != null) list.animateScrollToItem(0)
    }
    val busy = phase != SyncCoordinator.Phase.IDLE
    val time = remember { DateFormat.getTimeInstance(DateFormat.SHORT) }
    val join: (String) -> Unit = { code ->
        sheet = null
        localError = null
        scope.launch { sync.joinByQr(code) }
    }
    // Picks arrive here, also one redelivered after the activity was recreated while the picker was open.
    if (folderPicker != null) {
        LaunchedEffect(folderPicker, folderFlow) { folderPicker.results.collect { folderFlow.picked(it) } }
    }
    val pickFolder: (() -> Unit)? = folderPicker?.let { picker ->
        {
            localError = null
            picker.pick()
        }
    }

    Box(Modifier.fillMaxSize()) {
        PullToRefreshBox(
            isRefreshing = refreshing,
            onRefresh = {
                refreshing = true
                // The coordinator reports failures through its state; nothing is thrown here.
                scope.launch {
                    try {
                        sync.sync(SyncCoordinator.Trigger.PULL_TO_REFRESH)
                    } finally {
                        refreshing = false
                    }
                }
            },
            modifier = Modifier.fillMaxSize(),
        ) {
            LazyColumn(
                Modifier.fillMaxSize().testTag("sync-list"),
                state = list,
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = tabBarClearance()),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                item(key = "status") {
                    Card {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            if (busy) {
                                CircularProgressIndicator(Modifier.size(18.dp), color = c.secondaryText, strokeWidth = 2.dp)
                                Spacer(Modifier.width(10.dp))
                            }
                            Text(
                                SyncStatus.text(phase, connecting, membership.joined, lastSyncedAt, verificationCode) { time.format(Date(it * 1000)) },
                                color = c.text, style = MaterialTheme.typography.bodyLarge,
                                modifier = Modifier.testTag("sync-status"),
                            )
                        }
                        SyncStatus.conflictText(conflicts)?.let {
                            Text(it, color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
                        }
                        if (connecting != null) {
                            TextButton({ sync.cancelJoin() }) { Text("Cancel", color = c.accentText) }
                        }
                        verificationCode?.let { code ->
                            // QR join waiting for Accept on the inviting device, which shows the same code.
                            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(
                                    SyncWording.verificationCodeText(code),
                                    color = c.text,
                                    style = MaterialTheme.typography.displaySmall.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold),
                                    modifier = Modifier.testTag("sync-verification-code").semantics {
                                        contentDescription = "Verification code ${code.toList().joinToString(" ")}"
                                    },
                                )
                                Text(SyncWording.VERIFICATION_CODE_HINT, color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                        (actionError ?: localError ?: folderError)?.let {
                            Text(it, color = c.danger, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("sync-error"))
                        }
                        actionInfo?.let { Text(it, color = c.success, style = MaterialTheme.typography.bodyMedium) }
                        if (membership.joined) {
                            ActionButton("Sync now", enabled = !busy, bold = true) { scope.launch { sync.sync(SyncCoordinator.Trigger.MANUAL) } }
                        }
                    }
                }
                item(key = "wifi") {
                    Section("Wi-Fi", Modifier.testTag("sync-wifi")) {
                        val peer = membership.peer
                        when {
                            peer != null -> {
                                Text(SyncScreenText.pairedWith(peer.deviceId), color = c.text, style = MaterialTheme.typography.bodyLarge)
                                peer.endpoint?.let { Footnote("${it.host} port ${it.port}") }
                                Footnote(SyncScreenText.WIFI_PAIRED_HINT)
                            }
                            !membership.joined -> {
                                Footnote(SyncScreenText.WIFI_NOT_JOINED)
                                ActionButton("Scan QR code", enabled = !busy) { localError = null; sheet = Sheet.SCANNER }
                                ActionButton("Paste code text", enabled = !busy) { sheet = Sheet.PASTE }
                            }
                            else -> Footnote(SyncScreenText.WIFI_FOLDER_ONLY)
                        }
                    }
                }
                item(key = "folder") {
                    Section("Cloud folder", Modifier.testTag("sync-folder")) {
                        when {
                            membership.hasFolder -> {
                                Text(
                                    if (membership.hasFolderUri) SyncScreenText.FOLDER_SYNCING else SyncScreenText.FOLDER_PICK_AGAIN,
                                    color = if (membership.hasFolderUri) c.text else c.warning, style = MaterialTheme.typography.bodyLarge,
                                )
                                pickFolder?.let { ActionButton("Choose the folder again…", enabled = !busy, onClick = it) }
                            }
                            membership.joined -> {
                                Footnote(SyncScreenText.FOLDER_JOINED)
                                Footnote(FolderJoinText.GOOGLE_DRIVE_NOTICE)
                                pickFolder?.let { ActionButton("Use this group's cloud folder…", enabled = !busy, onClick = it) }
                            }
                            else -> {
                                Footnote(SyncScreenText.FOLDER_NOT_JOINED)
                                Footnote(FolderJoinText.GOOGLE_DRIVE_NOTICE)
                                pickFolder?.let { ActionButton("Join a folder…", enabled = !busy, onClick = it) }
                            }
                        }
                    }
                }
                if (issues.isNotEmpty()) {
                    item(key = "messages") {
                        Section("Messages", Modifier.testTag("sync-messages")) {
                            for (issue in issues) {
                                IssueRow(issue)
                                if (issue.resetOffered) ActionButton(SyncScreenText.RESET_BUTTON) { confirm = Confirm.RESET1 }
                            }
                        }
                    }
                }
                if (membership.joined) {
                    item(key = "leave") {
                        Card(Modifier.testTag("sync-leave")) {
                            ActionButton("Leave sync…", enabled = !busy, destructive = true, divider = false) { confirm = Confirm.LEAVE1 }
                            ActionButton(SyncScreenText.RESET_BUTTON, enabled = !busy, destructive = true) { confirm = Confirm.RESET1 }
                        }
                    }
                }
            }
        }
        when (sheet) {
            Sheet.SCANNER -> Overlay {
                QrScannerScreen(
                    "Scan QR code", QrScanner.SYNC_DENIED_TEXT,
                    onCode = join,
                    onUnavailable = { sheet = null; localError = SyncScreenText.CAMERA_UNAVAILABLE },
                    onCancel = { sheet = null },
                )
            }
            Sheet.PASTE -> Overlay { PasteCodeSheet(onCancel = { sheet = null }, onJoin = join) }
            null -> Unit
        }
        folderForm?.let { form ->
            Overlay {
                FolderPasswordSheet(
                    form,
                    onCancel = { scope.launch { folderFlow.cancel() } },
                    onJoin = { scope.launch { folderFlow.join() } },
                )
            }
        }
    }

    confirm?.let { step ->
        val leave = step == Confirm.LEAVE1 || step == Confirm.LEAVE2
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text(if (leave) "Leave sync" else SyncScreenText.RESET_TITLE) },
            text = {
                Text(
                    SyncWording.onPhone(
                        when (step) {
                            Confirm.LEAVE1 -> if (membership.hasFolder) SyncWording.LEAVE_TEXT else SyncWording.LEAVE_WIFI_TEXT
                            Confirm.LEAVE2 -> SyncWording.LEAVE_TEXT_2
                            Confirm.RESET1 -> SyncWording.RESET_TEXT_1
                            Confirm.RESET2 -> SyncWording.RESET_TEXT_2
                        },
                    ),
                )
            },
            confirmButton = {
                TextButton({
                    when (step) {
                        Confirm.LEAVE1 -> confirm = Confirm.LEAVE2
                        Confirm.RESET1 -> confirm = Confirm.RESET2
                        Confirm.LEAVE2 -> { confirm = null; scope.launch { sync.leave() } }
                        Confirm.RESET2 -> { confirm = null; scope.launch { sync.reset() } }
                    }
                }) {
                    Text(
                        when (step) {
                            Confirm.LEAVE1, Confirm.RESET1 -> "Continue"
                            Confirm.LEAVE2 -> "Leave sync"
                            Confirm.RESET2 -> "Reset"
                        },
                        color = c.danger,
                    )
                }
            },
            dismissButton = { TextButton({ confirm = null }) { Text("Cancel", color = c.accentText) } },
        )
    }
}

/** "Paste code text": the code text the PC copies, then Join (the iPhone's paste sheet). Never saved anywhere. */
@Composable
private fun PasteCodeSheet(onCancel: () -> Unit, onJoin: (String) -> Unit) {
    val c = LgkTheme.colors
    val monitor = LocalActivityMonitor.current
    var code by remember { mutableStateOf("") }
    BackHandler(onBack = onCancel)
    Box(Modifier.fillMaxSize().pointerInput(Unit) { awaitPointerEventScope { while (true) awaitPointerEvent() } }.testTag("paste-code")) {
        GlassBackdropHost(Modifier.fillMaxSize()) { AuroraBackground() }
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            Row(Modifier.fillMaxWidth().height(64.dp).padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                TextButton(onCancel) { Text("Cancel", color = c.accentText) }
                Text(
                    "Paste code text", color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    textAlign = TextAlign.Center, modifier = Modifier.weight(1f).semantics { heading() },
                )
                Button(
                    { onJoin(code) },
                    enabled = code.isNotEmpty(),
                    colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
                    modifier = Modifier.padding(end = 4.dp),
                ) { Text("Join", fontWeight = FontWeight.SemiBold) }
            }
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).navigationBarsPadding().imePadding().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Column(Modifier.fillMaxWidth().lgkGroupSurface().padding(16.dp)) {
                    BasicTextField(
                        value = code,
                        onValueChange = { monitor?.textChanged(); code = it },
                        textStyle = MaterialTheme.typography.bodyLarge.copy(color = c.text),
                        cursorBrush = SolidColor(c.accent),
                        // A pairing secret: no capitals, no autocorrect, no suggestions.
                        keyboardOptions = KeyboardOptions(KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = KeyboardType.Password),
                        maxLines = 8,
                        modifier = Modifier.fillMaxWidth().testTag("paste-field").semantics { contentDescription = "Code text" },
                        decorationBox = { inner ->
                            Box {
                                if (code.isEmpty()) Text(SyncScreenText.PASTE_PLACEHOLDER, color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
                                inner()
                            }
                        },
                    )
                }
                Text(
                    SyncScreenText.PASTE_FOOTER, color = c.secondaryText, style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(horizontal = 4.dp),
                )
            }
        }
    }
}

@Composable
private fun Card(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier.fillMaxWidth().lgkGroupSurface().padding(horizontal = 16.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
        content = content,
    )
}

@Composable
private fun Section(title: String, modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(modifier.fillMaxWidth()) {
        Text(
            title, color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(start = 4.dp, bottom = 6.dp).semantics { heading() },
        )
        Card(content = content)
    }
}

@Composable
private fun Footnote(text: String) {
    Text(text, color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.bodySmall)
}

/** A button drawn as a list row (the iPhone's List button): full width, a hairline above unless [divider] is false. */
@Composable
private fun ActionButton(
    label: String,
    enabled: Boolean = true,
    bold: Boolean = false,
    destructive: Boolean = false,
    divider: Boolean = true,
    onClick: () -> Unit,
) {
    val c = LgkTheme.colors
    Column(Modifier.fillMaxWidth()) {
        if (divider) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
        Box(
            Modifier.fillMaxWidth().heightIn(min = 44.dp).clickable(enabled = enabled, role = Role.Button, onClick = onClick),
            contentAlignment = Alignment.CenterStart,
        ) {
            Text(
                label,
                color = when {
                    !enabled -> c.secondaryText
                    destructive -> c.danger
                    else -> c.accentText
                },
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = if (bold) FontWeight.SemiBold else null,
            )
        }
    }
}

@Composable
private fun IssueRow(issue: SyncWording.IssueView) {
    val c = LgkTheme.colors
    val (icon, tint) = when (issue.severity) {
        SyncWording.Severity.ERROR -> Icons.Outlined.Cancel to c.danger
        SyncWording.Severity.WARNING -> Icons.Outlined.Warning to c.warning
        SyncWording.Severity.NOTICE -> Icons.Outlined.Info to c.secondaryText
    }
    Row(verticalAlignment = Alignment.Top) {
        Icon(icon, null, tint = tint, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(10.dp))
        Text(issue.text, color = c.text, style = MaterialTheme.typography.bodyMedium)
    }
}
