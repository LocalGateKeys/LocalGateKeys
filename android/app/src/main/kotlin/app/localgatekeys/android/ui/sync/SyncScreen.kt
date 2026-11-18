package app.localgatekeys.android.ui.sync
import androidx.compose.ui.res.stringResource

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.i18n.rememberTxt
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
import app.localgatekeys.android.ui.pro.UpgradeSheet
import app.localgatekeys.android.sync.SyncStatus
import app.localgatekeys.android.sync.SyncWording
import app.localgatekeys.android.ui.shell.Overlay
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.warningText
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.ui.vault.tabBarClearance
import app.localgatekeys.android.unlock.LocalActivityMonitor
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.launch

/** The Sync screen's copy that is not desktop wording (from `ios/App/Sync/SyncScreen.swift`, platform words adapted). */
object SyncScreenText {
    @StringRes val WIFI_PAIRED_HINT = R.string.sync_wifi_paired_hint
    @StringRes val WIFI_NOT_JOINED = R.string.sync_wifi_not_joined
    @StringRes val WIFI_FOLDER_ONLY = R.string.sync_wifi_folder_only
    @StringRes val FOLDER_SYNCING = R.string.sync_folder_syncing
    @StringRes val FOLDER_PICK_AGAIN = R.string.sync_folder_pick_again
    @StringRes val FOLDER_JOINED = R.string.sync_folder_joined

    /** Ruling 20 (amended): Google Drive offers no folder on Android, so it is named only in the Drive notice. */
    @StringRes val FOLDER_NOT_JOINED = R.string.sync_folder_not_joined
    @StringRes val CAMERA_UNAVAILABLE = R.string.sync_camera_unavailable
    @StringRes val PASTE_FOOTER = R.string.sync_paste_footer

    /** The pairing code's own prefix (data format, not translated). */
    const val PASTE_PLACEHOLDER = "lgk-pair:…"
    @StringRes val RESET_BUTTON = R.string.sync_reset_button
    @StringRes val RESET_TITLE = R.string.sync_reset_title
    @StringRes val ROLLBACK_KEEP = R.string.sync_rollback_keep

    /** The owner check's prompt title before a rollback is acknowledged (the iPhone's localizedReason). */
    @StringRes val ROLLBACK_REASON = R.string.sync_rollback_reason

    fun pairedWith(deviceId: String, t: Txt): String = t.s(R.string.sync_paired_with, SyncWording(t).shortID(deviceId))
}

private enum class Sheet { SCANNER, PASTE, FIND_AGAIN }

private enum class Confirm { LEAVE1, LEAVE2, RESET1, RESET2, ROLLBACK }

/** An open removal sheet: "I lost a device" ([lost]) or "Remove a device" with [initial] preselected. */
private data class RemoveRequest(val lost: Boolean, val initial: String?)

/**
 * The Sync tab (from `ios/App/Sync/SyncScreen.swift`): status (spinner, status line, conflict copies, Cancel while a QR
 * join connects, the last action's error or result, Sync now), the Wi-Fi card (pair by QR: scan or paste), the cloud
 * folder card, the messages in the desktop's wording, and Leave / Reset (two confirmations each). Pull to refresh syncs.
 * [folderPicker]: the system folder picker; a picked folder goes on to the password sheet (join or attach), or straight
 * to the coordinator when this phone already syncs through the group's folder (choose it again). null: no folder buttons.
 * [confirmOwner]: the owner's fingerprint, face or screen lock, asked before "This was me — keep this copy" acknowledges
 * a vault rollback (null: the button is not offered). A peer's rollback message offers Dismiss.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncScreen(sync: SyncCoordinator, folderPicker: FolderPicking? = null, confirmOwner: (suspend () -> Boolean)? = null) {
    val txt = rememberTxt()
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
    var removeRequest by remember { mutableStateOf<RemoveRequest?>(null) }
    var needsPro by remember { mutableStateOf<Int?>(null) }
    var upgradeOpen by remember { mutableStateOf(false) }
    var confirmDevices by remember { mutableStateOf(false) }
    var confirmedText by remember { mutableStateOf<String?>(null) }
    var hostSheet by remember { mutableStateOf(false) }
    val host = sync.host
    val pro = LocalProModel.current
    val proState = pro?.state?.collectAsStateWithLifecycle()
    val isPro = proState?.value?.isPro == true
    val words = remember(txt) { SyncWording(txt) }
    val folderFlow = remember(sync) { FolderJoinFlow(sync, txt) }
    val folderForm by folderFlow.form.collectAsStateWithLifecycle()
    val folderError by folderFlow.error.collectAsStateWithLifecycle()
    val freshKeyText by folderFlow.freshKeyText.collectAsStateWithLifecycle()
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
                                SyncStatus(txt).text(phase, connecting, membership.joined, lastSyncedAt, verificationCode) { time.format(Date(it * 1000)) },
                                color = c.text, style = MaterialTheme.typography.bodyLarge,
                                modifier = Modifier.testTag("sync-status"),
                            )
                        }
                        SyncStatus(txt).conflictText(conflicts)?.let {
                            Text(it, color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
                        }
                        if (connecting != null) {
                            TextButton({ sync.cancelJoin() }) { Text(stringResource(R.string.common_cancel), color = c.accentText) }
                        }
                        verificationCode?.let { code ->
                            val verificationDescription = txt.s(R.string.sync_verification_code_description, code.toList().joinToString(" "))
                            // QR join waiting for Accept on the inviting device, which shows the same code.
                            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(
                                    SyncWording.verificationCodeText(code),
                                    color = c.text,
                                    style = MaterialTheme.typography.displaySmall.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold),
                                    modifier = Modifier.testTag("sync-verification-code").semantics {
                                        contentDescription = verificationDescription
                                    },
                                )
                                Text(txt.s(SyncWording.VERIFICATION_CODE_HINT), color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                        (actionError ?: localError ?: folderError)?.let {
                            Text(it, color = c.danger, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("sync-error"))
                        }
                        actionInfo?.let { Text(it, color = c.success, style = MaterialTheme.typography.bodyMedium) }
                        if (membership.joined) {
                            ActionButton(txt.s(R.string.sync_now), enabled = !busy, bold = true) { scope.launch { sync.sync(SyncCoordinator.Trigger.MANUAL) } }
                        }
                    }
                }
                item(key = "wifi") {
                    Section(txt.s(R.string.sync_section_wifi), Modifier.testTag("sync-wifi")) {
                        val peer = membership.peer
                        when {
                            peer != null -> {
                                Text(SyncScreenText.pairedWith(peer.deviceId, txt), color = c.text, style = MaterialTheme.typography.bodyLarge)
                                peer.endpoint?.let { Footnote(txt.s(R.string.sync_host_port, it.host, it.port)) }
                                Footnote(txt.s(SyncScreenText.WIFI_PAIRED_HINT))
                                if (issues.any { it.kind == "unreachable" }) {
                                    // Pinned address and discovery both failed: a fresh QR from the same PC moves the address.
                                    Text(
                                        txt.s(SyncWording.CANT_FIND_PC), color = c.warningText, style = MaterialTheme.typography.bodyLarge,
                                        modifier = Modifier.testTag("sync-cant-find"),
                                    )
                                    Footnote(txt.s(SyncWording.CANT_FIND_PC_HINT))
                                    ActionButton(txt.s(SyncWording.FIND_AGAIN), enabled = !busy) { localError = null; sheet = Sheet.FIND_AGAIN }
                                }
                            }
                            !membership.joined -> {
                                Footnote(txt.s(SyncScreenText.WIFI_NOT_JOINED))
                                ActionButton(txt.s(R.string.sync_scan_qr), enabled = !busy) { localError = null; sheet = Sheet.SCANNER }
                                ActionButton(txt.s(R.string.sync_paste_code), enabled = !busy) { sheet = Sheet.PASTE }
                            }
                            // A Wi-Fi group this phone hosts is shown by the host part below.
                            membership.hasFolder || host == null -> Footnote(txt.s(SyncScreenText.WIFI_FOLDER_ONLY))
                        }
                        host?.let { WifiHostSection(it, membership, busy) { hostSheet = true } }
                    }
                }
                item(key = "folder") {
                    Section(txt.s(R.string.sync_section_folder), Modifier.testTag("sync-folder")) {
                        when {
                            membership.hasFolder -> {
                                Text(
                                    if (membership.hasFolderUri) txt.s(SyncScreenText.FOLDER_SYNCING) else txt.s(SyncScreenText.FOLDER_PICK_AGAIN),
                                    color = if (membership.hasFolderUri) c.text else c.warningText, style = MaterialTheme.typography.bodyLarge,
                                )
                                pickFolder?.let { ActionButton(txt.s(R.string.sync_choose_folder_again), enabled = !busy, onClick = it) }
                            }
                            membership.joined -> {
                                Footnote(txt.s(SyncScreenText.FOLDER_JOINED))
                                Footnote(txt.s(FolderJoinText.GOOGLE_DRIVE_NOTICE))
                                pickFolder?.let { pick ->
                                    ActionButton(txt.s(R.string.sync_use_group_folder), enabled = !busy) { folderFlow.startJoin(); pick() }
                                    ActionButton(txt.s(R.string.sync_add_folder_to_group), enabled = !busy) {
                                        if (isPro) {
                                            sync.clearActionError(); folderFlow.startAdd(); pick()
                                        } else {
                                            needsPro = R.string.sync_start_folder_needs_pro
                                        }
                                    }
                                }
                            }
                            else -> {
                                Footnote(txt.s(SyncScreenText.FOLDER_NOT_JOINED))
                                Footnote(txt.s(FolderJoinText.GOOGLE_DRIVE_NOTICE))
                                pickFolder?.let { pick ->
                                    ActionButton(txt.s(R.string.sync_join_folder), enabled = !busy) { folderFlow.startJoin(); pick() }
                                    ActionButton(txt.s(R.string.sync_start_folder), enabled = !busy) {
                                        if (isPro) {
                                            sync.clearActionError(); folderFlow.startCreate(); pick()
                                        } else {
                                            needsPro = R.string.sync_start_folder_needs_pro
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if (membership.hasFolder) {
                    item(key = "members") {
                        Section(txt.s(R.string.sync_members_title), Modifier.testTag("sync-members")) {
                            Text(txt.s(R.string.sync_this_device), color = c.text, style = MaterialTheme.typography.bodyLarge)
                            membership.deviceId?.let {
                                Text(words.thisDeviceLabel(it, membership.names), color = c.secondaryText, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("sync-own-id"))
                            }
                            val unconfirmed = membership.unconfirmed.toSet()
                            for (id in membership.members) {
                                HorizontalDivider(thickness = 0.5.dp, color = c.separator)
                                Row(Modifier.fillMaxWidth().heightIn(min = 44.dp).testTag("sync-member-$id"), verticalAlignment = Alignment.CenterVertically) {
                                    Column(Modifier.weight(1f).padding(vertical = 6.dp)) {
                                        Text(RemovalText.displayName(id, membership, words), color = c.text, style = MaterialTheme.typography.bodyLarge)
                                        if (id in unconfirmed) {
                                            Text(txt.s(R.string.sync_unconfirmed_detail), color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
                                        }
                                    }
                                    TextButton(
                                        { if (isPro) { localError = null; sync.clearActionError(); removeRequest = RemoveRequest(false, id) } else needsPro = R.string.sync_remove_needs_pro },
                                        enabled = !busy,
                                    ) { Text(txt.s(R.string.sync_remove_button), color = if (busy) c.secondaryText else c.danger) }
                                }
                            }
                            if (membership.unconfirmed.isNotEmpty()) {
                                Footnote(txt.s(R.string.sync_unconfirmed_text))
                                ActionButton(txt.s(R.string.sync_these_are_my_devices), enabled = !busy) { confirmDevices = true }
                            }
                            confirmedText?.let { Text(it, color = c.success, style = MaterialTheme.typography.bodyMedium) }
                            if (membership.members.isNotEmpty()) {
                                ActionButton(txt.s(R.string.sync_remove_a_device), enabled = !busy) {
                                    if (isPro) { localError = null; sync.clearActionError(); removeRequest = RemoveRequest(false, null) } else needsPro = R.string.sync_remove_needs_pro
                                }
                                ActionButton(txt.s(R.string.sync_lost_a_device), enabled = !busy) {
                                    if (isPro) { localError = null; sync.clearActionError(); removeRequest = RemoveRequest(true, null) } else needsPro = R.string.sync_remove_needs_pro
                                }
                            }
                        }
                    }
                }
                if (issues.isNotEmpty()) {
                    item(key = "messages") {
                        Section(txt.s(R.string.sync_section_messages), Modifier.testTag("sync-messages")) {
                            for (issue in issues) {
                                IssueRow(issue)
                                if (issue.kind == "vault-rollback" && confirmOwner != null) {
                                    ActionButton(txt.s(SyncWording.ROLLBACK_ACTION), enabled = !busy) { confirm = Confirm.ROLLBACK }
                                }
                                if (issue.kind == "peer-vault-rollback" && issue.detail.isNotEmpty()) {
                                    ActionButton(txt.s(SyncWording.PEER_ROLLBACK_DISMISS), enabled = !busy) {
                                        scope.launch { sync.dismissPeerRollback(issue.detail) }
                                    }
                                }
                                if (issue.resetOffered) ActionButton(txt.s(SyncScreenText.RESET_BUTTON)) { confirm = Confirm.RESET1 }
                            }
                        }
                    }
                }
                if (membership.joined) {
                    item(key = "leave") {
                        Card(Modifier.testTag("sync-leave")) {
                            ActionButton(txt.s(R.string.sync_leave_button), enabled = !busy, destructive = true, divider = false) { confirm = Confirm.LEAVE1 }
                            ActionButton(txt.s(SyncScreenText.RESET_BUTTON), enabled = !busy, destructive = true) { confirm = Confirm.RESET1 }
                        }
                    }
                }
            }
        }
        when (sheet) {
            Sheet.SCANNER -> Overlay {
                QrScannerScreen(
                    txt.s(R.string.sync_scan_qr), txt.s(QrScanner.SYNC_DENIED_TEXT),
                    onCode = join,
                    onUnavailable = { sheet = null; localError = txt.s(SyncScreenText.CAMERA_UNAVAILABLE) },
                    onCancel = { sheet = null },
                )
            }
            Sheet.PASTE -> Overlay { PasteCodeSheet(onCancel = { sheet = null }, onJoin = join) }
            Sheet.FIND_AGAIN -> Overlay {
                QrScannerScreen(
                    txt.s(SyncWording.FIND_AGAIN), txt.s(QrScanner.SYNC_DENIED_TEXT),
                    onCode = { code -> sheet = null; localError = null; scope.launch { sync.findAgain(code) } },
                    onUnavailable = { sheet = null; localError = txt.s(SyncScreenText.CAMERA_UNAVAILABLE) },
                    onCancel = { sheet = null },
                )
            }
            null -> Unit
        }
        removeRequest?.let { request ->
            Overlay {
                RemoveDeviceSheet(
                    membership, request.lost, request.initial, busy, actionError,
                    onCancel = { removeRequest = null },
                    onRemove = { ids, keep, password -> sync.removeDevices(ids, password, keep) },
                    onClose = { removeRequest = null },
                )
            }
        }
        host?.let { HostPairingOverlay(it, hostSheet) { hostSheet = false } }
        if (upgradeOpen && pro != null) {
            Overlay { UpgradeSheet(pro, null, onClose = { upgradeOpen = false }) }
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

    freshKeyText?.let { text ->
        AlertDialog(
            onDismissRequest = { scope.launch { folderFlow.cancelFreshKey() } },
            title = { Text(txt.s(R.string.sync_new_sync_key)) },
            text = { Text(text) },
            confirmButton = {
                TextButton({ scope.launch { folderFlow.confirmFreshKey() } }) { Text(stringResource(R.string.common_continue), color = c.accentText) }
            },
            dismissButton = {
                TextButton({ scope.launch { folderFlow.cancelFreshKey() } }) { Text(stringResource(R.string.common_cancel), color = c.accentText) }
            },
        )
    }
    needsPro?.let { proText ->
        AlertDialog(
            onDismissRequest = { needsPro = null },
            text = { Text(txt.s(proText)) },
            confirmButton = {
                if (pro != null) {
                    TextButton({ needsPro = null; upgradeOpen = true }) { Text(txt.s(R.string.settings_upgrade), color = c.accentText) }
                }
            },
            dismissButton = { TextButton({ needsPro = null }) { Text(stringResource(R.string.common_cancel), color = c.accentText) } },
        )
    }
    if (confirmDevices) {
        val ids = membership.unconfirmed
        val shown = ids.joinToString(", ") { RemovalText.displayName(it, membership, words) }
        AlertDialog(
            onDismissRequest = { confirmDevices = false },
            title = { Text(txt.s(R.string.sync_confirm_devices)) },
            text = { Text(txt.s(R.string.sync_are_these_your_devices, shown)) },
            confirmButton = {
                TextButton({
                    confirmDevices = false
                    scope.launch { if (sync.confirmMembers(ids)) confirmedText = txt.s(R.string.sync_confirmed_list, shown) }
                }) { Text(txt.s(R.string.sync_these_are_my_devices), color = c.accentText) }
            },
            dismissButton = { TextButton({ confirmDevices = false }) { Text(stringResource(R.string.common_cancel), color = c.accentText) } },
        )
    }
    if (confirm == Confirm.ROLLBACK) {
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text(txt.s(SyncWording.ROLLBACK_CONFIRM_TITLE)) },
            text = { Text(txt.s(SyncWording.ROLLBACK_CONFIRM_TEXT)) },
            confirmButton = {
                TextButton({
                    confirm = null
                    confirmOwner?.let { check -> scope.launch { sync.acknowledgeRollback(check) } }
                }) { Text(txt.s(SyncScreenText.ROLLBACK_KEEP), color = c.danger) }
            },
            dismissButton = { TextButton({ confirm = null }) { Text(stringResource(R.string.common_cancel), color = c.accentText) } },
        )
    }
    confirm?.takeIf { it != Confirm.ROLLBACK }?.let { step ->
        val leave = step == Confirm.LEAVE1 || step == Confirm.LEAVE2
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text(if (leave) txt.s(R.string.sync_leave_title) else txt.s(SyncScreenText.RESET_TITLE)) },
            text = {
                Text(
                    when (step) {
                        Confirm.LEAVE1 -> if (membership.hasFolder) txt.s(SyncWording.LEAVE_TEXT) else txt.s(SyncWording.LEAVE_WIFI_TEXT)
                        Confirm.LEAVE2 -> txt.s(SyncWording.LEAVE_TEXT_2)
                        Confirm.RESET1 -> txt.s(SyncWording.RESET_TEXT_1)
                        Confirm.RESET2 -> txt.s(SyncWording.RESET_TEXT_2)
                        Confirm.ROLLBACK -> txt.s(SyncWording.ROLLBACK_CONFIRM_TEXT)
                    },
                )
            },
            confirmButton = {
                TextButton({
                    when (step) {
                        Confirm.LEAVE1 -> confirm = Confirm.LEAVE2
                        Confirm.RESET1 -> confirm = Confirm.RESET2
                        Confirm.LEAVE2 -> { confirm = null; scope.launch { sync.leave() } }
                        Confirm.RESET2 -> { confirm = null; scope.launch { sync.reset() } }
                        Confirm.ROLLBACK -> confirm = null // its own dialog above
                    }
                }) {
                    Text(
                        when (step) {
                            Confirm.LEAVE1, Confirm.RESET1 -> txt.s(R.string.common_continue)
                            Confirm.LEAVE2 -> txt.s(R.string.sync_leave_title)
                            Confirm.RESET2 -> txt.s(R.string.sync_reset_confirm)
                            Confirm.ROLLBACK -> txt.s(SyncScreenText.ROLLBACK_KEEP)
                        },
                        color = c.danger,
                    )
                }
            },
            dismissButton = { TextButton({ confirm = null }) { Text(stringResource(R.string.common_cancel), color = c.accentText) } },
        )
    }
}

/** "Paste code text": the code text the PC copies, then Join (the iPhone's paste sheet). Never saved anywhere. */
@Composable
private fun PasteCodeSheet(onCancel: () -> Unit, onJoin: (String) -> Unit) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val monitor = LocalActivityMonitor.current
    var code by remember { mutableStateOf("") }
    val codeTextLabel = txt.s(R.string.sync_code_text_description)
    BackHandler(onBack = onCancel)
    Box(Modifier.fillMaxSize().pointerInput(Unit) { awaitPointerEventScope { while (true) awaitPointerEvent() } }.testTag("paste-code")) {
        GlassBackdropHost(Modifier.fillMaxSize()) { AuroraBackground() }
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            Row(Modifier.fillMaxWidth().height(64.dp).padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                TextButton(onCancel) { Text(stringResource(R.string.common_cancel), color = c.accentText) }
                Text(
                    txt.s(R.string.sync_paste_code), color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    textAlign = TextAlign.Center, modifier = Modifier.weight(1f).semantics { heading() },
                )
                Button(
                    { onJoin(code) },
                    enabled = code.isNotEmpty(),
                    colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
                    modifier = Modifier.padding(end = 4.dp),
                ) { Text(stringResource(R.string.sync_join), fontWeight = FontWeight.SemiBold) }
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
                        modifier = Modifier.fillMaxWidth().testTag("paste-field").semantics { contentDescription = codeTextLabel },
                        decorationBox = { inner ->
                            Box {
                                if (code.isEmpty()) Text(SyncScreenText.PASTE_PLACEHOLDER, color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
                                inner()
                            }
                        },
                    )
                }
                Text(
                    txt.s(SyncScreenText.PASTE_FOOTER), color = c.secondaryText, style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(horizontal = 4.dp),
                )
            }
        }
    }
}

@Composable
internal fun Card(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier.fillMaxWidth().lgkGroupSurface().padding(horizontal = 16.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
        content = content,
    )
}

@Composable
internal fun Section(title: String, modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(modifier.fillMaxWidth()) {
        Text(
            title, color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(start = 4.dp, bottom = 6.dp).semantics { heading() },
        )
        Card(content = content)
    }
}

@Composable
internal fun Footnote(text: String) {
    Text(text, color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.bodySmall)
}

/** A button drawn as a list row (the iPhone's List button): full width, a hairline above unless [divider] is false. */
@Composable
internal fun ActionButton(
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
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val (icon, tint) = when (issue.severity) {
        SyncWording.Severity.ERROR -> Icons.Outlined.Cancel to c.danger
        SyncWording.Severity.WARNING -> Icons.Outlined.Warning to c.warning
        SyncWording.Severity.NOTICE -> Icons.Outlined.Info to c.secondaryText
    }
    if (issue.kind == "vault-rollback") {
        Text(
            txt.s(SyncWording.ROLLBACK_TITLE), color = tint, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold,
            modifier = Modifier.testTag("sync-rollback-title").semantics { heading() },
        )
    }
    Row(verticalAlignment = Alignment.Top) {
        Icon(icon, null, tint = tint, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(10.dp))
        Text(issue.text, color = c.text, style = MaterialTheme.typography.bodyMedium)
    }
}
