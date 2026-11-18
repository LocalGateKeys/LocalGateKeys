package app.localgatekeys.android.ui.collections

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.R
import app.localgatekeys.android.collections.CollectionShareModel
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncWording
import app.localgatekeys.android.ui.settings.Page
import app.localgatekeys.android.ui.settings.RowButton
import app.localgatekeys.android.ui.settings.Section
import app.localgatekeys.android.ui.settings.Toggle
import app.localgatekeys.android.ui.sync.FolderPick
import app.localgatekeys.android.ui.sync.FolderPicking
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.unlock.LocalActivityMonitor
import app.localgatekeys.core.sync.CollectionShares
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * What the share sheet needs from the app (sub-plan 07 Task 5m): this unlock's coordinator, its own folder picker (the
 * system picker, separate from the Sync tab's), a stored folder's display name, the device-owner check before a share
 * (fingerprint, face or screen lock) and the upgrade sheet.
 */
class CollectionShareSeams(
    val sync: SyncCoordinator,
    val picker: FolderPicking?,
    val folderName: (String) -> String?,
    val confirmOwner: suspend () -> Boolean,
    val onUpgrade: () -> Unit,
) {
    override fun toString(): String = "CollectionShareSeams"
}

/**
 * Share a collection, or join a shared one (the iPhone's `CollectionShareSheet`, desktop `CollectionShare.svelte`). With a
 * collection: Share (folder, your name, the password twice, "Members can edit"), or once shared its status (with Join
 * again), the mode, People (Remove with a new password twice), Waiting for approval (Let them in, by name), Removed and
 * Leave / Stop sharing. Without one ([collectionId] null): Join a shared collection (folder and password); after the join
 * it shows that collection. The free plan gets the upgrade sheet for Share and Join. Password fields are emptied by every
 * action and on close. [onChange] runs after every change (the lists reload).
 */
@Composable
fun CollectionShareSheet(collectionId: String?, seams: CollectionShareSeams, onChange: () -> Unit, onClose: () -> Unit) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val scope = rememberCoroutineScope()
    val model = remember(collectionId) {
        CollectionShareModel(collectionId, seams.sync, txt, seams.folderName, seams.confirmOwner)
    }
    val state by model.state.collectAsStateWithLifecycle()
    val fields by model.fields.collectAsStateWithLifecycle()
    var removing by remember { mutableStateOf<CollectionShareModel.Member?>(null) }
    var confirmingApprove by remember { mutableStateOf(false) }
    var confirmingLeave by remember { mutableStateOf(false) }
    var confirmingForget by remember { mutableStateOf(false) }
    BackHandler(onBack = onClose)
    LaunchedEffect(model) { withContext(Dispatchers.IO) { model.reload() } }
    DisposableEffect(model) { onDispose { model.clearPasswords() } }
    // A shared folder chosen in the system picker (its permission persisted) goes to the model.
    LaunchedEffect(seams.picker) {
        seams.picker?.results?.collect { pick ->
            when (pick) {
                is FolderPick.Picked -> {
                    val name = withContext(Dispatchers.IO) { seams.folderName(pick.uri) }
                    model.pick(pick.uri, name ?: txt.s(R.string.collection_share_folder))
                }
                FolderPick.Cancelled -> {}
                else -> model.pickFailed()
            }
        }
    }
    LaunchedEffect(state.showUpgrade) {
        if (state.showUpgrade) {
            model.dismissUpgrade()
            seams.onUpgrade()
        }
    }

    fun act(action: suspend () -> Boolean) {
        scope.launch { if (action()) onChange() }
    }

    val summary = state.summary
    val title = summary?.let { txt.s(R.string.collection_share_share_title, it.collectionName) } ?: txt.s(R.string.collection_share_join_title)
    Page(title, "collection-share", onBack = onClose, doneLabel = txt.s(R.string.common_done)) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).imePadding().padding(start = 16.dp, end = 16.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            if (state.collectionId == null) {
                JoinSections(model, state, fields, seams.picker, busy = state.busy) { act { model.join() } }
            } else if (summary != null) {
                StatusSection(summary, fields.password, state.busy, { model.password = it }) { act { model.rejoin() } }
                if (summary.shared) {
                    if (summary.canUpgrade) UpgradeSection(model, fields, busy = state.busy) { act { model.upgrade() } }
                    SharedSections(
                        model, summary, state, busy = state.busy,
                        onRemove = { m -> model.clearPasswords(); model.dismissMessages(); removing = m },
                        onLetIn = { confirmingApprove = true }, onLeave = { confirmingLeave = true },
                    )
                } else if (summary.linked != null) {
                    LinkedSection(summary.linked, busy = state.busy) { confirmingForget = true }
                } else {
                    ShareSections(model, state, fields, seams.picker, busy = state.busy) { act { model.share() } }
                }
            }
            state.message?.let { Text(it, color = c.text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("collection-share-message")) }
            state.error?.let { Text(it, color = c.danger, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("collection-share-error")) }
        }
    }
    if (confirmingApprove) {
        AlertDialog(
            onDismissRequest = { confirmingApprove = false },
            confirmButton = {
                TextButton({ confirmingApprove = false; act { model.approve() } }, Modifier.testTag("collection-share-confirm-approve")) {
                    Text(txt.s(R.string.collection_share_let_in))
                }
            },
            dismissButton = { TextButton({ confirmingApprove = false }) { Text(txt.s(R.string.common_cancel)) } },
            title = { Text(txt.s(R.string.collection_share_approve_title)) },
            text = { Text(txt.s(R.string.collection_share_approve_text, summary?.collectionName ?: "", model.approvalNames ?: "")) },
        )
    }
    if (confirmingLeave && summary != null) {
        val name = SyncWording(txt).sanitize(summary.collectionName)
        AlertDialog(
            onDismissRequest = { confirmingLeave = false },
            confirmButton = {
                TextButton({ confirmingLeave = false; act { model.leave() } }, Modifier.testTag("collection-share-confirm-leave")) {
                    Text(txt.s(if (summary.isOwner) R.string.collection_share_stop_sharing else R.string.collection_share_leave), color = c.danger)
                }
            },
            dismissButton = { TextButton({ confirmingLeave = false }) { Text(txt.s(R.string.common_cancel)) } },
            title = { Text(txt.s(if (summary.isOwner) R.string.collection_share_stop_title else R.string.collection_share_leave_title)) },
            text = { Text(txt.s(if (summary.isOwner) R.string.collection_share_stop_text else R.string.collection_share_leave_text, name)) },
        )
    }
    if (confirmingForget && summary != null) {
        val name = SyncWording(txt).sanitize(summary.collectionName)
        AlertDialog(
            onDismissRequest = { confirmingForget = false },
            confirmButton = {
                TextButton({ confirmingForget = false; act { model.forgetLink() } }, Modifier.testTag("collection-share-confirm-forget")) {
                    Text(txt.s(R.string.collection_share_forget_link), color = c.danger)
                }
            },
            dismissButton = { TextButton({ confirmingForget = false }) { Text(txt.s(R.string.common_cancel)) } },
            title = { Text(txt.s(R.string.collection_share_forget_link_title)) },
            text = { Text(txt.s(R.string.collection_share_forget_link_text, name)) },
        )
    }
    removing?.let { member ->
        RemoveMemberPage(model, member, summary?.collectionName ?: "", state, onClose = { model.clearPasswords(); removing = null }) {
            scope.launch {
                if (model.remove(member.id)) {
                    removing = null
                    onChange()
                }
            }
        }
    }
}

@Composable
private fun JoinSections(
    model: CollectionShareModel,
    state: CollectionShareModel.State,
    fields: CollectionShareModel.Fields,
    picker: FolderPicking?,
    busy: Boolean,
    onJoin: () -> Unit,
) {
    val txt = rememberTxt()
    Section(null, footer = txt.s(R.string.collection_share_join_intro), tag = "collection-join") {
        FolderRow(state.picked?.name, picker, busy)
        NameField(fields.name) { model.name = it }
        SecretField(txt.s(R.string.collection_share_password), fields.password, "collection-share-password") { model.password = it }
    }
    Section(null) {
        RowButton(
            txt.s(R.string.collection_share_join_button), "collection-join-button",
            enabled = !busy && state.picked != null && fields.password.isNotEmpty(), divider = false, onClick = onJoin,
        )
    }
}

@Composable
private fun ShareSections(
    model: CollectionShareModel,
    state: CollectionShareModel.State,
    fields: CollectionShareModel.Fields,
    picker: FolderPicking?,
    busy: Boolean,
    onShare: () -> Unit,
) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    Text(txt.s(R.string.collection_share_intro), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium)
    Section(null, footer = txt.s(R.string.collection_share_mode_fixed), tag = "collection-share-form") {
        FolderRow(state.picked?.name, picker, busy)
        NameField(fields.name) { model.name = it }
        SecretField(txt.s(R.string.collection_share_password), fields.password, "collection-share-password") { model.password = it }
        SecretField(txt.s(R.string.collection_share_confirm_password), fields.passwordAgain, "collection-share-password-again") { model.passwordAgain = it }
        Toggle(txt.s(R.string.collection_share_can_edit), fields.membersCanEdit, enabled = !busy, tag = "collection-share-can-edit") {
            model.membersCanEdit = it
        }
    }
    Section(null, footer = helpText()) {
        RowButton(
            txt.s(R.string.collection_share_share_button), "collection-share-button",
            enabled = !busy && state.picked != null && fields.password.isNotEmpty() && fields.passwordAgain.isNotEmpty(),
            divider = false, onClick = onShare,
        )
    }
}

@Composable
private fun SharedSections(
    model: CollectionShareModel,
    summary: CollectionShareModel.Summary,
    state: CollectionShareModel.State,
    busy: Boolean,
    onRemove: (CollectionShareModel.Member) -> Unit,
    onLetIn: () -> Unit,
    onLeave: () -> Unit,
) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    if (summary.sharedTwice) {
        // Shared from two of this person's devices (re-review wave B, B1): one share should be stopped or left.
        Section(null, tag = "collection-share-twice") {
            Text(
                txt.s(R.string.collection_share_shared_twice), color = c.danger, style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(vertical = 12.dp),
            )
        }
    }
    Section(null, footer = txt.s(R.string.collection_share_mode_fixed), tag = "collection-share-mode") {
        Text(summary.modeText ?: "", color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(vertical = 12.dp))
        if (summary.folder.isNotEmpty()) {
            HorizontalDivider(thickness = 0.5.dp, color = c.separator)
            Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(txt.s(R.string.collection_share_folder), color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                Text(summary.folder, color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
            }
        }
    }
    Section(txt.s(R.string.collection_share_people), tag = "collection-share-people") {
        summary.members.forEachIndexed { i, member ->
            if (i > 0) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
            Row(Modifier.fillMaxWidth().heightIn(min = 56.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f).padding(vertical = 8.dp)) {
                    val shown = if (member.isSelf) "${member.name} (${txt.s(R.string.collection_share_you)})" else member.name
                    Text(shown, color = c.text, style = MaterialTheme.typography.bodyLarge)
                    Text(member.stateText, color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
                }
                if (member.removable) {
                    TextButton({ onRemove(member) }, enabled = !busy, modifier = Modifier.testTag("collection-share-remove")) {
                        Text(txt.s(R.string.collection_share_remove), color = c.danger)
                    }
                }
            }
        }
    }
    if (summary.pending.isNotEmpty()) {
        Section(txt.s(R.string.collection_share_waiting), footer = txt.s(R.string.collection_share_waiting_hint), tag = "collection-share-waiting") {
            summary.pending.forEachIndexed { i, member ->
                if (i > 0) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
                val ticked = member.id in state.selectedPending
                Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(member.name, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                    Checkbox(ticked, onCheckedChange = { on ->
                        model.selectedPending = if (on) model.selectedPending + member.id else model.selectedPending - member.id
                    }, enabled = !busy)
                }
            }
            RowButton(txt.s(R.string.collection_share_let_in), "collection-share-let-in", enabled = !busy && model.approvalNames != null, onClick = onLetIn)
        }
    }
    if (summary.removed.isNotEmpty()) {
        val format = remember { DateFormat.getDateInstance(DateFormat.MEDIUM) }
        Section(txt.s(R.string.collection_share_removed_heading), tag = "collection-share-removed") {
            summary.removed.forEachIndexed { i, r ->
                if (i > 0) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
                Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(r.name, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                    Text(format.format(Date(r.at * 1000)), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
    Section(null, footer = helpText()) {
        RowButton(
            txt.s(if (summary.isOwner) R.string.collection_share_stop_sharing else R.string.collection_share_leave), "collection-share-leave",
            enabled = !busy, destructive = true, divider = false, onClick = onLeave,
        )
    }
}

/**
 * Shared by another of this person's devices (a received share link): which role it has, and Forget share link for a
 * device that was lost or reset (final review finding 4; the sheet asks first).
 */
@Composable
private fun LinkedSection(link: CollectionShares.Link, busy: Boolean, onForget: () -> Unit) {
    val txt = rememberTxt()
    val linkedHelp = listOf(
        txt.s(if (link.role == "owner") R.string.collection_share_linked_owner else R.string.collection_share_linked_member),
        txt.s(R.string.collection_share_forget_link_hint),
    ).joinToString(PARAGRAPH_BREAK)
    Section(null, footer = linkedHelp, tag = "collection-share-linked") {
        RowButton(
            txt.s(R.string.collection_share_forget_link), "collection-share-forget-link",
            enabled = !busy, destructive = true, divider = false, onClick = onForget,
        )
    }
}

/**
 * The owner of a share v1 group (desktop `view` `upgrade`): the upgrade to share v2, where only approved devices open
 * the items, with the share password typed twice (the current one or a new one).
 */
@Composable
private fun UpgradeSection(model: CollectionShareModel, fields: CollectionShareModel.Fields, busy: Boolean, onUpgrade: () -> Unit) {
    val txt = rememberTxt()
    Section(txt.s(R.string.collection_share_upgrade_title), footer = txt.s(R.string.collection_share_upgrade_text), tag = "collection-share-upgrade") {
        SecretField(txt.s(R.string.collection_share_password), fields.password, "collection-share-upgrade-password") { model.password = it }
        SecretField(txt.s(R.string.collection_share_confirm_password), fields.passwordAgain, "collection-share-upgrade-password-again") {
            model.passwordAgain = it
        }
        RowButton(
            txt.s(R.string.collection_share_upgrade_button), "collection-share-upgrade-button",
            enabled = !busy && fields.password.isNotEmpty() && fields.passwordAgain.isNotEmpty(), divider = false, onClick = onUpgrade,
        )
    }
}

/** The last share run's status; Join again (with the share password) after a lost join. */
@Composable
private fun StatusSection(
    summary: CollectionShareModel.Summary,
    password: String,
    busy: Boolean,
    onPassword: (String) -> Unit,
    onJoinAgain: () -> Unit,
) {
    val status = summary.status ?: return
    val txt = rememberTxt()
    val c = LgkTheme.colors
    Section(null, tag = "collection-share-status") {
        Row(Modifier.fillMaxWidth().padding(vertical = 12.dp).semantics(mergeDescendants = true) {}, verticalAlignment = Alignment.Top) {
            Icon(
                if (status.severity == SyncWording.Severity.NOTICE) Icons.Filled.Info else Icons.Filled.Warning, null, Modifier.size(20.dp),
                tint = when (status.severity) {
                    SyncWording.Severity.ERROR -> c.danger
                    SyncWording.Severity.WARNING -> c.warning
                    SyncWording.Severity.NOTICE -> c.accentText
                },
            )
            Spacer(Modifier.width(10.dp))
            Text(status.text, color = c.text, style = MaterialTheme.typography.bodyMedium)
        }
        if (status.joinAgain) {
            SecretField(txt.s(R.string.collection_share_password), password, "collection-share-rejoin-password", onPassword)
            RowButton(SyncWording(txt).joinAgainAction, "collection-share-join-again", enabled = !busy && password.isNotEmpty(), onClick = onJoinAgain)
        }
    }
}

@Composable
private fun FolderRow(name: String?, picker: FolderPicking?, busy: Boolean) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(
            name ?: txt.s(R.string.collection_share_no_folder), color = if (name == null) c.secondaryText else c.text,
            style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f).testTag("collection-share-folder"),
        )
        if (picker != null) {
            TextButton({ picker.pick() }, enabled = !busy, modifier = Modifier.testTag("collection-share-choose-folder")) {
                Text(txt.s(R.string.collection_share_choose_folder_button), color = c.accentText)
            }
        }
    }
}

@Composable
private fun NameField(value: String, onChange: (String) -> Unit) {
    val txt = rememberTxt()
    val monitor = LocalActivityMonitor.current
    OutlinedTextField(
        value, { monitor?.textChanged(); onChange(it) }, singleLine = true,
        label = { Text(txt.s(R.string.collection_share_your_name)) },
        placeholder = { Text(txt.s(R.string.collection_share_name_placeholder)) },
        keyboardOptions = KeyboardOptions(KeyboardCapitalization.Words, autoCorrectEnabled = false),
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp).testTag("collection-share-name"),
    )
}

/** A masked password field: password keyboard, no suggestions; the text lives only in the model's memory. */
@Composable
private fun SecretField(label: String, value: String, tag: String, onChange: (String) -> Unit) {
    val monitor = LocalActivityMonitor.current
    OutlinedTextField(
        value, { monitor?.textChanged(); onChange(it) }, singleLine = true,
        label = { Text(label) },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = KeyboardType.Password),
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp).testTag(tag),
    )
}

/** Between two paragraphs of a section footer (not shown text). */
private const val PARAGRAPH_BREAK = "\n\n"

@Composable
private fun helpText(): String {
    val txt = rememberTxt()
    return txt.s(R.string.collection_share_help) + "\n\n" + txt.s(R.string.collection_share_owner_loss)
}

/** Remove a member: the hint, the new share password twice, then a confirmation that names them. */
@Composable
private fun RemoveMemberPage(
    model: CollectionShareModel,
    member: CollectionShareModel.Member,
    collectionName: String,
    state: CollectionShareModel.State,
    onClose: () -> Unit,
    onRemove: () -> Unit,
) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val fields by model.fields.collectAsStateWithLifecycle()
    var confirming by remember { mutableStateOf(false) }
    BackHandler(onBack = onClose)
    Page(txt.s(R.string.collection_share_remove_button, member.name), "collection-share-remove-page", onBack = onClose, doneLabel = txt.s(R.string.common_cancel)) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).imePadding().padding(start = 16.dp, end = 16.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            Text(txt.s(R.string.collection_share_remove_hint, member.name), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium)
            Section(null) {
                SecretField(txt.s(R.string.collection_share_new_password), fields.newPassword, "collection-share-new-password") { model.newPassword = it }
                SecretField(txt.s(R.string.collection_share_new_password_again), fields.newPasswordAgain, "collection-share-new-password-again") {
                    model.newPasswordAgain = it
                }
            }
            Section(null) {
                RowButton(
                    txt.s(R.string.collection_share_remove_button, member.name), "collection-share-remove-button",
                    enabled = !state.busy && fields.newPassword.isNotEmpty() && fields.newPasswordAgain.isNotEmpty(),
                    destructive = true, divider = false,
                ) { confirming = true }
            }
            // A refusal (weak or reused password, busy...) keeps this page open and says why here.
            state.error?.let { Text(it, color = c.danger, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("collection-share-remove-error")) }
        }
    }
    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            confirmButton = {
                TextButton({ confirming = false; onRemove() }, Modifier.testTag("collection-share-confirm-remove")) {
                    Text(txt.s(R.string.collection_share_remove), color = c.danger)
                }
            },
            dismissButton = { TextButton({ confirming = false }) { Text(txt.s(R.string.common_cancel)) } },
            title = { Text(txt.s(R.string.collection_share_remove_title, member.name)) },
            text = { Text(txt.s(R.string.collection_share_remove_text, member.name, SyncWording(txt).sanitize(collectionName))) },
        )
    }
}
