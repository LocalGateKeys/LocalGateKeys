package app.localgatekeys.android.ui.sync

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.R
import app.localgatekeys.android.backup.BackupPasswordCheck
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncWording
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.unlock.LocalActivityMonitor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** "I lost a device": the checklist's strings, in the order the desktop shows them. */
private val LOST_CHECKLIST = intArrayOf(
    R.string.sync_lost_checklist_passwords,
    R.string.sync_lost_checklist_encrypted,
    R.string.sync_lost_checklist_erase_folder,
    R.string.sync_lost_checklist_erase_wifi,
    R.string.sync_lost_checklist_cloud_sign_out,
    R.string.sync_lost_checklist_find_device,
)

/**
 * "Remove a device" ([lost] false: any number of the other members, [initial] preselected) or "I lost a device"
 * ([lost] true: one member, the checklist first). Both ask for a NEW sync password twice (the desktop rule, checked with
 * [BackupPasswordCheck]) and name who keeps the new key. [onRemove] runs the removal and answers whether it worked; the
 * sheet then closes through [onClose]. A refusal stays in [error] (the coordinator's `actionError`). The passwords live
 * in this composable only and are gone with it. [busy]: a sync action is running.
 */
@Composable
fun RemoveDeviceSheet(
    membership: SyncCoordinator.Membership,
    lost: Boolean,
    initial: String?,
    busy: Boolean,
    error: String?,
    onCancel: () -> Unit,
    onRemove: suspend (List<String>, List<String>, String) -> Boolean,
    onClose: () -> Unit,
) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val words = remember(txt) { SyncWording(txt) }
    val scope = rememberCoroutineScope()
    var selected by remember { mutableStateOf(setOfNotNull(initial)) }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var problem by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }
    val name: (String) -> String = { RemovalText.displayName(it, membership, words) }
    val chosen = membership.members.filter { it in selected } // list order, stable
    val title = when {
        lost -> txt.s(R.string.sync_lost_title)
        chosen.size > 1 -> txt.s(R.string.sync_remove_devices_title)
        else -> txt.s(R.string.sync_remove_title)
    }
    val canRemove = chosen.isNotEmpty() && password.isNotEmpty() && confirm.isNotEmpty() && !busy && !working
    val remove: () -> Unit = {
        if (canRemove) {
            scope.launch {
                working = true
                try {
                    // The strength estimate can take a moment: never on Main.
                    val bad = withContext(Dispatchers.Default) { BackupPasswordCheck.problem(password, confirm, txt) }
                    problem = bad
                    if (bad == null && onRemove(chosen, RemovalText.keeperIds(membership.members, chosen.toSet(), membership.unconfirmed.toSet()), password)) {
                        password = ""
                        confirm = ""
                        onClose()
                    }
                } finally {
                    working = false
                }
            }
        }
    }
    BackHandler(onBack = { if (!working) onCancel() })
    Box(Modifier.fillMaxSize().pointerInput(Unit) { awaitPointerEventScope { while (true) awaitPointerEvent() } }.testTag("remove-device")) {
        GlassBackdropHost(Modifier.fillMaxSize()) { AuroraBackground() }
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            Row(Modifier.fillMaxWidth().height(64.dp).padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                TextButton(onCancel, enabled = !working) { Text(txt.s(R.string.common_cancel), color = c.accentText) }
                Text(
                    title, color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    textAlign = TextAlign.Center, modifier = Modifier.weight(1f).semantics { heading() },
                )
                Button(
                    remove,
                    enabled = canRemove,
                    colors = ButtonDefaults.buttonColors(containerColor = c.danger, contentColor = Color.White),
                    modifier = Modifier.padding(end = 4.dp).testTag("remove-device-confirm"),
                ) { Text(if (working) txt.s(R.string.sync_removing) else txt.s(R.string.sync_remove_button), fontWeight = FontWeight.SemiBold) }
            }
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).navigationBarsPadding().imePadding().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (lost) Body(txt.s(R.string.sync_lost_intro_folder))
                Column(Modifier.fillMaxWidth().lgkGroupSurface().padding(horizontal = 16.dp, vertical = 4.dp)) {
                    for (id in membership.members) {
                        val on = id in selected
                        Row(
                            Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = if (lost) Role.RadioButton else Role.Checkbox) {
                                selected = if (lost) setOf(id) else if (on) selected - id else selected + id
                            }.testTag("remove-device-$id"),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            if (lost) RadioButton(on, onClick = null) else Checkbox(on, onCheckedChange = null)
                            Column(Modifier.weight(1f).padding(start = 12.dp)) {
                                Text(name(id), color = c.text, style = MaterialTheme.typography.bodyLarge)
                                if (id in membership.unconfirmed) {
                                    Text(txt.s(R.string.sync_unconfirmed_detail), color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    }
                }
                if (lost) {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        for (id in LOST_CHECKLIST) {
                            Row {
                                Text("•", color = c.secondaryText, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(end = 8.dp))
                                Text(txt.s(id), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                            }
                        }
                    }
                } else if (chosen.isNotEmpty()) {
                    Body(
                        if (chosen.size == 1) txt.s(R.string.sync_remove_device_text, name(chosen[0]))
                        else txt.s(R.string.sync_remove_list_text, chosen.joinToString(", ") { name(it) }),
                    )
                }
                Body(txt.s(R.string.sync_remove_needs_password), strong = true)
                Body(txt.s(R.string.sync_enter_new_sync_password))
                Column(Modifier.fillMaxWidth().lgkGroupSurface().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    SecretField(password, { password = it; problem = null }, txt.s(R.string.folder_sync_password), "remove-device-password", ImeAction.Next)
                    SecretField(confirm, { confirm = it; problem = null }, txt.s(R.string.backup_confirm), "remove-device-confirm-field", ImeAction.Done)
                }
                if (chosen.isNotEmpty()) {
                    Body(
                        RemovalText.keepText(
                            membership.members, chosen.toSet(), membership.unconfirmed.toSet(), txt.s(R.string.sync_this_device), txt, name,
                        ),
                    )
                }
                (problem ?: error)?.let {
                    Text(it, color = c.danger, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("remove-device-error"))
                }
            }
        }
    }
}

@Composable
private fun Body(text: String, strong: Boolean = false) {
    Text(
        text, color = LgkTheme.colors.text, style = MaterialTheme.typography.bodyMedium,
        fontWeight = if (strong) FontWeight.SemiBold else null, modifier = Modifier.padding(horizontal = 4.dp),
    )
}

/** A masked password field like the folder join sheet's: password keyboard, no suggestions, no autocorrect. */
@Composable
private fun SecretField(value: String, onChange: (String) -> Unit, label: String, tag: String, ime: ImeAction) {
    val c = LgkTheme.colors
    val monitor = LocalActivityMonitor.current
    BasicTextField(
        value = value,
        onValueChange = { monitor?.textChanged(); onChange(it) },
        textStyle = MaterialTheme.typography.bodyLarge.copy(color = c.text),
        cursorBrush = SolidColor(c.accent),
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = KeyboardType.Password, imeAction = ime),
        modifier = Modifier.fillMaxWidth().heightIn(min = 32.dp).testTag(tag).semantics { contentDescription = label },
        decorationBox = { inner ->
            Box {
                if (value.isEmpty()) Text(label, color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
                inner()
            }
        },
    )
}
