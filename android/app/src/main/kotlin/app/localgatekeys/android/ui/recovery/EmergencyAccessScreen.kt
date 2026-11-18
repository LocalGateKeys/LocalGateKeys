package app.localgatekeys.android.ui.recovery

import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.recovery.EmergencyAccess
import app.localgatekeys.android.ui.settings.Page
import app.localgatekeys.android.ui.settings.RowButton
import app.localgatekeys.android.ui.settings.Section
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.core.recovery.HeirPlan
import app.localgatekeys.core.recovery.HeirRequest
import app.localgatekeys.core.recovery.HeirStatus
import app.localgatekeys.core.recovery.Shard
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * What the emergency access page needs from the app: this unlock's [EmergencyAccess], the owner check before a grant,
 * the folder permission to keep, the bytes of a picked shard file, and the lock's allowance for the system picker.
 */
class EmergencySeams(
    val model: () -> EmergencyAccess?,
    val confirmOwner: suspend (String) -> Boolean,
    /** Keeps the picked tree's permission; returns the URI string to store (throws when it cannot be kept). */
    val persistFolder: (Uri) -> String,
    val readFile: suspend (Uri) -> ByteArray?,
    val willOpenSystemScreen: () -> Unit,
    /** True when the vault is still unlocked after the system screen. */
    val systemScreenClosed: () -> Boolean,
    /** Creates the estate pack note with this body (sub-plan 12); true when saved. Null: no entry shown. */
    val createEstate: (suspend (String) -> Boolean)? = null,
) {
    override fun toString(): String = "EmergencySeams"
}

/** Settings > Emergency access (sub-plan 08): the owner's plan by sync (deny, grant now) and the shards given to you. */
@Composable
fun EmergencyAccessPage(seams: EmergencySeams, onBack: () -> Unit) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    val scope = rememberCoroutineScope()
    val model = remember { seams.model() }
    var reload by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var plan by remember { mutableStateOf<HeirPlan?>(null) }
    var requests by remember { mutableStateOf<List<HeirRequest>>(emptyList()) }
    var shards by remember { mutableStateOf<List<Shard>>(emptyList()) }
    var folder by remember { mutableStateOf<String?>(null) }
    var reachable by remember { mutableStateOf(true) }
    var status by remember { mutableStateOf<HeirStatus?>(null) }
    var grantFor by remember { mutableStateOf<HeirRequest?>(null) }
    var phrase by remember { mutableStateOf<String?>(null) }
    var pasted by remember { mutableStateOf("") }
    BackHandler { onBack() }

    fun act(block: suspend () -> String?) {
        if (busy) return
        busy = true
        scope.launch {
            message = try {
                withContext(Dispatchers.IO) { block() }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                EmergencyAccess.message(e, txt)
            }
            busy = false
            reload++
        }
    }

    LaunchedEffect(reload) {
        val m = model ?: return@LaunchedEffect
        withContext(Dispatchers.IO) {
            folder = m.folderUri()
            reachable = m.folderReachable()
            plan = try { m.plan() } catch (e: Exception) { null }
            requests = if (plan != null && folder != null) try { m.pending().requests } catch (e: Exception) { emptyList() } else emptyList()
            shards = m.shards()
            status = if (shards.isNotEmpty() && folder != null) try { m.status() } catch (e: Exception) { null } else null
        }
    }

    val folderLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        val still = seams.systemScreenClosed()
        if (uri == null || !still) return@rememberLauncherForActivityResult
        act {
            val kept = seams.persistFolder(uri)
            model?.setFolder(kept)
            null
        }
    }
    val fileLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val still = seams.systemScreenClosed()
        if (uri == null || !still) return@rememberLauncherForActivityResult
        act {
            val bytes = seams.readFile(uri) ?: return@act txt.s(R.string.heir_no_file_chosen)
            val shard = model?.addPackage(bytes) ?: return@act null
            txt.s(R.string.heir_shard_added, shard.holder)
        }
    }

    Page(stringResource(R.string.heir_title), "emergency-access", onBack = onBack, doneLabel = stringResource(R.string.common_done)) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).imePadding().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            if (busy) CircularProgressIndicator()
            message?.let { Text(it, color = c.text, modifier = Modifier.testTag("emergency-message")) }
            Section(stringResource(R.string.heir_folder), tag = "emergency-folder") {
                Text(
                    stringResource(if (folder != null) R.string.heir_folder_set else R.string.heir_no_folder),
                    color = c.secondaryText, modifier = Modifier.padding(vertical = 8.dp).testTag("emergency-folder-state"),
                )
                RowButton(stringResource(R.string.heir_choose_folder), "emergency-choose-folder") {
                    seams.willOpenSystemScreen()
                    try {
                        folderLauncher.launch(null)
                    } catch (e: Exception) {
                        seams.systemScreenClosed()
                        message = txt.s(R.string.heir_no_folder_chosen)
                    }
                }
            }
            OwnerSection(txt, plan, requests, folder != null, folder != null && !reachable, onDeny = { r ->
                act {
                    model?.deny(r.requestId)
                    txt.s(R.string.heir_denied_msg, r.holder)
                }
            }, onGrant = { grantFor = it })
            seams.createEstate?.let { create ->
                Section(stringResource(R.string.estate_pack), footer = stringResource(R.string.estate_pack_hint), tag = "emergency-estate") {
                    RowButton(stringResource(R.string.estate_pack), "emergency-estate-create") {
                        val holders = plan?.holders ?: emptyList()
                        act {
                            val ok = create(app.localgatekeys.android.recovery.EstatePack.body(holders, txt))
                            txt.s(if (ok) R.string.estate_pack_created else R.string.estate_pack_failed)
                        }
                    }
                }
            }
            Section(stringResource(R.string.heir_receive), footer = stringResource(R.string.heir_receive_meta), tag = "emergency-receive") {
                if (shards.isEmpty()) {
                    Text(stringResource(R.string.heir_no_shards), color = c.secondaryText, modifier = Modifier.padding(vertical = 8.dp))
                } else {
                    Text(txt.s(R.string.heir_plan_of, shards[0].owner, shards[0].k), color = c.text, modifier = Modifier.padding(top = 8.dp))
                    for (s in shards) Text(txt.s(R.string.heir_shard_line, s.index, s.holder), color = c.secondaryText)
                }
                RowButton(stringResource(R.string.heir_add_file), "emergency-add-file") {
                    seams.willOpenSystemScreen()
                    try {
                        fileLauncher.launch(arrayOf("*/*"))
                    } catch (e: Exception) {
                        seams.systemScreenClosed()
                        message = txt.s(R.string.heir_no_file_chosen)
                    }
                }
                OutlinedTextField(
                    pasted, { pasted = it }, label = { Text(stringResource(R.string.heir_paste)) }, singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("emergency-paste"),
                )
                RowButton(stringResource(R.string.heir_add_text), "emergency-add-text", enabled = pasted.isNotBlank()) {
                    val text = pasted
                    act {
                        val shard = model?.addText(text) ?: return@act null
                        pasted = ""
                        txt.s(R.string.heir_shard_added, shard.holder)
                    }
                }
                if (shards.isNotEmpty()) {
                    status?.let { Text(EmergencyAccess.statusText(it, txt), color = c.text, modifier = Modifier.padding(vertical = 8.dp).testTag("emergency-status")) }
                    RowButton(stringResource(R.string.heir_request), "emergency-request", enabled = folder != null) {
                        act {
                            model?.request()
                            txt.s(R.string.heir_request_sent, shards[0].waitDays)
                        }
                    }
                    RowButton(stringResource(R.string.heir_refresh), "emergency-refresh") { reload++ }
                    if (status?.state == "ready") {
                        RowButton(stringResource(R.string.heir_show_phrase), "emergency-show-phrase") {
                            scope.launch {
                                // The most sensitive screen here: the screen lock first, as other secrets are revealed.
                                if (!seams.confirmOwner(txt.s(R.string.heir_show_phrase))) return@launch
                                act {
                                    phrase = model?.recoverPhrase()
                                    null
                                }
                            }
                        }
                    }
                    RowButton(stringResource(R.string.heir_clear), "emergency-clear", destructive = true) {
                        act {
                            model?.clearShards()
                            null
                        }
                    }
                }
            }
        }
    }
    grantFor?.let { r -> GrantDialog(r, onDismiss = { grantFor = null }) { typed ->
        grantFor = null
        scope.launch {
            if (!seams.confirmOwner(txt.s(R.string.heir_grant_title))) return@launch
            act {
                model?.grant(r.requestId, typed)
                txt.s(R.string.heir_granted_msg, r.holder)
            }
        }
    } }
    phrase?.let { words ->
        AlertDialog(
            onDismissRequest = { phrase = null },
            title = { Text(stringResource(R.string.heir_phrase_title)) },
            text = {
                Text(
                    words.split(" ").mapIndexed { i, w -> "${i + 1}. $w" }.chunked(3).joinToString("\n") { it.joinToString("    ") },
                    fontFamily = FontFamily.Monospace, modifier = Modifier.testTag("emergency-phrase"),
                )
            },
            confirmButton = { TextButton({ phrase = null }) { Text(stringResource(R.string.common_done), color = c.accentText) } },
        )
    }
}

@Composable
private fun OwnerSection(
    txt: Txt,
    plan: HeirPlan?,
    requests: List<HeirRequest>,
    hasFolder: Boolean,
    unreachable: Boolean,
    onDeny: (HeirRequest) -> Unit,
    onGrant: (HeirRequest) -> Unit,
) {
    val c = LgkTheme.colors
    Section(stringResource(R.string.heir_plan_section), footer = if (plan != null) stringResource(R.string.heir_collusion) else null, tag = "emergency-owner") {
        if (plan == null) {
            Text(stringResource(R.string.heir_no_plan), color = c.secondaryText, modifier = Modifier.padding(vertical = 8.dp))
            return@Section
        }
        val date = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(plan.created * 1000))
        Text(txt.s(R.string.heir_plan_line, plan.k, plan.n, plan.waitDays, date), color = c.text, modifier = Modifier.padding(top = 8.dp))
        Text(plan.holders.joinToString(", "), color = c.secondaryText)
        if (plan.stale) Text(stringResource(R.string.heir_stale), color = c.danger)
        if (unreachable) Text(stringResource(R.string.heir_folder_unreachable), color = c.danger, modifier = Modifier.testTag("emergency-folder-unreachable"))
        Text(stringResource(R.string.heir_not_home), color = c.secondaryText, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp))
        Text(stringResource(R.string.heir_requests), color = c.text, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp))
        if (!hasFolder || requests.isEmpty()) {
            Text(stringResource(R.string.heir_no_requests), color = c.secondaryText, modifier = Modifier.padding(vertical = 8.dp))
        }
        for (r in requests) {
            val asked = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(r.created * 1000))
            Column(Modifier.fillMaxWidth().padding(vertical = 6.dp).testTag("emergency-request-${r.requestId}")) {
                Text(txt.s(R.string.heir_request_line, r.holder, asked, r.daysLeft), color = c.text)
                if (r.granted) Text(stringResource(R.string.heir_granted_line), color = c.secondaryText)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton({ onDeny(r) }, modifier = Modifier.testTag("emergency-deny")) { Text(stringResource(R.string.heir_deny), color = c.danger) }
                    if (!plan.stale && !r.granted) {
                        TextButton({ onGrant(r) }, modifier = Modifier.testTag("emergency-grant")) { Text(stringResource(R.string.heir_grant), color = c.accentText) }
                    }
                }
            }
        }
    }
}

/** Grant now: the confirmation text and the owner's recovery phrase (checked against the plan, never stored). */
@Composable
private fun GrantDialog(r: HeirRequest, onDismiss: () -> Unit, onGrant: (String) -> Unit) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    var typed by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.heir_grant_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(txt.s(R.string.heir_grant_confirm, r.holder))
                OutlinedTextField(typed, { typed = it }, label = { Text(stringResource(R.string.heir_grant_phrase)) }, modifier = Modifier.fillMaxWidth().testTag("emergency-grant-phrase"))
            }
        },
        confirmButton = {
            TextButton(enabled = typed.isNotBlank(), onClick = { val p = typed; typed = ""; onGrant(p) }, modifier = Modifier.testTag("emergency-grant-confirm")) {
                Text(stringResource(R.string.heir_grant), color = c.accentText)
            }
        },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.common_cancel), color = c.accentText) } },
    )
}
