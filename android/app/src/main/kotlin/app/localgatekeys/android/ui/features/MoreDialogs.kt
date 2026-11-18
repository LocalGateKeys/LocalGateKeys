package app.localgatekeys.android.ui.features

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.R
import app.localgatekeys.android.history.CleanUpModel
import app.localgatekeys.android.history.PasskeyDoctor
import app.localgatekeys.core.hygiene.Hygiene
import app.localgatekeys.core.proof.PrivacyProof
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@androidx.annotation.StringRes
fun hygieneLabel(type: String): Int = when (type) {
    Hygiene.SAME_LOGIN -> R.string.hygiene_same_login
    Hygiene.SAME_ACCOUNT_OTHER_PASSWORD -> R.string.hygiene_same_account_other_password
    Hygiene.SAME_SITE -> R.string.hygiene_same_site
    Hygiene.SAME_ITEM -> R.string.hygiene_same_item
    Hygiene.NOT_CHANGED_2Y -> R.string.hygiene_not_changed
    else -> R.string.hygiene_expired
}

/**
 * Settings > Clean up (contract section 3): the findings with Merge (one pair, confirmed) and Delete (one item); Pro
 * adds "merge all same login", Delete all of a finding, and Undo of the last bulk action.
 */
@Composable
fun CleanUpDialog(model: CleanUpModel, title: (String) -> String, onNeedsPro: () -> Unit, onChanged: () -> Unit, onDone: () -> Unit) {
    var findings by remember { mutableStateOf<List<Hygiene.Finding>?>(null) }
    var reload by remember { mutableIntStateOf(0) }
    var message by remember { mutableStateOf<String?>(null) }
    var confirm by remember { mutableStateOf<Pair<String, String>?>(null) }
    var confirmAll by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val needsPro = stringResource(R.string.hygiene_bulk_needs_pro)
    val refusedFmt = stringResource(R.string.hygiene_refused)
    LaunchedEffect(reload) { findings = withContext(Dispatchers.IO) { runCatching { model.findings() }.getOrDefault(emptyList()) } }
    fun run(action: () -> CleanUpModel.Result) {
        scope.launch {
            when (val r = withContext(Dispatchers.IO) { action() }) {
                CleanUpModel.Result.Done -> { onChanged(); message = null }
                CleanUpModel.Result.NeedsPro -> { message = needsPro; onNeedsPro() }
                is CleanUpModel.Result.Refused -> message = refusedFmt.format(r.code)
                CleanUpModel.Result.Failed -> message = refusedFmt.format("failed")
            }
            reload++
        }
    }
    if (confirmAll) {
        // Contract section 3.2: every merge is user-confirmed, the bulk one too (as on Windows).
        AlertDialog(
            onDismissRequest = { confirmAll = false },
            title = { Text(stringResource(R.string.hygiene_merge_all)) },
            text = { Text(stringResource(R.string.hygiene_merge_review)) },
            confirmButton = { TextButton({ confirmAll = false; run { model.mergeAllSameLogin() } }, Modifier.testTag("hygiene-merge-all-confirm")) { Text(stringResource(R.string.hygiene_merge)) } },
            dismissButton = { TextButton({ confirmAll = false }) { Text(stringResource(R.string.common_cancel)) } },
        )
        return
    }
    val pending = confirm
    if (pending != null) {
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text(stringResource(R.string.hygiene_merge)) },
            text = { Text(stringResource(R.string.hygiene_merge_review) + "\n\n" + title(pending.first) + "  <-  " + title(pending.second)) },
            confirmButton = { TextButton({ confirm = null; run { model.merge(pending.first, pending.second) } }, Modifier.testTag("hygiene-merge-confirm")) { Text(stringResource(R.string.hygiene_merge)) } },
            dismissButton = { TextButton({ confirm = null }) { Text(stringResource(R.string.common_cancel)) } },
        )
        return
    }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(stringResource(R.string.hygiene_title)) },
        text = {
            val list = findings
            Column {
                if (list != null) {
                    // Distinct items in any duplicate group, as Windows `hygiene.summary` counts them.
                    val dupes = list.filter { it.type in Hygiene.DUPLICATE_TYPES }.flatMapTo(HashSet()) { it.ids }.size
                    val old = list.firstOrNull { it.type == Hygiene.NOT_CHANGED_2Y }?.ids?.size ?: 0
                    val expired = list.firstOrNull { it.type == Hygiene.EXPIRED }?.ids?.size ?: 0
                    Text(
                        stringResource(
                            R.string.hygiene_summary, pluralStringResource(R.plurals.hygiene_summary_duplicates, dupes, dupes),
                            pluralStringResource(R.plurals.hygiene_summary_stale, old, old), pluralStringResource(R.plurals.hygiene_summary_expired, expired, expired),
                        ),
                    )
                }
                message?.let { Text(it, Modifier.padding(top = 4.dp)) }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton({ confirmAll = true }, Modifier.testTag("hygiene-merge-all")) { Text(stringResource(R.string.hygiene_merge_all)) }
                    if (model.canUndo) TextButton({ run { model.undo() } }, Modifier.testTag("hygiene-undo")) { Text(stringResource(R.string.hygiene_undo)) }
                }
                LazyColumn(Modifier.heightIn(max = 420.dp)) {
                    items(list ?: emptyList()) { f ->
                        Column(Modifier.padding(vertical = 6.dp)) {
                            Text(stringResource(hygieneLabel(f.type)), fontWeight = FontWeight.SemiBold)
                            for (id in f.ids.take(6)) Text(title(id))
                            Row {
                                if (f.type in Hygiene.DUPLICATE_TYPES && f.ids.size >= 2) {
                                    TextButton({ confirm = f.ids[0] to f.ids[1] }) { Text(stringResource(R.string.hygiene_merge)) }
                                }
                                TextButton({ run { model.delete(listOf(f.ids.last())) } }) { Text(stringResource(R.string.common_delete)) }
                                if (f.ids.size > 1 && f.type !in Hygiene.DUPLICATE_TYPES) {
                                    TextButton({ run { model.delete(f.ids) } }) { Text(pluralStringResource(R.plurals.hygiene_delete_selected, f.ids.size, f.ids.size)) }
                                }
                            }
                            HorizontalDivider()
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onDone) { Text(stringResource(R.string.common_done)) } },
    )
}

/** Settings > Privacy proof (contract section 5): what the file holds, and Export. */
@Composable
fun PrivacyProofDialog(
    make: suspend () -> Pair<ByteArray, String?>,
    fileName: String,
    onPickerOpen: () -> Unit,
    onPickerClose: () -> Unit,
    onDone: () -> Unit,
) {
    val context = LocalContext.current
    var made by remember { mutableStateOf<Pair<ByteArray, String?>?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    LaunchedEffect(Unit) { made = runCatching { withContext(Dispatchers.IO) { make() } }.getOrNull() }
    val saved = stringResource(R.string.privacy_verify_hint, fileName)
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        onPickerClose()
        val bytes = made?.first
        if (uri != null && bytes != null) {
            scope.launch {
                val ok = withContext(Dispatchers.IO) { runCatching { context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) } != null }.getOrDefault(false) }
                status = if (ok) saved else null
            }
        }
    }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(stringResource(R.string.privacy_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(stringResource(R.string.privacy_intro))
                Text(stringResource(R.string.privacy_no_list_yet))
                val fp = made?.second
                Text(if (fp == null) stringResource(R.string.privacy_unsigned) else stringResource(R.string.privacy_signed_by, fp))
                if (fp != null) Text(stringResource(R.string.privacy_signature_means))
                status?.let { Text(it) }
            }
        },
        confirmButton = {
            TextButton({ onPickerOpen(); saver.launch(fileName) }, enabled = made != null, modifier = Modifier.testTag("privacy-export")) {
                Text(stringResource(R.string.privacy_export))
            }
        },
        dismissButton = { TextButton(onDone) { Text(stringResource(R.string.common_done)) } },
    )
}

/** Settings > Passkey doctor (contract section 6.2): whether LocalGateKeys is the selected provider, with the setting. */
@Composable
fun PasskeyDoctorDialog(onPickerOpen: () -> Unit, onDone: () -> Unit, onPickerFailed: () -> Unit = {}) {
    val context = LocalContext.current
    var status by remember { mutableStateOf(PasskeyDoctor.status(context)) }
    LaunchedEffect(Unit) { status = PasskeyDoctor.status(context) }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(stringResource(R.string.passkey_doctor_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                stringResource(
                    when (status) {
                        PasskeyDoctor.Status.ON -> R.string.passkey_doctor_on
                        PasskeyDoctor.Status.OFF -> R.string.passkey_doctor_off
                        PasskeyDoctor.Status.UNKNOWN -> R.string.passkey_doctor_unknown
                    },
                ),
            )
            Text(stringResource(R.string.passkey_doctor_how_to))
            }
        },
        confirmButton = {
            TextButton({
                // The lock's one-trip allowance (as the folder pickers): coming back from Settings is not a lock bypass
                // and does not lock with "Immediately".
                onPickerOpen()
                if (runCatching { context.startActivity(PasskeyDoctor.settingsIntent(context)) }.isFailure) onPickerFailed()
                onDone()
            }, Modifier.testTag("passkey-doctor-open")) { Text(stringResource(R.string.passkey_doctor_open_settings)) }
        },
        dismissButton = { TextButton(onDone) { Text(stringResource(R.string.common_done)) } },
    )
}

/** Keeps [PrivacyProof] referenced for the file name rule. */
fun proofFileName(today: String): String = PrivacyProof.fileName(today)
