package app.localgatekeys.android.ui.features

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.R
import app.localgatekeys.android.access.AccessRulesModel
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.vault.VaultItem
import kotlinx.coroutines.launch

/**
 * A web login's Access rules (contract section 4.5): the two existing policy switches plus copy once, view only on
 * phones and a lock date. [save] writes off the main thread; NEEDS_PRO opens the upgrade sheet ([onNeedsPro]).
 */
@Composable
fun AccessRulesDialog(
    item: VaultItem,
    save: suspend (AccessRulesModel.Form) -> SaveResult,
    onNeedsPro: () -> Unit,
    onDone: (Boolean) -> Unit,
) {
    val start = remember(item) { AccessRulesModel.form(item.record) }
    var reauth by remember(item) { mutableStateOf(start.reauth) }
    var neverFill by remember(item) { mutableStateOf(start.neverFill) }
    var copyOnce by remember(item) { mutableStateOf(start.settings.copyOnce) }
    var phonesView by remember(item) { mutableStateOf(start.settings.phonesView) }
    var expires by remember(item) { mutableStateOf(start.settings.expires) }
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val needsPro = stringResource(R.string.access_needs_pro)
    val badDate = stringResource(R.string.access_bad_date)
    val loosenRefused = stringResource(R.string.access_loosen_confirm)
    AlertDialog(
        onDismissRequest = { onDone(false) },
        title = { Text(stringResource(R.string.access_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                if (start.unknownRule) {
                    Text(stringResource(R.string.access_unknown_rule))
                } else {
                    Rule(stringResource(R.string.access_reauth), reauth, "access-reauth") { reauth = it }
                    Rule(stringResource(R.string.access_never_fill), neverFill, "access-never-fill") { neverFill = it }
                    Rule(stringResource(R.string.access_copy_once), copyOnce, "access-copy-once") { copyOnce = it }
                    Rule(stringResource(R.string.access_phones_view), phonesView, "access-phones-view") { phonesView = it }
                    OutlinedTextField(
                        expires, { expires = it.trim(); error = null }, singleLine = true,
                        label = { Text(stringResource(R.string.access_expires)) },
                        placeholder = { Text("YYYY-MM-DD") },
                        modifier = Modifier.fillMaxWidth().testTag("access-expires"),
                    )
                }
                Text(stringResource(R.string.access_older_devices))
                error?.let { Text(it) }
            }
        },
        confirmButton = {
            if (!start.unknownRule) {
                TextButton(
                    {
                        if (!AccessRulesModel.validDate(expires)) {
                            error = badDate
                            return@TextButton
                        }
                        working = true
                        scope.launch {
                            val form = AccessRulesModel.Form(reauth, neverFill, app.localgatekeys.core.access.AccessRules.Settings(copyOnce, phonesView, expires), false)
                            when (save(form)) {
                                SaveResult.SAVED -> onDone(true)
                                SaveResult.UNCHANGED -> onDone(false)
                                SaveResult.NEEDS_PRO -> { error = needsPro; onNeedsPro() }
                                SaveResult.FAILED -> error = loosenRefused
                                else -> error = badDate
                            }
                            working = false
                        }
                    },
                    enabled = !working,
                    modifier = Modifier.testTag("access-save"),
                ) { Text(stringResource(R.string.common_save)) }
            }
        },
        dismissButton = { TextButton({ onDone(false) }) { Text(stringResource(R.string.common_cancel)) } },
    )
}

@Composable
private fun Rule(label: String, on: Boolean, tag: String, set: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f))
        Switch(on, set, Modifier.testTag(tag).semantics { contentDescription = label })
    }
}
