package app.localgatekeys.android.autofill

import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource
import app.localgatekeys.android.i18n.AndroidTxt
import android.os.Bundle
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.unlock.UnlockedVault
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The save prompt (spec section 5, Save): unlock, then **Save** or **Update password** when that site and username
 * exist. A full free plan blocks Save with the limit message; Update always works. An app's login asks for its website.
 */
class SaveLoginActivity : VaultGateActivity() {
    private var pending: PendingSaves.Pending? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        pending = PendingSaves.take(intent.getStringExtra(TOKEN))
        super.onCreate(savedInstanceState)
        if (pending == null) finish()
    }

    @Composable
    override fun Unlocked(vault: UnlockedVault) {
        val p = pending ?: return
        val scope = rememberCoroutineScope()
        var decision by remember { mutableStateOf<SaveDecision?>(null) }
        var website by remember { mutableStateOf((p.target as? FillTarget.Web)?.origin ?: "") }
        var error by remember { mutableStateOf<String?>(null) }
        val matcher = remember { FillMatcher(app.urlMatcher) }
        LaunchedEffect(vault) {
            decision = withContext(Dispatchers.IO) {
                val s = vault.store.load()
                app.pro.update(s)
                SaveDecision.decide(s, p.target, p.username, p.password, app.pro.isPro, matcher, app.fillIndex.read() ?: FillIndex.build(s))
            }
            if (decision is SaveDecision.Unchanged) finish()
        }
        val d = decision ?: return
        Column(Modifier.fillMaxWidth().safeDrawingPadding().padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            val site = (p.target as? FillTarget.Web)?.let { SaveDecision.titleFor(it.origin) }
            Text(stringResource(if (d is SaveDecision.Update) R.string.autofill_update_password_q else R.string.autofill_save_login_q), style = MaterialTheme.typography.titleLarge)
            Text(listOfNotNull(site, p.username.ifEmpty { null }).joinToString(" · "), style = MaterialTheme.typography.bodyMedium)
            if (d is SaveDecision.NeedsPro) Text(SaveDecision.limitMessage(AndroidTxt(resources)), color = MaterialTheme.colorScheme.error)
            if (d is SaveDecision.New && p.target is FillTarget.App) {
                OutlinedTextField(
                    website, { website = it; error = null }, Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.detail_pane_website)) }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                )
            }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { finish() }) { Text(stringResource(R.string.common_not_now)) }
                if (d !is SaveDecision.NeedsPro) {
                    Button(onClick = {
                        scope.launch {
                            error = withContext(Dispatchers.IO) { save(vault, p, d, website) }
                            if (error == null) finish()
                        }
                    }) { Text(stringResource(if (d is SaveDecision.Update) R.string.autofill_update_password else R.string.common_save)) }
                }
            }
        }
    }

    /** Null on success, else the message to show. */
    private fun save(vault: UnlockedVault, p: PendingSaves.Pending, d: SaveDecision, website: String): String? = try {
        val s = vault.store.load()
        val now = SystemClock().now
        val record = when (d) {
            is SaveDecision.Update -> {
                val r = SaveDecision.recordOf(s, d.itemId) ?: return getString(R.string.autofill_login_gone)
                SaveDecision.updatedRecord(r, p.password, now)
            }
            is SaveDecision.New -> {
                app.pro.update(s)
                if (!app.pro.isPro && !ItemLimit.allows(ItemLimit.Action.CREATE, s, false)) {
                    return SaveDecision.limitMessage(AndroidTxt(resources))
                }
                SaveDecision.newRecord(website, p.username, p.password, now, SystemRandomSource())
            }
            else -> return null
        }
        vault.store.commit(SaveDecision.change(s, record))
        val after = vault.store.load()
        val id = ((record as JsonValue.Obj).fields["id"] as JsonValue.Str).v
        if (p.target is FillTarget.App) app.fillIndex.pair(after, p.target.pairKey, id) else app.fillIndex.rebuild(after)
        null
    } catch (e: Exception) {
        getString(if (d is SaveDecision.New) R.string.editor_check_website else R.string.autofill_login_not_saved)
    }

    companion object {
        const val TOKEN = "lgk.save.token"
    }
}
