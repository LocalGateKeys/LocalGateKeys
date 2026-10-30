package app.localgatekeys.android.autofill

import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Build
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.unlock.UnlockedVault
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.totp.Totp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Opened by an autofill dataset: unlock, re-read the login from the store, re-check it against the request's target,
 * and return the filled dataset. Without an item id it shows a search list; choosing a login for an app pairs that app
 * with it on this phone (spec: first fill in an app goes through a search list).
 */
class FillAuthActivity : VaultGateActivity() {
    private data class Row(val id: String, val title: String, val username: String)

    @Composable
    override fun Unlocked(vault: UnlockedVault) {
        val target = FillExtras.get(intent)
        val itemId = intent.getStringExtra(ITEM)
        val scope = rememberCoroutineScope()
        var rows by remember { mutableStateOf<List<Row>?>(null) }
        var query by remember { mutableStateOf("") }
        var snapshot by remember { mutableStateOf<StoreSnapshot?>(null) }
        LaunchedEffect(vault) {
            if (target == null) return@LaunchedEffect finish()
            val snap = withContext(Dispatchers.IO) { vault.store.load() }
            snapshot = snap
            if (itemId != null) {
                fill(snap, target, itemId, chosen = false)
            } else {
                rows = FillIndex.build(snap).entries.map { Row(it.id, it.title, it.username) }
                    .sortedBy { it.title.lowercase() }
            }
        }
        val list = rows ?: return
        Column(Modifier.fillMaxSize().safeDrawingPadding().padding(16.dp)) {
            Text(stringResource(R.string.autofill_choose_login), style = MaterialTheme.typography.titleLarge)
            Text(
                when (target) {
                    is FillTarget.Web -> stringResource(R.string.autofill_for_site, SaveDecision.titleFor(target.origin))
                    is FillTarget.App -> stringResource(R.string.autofill_app_pairing_hint)
                    null -> ""
                },
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(vertical = 8.dp),
            )
            OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.autofill_search)) }, singleLine = true)
            val q = query.trim().lowercase()
            LazyColumn(Modifier.weight(1f)) {
                items(list.filter { q.isEmpty() || it.title.lowercase().contains(q) || it.username.lowercase().contains(q) }, key = { it.id }) { r ->
                    Column(
                        Modifier.fillMaxWidth().clickable {
                            val snap = snapshot ?: return@clickable
                            scope.launch { if (target != null) fill(snap, target, r.id, chosen = true) }
                        }.padding(vertical = 12.dp),
                    ) {
                        Text(r.title.ifEmpty { r.username })
                        if (r.username.isNotEmpty()) Text(r.username, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            TextButton(onClick = { finish() }) { Text(stringResource(R.string.common_cancel)) }
        }
    }

    /** [chosen]: the person picked it in the list (pairs an app); otherwise it must still match the target. */
    private suspend fun fill(snap: StoreSnapshot, target: FillTarget, id: String, chosen: Boolean) {
        val record = SaveDecision.recordOf(snap, id) ?: return finish()
        val matcher = FillMatcher(app.urlMatcher)
        val index = withContext(Dispatchers.IO) { app.fillIndex.read() } ?: FillIndex.build(snap)
        if (!chosen && !matcher.recordMatches(record, id, target, index)) return finish()
        if (chosen && target is FillTarget.App) withContext(Dispatchers.IO) { app.fillIndex.pair(snap, target.pairKey, id) }
        val username = (record["username"] as? JsonValue.Str)?.v ?: ""
        val password = (record["password"] as? JsonValue.Str)?.v ?: ""
        val users = ids(USERS)
        val passwords = ids(PASSWORDS)
        val title = (record["label"] as? JsonValue.Str)?.v ?: username
        val dataset = Presentations.filled(Presentations.row(this, title, username), users, passwords, username, password)
        setResult(Activity.RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
        if (app.settings.copyCodeOnFill) copyCode(record)
        finish()
    }

    private fun copyCode(record: Map<String, JsonValue>) {
        val t = (record["totp"] as? JsonValue.Obj)?.fields ?: return
        val secret = (t["secret"] as? JsonValue.Str)?.v ?: return
        try {
            val code = Totp.code(
                secret, (t["algorithm"] as? JsonValue.Str)?.v ?: "SHA1", ((t["digits"] as? JsonValue.Int)?.v ?: 6).toInt(),
                ((t["period"] as? JsonValue.Int)?.v ?: 30).toInt(), SystemClock().now,
            )
            app.clipboard.copy(code)
            app.copyToast.show(getString(R.string.autofill_code_copied))
        } catch (e: Exception) {
            // a bad secret: nothing copied
        }
    }

    @Suppress("DEPRECATION")
    private fun ids(key: String): List<AutofillId> =
        if (Build.VERSION.SDK_INT >= 33) intent.getParcelableArrayListExtra(key, AutofillId::class.java) ?: emptyList()
        else intent.getParcelableArrayListExtra<AutofillId>(key) ?: emptyList()

    companion object {
        private const val ITEM = "lgk.item"
        private const val USERS = "lgk.users"
        private const val PASSWORDS = "lgk.passwords"

        fun intent(context: Context, target: FillTarget, itemId: String?, users: List<AutofillId>, passwords: List<AutofillId>): Intent =
            FillExtras.put(Intent(context, FillAuthActivity::class.java), target)
                .putExtra(ITEM, itemId)
                .putParcelableArrayListExtra(USERS, ArrayList(users))
                .putParcelableArrayListExtra(PASSWORDS, ArrayList(passwords))
    }
}
