package app.localgatekeys.android.autofill

import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource
import app.localgatekeys.android.i18n.AndroidTxt
import android.os.Bundle
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.ui.Alignment
import app.localgatekeys.android.ui.theme.LgkTheme
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
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
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
 *
 * A browser page is checked against the vault's saved sites first ([SiteCheck], sub-plan 09): the sheet names it a
 * verified, related or new site. A lookalike asks "Is this the right site?" before anything else, with "Go back"
 * (saves nothing) as the main button; the same name on another ending asks once whether it is the same account.
 */
class SaveLoginActivity : VaultGateActivity() {
    private var pending: PendingSaves.Pending? = null

    /**
     * Holds the taken save across a rotation, a theme or language change or a resize (the token is taken once), in
     * memory only: never in the saved-instance Bundle. It is dropped when the sheet finishes.
     */
    class Held : ViewModel() {
        var taken = false
        var pending: PendingSaves.Pending? = null

        override fun onCleared() {
            pending = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        val held = ViewModelProvider(this)[Held::class.java]
        if (!held.taken) {
            held.taken = true
            held.pending = PendingSaves.take(intent.getStringExtra(TOKEN))
        }
        pending = held.pending
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
        var prompt by remember { mutableStateOf<SitePrompt?>(null) }
        var acknowledged by remember { mutableStateOf(false) }
        val matcher = remember { FillMatcher(app.urlMatcher) }
        LaunchedEffect(vault) {
            val (decided, site) = withContext(Dispatchers.IO) {
                val s = vault.store.load()
                app.pro.update(s)
                val web = p.target as? FillTarget.Web
                SaveDecision.decide(s, p.target, p.username, p.password, app.pro.isPro, matcher, app.fillIndex.read() ?: FillIndex.build(s)) to
                    web?.let { SiteCheck.prompt(app.lookalike, it.origin, SiteCheck.savedOrigins(s), vault.localKey, app.securityPrefs.sameAccountPairs) }
            }
            prompt = site
            decision = decided
            if (decided is SaveDecision.Unchanged) finish()
        }
        val d = decision ?: return
        val site = prompt
        if (!acknowledged && site != null && site.needsAnswer()) {
            LookalikeGuard(site, onGoBack = { finish() }, onContinue = {
                if (site is SitePrompt.SameAccount) app.securityPrefs.sameAccountPairs = app.securityPrefs.sameAccountPairs + site.pair
                acknowledged = true
            })
            return
        }
        val c = LgkTheme.colors
        AutofillSheet {
            val siteName = (p.target as? FillTarget.Web)?.let { SaveDecision.titleFor(it.origin) }
            SheetHeader(
                stringResource(if (d is SaveDecision.Update) R.string.autofill_update_password_q else R.string.autofill_save_login_q),
                listOfNotNull(siteName, p.username.ifEmpty { null }).joinToString(" · "),
            )
            if (site != null || d is SaveDecision.NeedsPro || (d is SaveDecision.New && p.target is FillTarget.App) || error != null) {
                SheetCard {
                    site?.let { SiteVerdictLine(it) }
                    if (d is SaveDecision.NeedsPro) Text(SaveDecision.limitMessage(AndroidTxt(resources)), color = c.danger)
                    if (d is SaveDecision.New && p.target is FillTarget.App) {
                        OutlinedTextField(
                            website, { website = it; error = null }, Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.detail_pane_website)) }, singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                            shape = RoundedCornerShape(14.dp), colors = sheetFieldColors(),
                        )
                    }
                    error?.let { Text(it, color = c.danger) }
                }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End), verticalAlignment = Alignment.CenterVertically) {
                SheetTextButton(stringResource(R.string.common_not_now), onClick = { finish() })
                if (d !is SaveDecision.NeedsPro) {
                    AccentButton(
                        stringResource(if (d is SaveDecision.Update) R.string.autofill_update_password else R.string.common_save),
                        onClick = {
                            scope.launch {
                                error = withContext(Dispatchers.IO) { save(vault, p, d, website) }
                                if (error == null) finish()
                            }
                        },
                    )
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
        if (p.target is FillTarget.App) app.fillIndex.pair(after, p.target.pairKey, id, app.pro.isPro) else app.fillIndex.rebuild(after, app.pro.isPro)
        null
    } catch (e: Exception) {
        getString(if (d is SaveDecision.New) R.string.editor_check_website else R.string.autofill_login_not_saved)
    }

    companion object {
        const val TOKEN = "lgk.save.token"
    }
}
