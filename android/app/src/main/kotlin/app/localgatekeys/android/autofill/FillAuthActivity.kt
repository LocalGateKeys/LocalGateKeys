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
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.testTag
import app.localgatekeys.android.ui.theme.LgkTheme
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
import app.localgatekeys.core.records.UrlMatcher
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.TravelMode
import app.localgatekeys.android.access.AccessGate
import app.localgatekeys.core.totp.Totp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Opened by an autofill dataset: unlock, re-read the login from the store, re-check it against the request's target,
 * and return the filled dataset. Without an item id it shows a search list; choosing a login for an app pairs that app
 * with it on this phone (spec: first fill in an app goes through a search list). A login chosen for a web page that
 * is not its own site (or a lookalike of it, or a page whose scheme the browser did not name) asks first, naming both
 * sites, with "Go back" as the main button ([SiteCheck.picked]). A login chosen for an app it is not yet paired with
 * asks the same way first, naming the app ([SiteCheck.pickedApp]).
 */
class FillAuthActivity : VaultGateActivity() {
    /** A login picked by hand that waits for the person's answer to [prompt]. */
    private class Picked(val snap: StoreSnapshot, val id: String, val prompt: SitePrompt)

    @Composable
    override fun Unlocked(vault: UnlockedVault) {
        val target = FillExtras.get(intent)
        val itemId = intent.getStringExtra(ITEM)
        val scope = rememberCoroutineScope()
        var split by remember { mutableStateOf<FillPickerOrder.Split?>(null) }
        var query by remember { mutableStateOf("") }
        var snapshot by remember { mutableStateOf<StoreSnapshot?>(null) }
        var picked by remember { mutableStateOf<Picked?>(null) }
        LaunchedEffect(vault) {
            if (target == null) return@LaunchedEffect finish()
            val snap = withContext(Dispatchers.IO) { vault.store.load() }
            snapshot = snap
            if (itemId != null) {
                fill(snap, target, itemId, chosen = false)
            } else {
                split = withContext(Dispatchers.IO) {
                    // Travel mode and the access rules leave the same logins out as the stored index does.
                    val stored = app.fillIndex.read()
                    // The vault's own travel setting; unreadable lists nothing (fail closed, scan A-M4).
                    val travel = app.travelFor(vault)
                    val built = if (travel == null) FillIndex.build(StoreSnapshot()) else FillIndex.build(snap, travel = travel)
                    // The same match the suggestions use (FillMatcher.match): ordering only, every login stays listed.
                    val matchIds = FillMatcher(app.urlMatcher).match(stored ?: built, target).map { it.id }
                    FillPickerOrder.split(built.entries.map { FillPickerOrder.Row(it.id, it.title, it.username) }, matchIds)
                }
            }
        }
        val lists = split ?: return
        picked?.let { p ->
            LookalikeGuard(p.prompt, onGoBack = { finish() }, onContinue = {
                if (p.prompt is SitePrompt.SameAccount) app.securityPrefs.sameAccountPairs = app.securityPrefs.sameAccountPairs + p.prompt.pair
                picked = null
                scope.launch { if (target != null) fill(p.snap, target, p.id, chosen = true) }
            })
            return
        }
        val choose: (String) -> Unit = { id ->
            val snap = snapshot
            if (snap != null && target != null) {
                scope.launch {
                    val ask = when (target) {
                        is FillTarget.Web -> check(vault, snap, target, id)
                        is FillTarget.App -> checkApp(snap, target, id)
                    }
                    if (ask != null) picked = Picked(snap, id, ask) else fill(snap, target, id, chosen = true)
                }
            }
        }
        val c = LgkTheme.colors
        AutofillSheet {
            SheetHeader(
                stringResource(R.string.autofill_fill_title),
                when (target) {
                    is FillTarget.Web -> stringResource(R.string.autofill_for_site, SaveDecision.titleFor(target.origin))
                    is FillTarget.App -> stringResource(R.string.autofill_for_site, appName(target.packageName))
                    null -> null
                },
            )
            if (target is FillTarget.App && lists.matches.isEmpty()) {
                Text(stringResource(R.string.autofill_app_pairing_hint), color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
            }
            LazyColumn(Modifier.weight(1f, fill = false), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                lists.matches.firstOrNull()?.let { best ->
                    item(key = "matches") {
                        SheetCard {
                            LoginLine(best, trailing = { MatchTag(stringResource(R.string.autofill_matches_site)) })
                            AccentButton(stringResource(R.string.autofill_fill), onClick = { choose(best.id) }, modifier = Modifier.fillMaxWidth().testTag("fill-best"))
                            for (r in lists.matches.drop(1)) {
                                LoginLine(r, Modifier.fillMaxWidth().clickable { choose(r.id) })
                            }
                        }
                    }
                    item(key = "others-label") { SectionLabel(stringResource(R.string.autofill_other_logins)) }
                }
                item(key = "search") {
                    OutlinedTextField(
                        query, { query = it }, Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.autofill_search_vault)) },
                        singleLine = true, shape = RoundedCornerShape(14.dp), colors = sheetFieldColors(),
                    )
                }
                val shown = FillPickerOrder.filter(lists.others, query)
                if (shown.isNotEmpty()) {
                    item(key = "others") {
                        SheetCard {
                            for (r in shown) LoginLine(r, Modifier.fillMaxWidth().clickable { choose(r.id) })
                        }
                    }
                }
            }
            SheetTextButton(stringResource(R.string.common_cancel), onClick = { finish() }, modifier = Modifier.align(Alignment.CenterHorizontally))
        }
    }

    /** The requesting app's name for the header (presentation only; pairing still uses the package and certificate). */
    private fun appName(pkg: String): String = try {
        packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
    } catch (e: Exception) {
        pkg
    }

    /**
     * The same site check as the suggestions (the URL match) and the save sheet (the lookalike check) for a login
     * picked by hand for [target]: null fills at once, else the question to ask first.
     */
    private suspend fun check(vault: UnlockedVault, snap: StoreSnapshot, target: FillTarget.Web, id: String): SitePrompt? {
        val record = SaveDecision.recordOf(snap, id) ?: return null // fill() then finishes
        return withContext(Dispatchers.IO) {
            val index = app.fillIndex.read() ?: FillIndex.build(snap)
            val matches = FillMatcher(app.urlMatcher).recordMatches(record, id, target, index)
            val saved = UrlMatcher.entryUrls(record).map { it.url }
            SiteCheck.picked(app.lookalike, target.origin, saved, matches, target.schemeKnown, vault.localKey, app.securityPrefs.sameAccountPairs)
        }
    }

    /** Audit A3: a login picked for an app it is not yet paired with asks first ([SiteCheck.pickedApp]). */
    private suspend fun checkApp(snap: StoreSnapshot, target: FillTarget.App, id: String): SitePrompt? {
        val record = SaveDecision.recordOf(snap, id) ?: return null // fill() then finishes
        return withContext(Dispatchers.IO) {
            val index = app.fillIndex.read() ?: FillIndex.build(snap)
            SiteCheck.pickedApp(target, id, index, UrlMatcher.entryUrls(record).map { it.url })
        }
    }

    /**
     * [chosen]: the person picked it in the list (pairs an app; a web page was checked by [check] and confirmed when
     * asked); otherwise it must still match the target, on a page whose scheme the browser named.
     */
    private suspend fun fill(snap: StoreSnapshot, target: FillTarget, id: String, chosen: Boolean) {
        val record = SaveDecision.recordOf(snap, id) ?: return finish()
        val matcher = FillMatcher(app.urlMatcher)
        val index = withContext(Dispatchers.IO) { app.fillIndex.read() } ?: FillIndex.build(snap)
        if (!chosen && (!matcher.recordMatches(record, id, target, index) || (target is FillTarget.Web && !target.schemeKnown))) return finish()
        // Access rules (contract section 4.3), re-read from the stored login: never autofill refuses; re-authenticate
        // asks for the owner unless this fill's own unlock just did; travel mode hides it.
        // Travel mode from the open vault's own local data; unreadable fills nothing (fail closed, scan A-M4).
        val travel = withContext(Dispatchers.IO) { app.lock.vault.value?.let { app.travelFor(it) } } ?: return finish()
        if (id in TravelMode.hiddenIds(snap, travel)) return finish()
        when (AccessGate.fill(AccessGate.effective(record), unlockedJustNow = !wasUnlockedAtStart)) {
            AccessGate.Need.REFUSED -> return finish()
            AccessGate.Need.OWNER -> if (!app.confirmOwner(getString(R.string.access_reauth))) return finish()
            AccessGate.Need.NOTHING -> Unit
        }
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
