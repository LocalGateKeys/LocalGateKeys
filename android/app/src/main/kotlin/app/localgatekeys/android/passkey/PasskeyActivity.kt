package app.localgatekeys.android.passkey

import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource
import app.localgatekeys.android.i18n.AndroidTxt
import android.app.Activity
import android.content.Intent
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
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
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CreatePasswordResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import app.localgatekeys.android.autofill.FillIndex
import app.localgatekeys.android.autofill.FillMatcher
import app.localgatekeys.android.autofill.FillTarget
import app.localgatekeys.android.autofill.LookalikeGuard
import app.localgatekeys.android.autofill.SaveDecision
import app.localgatekeys.android.autofill.SiteCheck
import app.localgatekeys.android.autofill.SitePrompt
import app.localgatekeys.android.autofill.needsAnswer
import app.localgatekeys.android.autofill.VaultGateActivity
import app.localgatekeys.android.unlock.UnlockedVault
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreSnapshot
import kotlinx.coroutines.Dispatchers
import app.localgatekeys.android.access.AccessGate
import app.localgatekeys.core.sync.TravelMode
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalDate

/**
 * The Credential Manager sheet: unlock (or, when the vault was already open, a fresh owner check, since the
 * response claims user verification), then sign in, create, fill a password, or list entries after "Unlock".
 * Every refusal is a fixed message; nothing from the request or the vault is logged.
 *
 * A password save from a browser gets the save sheet's checks: a lookalike of a saved site asks "Is this the right
 * site?" first ([SiteCheck], "Go back" saves nothing), and replacing a saved password asks "Update password?".
 */
@RequiresApi(34)
class PasskeyActivity : VaultGateActivity() {
    /** A Credential Manager password save waiting for the person's answer. */
    private class PasswordSave(
        val target: FillTarget.Web,
        val username: String,
        val password: String,
        val decision: SaveDecision,
        val site: SitePrompt,
    ) {
        override fun toString(): String = "PasswordSave(target=$target)"
    }

    @Composable
    override fun Unlocked(vault: UnlockedVault) {
        var message by remember { mutableStateOf<String?>(null) }
        var save by remember { mutableStateOf<PasswordSave?>(null) }
        var acknowledged by remember { mutableStateOf(false) }
        val scope = rememberCoroutineScope()
        LaunchedEffect(vault) {
            message = attempt { save = run(vault) }
            if (message == null && save == null) finish()
        }
        val ask = save
        if (message == null && ask != null) {
            val commit: () -> Unit = {
                scope.launch {
                    message = attempt { commitPassword(vault.store, ask) }
                    save = null
                    if (message == null) finish()
                }
            }
            if (!acknowledged && ask.site.needsAnswer()) {
                LookalikeGuard(ask.site, onGoBack = { failAndFinish() }, onContinue = {
                    if (ask.site is SitePrompt.SameAccount) app.securityPrefs.sameAccountPairs = app.securityPrefs.sameAccountPairs + ask.site.pair
                    acknowledged = true
                })
            } else if (ask.decision is SaveDecision.Update) {
                Column(Modifier.fillMaxWidth().safeDrawingPadding().padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(stringResource(R.string.autofill_update_password_q), style = MaterialTheme.typography.titleLarge)
                    Text(listOfNotNull(SaveDecision.titleFor(ask.target.origin), ask.username.ifEmpty { null }).joinToString(" · "), style = MaterialTheme.typography.bodyMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = { failAndFinish() }) { Text(stringResource(R.string.common_not_now)) }
                        Button(onClick = commit) { Text(stringResource(R.string.autofill_update_password)) }
                    }
                }
            } else {
                LaunchedEffect(ask) { commit() }
            }
            return
        }
        val m = message ?: return
        Column(Modifier.fillMaxWidth().safeDrawingPadding().padding(20.dp)) {
            Text(m, style = MaterialTheme.typography.bodyLarge)
            TextButton(onClick = { failAndFinish() }) { Text(stringResource(R.string.common_close)) }
        }
    }

    /** Null when [block] succeeded, else the fixed message for its refusal. */
    private suspend fun attempt(block: suspend () -> Unit): String? = try {
        block()
        null
    } catch (e: WebAuthnException) {
        refusal(e.reason)
    } catch (e: Exception) {
        getString(R.string.passkey_could_not)
    }

    private fun refusal(r: WebAuthnException.Reason): String = when (r) {
        WebAuthnException.Reason.NEEDS_PRO -> SaveDecision.limitMessage(AndroidTxt(resources))
        WebAuthnException.Reason.EXCLUDED -> getString(R.string.passkey_excluded)
        WebAuthnException.Reason.NO_ES256 -> getString(R.string.passkey_no_es256)
        WebAuthnException.Reason.ORIGIN_REFUSED, WebAuthnException.Reason.RP_ID_REFUSED -> getString(R.string.passkey_origin_refused)
        WebAuthnException.Reason.NOT_FOUND -> getString(R.string.passkey_gone)
        WebAuthnException.Reason.PASSKEYS_OFF -> getString(R.string.passkey_off)
        else -> getString(R.string.passkey_could_not)
    }

    private fun failAndFinish() {
        val result = Intent()
        when (intent.action) {
            CREATE -> PendingIntentHandler.setCreateCredentialException(result, CreateCredentialUnknownException())
            GET, PASSWORD -> PendingIntentHandler.setGetCredentialException(result, GetCredentialUnknownException())
        }
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    /** Sign-in and creation claim UV: a vault opened earlier needs the owner again now. */
    private suspend fun verifyOwner(): Boolean = !wasUnlockedAtStart || app.confirmOwner(getString(R.string.passkey_use_reason))

    /** Null when done; a password save that waits for the person's answer otherwise. */
    private suspend fun run(vault: UnlockedVault): PasswordSave? {
        val store = vault.store
        when (intent.action) {
            UNLOCK -> {
                val req = PendingIntentHandler.retrieveBeginGetCredentialRequest(intent) ?: throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
                val response = withContext(Dispatchers.IO) { ProviderEntries.begin(this@PasskeyActivity, app, req) }
                val result = Intent()
                PendingIntentHandler.setBeginGetCredentialResponse(result, response)
                setResult(Activity.RESULT_OK, result)
            }
            GET -> get(store)
            PASSWORD -> password(store)
            CREATE -> return create(vault)
            else -> throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
        }
        return null
    }

    private suspend fun get(store: ItemStore) {
        if (!app.settings.passkeyProvider) throw WebAuthnException(WebAuthnException.Reason.PASSKEYS_OFF)
        val req = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
        val option = req.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull()
            ?: throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
        val itemId = intent.getStringExtra(ITEM) ?: throw WebAuthnException(WebAuthnException.Reason.NOT_FOUND)
        val parsed = AssertionRequest.parse(option.requestJson)
        val caller = verify(req.callingAppInfo, parsed.rpId, option.clientDataHash)
        // A stale entry never signs with a passkey travel mode hides now (unreadable setting: hidden, scan A-M4).
        val travel = withContext(Dispatchers.IO) { app.lock.vault.value?.let { app.travelFor(it) } }
        if (travel == null || itemId in withContext(Dispatchers.IO) { TravelMode.hiddenIds(store.load(), travel) }) throw WebAuthnException(WebAuthnException.Reason.NOT_FOUND)
        if (!verifyOwner()) return failAndFinish()
        val clientData = if (caller.clientDataHash == null) ClientData.json(ClientData.GET, parsed.challenge, caller.origin, caller.androidPackage) else null
        val hash = caller.clientDataHash ?: ClientData.hash(clientData!!)
        val a = withContext(Dispatchers.IO) { PasskeyVault.assert(store.load(), itemId, caller.rpId, hash, userVerified = true) }
        val json = WebAuthnResponse.assertion(a.credentialId, clientData ?: WebAuthnResponse.PLACEHOLDER_CLIENT_DATA, a.authenticatorData, a.signature, a.userHandle)
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PublicKeyCredential(json)))
        setResult(Activity.RESULT_OK, result)
    }

    private suspend fun password(store: ItemStore) {
        val req = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
        val itemId = intent.getStringExtra(ITEM) ?: throw WebAuthnException(WebAuthnException.Reason.NOT_FOUND)
        val s = withContext(Dispatchers.IO) { store.load() }
        val record = SaveDecision.recordOf(s, itemId) ?: throw WebAuthnException(WebAuthnException.Reason.NOT_FOUND)
        val target = ProviderEntries.passwordTarget(req.callingAppInfo, app)
        val index = withContext(Dispatchers.IO) { app.fillIndex.read() } ?: FillIndex.build(s)
        // Re-checked against the stored login: a stale entry never hands one site's password to another.
        if (!FillMatcher(app.urlMatcher).recordMatches(record, itemId, target, index)) throw WebAuthnException(WebAuthnException.Reason.ORIGIN_REFUSED)
        // Access rules (contract section 4.3) and travel mode, re-read from the stored login.
        // Travel mode from the open vault's own local data; unreadable counts as hidden (fail closed, scan A-M4).
        val travel = withContext(Dispatchers.IO) { app.lock.vault.value?.let { app.travelFor(it) } }
        if (travel == null || itemId in TravelMode.hiddenIds(s, travel)) throw WebAuthnException(WebAuthnException.Reason.NOT_FOUND)
        when (AccessGate.fill(AccessGate.effective(record), unlockedJustNow = !wasUnlockedAtStart)) {
            AccessGate.Need.REFUSED -> throw WebAuthnException(WebAuthnException.Reason.ORIGIN_REFUSED)
            AccessGate.Need.OWNER -> if (!app.confirmOwner(getString(R.string.access_reauth))) return failAndFinish()
            AccessGate.Need.NOTHING -> Unit
        }
        val username = (record["username"] as? JsonValue.Str)?.v ?: ""
        val pw = (record["password"] as? JsonValue.Str)?.v ?: ""
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PasswordCredential(username, pw)))
        setResult(Activity.RESULT_OK, result)
    }

    private suspend fun create(vault: UnlockedVault): PasswordSave? {
        val store = vault.store
        val req = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
        when (val call = req.callingRequest) {
            is CreatePublicKeyCredentialRequest -> {
                if (!app.settings.passkeyProvider) throw WebAuthnException(WebAuthnException.Reason.PASSKEYS_OFF)
                val parsed = CreationRequest.parse(call.requestJson)
                val caller = verify(req.callingAppInfo, parsed.rpId, call.clientDataHash)
                if (!verifyOwner()) {
                    failAndFinish()
                    return null
                }
                val reg = withContext(Dispatchers.IO) {
                    PasskeyVault.register(
                        store, caller.rpId, parsed.rpName, parsed.userName, parsed.userDisplayName, parsed.userHandle, parsed.exclude,
                        now = SystemClock().now, today = LocalDate.now().toString(), random = SystemRandomSource(),
                        isPro = { snap -> app.pro.update(snap); app.pro.isPro },
                    ).also { app.fillIndex.rebuild(store.load(), app.pro.isPro) }
                }
                val clientData = if (caller.clientDataHash == null) ClientData.json(ClientData.CREATE, parsed.challenge, caller.origin, caller.androidPackage) else null
                val json = WebAuthnResponse.registration(
                    reg.credentialId, clientData ?: WebAuthnResponse.PLACEHOLDER_CLIENT_DATA, reg.attestationObject, reg.authenticatorData, reg.spki,
                )
                val result = Intent()
                PendingIntentHandler.setCreateCredentialResponse(result, CreatePublicKeyCredentialResponse(json))
                setResult(Activity.RESULT_OK, result)
            }
            is CreatePasswordRequest -> {
                val target = ProviderEntries.passwordTarget(req.callingAppInfo, app) as? FillTarget.Web
                    ?: throw WebAuthnException(WebAuthnException.Reason.ORIGIN_REFUSED) // apps save through the autofill sheet, which asks for the website
                return withContext(Dispatchers.IO) {
                    val s = store.load()
                    app.pro.update(s)
                    when (val d = decidePassword(s, target, call.id, call.password)) {
                        is SaveDecision.Unchanged -> {
                            passwordSaved()
                            null
                        }
                        SaveDecision.NeedsPro -> throw WebAuthnException(WebAuthnException.Reason.NEEDS_PRO)
                        else -> PasswordSave(
                            target, call.id, call.password, d,
                            SiteCheck.prompt(app.lookalike, target.origin, SiteCheck.savedOrigins(s), vault.localKey, app.securityPrefs.sameAccountPairs),
                        )
                    }
                }
            }
            else -> throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
        }
        return null
    }

    private fun decidePassword(s: StoreSnapshot, target: FillTarget.Web, username: String, password: String): SaveDecision =
        SaveDecision.decide(s, target, username, password, app.pro.isPro, FillMatcher(app.urlMatcher), app.fillIndex.read() ?: FillIndex.build(s))

    /**
     * Writes the save the person answered. Decided again on the current vault: a change since the question (a sync,
     * another save) that would write something else than what was asked refuses instead.
     */
    private suspend fun commitPassword(store: ItemStore, ask: PasswordSave) {
        withContext(Dispatchers.IO) {
            val s = store.load()
            app.pro.update(s)
            val d = decidePassword(s, ask.target, ask.username, ask.password)
            if (d is SaveDecision.Unchanged) return@withContext
            if (d == SaveDecision.NeedsPro) throw WebAuthnException(WebAuthnException.Reason.NEEDS_PRO)
            if (d != ask.decision) throw WebAuthnException(WebAuthnException.Reason.STORE_BUSY)
            val now = SystemClock().now
            val record = when (d) {
                is SaveDecision.Update -> SaveDecision.updatedRecord(
                    SaveDecision.recordOf(s, d.itemId) ?: throw WebAuthnException(WebAuthnException.Reason.NOT_FOUND), ask.password, now,
                )
                else -> SaveDecision.newRecord(ask.target.origin, ask.username, ask.password, now, SystemRandomSource())
            }
            store.commit(SaveDecision.change(s, record))
            app.fillIndex.rebuild(store.load(), app.pro.isPro)
        }
        passwordSaved()
    }

    private fun passwordSaved() {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialResponse(result, CreatePasswordResponse())
        setResult(Activity.RESULT_OK, result)
    }

    private fun verify(info: CallingAppInfo, rpId: String?, clientDataHash: ByteArray?): VerifiedCaller =
        CallerOrigin(app.privilegedBrowsers, app.urlMatcher.rules)
            .verify(info.packageName, ProviderEntries.certs(info), ProviderEntries.origin(info, app), rpId, clientDataHash)

    companion object {
        const val UNLOCK = "app.localgatekeys.passkey.UNLOCK"
        const val GET = "app.localgatekeys.passkey.GET"
        const val PASSWORD = "app.localgatekeys.passkey.PASSWORD"
        const val CREATE = "app.localgatekeys.passkey.CREATE"
        const val ITEM = "lgk.item"
    }
}
