package app.localgatekeys.android.passkey

import app.localgatekeys.android.R
import androidx.compose.ui.res.stringResource
import app.localgatekeys.android.i18n.AndroidTxt
import android.app.Activity
import android.content.Intent
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
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
import app.localgatekeys.android.autofill.SaveDecision
import app.localgatekeys.android.autofill.VaultGateActivity
import app.localgatekeys.android.unlock.UnlockedVault
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.ItemStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.LocalDate

/**
 * The Credential Manager sheet: unlock (or, when the vault was already open, a fresh owner check, since the
 * response claims user verification), then sign in, create, fill a password, or list entries after "Unlock".
 * Every refusal is a fixed message; nothing from the request or the vault is logged.
 */
@RequiresApi(34)
class PasskeyActivity : VaultGateActivity() {
    @Composable
    override fun Unlocked(vault: UnlockedVault) {
        var message by remember { mutableStateOf<String?>(null) }
        LaunchedEffect(vault) {
            message = try {
                run(vault)
                null
            } catch (e: WebAuthnException) {
                refusal(e.reason)
            } catch (e: Exception) {
                getString(R.string.passkey_could_not)
            }
            if (message == null) finish()
        }
        val m = message ?: return
        Column(Modifier.fillMaxWidth().safeDrawingPadding().padding(20.dp)) {
            Text(m, style = MaterialTheme.typography.bodyLarge)
            TextButton(onClick = { failAndFinish() }) { Text(stringResource(R.string.common_close)) }
        }
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

    private suspend fun run(vault: UnlockedVault) {
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
            CREATE -> create(store)
            else -> throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
        }
    }

    private suspend fun get(store: ItemStore) {
        if (!app.settings.passkeyProvider) throw WebAuthnException(WebAuthnException.Reason.PASSKEYS_OFF)
        val req = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
        val option = req.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull()
            ?: throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
        val itemId = intent.getStringExtra(ITEM) ?: throw WebAuthnException(WebAuthnException.Reason.NOT_FOUND)
        val parsed = AssertionRequest.parse(option.requestJson)
        val caller = verify(req.callingAppInfo, parsed.rpId, option.clientDataHash)
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
        val username = (record["username"] as? JsonValue.Str)?.v ?: ""
        val pw = (record["password"] as? JsonValue.Str)?.v ?: ""
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PasswordCredential(username, pw)))
        setResult(Activity.RESULT_OK, result)
    }

    private suspend fun create(store: ItemStore) {
        val req = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
        when (val call = req.callingRequest) {
            is CreatePublicKeyCredentialRequest -> {
                if (!app.settings.passkeyProvider) throw WebAuthnException(WebAuthnException.Reason.PASSKEYS_OFF)
                val parsed = CreationRequest.parse(call.requestJson)
                val caller = verify(req.callingAppInfo, parsed.rpId, call.clientDataHash)
                if (!verifyOwner()) return failAndFinish()
                val reg = withContext(Dispatchers.IO) {
                    PasskeyVault.register(
                        store, caller.rpId, parsed.rpName, parsed.userName, parsed.userDisplayName, parsed.userHandle, parsed.exclude,
                        now = SystemClock().now, today = LocalDate.now().toString(), random = SystemRandomSource(),
                        isPro = { snap -> app.pro.update(snap); app.pro.isPro },
                    )
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
                val target = ProviderEntries.passwordTarget(req.callingAppInfo, app)
                val website = (target as? FillTarget.Web)?.origin
                    ?: throw WebAuthnException(WebAuthnException.Reason.ORIGIN_REFUSED) // apps save through the autofill sheet, which asks for the website
                withContext(Dispatchers.IO) {
                    val s = store.load()
                    app.pro.update(s)
                    val matcher = FillMatcher(app.urlMatcher)
                    val index = app.fillIndex.read() ?: FillIndex.build(s)
                    val now = SystemClock().now
                    val record = when (val d = SaveDecision.decide(s, target, call.id, call.password, app.pro.isPro, matcher, index)) {
                        is SaveDecision.Update -> SaveDecision.updatedRecord(SaveDecision.recordOf(s, d.itemId)!!, call.password, now)
                        is SaveDecision.New -> SaveDecision.newRecord(website, call.id, call.password, now, SystemRandomSource())
                        is SaveDecision.Unchanged -> null
                        SaveDecision.NeedsPro -> throw WebAuthnException(WebAuthnException.Reason.NEEDS_PRO)
                    }
                    if (record != null) {
                        store.commit(SaveDecision.change(s, record))
                        app.fillIndex.rebuild(store.load())
                    }
                }
                val result = Intent()
                PendingIntentHandler.setCreateCredentialResponse(result, CreatePasswordResponse())
                setResult(Activity.RESULT_OK, result)
            }
            else -> throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
        }
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
