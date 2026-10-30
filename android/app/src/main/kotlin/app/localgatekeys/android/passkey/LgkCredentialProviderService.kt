package app.localgatekeys.android.passkey

import app.localgatekeys.android.R
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePasswordCredentialRequest
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.PasswordCredentialEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import app.localgatekeys.android.LgkApp
import app.localgatekeys.android.autofill.FillIndex
import app.localgatekeys.android.autofill.FillMatcher
import app.localgatekeys.android.autofill.FillTarget
import app.localgatekeys.android.autofill.Signatures
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.unlock.AppLockModel
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.records.Origin
import java.util.concurrent.atomic.AtomicInteger

/**
 * Credential Manager provider (API 34+): passkeys (sign-in and creation, the desktop/iPhone authenticator) and vault
 * passwords. Entries carry no secret; each one opens [PasskeyActivity], which unlocks (or asks for a fresh owner check)
 * and answers. Locked: passkeys show one "Unlock LocalGateKeys" action; passwords come from the fill index.
 */
@RequiresApi(34)
class LgkCredentialProviderService : CredentialProviderService() {
    private val app: LgkApp get() = application as LgkApp

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        val response = try {
            ProviderEntries.begin(this, app, request)
        } catch (e: Exception) {
            BeginGetCredentialResponse()
        }
        callback.onResult(response)
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        val b = BeginCreateCredentialResponse.Builder()
        try {
            val offer = when (request) {
                is BeginCreatePublicKeyCredentialRequest -> app.settings.passkeyProvider && !fullWithoutPro()
                is BeginCreatePasswordCredentialRequest -> !fullWithoutPro()
                else -> false
            }
            if (offer) {
                val pi = ProviderEntries.pending(this, Intent(this, PasskeyActivity::class.java).setAction(PasskeyActivity.CREATE))
                b.addCreateEntry(CreateEntry.Builder(ACCOUNT, pi).build())
            }
        } catch (e: Exception) {
            // nothing offered: Android shows the other providers
        }
        callback.onResult(b.build())
    }

    /** Known only while unlocked; when locked the sheet re-checks after the unlock and refuses with NEEDS_PRO. */
    private fun fullWithoutPro(): Boolean {
        val vault = app.lock.vault.value ?: return false
        if (app.lock.state.value != AppLockModel.State.UNLOCKED) return false
        val s = vault.store.load()
        app.pro.update(s)
        return !app.pro.isPro && !ItemLimit.allows(ItemLimit.Action.CREATE, s, false)
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        callback.onResult(null)
    }

    companion object {
        const val ACCOUNT = "LocalGateKeys"
    }
}

/** The entry lists, shared by the service and by [PasskeyActivity] after an "Unlock" action. */
@RequiresApi(34)
object ProviderEntries {
    private val codes = AtomicInteger(5000)

    fun pending(context: Context, intent: Intent): PendingIntent =
        PendingIntent.getActivity(context, codes.incrementAndGet(), intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

    /** The caller's signing-certificate hashes. */
    fun certs(info: CallingAppInfo): List<ByteArray> = Signatures.sha256(info.signingInfo)

    /** The origin a privileged browser passed (null for apps or browsers not on the allowlist). */
    fun origin(info: CallingAppInfo, app: LgkApp): String? = try {
        info.getOrigin(app.privilegedBrowsers.json)
    } catch (e: Exception) {
        null
    }

    /** The password target: a privileged browser's page, or the app itself. */
    fun passwordTarget(info: CallingAppInfo, app: LgkApp): FillTarget {
        val o = origin(info, app)
        if (o != null && app.privilegedBrowsers.trusts(info.packageName, certs(info))) {
            try {
                return FillTarget.Web(Origin.canonicalize(o.trimEnd('/')), info.packageName)
            } catch (e: Exception) {
                // fall through: treated as the app
            }
        }
        return FillTarget.App(info.packageName, certs(info).firstOrNull()?.let { Hex.lower(it) } ?: "")
    }

    fun begin(context: Context, app: LgkApp, request: BeginGetCredentialRequest): BeginGetCredentialResponse {
        val b = BeginGetCredentialResponse.Builder()
        val info = request.callingAppInfo ?: return b.build()
        val open = app.lock.vault.value?.takeIf { app.lock.state.value == AppLockModel.State.UNLOCKED }
        var needsUnlock = false
        for (option in request.beginGetCredentialOptions) {
            when (option) {
                is BeginGetPublicKeyCredentialOption -> {
                    if (!app.settings.passkeyProvider) continue
                    if (open == null) {
                        needsUnlock = true
                        continue
                    }
                    val req = AssertionRequest.parse(option.requestJson)
                    val caller = CallerOrigin(app.privilegedBrowsers, app.urlMatcher.rules)
                        .verify(info.packageName, certs(info), origin(info, app), req.rpId, option.clientDataHash)
                    for (c in PasskeyVault.candidates(open.store.load(), caller.rpId, req.allowed)) {
                        val intent = Intent(context, PasskeyActivity::class.java).setAction(PasskeyActivity.GET).putExtra(PasskeyActivity.ITEM, c.itemId)
                        b.addCredentialEntry(
                            PublicKeyCredentialEntry.Builder(context, c.userName.ifEmpty { c.title }, pending(context, intent), option)
                                .setDisplayName(c.title)
                                .build(),
                        )
                    }
                }
                is BeginGetPasswordOption -> {
                    if (!app.settings.autofillSuggestions) {
                        needsUnlock = needsUnlock || open == null
                        continue
                    }
                    val index = app.fillIndex.read() ?: open?.let { FillIndex.build(it.store.load()) } ?: continue
                    val target = passwordTarget(info, app)
                    for (m in FillMatcher(app.urlMatcher).match(index, target).take(5)) {
                        val intent = Intent(context, PasskeyActivity::class.java).setAction(PasskeyActivity.PASSWORD).putExtra(PasskeyActivity.ITEM, m.id)
                        b.addCredentialEntry(
                            PasswordCredentialEntry.Builder(context, m.username.ifEmpty { m.title }, pending(context, intent), option)
                                .setDisplayName(m.title)
                                .build(),
                        )
                    }
                }
            }
        }
        if (needsUnlock) {
            val intent = Intent(context, PasskeyActivity::class.java).setAction(PasskeyActivity.UNLOCK)
            b.addAuthenticationAction(AuthenticationAction(context.getString(R.string.main_unlock_localgatekeys), pending(context, intent)))
        }
        return b.build()
    }
}
