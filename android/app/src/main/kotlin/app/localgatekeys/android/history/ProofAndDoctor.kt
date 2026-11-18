package app.localgatekeys.android.history

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.view.autofill.AutofillManager
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.proof.PrivacyProof
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.TravelMode
import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * The privacy proof on Android (contract section 5): facts read from this vault, no claims (Android has no network
 * guard test, so `connections_listed` and `no_item_content_sent` are not allowed; `breach_prefix_only` needs a test
 * that asserts the prefix length), the network list unavailable. Signed with the sync device key; unsigned (null
 * signature) when sync is off.
 */
object PhoneProof {
    fun facts(snap: StoreSnapshot, breachChecks: Boolean, strictOffline: Boolean, travel: TravelMode.Setting = TravelMode.Setting.OFF): PrivacyProof.Facts {
        val s = snap.sync
        val shares = (snap.shares as? JsonValue.Obj)?.fields?.size ?: 0
        // Items the person can see: travel-hidden ones are not counted (as Windows, finding W-L7).
        val hidden = TravelMode.hiddenIds(snap, travel)
        val visible = if (hidden.isEmpty()) snap else snap.copy(records = snap.records.filterKeys { it !in hidden })
        return PrivacyProof.Facts(
            sync = when {
                s == null -> "off"
                // The cloud folder and Wi-Fi peers together: "both" (as Windows `privacy_page._facts`).
                s.hasFolder && s.lanPeers.isNotEmpty() -> "both"
                s.hasFolder -> "folder"
                else -> "wifi"
            },
            devices = (s?.members?.size ?: 0).toLong(),
            shares = shares.toLong(),
            items = ItemLimit.liveCount(visible).toLong(),
            breachChecks = breachChecks,
            strictOffline = strictOffline,
            updateCheck = false,
        )
    }

    /** The signed (or unsigned) document's bytes for the export file. */
    fun build(
        snap: StoreSnapshot, version: String, breachChecks: Boolean, strictOffline: Boolean, now: Instant = Instant.now(),
        travel: TravelMode.Setting = TravelMode.Setting.OFF,
    ): ByteArray {
        val doc = PrivacyProof.document(
            now.truncatedTo(ChronoUnit.SECONDS).toString(), "android", version, facts(snap, breachChecks, strictOffline, travel), emptyList(),
        )
        return PrivacyProof.encode(PrivacyProof.sign(doc, snap.sync?.identity))
    }

    /** "Signed by this device (fingerprint)", or null when unsigned. */
    fun fingerprint(snap: StoreSnapshot): String? = snap.sync?.identity?.let { PrivacyProof.fingerprint(it.signingPublicKey) }
}

/**
 * Passkey doctor (contract section 6.2): is LocalGateKeys the selected credential provider (Android 14+) or the
 * autofill service, with a link to the system setting. Any error or an older OS reads as unknown.
 */
object PasskeyDoctor {
    enum class Status { ON, OFF, UNKNOWN }

    fun status(context: Context): Status = try {
        if (Build.VERSION.SDK_INT >= 34) {
            val cm = context.getSystemService(android.credentials.CredentialManager::class.java)
            val component = android.content.ComponentName(context, app.localgatekeys.android.passkey.LgkCredentialProviderService::class.java)
            when {
                cm == null -> Status.UNKNOWN
                cm.isEnabledCredentialProviderService(component) -> Status.ON
                else -> Status.OFF
            }
        } else {
            val am = context.getSystemService(AutofillManager::class.java)
            when {
                am == null || !am.isAutofillSupported -> Status.UNKNOWN
                am.hasEnabledAutofillServices() -> Status.ON
                else -> Status.OFF
            }
        }
    } catch (e: Exception) {
        Status.UNKNOWN
    }

    /** The system screen to choose the provider. */
    fun settingsIntent(context: Context): Intent {
        val data = Uri.parse("package:" + context.packageName)
        return if (Build.VERSION.SDK_INT >= 34) {
            Intent(Settings.ACTION_CREDENTIAL_PROVIDER).setData(data)
        } else {
            Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(data)
        }
    }
}
