package app.localgatekeys.android.detail

import app.localgatekeys.android.editor.Amount
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.editor.WifiSecurity
import app.localgatekeys.android.vault.TotpState
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.passkey.PasskeyRecord
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.primitives.UnixClock
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.time.format.ResolverStyle
import java.util.Locale
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** One row of the detail screen. [value] can be a secret: [toString] leaves it out. */
data class DetailField(val id: String, val label: String, val value: String, val isSecret: Boolean) {
    val isMultiline: Boolean get() = value.contains("\n")

    override fun toString(): String = "DetailField(id=$id, label=$label, isSecret=$isSecret)"
}

/**
 * Item detail: the fields to show, reveal state, copy, and the two-factor code and ring. A port of
 * `ios/App/Detail/ItemDetailModel.swift`. Main thread only.
 *
 * [concealSecrets] false ("Hide passwords until tapped" off): protected fields start revealed.
 */
class ItemDetailModel(
    val item: VaultItem,
    private val clock: UnixClock,
    private val clipboard: SecretClipboard,
    concealSecrets: Boolean = true,
) {
    val fields: List<DetailField> = fields(item)

    private val _revealed = MutableStateFlow(if (concealSecrets) emptySet() else fields.filter { it.isSecret }.map { it.id }.toSet())
    val revealed: StateFlow<Set<String>> = _revealed.asStateFlow()

    private val _totp = MutableStateFlow<TotpState?>(null)
    /** The code now and the time left in its period; null when the item has no usable secret. */
    val totp: StateFlow<TotpState?> = _totp.asStateFlow()

    private val _lastCopied = MutableStateFlow<String?>(null)
    /** The label of the last thing copied ("Password", "Code"), for the footnote. */
    val lastCopied: StateFlow<String?> = _lastCopied.asStateFlow()

    init {
        tick()
    }

    fun displayValue(field: DetailField): String = if (field.isSecret && field.id !in _revealed.value) MASK else field.value

    fun isRevealed(field: DetailField): Boolean = field.id in _revealed.value

    fun toggleReveal(field: DetailField) {
        val r = _revealed.value
        _revealed.value = if (field.id in r) r - field.id else r + field.id
    }

    fun copy(field: DetailField) {
        clipboard.copy(field.value)
        _lastCopied.value = field.label
    }

    /** True when there was a code to copy. */
    fun copyTotp(): Boolean {
        val code = _totp.value?.code ?: return false
        clipboard.copy(code)
        _lastCopied.value = "Code"
        return true
    }

    /** Recomputes the code; the screen calls this once a second. */
    fun tick() {
        _totp.value = TotpState.of(item, clock.now)
    }

    /** Never shows field values, the code or the item's record. */
    override fun toString(): String = "ItemDetailModel(item=$item, fields=${fields.size}, revealed=${_revealed.value.size})"

    companion object {
        const val MASK = "••••••••"

        /** Desktop `PROTECTED_FIELD_LABELS`: the payload fields the editor masks, in order. */
        val maskedPayloadFields: Map<String, List<Pair<String, String>>> = mapOf(
            "card" to listOf("number" to "Card number", "cvv" to "CVV", "pin" to "PIN"),
            "bank_account" to listOf("account_number" to "IBAN / account number", "pin" to "PIN"),
            "ssh_key" to listOf("private_key" to "Private key", "passphrase" to "Passphrase"),
            "api_key" to listOf("key" to "Key", "secret" to "Secret"),
            "wifi" to listOf("password" to "Password"),
            "passkey" to listOf("private_key" to "Private key"), // never shown: passkeys take the passkeyFields path
            "license" to listOf("license_value" to "License key / serial"),
        )

        /** Payload keys never listed: bookkeeping, or shown through another row (currency with the amount). */
        val hiddenPayloadKeys: Set<String> = setOf("fields", "template_id", "document_ids", "last4", "number_format", "currency")
        val dateKeys: Set<String> = setOf("purchase_date", "expiration_date", "renewal_date", "expires")
        val labelOverrides: Map<String, String> = mapOf(
            "url" to "URL", "ssid" to "Network name", "routing" to "Routing number / BIC", "license_value" to "License key",
            "hidden" to "Hidden network", "key_format" to "Key format", "job_title" to "Job title",
        )

        fun label(key: String): String = labelOverrides[key] ?: VaultItem.kindLabel(key)

        /** Kinds the phone cannot edit (desktop logins, documents): the detail screen offers Delete only. */
        fun offersDeleteOnly(kind: String): Boolean = EditorKind.of(kind) == null && kind != "passkey"

        private fun JsonValue?.str(): String? = (this as? JsonValue.Str)?.v

        fun fields(item: VaultItem): List<DetailField> {
            val r = item.record
            val out = mutableListOf<DetailField>()
            fun add(id: String, label: String, value: String?, secret: Boolean = false) {
                if (!value.isNullOrEmpty()) out.add(DetailField(id, label, value, secret))
            }
            if (item.isLogin) {
                add("username", "Username", item.username)
                add("password", "Password", r["password"].str(), secret = true)
                add("target", if (item.kind == "web") "Website" else "Application", item.target)
                add("notes", "Notes", r["notes"].str())
                return out
            }
            if (item.kind == "passkey") return passkeyFields(item)
            val payload = (r["payload"] as? JsonValue.Obj)?.fields ?: emptyMap()
            val masked = maskedPayloadFields[item.kind] ?: emptyList()
            val maskedKeys = masked.map { it.first }.toSet()
            for ((key, label) in masked) add(key, label, payload[key].str(), secret = true)
            for (key in payload.keys.sortedWith(Scalars::compare)) {
                if (key in maskedKeys || key in hiddenPayloadKeys) continue
                val v = payload[key]
                when {
                    // A Wi-Fi network is shown as hidden only when it is; "Active" always says which.
                    v is JsonValue.Bool -> if (key != "hidden" || v.v) add(key, label(key), if (v.v) "Yes" else "No")
                    v is JsonValue.Int && key == "amount_minor" -> {
                        val code = payload["currency"].str() ?: "XXX"
                        if (v.v != 0L || code != "XXX") add(key, "Amount", Amount.display(v.v, code))
                    }
                    v is JsonValue.Str && key == "security" -> add(key, "Security", WifiSecurity.label(v.v))
                    v is JsonValue.Str && key in dateKeys -> add(key, label(key), displayDate(v.v))
                    else -> add(key, label(key), v.str())
                }
            }
            val custom = (payload["fields"] as? JsonValue.Arr)?.items ?: emptyList()
            for ((i, f) in custom.withIndex()) {
                val o = (f as? JsonValue.Obj)?.fields ?: continue
                add("field-$i", o["name"].str() ?: "Field", o["value"].str(), secret = o["hidden"] == JsonValue.Bool(true))
            }
            return out
        }

        private val isoDay: DateTimeFormatter =
            DateTimeFormatter.ofPattern("uuuu-MM-dd", Locale.ROOT).withResolverStyle(ResolverStyle.STRICT)

        /** "2026-12-31" in the person's medium date style (UTC); anything else (an ISO week date) as stored. */
        fun displayDate(iso: String, locale: Locale = Locale.getDefault()): String {
            val d = try {
                LocalDate.parse(iso, isoDay)
            } catch (_: Exception) {
                return iso
            }
            if (d.format(isoDay) != iso) return iso
            return DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withLocale(locale).withZone(ZoneOffset.UTC).format(d)
        }

        /**
         * Site, user, created date and whether it can sign in. Never the private key, credential id or user handle:
         * nothing here is secret, so nothing can be revealed or copied that would let someone sign in.
         */
        fun passkeyFields(item: VaultItem): List<DetailField> {
            val payload = (item.record["payload"] as? JsonValue.Obj)?.fields ?: emptyMap()
            val out = mutableListOf<DetailField>()
            fun add(id: String, label: String, value: String?) {
                if (!value.isNullOrEmpty()) out.add(DetailField(id, label, value, false))
            }
            add("relying_party_id", "Website", payload["relying_party_id"].str())
            add("user_name", "User", payload["user_name"].str())
            add("created", "Created", payload["created"].str())
            val usable = PasskeyRecord.from(JsonValue.Obj(item.record), item.id)?.key != null
            add("status", "Status", if (usable) "Can sign in" else "Backup only")
            add("notes", "Notes", payload["notes"].str())
            return out
        }
    }
}
