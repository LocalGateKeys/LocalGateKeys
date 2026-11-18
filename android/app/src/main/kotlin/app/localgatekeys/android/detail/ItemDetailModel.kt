package app.localgatekeys.android.detail

import app.localgatekeys.core.access.AccessRules
import app.localgatekeys.android.access.CopyOnceLedger
import app.localgatekeys.android.access.AccessGate
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.editor.Amount
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.editor.WifiSecurity
import app.localgatekeys.android.vault.TotpState
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.passkey.PasskeyRecord
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.JwtInfo
import app.localgatekeys.core.records.JwtView
import app.localgatekeys.core.records.WifiQr
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
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
    private val t: Txt,
    concealSecrets: Boolean = true,
    private val copyOnce: CopyOnceLedger = CopyOnceLedger(),
    today: String = AccessGate.today(),
) {
    val fields: List<DetailField> = fields(item, t)

    /** The login's access rules on this phone (contract section 4); none for other kinds (typed items are deferred). */
    val access: AccessRules.Effective = if (item.isLogin) AccessGate.effective(item.record, today) else AccessRules.NONE

    private val _revealed = MutableStateFlow(if (concealSecrets || access.reauth || access.phoneView) emptySet() else fields.filter { it.isSecret }.map { it.id }.toSet())
    val revealed: StateFlow<Set<String>> = _revealed.asStateFlow()

    private val _codeRevealed = MutableStateFlow(AccessGate.reveal(access) == AccessGate.Need.NOTHING)
    /**
     * Whether the one-time code is shown. A login whose rules ask for the owner before a reveal (re-authenticate, view
     * only on phones, an unknown rule) starts with the code hidden, exactly like its password.
     */
    val codeRevealed: StateFlow<Boolean> = _codeRevealed.asStateFlow()

    /** What showing the code needs first (hiding never needs anything). */
    fun codeRevealNeed(): AccessGate.Need = if (_codeRevealed.value) AccessGate.Need.NOTHING else AccessGate.reveal(access)

    /** The code as the screen draws it: [MASK] while hidden. */
    fun displayCode(): String? = _totp.value?.code?.let { if (_codeRevealed.value) it else MASK }

    /** Shows or hides the code; the caller checks [codeRevealNeed] first. */
    fun toggleCodeReveal() {
        _codeRevealed.value = !_codeRevealed.value
    }

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

    /** What showing [field] needs first (hiding never needs anything). */
    fun revealNeed(field: DetailField): AccessGate.Need =
        if (!field.isSecret || field.id in _revealed.value) AccessGate.Need.NOTHING else AccessGate.reveal(access)

    /** What a copy of one of this item's secrets needs first ([copy] and [copyTotp] after the owner's check). */
    fun copyNeed(): AccessGate.Need = AccessGate.copy(access, copyOnce.copiedBefore(item.id))

    /**
     * Copies the old password at [index] of the login's password history, the same way as the current one (copy
     * once: 10 seconds and noted). The caller checks [copyNeed] first, exactly as for the current password.
     */
    fun copyHistoryPassword(index: Int): Boolean {
        val old = app.localgatekeys.core.records.PasswordHistory.entries(item.record).getOrNull(index) ?: return false
        copySecret(old.password)
        return true
    }

    private fun copySecret(text: String) {
        if (access.copyOnce) {
            clipboard.copy(text, AccessGate.COPY_ONCE_SECONDS)
            copyOnce.note(item.id)
        } else {
            clipboard.copy(text)
        }
    }

    fun toggleReveal(field: DetailField) {
        val r = _revealed.value
        _revealed.value = if (field.id in r) r - field.id else r + field.id
    }

    private val wifiPayload: Map<String, JsonValue>
        get() = (item.record["payload"] as? JsonValue.Obj)?.fields ?: emptyMap()

    private val wifiSecurity: String get() = wifiPayload["security"].str() ?: "wpa2"

    /** A Wi-Fi item whose security type a plain QR can express: "Show QR" is offered. */
    val offersWifiQr: Boolean
        get() = item.kind == "wifi" && WifiQr.text("", "", wifiSecurity, false) != null

    /** A Wi-Fi item of a type a QR cannot carry (enterprise): the screen explains instead of offering the button. */
    val isWifiEnterprise: Boolean
        get() = item.kind == "wifi" && WifiQr.text("", "", wifiSecurity, false) == null

    /**
     * The QR text, only while the password is revealed (showing the QR needs the same permission as revealing the
     * password); an open network has no password and needs no reveal. Null for enterprise and other kinds.
     */
    fun wifiQrText(): String? {
        if (!offersWifiQr) return null
        if (fields.any { it.id == "password" && it.id !in _revealed.value }) return null
        val p = wifiPayload
        return WifiQr.text(p["ssid"].str() ?: "", p["password"].str() ?: "", wifiSecurity, (p["hidden"] as? JsonValue.Bool)?.v == true)
    }

    /**
     * The decoded JWT of a revealed API-key value (`key`, `secret`), or null: other kinds, a hidden value, or a value
     * that is not a token. The signature is never checked. A hidden value is never decoded.
     */
    fun token(field: DetailField): JwtInfo? {
        if (item.kind != "api_key" || field.id != "key" && field.id != "secret") return null
        if (!field.isSecret || field.id !in _revealed.value) return null
        return JwtView.decode(field.value)
    }

    fun tokenExpired(info: JwtInfo): Boolean = info.expired(clock.now)

    /** A token time as a local date and time. */
    fun tokenTime(seconds: Long, locale: Locale = Locale.getDefault(), zone: ZoneId = ZoneId.systemDefault()): String =
        DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT).withLocale(locale).withZone(zone)
            .format(Instant.ofEpochSecond(seconds))

    /** "Set expiry from token": the token has an `exp` and the item has no expiry yet. */
    fun canSetExpiryFrom(info: JwtInfo): Boolean = info.expires != null && fields.none { it.id == "expires" }

    /** The item's `expires` value for [info]: the token's local date, `YYYY-MM-DD`. Null without an `exp`. */
    fun expiryDate(info: JwtInfo, zone: ZoneId = ZoneId.systemDefault()): String? =
        info.expires?.let { Instant.ofEpochSecond(it).atZone(zone).toLocalDate().toString() }

    fun copy(field: DetailField) {
        if (field.isSecret) copySecret(field.value) else clipboard.copy(field.value)
        _lastCopied.value = field.label
    }

    /** True when there was a code to copy. */
    fun copyTotp(): Boolean {
        val code = _totp.value?.code ?: return false
        copySecret(code)
        _lastCopied.value = t.s(R.string.detail_code)
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
        val maskedPayloadFields: Map<String, List<Pair<String, Int>>> = mapOf(
            "card" to listOf("number" to R.string.typed_field_card_number_short, "cvv" to R.string.typed_field_card_cvv, "pin" to R.string.login_editor_chip_pin),
            "bank_account" to listOf("account_number" to R.string.typed_field_bank_account_account_number_short, "pin" to R.string.login_editor_chip_pin),
            "ssh_key" to listOf("private_key" to R.string.typed_field_passkey_private_key, "passphrase" to R.string.generator_passphrase),
            "api_key" to listOf("key" to R.string.typed_field_api_key_key, "secret" to R.string.typed_field_api_key_secret),
            "wifi" to listOf("password" to R.string.detail_pane_password),
            "passkey" to listOf("private_key" to R.string.typed_field_passkey_private_key), // never shown: passkeys take the passkeyFields path
            "license" to listOf("license_value" to R.string.typed_field_license_license_value_short),
        )

        /** Payload keys never listed: bookkeeping, or shown through another row (currency with the amount). */
        val hiddenPayloadKeys: Set<String> = setOf("fields", "template_id", "document_ids", "last4", "number_format", "currency")
        val dateKeys: Set<String> = setOf("purchase_date", "expiration_date", "renewal_date", "expires")
        /** Payload keys whose row label is a known resource; any other key shows its name capitalised. */
        val labelIds: Map<String, Int> = mapOf(
            "url" to R.string.field_url, "ssid" to R.string.typed_field_wifi_ssid_short, "routing" to R.string.typed_field_bank_account_routing,
            "license_value" to R.string.detail_license_key, "hidden" to R.string.typed_field_wifi_hidden,
            "key_format" to R.string.detail_key_format, "job_title" to R.string.typed_identity_job_title,
            "product" to R.string.typed_field_license_product, "vendor" to R.string.typed_field_license_vendor, "provider" to R.string.typed_field_purchase_provider,
            "currency" to R.string.typed_field_purchase_currency_short, "active" to R.string.typed_field_purchase_active, "purchase_date" to R.string.typed_field_license_purchase_date_short,
            "renewal_date" to R.string.typed_field_purchase_renewal_date_short, "expiration_date" to R.string.typed_field_license_expiration_date_short,
            "cardholder" to R.string.typed_field_card_cardholder, "expiry" to R.string.typed_field_card_expiry_short, "name" to R.string.import_sheet_col_name,
            "email" to R.string.typed_identity_email, "phone" to R.string.typed_identity_phone, "organization" to R.string.typed_identity_organization,
            "address_line1" to R.string.typed_identity_address_line1, "address_line2" to R.string.typed_identity_address_line2,
            "city" to R.string.typed_identity_city, "state" to R.string.field_state_region, "postal_code" to R.string.typed_identity_postal_code,
            "country" to R.string.typed_identity_country, "bank" to R.string.typed_field_bank_account_bank, "account_holder" to R.string.typed_field_bank_account_account_holder,
            "service" to R.string.typed_field_api_key_service, "expires" to R.string.typed_field_api_key_expires_short, "public_key" to R.string.typed_field_ssh_key_public_key_short,
            "fingerprint" to R.string.typed_field_ssh_key_fingerprint, "body" to R.string.detail_body,
        )

        fun label(key: String, t: Txt): String = labelIds[key]?.let { t.s(it) } ?: VaultItem.kindLabel(key, t)

        /** Kinds the phone cannot edit (desktop logins, documents): the detail screen offers Delete only. */
        fun offersDeleteOnly(kind: String): Boolean = EditorKind.of(kind) == null && kind != "passkey"

        private fun JsonValue?.str(): String? = (this as? JsonValue.Str)?.v

        fun fields(item: VaultItem, t: Txt): List<DetailField> {
            val r = item.record
            val out = mutableListOf<DetailField>()
            fun add(id: String, label: String, value: String?, secret: Boolean = false) {
                if (!value.isNullOrEmpty()) out.add(DetailField(id, label, value, secret))
            }
            if (item.isLogin) {
                add("username", t.s(R.string.detail_pane_username), item.username)
                add("password", t.s(R.string.detail_pane_password), r["password"].str(), secret = true)
                add("target", t.s(if (item.kind == "web") R.string.detail_pane_website else R.string.detail_application), item.target)
                add("notes", t.s(R.string.detail_pane_notes), r["notes"].str())
                return out
            }
            if (item.kind == "passkey") return passkeyFields(item, t)
            val payload = (r["payload"] as? JsonValue.Obj)?.fields ?: emptyMap()
            val masked = maskedPayloadFields[item.kind] ?: emptyList()
            val maskedKeys = masked.map { it.first }.toSet()
            for ((key, label) in masked) add(key, t.s(label), payload[key].str(), secret = true)
            for (key in payload.keys.sortedWith(Scalars::compare)) {
                if (key in maskedKeys || key in hiddenPayloadKeys) continue
                val v = payload[key]
                when {
                    // A Wi-Fi network is shown as hidden only when it is; "Active" always says which.
                    v is JsonValue.Bool -> if (key != "hidden" || v.v) add(key, label(key, t), t.s(if (v.v) R.string.detail_pane_yes else R.string.detail_pane_no))
                    v is JsonValue.Int && key == "amount_minor" -> {
                        val code = payload["currency"].str() ?: "XXX"
                        if (v.v != 0L || code != "XXX") add(key, t.s(R.string.typed_field_purchase_amount_minor), Amount.display(v.v, code))
                    }
                    v is JsonValue.Str && key == "security" -> add(key, t.s(R.string.field_security), WifiSecurity.label(v.v, t))
                    v is JsonValue.Str && key in dateKeys -> add(key, label(key, t), displayDate(v.v))
                    else -> add(key, label(key, t), v.str())
                }
            }
            val custom = (payload["fields"] as? JsonValue.Arr)?.items ?: emptyList()
            for ((i, f) in custom.withIndex()) {
                val o = (f as? JsonValue.Obj)?.fields ?: continue
                add("field-$i", o["name"].str() ?: t.s(R.string.detail_field), o["value"].str(), secret = o["hidden"] == JsonValue.Bool(true))
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
        fun passkeyFields(item: VaultItem, t: Txt): List<DetailField> {
            val payload = (item.record["payload"] as? JsonValue.Obj)?.fields ?: emptyMap()
            val out = mutableListOf<DetailField>()
            fun add(id: String, label: String, value: String?) {
                if (!value.isNullOrEmpty()) out.add(DetailField(id, label, value, false))
            }
            add("relying_party_id", t.s(R.string.detail_pane_website), payload["relying_party_id"].str())
            add("user_name", t.s(R.string.detail_user), payload["user_name"].str())
            add("created", t.s(R.string.typed_field_passkey_created_short), payload["created"].str())
            val usable = PasskeyRecord.from(JsonValue.Obj(item.record), item.id)?.key != null
            add("status", t.s(R.string.import_sheet_col_status), t.s(if (usable) R.string.detail_can_sign_in else R.string.detail_backup_only))
            add("notes", t.s(R.string.detail_pane_notes), payload["notes"].str())
            return out
        }
    }
}
