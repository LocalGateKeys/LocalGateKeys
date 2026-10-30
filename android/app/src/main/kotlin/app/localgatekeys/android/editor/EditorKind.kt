package app.localgatekeys.android.editor

import androidx.annotation.StringRes
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import java.util.Locale

/**
 * The kinds the phone edits field by field: the phone kinds (core `Normalise.phoneEntryKinds` + `phoneItemKinds`)
 * that have a case here. `passkey` is a phone kind (autofill creates it) but has no case: it is only renamed or
 * deleted ([PasskeyRenameModel]). Desktop logins and documents stay desktop-only. Port of `EditorKind` in
 * `ios/App/Editor/EditorModel.swift`.
 */
enum class EditorKind(val raw: String, @StringRes val newTitle: Int, @StringRes val editTitle: Int) {
    WEB("web", R.string.login_editor_new_website, R.string.typed_title_edit_web), NOTE("note", R.string.typed_title_new_note, R.string.typed_title_edit_note), CARD("card", R.string.typed_title_new_card, R.string.typed_title_edit_card), IDENTITY("identity", R.string.typed_title_new_identity, R.string.typed_title_edit_identity),
    BANK_ACCOUNT("bank_account", R.string.typed_title_new_bank_account, R.string.typed_title_edit_bank_account), PURCHASE("purchase", R.string.typed_title_new_purchase, R.string.typed_title_edit_purchase), SUBSCRIPTION("subscription", R.string.typed_title_new_subscription, R.string.typed_title_edit_subscription), WARRANTY("warranty", R.string.typed_title_new_warranty, R.string.typed_title_edit_warranty),
    WIFI("wifi", R.string.editor_new_wifi, R.string.editor_edit_wifi), LICENSE("license", R.string.typed_title_new_license, R.string.typed_title_edit_license), API_KEY("api_key", R.string.typed_title_new_api_key, R.string.typed_title_edit_api_key), SSH_KEY("ssh_key", R.string.typed_title_new_ssh_key, R.string.typed_title_edit_ssh_key), BOOKMARK("bookmark", R.string.typed_title_new_bookmark, R.string.typed_title_edit_bookmark),
    ;

    val ns: Namespace get() = if (this == WEB) Namespace.ENTRY else Namespace.ITEM
    fun label(t: Txt): String = VaultItem.kindLabel(raw, t)
    val isPurchaseLike: Boolean get() = this == PURCHASE || this == WARRANTY || this == SUBSCRIPTION

    enum class Keyboard { TEXT, URL, EMAIL, NUMBER, PHONE, DECIMAL }

    /** `TOGGLE` values are "true"/"false"; `DATE` values are ISO `YYYY-MM-DD`; `AMOUNT` is a decimal in the major unit. */
    sealed interface Control {
        data object Text : Control
        data object Toggle : Control
        data class Choice(val options: List<String>) : Control
        data object Date : Control
        data object Amount : Control
    }

    enum class Caps { NONE, WORDS, SENTENCES, CHARACTERS }

    /** One form field: [key] is `label`/`title` or the record or payload key it edits. [hint] is a line under it. */
    data class Field(
        val key: String,
        @StringRes val label: Int,
        val secret: Boolean = false,
        val multiline: Boolean = false,
        val keyboard: Keyboard = Keyboard.TEXT,
        val control: Control = Control.Text,
        val caps: Caps = Caps.NONE,
        @StringRes val hint: Int? = null,
    ) {
        fun label(t: Txt): String = t.s(label)
        fun hint(t: Txt): String? = hint?.let { t.s(it) }
    }

    /** A normaliser message ("label cannot be empty") with the field's on-screen name ("Title can't be empty"). */
    /** The message may lead with up to two words ("item title", "card number"); the longest key wins. */
    fun friendlyError(detail: String, t: Txt): String {
        val words = detail.split(" ")
        var best: Triple<String, String, Int>? = null
        for (f in fields) {
            val name = f.key.replace("_", " ")
            for (skip in 0..minOf(2, words.size)) {
                val tail = words.drop(skip).joinToString(" ")
                if (!tail.startsWith("$name ") || name.length <= (best?.third ?: 0)) continue
                best = Triple(f.label(t), tail.substring(name.length), name.length)
            }
        }
        val (label, rest) = best ?: return detail
        return label + rest.replace(" cannot ", " can't ")
    }

    val fields: List<Field>
        get() = when (this) {
            WEB -> listOf(
                title("label"), Field("origin", R.string.detail_pane_website, keyboard = Keyboard.URL),
                Field("username", R.string.detail_pane_username, keyboard = Keyboard.EMAIL), Field("password", R.string.detail_pane_password, secret = true),
                Field("totp", R.string.field_totp, secret = true), notes,
            )
            NOTE -> listOf(title(), Field("body", R.string.field_note, multiline = true, caps = Caps.SENTENCES))
            CARD -> listOf(
                title(), words("cardholder", R.string.typed_field_card_cardholder),
                Field("number", R.string.typed_field_card_number_short, secret = true, keyboard = Keyboard.NUMBER),
                Field("expiry", R.string.field_expiry_mm_yy), Field("cvv", R.string.typed_field_card_cvv, secret = true, keyboard = Keyboard.NUMBER),
                Field("pin", R.string.login_editor_chip_pin, secret = true, keyboard = Keyboard.NUMBER), notes,
            )
            IDENTITY -> listOf(
                title(), words("name", R.string.typed_identity_name),
                Field("email", R.string.typed_identity_email, keyboard = Keyboard.EMAIL), Field("phone", R.string.typed_identity_phone, keyboard = Keyboard.PHONE),
                words("organization", R.string.typed_identity_organization), words("job_title", R.string.typed_identity_job_title),
                words("address_line1", R.string.typed_identity_address_line1), words("address_line2", R.string.typed_identity_address_line2),
                words("city", R.string.typed_identity_city), words("state", R.string.field_state_region),
                Field("postal_code", R.string.typed_identity_postal_code, caps = Caps.CHARACTERS), words("country", R.string.typed_identity_country),
            )
            BANK_ACCOUNT -> listOf(
                title(), words("bank", R.string.typed_field_bank_account_bank), words("account_holder", R.string.typed_field_bank_account_account_holder),
                Field(
                    "account_number", R.string.typed_field_bank_account_account_number_short, secret = true, caps = Caps.CHARACTERS,
                    hint = R.string.hint_iban,
                ),
                Field("routing", R.string.typed_field_bank_account_routing, caps = Caps.CHARACTERS),
                Field("pin", R.string.login_editor_chip_pin, secret = true, keyboard = Keyboard.NUMBER), notes,
            )
            PURCHASE, WARRANTY, SUBSCRIPTION -> listOf(
                title(), words("product", R.string.typed_field_license_product), words("vendor", R.string.typed_field_license_vendor), words("provider", R.string.typed_field_purchase_provider),
                Field("amount_minor", R.string.typed_field_purchase_amount_minor, keyboard = Keyboard.DECIMAL, control = Control.Amount),
                Field("currency", R.string.typed_field_purchase_currency_short, caps = Caps.CHARACTERS, hint = R.string.hint_currency),
                date("purchase_date", R.string.typed_field_license_purchase_date_short), date("renewal_date", R.string.typed_field_purchase_renewal_date_short),
                date("expiration_date", R.string.typed_field_license_expiration_date_short), Field("active", R.string.typed_field_purchase_active, control = Control.Toggle), notes,
            )
            WIFI -> listOf(
                title(), Field("ssid", R.string.typed_field_wifi_ssid), Field("password", R.string.detail_pane_password, secret = true),
                Field("security", R.string.field_security, control = Control.Choice(Normalise.wifiSecurityTypes)),
                Field("hidden", R.string.typed_field_wifi_hidden, control = Control.Toggle), notes,
            )
            LICENSE -> listOf(
                title(), words("product", R.string.typed_field_license_product), words("vendor", R.string.typed_field_license_vendor),
                Field("license_value", R.string.typed_field_license_license_value_short, secret = true),
                date("purchase_date", R.string.typed_field_license_purchase_date_short), date("expiration_date", R.string.typed_field_license_expiration_date_short), notes,
            )
            API_KEY -> listOf(
                title(), words("service", R.string.typed_field_api_key_service), Field("key", R.string.typed_field_api_key_key, secret = true),
                Field("secret", R.string.typed_field_api_key_secret, secret = true), date("expires", R.string.typed_field_api_key_expires_short), notes,
            )
            SSH_KEY -> listOf(
                title(), Field("private_key", R.string.typed_field_passkey_private_key, secret = true, multiline = true),
                Field(
                    "public_key", R.string.typed_field_ssh_key_public_key_short, multiline = true,
                    hint = R.string.hint_public_key,
                ),
                Field("passphrase", R.string.generator_passphrase, secret = true), Field("fingerprint", R.string.typed_field_ssh_key_fingerprint), notes,
            )
            BOOKMARK -> listOf(title(), Field("url", R.string.field_url, keyboard = Keyboard.URL, hint = R.string.hint_bookmark_url), notes)
        }

    /** What a new item of this kind starts with ([locale] gives the purchase-like kinds their currency). */
    fun defaults(locale: Locale = Locale.getDefault()): Map<String, String> = when (this) {
        WIFI -> mapOf("security" to "wpa2")
        PURCHASE, WARRANTY, SUBSCRIPTION -> mapOf("active" to "true", "currency" to Amount.localCurrency(locale))
        else -> emptyMap()
    }

    companion object {
        /** Null for a kind the phone does not edit field by field (desktop logins, documents, passkeys, unknown). */
        fun of(kind: String): EditorKind? {
            if (kind !in Normalise.phoneEntryKinds && kind !in Normalise.phoneItemKinds) return null
            return entries.firstOrNull { it.raw == kind }
        }

        /** The New item menu, in sections. */
        val menuSections: List<List<EditorKind>> = listOf(
            listOf(WEB, NOTE, CARD, IDENTITY),
            listOf(BANK_ACCOUNT, PURCHASE, SUBSCRIPTION, WARRANTY),
            listOf(WIFI, LICENSE, API_KEY, SSH_KEY, BOOKMARK),
        )

        /** Display names for the Wi-Fi security choices. */
        fun choiceLabel(value: String, t: Txt): String = WifiSecurity.label(value, t)

        private fun title(key: String = "title") = Field(key, R.string.login_editor_title, caps = Caps.SENTENCES)
        private val notes = Field("notes", R.string.detail_pane_notes, multiline = true, caps = Caps.SENTENCES)
        private fun words(key: String, @StringRes label: Int) = Field(key, label, caps = Caps.WORDS)
        private fun date(key: String, @StringRes label: Int) = Field(key, label, control = Control.Date)
    }
}
