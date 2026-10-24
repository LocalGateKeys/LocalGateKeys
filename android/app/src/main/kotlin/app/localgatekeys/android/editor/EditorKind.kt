package app.localgatekeys.android.editor

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
enum class EditorKind(val raw: String) {
    WEB("web"), NOTE("note"), CARD("card"), IDENTITY("identity"),
    BANK_ACCOUNT("bank_account"), PURCHASE("purchase"), SUBSCRIPTION("subscription"), WARRANTY("warranty"),
    WIFI("wifi"), LICENSE("license"), API_KEY("api_key"), SSH_KEY("ssh_key"), BOOKMARK("bookmark"),
    ;

    val ns: Namespace get() = if (this == WEB) Namespace.ENTRY else Namespace.ITEM
    val label: String get() = VaultItem.kindLabel(raw)
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
        val label: String,
        val secret: Boolean = false,
        val multiline: Boolean = false,
        val keyboard: Keyboard = Keyboard.TEXT,
        val control: Control = Control.Text,
        val caps: Caps = Caps.NONE,
        val hint: String? = null,
    )

    val fields: List<Field>
        get() = when (this) {
            WEB -> listOf(
                title("label"), Field("origin", "Website", keyboard = Keyboard.URL),
                Field("username", "Username", keyboard = Keyboard.EMAIL), Field("password", "Password", secret = true),
                Field("totp", "2FA secret (TOTP)", secret = true), notes,
            )
            NOTE -> listOf(title(), Field("body", "Note", multiline = true, caps = Caps.SENTENCES))
            CARD -> listOf(
                title(), words("cardholder", "Cardholder"),
                Field("number", "Card number", secret = true, keyboard = Keyboard.NUMBER),
                Field("expiry", "Expiry (MM/YY)"), Field("cvv", "CVV", secret = true, keyboard = Keyboard.NUMBER),
                Field("pin", "PIN", secret = true, keyboard = Keyboard.NUMBER), notes,
            )
            IDENTITY -> listOf(
                title(), words("name", "Full name"),
                Field("email", "Email", keyboard = Keyboard.EMAIL), Field("phone", "Phone", keyboard = Keyboard.PHONE),
                words("organization", "Organization"), words("job_title", "Job title"),
                words("address_line1", "Address line 1"), words("address_line2", "Address line 2"),
                words("city", "City"), words("state", "State / region"),
                Field("postal_code", "Postal code", caps = Caps.CHARACTERS), words("country", "Country"),
            )
            BANK_ACCOUNT -> listOf(
                title(), words("bank", "Bank"), words("account_holder", "Account holder"),
                Field(
                    "account_number", "IBAN / account number", secret = true, caps = Caps.CHARACTERS,
                    hint = "An IBAN is checked and stored without spaces.",
                ),
                Field("routing", "Routing number / BIC", caps = Caps.CHARACTERS),
                Field("pin", "PIN", secret = true, keyboard = Keyboard.NUMBER), notes,
            )
            PURCHASE, WARRANTY, SUBSCRIPTION -> listOf(
                title(), words("product", "Product"), words("vendor", "Vendor"), words("provider", "Provider"),
                Field("amount_minor", "Amount", keyboard = Keyboard.DECIMAL, control = Control.Amount),
                Field("currency", "Currency", caps = Caps.CHARACTERS, hint = "Three letters, for example EUR or USD."),
                date("purchase_date", "Purchase date"), date("renewal_date", "Renewal date"),
                date("expiration_date", "Expiration date"), Field("active", "Active", control = Control.Toggle), notes,
            )
            WIFI -> listOf(
                title(), Field("ssid", "Network name (SSID)"), Field("password", "Password", secret = true),
                Field("security", "Security", control = Control.Choice(Normalise.wifiSecurityTypes)),
                Field("hidden", "Hidden network", control = Control.Toggle), notes,
            )
            LICENSE -> listOf(
                title(), words("product", "Product"), words("vendor", "Vendor"),
                Field("license_value", "License key / serial", secret = true),
                date("purchase_date", "Purchase date"), date("expiration_date", "Expiration date"), notes,
            )
            API_KEY -> listOf(
                title(), words("service", "Service"), Field("key", "Key", secret = true),
                Field("secret", "Secret", secret = true), date("expires", "Expires"), notes,
            )
            SSH_KEY -> listOf(
                title(), Field("private_key", "Private key", secret = true, multiline = true),
                Field(
                    "public_key", "Public key", multiline = true,
                    hint = "An OpenSSH line (ssh-ed25519 AAAA…). The fingerprint is worked out from it.",
                ),
                Field("passphrase", "Passphrase", secret = true), Field("fingerprint", "Fingerprint"), notes,
            )
            BOOKMARK -> listOf(title(), Field("url", "URL", keyboard = Keyboard.URL, hint = "http:// or https://"), notes)
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
        fun choiceLabel(value: String): String = WifiSecurity.label(value)

        private fun title(key: String = "title") = Field(key, "Title", caps = Caps.SENTENCES)
        private val notes = Field("notes", "Notes", multiline = true, caps = Caps.SENTENCES)
        private fun words(key: String, label: String) = Field(key, label, caps = Caps.WORDS)
        private fun date(key: String, label: String) = Field(key, label, control = Control.Date)
    }
}
