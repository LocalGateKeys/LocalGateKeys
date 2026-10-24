package app.localgatekeys.android.editor

import app.localgatekeys.android.detail.ItemDetailModel
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.android.vault.i
import app.localgatekeys.android.vault.s
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.Normalise
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Port of `ios/LocalGateKeysTests/EditorKindsTests.swift`: create, reopen unchanged, and the non-text controls. */
class EditorKindsTest {
    private val clock = clock()

    private fun ed(store: CountingStore, kind: EditorKind, item: app.localgatekeys.android.vault.VaultItem? = null) =
        editor(store, item, kind, { false }, clock)

    /** One valid form per new kind. */
    private val samples: Map<EditorKind, Map<String, String>> = mapOf(
        EditorKind.BANK_ACCOUNT to mapOf(
            "title" to "Everyday", "bank" to "Bank", "account_holder" to "Ann", "account_number" to "ch93 0076 2011 6238 5295 7",
            "routing" to "ubswchzh80a", "pin" to "1234",
        ),
        EditorKind.PURCHASE to mapOf("title" to "Laptop", "vendor" to "Shop", "amount_minor" to "1299.99", "currency" to "chf", "purchase_date" to "2026-01-02"),
        EditorKind.SUBSCRIPTION to mapOf("title" to "Music", "amount_minor" to "10,99", "currency" to "EUR", "renewal_date" to "2026-11-01"),
        EditorKind.WARRANTY to mapOf("title" to "Fridge", "expiration_date" to "2028-01-01"),
        EditorKind.WIFI to mapOf("title" to "Home", "ssid" to "DemoNet", "password" to "pw", "security" to "wpa3", "hidden" to "true"),
        EditorKind.LICENSE to mapOf("title" to "Editor", "license_value" to "AAAA-BBBB", "purchase_date" to "2026-01-01", "expiration_date" to "2027-01-01"),
        EditorKind.API_KEY to mapOf("title" to "Weather", "service" to "Weather", "key" to "k", "secret" to "s", "expires" to "2027-12-31"),
        EditorKind.SSH_KEY to mapOf(
            "title" to "Laptop key",
            "private_key" to "-----BEGIN OPENSSH PRIVATE KEY-----\nAA==\n-----END OPENSSH PRIVATE KEY-----",
            "public_key" to "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ann@laptop",
        ),
        EditorKind.BOOKMARK to mapOf("title" to "Docs", "url" to "https://example.com/docs"),
    )

    @Test fun every_phone_item_kind_but_passkey_has_an_editor() {
        for (kind in Normalise.phoneItemKinds - "passkey") assertNotNull(kind, EditorKind.of(kind))
        assertNull(EditorKind.of("document"))
        assertNull(EditorKind.of("desktop"))
        assertEquals("every kind is in the menu once", EditorKind.entries.toSet(), EditorKind.menuSections.flatten().toSet())
        assertEquals(EditorKind.entries.size, EditorKind.menuSections.flatten().size)
    }

    @Test fun each_new_kind_saves_and_reopens_unchanged() {
        for ((kind, form) in samples) {
            val store = CountingStore(snapshot(emptyList()))
            val e = ed(store, kind)
            for ((k, v) in form) e.set(k, v)
            assertEquals("$kind: ${e.error}", SaveResult.SAVED, e.save())
            val item = items(store).first()
            assertEquals(kind.raw, item.kind)
            val again = ed(store, kind, item)
            assertEquals("$kind: opening and saving changes nothing", SaveResult.UNCHANGED, again.save())
            assertEquals("$kind", 1, store.commits)
        }
    }

    private fun payload(kind: EditorKind): Map<String, JsonValue> {
        val store = CountingStore(snapshot(emptyList()))
        val e = ed(store, kind)
        for ((k, v) in samples.getValue(kind)) e.set(k, v)
        assertEquals(e.error, SaveResult.SAVED, e.save())
        return items(store).first().record.getValue("payload").obj().fields
    }

    @Test fun saved_payloads_match_the_desktop_shape() {
        val bank = payload(EditorKind.BANK_ACCOUNT)
        assertEquals(s("CH9300762011623852957"), bank["account_number"])
        assertEquals(s("iban"), bank["number_format"])
        assertEquals(s("UBSWCHZH80A"), bank["routing"])
        val purchase = payload(EditorKind.PURCHASE)
        assertEquals(i(129_999), purchase["amount_minor"])
        assertEquals(s("CHF"), purchase["currency"])
        assertEquals(JsonValue.Bool(true), purchase["active"])
        assertEquals(i(1099), payload(EditorKind.SUBSCRIPTION)["amount_minor"])
        val wifi = payload(EditorKind.WIFI)
        assertEquals(JsonValue.Bool(true), wifi["hidden"])
        assertEquals(s("wpa3"), wifi["security"])
        val ssh = payload(EditorKind.SSH_KEY)
        assertEquals(s("openssh"), ssh["key_format"])
        assertTrue((ssh["fingerprint"] as JsonValue.Str).v.startsWith("SHA256:"))
    }

    @Test fun no_amount_saves_neither_amount_nor_currency() {
        val store = CountingStore(snapshot(emptyList()))
        val e = ed(store, EditorKind.WARRANTY)
        e.set("title", "Fridge"); e.set("currency", "EUR")
        assertEquals(e.error, SaveResult.SAVED, e.save())
        val p = items(store).first().record.getValue("payload").obj().fields
        assertEquals(i(0), p["amount_minor"])
        assertEquals("the desktop's empty amount", s("XXX"), p["currency"])
        val reopened = ed(store, EditorKind.WARRANTY, items(store)[0])
        assertEquals("", reopened.value("amount_minor"))
        assertEquals("", reopened.value("currency"))
    }

    @Test fun a_whitespace_only_amount_is_no_amount() {
        // Swift `.whitespaces`: a no-break space (or any Zs) alone is blank, so neither amount nor currency is saved.
        val store = CountingStore(snapshot(emptyList()))
        val e = ed(store, EditorKind.WARRANTY)
        e.set("title", "Fridge"); e.set("currency", "EUR"); e.set("amount_minor", "  	")
        assertEquals(e.error, SaveResult.SAVED, e.save())
        val p = items(store).first().record.getValue("payload").obj().fields
        assertEquals(i(0), p["amount_minor"])
        assertEquals(s("XXX"), p["currency"])
    }

    @Test fun bad_amount_is_an_inline_error() {
        val store = CountingStore(snapshot(emptyList()))
        val e = ed(store, EditorKind.PURCHASE)
        e.set("title", "x"); e.set("currency", "EUR"); e.set("amount_minor", "1.999")
        assertEquals(SaveResult.INVALID, e.save())
        assertEquals("Use at most 2 decimals.", e.amountError)
        assertEquals("Check the amount.", e.error)
        e.set("amount_minor", "1.99")
        assertNull(e.amountError)
        assertEquals(0, store.commits)
    }

    @Test fun amount_conversion() {
        assertEquals(1250L, Amount.minorUnits("12.5", "EUR"))
        assertEquals(-300L, Amount.minorUnits("-3", "USD"))
        assertEquals(50L, Amount.minorUnits(".5", "EUR"))
        assertEquals(1500L, Amount.minorUnits("1500", "JPY"))
        assertEquals(1299L, Amount.minorUnits(" 12,99 ", "EUR"))
        assertEquals(0L, Amount.minorUnits("  ", "EUR"))
        assertEquals("This currency has no decimals.", assertThrows(AmountException::class.java) { Amount.minorUnits("1.5", "JPY") }.message)
        for (bad in listOf("abc", ".", "1.2.3", "-", "１２")) {
            assertEquals(bad, "Enter the amount as a number, for example 12.99.", assertThrows(AmountException::class.java) { Amount.minorUnits(bad, "EUR") }.message)
        }
        assertEquals("This amount is too large.", assertThrows(AmountException::class.java) { Amount.minorUnits("99999999999999999", "EUR") }.message)
        assertEquals(129_999L * 1, Amount.minorUnits("1299.99", "CHF"))
        assertEquals("1299.99", Amount.text(129_999, "CHF"))
        assertEquals("0.05", Amount.text(5, "EUR"))
        assertEquals("-15.00", Amount.text(-1500, "EUR"))
        assertEquals("1500", Amount.text(1500, "JPY"))
        // Round trip: what the editor shows parses back to the stored minor units.
        for ((minor, code) in listOf(129_999L to "CHF", 5L to "EUR", -1500L to "EUR", 1500L to "JPY")) {
            assertEquals(minor, Amount.minorUnits(Amount.text(minor, code), code))
        }
    }

    @Test fun local_currency_is_the_locale_code_or_empty() {
        assertEquals("CHF", Amount.localCurrency(java.util.Locale.forLanguageTag("de-CH")))
        assertEquals("JPY", Amount.localCurrency(java.util.Locale.JAPAN))
        assertEquals("", Amount.localCurrency(java.util.Locale.ENGLISH))
    }

    @Test fun bad_iban_is_refused() {
        val store = CountingStore(snapshot(emptyList()))
        val e = ed(store, EditorKind.BANK_ACCOUNT)
        e.set("title", "x"); e.set("account_number", "CH9400762011623852957")
        assertEquals(SaveResult.INVALID, e.save())
        assertEquals("IBAN failed its checksum", e.error)
    }

    @Test fun detail_shows_amount_dates_and_flags_readably() {
        val store = CountingStore(snapshot(emptyList()))
        val e = ed(store, EditorKind.WIFI)
        for ((k, v) in samples.getValue(EditorKind.WIFI)) e.set(k, v)
        assertEquals(SaveResult.SAVED, e.save())
        val wifi = ItemDetailModel.fields(items(store)[0])
        assertEquals("WPA3", wifi.first { it.id == "security" }.value)
        assertEquals("Yes", wifi.first { it.id == "hidden" }.value)
        assertEquals(true, wifi.first { it.id == "password" }.isSecret)
        val s2 = CountingStore(snapshot(emptyList()))
        val p = ed(s2, EditorKind.SUBSCRIPTION)
        for ((k, v) in samples.getValue(EditorKind.SUBSCRIPTION)) p.set(k, v)
        assertEquals(SaveResult.SAVED, p.save())
        val sub = ItemDetailModel.fields(items(s2)[0])
        assertEquals("Yes", sub.first { it.id == "active" }.value)
        val amount = sub.first { it.id == "amount_minor" }.value
        assertTrue(amount, amount.contains("10.99") || amount.contains("10,99"))
        assertFalse(sub.any { it.id == "currency" || it.id == "template_id" || it.id == "document_ids" })
    }

    @Test fun wifi_choices_and_defaults() {
        val security = EditorKind.WIFI.fields.first { it.key == "security" }
        assertEquals(EditorKind.Control.Choice(Normalise.wifiSecurityTypes), security.control)
        assertEquals("None (open)", EditorKind.choiceLabel("none"))
        assertEquals("WPA2 Enterprise", EditorKind.choiceLabel("wpa2-enterprise"))
        assertEquals("wpa9", EditorKind.choiceLabel("wpa9"))
        assertEquals(mapOf("security" to "wpa2"), EditorKind.WIFI.defaults())
        assertEquals(mapOf("active" to "true", "currency" to "EUR"), EditorKind.PURCHASE.defaults(java.util.Locale.GERMANY))
        assertEquals(emptyMap<String, String>(), EditorKind.NOTE.defaults())
        assertEquals("New wi-fi network", EditorScreenText.title(EditorKind.WIFI, isNew = true))
        assertEquals("Edit website login", EditorScreenText.title(EditorKind.WEB, isNew = false))
    }

    @Test fun iso_dates_for_the_date_fields() {
        assertEquals(java.time.LocalDate.of(2026, 1, 2), IsoDate.parse("2026-01-02"))
        assertNull(IsoDate.parse("2026-02-30"))
        assertNull(IsoDate.parse("2026-W05-1"))
        assertNull(IsoDate.parse("2026-1-2"))
        assertEquals("2027-01-15", IsoDate.today(app.localgatekeys.android.unlock.TestClock(1_800_000_000)))
        val day = java.time.LocalDate.of(2026, 11, 1)
        assertEquals("2026-11-01", IsoDate.fromUtcMillis(IsoDate.utcMillis(day)))
        assertEquals("•••••••• (3 lines)", EditorScreenText.hiddenLines("a\nb\n\nc"))
    }
}
