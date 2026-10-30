package app.localgatekeys.android.detail

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.editor.Amount
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.unlock.ManualScheduler
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.CodeTileModel
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.card
import app.localgatekeys.android.vault.i
import app.localgatekeys.android.vault.note
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.android.vault.strs
import app.localgatekeys.android.vault.webLogin
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.json.JsonValue.Arr
import app.localgatekeys.core.json.JsonValue.Bool
import app.localgatekeys.core.json.JsonValue.Obj
import app.localgatekeys.core.passkey.PasskeyKey
import app.localgatekeys.core.passkey.PasskeyRecord
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.totp.Totp
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** A desktop-shaped passkey item (`PasskeyRecord.newPayload`), normalised. [usable] false: an RS256 import. */
fun passkeyItem(id: String = "9a550000-0000-4000-8000-000000000001", usable: Boolean = true): Obj {
    val made = PasskeyRecord.newPayload(
        rpId = "example.com", rpName = "Example", userName = "ada", userDisplayName = "Ada",
        userHandle = byteArrayOf(1, 2, 3), credentialId = ByteArray(16) { 5 },
        key = PasskeyKey.generate(), today = "2026-10-18",
    )
    val payload = LinkedHashMap((made.fields as Obj).fields)
    if (!usable) payload["algorithm"] = s("RS256")
    return Normalise.normalForm(
        Namespace.ITEM,
        rec(
            "id" to s(id), "kind" to s("passkey"), "title" to s(made.title), "payload" to Obj(payload),
            "created_at" to i(1_700_000_000), "updated_at" to i(1_700_000_100), "favorite" to Bool(false), "tags" to Arr(emptyList()),
        ),
    ) as Obj
}

/** Port of ios/LocalGateKeysTests/ItemDetailModelTests.swift, plus the per-kind field rules of the map and toString. */
class ItemDetailModelTest {
    private fun item(r: Obj): VaultItem = VaultItem.items(snapshot(listOf(r)))[0]

    private class Clip(val clock: TestClock = TestClock(0)) {
        val sink = FakeClipboardSink()
        val scheduler = ManualScheduler(clock)
        val settings = AppSettings(MemoryStore())
        val clipboard = SecretClipboard(sink, settings, scheduler, clock).also { it.focusChanged(true) }
    }

    private fun model(r: Obj, clock: TestClock = TestClock(0), clip: Clip = Clip(clock), conceal: Boolean = true) =
        ItemDetailModel(item(r), clock, clip.clipboard, EnglishTxt(), conceal)

    @Test fun test_clipboard_is_sensitive_and_expires_in_60s() {
        val clock = TestClock(1_790_000_000)
        val c = Clip(clock)
        c.clipboard.copy("s3cret")
        assertEquals(FakeClipboardSink.Write("s3cret", true), c.sink.history.single())
        assertEquals(1_790_000_060, c.scheduler.timers.single().due)
        c.scheduler.advance(60)
        assertNull(c.sink.text)
    }

    @Test fun test_login_fields_hide_password_until_revealed_and_copy_it() {
        val c = Clip()
        val m = model(webLogin, clip = c)
        val pw = m.fields.first { it.label == "Password" }
        assertTrue(pw.isSecret)
        assertEquals("••••••••", m.displayValue(pw))
        m.toggleReveal(pw); assertEquals("Maple-Orbit-7731", m.displayValue(pw))
        m.copy(pw); assertEquals("Maple-Orbit-7731", c.sink.text)
        assertEquals("Password", m.lastCopied.value)
        assertEquals(false, m.fields.first { it.label == "Username" }.isSecret)
    }

    @Test fun test_conceal_off_shows_protected_fields_at_once() {
        val m = model(webLogin, conceal = false)
        val pw = m.fields.first { it.label == "Password" }
        assertEquals("Maple-Orbit-7731", m.displayValue(pw))
        m.toggleReveal(pw); assertEquals("the eye still hides it", ItemDetailModel.MASK, m.displayValue(pw))
    }

    @Test fun test_card_protected_fields_are_masked() {
        val m = model(card)
        assertEquals(true, m.fields.first { it.label == "Card number" }.isSecret)
        assertEquals(true, m.fields.first { it.label == "CVV" }.isSecret)
    }

    @Test fun test_totp_uses_lgkcore_and_ring_reflects_remaining_period() {
        val clock = TestClock(1_790_000_500) // 1790000500 % 30 == 10
        val m = model(webLogin, clock)
        val t = m.totp.value!!
        assertEquals(Totp.code("JBSWY3DPEHPK3PXP", "SHA1", 6, 30, 1_790_000_500), t.code)
        assertEquals(20, t.secondsRemaining)
        assertEquals(20.0 / 30.0, t.fractionRemaining, 1e-9)
        clock.now += 20; m.tick()
        assertEquals(30, m.totp.value?.secondsRemaining)
        assertNotEquals(t.code, m.totp.value?.code)
    }

    @Test fun test_code_tile_rebuilds_its_model_when_the_totp_secret_changes() {
        val clock = TestClock(1_790_000_500)
        val c = Clip(clock)
        val before = item(webLogin)
        val m1 = CodeTileModel.modelFor(before, null, clock)
        assertSame("same item keeps its model", m1, CodeTileModel.modelFor(before, m1, clock))
        val r = LinkedHashMap(webLogin.fields)
        val t = LinkedHashMap((r["totp"] as Obj).fields)
        t["secret"] = s("GEZDGNBVGY3TQOJQ"); r["totp"] = Obj(t)
        val after = item(Obj(r))
        val m2 = CodeTileModel.modelFor(after, m1, clock)
        assertNotSame(m1, m2)
        val fresh = Totp.code("GEZDGNBVGY3TQOJQ", "SHA1", 6, 30, 1_790_000_500)
        assertEquals(fresh, m2.state?.code)
        assertNotEquals(fresh, m1.state?.code)
        m2.copy { c.clipboard.copy(it) }
        assertEquals(fresh, c.sink.text)
    }

    @Test fun test_no_totp_for_items_without_one() {
        assertNull(model(note).totp.value)
    }

    @Test fun test_invalid_totp_secret_gives_no_code() {
        val bad = rec(
            "id" to s("w9"), "kind" to s("web"), "label" to s("x"), "username" to s(""),
            "password" to s(""), "scope" to rec("origin" to s("https://x.example")),
            "totp" to rec("secret" to s("!!!not base32!!!")),
        )
        val m = model(bad)
        assertNull(m.totp.value)
        assertFalse(m.copyTotp())
        assertNull(m.lastCopied.value)
    }

    @Test fun test_copy_totp_is_sensitive_with_60s_expiry() {
        val clock = TestClock(1_790_000_500)
        val c = Clip(clock)
        val m = model(webLogin, clock, c)
        assertTrue(m.copyTotp())
        assertEquals(FakeClipboardSink.Write(m.totp.value!!.code, true), c.sink.history.single())
        assertEquals(1_790_000_560, c.scheduler.timers.single().due)
        assertEquals("Code", m.lastCopied.value)
    }

    @Test fun test_passkey_detail_hides_private_key() {
        val record = passkeyItem()
        val key = ((record.fields["payload"] as Obj).fields["private_key"] as JsonValue.Str).v
        val c = Clip()
        val m = model(record, clip = c, conceal = false)
        assertEquals(listOf("Website", "User", "Created", "Status"), m.fields.map { it.label })
        assertEquals(listOf("example.com", "ada", "2026-10-18", "Can sign in"), m.fields.map { it.value })
        for (f in m.fields) {
            assertFalse(f.value.contains(key)); assertFalse(m.displayValue(f).contains(key))
            m.toggleReveal(f); assertFalse(m.displayValue(f).contains(key))
            m.copy(f)
        }
        val copied = c.sink.history.map { it.text }
        assertEquals(m.fields.size, copied.size)
        assertFalse("the private key never reaches the clipboard", copied.any { it.contains(key) })
        assertFalse(m.fields.any { it.id == "private_key" || it.id == "credential_id" || it.id == "user_handle" })
        val backup = model(passkeyItem(usable = false))
        assertEquals("Backup only", backup.fields.last().value)
    }

    // ---- Per-kind field rules from the map (desktop `PROTECTED_FIELD_LABELS` and the payload listing). ----

    @Test fun login_fields_are_username_password_target_notes_and_skip_empty_values() {
        val m = model(webLogin)
        assertEquals(listOf("username", "password", "target", "notes"), m.fields.map { it.id })
        assertEquals(listOf("Username", "Password", "Website", "Notes"), m.fields.map { it.label })
        assertEquals("https://accounts.example.com", m.fields[2].value)
        val desk = rec(
            "id" to s("d1"), "kind" to s("desktop"), "label" to s("Mail"), "username" to s(""), "password" to s("pw"),
            "scope" to rec("exe_path" to s("C:/Mail/mail.exe")),
        )
        assertEquals(listOf("Password", "Application"), model(desk).fields.map { it.label })
    }

    @Test fun masked_payload_fields_come_first_then_sorted_payload_keys_then_custom_fields() {
        val wifi = rec(
            "id" to s("f1"), "kind" to s("wifi"), "title" to s("Home"),
            "payload" to rec("ssid" to s("Home"), "security" to s("wpa2"), "hidden" to Bool(false), "password" to s("pw-wifi")),
        )
        val m = model(wifi)
        assertEquals(listOf("Password", "Security", "Network name"), m.fields.map { it.label })
        assertEquals(listOf(true, false, false), m.fields.map { it.isSecret })
        assertEquals("WPA2", m.fields[1].value)
        val hidden = rec("id" to s("f2"), "kind" to s("wifi"), "payload" to rec("ssid" to s("Lab"), "hidden" to Bool(true)))
        assertEquals(listOf("Hidden network" to "Yes", "Network name" to "Lab"), model(hidden).fields.map { it.label to it.value })
    }

    @Test fun purchase_amounts_dates_flags_and_custom_fields_read_well() {
        val purchase = rec(
            "id" to s("p1"), "kind" to s("purchase"), "title" to s("Laptop"),
            "payload" to rec(
                "product" to s("Laptop"), "vendor" to s("Shop"), "amount_minor" to i(129_999), "currency" to s("EUR"),
                "purchase_date" to s("2026-12-31"), "active" to Bool(true), "template_id" to s("t"), "last4" to s("1234"),
                "fields" to Arr(
                    listOf(rec("name" to s("Order"), "value" to s("A-1")), rec("name" to s("Door"), "value" to s("9"), "hidden" to Bool(true)), rec("value" to s("x"))),
                ),
            ),
        )
        val m = model(purchase)
        assertEquals(
            listOf("Active", "Amount", "Product", "Purchase date", "Vendor", "Order", "Door", "Field"),
            m.fields.map { it.label },
        )
        assertEquals("Yes", m.fields[0].value)
        assertEquals(Amount.display(129_999, "EUR"), m.fields[1].value)
        assertEquals(ItemDetailModel.displayDate("2026-12-31"), m.fields[3].value)
        assertEquals(listOf("field-0", "field-1", "field-2"), m.fields.takeLast(3).map { it.id })
        assertEquals(listOf(false, true, false), m.fields.takeLast(3).map { it.isSecret })
        val none = rec("id" to s("p2"), "kind" to s("purchase"), "payload" to rec("amount_minor" to i(0), "currency" to s("XXX"), "product" to s("Pen")))
        assertEquals("no amount: no Amount row", listOf("Product"), model(none).fields.map { it.label })
    }

    @Test fun label_overrides_and_kind_label_fallback() {
        assertEquals("URL", ItemDetailModel.label("url", EnglishTxt()))
        assertEquals("Routing number / BIC", ItemDetailModel.label("routing", EnglishTxt()))
        assertEquals("License key", ItemDetailModel.label("license_value", EnglishTxt()))
        assertEquals("Job title", ItemDetailModel.label("job_title", EnglishTxt()))
        assertEquals("First name", ItemDetailModel.label("first_name", EnglishTxt()))
    }

    @Test fun dates_show_in_the_medium_style_only_when_they_are_real_iso_days() {
        assertEquals("Dec 31, 2026", ItemDetailModel.displayDate("2026-12-31", Locale.US))
        assertEquals("2026-W53", ItemDetailModel.displayDate("2026-W53", Locale.US))
        assertEquals("2026-02-30", ItemDetailModel.displayDate("2026-02-30", Locale.US))
        assertEquals("2026-2-3", ItemDetailModel.displayDate("2026-2-3", Locale.US))
    }

    @Test fun amounts_show_in_the_currency_with_its_decimals() {
        assertEquals("€1,299.99", Amount.display(129_999, "EUR", Locale.US))
        assertEquals("¥1,500", Amount.display(1_500, "JPY", Locale.US))
        assertEquals("12.99", Amount.display(1_299, "XXX", Locale.US))
        assertEquals("-$5.00", Amount.display(-500, "USD", Locale.US))
        // A well-formed code the platform does not know shows itself, like the iPhone's NumberFormatter.
        assertEquals("ABC 12.99", Amount.display(1_299, "ABC", Locale.US))
        assertEquals("-ABC 0.05", Amount.display(-5, "ABC", Locale.US))
        assertEquals("12,99 ABC", Amount.display(1_299, "ABC", Locale.GERMANY))
        assertEquals("12.99", Amount.display(1_299, "abc", Locale.US))
        assertEquals(2, Amount.fractionDigits("XXX")); assertEquals(0, Amount.fractionDigits("JPY")); assertEquals(2, Amount.fractionDigits("eu"))
        assertEquals("1299.99", Amount.text(129_999, "CHF")); assertEquals("15.00", Amount.text(1_500, "EUR"))
        assertEquals("-0.05", Amount.text(-5, "EUR")); assertEquals("1500", Amount.text(1_500, "JPY"))
    }

    @Test fun multiline_values_are_flagged() {
        val n = rec("id" to s("n2"), "kind" to s("note"), "payload" to rec("body" to s("line 1\nline 2")))
        val f = model(n).fields.single()
        assertTrue(f.isMultiline)
        assertFalse(model(webLogin).fields.first().isMultiline)
    }

    @Test fun reveal_toggles_per_field() {
        val m = model(card)
        val number = m.fields.first { it.id == "number" }
        val cvv = m.fields.first { it.id == "cvv" }
        m.toggleReveal(number)
        assertTrue(m.isRevealed(number)); assertFalse(m.isRevealed(cvv))
        assertEquals("4111111111111111", m.displayValue(number)); assertEquals(ItemDetailModel.MASK, m.displayValue(cvv))
        m.toggleReveal(number)
        assertFalse(m.isRevealed(number))
    }

    @Test fun to_string_never_shows_secrets() {
        val m = model(webLogin, TestClock(1_790_000_500), conceal = false)
        m.copy(m.fields.first { it.id == "password" })
        val code = m.totp.value!!.code
        val texts = listOf(m.toString(), m.fields.toString(), m.fields.first { it.id == "password" }.toString())
        for (t in texts) {
            assertFalse(t, t.contains("Maple-Orbit-7731"))
            assertFalse(t, t.contains("JBSWY3DPEHPK3PXP"))
            assertFalse(t, t.contains(code))
            assertFalse(t, t.contains("Sample.User"))
        }
        assertNotNull(m.fields.first().toString().takeIf { it.contains("username") })
    }

    @Test fun tags_and_title_do_not_become_fields() {
        val m = model(rec("id" to s("n3"), "kind" to s("note"), "title" to s("T"), "tags" to strs("a"), "payload" to rec("body" to s("b"))))
        assertEquals(listOf("Body"), m.fields.map { it.label })
    }
}
