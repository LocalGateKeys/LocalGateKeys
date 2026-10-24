package app.localgatekeys.android.vault

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.json.JsonValue.Arr
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultItemTest {
    private val items = itemsOf(webLogin, deskLogin, note, card)
    private val byId = items.associateBy { it.id }

    @Test fun decodes_titles_and_targets_like_the_desktop() {
        assertEquals("Example account", byId["w1"]?.title)
        assertEquals("https://accounts.example.com", byId["w1"]?.target)
        assertEquals("samplemail.exe", byId["d1"]?.target)
        assertEquals("Visa", byId["c1"]?.target)
        assertEquals("Note", byId["n1"]?.kindLabel)
        assertEquals("Payment card", byId["c1"]?.kindLabel)
    }

    @Test fun card_subtitle_is_masked_last_four_with_expiry() {
        fun card(vararg p: Pair<String, JsonValue>) = item("card", "title" to s("Visa"), "payload" to rec(*p))
        val withExpiry = card("brand" to s("visa"), "number" to s("4000 0000 0002 6411"), "expiry" to s("08/27"))
        assertEquals("•••• 6411 · 08/27", withExpiry.listSubtitle)
        assertFalse(withExpiry.listSubtitle.contains("40000000"))
        assertEquals("•••• 1111", card("brand" to s("visa"), "number" to s("4111111111111111")).listSubtitle)
        assertEquals("Visa", card("brand" to s("visa"), "number" to s("41")).listSubtitle)
        assertEquals("Visa", card("brand" to s("visa")).listSubtitle)
        assertEquals("•••• 1111", byId["c1"]?.listSubtitle)
    }

    @Test fun card_summary_keeps_only_ascii_digits_and_bounds_the_expiry() {
        // Arabic-Indic digits are digits for Unicode but not card digits.
        assertNull(VaultItem.cardSummary(mapOf("number" to s("١٢٣٤٥"))))
        val long = VaultItem.cardSummary(mapOf("number" to s("4111111111111111"), "expiry" to s("12/2099-extra-long ")))
        assertEquals("•••• 1111 · 12/2099-ex", long)
    }

    @Test fun web_title_equal_to_origin_shows_friendly_host() {
        val r = rec(
            "id" to s("w2"), "kind" to s("web"), "label" to s("https://login.example.org"),
            "username" to s(""), "password" to s(""), "scope" to rec("origin" to s("https://login.example.org")),
        )
        assertEquals("example.org", itemsOf(r).first().title)
    }

    @Test fun origin_labels_follow_the_desktop() {
        assertEquals("example.com", OriginLabel.friendly("https://accounts.example.com:8443"))
        assertEquals("login.com", OriginLabel.friendly("https://login.com")) // fewer than two dots: kept
        assertEquals("https://[::1]:8080", OriginLabel.friendly("https://[::1]:8080"))
        assertEquals("", OriginLabel.friendly(""))
        assertEquals("https://", OriginLabel.friendly("https://"))
    }

    @Test fun skips_tombstones_and_licences_and_unreadable_records() {
        val lic = Wrapper.make(Namespace.LICENSE, rec("x" to i(1)))
        val broken = rec("no" to s("kind"))
        val snap = snapshot(
            listOf(webLogin, note),
            extra = mapOf("license-abc" to lic, "bad" to broken, "bare" to s("x")),
            deleted = setOf("n1"),
        )
        assertEquals(listOf("w1"), VaultItem.items(snap).map { it.id })
    }

    @Test fun kind_labels_and_fallbacks() {
        assertEquals("Website login", VaultItem.kindLabel("web"))
        assertEquals("Wi-Fi network", VaultItem.kindLabel("wifi"))
        assertEquals("Passkey", VaultItem.kindLabel("passkey"))
        assertEquals("Custom thing", VaultItem.kindLabel("custom_thing"))
        assertEquals("Item", VaultItem.kindLabel(""))
        assertEquals("Item", VaultItem.kindLabel("  "))
    }

    @Test fun list_subtitle_prefers_username_then_card_then_target_then_kind() {
        assertEquals("Sample.User@example.com", byId["w1"]?.listSubtitle)
        assertEquals("Note", byId["n1"]?.listSubtitle)
        assertEquals("mailer", byId["d1"]?.listSubtitle)
        assertEquals("sample.com", item("api_key", "payload" to rec("service" to s(" sample.com "))).listSubtitle)
        assertEquals(
            "Acme · Gadget",
            item("warranty", "payload" to rec("vendor" to s("Acme"), "product" to s("Gadget"), "other" to s("x"))).target,
        )
        assertEquals("example.org", item("bookmark", "payload" to rec("url" to s("https://example.org/a"))).target)
        assertEquals("Wi-Fi network", item("wifi", "payload" to rec("ssid" to s("   "))).listSubtitle)
    }

    @Test fun safe_display_replaces_control_characters_and_truncates() {
        assertEquals("a b c d", VaultItem.safeDisplay("a\u0000b​c d")) // control, format, no-break space
        assertEquals("a b", VaultItem.safeDisplay("a b")) // a plain space stays
        assertEquals(120, VaultItem.safeDisplay("x".repeat(500)).length)
        assertEquals("😀".repeat(120), VaultItem.safeDisplay("😀".repeat(130)))
        assertEquals("a b", item("web", "scope" to rec("origin" to s("a\nb"))).target)
    }

    @Test fun derived_flags() {
        assertTrue(byId["w1"]!!.isLogin)
        assertTrue(byId["d1"]!!.isLogin)
        assertFalse(byId["n1"]!!.isLogin)
        assertTrue(byId["w1"]!!.hasTotp)
        assertFalse(byId["d1"]!!.hasTotp)
        assertFalse(item("web", "totp" to rec("digits" to i(6))).hasTotp)
        assertFalse(item("web", "totp" to s("x")).hasTotp)
        assertTrue(byId["d1"]!!.favorite)
        assertFalse(byId["w1"]!!.favorite)
        assertEquals(1_790_000_500L, byId["w1"]!!.updatedAt)
        assertEquals(0L, item("note").updatedAt)
        assertEquals(listOf("Personal"), byId["w1"]!!.tags)
    }

    @Test fun openable_url_only_for_web_and_bookmark_with_http_or_https_and_a_host() {
        assertEquals("https://accounts.example.com", byId["w1"]!!.openableUrl)
        assertEquals("http://example.org/x", item("bookmark", "payload" to rec("url" to s("http://example.org/x"))).openableUrl)
        assertNull(item("bookmark", "payload" to rec("url" to s("javascript:alert(1)"))).openableUrl)
        assertNull(item("bookmark", "payload" to rec("url" to s("ftp://example.org"))).openableUrl)
        assertNull(item("bookmark", "payload" to rec("url" to s("https://"))).openableUrl)
        assertNull(item("bookmark", "payload" to rec("url" to s("not a url"))).openableUrl)
        assertNull(item("web", "scope" to rec("origin" to s("file:///etc/passwd"))).openableUrl)
        assertNull(byId["d1"]!!.openableUrl)
        assertNull(byId["n1"]!!.openableUrl)
    }

    @Test fun a_record_without_a_string_kind_is_not_an_item() {
        assertNull(VaultItem.of("x", rec("title" to s("t"))))
        assertNull(VaultItem.of("x", rec("kind" to i(3))))
        // tags keep only their strings
        assertEquals(listOf("a"), item("note", "tags" to Arr(listOf(s("a"), i(1)))).tags)
    }

    @Test fun password_for_quick_actions_comes_from_the_login_or_the_wifi_payload() {
        assertEquals("Maple-Orbit-7731", byId["w1"]!!.copyablePassword)
        assertEquals("pw", item("wifi", "payload" to rec("password" to s("pw"))).copyablePassword)
        assertNull(item("note", "payload" to rec("password" to s("pw"))).copyablePassword)
        assertNull(item("web", "password" to s("")).copyablePassword)
        assertNull(byId["n1"]!!.copyablePassword)
    }
}
