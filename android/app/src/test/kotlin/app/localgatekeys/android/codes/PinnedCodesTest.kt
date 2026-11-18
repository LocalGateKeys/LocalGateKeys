package app.localgatekeys.android.codes

import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.vault.i
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.totp.Totp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PinnedCodesTest {
    private val secret = "JBSWY3DPEHPK3PXP"
    private val now = 1_790_000_010L

    private fun login(id: String, title: String = "Site $id", totp: JsonValue? = rec("secret" to s(secret))): JsonValue.Obj {
        val f = mutableListOf<Pair<String, JsonValue>>("id" to s(id), "kind" to s("web"), "title" to s(title))
        if (totp != null) f += "totp" to totp
        return rec(*f.toTypedArray())
    }

    private val settings = AppSettings(MemoryStore())
    private var snap: StoreSnapshot? = snapshot(listOf(login("a"), login("b"), login("c"), login("d"), login("e")))
    private val codes = PinnedCodes(settings, { snap })

    @Test fun travel_mode_hides_pinned_codes_but_keeps_the_pins() {
        var travel = app.localgatekeys.core.sync.TravelMode.Setting.OFF
        val tagged = rec(*(login("t").fields + ("tags" to app.localgatekeys.android.vault.strs("Work"))).toList().toTypedArray())
        snap = snapshot(listOf(login("a"), tagged))
        val c = PinnedCodes(settings, { snap }, travel = { travel })
        assertTrue(c.toggle("a", isPro = true))
        assertTrue(c.toggle("t", isPro = true))
        assertEquals(listOf("a", "t"), c.codes(now).map { it.id })
        travel = app.localgatekeys.core.sync.TravelMode.Setting(true, emptyList(), listOf("work"), 1)
        assertEquals(listOf("a"), c.codes(now).map { it.id })
        assertEquals("the hidden pin is kept for later", listOf("a", "t"), c.ids())
        travel = app.localgatekeys.core.sync.TravelMode.Setting.OFF
        assertEquals(listOf("a", "t"), c.codes(now).map { it.id })
    }

    @Test fun an_unreadable_travel_setting_shows_no_code_and_keeps_the_pins() {
        val c = PinnedCodes(settings, { snap }, travel = { null })
        assertTrue(c.toggle("a", isPro = true))
        assertEquals(emptyList<PinnedCode>(), c.codes(now))
        assertEquals(listOf("a"), c.ids())
        val throws = PinnedCodes(settings, { snap }, travel = { error("unreadable") })
        assertEquals(emptyList<PinnedCode>(), throws.codes(now))
    }

    @Test fun a_login_with_access_rules_shows_no_code_here_but_keeps_its_pin() {
        // Scan A-M1: the widget and the tile have no owner check, so a re-auth / view-only / copy-once login stays in the app.
        fun ruled(id: String, scope: JsonValue? = null, policy: JsonValue? = null) =
            rec(*(login(id).fields + listOfNotNull(scope?.let { "scope" to it }, policy?.let { "policy" to it })).toList().toTypedArray())
        snap = snapshot(
            listOf(
                login("a"),
                ruled("b", scope = rec("access" to rec("phones" to s("view")))),
                ruled("c", policy = rec("require_master_password" to JsonValue.Bool(true))),
                ruled("d", scope = rec("access" to rec("copy" to s("once")))),
            ),
        )
        for (id in listOf("a", "b", "c", "d")) assertTrue(codes.toggle(id, isPro = true))
        assertEquals(listOf("a"), codes.codes(now).map { it.id })
        assertEquals(listOf("a", "b", "c", "d"), codes.ids())
    }

    @Test fun pinning_needs_pro_but_unpinning_never_does() {
        assertFalse(codes.toggle("a", isPro = false))
        assertEquals(PinResult.NEEDS_PRO, codes.pin("a", isPro = false))
        assertEquals(emptyList<String>(), codes.ids())
        assertTrue(codes.toggle("a", isPro = true))
        assertEquals(listOf("a"), codes.ids())
        // The plan lapsed: the pin can still be removed.
        assertTrue(codes.toggle("a", isPro = false))
        assertEquals(emptyList<String>(), codes.ids())
    }

    @Test fun at_most_four_pins_are_kept_in_pin_order() {
        for (id in listOf("d", "a", "c", "b")) assertTrue(codes.toggle(id, isPro = true))
        assertEquals(PinResult.FULL, codes.pin("e", isPro = true))
        assertEquals(listOf("d", "a", "c", "b"), codes.ids())
        // A stored list that grew past the limit (or has repeats and malformed ids) is read cleaned.
        settings.pinnedCodeIds = listOf("a", "a", "b c", "", "b", "c", "d", "e")
        assertEquals(listOf("a", "b", "c", "d"), codes.ids())
        assertEquals(4, codes.codes(now).size)
    }

    @Test fun a_duress_session_neither_prunes_nor_changes_the_real_vaults_pins() {
        codes.toggle("a", true); codes.toggle("b", true)
        var duress = true
        val second = PinnedCodes(settings, { snapshot(listOf(login("x"))) }, frozen = { duress })
        // The open (second) vault holds none of the pinned items: they show as locked and stay pinned.
        val shown = second.codes(now)
        assertEquals(listOf("a", "b"), shown.map { it.id })
        assertTrue(shown.all { it.code == null && it.title.isEmpty() })
        assertEquals(listOf("a", "b"), settings.pinnedCodeIds)
        assertEquals(PinResult.FULL, second.pin("x", isPro = true))
        assertEquals(PinResult.FULL, second.pin("a", isPro = true))
        assertEquals(listOf("a", "b"), settings.pinnedCodeIds)
        duress = false
        assertEquals(listOf("a", "b"), codes.codes(now).map { it.id })
    }

    @Test fun a_locked_vault_gives_no_code_and_no_title() {
        codes.toggle("a", true); codes.toggle("b", true)
        snap = null
        val shown = codes.codes(now)
        assertEquals(listOf("a", "b"), shown.map { it.id })
        assertTrue(shown.all { it.code == null && it.title.isEmpty() })
        // Locked: nothing is pruned.
        assertEquals(listOf("a", "b"), codes.ids())
    }

    @Test fun a_store_that_fails_counts_as_locked() {
        codes.toggle("a", true)
        val failing = PinnedCodes(settings, { throw IllegalStateException("closed") })
        assertNull(failing.codes(now).single().code)
        assertEquals(listOf("a"), codes.ids())
    }

    @Test fun an_open_vault_gives_six_digits_and_the_time_left() {
        codes.toggle("b", true)
        val c = codes.codes(now).single()
        assertEquals("Site b", c.title)
        assertEquals(Totp.code(secret, "SHA1", 6, 30, now), c.code)
        assertTrue(c.code!!.matches(Regex("\\d{6}")))
        assertEquals(30 - (now % 30).toInt(), c.secondsRemaining)
        // The next period gives the next code: nothing is cached.
        val next = codes.codes(now + c.secondsRemaining).single()
        assertEquals(Totp.code(secret, "SHA1", 6, 30, now + c.secondsRemaining), next.code)
        assertEquals(30, next.secondsRemaining)
    }

    @Test fun nothing_pinned_is_empty() {
        assertEquals(emptyList<PinnedCode>(), codes.codes(now))
    }

    @Test fun deleted_items_and_removed_secrets_are_pruned_and_a_changed_secret_is_used() {
        for (id in listOf("a", "b", "c", "d")) codes.toggle(id, true)
        val other = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        snap = snapshot(
            listOf(login("a"), login("b", totp = null), login("c", totp = rec("secret" to s(other))), login("d")),
            deleted = setOf("d"),
        )
        val shown = codes.codes(now)
        assertEquals(listOf("a", "c"), shown.map { it.id })
        assertEquals(Totp.code(other, "SHA1", 6, 30, now), shown[1].code)
        assertEquals(listOf("a", "c"), codes.ids())
        assertEquals(listOf("a", "c"), settings.pinnedCodeIds)
    }

    @Test fun an_unusable_secret_shows_an_empty_code_not_a_lock() {
        codes.toggle("a", true)
        snap = snapshot(listOf(login("a", totp = rec("secret" to s("x"), "digits" to i(99)))))
        val c = codes.codes(now).single()
        assertEquals("", c.code)
    }

    @Test fun the_last_unpin_leaves_nothing_stored() {
        codes.toggle("a", true)
        codes.toggle("a", true)
        assertNull(settings.pinnedCodeIds.firstOrNull())
        assertEquals(emptyList<PinnedCode>(), codes.codes(now))
    }

    @Test fun to_string_never_shows_the_code() {
        val c = PinnedCode("a", "Site", "123456", 12)
        assertFalse(c.toString().contains("123456"))
        assertFalse(c.toString().contains("Site"))
    }
}
