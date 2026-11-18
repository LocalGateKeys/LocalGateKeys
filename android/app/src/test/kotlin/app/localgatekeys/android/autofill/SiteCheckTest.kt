package app.localgatekeys.android.autofill

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.security.SecurityPrefs
import app.localgatekeys.android.security.login
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.core.json.JsonValue.Obj
import app.localgatekeys.core.security.Lookalike
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The autofill save prompt's site verdict (extension Task 4 rules): verified, related or new site; a lookalike asks
 * "Is this the right site?" with "Go back" first; the same name on another ending asks "Is this the same account as
 * <saved>?" once, and a "Same account" answer is remembered per origin pair as an opaque id.
 */
class SiteCheckTest {
    private val lookalike = Lookalike(testRules)
    private val key = ByteArray(32) { it.toByte() }

    private fun at(id: String, origin: String) = Obj(login(id, "pw").fields + ("scope" to rec("origin" to s(origin))))

    private val vault = snapshot(listOf(at("p", "https://paypal.com"), at("a", "https://amazon.com"), at("e", "https://example.com")))

    private fun prompt(origin: String, remembered: List<String> = emptyList()) =
        SiteCheck.prompt(lookalike, origin, SiteCheck.savedOrigins(vault), key, remembered)

    private fun picked(origin: String, saved: List<String>, matches: Boolean, schemeKnown: Boolean = true, remembered: List<String> = emptyList()) =
        SiteCheck.picked(lookalike, origin, saved, matches, schemeKnown, key, remembered)

    @Test fun a_login_picked_by_hand_for_its_own_site_fills_at_once() {
        assertEquals(null, picked("https://paypal.com", listOf("https://paypal.com"), matches = true))
        assertEquals(null, picked("https://www.paypal.com", listOf("https://paypal.com"), matches = true))
    }

    @Test fun a_login_picked_by_hand_for_a_lookalike_gets_the_lookalike_question() {
        assertEquals(SitePrompt.Guard("paypa1.com", "paypal.com"), picked("https://paypa1.com", listOf("https://paypal.com"), matches = false))
        val same = picked("https://amazon.de", listOf("https://amazon.com"), matches = false) as SitePrompt.SameAccount
        assertEquals("amazon.com", same.savedHost)
    }

    @Test fun a_login_picked_by_hand_for_another_site_names_both_sites() {
        assertEquals(
            SitePrompt.Mismatch("unrelated.org", "paypal.com", otherSite = true, schemeKnown = true),
            picked("https://unrelated.org", listOf("https://paypal.com", "https://example.com"), matches = false),
        )
        assertEquals(SitePrompt.Mismatch("unrelated.org", null, otherSite = true, schemeKnown = true), picked("https://unrelated.org", emptyList(), matches = false))
        // A remembered "same account" pair is still another site for this login: asked, naming both.
        val pair = (picked("https://amazon.de", listOf("https://amazon.com"), matches = false) as SitePrompt.SameAccount).pair
        assertEquals(
            SitePrompt.Mismatch("amazon.de", "amazon.com", otherSite = true, schemeKnown = true),
            picked("https://amazon.de", listOf("https://amazon.com"), matches = false, remembered = listOf(pair)),
        )
    }

    @Test fun a_page_without_a_scheme_always_asks() {
        assertEquals(
            SitePrompt.Mismatch("paypal.com", "paypal.com", otherSite = false, schemeKnown = false),
            picked("https://paypal.com", listOf("https://paypal.com"), matches = true, schemeKnown = false),
        )
        assertEquals(
            SitePrompt.Mismatch("unrelated.org", "paypal.com", otherSite = true, schemeKnown = false),
            picked("https://unrelated.org", listOf("https://paypal.com"), matches = false, schemeKnown = false),
        )
    }

    @Test fun saved_origins_are_every_url_row_of_live_web_logins() {
        val deleted = snapshot(listOf(at("x", "https://gone.example.org"), at("p", "https://paypal.com")), deleted = setOf("x"))
        assertEquals(listOf("https://paypal.com"), SiteCheck.savedOrigins(deleted))
        val desktop = snapshot(listOf(Obj(at("d", "https://desk.example.org").fields + ("kind" to s("desktop")))))
        assertEquals(emptyList<String>(), SiteCheck.savedOrigins(desktop))
    }

    @Test fun verified_related_and_new_sites() {
        assertEquals(SitePrompt.Verified, prompt("https://paypal.com"))
        assertEquals(SitePrompt.Related, prompt("https://www.paypal.com"))
        assertEquals(SitePrompt.New, prompt("https://unrelated.org"))
    }

    /** Design decision 2026-11-12 (desktop `lookalike.classify`): "Related site" only for the same host or its www twin. */
    @Test fun another_host_on_a_saved_domain_is_not_related() {
        assertEquals(SitePrompt.Related, prompt("http://paypal.com"))
        assertEquals(SitePrompt.New, prompt("https://login.paypal.com"))
        assertEquals(SitePrompt.New, prompt("https://www.accounts.paypal.com"))
        assertEquals(null, picked("https://login.paypal.com", listOf("https://paypal.com"), matches = true))
    }

    @Test fun a_lookalike_names_both_hosts_and_mixed_script_names_only_the_page() {
        assertEquals(SitePrompt.Guard("paypa1.com", "paypal.com"), prompt("https://paypa1.com"))
        assertEquals(SitePrompt.Guard("paypal.com.secure-login.net", "paypal.com"), prompt("https://paypal.com.secure-login.net"))
        assertEquals(SitePrompt.Guard("xn--pple-43d.com", null), prompt("https://xn--pple-43d.com"))
    }

    @Test fun another_ending_asks_once_and_the_answer_is_remembered_per_pair() {
        val first = prompt("https://amazon.de") as SitePrompt.SameAccount
        assertEquals("amazon.de", first.host)
        assertEquals("amazon.com", first.savedHost)
        assertTrue(first.pair.matches(Regex("[0-9a-f]{32}")))
        assertEquals(SitePrompt.Related, prompt("https://amazon.de", listOf(first.pair)))
        // amazon.co.uk is another pair: still asked.
        val other = prompt("https://amazon.co.uk", listOf(first.pair)) as SitePrompt.SameAccount
        assertNotEquals(first.pair, other.pair)
        // The id is keyed: another vault key gives another id, and the id never contains a host.
        val elsewhere = SiteCheck.prompt(lookalike, "https://amazon.de", SiteCheck.savedOrigins(vault), ByteArray(32) { 7 }, emptyList()) as SitePrompt.SameAccount
        assertNotEquals(first.pair, elsewhere.pair)
    }

    @Test fun the_same_account_list_is_capped_and_wiped_with_the_security_settings() {
        val prefs = SecurityPrefs(MemoryStore())
        prefs.sameAccountPairs = (1..600).map { "%032x".format(it) }
        assertEquals(500, prefs.sameAccountPairs.size)
        assertEquals("%032x".format(600), prefs.sameAccountPairs.last())
        prefs.wipe()
        assertEquals(emptyList<String>(), prefs.sameAccountPairs)
    }

    @Test fun the_prompt_texts_follow_the_extension() {
        val t = EnglishTxt()
        assertEquals("Is this the right site?", t.s(R.string.autofill_guard_title))
        assertEquals("Continue on paypa1.com", t.s(R.string.autofill_guard_continue, "paypa1.com"))
        assertEquals("Is this the same account as amazon.com?", t.s(R.string.autofill_same_account_title, "amazon.com"))
        assertEquals("Verified site", t.s(R.string.autofill_site_verified))
    }

    // ---- audit A3: a login picked by hand for an app ----

    @Test fun a_first_pick_for_an_app_asks_first_naming_the_app_and_the_saved_site() {
        val app = FillTarget.App("com.evil.bank", "ab12")
        val index = FillIndex(emptyList(), emptyMap())
        assertEquals(
            SitePrompt.UnverifiedApp("com.evil.bank", "paypal.com"),
            SiteCheck.pickedApp(app, "p", index, listOf("https://paypal.com")),
        )
        assertEquals(SitePrompt.UnverifiedApp("com.evil.bank", null), SiteCheck.pickedApp(app, "p", index, emptyList()))
    }

    @Test fun an_app_already_paired_with_the_login_fills_at_once() {
        val app = FillTarget.App("com.bank", "ab12")
        val index = FillIndex(emptyList(), emptyMap()).paired(app.pairKey, "p")
        assertEquals(null, SiteCheck.pickedApp(app, "p", index, listOf("https://paypal.com")))
        // the same package signed by another certificate, or another login, is a first pick again
        assertTrue(SiteCheck.pickedApp(FillTarget.App("com.bank", "ff00"), "p", index, emptyList()) is SitePrompt.UnverifiedApp)
        assertTrue(SiteCheck.pickedApp(app, "a", index, emptyList()) is SitePrompt.UnverifiedApp)
    }
}
