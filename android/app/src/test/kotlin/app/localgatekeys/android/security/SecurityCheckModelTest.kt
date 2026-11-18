package app.localgatekeys.android.security

import app.localgatekeys.android.autofill.testRules
import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.unlock.MemoryItemStore
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.core.json.JsonValue.Obj
import app.localgatekeys.core.records.UrlMatcher
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The iPhone `SecurityCheckModelTests` plus the Android seams (settings store, scope, transport). */
class SecurityCheckModelTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val txt = EnglishTxt()

    /** Every test login lives on <id>.example.com, a site that offers 2FA codes. */
    private val exampleOffersTotp = SiteFeatures(mapOf("example.com" to setOf("totp")), UrlMatcher(testRules))

    @After fun stop() = scope.cancel()

    private fun model(records: List<Obj>, prefs: SecurityPrefs, transport: BreachTransport = RecordingTransport()): SecurityCheckModel {
        val m = SecurityCheckModel(MemoryItemStore(snapshot(records)), prefs, TestClock(NOW), scope, strength, transport, "1.0", pauseMillis = 0, featuresSource = { exampleOffersTotp })
        m.refresh()
        return m
    }

    private fun prefs(store: MemoryStore = MemoryStore()) = SecurityPrefs(store)

    private fun allow(p: SecurityPrefs) { p.strictOfflineMode = false; p.breachCheckEnabled = true }

    @Test fun categories_match_the_shared_health() {
        val m = model(
            listOf(
                login("a", "password"), login("b", "Tr1cky-Orbit-Maple-7731", totp = true),
                login("c", "Tr1cky-Orbit-Maple-7731"), login("d", "Unique-Lantern-Quartz-9921", updated = 1_700_000_000),
            ),
            prefs(),
        )
        val s = m.state.value
        assertEquals(setOf("a"), s.ids(SecurityCategory.WEAK))
        assertEquals(setOf("b", "c"), s.ids(SecurityCategory.REUSED))
        assertEquals(setOf("d"), s.ids(SecurityCategory.OLD))
        assertEquals(setOf("a", "c", "d"), s.ids(SecurityCategory.NO_TWO_FACTOR))
        assertEquals(emptySet<String>(), s.ids(SecurityCategory.BREACHED))
        // The same score as the Mac and the iPhone: 4 logins, a, b and c need attention.
        assertEquals(25, s.score)
        assertEquals(HealthBand.POOR, s.band)
        assertEquals(3, s.count(SecurityCategory.NO_TWO_FACTOR))
    }

    @Test fun only_logins_are_checked_and_a_qr_placeholder_login_is_left_out() {
        val note = Obj(mapOf("id" to app.localgatekeys.android.vault.s("n1"), "kind" to app.localgatekeys.android.vault.s("note"), "title" to app.localgatekeys.android.vault.s("Note")))
        val m = model(listOf(login("a", "password"), login("p", "placeholder-pass", tags = listOf("needs-password")), note, login("w", "Unique-Lantern-Quartz-9921", kind = "desktop")), prefs())
        assertEquals(setOf("a", "w"), SecurityCheckModel.healthLogins(m.state.value.items).map { it.id }.toSet())
        assertEquals(2, m.state.value.health!!.total)
    }

    @Test fun an_empty_vault_has_no_score() {
        val m = model(emptyList(), prefs())
        assertNull(m.state.value.score)
        assertEquals(HealthBand.NONE, m.state.value.band)
    }

    @Test fun a_row_lists_most_recently_updated_first() {
        val m = model(listOf(login("a", "password", updated = 1_790_000_100), login("b", "password", updated = 1_790_000_900), login("c", "password", updated = 1_790_000_500)), prefs())
        assertEquals(listOf("b", "c", "a"), m.state.value.items(SecurityCategory.WEAK).map { it.id })
    }

    @Test fun http_and_passkey_rows_read_urls_and_passkey_items() {
        val features = SiteFeatures(mapOf("example.com" to setOf("passkey"), "other.test" to setOf("passkey")), UrlMatcher(testRules))
        fun at(id: String, origin: String) = Obj(login(id, "Unique-Lantern-Quartz-9921").fields + ("scope" to rec("origin" to s(origin))))
        val passkey = rec("id" to s("p"), "kind" to s("passkey"), "label" to s("Key"), "payload" to rec("relying_party_id" to s("Accounts.Example.com")))
        val records = listOf(at("a", "http://a.example.com"), at("b", "https://www.other.test"), at("c", "http://localhost:3000"), passkey)
        val m = SecurityCheckModel(MemoryItemStore(snapshot(records)), prefs(), TestClock(NOW), scope, strength, RecordingTransport(), "1.0", 0, { features })
        m.refresh()
        assertEquals(setOf("a"), m.state.value.ids(SecurityCategory.HTTP))
        // a.example.com already has a passkey (saved for a subdomain of the same registrable domain); other.test has none.
        assertEquals(setOf("b"), m.state.value.ids(SecurityCategory.PASSKEY))
    }

    @Test fun dismiss_hides_one_item_from_one_row_and_persists() {
        val store = MemoryStore()
        val records = listOf(login("a", "password"), login("b", "Unique-Lantern-Quartz-9921"))
        val m = model(records, prefs(store))
        m.dismiss(SecurityCategory.NO_TWO_FACTOR, "a")
        assertEquals(setOf("b"), m.state.value.ids(SecurityCategory.NO_TWO_FACTOR))
        assertEquals(setOf("a"), m.state.value.ids(SecurityCategory.WEAK))
        // A new model over the same settings still hides it.
        assertEquals(setOf("b"), model(records, prefs(store)).state.value.ids(SecurityCategory.NO_TWO_FACTOR))
        m.restoreDismissed()
        assertEquals(setOf("a", "b"), m.state.value.ids(SecurityCategory.NO_TWO_FACTOR))
        assertTrue(prefs(store).dismissed.isEmpty())
    }

    @Test fun travel_mode_leaves_hidden_items_out_and_keeps_their_dismissals() {
        val store = MemoryStore()
        prefs(store).dismissed = setOf("weak:b")
        val records = listOf(login("a", "password"), login("b", "password", tags = listOf("Bank")))
        val m = model(records, prefs(store))
        assertEquals(setOf("a"), m.state.value.ids(SecurityCategory.WEAK))
        assertEquals(setOf("a", "b"), m.state.value.ids(SecurityCategory.NO_TWO_FACTOR))
        m.travel = { app.localgatekeys.core.sync.TravelMode.Setting(true, emptyList(), listOf(" bank "), 1) }
        m.refresh()
        assertEquals(setOf("a"), m.state.value.ids(SecurityCategory.NO_TWO_FACTOR))
        assertEquals(listOf("a"), m.state.value.items.map { it.id })
        // A dismissal of a hidden item is kept (it is still in the vault).
        m.dismiss(SecurityCategory.WEAK, "a")
        assertEquals(setOf("weak:a", "weak:b"), prefs(store).dismissed)
    }

    @Test fun a_dismissed_id_that_left_the_vault_is_dropped_on_the_next_dismiss() {
        val store = MemoryStore()
        prefs(store).dismissed = setOf("weak:gone")
        val m = model(listOf(login("a", "password")), prefs(store))
        m.dismiss(SecurityCategory.WEAK, "a")
        assertEquals(setOf("weak:a"), prefs(store).dismissed)
    }

    @Test fun breach_checks_are_off_on_a_new_install_and_send_nothing() = runBlocking {
        val p = prefs()
        assertFalse(p.breachCheckEnabled)
        assertTrue(p.strictOfflineMode)
        val t = RecordingTransport()
        val m = model(listOf(login("a", "password")), p, t)
        assertEquals(BreachStatus.BlockedOffline, m.breachBlocked)
        assertNull(m.checkBreaches())
        p.strictOfflineMode = false
        assertEquals(BreachStatus.BlockedDisabled, m.breachBlocked)
        assertNull(m.checkBreaches())
        assertEquals(0, t.requests)
        assertTrue(m.state.value.status!!.text(txt).contains("Breach checks are off"))
    }

    @Test fun a_breach_check_runs_once_allowed_and_asks_for_identical_passwords_once() = runBlocking {
        val p = prefs(); allow(p)
        val t = RecordingTransport { rangeBody("password", 3) }
        val m = model(listOf(login("a", "password"), login("b", "password"), login("c", "Unique-Lantern-Quartz-9921")), p, t)
        m.checkBreaches()!!.join()
        assertEquals(2, t.requests)
        val s = m.state.value
        assertFalse(s.running)
        assertEquals(setOf("a", "b"), s.ids(SecurityCategory.BREACHED))
        assertEquals(setOf("a", "b"), s.breached)
        assertEquals("2 breached password(s) found.", s.status!!.text(txt))
    }

    @Test fun nothing_found_and_some_failed_have_their_own_messages() = runBlocking {
        val p = prefs(); allow(p)
        val none = model(listOf(login("a", "password")), p, RecordingTransport { rangeBody("other", 1) })
        none.checkBreaches()!!.join()
        assertEquals(BreachStatus.NoneFound, none.state.value.status)
        assertEquals("No breached passwords found.", none.state.value.status!!.text(txt))

        val failing = object : BreachTransport { override suspend fun get(url: String, headers: Map<String, String>): ByteArray = throw java.io.IOException("x") }
        val failed = model(listOf(login("a", "password")), p, failing)
        failed.checkBreaches()!!.join()
        assertEquals(BreachStatus.SomeFailed, failed.state.value.status)
    }

    @Test fun cancelling_stops_a_running_check_and_keeps_no_results() = runBlocking {
        val p = prefs(); allow(p)
        val started = CompletableDeferred<Unit>()
        val hang = object : BreachTransport {
            override suspend fun get(url: String, headers: Map<String, String>): ByteArray { started.complete(Unit); awaitCancellation() }
        }
        val m = model(listOf(login("a", "password")), p, hang)
        val job = m.checkBreaches()!!
        started.await()
        assertTrue(m.state.value.running)
        // A second start while running does nothing.
        assertNull(m.checkBreaches())
        m.cancelBreachCheck()
        job.join()
        assertFalse(m.state.value.running)
        assertEquals(BreachStatus.Cancelled, m.state.value.status)
        assertTrue(m.state.value.breached.isEmpty())
    }

    @Test fun lock_forgets_results_but_not_the_dismissed_list() = runBlocking {
        val p = prefs(); allow(p)
        val m = model(listOf(login("a", "password")), p, RecordingTransport { rangeBody("password", 3) })
        m.dismiss(SecurityCategory.OLD, "a")
        m.checkBreaches()!!.join()
        assertNotNull(m.state.value.health)
        m.clear()
        val s = m.state.value
        assertNull(s.health); assertTrue(s.items.isEmpty()); assertTrue(s.breached.isEmpty()); assertNull(s.status)
        assertEquals(setOf("old:a"), s.dismissed)
    }

    @Test fun breach_results_drop_logins_that_left_the_vault_on_refresh() = runBlocking {
        val p = prefs(); allow(p)
        val store = MemoryItemStore(snapshot(listOf(login("a", "password"), login("b", "Unique-Lantern-Quartz-9921"))))
        val m = SecurityCheckModel(store, p, TestClock(NOW), scope, strength, RecordingTransport { rangeBody("password", 1) }, "1.0", 0)
        m.refresh()
        m.checkBreaches()!!.join()
        assertEquals(setOf("a"), m.state.value.breached)
        store.snapshot = snapshot(listOf(login("b", "Unique-Lantern-Quartz-9921")))
        m.refresh()
        assertTrue(m.state.value.breached.isEmpty())
    }

    @Test fun settings_defaults_and_keys() {
        val store = MemoryStore()
        val p = SecurityPrefs(store)
        assertTrue(p.strictOfflineMode); assertFalse(p.breachCheckEnabled)
        p.strictOfflineMode = false; p.breachCheckEnabled = true
        assertEquals(false, store.getBoolean("settings.strictOfflineMode"))
        assertEquals(true, store.getBoolean("settings.breachCheckEnabled"))
    }
}
