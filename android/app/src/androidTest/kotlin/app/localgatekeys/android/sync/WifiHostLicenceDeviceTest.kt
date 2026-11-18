package app.localgatekeys.android.sync

import androidx.test.platform.app.InstrumentationRegistry
import app.localgatekeys.android.i18n.appTxt
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.android.vault.VaultCounterStore
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.HelloCounterSource
import app.localgatekeys.core.lan.MonotonicClock
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.StoreSnapshot
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The free plan of the phone Wi-Fi host on the device, with the real network seams (as [WifiHostDeviceTest]: the
 * host listens on the emulator's Wi-Fi address and a second coordinator in this process joins it with the app's
 * Wi-Fi-bound dialer). Pro is a valid licence state in the vault, verified with the TEST licence key of
 * `tests/vectors/sync/license_state.json` (never a production key), so the licence travels with sync as it does
 * between real devices. The host's listen window runs on a fake monotonic clock (the [WifiHost] seam).
 *
 * A: free host, Pro joiner. B: Pro host, free joiner. C: two free phones. D: the free host's listen window.
 */
class WifiHostLicenceDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val clock = SystemClock()
    private val scopes = ArrayList<CoroutineScope>()
    private val coordinators = ArrayList<SyncCoordinator>()
    private val hosts = ArrayList<WifiHost>()
    private val files = ArrayList<File>()

    @After fun tearDown() {
        hosts.forEach { runCatching { it.shutdown() } }
        coordinators.forEach { runCatching { it.shutdown() } }
        scopes.forEach { it.cancel() }
        files.forEach { it.delete() }
    }

    private class FakeMonotonic(@Volatile var now: Double = 1_000.0) : MonotonicClock {
        override fun seconds(): Double = now
    }

    private class Phone(val coordinator: SyncCoordinator, val store: MemoryStore, val slots: SecretSlots)

    private fun CoroutineScope.phone(name: String, store: MemoryStore, lan: (HelloCounterSource) -> LanTransporting): Phone {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        scopes.add(scope)
        val file = File(context.cacheDir, "wifi-host-licence-$name-${System.nanoTime()}.bin").also { files.add(it) }
        val slots = SecretSlots(file, ByteArray(32) { 5 }, SystemRandomSource())
        val counters = HelloCounterSource(VaultCounterStore(slots), clock)
        val deps = SyncDependencies(
            slots = slots, folders = FolderOpening.UNAVAILABLE, lan = lan(counters), random = SystemRandomSource(), clock = clock,
            licenseKeys = TEST_KEYS, sleep = {}, counters = counters,
        )
        val c = SyncCoordinator(store, deps, scope, appTxt())
        coordinators.add(c)
        return Phone(c, store, slots)
    }

    private fun joiner(scope: CoroutineScope, name: String, store: MemoryStore, binder: WifiNetworkBinder): Phone =
        scope.phone(name, store) { SocketLanTransport(it, SystemRandomSource(), clock, dialer = ChannelLanDialer(bind = binder::bind)) }

    private suspend fun until(what: String, ms: Long = 30_000, cond: () -> Boolean) {
        try {
            withTimeout(ms) { while (!cond()) delay(20) }
        } catch (e: Exception) {
            throw AssertionError("timed out waiting for $what", e)
        }
    }

    private fun isPro(store: MemoryStore): Boolean = ItemLimit.validLicense(store.snapshot, TEST_KEYS) != null

    private class Setup(val host: WifiHost, val a: Phone, val wifi: String, val binder: WifiNetworkBinder, val mono: FakeMonotonic)

    /** A host phone on the real Wi-Fi seams, Pro exactly when its vault holds a valid (test) licence; on and in front. */
    private suspend fun CoroutineScope.hostPhone(store: MemoryStore): Setup {
        val binder = WifiNetworkBinder(context)
        val platform = AndroidHostPlatform(context, binder::localNetwork)
        val wifi = platform.wifiAddress()
        assumeTrue("the device has no Wi-Fi address", wifi != null)
        val a = phone("host", store) { LanTransporting.UNAVAILABLE }
        val mono = FakeMonotonic()
        val hostScope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob()).also { scopes.add(it) }
        val enabled = booleanArrayOf(false)
        val host = WifiHost(
            a.coordinator, a.coordinator.deps.counters!!, platform, hostScope, { enabled[0] }, { enabled[0] = it },
            monotonic = mono, tickMillis = 200,
        )
        host.isPro = { isPro(store) }
        a.coordinator.host = host
        hosts.add(host)
        host.foreground = true
        host.setEnabled(true)
        return Setup(host, a, wifi!!, binder, mono)
    }

    /** Show QR code, the joiner joins (its first sync runs inside the join), Accept. */
    private suspend fun CoroutineScope.pair(s: Setup, b: Phone) {
        assertEquals(WifiHost.ShowResult.SHOWN, s.host.showQr())
        assertTrue(s.host.isListening)
        val qr = s.host.pairing.state.value.qrText!!
        val joined = async { b.coordinator.joinByQr(qr) }
        until("asked", 60_000) { s.host.pairing.state.value.stage == HostPairing.Stage.CONFIRM }
        assertTrue(s.host.pairing.decide(true, s.host.pairing.state.value.request!!.deviceId))
        assertTrue(b.coordinator.actionError.value ?: "", joined.await())
        until("paired") { s.host.pairing.state.value.stage == HostPairing.Stage.PAIRED }
        assertEquals(s.wifi, b.slots.pairedPeer()!!.endpoint!!.host)
        assertEquals(1, s.a.store.snapshot.sync!!.lanPeers.size)
    }

    private suspend fun reachable(wifi: String, port: Int): Boolean = withContext(Dispatchers.IO) {
        try {
            Socket().use { it.connect(InetSocketAddress(InetAddress.getByName(wifi), port), 3_000) }
            true
        } catch (e: java.io.IOException) {
            false
        }
    }

    @Test fun a_free_host_and_a_pro_joiner_licence_first_then_items_both_ways() = runBlocking<Unit> {
        withTimeout(240_000) {
            val (id1, rec1) = deviceNoteRecord(11, "On the free host")
            val (id2, rec2) = deviceNoteRecord(12, "On the Pro joiner")
            val aStore = MemoryStore(StoreSnapshot(records = mapOf(id1 to rec1)))
            val bStore = MemoryStore(StoreSnapshot(records = mapOf(id2 to rec2, LICENCE_STATE_ID to licenceWrapper())))
            assertTrue(isPro(bStore))
            val s = hostPhone(aStore)
            assertTrue(s.host.status.value.licenceOnly)
            assertFalse("a free host does not listen before a code is shown", s.host.isListening)
            val b = joiner(this, "joiner", bStore, s.binder)

            pair(s, b)
            // The first exchange (inside the join): only the licence crossed, no item either way.
            until("the licence reached the host") { aStore.snapshot.records.containsKey(LICENCE_STATE_ID) }
            assertFalse("the joiner's item landed on the free host", aStore.snapshot.records.containsKey(id2))
            assertFalse("the free host's item reached the joiner", bStore.snapshot.records.containsKey(id1))
            assertTrue(isPro(aStore))

            // The host reads Pro on its next tick: full hosting, no window.
            until("the host became Pro") { !s.host.status.value.licenceOnly }
            s.mono.now += 10_000
            delay(500)
            assertTrue("a Pro host keeps listening", s.host.isListening)

            // The next sync: items cross both ways.
            b.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
            until("joiner got the host's item", 60_000) { bStore.snapshot.records.containsKey(id1) }
            until("host got the joiner's item", 60_000) { aStore.snapshot.records.containsKey(id2) }
            assertTrue(b.coordinator.issues.value.toString(), b.coordinator.issues.value.isEmpty())
        }
    }

    @Test fun a_pro_host_and_a_free_joiner_the_licence_reaches_the_joiner_and_items_sync() = runBlocking<Unit> {
        withTimeout(240_000) {
            val (id1, rec1) = deviceNoteRecord(21, "On the Pro host")
            val (id2, rec2) = deviceNoteRecord(22, "On the free joiner")
            val aStore = MemoryStore(StoreSnapshot(records = mapOf(id1 to rec1, LICENCE_STATE_ID to licenceWrapper())))
            val bStore = MemoryStore(StoreSnapshot(records = mapOf(id2 to rec2)))
            assertFalse(isPro(bStore))
            val s = hostPhone(aStore)
            until("a Pro host listens without a code") { s.host.isListening }
            assertFalse(s.host.status.value.licenceOnly)
            val b = joiner(this, "joiner", bStore, s.binder)

            pair(s, b)
            // The first exchange (inside the join): the licence and the items, both ways.
            until("the licence reached the joiner") { bStore.snapshot.records.containsKey(LICENCE_STATE_ID) }
            assertTrue("the free joiner is Pro now", isPro(bStore))
            val itemsInFirstRun = bStore.snapshot.records.containsKey(id1) && aStore.snapshot.records.containsKey(id2)
            android.util.Log.i("WifiHostLicence", "B: items crossed in the first exchange with the licence: $itemsInFirstRun")

            b.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
            until("joiner got the host's item", 60_000) { bStore.snapshot.records.containsKey(id1) }
            until("host got the joiner's item", 60_000) { aStore.snapshot.records.containsKey(id2) }
            assertTrue(b.coordinator.issues.value.toString(), b.coordinator.issues.value.isEmpty())
        }
    }

    @Test fun two_free_phones_pair_but_no_item_syncs() = runBlocking<Unit> {
        withTimeout(240_000) {
            val (id1, rec1) = deviceNoteRecord(31, "On the free host")
            val (id2, rec2) = deviceNoteRecord(32, "On the free joiner")
            val aStore = MemoryStore(StoreSnapshot(records = mapOf(id1 to rec1)))
            val bStore = MemoryStore(StoreSnapshot(records = mapOf(id2 to rec2)))
            val s = hostPhone(aStore)
            assertFalse(s.host.isListening)
            val b = joiner(this, "joiner", bStore, s.binder)

            pair(s, b)
            val aRecords = aStore.snapshot.records.keys
            val bRecords = bStore.snapshot.records.keys
            // A second sync inside the window (Sync now on the host keeps it open): still nothing crosses.
            s.a.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
            assertTrue(s.host.isListening)
            b.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
            delay(1_000)
            assertEquals(setOf(id1), aStore.snapshot.records.keys)
            assertEquals(setOf(id2), bStore.snapshot.records.keys)
            assertEquals(aRecords, aStore.snapshot.records.keys)
            assertEquals(bRecords, bStore.snapshot.records.keys)
            assertFalse(isPro(aStore))
            assertFalse(isPro(bStore))
            assertTrue(s.host.status.value.licenceOnly)
            android.util.Log.i("WifiHostLicence", "C: joiner issues after a licence-only exchange: ${b.coordinator.issues.value}")
        }
    }

    @Test fun a_free_host_listens_for_the_window_after_the_code_closes_and_after_sync_now() = runBlocking<Unit> {
        withTimeout(240_000) {
            val aStore = MemoryStore(StoreSnapshot(records = mapOf(deviceNoteRecord(41, "On the free host"))))
            val bStore = MemoryStore(StoreSnapshot(records = mapOf(deviceNoteRecord(42, "On the free joiner"))))
            val s = hostPhone(aStore)
            assertEquals(120.0, WifiHost.LISTEN_WINDOW_SECONDS, 0.0)
            delay(500)
            assertFalse(s.host.isListening)
            val b = joiner(this, "joiner", bStore, s.binder)

            pair(s, b)
            val port = s.host.status.value.endpoint!!.port
            s.host.closePairing()
            assertNull(s.host.status.value.problem)

            // Inside the window: listening, reachable, and the paired joiner's sync is served.
            s.mono.now += WifiHost.LISTEN_WINDOW_SECONDS - 1
            s.host.tick()
            assertTrue(s.host.isListening)
            assertTrue(reachable(s.wifi, port))
            b.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
            assertTrue("served inside the window: ${b.coordinator.issues.value}", b.coordinator.issues.value.isEmpty())

            // After it: closed (nothing listens on the port; the joiner cannot reach the host).
            s.mono.now += 2
            s.host.tick()
            assertFalse(s.host.isListening)
            assertNull(s.host.status.value.endpoint)
            assertNull(s.host.status.value.problem)
            assertFalse(reachable(s.wifi, port))
            b.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
            assertTrue("the joiner reached a closed host", b.coordinator.issues.value.isNotEmpty())
            delay(1_000)
            assertFalse("the host started again by itself", s.host.isListening)

            // Sync now on the host opens the window again, for 120 s.
            s.a.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
            until("listening after Sync now") { s.host.isListening }
            assertEquals(port, s.host.status.value.endpoint!!.port)
            assertTrue(reachable(s.wifi, port))
            s.mono.now += WifiHost.LISTEN_WINDOW_SECONDS - 1
            s.host.tick()
            assertTrue(s.host.isListening)
            s.mono.now += 2
            s.host.tick()
            assertFalse(s.host.isListening)
            assertFalse(reachable(s.wifi, port))
        }
    }

    private companion object {
        /** TEST ONLY (`tests/vectors/sync/license_state.json`): production keys never verify this licence. */
        const val LICENCE_STATE_ID = "lic:c0c4c0830c8852c32ec77d23552e01ac"
        val TEST_KEYS: Map<String, ByteArray> = mapOf("08974d13b2b5fc4d" to Base64Std.decodeStrict("ymxvVxqcaDrLVlrVMEJ3vow1Fx4Q9aWJ5fzDHmnktTk="))
        const val LICENCE_WRAPPER = """{"ns":"license","record":{"license":{"edition":"pro","email":"ada@example.com","format":1,""" +
            """"issued_at":"2026-09-21","license_id":"lic-vector-0001","name":"Ada Lovelace","updates_until":"2027-09-21"},""" +
            """"signature":{"alg":"Ed25519","key_id":"08974d13b2b5fc4d","signature":""" +
            """"ejfT3fXgqVKY1AJwdSyCgwms4zBodRvXXGR8PyETHYedaPdZyampUwwoxupDTXjWcMtKRffq5rpogVLb2ryXBg=="}},"schema":1,"updated_at":0}"""

        fun licenceWrapper(): JsonValue = CanonicalJson.parse(LICENCE_WRAPPER.toByteArray(Charsets.UTF_8))
    }
}
