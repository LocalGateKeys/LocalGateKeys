package app.localgatekeys.android.sync

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.android.vault.VaultCounterStore
import app.localgatekeys.core.lan.HelloCounterSource
import app.localgatekeys.core.lan.MonotonicClock
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.Collections

/**
 * Phone Wi-Fi host mode (design 2026-11-13): the lifecycle and Pro rules of [WifiHost] with a fake network (a LAN
 * address named, loopback bound), and a phone that joins this phone host by QR and syncs through the app's own
 * socket transport. Each test runs on runBlocking's event loop (the coordinator's "main thread").
 */
class WifiHostTest {
    @get:Rule val tmp = TemporaryFolder()

    private val scopes = ArrayList<CoroutineScope>()
    private val coordinators = ArrayList<SyncCoordinator>()
    private val clock = SystemClock()

    @After fun tearDown() {
        coordinators.forEach { runCatching { it.shutdown() } }
        scopes.forEach { it.cancel() }
    }

    private class FakeMonotonic : MonotonicClock {
        @Volatile var now = 1_000.0
        override fun seconds(): Double = now
    }

    /** Names a Wi-Fi address (null: none) and binds loopback; records announcements and their withdrawals. */
    private class FakePlatform : HostPlatform {
        @Volatile var address: String? = "192.168.77.10"
        val announced: MutableList<Triple<String, Int, Map<String, String>>> = Collections.synchronizedList(ArrayList())
        @Volatile var live = 0
        override fun wifiAddress(): String? = address
        override fun announce(name: String, port: Int, txt: Map<String, String>): AutoCloseable {
            announced.add(Triple(name, port, txt))
            live += 1
            return AutoCloseable { live -= 1 }
        }
        override fun bindAddress(address: String): InetAddress = InetAddress.getLoopbackAddress()
    }

    private class Phone(val coordinator: SyncCoordinator, val store: LockedStore, val slots: SecretSlots)

    private fun test(body: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60_000) { body() } }

    private fun CoroutineScope.phone(name: String, store: LockedStore, lan: (HelloCounterSource) -> LanTransporting = { LanTransporting.UNAVAILABLE }): Phone {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        scopes.add(scope)
        val slots = SecretSlots(tmp.newFile("$name.bin").also { it.delete() }, ByteArray(32) { 3 }, SystemRandomSource())
        val counters = HelloCounterSource(VaultCounterStore(slots), clock)
        val deps = SyncDependencies(
            slots = slots, folders = FolderOpening.UNAVAILABLE, lan = lan(counters), random = SystemRandomSource(), clock = clock,
            licenseKeys = emptyMap(), sleep = {}, counters = counters,
        )
        val c = SyncCoordinator(store, deps, scope, EnglishTxt())
        coordinators.add(c)
        return Phone(c, store, slots)
    }

    private fun CoroutineScope.host(
        phone: Phone,
        platform: FakePlatform,
        mono: FakeMonotonic,
        pro: Boolean,
        enabled: Boolean = false,
    ): Pair<WifiHost, BooleanArray> {
        val saved = booleanArrayOf(enabled)
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        scopes.add(scope)
        val h = WifiHost(
            phone.coordinator, phone.coordinator.deps.counters!!, platform, scope,
            readEnabled = { saved[0] }, writeEnabled = { saved[0] = it }, monotonic = mono, tickMillis = 3_600_000,
        )
        h.isPro = { pro }
        phone.coordinator.host = h
        return h to saved
    }

    private suspend fun until(what: String, cond: () -> Boolean) {
        try {
            withTimeout(20_000) { while (!cond()) delay(2) }
        } catch (e: Exception) {
            throw AssertionError("timed out waiting for $what", e)
        }
    }

    @Test fun off_by_default_and_listens_only_in_front_while_unlocked() = test {
        val platform = FakePlatform()
        val a = phone("a", LockedStore())
        val (host, saved) = host(a, platform, FakeMonotonic(), pro = true)
        host.foreground = true
        assertFalse(host.status.value.enabled)
        delay(20)
        assertFalse(host.isListening)

        host.setEnabled(true)
        assertTrue(saved[0])
        until("listening") { host.status.value.listening }
        val ep = host.status.value.endpoint!!
        assertEquals("192.168.77.10", ep.host)
        assertTrue(ep.port > 0)
        assertFalse(host.status.value.licenceOnly)
        assertEquals(0, platform.live) // no group yet: nothing to announce

        host.foreground = false // background
        assertFalse(host.isListening)
        assertFalse(host.status.value.listening)
        host.foreground = true
        until("listening again") { host.status.value.listening }
        assertEquals(ep.port, host.status.value.endpoint!!.port) // the same port again when it is free

        host.setEnabled(false)
        assertFalse(saved[0])
        assertFalse(host.isListening)
        host.setEnabled(true)
        until("listening once more") { host.isListening }

        a.coordinator.shutdown() // the lock
        assertFalse(host.isListening)
        host.setEnabled(true)
        host.foreground = false
        host.foreground = true
        delay(50)
        assertFalse(host.isListening)
        assertEquals(WifiHost.ShowResult.NOT_LISTENING, host.showQr())
    }

    /** A host for [phone] whose saved port lives in [port] (the app's settings), as each unlock builds a new one. */
    private fun CoroutineScope.portHost(phone: Phone, port: Array<Int?>, writes: MutableList<Int>): WifiHost {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        scopes.add(scope)
        val h = WifiHost(
            phone.coordinator, phone.coordinator.deps.counters!!, FakePlatform(), scope,
            readEnabled = { true }, writeEnabled = {}, monotonic = FakeMonotonic(), tickMillis = 3_600_000,
            readPort = { port[0] }, writePort = { port[0] = it; writes.add(it) },
        )
        h.isPro = { true }
        phone.coordinator.host = h
        return h
    }

    private fun freePort(): Int = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { it.localPort }

    @Test fun the_port_is_saved_and_listened_on_again_after_the_next_unlock() = test {
        val saved = arrayOf<Int?>(freePort())
        val writes = ArrayList<Int>()
        val a = phone("a", LockedStore())
        val first = portHost(a, saved, writes)
        first.foreground = true
        until("listening") { first.isListening }
        val port = first.status.value.endpoint!!.port
        assertEquals(saved[0], port)
        assertEquals(emptyList<Int>(), writes) // already saved: not written again
        a.coordinator.shutdown() // the lock
        assertFalse(first.isListening)

        // The next unlock builds a new coordinator and host: the same saved port.
        val second = portHost(phone("b", LockedStore()), saved, writes)
        second.foreground = true
        until("listening after the unlock") { second.isListening }
        assertEquals(port, second.status.value.endpoint!!.port)
        assertEquals(emptyList<Int>(), writes)
    }

    @Test fun a_taken_saved_port_falls_back_to_a_system_port_which_is_saved() = test {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { taken ->
            val saved = arrayOf<Int?>(taken.localPort)
            val writes = ArrayList<Int>()
            val host = portHost(phone("a", LockedStore()), saved, writes)
            host.foreground = true
            until("listening") { host.isListening }
            val port = host.status.value.endpoint!!.port
            assertTrue(port != taken.localPort && port > 0)
            assertEquals(listOf(port), writes)
            assertEquals(port, saved[0])
        }
    }

    @Test fun with_no_saved_port_the_desktop_port_is_tried_first() = test {
        assertEquals(47821, WifiHost.FIRST_PORT)
        val free = try {
            ServerSocket(WifiHost.FIRST_PORT, 1, InetAddress.getLoopbackAddress()).close()
            true
        } catch (e: java.io.IOException) {
            false
        }
        val saved = arrayOf<Int?>(null)
        val writes = ArrayList<Int>()
        val host = portHost(phone("a", LockedStore()), saved, writes)
        host.foreground = true
        until("listening") { host.isListening }
        val port = host.status.value.endpoint!!.port
        if (free) assertEquals(WifiHost.FIRST_PORT, port)
        assertEquals(listOf(port), writes)
        assertEquals(port, saved[0])
    }

    @Test fun a_free_host_listens_only_while_a_code_is_shown_and_two_minutes_after() = test {
        val platform = FakePlatform()
        val mono = FakeMonotonic()
        val a = phone("a", LockedStore())
        val (host, _) = host(a, platform, mono, pro = false, enabled = true)
        host.foreground = true
        delay(20)
        assertTrue(host.status.value.enabled)
        assertTrue(host.status.value.licenceOnly)
        assertFalse(host.isListening)

        // Show QR code: the window opens, the listener starts, a Wi-Fi group is made and announced.
        assertEquals(WifiHost.ShowResult.SHOWN, host.showQr())
        assertTrue(host.isListening)
        assertEquals(HostPairing.Stage.SHOWING, host.pairing.state.value.stage)
        val state = a.store.snapshot.sync
        assertNotNull(state)
        assertFalse(state!!.hasFolder)
        until("announced") { platform.live == 1 }
        val (name, port, txt) = platform.announced.last()
        assertTrue(name, Regex("LocalGateKeys-[0-9a-f]{4}").matches(name))
        assertEquals(host.status.value.endpoint!!.port, port)
        assertEquals(setOf("v", "t"), txt.keys)
        assertEquals("1", txt["v"])
        assertEquals(16, txt["t"]!!.length)
        val qr = host.pairing.state.value.qrText!!
        assertTrue(qr.startsWith("lgk-pair:"))

        // While shown, the window keeps moving; closed, it runs 120 s more, then the host stops quietly.
        mono.now += 500
        host.tick()
        assertTrue(host.isListening)
        host.closePairing()
        mono.now += 119
        host.tick()
        assertTrue(host.isListening)
        mono.now += 2
        host.tick()
        assertFalse(host.isListening)
        assertEquals(0, platform.live)
        assertNull(host.status.value.problem)

        // Sync now opens the window again.
        a.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
        until("listening after Sync now") { host.isListening }
        mono.now += 121
        host.tick()
        assertFalse(host.isListening)

        // Pro gained: full hosting, no window.
        host.isPro = { true }
        host.tick()
        until("listening with Pro") { host.isListening }
        assertFalse(host.status.value.licenceOnly)
        mono.now += 10_000
        host.tick()
        assertTrue(host.isListening)
    }

    @Test fun no_wifi_then_wifi_and_an_address_that_goes_and_comes_back() = test {
        val platform = FakePlatform()
        platform.address = null
        val a = phone("a", LockedStore())
        val (host, _) = host(a, platform, FakeMonotonic(), pro = true, enabled = true)
        host.foreground = true
        assertEquals(WifiHost.Problem.NO_WIFI, host.status.value.problem)
        assertFalse(host.isListening)
        platform.address = "192.168.77.10"
        host.tick()
        until("listening") { host.isListening }
        assertNull(host.status.value.problem)

        platform.address = null
        host.tick()
        assertFalse(host.isListening)
        assertEquals(WifiHost.Problem.STOPPED, host.status.value.problem)
        platform.address = "192.168.77.10"
        host.tick()
        until("listening again") { host.isListening }
        assertNull(host.status.value.problem)
    }

    @Test fun pairing_text_helpers_match_the_desktop() {
        assertEquals("123 456", HostPairing.formatCode("123456"))
        assertEquals("", HostPairing.formatCode("12345a"))
        assertEquals("", HostPairing.formatCode("1234567"))
        assertEquals("0123 4567 89ab cdef", HostPairing.fingerprintText("0123456789abcdef0123"))
        assertEquals("", HostPairing.fingerprintText("0123456789ABCDEF"))
        assertEquals("1:05", HostPairing.clock(65))
        assertEquals("0:00", HostPairing.clock(0))
    }

    // MARK: end to end: a phone joins this phone host and syncs through the app's socket transport

    /** Every dial goes to the host's port on loopback, whatever LAN address the offer or peer names. */
    private fun loopbackTransport(counters: HelloCounterSource, port: () -> Int): SocketLanTransport {
        val dialer = ChannelLanDialer(
            30_000, enrollReplyMs = 90_000, bind = { _, _ -> }, route = { InetSocketAddress(InetAddress.getLoopbackAddress(), port()) },
        )
        return SocketLanTransport(counters, SystemRandomSource(), clock, dialer = dialer)
    }

    @Test fun a_phone_declined_then_accepted_pairs_with_the_phone_host_and_syncs_both_ways() = test {
        val platform = FakePlatform()
        val (id1, rec1) = noteRecord(1, "On the host")
        val (id2, rec2) = noteRecord(2, "On the joiner")
        val aStore = LockedStore(StoreSnapshot(records = mapOf(id1 to rec1)))
        val a = phone("a", aStore)
        val (host, _) = host(a, platform, FakeMonotonic(), pro = true, enabled = true)
        host.foreground = true
        until("listening") { host.isListening }
        val port = { host.status.value.endpoint!!.port }
        val bStore = LockedStore(StoreSnapshot(records = mapOf(id2 to rec2)))
        val b = phone("b", bStore) { loopbackTransport(it, port) }

        // Declined: nothing is pinned on either side.
        assertEquals(WifiHost.ShowResult.SHOWN, host.showQr())
        val first = host.pairing.state.value.qrText!!
        val declined = async { b.coordinator.joinByQr(first) }
        until("asked") { host.pairing.state.value.stage == HostPairing.Stage.CONFIRM }
        val asked = host.pairing.state.value.request!!
        assertEquals(7, asked.code.length)
        assertTrue(host.pairing.decide(false, asked.deviceId))
        assertFalse(declined.await())
        assertEquals(HostPairing.Stage.DECLINED, host.pairing.state.value.stage)
        assertNull(b.slots.pairedPeer())
        assertTrue(aStore.snapshot.sync!!.lanPeers.isEmpty())
        assertFalse(host.pairing.decide(true, asked.deviceId)) // no longer waiting
        assertEquals(HostPairing.Note.NOT_WAITING, host.pairing.state.value.note)

        // The used code: a second scan gets no pairing.
        assertFalse(b.coordinator.joinByQr(first))

        // A new code, accepted: the phone is pinned without an endpoint and syncs both ways.
        assertEquals(WifiHost.ShowResult.SHOWN, host.showQr())
        val second = host.pairing.state.value.qrText!!
        val joined = async { b.coordinator.joinByQr(second) }
        until("asked again") { host.pairing.state.value.stage == HostPairing.Stage.CONFIRM }
        val request = host.pairing.state.value.request!!
        assertTrue(host.pairing.decide(true, request.deviceId))
        assertTrue(b.coordinator.actionError.value ?: "", joined.await())
        until("paired") { host.pairing.state.value.stage == HostPairing.Stage.PAIRED }
        val peers = aStore.snapshot.sync!!.lanPeers
        assertEquals(1, peers.size)
        assertNull(peers[0].endpoint)
        assertTrue(peers[0].sealed)
        assertEquals(b.store.snapshot.sync!!.deviceId, peers[0].deviceId)
        assertEquals(a.store.snapshot.sync!!.deviceId, b.slots.pairedPeer()!!.deviceId)
        val pinned = b.slots.pairedPeer()!!.endpoint!!
        assertEquals("192.168.77.10" to port(), pinned.host to pinned.port)

        until("joiner got the host's item") { bStore.snapshot.records.containsKey(id1) }
        until("host got the joiner's item") { aStore.snapshot.records.containsKey(id2) }
        assertTrue(b.coordinator.issues.value.toString(), b.coordinator.issues.value.isEmpty())

        // Undo: revoked (kept listed); the joiner's next sync is refused.
        assertTrue(host.undo())
        assertTrue(aStore.snapshot.sync!!.lanPeers.single().revoked)
        b.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
        assertTrue(b.coordinator.issues.value.isNotEmpty())
    }

    /** Shows a new code on [host], has [b] scan it and the host's user choose Accept; returns the request's device id. */
    private suspend fun CoroutineScope.pairAccepted(host: WifiHost, b: Phone): String {
        assertEquals(WifiHost.ShowResult.SHOWN, host.showQr())
        val text = host.pairing.state.value.qrText!!
        val joined = async { b.coordinator.joinByQr(text) }
        until("asked") { host.pairing.state.value.stage == HostPairing.Stage.CONFIRM }
        val request = host.pairing.state.value.request!!
        assertTrue(host.pairing.decide(true, request.deviceId))
        assertTrue(b.coordinator.actionError.value ?: "", joined.await())
        until("paired") { host.pairing.state.value.stage == HostPairing.Stage.PAIRED }
        return request.deviceId
    }

    // Design 2026-11-17 keep-device-id-on-rejoin: Leave, then pair again with the same phone host.

    @Test fun a_phone_that_left_pairs_again_under_its_id_and_syncs_both_ways() = test {
        val platform = FakePlatform()
        val (id1, rec1) = noteRecord(1, "On the host")
        val (id2, rec2) = noteRecord(2, "On the joiner")
        val aStore = LockedStore(StoreSnapshot(records = mapOf(id1 to rec1)))
        val a = phone("a", aStore)
        val (host, _) = host(a, platform, FakeMonotonic(), pro = true, enabled = true)
        host.foreground = true
        until("listening") { host.isListening }
        val port = { host.status.value.endpoint!!.port }
        val bStore = LockedStore(StoreSnapshot(records = mapOf(id2 to rec2)))
        val b = phone("b", bStore) { loopbackTransport(it, port) }

        val firstId = pairAccepted(host, b)
        until("first exchange") { bStore.snapshot.records.containsKey(id1) && aStore.snapshot.records.containsKey(id2) }
        val counterBefore = bStore.snapshot.sync!!.ownCounter

        b.coordinator.leave()
        assertNull(bStore.snapshot.sync)
        assertEquals(firstId, b.slots.keptIdentity()!!.deviceId)
        // Both sides change while apart.
        val (id3, rec3) = noteRecord(3, "Host, while apart")
        val (id4, rec4) = noteRecord(4, "Joiner, while apart")
        aStore.snapshot.let { aStore.commit(StoreChange(it.revision, it.records + (id3 to rec3), it.meta, it.sync)) }
        bStore.snapshot.let { bStore.commit(StoreChange(it.revision, it.records + (id4 to rec4), it.meta, it.sync)) }

        // Paired again: the same Accept prompt, under the same id; the host keeps one entry for it.
        assertEquals(firstId, pairAccepted(host, b))
        val peers = aStore.snapshot.sync!!.lanPeers
        assertEquals(listOf(firstId), peers.map { it.deviceId })
        assertFalse(peers[0].revoked)
        assertEquals(firstId, bStore.snapshot.sync!!.deviceId)
        assertTrue(bStore.snapshot.sync!!.ownCounter >= counterBefore)
        assertNull(b.slots.keptIdentity())
        until("joiner got the host's new item") { bStore.snapshot.records.containsKey(id3) }
        until("host got the joiner's new item") { aStore.snapshot.records.containsKey(id4) }
        b.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
        assertTrue(b.coordinator.issues.value.toString(), b.coordinator.issues.value.isEmpty())
    }

    @Test fun a_removed_phone_that_left_is_refused_under_its_id_and_pairs_again_under_a_new_one() = test {
        val platform = FakePlatform()
        val a = phone("a", LockedStore())
        val (host, _) = host(a, platform, FakeMonotonic(), pro = true, enabled = true)
        host.foreground = true
        until("listening") { host.isListening }
        val port = { host.status.value.endpoint!!.port }
        val b = phone("b", LockedStore()) { loopbackTransport(it, port) }
        val firstId = pairAccepted(host, b)
        assertTrue(host.undo()) // removed on the host: revoked, kept listed
        b.coordinator.leave()
        assertEquals(firstId, b.slots.keptIdentity()!!.deviceId)

        // The host refuses the revoked id (the plain refusal): the kept identity goes and the phone says what to do.
        assertEquals(WifiHost.ShowResult.SHOWN, host.showQr())
        val text = host.pairing.state.value.qrText!!
        assertFalse(b.coordinator.joinByQr(text))
        assertEquals(
            "The other device could not pair this device under its earlier name. Show a new code there and scan it again.",
            b.coordinator.actionError.value,
        )
        assertNull(b.slots.keptIdentity())
        assertEquals(listOf(firstId), a.store.snapshot.sync!!.lanPeers.map { it.deviceId })

        // A new code: a new identity, as before; the revoked entry stays.
        val secondId = pairAccepted(host, b)
        assertNotEquals(firstId, secondId)
        assertEquals(secondId, b.store.snapshot.sync!!.deviceId)
        val peers = a.store.snapshot.sync!!.lanPeers.associateBy { it.deviceId }
        assertTrue(peers.getValue(firstId).revoked)
        assertFalse(peers.getValue(secondId).revoked)
    }
}
