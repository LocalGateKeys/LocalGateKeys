package app.localgatekeys.android.sync

import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import app.localgatekeys.android.i18n.appTxt
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.android.vault.VaultCounterStore
import app.localgatekeys.core.lan.Discovery
import app.localgatekeys.core.lan.HelloCounterSource
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.Wrapper
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
 * Phone Wi-Fi host on the device itself, with the real network seams: [AndroidHostPlatform] picks the emulator's Wi-Fi
 * address and announces `_lgksync._tcp` (API 33+: NsdManager on the Wi-Fi network; 29-32: JmDNS on the Wi-Fi address),
 * the listener is bound to that address, and a second coordinator in this process joins it through the app's real
 * dialer bound to the Wi-Fi network (nothing leaves the emulator): background and front, QR pairing, Accept, sync both
 * ways, Undo, then the lock. Each test runs on runBlocking's event loop (the coordinator's "main thread").
 */
class WifiHostDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val clock = SystemClock()
    private val scopes = ArrayList<CoroutineScope>()
    private val coordinators = ArrayList<SyncCoordinator>()
    private val files = ArrayList<File>()

    @After fun tearDown() {
        coordinators.forEach { runCatching { it.shutdown() } }
        scopes.forEach { it.cancel() }
        files.forEach { it.delete() }
    }

    private class Phone(val coordinator: SyncCoordinator, val store: MemoryStore, val slots: SecretSlots)

    private fun CoroutineScope.phone(name: String, store: MemoryStore, lan: (HelloCounterSource) -> LanTransporting): Phone {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        scopes.add(scope)
        val file = File(context.cacheDir, "wifi-host-device-$name-${System.nanoTime()}.bin").also { files.add(it) }
        val slots = SecretSlots(file, ByteArray(32) { 3 }, SystemRandomSource())
        val counters = HelloCounterSource(VaultCounterStore(slots), clock)
        val deps = SyncDependencies(
            slots = slots, folders = FolderOpening.UNAVAILABLE, lan = lan(counters), random = SystemRandomSource(), clock = clock,
            licenseKeys = emptyMap(), sleep = {}, counters = counters,
        )
        val c = SyncCoordinator(store, deps, scope, appTxt())
        coordinators.add(c)
        return Phone(c, store, slots)
    }

    private suspend fun until(what: String, ms: Long = 30_000, cond: () -> Boolean) {
        try {
            withTimeout(ms) { while (!cond()) delay(20) }
        } catch (e: Exception) {
            throw AssertionError("timed out waiting for $what", e)
        }
    }

    private suspend fun browse(binder: WifiNetworkBinder, port: Int, ms: Long = 10_000): Discovery.Announcement? =
        withContext(Dispatchers.IO) {
            val deadline = System.currentTimeMillis() + 45_000
            var hit: Discovery.Announcement? = null
            while (hit == null && System.currentTimeMillis() < deadline) {
                hit = NsdServiceBrowser(context, binder::localNetwork).browse(Discovery.SERVICE_TYPE, ms).firstOrNull { it.port == port }
            }
            hit
        }

    @Test fun the_phone_host_listens_on_wifi_announces_pairs_and_syncs_both_ways() = runBlocking {
        withTimeout(240_000) {
            val binder = WifiNetworkBinder(context)
            val platform = AndroidHostPlatform(context, binder::localNetwork)
            val wifi = platform.wifiAddress()
            assumeTrue("the device has no Wi-Fi address", wifi != null)
            assertEquals(
                if (Build.VERSION.SDK_INT >= 33) AnnouncerKind.NSD_ON_WIFI_NETWORK else AnnouncerKind.JMDNS_ON_WIFI_ADDRESS,
                AnnouncerKind.forSdk(Build.VERSION.SDK_INT),
            )

            val (id1, rec1) = deviceNoteRecord(1, "On the host")
            val (id2, rec2) = deviceNoteRecord(2, "On the joiner")
            val aStore = MemoryStore(StoreSnapshot(records = mapOf(id1 to rec1)))
            val a = phone("a", aStore) { LanTransporting.UNAVAILABLE }
            val saved = booleanArrayOf(false)
            val hostScope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob()).also { scopes.add(it) }
            val host = WifiHost(a.coordinator, a.coordinator.deps.counters!!, platform, hostScope, { saved[0] }, { saved[0] = it })
            host.isPro = { true }
            a.coordinator.host = host

            // Off by default; on + in front: listening on the Wi-Fi address; background stops it, front starts it again.
            host.foreground = true
            host.update()
            assertFalse(host.isListening)
            host.setEnabled(true)
            until("listening") { host.isListening }
            val endpoint = host.status.value.endpoint!!
            assertEquals(wifi, endpoint.host)
            withContext(Dispatchers.IO) { Socket().use { it.connect(InetSocketAddress(InetAddress.getByName(wifi), endpoint.port), 3_000) } }
            host.foreground = false
            until("stopped in the background") { !host.isListening }
            assertNull(host.status.value.endpoint)
            host.foreground = true
            until("listening again") { host.isListening }
            val port = host.status.value.endpoint!!.port

            val bStore = MemoryStore(StoreSnapshot(records = mapOf(id2 to rec2)))
            val b = phone("b", bStore) { SocketLanTransport(it, SystemRandomSource(), clock, dialer = ChannelLanDialer(bind = binder::bind)) }

            // The QR code makes the Wi-Fi group, so the service is announced on the Wi-Fi network with v and t.
            assertEquals(WifiHost.ShowResult.SHOWN, host.showQr())
            val qr = host.pairing.state.value.qrText!!
            assertTrue(qr, qr.startsWith("lgk-pair:"))
            val seen = browse(binder, port)
            assertNotNull("the announcement was not found on the Wi-Fi network", seen)
            assertEquals(wifi, seen!!.host)
            assertEquals("1", seen.txt["v"])
            assertTrue(seen.txt["t"].orEmpty().isNotEmpty())

            // Pair: the joiner dials the real Wi-Fi address; the host accepts.
            val joined = async { b.coordinator.joinByQr(qr) }
            until("asked", 60_000) { host.pairing.state.value.stage == HostPairing.Stage.CONFIRM }
            val request = host.pairing.state.value.request!!
            assertTrue(host.pairing.decide(true, request.deviceId))
            assertTrue(b.coordinator.actionError.value ?: "", joined.await())
            until("paired") { host.pairing.state.value.stage == HostPairing.Stage.PAIRED }
            val pinned = b.slots.pairedPeer()!!.endpoint!!
            assertEquals(wifi to port, pinned.host to pinned.port)
            assertEquals(1, aStore.snapshot.sync!!.lanPeers.size)

            // Sync both ways, then a change on each side travels on the next run.
            until("joiner got the host's item", 60_000) { bStore.snapshot.records.containsKey(id1) }
            until("host got the joiner's item", 60_000) { aStore.snapshot.records.containsKey(id2) }
            val (id3, rec3) = deviceNoteRecord(3, "Later on the joiner")
            bStore.put(id3, rec3)
            b.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
            until("host got the later item", 60_000) { aStore.snapshot.records.containsKey(id3) }
            assertTrue(b.coordinator.issues.value.toString(), b.coordinator.issues.value.isEmpty())

            // Undo: revoked; the joiner's next sync is refused.
            assertTrue(host.undo())
            assertTrue(aStore.snapshot.sync!!.lanPeers.single().revoked)
            b.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
            assertTrue(b.coordinator.issues.value.isNotEmpty())

            // Locking stops the listener (the coordinator's gate closes).
            a.coordinator.shutdown()
            until("stopped by the lock") { !host.isListening }
        }
    }
}

/** An [ItemStore] safe to touch from the coordinator's background work. */
class MemoryStore(s: StoreSnapshot = StoreSnapshot()) : ItemStore {
    private var snap = s
    val snapshot: StoreSnapshot get() = synchronized(this) { snap }

    override fun load(): StoreSnapshot = synchronized(this) { snap }

    @Synchronized override fun commit(change: StoreChange) {
        check(change.baseRevision == snap.revision) { "stale: ${change.baseRevision} != ${snap.revision}" }
        val shares = when (val sh = change.shares) {
            StoreChange.Shares.Keep -> snap.shares
            is StoreChange.Shares.Replace -> sh.value
        }
        snap = StoreSnapshot(change.records, change.meta, change.sync, snap.revision + 1, shares, change.collectionsMigrated ?: snap.collectionsMigrated)
    }

    /** A local edit: the item [id] added or replaced. */
    @Synchronized fun put(id: String, record: JsonValue) {
        snap = snap.copy(records = snap.records + (id to record), revision = snap.revision + 1)
    }
}

fun deviceNoteRecord(i: Int, title: String = "Note"): Pair<String, JsonValue> {
    val id = "00000000-0000-4000-8000-%012d".format(i)
    val r = JsonValue.Obj(
        mapOf(
            "id" to JsonValue.Str(id), "kind" to JsonValue.Str("note"), "title" to JsonValue.Str("$title $i"),
            "created_at" to JsonValue.Int(1_700_000_000), "updated_at" to JsonValue.Int(1_700_000_000L + i),
            "favorite" to JsonValue.Bool(false), "tags" to JsonValue.Arr(emptyList()),
            "payload" to JsonValue.Obj(
                mapOf("body" to JsonValue.Str("body $i"), "fields" to JsonValue.Arr(emptyList()), "template_id" to JsonValue.Null),
            ),
        ),
    )
    return id to Wrapper.make(Namespace.ITEM, Normalise.normalForm(Namespace.ITEM, r))
}
