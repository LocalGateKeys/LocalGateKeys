package app.localgatekeys.android.sync

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.android.vault.Slot
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.lan.CounterStore
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.Discovery
import app.localgatekeys.core.lan.Enrollment
import app.localgatekeys.core.lan.HelloCounterSource
import app.localgatekeys.core.lan.LanConnection
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.LanMessage
import app.localgatekeys.core.lan.LanMessages
import app.localgatekeys.core.lan.LanPeerNotAnswering
import app.localgatekeys.core.lan.LanSyncException
import app.localgatekeys.core.lan.LanTransport
import app.localgatekeys.core.lan.PairingOffer
import app.localgatekeys.core.lan.PinnedPeer
import app.localgatekeys.core.lan.SecureChannel
import app.localgatekeys.core.lan.SessionHello
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.RunReport
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import java.io.Closeable
import java.io.DataInputStream
import java.io.EOFException
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The socket transport (semantics of `ios/App/Sync/NWLanConnection.swift`) against a loopback responder built on core
 * `SecureChannel` / `SessionHello` / `Enrollment`, in this process. Nothing leaves 127.0.0.1. Also the ports of the
 * Swift `PairedConnectorTests` (scripted dialer).
 */
class SocketLanTransportTest {
    @get:Rule val tmp = TemporaryFolder()

    private val closeables = ArrayList<Closeable>()
    private val scopes = ArrayList<CoroutineScope>()
    private lateinit var clock: TestClock
    private val a: DeviceIdentity by lazy { SyncVectors.identity("A") }
    private val b: DeviceIdentity by lazy { SyncVectors.identity("B") }
    private val offer: PairingOffer by lazy { PairingOffer.parseQr(SyncVectors.qrText()) }
    private val groupKey: GroupKey by lazy { SyncVectors.lanGroupKey() }

    @Before fun setUp() {
        clock = TestClock(SyncVectors.lanNow())
    }

    @After fun tearDown() {
        scopes.forEach { it.cancel() }
        closeables.reversed().forEach { runCatching { it.close() } }
    }

    // MARK: test peer

    private class MemoryCounters : CounterStore {
        private var hello = 0L
        val inbound = HashMap<String, Long>()
        @Synchronized override fun persistedHelloCounter(): Long = hello
        @Synchronized override fun persistHelloCounter(last: Long) { hello = last }
        @Synchronized override fun lastAcceptedCounter(peer: String): Long = inbound[peer] ?: 0
        @Synchronized override fun setLastAcceptedCounter(counter: Long, peer: String) { inbound[peer] = counter }
    }

    /**
     * A TCP listener on 127.0.0.1; each accepted connection runs [handle] on its own thread with its index, then is
     * closed. [connections] counts accepts.
     */
    private inner class Responder(val handle: (Socket, Int) -> Unit) : Closeable {
        val server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = server.localPort
        val connections = AtomicInteger()
        val sockets: MutableList<Socket> = Collections.synchronizedList(ArrayList())
        val errors: MutableList<Throwable> = Collections.synchronizedList(ArrayList())
        private val acceptor = Thread {
            while (!server.isClosed) {
                val s = try { server.accept() } catch (_: Exception) { break }
                sockets.add(s)
                val n = connections.getAndIncrement()
                Thread {
                    try {
                        s.use { handle(it, n) }
                    } catch (e: Throwable) {
                        errors.add(e)
                    }
                }.apply { isDaemon = true }.start()
            }
        }.apply { isDaemon = true; start() }

        val endpoint: LanEndpoint get() = LanEndpoint("127.0.0.1", port)

        override fun close() {
            server.close()
            synchronized(sockets) { sockets.forEach { runCatching { it.close() } } }
            acceptor.join(2_000)
        }
    }

    private fun responder(handle: (Socket, Int) -> Unit): Responder = Responder(handle).also { closeables.add(it) }

    /** One whole frame (length prefix included), read as the desktop's `transport.read_frame` does. */
    private fun readFrame(input: InputStream): ByteArray {
        val d = DataInputStream(input)
        val header = ByteArray(4).also { d.readFully(it) }
        val n = ((header[0].toInt() and 0xFF) shl 24) or ((header[1].toInt() and 0xFF) shl 16) or
            ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
        return header + ByteArray(n).also { d.readFully(it) }
    }

    private fun pinned(id: DeviceIdentity, endpoint: LanEndpoint?) =
        PinnedPeer(id.deviceId, groupKey.groupId, id.signingPublicKey, id.exchangePublicKey, endpoint)

    /** Reads and drops whatever the client sends until it closes its end (true), or 10 s pass without that (false). */
    private fun awaitClientClose(s: Socket): Boolean {
        s.soTimeout = 10_000
        val buf = ByteArray(4096)
        return try {
            while (s.getInputStream().read(buf) >= 0) Unit
            true
        } catch (_: java.net.SocketTimeoutException) {
            false
        } catch (_: Exception) {
            true
        }
    }

    /**
     * The desktop (A) answering B's LAN sync: per connection a hello, then one sealed request; a single-chunk view of
     * B is answered with A's single-chunk view of [aStates]. [received] gets B's view bytes.
     */
    private fun viewResponder(
        aStates: List<ItemState>,
        received: AtomicReference<ByteArray?>,
        holdHello: CountDownLatch? = null,
        host: DeviceIdentity = a,
    ): Responder {
        val counter = AtomicLong(0)
        val pinnedB = pinned(b, null)
        return responder { s, _ ->
            val input = s.getInputStream()
            val out = s.getOutputStream()
            val hello = SessionHello.parse(LanTransport.decodeFrame(readFrame(input)))
            SessionHello.verify(hello, pinnedB, groupKey.groupId)
            holdHello?.await()
            val mine = SessionHello.make(host, groupKey.groupId, hello.sessionId, counter.incrementAndGet(), SystemRandomSource())
            val channel = SecureChannel(host, pinnedB, groupKey.groupId, hello.sessionId, SecureChannel.Role.RESPONDER, mine, hello)
            out.write(LanTransport.encodeFrame(mine.toBytes())); out.flush()
            val parsed = LanMessages.parse(channel.open(readFrame(input)))
            if (parsed !is LanMessage.View) {
                // A responder from before witness messages (2026-10-29) answers anything else with bad-message.
                out.write(channel.seal(LanMessages.encode(LanMessage.Error("bad-message")))); out.flush()
                return@responder
            }
            val request = parsed
            check(request.seq == 0L && request.total == 1L) { "one chunk expected" }
            received.set(Base64Std.decodeStrict(request.view))
            val raw = ViewFile.encode(groupKey, host.deviceId, 3, aStates, clock, SystemRandomSource())
            val answer = LanMessage.View(
                groupKey.groupId, groupKey.epoch, Hex.lower(SystemRandomSource().bytes(16)), 0, 1, raw.size.toLong(), Base64Std.encode(raw),
            )
            out.write(channel.seal(LanMessages.encode(answer))); out.flush()
        }
    }

    /** The desktop's inviter side of the vector enrollment: checks B's request, answers with the recorded reply. */
    private fun inviterResponder(reply: ByteArray = SyncVectors.data("lan/enroll_reply_no_endpoint.bin"), frames: MutableList<ByteArray>? = null) =
        responder { s, _ ->
            val frame = readFrame(s.getInputStream())
            frames?.add(frame)
            val opened = Enrollment.openRequest(offer, a, LanTransport.decodeFrame(frame))
            check(opened.endpoint == null) { "a phone announces no endpoint" }
            s.getOutputStream().apply { write(LanTransport.encodeFrame(reply)); flush() }
        }

    private fun transport(timeoutMs: Int = 5_000, counters: CounterStore = MemoryCounters(), enrollReplyMs: Int = timeoutMs): SocketLanTransport =
        SocketLanTransport(HelloCounterSource(counters, clock), SystemRandomSource(), clock, timeoutMs = timeoutMs, enrollReplyMs = enrollReplyMs)

    private fun request(): ByteArray = Enrollment.buildRequest(offer, b, SyncVectors.DEVICE_NAME, null, SystemRandomSource(), clock)

    private fun <T> failure(block: () -> T): Throwable {
        try {
            block()
        } catch (e: Throwable) {
            return e
        }
        throw AssertionError("expected a failure")
    }

    private fun elapsedMs(started: Long) = (System.nanoTime() - started) / 1_000_000

    // MARK: enrollment

    @Test fun enrollment_round_trip_over_loopback() {
        val frames = Collections.synchronizedList(ArrayList<ByteArray>())
        val peer = inviterResponder(frames = frames)
        val connected = AtomicInteger()
        val request = request()
        val reply = transport().enroll(peer.endpoint, request) { connected.incrementAndGet() }
        assertEquals(1, connected.get())
        assertEquals(groupKey, Enrollment.openReply(offer, b, reply, SyncVectors.DEVICE_NAME, null))
        // Exactly one frame: the request, length-prefixed.
        assertEquals(1, frames.size)
        assertArrayEquals(LanTransport.encodeFrame(request), frames[0])
        assertEquals(1, peer.connections.get())
        assertTrue(peer.errors.toString(), peer.errors.isEmpty())
    }

    @Test fun enrollment_prechecks_send_nothing() {
        val peer = inviterResponder()
        val t = transport()
        // (A LanEndpoint is a private LAN address by construction.) Only an enrollment request within the bound.
        val bad = failure { t.enroll(peer.endpoint, byteArrayOf(1, 2, 3)) {} }
        assertEquals("enrollment request is malformed", (bad as LanSocketException).message)
        val big = failure { t.enroll(peer.endpoint, Enrollment.REQUEST_MAGIC + ByteArray(Enrollment.MAX_BYTES)) {} }
        assertEquals("enrollment request is malformed", (big as LanSocketException).message)
        Thread.sleep(100)
        assertEquals(0, peer.connections.get())
    }

    @Test fun refused_enrollment_names_the_failure() {
        val port = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
        val e = failure { transport().enroll(LanEndpoint("127.0.0.1", port), request()) {} } as LanSocketException
        assertEquals(e.message, LanFailure.REFUSED, e.kind)
    }

    @Test fun peer_closing_before_the_reply_is_closed_by_peer() {
        val peer = responder { s, _ -> readFrame(s.getInputStream()) } // reads the request, then hangs up
        val e = failure { transport().enroll(peer.endpoint, request()) {} } as LanSocketException
        assertEquals(e.message, LanFailure.CLOSED_BY_PEER, e.kind)
    }

    // MARK: frame bounds

    @Test fun oversized_frame_is_refused() {
        for (header in listOf(byteArrayOf(0x00, 0x10, 0x00, 0x01), byteArrayOf(0x7F, -1, -1, -1), byteArrayOf(0, 0, 0, 0))) {
            val peer = responder { s, _ ->
                readFrame(s.getInputStream())
                s.getOutputStream().apply { write(header); write(ByteArray(64)); flush() }
                awaitClientClose(s)
            }
            val e = failure { transport().enroll(peer.endpoint, request()) {} } as LanSocketException
            assertEquals("frame length is outside the bound", e.message)
        }
    }

    @Test fun enrollment_reply_over_its_bound_is_refused() {
        val peer = inviterResponder(reply = Enrollment.REPLY_MAGIC + ByteArray(Enrollment.MAX_BYTES))
        val e = failure { transport().enroll(peer.endpoint, request()) {} } as LanSocketException
        assertEquals("enrollment reply exceeds the bound", e.message)
    }

    // MARK: view exchange

    @Test fun view_exchange_over_loopback() {
        val now = clock.now
        val aStates = peerStates(mapOf(noteRecord(1, "From PC"), noteRecord(2, "From PC")), a.deviceId, now)
        val bStates = peerStates(mapOf(noteRecord(3, "From phone")), b.deviceId, now)
        val received = AtomicReference<ByteArray?>(null)
        val peer = viewResponder(aStates, received)
        val counters = MemoryCounters()
        val got = transport(counters = counters).exchangeViews(pinned(a, peer.endpoint), b, groupKey, bStates, ownCounter = 7)
        assertEquals(aStates, got)
        val sent = ViewFile.decode(received.get()!!, groupKey, b.deviceId)
        assertEquals(bStates, sent.second)
        assertEquals(7L, sent.first.counter)
        // One connection: hello, then the sealed request; the responder's counter was accepted.
        assertEquals(1, peer.connections.get())
        assertEquals(1L, counters.inbound[a.deviceId])
        assertTrue(peer.errors.toString(), peer.errors.isEmpty())
    }

    @Test fun view_exchange_only_dials_the_paired_peer_at_a_lan_address() {
        val t = transport()
        assertTrue(failure { t.exchangeViews(pinned(a, null), b, groupKey, emptyList(), 0) } !is LanSyncException)
    }

    // MARK: timeouts -> unreachable

    @Test fun silent_peer_times_out() {
        val peer = responder { s, _ -> awaitClientClose(s) } // accepts, never answers
        val started = System.nanoTime()
        val e = failure { transport(timeoutMs = 300, enrollReplyMs = 300).enroll(peer.endpoint, request()) {} } as LanSocketException
        assertEquals(e.message, LanFailure.TIMED_OUT, e.kind)
        assertEquals("read timed out", e.message)
        assertTrue(elapsedMs(started) < 3_000)
    }

    @Test fun silent_peer_is_reported_unreachable_by_the_sync_run() = runBlocking {
        val peer = responder { s, _ -> awaitClientClose(s) }
        val slots = SecretSlots(tmp.newFile("secrets.bin").also { it.delete() }, ByteArray(32) { 3 }, SystemRandomSource())
        val installId = slots.installId()
        val state = SyncGroupState(groupKey.groupId, groupKey.epoch, groupKey.key, b, installId, hasFolder = false)
        val store = LockedStore(StoreSnapshot(sync = state))
        val deps = SyncDependencies(
            slots = slots, folders = FolderOpening.UNAVAILABLE, lan = transport(timeoutMs = 300), random = SystemRandomSource(),
            clock = clock, licenseKeys = emptyMap(),
        )
        val report = SyncCoordinator.lanRun(store, deps, installId, pinned(a, peer.endpoint))
        assertEquals(listOf("unreachable"), report.issues.map { it.kind })
        assertEquals(0, store.commits)
    }

    // MARK: interrupts (the coordinator cancels LAN calls with runInterruptible)

    @Test fun interrupt_during_a_blocked_read_stops_promptly_and_closes_the_socket() {
        val accepted = CountDownLatch(1)
        val clientClosed = CountDownLatch(1)
        val peer = responder { s, _ ->
            readFrame(s.getInputStream())
            accepted.countDown()
            if (awaitClientClose(s)) clientClosed.countDown()
        }
        val outcome = AtomicReference<Throwable?>(null)
        val worker = Thread {
            try {
                transport(timeoutMs = 30_000).enroll(peer.endpoint, request()) {}
            } catch (e: Throwable) {
                outcome.set(e)
            }
        }
        worker.start()
        assertTrue(accepted.await(5, TimeUnit.SECONDS))
        val started = System.nanoTime()
        worker.interrupt()
        worker.join(2_000)
        assertFalse("still blocked after the interrupt", worker.isAlive)
        assertTrue(elapsedMs(started) < 2_000)
        assertEquals(LanFailure.CANCELLED, (outcome.get() as LanSocketException).kind)
        assertTrue("the socket was not closed", clientClosed.await(3, TimeUnit.SECONDS))
    }

    @Test fun interrupted_before_the_dial_connects_to_nothing() {
        val peer = inviterResponder()
        val outcome = AtomicReference<Throwable?>(null)
        val worker = Thread {
            Thread.currentThread().interrupt()
            try {
                transport().enroll(peer.endpoint, request()) {}
            } catch (e: Throwable) {
                outcome.set(e)
            }
        }
        worker.start(); worker.join(5_000)
        assertEquals(LanFailure.CANCELLED, (outcome.get() as LanSocketException).kind)
        Thread.sleep(100)
        assertEquals(0, peer.connections.get())
    }

    @Test fun interrupt_during_a_blocked_hello_is_not_retried() {
        val hold = CountDownLatch(1)
        val peer = viewResponder(emptyList(), AtomicReference(null), holdHello = hold)
        closeables.add(Closeable { hold.countDown() })
        val outcome = AtomicReference<Throwable?>(null)
        val worker = Thread {
            try {
                transport().exchangeViews(pinned(a, peer.endpoint), b, groupKey, emptyList(), 0)
            } catch (e: Throwable) {
                outcome.set(e)
            }
        }
        worker.start()
        val deadline = System.nanoTime() + 5_000_000_000
        while (peer.connections.get() == 0 && System.nanoTime() < deadline) Thread.sleep(5)
        Thread.sleep(100)
        worker.interrupt()
        worker.join(2_000)
        assertFalse(worker.isAlive)
        assertEquals(outcome.get().toString(), LanFailure.CANCELLED, (outcome.get() as? LanSocketException)?.kind)
        Thread.sleep(200)
        assertEquals("a cancelled hello is not dialled again", 1, peer.connections.get())
    }

    // MARK: through the coordinator (offer address sent to the loopback responder)

    private fun CoroutineScope.coordinator(store: LockedStore, slots: SecretSlots, lan: LanTransporting): SyncCoordinator {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        scopes.add(scope)
        val deps = SyncDependencies(
            slots = slots, folders = FolderOpening.UNAVAILABLE, lan = lan, random = SystemRandomSource(), clock = clock,
            licenseKeys = emptyMap(), sleep = {}, newIdentity = { b }, deviceName = SyncVectors.DEVICE_NAME,
        )
        return SyncCoordinator(store, deps, scope, EnglishTxt())
    }

    /** Every dial goes to [port] on loopback, whatever address the offer or peer names. */
    private fun loopbackTransport(port: () -> Int, timeoutMs: Int = 30_000): SocketLanTransport {
        val dialer = ChannelLanDialer(
            timeoutMs, enrollReplyMs = timeoutMs, bind = { _, _ -> }, route = { InetSocketAddress(InetAddress.getByName("127.0.0.1"), port()) },
        )
        return SocketLanTransport(HelloCounterSource(MemoryCounters(), clock), SystemRandomSource(), clock, dialer = dialer)
    }

    @Test fun qr_join_and_first_sync_over_loopback_sockets() = runBlocking {
        withTimeout(30_000) {
            val aStates = peerStates(mapOf(noteRecord(1, "From PC")), a.deviceId, clock.now)
            val enroller = inviterResponder()
            val viewer = viewResponder(aStates, AtomicReference(null))
            // First dial: the enrollment; every later one: the paired PC's LAN sync.
            val dials = AtomicInteger()
            val lan = loopbackTransport({ if (dials.getAndIncrement() == 0) enroller.port else viewer.port })
            val slots = SecretSlots(tmp.newFile("secrets.bin").also { it.delete() }, ByteArray(32) { 3 }, SystemRandomSource())
            val store = LockedStore()
            val c = coordinator(store, slots, lan)
            assertTrue(c.actionError.value ?: "", c.joinByQr(SyncVectors.qrText()))
            assertEquals("This phone joined the sync group. The first sync is running.", c.actionInfo.value)
            while (c.completedRuns.value == 0) delay(5)
            assertNotNull(slots.pairedPeer())
            assertEquals(a.deviceId, store.snapshot.sync?.let { slots.pairedPeer()?.deviceId })
            assertTrue(store.snapshot.records.containsKey(noteRecord(1).first))
            assertTrue(c.issues.value.toString(), c.issues.value.isEmpty())
            c.shutdown()
        }
    }

    @Test fun lock_during_a_blocked_enrollment_read_stops_promptly_without_committing() = runBlocking {
        withTimeout(30_000) {
            val accepted = CountDownLatch(1)
            val peer = responder { s, _ ->
                readFrame(s.getInputStream())
                accepted.countDown()
                awaitClientClose(s)
            }
            val slots = SecretSlots(tmp.newFile("secrets.bin").also { it.delete() }, ByteArray(32) { 3 }, SystemRandomSource())
            val store = LockedStore()
            val c = coordinator(store, slots, loopbackTransport({ peer.port }))
            val join = async(Dispatchers.Default) { c.joinByQr(SyncVectors.qrText()) }
            while (accepted.count > 0) delay(5)
            while (c.connecting.value != null) delay(5) // connected: Cancel is no longer offered
            val started = System.nanoTime()
            c.shutdown() // what the lock does
            val joined = try {
                withTimeout(2_000) { join.await() }
            } catch (e: kotlinx.coroutines.CancellationException) {
                if (e is kotlinx.coroutines.TimeoutCancellationException) throw AssertionError("join still blocked after lock", e)
                false
            }
            assertFalse(joined)
            assertTrue(elapsedMs(started) < 2_000)
            assertNull(store.snapshot.sync)
            assertEquals(0, store.commits)
            assertNull(slots.read(Slot.PAIRED_PEER))
        }
    }

    @Test fun lock_during_a_blocked_sync_read_stops_promptly_without_committing() = runBlocking {
        withTimeout(30_000) {
            val hold = CountDownLatch(1)
            closeables.add(Closeable { hold.countDown() })
            val enroller = inviterResponder()
            val viewer = viewResponder(peerStates(mapOf(noteRecord(1)), a.deviceId, clock.now), AtomicReference(null), holdHello = hold)
            val dials = AtomicInteger()
            val lan = loopbackTransport({ if (dials.getAndIncrement() == 0) enroller.port else viewer.port })
            val slots = SecretSlots(tmp.newFile("secrets.bin").also { it.delete() }, ByteArray(32) { 3 }, SystemRandomSource())
            val store = LockedStore()
            val c = coordinator(store, slots, lan)
            // joinByQr returns once its first sync has run; that sync waits for the PC's hello.
            val join = async(Dispatchers.Default) { c.joinByQr(SyncVectors.qrText()) }
            while (viewer.connections.get() == 0) delay(5)
            delay(100)
            assertNotNull(store.snapshot.sync) // the join itself committed
            val commitsAfterJoin = store.commits
            val started = System.nanoTime()
            c.shutdown()
            try {
                withTimeout(2_000) { join.await() }
            } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
                throw AssertionError("sync still blocked after lock", e)
            } catch (_: kotlinx.coroutines.CancellationException) {
            }
            assertTrue(elapsedMs(started) < 2_000)
            delay(200)
            assertEquals(commitsAfterJoin, store.commits)
            assertFalse(store.snapshot.records.containsKey(noteRecord(1).first))
            assertEquals("a cancelled sync dials nothing more", 1, viewer.connections.get())
        }
    }

    // MARK: Swift PairedConnectorTests (scripted dialer)

    private val endpoint = LanEndpoint("192.168.1.20", 47821)
    private val scriptedPeer = PinnedPeer("a1111111-0000-4000-8000-00000000000a", "g", ByteArray(32) { 1 }, ByteArray(32) { 2 }, endpoint)

    private fun hello(): ByteArray = LanTransport.encodeFrame("hello".toByteArray())

    private class ScriptedDialer(steps: List<Step>) : LanDialer {
        enum class Step { REFUSE, DROP_BEFORE_REPLY, ANSWER }
        private val steps = ArrayDeque(steps)
        val dials = ArrayList<LanEndpoint>()
        val sentFrames = ArrayList<ByteArray>()
        val waited = ArrayList<Boolean>()

        override fun dial(endpoint: LanEndpoint, forEnrollment: Boolean): LanSocket {
            dials.add(endpoint)
            waited.add(forEnrollment)
            return when (steps.removeFirstOrNull()) {
                Step.REFUSE, null -> throw LanSocketException("connect failed: ECONNREFUSED", LanFailure.REFUSED)
                Step.DROP_BEFORE_REPLY -> object : LanSocket {
                    override fun send(bytes: ByteArray) { sentFrames.add(bytes) }
                    override fun receiveFrame(): ByteArray = throw LanSocketException("peer closed the connection", LanFailure.CLOSED_BY_PEER)
                    override fun close() {}
                }
                Step.ANSWER -> object : LanSocket {
                    override fun send(bytes: ByteArray) { sentFrames.add(bytes) }
                    override fun receiveFrame(): ByteArray = LanTransport.encodeFrame("reply".toByteArray())
                    override fun close() {}
                }
            }
        }
    }

    @Test fun refused_or_unanswered_hello_is_peer_not_answering() {
        for (step in listOf(ScriptedDialer.Step.REFUSE, ScriptedDialer.Step.DROP_BEFORE_REPLY)) {
            val dialer = ScriptedDialer(listOf(step))
            val conn: LanConnection = PairedLanConnector(scriptedPeer, dialer).connect(scriptedPeer)
            assertTrue(failure { conn.exchange(hello()) } is LanPeerNotAnswering)
            assertEquals(listOf(endpoint), dialer.dials)
        }
    }

    @Test fun the_sealed_request_is_not_peer_not_answering() {
        val dialer = ScriptedDialer(listOf(ScriptedDialer.Step.ANSWER))
        val conn = PairedLanConnector(scriptedPeer, dialer).connect(scriptedPeer)
        assertArrayEquals("reply".toByteArray(), LanTransport.decodeFrame(conn.exchange(hello())))
        conn.exchange("sealed".toByteArray())
        assertTrue(failure { conn.exchange("again".toByteArray()) } is LanSocketException)
        assertEquals(1, dialer.dials.size)
    }

    @Test fun only_the_paired_peer_at_a_lan_address() {
        val dialer = ScriptedDialer(emptyList())
        val other = PinnedPeer("other", "g", scriptedPeer.signingPublic, scriptedPeer.exchangePublic, endpoint)
        assertTrue(failure { PairedLanConnector(scriptedPeer, dialer).connect(other) } is LanSocketException)
        val noAddress = scriptedPeer.copy(endpoint = null)
        assertTrue(failure { PairedLanConnector(noAddress, dialer).connect(noAddress) } is LanSocketException)
        assertEquals(0, dialer.dials.size)
    }

    @Test fun enroller_gets_its_own_deadline_and_sends_exactly_one_frame() {
        val dialer = ScriptedDialer(listOf(ScriptedDialer.Step.ANSWER))
        val connected = AtomicInteger()
        val request = Enrollment.REQUEST_MAGIC + byteArrayOf(1, 2)
        val reply = SocketEnroller(dialer).enroll(endpoint, request) { connected.incrementAndGet() }
        assertEquals(1, connected.get())
        assertArrayEquals("reply".toByteArray(), reply)
        assertEquals(1, dialer.sentFrames.size)
        assertArrayEquals(LanTransport.encodeFrame(request), dialer.sentFrames[0])
        assertEquals(listOf(true), dialer.waited) // Swift: waitForNetwork true
    }

    // MARK: Ruling 17: one deadline per connection

    @Test fun a_peer_stalling_mid_read_fails_within_one_connection_deadline() {
        // The peer answers the first frame at once, then trickles the second one a byte at a time: per-step timeouts
        // would never fire; the connection's one deadline does.
        val peer = responder { s, _ ->
            val out = s.getOutputStream()
            out.write(LanTransport.encodeFrame("first".toByteArray())); out.flush()
            out.write(byteArrayOf(0, 0, 0, 100)); out.flush()
            repeat(100) {
                Thread.sleep(50)
                out.write(1); out.flush()
            }
        }
        val started = System.nanoTime()
        val socket = ChannelLanDialer(timeoutMs = 600).dial(peer.endpoint)
        assertArrayEquals("first".toByteArray(), LanTransport.decodeFrame(socket.receiveFrame()))
        val e = failure { socket.receiveFrame() } as LanSocketException
        assertEquals(LanFailure.TIMED_OUT, e.kind)
        assertEquals("read timed out", e.message)
        val took = elapsedMs(started)
        assertTrue("took $took ms", took in 550..1_500)
    }

    @Test fun the_enrollment_dial_waits_for_accept_past_the_sync_deadline() {
        // Ruling 17 amended: once connected, an enrollment dial (forEnrollment) gives the reply ENROLL_REPLY_SECONDS (the
        // inviting device answers only after its user chose Accept); a sync dial of the same dialer keeps its one
        // deadline. Short injected values: 300 ms per connection, 1.5 s for the enrollment reply.
        val dialer = ChannelLanDialer(timeoutMs = 300, enrollReplyMs = 1_500)
        val reply = SyncVectors.data("lan/enroll_reply_no_endpoint.bin")
        val accepting = responder { s, _ ->
            readFrame(s.getInputStream())
            Thread.sleep(900) // Accept chosen well after the 300 ms connection deadline
            s.getOutputStream().apply { write(LanTransport.encodeFrame(reply)); flush() }
        }
        val got = SocketEnroller(dialer).enroll(accepting.endpoint, request()) {}
        assertEquals(groupKey, Enrollment.openReply(offer, b, got, SyncVectors.DEVICE_NAME, null))
        // Nobody answers: the enrollment fails at its reply deadline, not before.
        val silent = responder { s, _ -> awaitClientClose(s) }
        val started = System.nanoTime()
        val e = failure { SocketEnroller(dialer).enroll(silent.endpoint, request()) {} } as LanSocketException
        assertEquals(LanFailure.TIMED_OUT, e.kind)
        val took = elapsedMs(started)
        assertTrue("took $took ms", took in 1_400..4_000)
        // A sync connection through the same dialer: still its one 300 ms deadline.
        val syncStarted = System.nanoTime()
        val socket = dialer.dial(silent.endpoint)
        assertEquals(LanFailure.TIMED_OUT, (failure { socket.receiveFrame() } as LanSocketException).kind)
        val syncTook = elapsedMs(syncStarted)
        assertTrue("took $syncTook ms", syncTook < 1_200)
    }

    @Test fun the_reply_deadline_counts_from_the_connect() {
        // An enrollment socket's deadline is at least now + the reply time after the connect (Swift max(deadline, now +
        // ioTimeout)), even when the connect took most of the connection deadline.
        val peer = responder { s, _ -> awaitClientClose(s) }
        val socket = ChannelLanDialer(timeoutMs = 400, enrollReplyMs = 400).dial(peer.endpoint, forEnrollment = true) as ChannelLanSocket
        Thread.sleep(300) // most of the reply time gone
        socket.extendDeadline(400)
        val started = System.nanoTime()
        val e = failure { socket.receiveFrame() } as LanSocketException
        assertEquals(LanFailure.TIMED_OUT, e.kind)
        assertTrue(elapsedMs(started) >= 350)
    }

    @Test fun production_deadlines_are_five_seconds_and_the_enrollment_reply_time() {
        assertEquals(5_000, ChannelLanDialer().timeoutMs)
        assertEquals(Enrollment.ENROLL_REPLY_SECONDS * 1_000, ChannelLanDialer().enrollReplyMs)
        assertEquals(75_000, ChannelLanDialer().enrollReplyMs)
        val t = SocketLanTransport(HelloCounterSource(MemoryCounters(), clock), SystemRandomSource(), clock)
        assertEquals(5_000, t.timeoutMs)
        assertEquals(75_000, t.enrollReplyMs)
    }

    // MARK: a blocked connect

    /** A non-blocking channel that never connects (no connect started), registered like a dial's: OP_CONNECT never fires. */
    private fun stalledConnect(deadlineMs: Long): ChannelLanSocket {
        val channel = java.nio.channels.SocketChannel.open().apply { configureBlocking(false) }
        val selector = java.nio.channels.Selector.open()
        val key = channel.register(selector, 0)
        return ChannelLanSocket(channel, selector, key, System.nanoTime() + deadlineMs * 1_000_000L).also { s ->
            closeables.add(Closeable { s.close() })
        }
    }

    @Test fun cancel_during_a_blocked_connect_returns_promptly() {
        val socket = stalledConnect(30_000)
        val outcome = AtomicReference<Throwable?>(null)
        val waiting = CountDownLatch(1)
        val worker = Thread {
            waiting.countDown()
            try {
                socket.await(java.nio.channels.SelectionKey.OP_CONNECT, "connect timed out")
            } catch (e: Throwable) {
                outcome.set(e)
            }
        }
        worker.start()
        assertTrue(waiting.await(5, TimeUnit.SECONDS))
        Thread.sleep(200) // inside select
        val started = System.nanoTime()
        worker.interrupt()
        worker.join(2_000)
        assertFalse("still blocked after the interrupt", worker.isAlive)
        assertTrue(elapsedMs(started) < 1_000)
        assertEquals(LanFailure.CANCELLED, (outcome.get() as LanSocketException).kind)
    }

    @Test fun a_blocked_connect_times_out_at_the_deadline() {
        val socket = stalledConnect(300)
        val started = System.nanoTime()
        val e = failure { socket.await(java.nio.channels.SelectionKey.OP_CONNECT, "connect timed out") } as LanSocketException
        assertEquals(LanFailure.TIMED_OUT, e.kind)
        assertEquals("connect timed out", e.message)
        assertTrue(elapsedMs(started) in 250..2_000)
    }

    // MARK: Ruling 18: never over cellular

    @Test fun no_wifi_network_fails_the_dial_as_unreachable_before_connecting() {
        val binder = WifiNetworkBinder { null }
        // Loopback never leaves the phone: allowed without a Wi-Fi network.
        java.nio.channels.SocketChannel.open().use { binder.bind(it, InetAddress.getByName("127.0.0.1")) }
        // A LAN address: refused before any packet is sent (bind runs before connect).
        val e = failure {
            SocketEnroller(ChannelLanDialer(5_000, bind = binder::bind)).enroll(LanEndpoint("192.168.1.20", 47821), request()) {}
        } as LanSocketException
        assertEquals(LanFailure.UNREACHABLE, e.kind)
        assertEquals("no Wi-Fi network", e.message)
        // The Sync screen explains it with the iPhone's wording.
        val text = SyncWording(EnglishTxt()).enrollFailureText(EnrollConnectException(e.kind, LanEndpoint("192.168.1.20", 47821)))
        assertEquals(
            "192.168.1.20:47821 cannot be reached from this phone. Check that the PC is on this Wi-Fi and that the code shows the PC's Wi-Fi address.",
            text,
        )
    }

    // MARK: secrets never in toString

    @Test fun to_string_shows_no_secrets() {
        val t = transport()
        assertEquals("SocketLanTransport(timeoutMs=5000)", t.toString())
        assertEquals("ChannelLanDialer(timeoutMs=5000)", ChannelLanDialer().toString())
        val peer = inviterResponder()
        val conn = PairedLanConnector(pinned(a, peer.endpoint), ChannelLanDialer())
        val text = conn.toString() + conn.connect(pinned(a, peer.endpoint)).toString()
        for (secret in listOf(Base64Std.encode(groupKey.key), Hex.lower(groupKey.key), Base64Std.encode(a.signingPublicKey))) {
            assertFalse(text, text.contains(secret))
        }
    }

    @Test fun socket_errors_never_carry_frame_bytes() {
        val peer = responder { s, _ ->
            readFrame(s.getInputStream())
            s.getOutputStream().apply { write(byteArrayOf(0x00, 0x10, 0x00, 0x01)); flush() }
        }
        val request = request()
        val e = failure { transport().enroll(peer.endpoint, request) {} }
        val text = e.toString() + (e.cause?.toString() ?: "")
        assertFalse(text.contains(Base64Std.encode(request)))
        assertFalse(text.contains(Hex.lower(request)))
    }

    // MARK: discovery (plan 2026-10-29-sync-ip-change): the pinned address fails, the host is found by its announcement

    /** Dials to the fake LAN hosts of [routes] go to loopback ports; [dialled] records every dial. */
    private inner class Discovering(val routes: Map<String, Int>) {
        val dialled: MutableList<LanEndpoint> = Collections.synchronizedList(ArrayList())
        val announcements = ArrayList<Discovery.Announcement>()
        val browses = AtomicInteger()

        fun announce(host: String, port: Int = 47821, tag: String = todayTag()) {
            announcements.add(Discovery.Announcement(host, port, mapOf("v" to "1", "t" to tag)))
        }

        fun transport(): SocketLanTransport {
            val dialer = ChannelLanDialer(2_000, 2_000, { _, _ -> }) { e ->
                dialled.add(e)
                InetSocketAddress(InetAddress.getByName("127.0.0.1"), routes[e.host] ?: error("unrouted ${e.host}"))
            }
            val browser = ServiceBrowser { type, _ ->
                assertEquals("_lgksync._tcp", type)
                browses.incrementAndGet()
                announcements.toList()
            }
            return SocketLanTransport(HelloCounterSource(MemoryCounters(), clock), SystemRandomSource(), clock, dialer = dialer, browser = browser)
        }
    }

    private fun todayTag(): String = Discovery.tag(groupKey, a.deviceId, Discovery.utcDay(clock.now))

    private fun deadPort(): Int = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }

    private val oldAddress = LanEndpoint("192.168.50.1", 47821)

    private fun impostor(): DeviceIdentity = DeviceIdentity(a.deviceId, SystemRandomSource().bytes(32), SystemRandomSource().bytes(32))

    private fun lanRunWith(d: Discovering): Triple<RunReport, SecretSlots, LockedStore> = runBlocking {
        val slots = SecretSlots(tmp.newFile("secrets.bin").also { it.delete() }, ByteArray(32) { 3 }, SystemRandomSource())
        val installId = slots.installId()
        val peer = pinned(a, oldAddress)
        slots.setPairedPeer(peer)
        val state = SyncGroupState(groupKey.groupId, groupKey.epoch, groupKey.key, b, installId, hasFolder = false)
        val store = LockedStore(StoreSnapshot(sync = state))
        val deps = SyncDependencies(
            slots = slots, folders = FolderOpening.UNAVAILABLE, lan = d.transport(), random = SystemRandomSource(),
            clock = clock, licenseKeys = emptyMap(),
        )
        Triple(SyncCoordinator.lanRun(store, deps, installId, peer), slots, store)
    }

    @Test fun pinned_fails_and_the_announced_host_syncs_and_its_address_is_stored() {
        val aStates = peerStates(mapOf(noteRecord(1, "From PC")), a.deviceId, clock.now)
        val host = viewResponder(aStates, AtomicReference(null))
        val d = Discovering(mapOf("192.168.50.1" to deadPort(), "192.168.50.2" to host.port))
        d.announce("192.168.50.2")
        val (report, slots, _) = lanRunWith(d)
        assertEquals(emptyList<String>(), report.issues.map { it.kind })
        assertEquals(1, d.browses.get())
        // The view exchange at the found host, then (format 1) the one witness message to the same host.
        val found = LanEndpoint("192.168.50.2", 47821)
        assertEquals(listOf(oldAddress, found, found), d.dialled.toList())
        assertEquals(found, slots.pairedPeer()?.endpoint)
        assertTrue(host.errors.toString(), host.errors.isEmpty())
    }

    @Test fun the_pinned_address_that_answers_is_used_without_a_browse() {
        val host = viewResponder(emptyList(), AtomicReference(null))
        val d = Discovering(mapOf("192.168.50.1" to host.port))
        d.announce("192.168.50.2")
        val moved = AtomicReference<LanEndpoint?>(null)
        d.transport().exchangeViewsFindingHost(pinned(a, oldAddress), b, groupKey, emptyList(), 0) { moved.set(it) }
        assertEquals(0, d.browses.get())
        assertNull(moved.get())
    }

    @Test fun yesterdays_tag_is_accepted() {
        val host = viewResponder(emptyList(), AtomicReference(null))
        val d = Discovering(mapOf("192.168.50.1" to deadPort(), "192.168.50.2" to host.port))
        d.announce("192.168.50.2", tag = Discovery.tag(groupKey, a.deviceId, Discovery.utcDay(clock.now - 86_400)))
        val moved = AtomicReference<LanEndpoint?>(null)
        d.transport().exchangeViewsFindingHost(pinned(a, oldAddress), b, groupKey, emptyList(), 0) { moved.set(it) }
        assertEquals(LanEndpoint("192.168.50.2", 47821), moved.get())
    }

    @Test fun an_announcement_with_another_tag_is_ignored() {
        val host = viewResponder(emptyList(), AtomicReference(null))
        val d = Discovering(mapOf("192.168.50.1" to deadPort(), "192.168.50.2" to host.port))
        d.announce("192.168.50.2", tag = "aaaaaaaaaaaaaaaa")
        d.announce("192.168.50.2", 47822, Discovery.tag(groupKey, b.deviceId, Discovery.utcDay(clock.now))) // another device's tag
        val moved = AtomicReference<LanEndpoint?>(null)
        val e = failure { d.transport().exchangeViewsFindingHost(pinned(a, oldAddress), b, groupKey, emptyList(), 0) { moved.set(it) } }
        assertTrue(e.toString(), e is LanPeerNotAnswering)
        assertEquals(listOf(oldAddress), d.dialled.toList())
        assertEquals(0, host.connections.get())
        assertNull(moved.get())
    }

    @Test fun a_non_lan_address_is_never_dialled() {
        val d = Discovering(mapOf("192.168.50.1" to deadPort()))
        d.announce("8.8.8.8")
        d.announce("100.64.0.1")
        d.announce("fe80::1%wlan0")
        failure { d.transport().exchangeViewsFindingHost(pinned(a, oldAddress), b, groupKey, emptyList(), 0) {} }
        assertEquals(listOf(oldAddress), d.dialled.toList())
    }

    @Test fun at_most_four_announced_addresses_are_dialled() {
        val dead = deadPort()
        val d = Discovering((1..8).associate { "192.168.50.$it" to dead })
        (2..8).forEach { d.announce("192.168.50.$it") }
        val e = failure { d.transport().exchangeViewsFindingHost(pinned(a, oldAddress), b, groupKey, emptyList(), 0) {} }
        assertTrue(e.toString(), e is LanPeerNotAnswering)
        // The pinned address once, then four candidates (the first request of a sync is not retried).
        assertEquals(listOf(oldAddress) + (2..5).map { LanEndpoint("192.168.50.$it", 47821) }, d.dialled.toList())
    }

    @Test fun a_host_with_other_keys_is_refused_and_the_next_candidate_is_tried() {
        val fake = viewResponder(emptyList(), AtomicReference(null), host = impostor())
        val host = viewResponder(emptyList(), AtomicReference(null))
        val d = Discovering(mapOf("192.168.50.1" to deadPort(), "192.168.50.3" to fake.port, "192.168.50.4" to host.port))
        d.announce("192.168.50.3")
        d.announce("192.168.50.4")
        val moved = AtomicReference<LanEndpoint?>(null)
        d.transport().exchangeViewsFindingHost(pinned(a, oldAddress), b, groupKey, emptyList(), 0) { moved.set(it) }
        assertEquals(1, fake.connections.get())
        assertEquals(LanEndpoint("192.168.50.4", 47821), moved.get())
    }

    @Test fun only_a_host_with_other_keys_stores_nothing() {
        val fake = viewResponder(emptyList(), AtomicReference(null), host = impostor())
        val d = Discovering(mapOf("192.168.50.1" to deadPort(), "192.168.50.3" to fake.port))
        d.announce("192.168.50.3")
        val (report, slots, store) = lanRunWith(d)
        assertEquals(listOf("unreachable"), report.issues.map { it.kind })
        assertEquals(1, fake.connections.get())
        assertEquals(oldAddress, slots.pairedPeer()?.endpoint)
        assertEquals(0, store.commits)
    }
}
