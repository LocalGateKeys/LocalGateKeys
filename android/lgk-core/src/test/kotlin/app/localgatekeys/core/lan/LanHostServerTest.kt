package app.localgatekeys.core.lan

import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.support.MemoryCounterStore
import app.localgatekeys.core.support.MemoryStore
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncRunner
import java.io.DataInputStream
import java.io.IOException
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The phone host: connection limits, the per-connection protocol, the enrollment handler, and an end-to-end run of the
 * Android joiner (Enrollment + LanClient) against [LanHostServer] over a loopback socket, pairing then syncing.
 */
class LanHostServerTest {
    private val install = "android-install-0001"
    private val servers = ArrayList<LanHostServer>()

    @AfterTest
    fun stopServers() {
        servers.forEach { it.stop() }
    }

    // ---- limits ----

    @Test
    fun inbound_limits_per_address_and_reserved_slot() {
        val l = InboundLimits()
        assertTrue(l.reserve(1, "192.168.1.5", 0.0))
        assertFalse(l.reserve(2, "192.168.1.5", 0.0)) // one unauthenticated connection per address
        assertTrue(l.reserve(2, "192.168.1.6", 0.0))
        assertTrue(l.reserve(3, "192.168.1.7", 0.0))
        assertFalse(l.reserve(4, "192.168.2.8", 0.0)) // the last slot is kept for a verified address
        assertEquals(3, l.preAuthCount)
        l.release(3)
        assertTrue(l.reserve(4, "192.168.1.9", 0.0))
        l.release(4)
        l.authenticated(1, 10.0)
        l.authenticated(2, 10.0)
        assertEquals(0, l.preAuthCount)
        // A verified address may open a second connection and use the reserved slot.
        assertTrue(l.reserve(5, "192.168.1.5", 20.0))
        assertTrue(l.reserve(6, "192.168.1.6", 20.0))
        assertEquals(4, l.count)
        assertFalse(l.reserve(7, "10.0.0.1", 20.0)) // 4 in total
        l.removeAll()
        assertEquals(0, l.count)
        // The verified mark lapses after 15 minutes.
        val later = 20.0 + LanListenLimits.VERIFIED_SECONDS + 1
        assertTrue(l.reserve(8, "192.168.1.5", later))
        assertFalse(l.reserve(9, "192.168.1.5", later))
    }

    @Test
    fun prefixes_group_ipv4_ipv6_and_mapped_addresses() {
        assertEquals("192.168.1.0/24", InboundLimits.prefix("192.168.1.77"))
        assertEquals("192.168.1.0/24", InboundLimits.prefix("::ffff:192.168.1.77"))
        assertEquals("fe800000000000aa::/64", InboundLimits.prefix("fe80::aa:1:2:3:4%wlan0"))
        assertEquals("not-an-address", InboundLimits.prefix("not-an-address"))
    }

    // ---- one connection ----

    private class FakeSocket(vararg frames: ByteArray) : HostSocket {
        val inbound = ArrayList(frames.toList())
        val sent = ArrayList<ByteArray>()
        var closed = false

        override fun receiveFrame(limit: Int, deadlineNanos: Long): ByteArray {
            if (inbound.isEmpty()) throw IOException("closed")
            val f = inbound.removeAt(0)
            if (f.size - 4 > limit) throw IOException("too large")
            return f
        }

        override fun send(bytes: ByteArray, deadlineNanos: Long) {
            if (closed) throw IOException("closed")
            sent.add(bytes)
        }

        override fun close() {
            closed = true
        }
    }

    private class Host(val store: MemoryStore, val service: LanHostService) {
        val state get() = store.load().sync!!
    }

    private fun host(seed: Boolean = false): Host {
        var state = LanPeers.createWifiGroup(install, SystemRandomSource())
        val store = MemoryStore(StoreSnapshot(sync = state))
        if (seed) {
            // The host already has C's items (merged earlier).
            val c = SyncFixtures.views().first { it.deviceId == SyncFixtures.devices[2].id }
            val snap = store.load()
            val run = SyncRunner.run(snap, listOf(PeerView(c.deviceId, c.states)), state.deviceId, SyncFixtures.T0 + 100)
            store.commit(StoreChange(snap.revision, run.records!!, run.meta!!, snap.sync))
        }
        val service = LanHostService(
            store, install, HelloCounterSource(MemoryCounterStore(), SystemClock()), SystemRandomSource(), SystemClock(),
        )
        return Host(store, service)
    }

    private class Decider(private val accept: Boolean) : PairingDecider {
        val asked = ArrayList<Enrollment.Request>()
        var paired: Enrollment.Request? = null
        var failed: String? = null

        override fun ask(request: Enrollment.Request, session: OfferSession): Boolean {
            asked.add(request)
            return accept
        }

        override fun didPair(request: Enrollment.Request, session: OfferSession) {
            paired = request
        }

        override fun failed(reason: String, session: OfferSession) {
            failed = reason
        }
    }

    private fun armed(h: Host, accept: Boolean, endpoint: LanEndpoint = LanEndpoint("192.168.1.20", 47821)): Triple<PairingOffer, PairingEnrollment, Decider> {
        val st = h.state
        val (offer, _) = PairingOffer.create(st.groupId, st.identity, endpoint, SystemClock(), SystemRandomSource())
        val decider = Decider(accept)
        val handler = PairingEnrollment(OfferSession(offer, st.identity), h.store, SystemRandomSource(), SystemClock(), decider)
        return Triple(offer, handler, decider)
    }

    private val joiner = SyncFixtures.identity("A")

    private fun joinRequest(offer: PairingOffer): ByteArray =
        Enrollment.buildRequest(PairingOffer.parseQr(offer.qrPayload()), joiner, "Pixel", null, SystemRandomSource(), SystemClock())

    @Test
    fun an_enrollment_request_without_an_armed_offer_is_dropped_silently() {
        val h = host()
        val (offer, _, _) = armed(h, true)
        val s = FakeSocket(LanTransport.encodeFrame(joinRequest(offer)))
        assertEquals(LanHostSession.Outcome.CLOSED, LanHostSession(h.service, null).handle(s))
        assertTrue(s.sent.isEmpty())
        assertTrue(s.closed)
        // Junk and an unknown device's hello get no answer either.
        val junk = FakeSocket(LanTransport.encodeFrame("{\"x\":1}".toByteArray()))
        assertEquals(LanHostSession.Outcome.CLOSED, LanHostSession(h.service, null).handle(junk))
        assertTrue(junk.sent.isEmpty())
        val stranger = LanClient(joiner, h.state.groupKey(), HelloCounterSource(MemoryCounterStore(), SystemClock()), SystemRandomSource(), SystemClock())
        val hostPeer = PinnedPeer(h.state.deviceId, h.state.groupId, h.state.identity.signingPublicKey, h.state.identity.exchangePublicKey, null)
        var first: ByteArray? = null
        try {
            stranger.request("{}".toByteArray(), hostPeer, object : LanConnection {
                override fun exchange(frame: ByteArray): ByteArray {
                    first = frame
                    throw LanPeerNotAnswering("test")
                }
            })
        } catch (_: Exception) {
        }
        val hello = FakeSocket(first!!)
        assertEquals(LanHostSession.Outcome.CLOSED, LanHostSession(h.service, null).handle(hello))
        assertTrue(hello.sent.isEmpty())
    }

    @Test
    fun accepted_enrollment_sends_the_reveal_then_the_reply_and_pins_without_an_endpoint() {
        val h = host()
        val (offer, handler, decider) = armed(h, true)
        val scanned = PairingOffer.parseQr(offer.qrPayload())
        val request = joinRequest(offer)
        val s = FakeSocket(LanTransport.encodeFrame(request))
        assertEquals(LanHostSession.Outcome.ENROLLMENT_ANSWERED, LanHostSession(h.service, handler).handle(s))
        assertEquals(2, s.sent.size)
        val reveal = Enrollment.openReveal(scanned, LanTransport.decodeFrame(s.sent[0]))
        val gk = Enrollment.openReply(scanned, joiner, LanTransport.decodeFrame(s.sent[1]), "Pixel", null, reveal)
        assertEquals(h.state.groupKey(), gk)
        assertEquals(1, decider.asked.size)
        assertEquals(Enrollment.verificationCode(scanned, joiner, null, "Pixel", reveal), decider.asked[0].code)
        assertEquals(joiner.deviceId, decider.paired?.deviceId)
        val peer = LanPeers.entry(h.state, joiner.deviceId)!!
        assertNull(peer.endpoint)
        assertTrue(peer.sealed)
        assertEquals("Pixel", peer.name)
        // One use: the same request again is refused as used.
        val again = FakeSocket(LanTransport.encodeFrame(request))
        assertEquals(LanHostSession.Outcome.ENROLLMENT_ANSWERED, LanHostSession(h.service, handler).handle(again))
        assertContentEquals(Enrollment.refusal("used-or-expired"), LanTransport.decodeFrame(again.sent.single()))
    }

    @Test
    fun declined_enrollment_pins_nothing() {
        val h = host()
        val (offer, handler, decider) = armed(h, false)
        val s = FakeSocket(LanTransport.encodeFrame(joinRequest(offer)))
        assertEquals(LanHostSession.Outcome.ENROLLMENT_ANSWERED, LanHostSession(h.service, handler).handle(s))
        assertContentEquals(Enrollment.refusal("declined"), LanTransport.decodeFrame(s.sent.last()))
        assertTrue(h.state.lanPeers.isEmpty())
        assertNull(decider.paired)
        assertEquals(0, h.store.commits)
    }

    @Test
    fun a_device_gone_before_the_reveal_gets_no_prompt() {
        val h = host()
        val (offer, handler, decider) = armed(h, true)
        val reply = handler.enroll(joinRequest(offer)) { throw IOException("gone") }
        assertNull(reply)
        assertTrue(decider.asked.isEmpty())
        assertEquals("refused", decider.failed)
        assertTrue(h.state.lanPeers.isEmpty())
    }

    // ---- end to end over a loopback socket ----

    private fun readFrame(input: DataInputStream): ByteArray {
        val head = ByteArray(4)
        input.readFully(head)
        val n = ((head[0].toInt() and 0xFF) shl 24) or ((head[1].toInt() and 0xFF) shl 16) or
            ((head[2].toInt() and 0xFF) shl 8) or (head[3].toInt() and 0xFF)
        val body = ByteArray(n)
        input.readFully(body)
        return head + body
    }

    /** One request per connection to the loopback listener (the app's SocketLanConnection, over java.net). */
    private inner class LoopbackConnector(private val port: Int) : LanConnector {
        override fun connect(peer: PinnedPeer): LanConnection = object : LanConnection {
            private var socket: Socket? = null
            private var calls = 0

            override fun exchange(frame: ByteArray): ByteArray {
                calls += 1
                if (calls == 1) {
                    val s = try {
                        Socket(InetAddress.getLoopbackAddress(), port)
                    } catch (e: IOException) {
                        throw LanPeerNotAnswering(e.message ?: "connect")
                    }
                    try {
                        s.soTimeout = 5_000
                        s.getOutputStream().write(frame)
                        val reply = readFrame(DataInputStream(s.getInputStream()))
                        socket = s
                        return reply
                    } catch (e: IOException) {
                        s.close()
                        throw LanPeerNotAnswering(e.message ?: "closed")
                    }
                }
                val s = socket ?: throw IOException("connection is closed")
                try {
                    s.getOutputStream().write(frame)
                    return readFrame(DataInputStream(s.getInputStream()))
                } finally {
                    s.close()
                    socket = null
                }
            }
        }
    }

    @Test
    fun the_android_joiner_pairs_with_and_syncs_through_the_phone_host() {
        val h = host(seed = true)
        val served = ArrayBlockingQueue<Int>(16)
        val server = LanHostServer(h.service, onServed = { served.add(1) }).also { servers.add(it) }
        val port = server.start(InetAddress.getLoopbackAddress())
        assertTrue(port > 0)
        assertTrue(server.isRunning)
        val (offer, handler, decider) = armed(h, true, LanEndpoint("127.0.0.1", port))
        server.enrollment = handler

        // Pairing: the joiner scans the QR text, sends its request, reads the reveal, then (after Accept) the reply.
        val scanned = PairingOffer.parseQr(offer.qrPayload())
        val request = Enrollment.buildRequest(scanned, joiner, "Pixel", null, SystemRandomSource(), SystemClock())
        val gk: GroupKey = Socket(InetAddress.getLoopbackAddress(), port).use { s ->
            s.soTimeout = 10_000
            s.getOutputStream().write(LanTransport.encodeFrame(request))
            val input = DataInputStream(s.getInputStream())
            var reply = LanTransport.decodeFrame(readFrame(input))
            assertTrue(Enrollment.isReveal(reply))
            val reveal = Enrollment.openReveal(scanned, reply)
            reply = LanTransport.decodeFrame(readFrame(input))
            Enrollment.openReply(scanned, joiner, reply, "Pixel", null, reveal)
        }
        assertEquals(h.state.groupKey(), gk)
        assertEquals(joiner.deviceId, decider.paired?.deviceId)
        server.enrollment = null

        // Sync: the joiner's LanClient against the host (both ways).
        val hostPeer = PinnedPeer(scanned.inviterDeviceId, scanned.groupId, scanned.inviterSigningPublic, scanned.inviterExchangePublic, scanned.endpoint)
        val client = LanClient(joiner, gk, HelloCounterSource(MemoryCounterStore(), SystemClock()), SystemRandomSource(), SystemClock())
        val aStates = SyncFixtures.views().first { it.deviceId == joiner.deviceId }.states
        val before = h.store.load().records
        val got = client.exchange(hostPeer, aStates, 1, LoopbackConnector(port), null)
        // The host's own items (C's) came back to the joiner ...
        assertTrue(before.keys.isNotEmpty())
        assertTrue(got.states.map { it.itemId }.containsAll(before.keys))
        // ... and the joiner's view was merged into the host's vault.
        assertNotNull(served.poll(5, TimeUnit.SECONDS))
        val after = h.store.load()
        assertTrue(after.records.keys.containsAll(before.keys))
        assertTrue(after.revision >= 2)
        assertTrue(h.service.takeReport()?.wrote == true)
        // The sealed hello pinned the joiner.
        assertTrue(LanPeers.entry(after.sync!!, joiner.deviceId)!!.sealed)

        // A revoked joiner is refused from then on, without an answer.
        val snap = h.store.load()
        h.store.commit(StoreChange(snap.revision, snap.records, snap.meta, LanPeers.revoking(joiner.deviceId, snap.sync!!).first))
        val refused = runCatching { client.exchange(hostPeer, aStates, 1, LoopbackConnector(port), null) }
        assertTrue(refused.isFailure)

        server.stop()
        assertFalse(server.isRunning)
        assertEquals(0, server.port)
    }
}
