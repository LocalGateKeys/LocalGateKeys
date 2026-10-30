package app.localgatekeys.android.sync

import app.localgatekeys.core.lan.BlobFetch
import app.localgatekeys.core.sync.AttachmentRef
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.Discovery
import app.localgatekeys.core.lan.Enrollment
import app.localgatekeys.core.lan.HelloCounterSource
import app.localgatekeys.core.lan.LanAddress
import app.localgatekeys.core.lan.LanClient
import app.localgatekeys.core.lan.LanConnection
import app.localgatekeys.core.lan.LanConnector
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.LanExchange
import app.localgatekeys.core.lan.LanPublish
import app.localgatekeys.core.lan.LanPeerNotAnswering
import app.localgatekeys.core.lan.LanSyncException
import app.localgatekeys.core.lan.LanTransport
import app.localgatekeys.core.lan.LanTransportException
import app.localgatekeys.core.lan.PinnedPeer
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel

// LAN sync over plain TCP sockets (semantics of ios/App/Sync/NWLanConnection.swift). Ruling 17 (amended): one deadline
// per connection (connect and all I/O, desktop DEFAULT_SOCKET_TIMEOUT = 5.0), except that an enrollment, once connected,
// waits up to Enrollment.ENROLL_REPLY_SECONDS for the reply (the other side's Accept). Every blocking wait is a
// Selector.select up to that deadline, and an interrupted thread (the coordinator's
// runInterruptible on cancel or lock) wakes the selector at once: the socket is closed and the step throws CANCELLED.

/** One TCP connection to a LAN endpoint. [receiveFrame] returns one whole frame, length prefix included. */
interface LanSocket {
    fun send(bytes: ByteArray)
    fun receiveFrame(): ByteArray
    fun close()
}

/** Opens TCP connections. Production: [ChannelLanDialer]; tests: a fake. Throws [LanSocketException]. */
interface LanDialer {
    /**
     * [forEnrollment]: once connected, the request and the reply get the enrollment reply time (Swift `waitForNetwork`:
     * the deadline becomes max(deadline, now + enrollReplyTimeout), desktop `ENROLL_REPLY_SECONDS` = 75 s: the inviting
     * device answers only after its user chose Accept); a sync connection keeps its one deadline from the dial.
     */
    fun dial(endpoint: LanEndpoint, forEnrollment: Boolean): LanSocket
}

fun LanDialer.dial(endpoint: LanEndpoint): LanSocket = dial(endpoint, forEnrollment = false)

private fun isCancelled(): Boolean = Thread.currentThread().isInterrupted

private fun cancelled(): LanSocketException = LanSocketException("cancelled", LanFailure.CANCELLED)

/**
 * The [LanConnector] the app gives `LanClient.sync`. Only the paired peer is contacted, and only at an address where
 * `LanAddress.isLan` is true. A connect or hello that fails surfaces as [LanPeerNotAnswering] (nothing of the request
 * was sent), which `LanClient` retries once after 50 ms with a newly minted hello; a cancelled one does not.
 */
class PairedLanConnector(private val paired: PinnedPeer, private val dialer: LanDialer) : LanConnector {
    override fun connect(peer: PinnedPeer): LanConnection {
        if (peer != paired) throw LanSocketException("not the paired device")
        val endpoint = peer.endpoint
        if (endpoint == null || !LanAddress.isLan(endpoint.host)) throw LanSocketException("the paired device has no LAN address")
        return SocketLanConnection(endpoint, dialer)
    }

    override fun toString(): String = "PairedLanConnector(peer=${paired.deviceId})"
}

/** One request on one connection: the first [exchange] dials and sends the hello, the second sends the sealed request and closes. */
class SocketLanConnection(private val endpoint: LanEndpoint, private val dialer: LanDialer) : LanConnection {
    private var socket: LanSocket? = null
    private var exchanges = 0

    @Synchronized
    override fun exchange(frame: ByteArray): ByteArray {
        exchanges += 1
        if (exchanges == 1) {
            val s = try {
                dialer.dial(endpoint)
            } catch (e: LanSocketException) {
                if (e.kind == LanFailure.CANCELLED || isCancelled()) throw e
                throw LanPeerNotAnswering(e.message ?: "connect failed")
            }
            try {
                s.send(frame)
                val reply = s.receiveFrame()
                socket = s
                return reply
            } catch (e: Exception) {
                s.close()
                if ((e as? LanSocketException)?.kind == LanFailure.CANCELLED || isCancelled()) throw e
                throw LanPeerNotAnswering(e.message ?: e.javaClass.simpleName)
            }
        }
        val s = socket ?: throw LanSocketException("connection is closed")
        try {
            s.send(frame)
            return s.receiveFrame()
        } finally {
            s.close()
            socket = null
        }
    }

    override fun toString(): String = "SocketLanConnection(${SyncWording.hostPort(endpoint)})"
}

/**
 * Sends the one enrollment request of a scanned offer and returns the one-frame reply (desktop `SyncTransport.enroll`).
 * Not retried. The reply comes only after the user chose Accept on the inviting device, so the read waits up to the
 * dialer's enrollment reply time ([LanDialer.dial] forEnrollment).
 */
class SocketEnroller(private val dialer: LanDialer) {
    /** [onConnected]: called once the connection is up, before the request is sent. */
    fun enroll(endpoint: LanEndpoint, request: ByteArray, onConnected: () -> Unit = {}): ByteArray {
        if (!LanAddress.isLan(endpoint.host)) throw LanSocketException("not a LAN address")
        val magic = Enrollment.REQUEST_MAGIC
        if (request.size > Enrollment.MAX_BYTES || request.size < magic.size || !request.copyOf(magic.size).contentEquals(magic)) {
            throw LanSocketException("enrollment request is malformed")
        }
        val s = dialer.dial(endpoint, forEnrollment = true)
        try {
            onConnected()
            s.send(LanTransport.encodeFrame(request))
            val reply = LanTransport.decodeFrame(s.receiveFrame())
            if (reply.size > Enrollment.MAX_BYTES) throw LanSocketException("enrollment reply exceeds the bound")
            return reply
        } finally {
            s.close()
        }
    }

    override fun toString(): String = "SocketEnroller"
}

/**
 * TCP to a literal LAN address over a non-blocking [SocketChannel]. The address comes from the scanned QR offer and is
 * pinned with the peer (or from discovery, [SocketLanTransport.exchangeViewsFindingHost]); no DNS lookup is made. [timeoutMs] is the connection's one deadline
 * (Ruling 17: connect plus every send and read, desktop `DEFAULT_SOCKET_TIMEOUT = 5.0`); an enrollment dial, once
 * connected, gives its request and reply [enrollReplyMs] (Ruling 17 amended, desktop `ENROLL_REPLY_SECONDS`). [bind] runs on the
 * unconnected channel (the app binds it to the Wi-Fi network, [WifiNetworkBinder]); [route] turns the endpoint into the
 * socket address (tests send every dial to a loopback responder).
 */
class ChannelLanDialer internal constructor(
    val timeoutMs: Int,
    val enrollReplyMs: Int,
    private val bind: (SocketChannel, InetAddress) -> Unit,
    private val route: (LanEndpoint) -> InetSocketAddress,
) : LanDialer {
    constructor(
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
        enrollReplyMs: Int = DEFAULT_ENROLL_REPLY_MS,
        bind: (SocketChannel, InetAddress) -> Unit = { _, _ -> },
    ) : this(timeoutMs, enrollReplyMs, bind, ::literal)

    override fun dial(endpoint: LanEndpoint, forEnrollment: Boolean): LanSocket {
        if (!LanAddress.isLan(endpoint.host) || endpoint.port !in 1..65535) throw LanSocketException("not a LAN address")
        if (isCancelled()) throw cancelled()
        val address = try {
            route(endpoint)
        } catch (e: Exception) {
            throw LanSocketException("not a LAN address")
        }
        val channel = try {
            SocketChannel.open()
        } catch (e: IOException) {
            throw LanSocketException("socket failed: ${e.message}", LanDiagnostics.classify(e))
        }
        var selector: Selector? = null
        try {
            bind(channel, address.address)
            channel.configureBlocking(false)
            val sel = Selector.open().also { selector = it }
            val key = channel.register(sel, 0)
            val socket = ChannelLanSocket(channel, sel, key, System.nanoTime() + timeoutMs * 1_000_000L)
            val done = try {
                channel.connect(address)
            } catch (e: IOException) {
                throw LanSocketException("connect failed: ${e.message}", LanDiagnostics.classify(e))
            }
            if (!done) {
                while (true) {
                    socket.await(SelectionKey.OP_CONNECT, "connect timed out")
                    val finished = try {
                        channel.finishConnect()
                    } catch (e: IOException) {
                        throw LanSocketException("connect failed: ${e.message}", LanDiagnostics.classify(e))
                    }
                    if (finished) break
                }
            }
            if (forEnrollment) socket.extendDeadline(enrollReplyMs)
            return socket
        } catch (e: Throwable) {
            try { selector?.close() } catch (_: IOException) { }
            try { channel.close() } catch (_: IOException) { }
            if (e is LanSocketException) throw e
            if (isCancelled()) throw cancelled()
            throw LanSocketException("connect failed: ${e.message}", LanDiagnostics.classify(e))
        }
    }

    override fun toString(): String = "ChannelLanDialer(timeoutMs=$timeoutMs)"

    companion object {
        /** Desktop `DEFAULT_SOCKET_TIMEOUT = 5.0` (Ruling 17). */
        const val DEFAULT_TIMEOUT_MS = 5_000

        /** Desktop `ENROLL_REPLY_SECONDS` (75 s: the 60 s Accept timeout plus a margin), Ruling 17 amended. */
        const val DEFAULT_ENROLL_REPLY_MS = Enrollment.ENROLL_REPLY_SECONDS * 1_000

        /** A literal host: no DNS lookup is ever made. */
        internal fun literal(e: LanEndpoint): InetSocketAddress = InetSocketAddress(InetAddress.getByName(e.host), e.port)
    }
}

/** A connected non-blocking channel; every wait is a select with a deadline that an interrupt cuts short. */
internal class ChannelLanSocket(
    private val channel: SocketChannel,
    private val selector: Selector,
    private val key: SelectionKey,
    /** The connection's one deadline (System.nanoTime): connect and all I/O end by then. */
    @Volatile private var deadline: Long,
) : LanSocket {
    /** Enrollment once connected: the exchange gets at least [ms] from now (Swift max(deadline, now + ioTimeout)). */
    fun extendDeadline(ms: Int) {
        deadline = maxOf(deadline, System.nanoTime() + ms * 1_000_000L)
    }

    /** Waits for [op] until the deadline. Closes the socket and throws on interrupt or timeout. */
    fun await(op: Int, timeoutMessage: String) {
        key.interestOps(op)
        while (true) {
            if (isCancelled()) {
                close()
                throw cancelled()
            }
            val left = deadline - System.nanoTime()
            if (left <= 0) {
                close()
                throw LanSocketException(timeoutMessage, LanFailure.TIMED_OUT)
            }
            selector.selectedKeys().clear()
            try {
                selector.select(maxOf(1L, (left + 999_999) / 1_000_000))
            } catch (e: IOException) {
                close()
                throw LanSocketException("wait failed: ${e.message}", LanDiagnostics.classify(e))
            }
            if (isCancelled()) {
                close()
                throw cancelled()
            }
            if (key.isValid && (key.readyOps() and op) != 0) return
        }
    }

    private fun failure(what: String, e: IOException): LanSocketException {
        close()
        if (isCancelled()) return cancelled()
        return LanSocketException("$what failed: ${e.message}", LanDiagnostics.classify(e))
    }

    override fun send(bytes: ByteArray) {
        val buf = ByteBuffer.wrap(bytes)
        while (buf.hasRemaining()) {
            val n = try {
                channel.write(buf)
            } catch (e: IOException) {
                throw failure("write", e)
            }
            if (n == 0) await(SelectionKey.OP_WRITE, "write timed out")
        }
    }

    private fun readExactly(n: Int): ByteArray {
        val buf = ByteBuffer.allocate(n)
        while (buf.hasRemaining()) {
            val r = try {
                channel.read(buf)
            } catch (e: IOException) {
                throw failure("read", e)
            }
            if (r < 0) {
                close()
                throw LanSocketException("peer closed the connection", LanFailure.CLOSED_BY_PEER)
            }
            if (r == 0) await(SelectionKey.OP_READ, "read timed out")
        }
        return buf.array()
    }

    override fun receiveFrame(): ByteArray {
        val header = readExactly(4)
        val n = ((header[0].toInt() and 0xFF) shl 24) or ((header[1].toInt() and 0xFF) shl 16) or
            ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
        if (n < 1 || n > LanTransport.MAX_FRAME_PAYLOAD) {
            close()
            throw LanSocketException("frame length is outside the bound")
        }
        return header + readExactly(n)
    }

    override fun close() {
        try { key.cancel() } catch (_: Exception) { }
        try { selector.close() } catch (_: IOException) { }
        try { channel.close() } catch (_: IOException) { }
    }

    override fun toString(): String = "ChannelLanSocket"
}

/**
 * The production [LanTransporting]: `LanClient` over [PairedLanConnector] with the retry-once rule, hello counters
 * from the unlock's one shared [HelloCounterSource]; enrollment through [SocketEnroller].
 */
class SocketLanTransport(
    private val counters: HelloCounterSource,
    private val random: RandomSource,
    private val clock: UnixClock,
    val timeoutMs: Int = ChannelLanDialer.DEFAULT_TIMEOUT_MS,
    val enrollReplyMs: Int = ChannelLanDialer.DEFAULT_ENROLL_REPLY_MS,
    private val dialer: LanDialer = ChannelLanDialer(timeoutMs, enrollReplyMs),
    /** Finds the host when its pinned address does not answer; null: no discovery. */
    private val browser: ServiceBrowser? = null,
    val browseMs: Long = DEFAULT_BROWSE_MS,
) : LanTransporting {
    override fun exchangeViews(
        peer: PinnedPeer,
        identity: DeviceIdentity,
        groupKey: GroupKey,
        localStates: List<ItemState>,
        ownCounter: Long,
    ): List<ItemState> {
        val client = LanClient(identity, groupKey, counters, random, clock)
        return client.sync(peer, localStates, ownCounter, PairedLanConnector(peer, dialer))
    }

    /**
     * The pinned address first. When it does not answer (connect refused or timed out, or no hello: nothing was sent),
     * browse [Discovery.SERVICE_TYPE] for [browseMs] and dial each announcement with today's or yesterday's tag for
     * this host, at a LAN address, at most [Discovery.MAX_CANDIDATES], with the normal handshake. A candidate whose
     * hello fails the pinned keys (or that does not answer) is skipped. Nothing found: the pinned failure is thrown.
     */
    override fun exchangeViewsFindingHost(
        peer: PinnedPeer,
        identity: DeviceIdentity,
        groupKey: GroupKey,
        localStates: List<ItemState>,
        ownCounter: Long,
        onMoved: (LanEndpoint) -> Unit,
    ): List<ItemState> = exchangeWitnessing(peer, identity, groupKey, localStates, ownCounter, null, onMoved).states

    /** [exchangeViewsFindingHost] with rollback witnesses ([LanClient.exchange]). */
    override fun exchangeWitnessing(
        peer: PinnedPeer,
        identity: DeviceIdentity,
        groupKey: GroupKey,
        localStates: List<ItemState>,
        ownCounter: Long,
        publish: LanPublish?,
        onMoved: (LanEndpoint) -> Unit,
    ): LanExchange {
        val client = LanClient(identity, groupKey, counters, random, clock)
        try {
            return client.exchange(peer, localStates, ownCounter, PairedLanConnector(peer, dialer), publish)
        } catch (e: LanPeerNotAnswering) {
            val b = browser ?: throw e
            if (Thread.currentThread().isInterrupted) throw cancelledError()
            val found = try {
                b.browse(Discovery.SERVICE_TYPE, browseMs)
            } catch (x: LanSocketException) {
                if (x.kind == LanFailure.CANCELLED) throw x
                throw e
            } catch (x: Exception) {
                throw e
            }
            val accepted = Discovery.acceptedTags(groupKey, peer.deviceId, clock.now)
            for (candidate in Discovery.candidates(found, accepted, peer.endpoint)) {
                if (Thread.currentThread().isInterrupted) throw cancelledError()
                val moved = peer.copy(endpoint = candidate)
                try {
                    val result = client.exchange(moved, localStates, ownCounter, PairedLanConnector(moved, dialer), publish)
                    onMoved(candidate)
                    return result
                } catch (x: LanPeerNotAnswering) {
                    continue
                } catch (x: LanTransportException) {
                    continue // not the paired host: its hello failed the pinned keys
                } catch (x: LanSyncException) {
                    // An unsigned version refusal proves nothing about who answered.
                    if (x.reason == "peer-update-needed" || x.reason == "lan-update-needed") continue
                    throw x
                } catch (x: LanSocketException) {
                    if (x.kind == LanFailure.CANCELLED || Thread.currentThread().isInterrupted) throw x
                    continue
                }
            }
            throw e
        }
    }

    private fun cancelledError() = LanSocketException("cancelled", LanFailure.CANCELLED)

    override fun fetchBlobs(
        peer: PinnedPeer,
        identity: DeviceIdentity,
        groupKey: GroupKey,
        refs: List<AttachmentRef>,
        probe: Boolean,
    ): BlobFetch = LanClient(identity, groupKey, counters, random, clock).fetchBlobs(peer, PairedLanConnector(peer, dialer), refs, probe)

    override fun enroll(endpoint: LanEndpoint, request: ByteArray, onConnected: () -> Unit): ByteArray =
        SocketEnroller(dialer).enroll(endpoint, request, onConnected)

    /** Never shows the counters, keys or frames. */
    override fun toString(): String = "SocketLanTransport(timeoutMs=$timeoutMs)"

    companion object {
        /** Plan 2026-10-29-sync-ip-change: browse for up to 3 s when the pinned address fails. */
        const val DEFAULT_BROWSE_MS = 3_000L
    }
}

/**
 * Binds each LAN socket to the Wi-Fi (or Ethernet) network, so a LAN address is never sent over cellular, even when
 * Android routes the default traffic there (a Wi-Fi without internet). Ruling 18: with no such network the dial fails at
 * once as UNREACHABLE (the Sync screen then says the address "cannot be reached from this phone"); loopback is left
 * alone. [lookup] finds the network (tests: a fake).
 */
class WifiNetworkBinder internal constructor(private val lookup: () -> Network?) {
    constructor(context: Context) : this(systemLookup(context.applicationContext.getSystemService(ConnectivityManager::class.java)))

    /** The Wi-Fi network, else an Ethernet one; never cellular or a VPN. */
    fun localNetwork(): Network? = lookup()

    fun bind(channel: SocketChannel, address: InetAddress) {
        if (address.isLoopbackAddress) return
        val network = localNetwork() ?: throw LanSocketException("no Wi-Fi network", LanFailure.UNREACHABLE)
        try {
            network.bindSocket(channel.socket())
        } catch (e: IOException) {
            throw LanSocketException("could not use the Wi-Fi network: ${e.message}", LanFailure.UNREACHABLE)
        }
    }

    override fun toString(): String = "WifiNetworkBinder"

    companion object {
        @Suppress("DEPRECATION") // allNetworks: the one synchronous list; a callback would be needed otherwise.
        private fun systemLookup(cm: ConnectivityManager?): () -> Network? = lookup@{
            if (cm == null) return@lookup null
            val networks = try { cm.allNetworks.toList() } catch (_: Exception) { emptyList() }
            fun has(n: Network, transport: Int): Boolean = try {
                val caps = cm.getNetworkCapabilities(n)
                caps != null && caps.hasTransport(transport) && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            } catch (_: Exception) {
                false
            }
            networks.firstOrNull { has(it, NetworkCapabilities.TRANSPORT_WIFI) }
                ?: networks.firstOrNull { has(it, NetworkCapabilities.TRANSPORT_ETHERNET) }
        }
    }
}
