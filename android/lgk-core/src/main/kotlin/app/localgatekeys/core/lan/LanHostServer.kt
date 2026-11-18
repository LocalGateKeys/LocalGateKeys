package app.localgatekeys.core.lan

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit

// The Wi-Fi sync host of a phone (Mac `ios/Mac/Sync/LanListener.swift`, desktop `transport.SyncTransport` listener).
// The pure parts, connection limits ([InboundLimits]) and the per-connection protocol ([LanHostSession]), are unit-tested;
// [LanHostServer] only moves bytes over java.net sockets (one thread per connection, deadlines as the Mac).

/** Desktop `transport.py` listener constants (Swift `LanListenLimits`). */
object LanListenLimits {
    const val MAX_CONNECTIONS = 4
    const val MAX_PER_ADDRESS = 2
    const val MAX_PRE_AUTH_PER_ADDRESS = 1
    const val MAX_PRE_AUTH_PER_PREFIX = 3
    const val RESERVED_FOR_VERIFIED = 1
    const val VERIFIED_SECONDS: Double = 15.0 * 60
    const val MAX_VERIFIED_ADDRESSES = 64

    /** `FIRST_FRAME_SECONDS`. */
    const val FIRST_FRAME_MS: Long = 2_000

    /** `DEFAULT_SOCKET_TIMEOUT`: the whole inbound connection. */
    const val SOCKET_MS: Long = 5_000

    /** `MAX_FIRST_FRAME_BYTES`. */
    const val MAX_FIRST_FRAME_BYTES = 64 * 1024

    /** `LISTEN_BACKLOG`. */
    const val BACKLOG = 8
}

/**
 * Inbound connection bookkeeping (desktop `_reserve_inbound`, `_inbound_authenticated`, `_release_inbound`; Swift
 * `InboundLimits`). Every address: at most 4 connections in total and 2 from it. An address without a verified hello in
 * the last 15 minutes also leaves 1 slot free and holds at most 1 unauthenticated connection itself and 3 together with
 * its /24 (IPv4) or /64 (IPv6) network. Not thread-safe: the server guards it with a lock.
 */
class InboundLimits {
    private val inbound = HashMap<Int, String>() // connection id -> source address
    private val preAuth = HashMap<Int, String>() // not yet authenticated -> source network
    private val verified = ArrayList<Pair<String, Double>>() // oldest first

    val count: Int get() = inbound.size
    val preAuthCount: Int get() = preAuth.size

    private fun recentlyVerified(address: String, now: Double): Boolean {
        verified.removeAll { now - it.second > LanListenLimits.VERIFIED_SECONDS }
        return verified.any { it.first == address }
    }

    /** Takes a slot for connection [id] from [address]; false when a cap is reached (close it unread). */
    fun reserve(id: Int, address: String, now: Double): Boolean {
        val prefix = prefix(address)
        if (inbound.size >= LanListenLimits.MAX_CONNECTIONS) return false
        if (inbound.values.count { it == address } >= LanListenLimits.MAX_PER_ADDRESS) return false
        if (!recentlyVerified(address, now)) {
            if (inbound.size >= LanListenLimits.MAX_CONNECTIONS - LanListenLimits.RESERVED_FOR_VERIFIED) return false
            if (preAuth.keys.count { inbound[it] == address } >= LanListenLimits.MAX_PRE_AUTH_PER_ADDRESS) return false
            if (preAuth.values.count { it == prefix } >= LanListenLimits.MAX_PRE_AUTH_PER_PREFIX) return false
        }
        inbound[id] = address
        preAuth[id] = prefix
        return true
    }

    /** Connection [id] sent a verified session hello: it leaves the pre-authentication caps and its address may use the reserved slot for 15 minutes. */
    fun authenticated(id: Int, now: Double) {
        preAuth.remove(id)
        val address = inbound[id] ?: return
        verified.removeAll { it.first == address }
        verified.add(address to now)
        while (verified.size > LanListenLimits.MAX_VERIFIED_ADDRESSES) verified.removeAt(0)
    }

    fun release(id: Int) {
        inbound.remove(id)
        preAuth.remove(id)
    }

    /** The listener stopped: every connection is gone (verified addresses are kept, like the desktop). */
    fun removeAll() {
        inbound.clear()
        preAuth.clear()
    }

    companion object {
        /** The /24 or /64 network of [address] (a zone id is dropped, an IPv4-mapped IPv6 address counts as IPv4); the address itself when it does not parse. */
        fun prefix(address: String): String {
            val bare = address.split('%', limit = 2).first()
            return when (val p = LanAddress.parse(bare)) {
                is LanAddress.Parsed.V4 -> {
                    val b = p.bytes.map { it.toInt() and 0xFF }
                    "${b[0]}.${b[1]}.${b[2]}.0/24"
                }
                is LanAddress.Parsed.V6 -> {
                    val b = p.bytes.map { it.toInt() and 0xFF }
                    if ((0 until 10).all { b[it] == 0 } && b[10] == 0xFF && b[11] == 0xFF) {
                        "${b[12]}.${b[13]}.${b[14]}.0/24"
                    } else {
                        (0 until 8).joinToString("") { "%02x".format(b[it]) } + "::/64"
                    }
                }
                null -> bare
            }
        }
    }
}

/**
 * One accepted TCP connection as the host protocol uses it. [receiveFrame] returns one whole frame, length prefix
 * included, of at most [limit] payload bytes, by [deadlineNanos] (System.nanoTime). Failures throw.
 */
interface HostSocket {
    fun receiveFrame(limit: Int, deadlineNanos: Long): ByteArray
    fun send(bytes: ByteArray, deadlineNanos: Long)
    fun close()
}

/**
 * Answers one enrollment request (`LGKENROLL1`): the reply payload to send, or null to close without one. It may block
 * for the user's Accept (up to 60 s). [sendInterim] sends one interim frame payload before the reply (the reveal of a
 * version-2 offer); it throws when the device is gone.
 */
fun interface EnrollmentHandling {
    fun enroll(raw: ByteArray, sendInterim: (ByteArray) -> Unit): ByteArray?
}

/**
 * The host side of one inbound connection (desktop `transport._handle_inbound`, Swift `LanHostSession`): the first frame
 * (at most 64 KiB, within 2 s) is either an enrollment request, answered only while an offer is shown, or a session
 * hello, which [LanHostService] checks against the listed peers; then one sealed request and its sealed answer, all
 * within 5 s. Any failure closes the connection without an answer.
 */
class LanHostSession(
    private val service: LanHostService,
    /** The armed offer's handler; null while no pairing code is shown (an enrollment request is then dropped). */
    private val enrollment: EnrollmentHandling?,
    private val socketMs: Long = LanListenLimits.SOCKET_MS,
    private val firstFrameMs: Long = LanListenLimits.FIRST_FRAME_MS,
) {
    enum class Outcome { CLOSED, ENROLLMENT_ANSWERED, VERSION_REFUSED, SERVED }

    private fun after(ms: Long): Long = System.nanoTime() + ms * 1_000_000L

    /** Runs the connection to its end and closes the socket. [authenticated] is called once a session hello verified. */
    fun handle(socket: HostSocket, authenticated: () -> Unit = {}): Outcome {
        try {
            val deadline = after(socketMs)
            val first = socket.receiveFrame(LanListenLimits.MAX_FIRST_FRAME_BYTES, minOf(deadline, after(firstFrameMs)))
            val payload = LanTransport.decodeFrame(first)
            if (startsWith(payload, Enrollment.REQUEST_MAGIC)) {
                val handler = enrollment ?: return Outcome.CLOSED
                if (payload.size > Enrollment.MAX_BYTES) return Outcome.CLOSED
                val interim: (ByteArray) -> Unit = { frame ->
                    if (frame.size !in 1..Enrollment.MAX_BYTES) throw IOException("Enrollment interim frame is malformed")
                    socket.send(LanTransport.encodeFrame(frame), after(socketMs))
                }
                val reply = handler.enroll(payload, interim) ?: return Outcome.CLOSED
                if (reply.size !in 1..Enrollment.MAX_BYTES) return Outcome.CLOSED
                // The reply comes after the user's Accept: it gets a fresh socket timeout.
                socket.send(LanTransport.encodeFrame(reply), after(socketMs))
                return Outcome.ENROLLMENT_ANSWERED
            }
            when (val opening = service.accept(payload)) {
                is LanHostService.Opening.Refuse -> {
                    socket.send(LanTransport.encodeFrame(opening.payload), deadline)
                    return Outcome.VERSION_REFUSED
                }
                is LanHostService.Opening.Accepted -> {
                    authenticated()
                    val connection = opening.connection
                    socket.send(LanTransport.encodeFrame(connection.helloPayload), deadline)
                    val request = socket.receiveFrame(LanTransport.MAX_FRAME_PAYLOAD, deadline)
                    val answer = service.respond(connection, request)
                    socket.send(answer, deadline)
                    return Outcome.SERVED
                }
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            return Outcome.CLOSED
        } catch (e: Exception) {
            return Outcome.CLOSED
        } finally {
            socket.close()
        }
    }

    private fun startsWith(data: ByteArray, prefix: ByteArray): Boolean =
        data.size >= prefix.size && (prefix.indices).all { data[it] == prefix[it] }
}

/**
 * A [java.net.Socket] as a [HostSocket]: every read waits at most until its deadline (SO_TIMEOUT), and a write that is
 * still blocked at its deadline has the socket closed under it by [watchdog].
 */
class StreamHostSocket(private val socket: Socket, private val watchdog: ScheduledExecutorService) : HostSocket {
    private val input: InputStream = socket.getInputStream()
    private val output: OutputStream = socket.getOutputStream()

    private fun remainingMs(deadlineNanos: Long): Int {
        val left = (deadlineNanos - System.nanoTime()) / 1_000_000L
        if (left <= 0) throw SocketTimeoutException("deadline passed")
        return left.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    }

    private fun readExactly(n: Int, deadlineNanos: Long): ByteArray {
        val out = ByteArray(n)
        var got = 0
        while (got < n) {
            socket.soTimeout = remainingMs(deadlineNanos)
            val r = input.read(out, got, n - got)
            if (r < 0) throw IOException("connection closed")
            got += r
        }
        return out
    }

    override fun receiveFrame(limit: Int, deadlineNanos: Long): ByteArray {
        val head = readExactly(4, deadlineNanos)
        val n = ((head[0].toInt() and 0xFF) shl 24) or ((head[1].toInt() and 0xFF) shl 16) or
            ((head[2].toInt() and 0xFF) shl 8) or (head[3].toInt() and 0xFF)
        if (n < 1 || n > limit || n > LanTransport.MAX_FRAME_PAYLOAD) throw IOException("frame length is outside the bound")
        return head + readExactly(n, deadlineNanos)
    }

    override fun send(bytes: ByteArray, deadlineNanos: Long) {
        val ms = remainingMs(deadlineNanos)
        val guard = watchdog.schedule({ close() }, ms.toLong(), TimeUnit.MILLISECONDS)
        try {
            output.write(bytes)
            output.flush()
        } finally {
            guard.cancel(false)
        }
    }

    override fun close() {
        try {
            socket.close()
        } catch (_: IOException) {
        }
    }
}

/**
 * The listener (Swift `LanHostServer`): a [ServerSocket] on one address with a system-chosen port, an accept thread and
 * one thread per connection under [InboundLimits]. Thread-safe. [enrollment] is the armed offer's handler (null while no
 * code is shown).
 */
class LanHostServer(
    private val service: LanHostService,
    private val monotonic: MonotonicClock = SystemMonotonicClock,
    private val socketMs: Long = LanListenLimits.SOCKET_MS,
    private val firstFrameMs: Long = LanListenLimits.FIRST_FRAME_MS,
    /** Called after each connection that was served (a merge may have changed the vault). */
    private val onServed: () -> Unit = {},
) {
    private val lock = Any()
    private val limits = InboundLimits()
    private val connections = HashMap<Int, Socket>()
    private var server: ServerSocket? = null
    private var acceptThread: Thread? = null
    private var watchdog: ScheduledExecutorService? = null
    private var nextId = 0

    @Volatile
    var enrollment: EnrollmentHandling? = null

    val isRunning: Boolean get() = synchronized(lock) { server != null }

    /** The bound port while running, else 0. */
    val port: Int get() = synchronized(lock) { server?.localPort ?: 0 }

    /** Inbound connections in progress (tests and diagnostics). */
    val activeConnections: Int get() = synchronized(lock) { limits.count }

    /** Binds [host]:[port] (0: a system-chosen port) and starts accepting; returns the bound port. Throws IOException. */
    fun start(host: InetAddress, port: Int = 0): Int {
        stop()
        val ss = ServerSocket()
        try {
            ss.reuseAddress = true
            ss.bind(InetSocketAddress(host, port), LanListenLimits.BACKLOG)
        } catch (e: IOException) {
            try { ss.close() } catch (_: IOException) { }
            throw e
        }
        val dog = Executors.newSingleThreadScheduledExecutor(daemon("lgk-host-watchdog"))
        val t = daemon("lgk-host-accept").newThread { acceptLoop(ss) }
        synchronized(lock) {
            server = ss
            watchdog = dog
            acceptThread = t
        }
        t.start()
        return ss.localPort
    }

    /** Closes the listener and every open connection; the armed offer handler is dropped. */
    fun stop() {
        val (ss, open, dog) = synchronized(lock) {
            val r = Triple(server, connections.values.toList(), watchdog)
            server = null
            acceptThread = null
            watchdog = null
            connections.clear()
            limits.removeAll()
            enrollment = null
            r
        }
        try { ss?.close() } catch (_: IOException) { }
        for (s in open) try { s.close() } catch (_: IOException) { }
        dog?.shutdownNow()
    }

    private fun acceptLoop(ss: ServerSocket) {
        while (!ss.isClosed) {
            val socket = try {
                ss.accept()
            } catch (e: IOException) {
                break
            }
            accept(ss, socket)
        }
    }

    private fun accept(ss: ServerSocket, socket: Socket) {
        val address = socket.inetAddress?.hostAddress ?: ""
        val (id, dog, handler) = synchronized(lock) {
            val dog = watchdog
            if (server !== ss || dog == null) {
                null
            } else {
                val id = nextId++
                if (limits.reserve(id, address, monotonic.seconds())) {
                    connections[id] = socket
                    Triple(id, dog, enrollment)
                } else {
                    null
                }
            }
        } ?: run {
            try { socket.close() } catch (_: IOException) { }
            return
        }
        val session = LanHostSession(service, handler, socketMs, firstFrameMs)
        val worker = daemon("lgk-host-conn").newThread {
            var outcome = LanHostSession.Outcome.CLOSED
            try {
                socket.tcpNoDelay = true
                outcome = session.handle(StreamHostSocket(socket, dog)) {
                    synchronized(lock) { limits.authenticated(id, monotonic.seconds()) }
                }
            } catch (_: Exception) {
                try { socket.close() } catch (_: IOException) { }
            } finally {
                synchronized(lock) {
                    limits.release(id)
                    connections.remove(id)
                }
            }
            if (outcome == LanHostSession.Outcome.SERVED) {
                try { onServed() } catch (_: Exception) { }
            }
        }
        worker.start()
    }

    override fun toString(): String = "LanHostServer(port=$port)"

    private companion object {
        fun daemon(name: String) = ThreadFactory { r -> Thread(r, name).apply { isDaemon = true } }
    }
}
