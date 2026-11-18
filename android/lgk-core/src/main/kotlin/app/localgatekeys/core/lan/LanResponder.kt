package app.localgatekeys.core.lan

import app.localgatekeys.core.primitives.RandomSource

/**
 * The peers this device has had a sealed session with (desktop `SyncState.sealed_peers`, spec 2.5): kept in
 * memory, and [onSealed] persists a new pin once (the app writes `"hello":3` into the peer's entry). A pin is
 * removed only with the peer ([remove]).
 */
class SealedPeers(initial: Collection<String> = emptySet(), private val onSealed: (String) -> Unit = {}) {
    private val pinned = HashSet<String>(initial)

    @Synchronized
    operator fun contains(deviceId: String): Boolean = deviceId in pinned

    /** Pins [deviceId]; a new pin is handed to [onSealed] (a failed save never fails the finished session). */
    fun mark(deviceId: String) {
        val added = synchronized(this) { pinned.add(deviceId) }
        if (!added) return
        try {
            onSealed(deviceId)
        } catch (e: Exception) {
            // kept in memory; the next sealed session tries the save again only after a restart
        }
    }

    @Synchronized
    fun remove(deviceId: String) {
        pinned.remove(deviceId)
    }
}

/**
 * The responder of one LAN connection (desktop `SyncTransport._handle_inbound`, `docs/formats/LAN_SYNC_V3.md`
 * 2.3). Android never listens for LAN connections, so the app does not use it; it is the reference responder
 * of lgk-core (the tests drive [LanClient] against it) for a future listener.
 *
 * [first] takes the first frame payload and returns the payload to answer, or null to close without a word;
 * [request] takes the first encrypted frame (with its length prefix) and returns the encrypted response frame,
 * or null to close. One instance per connection.
 */
class LanResponder(
    private val identity: DeviceIdentity,
    private val groupId: String,
    private val peers: (String) -> PinnedPeer?,
    private val counters: HelloCounterSource,
    private val random: RandomSource,
    private val sealed: SealedPeers,
    private val handler: (PinnedPeer, ByteArray) -> ByteArray,
) {
    private var channel: SecureChannel? = null
    private var peer: PinnedPeer? = null
    private var wasSealed = false
    private var done = false

    /** Rules 2 to 5 of spec 2.3 for the first frame (an enrollment request is the caller's, rule 1). */
    fun first(payload: ByteArray): ByteArray? {
        if (done) return null
        done = true
        if (payload.size > LanTransport.MAX_FIRST_FRAME_BYTES) return null
        return try {
            hello(payload)
        } catch (e: InterruptedException) {
            throw e
        } catch (e: Exception) {
            null // anything that fails closes the connection without an answer (spec 2.3, step 4)
        }
    }

    private fun hello(payload: ByteArray): ByteArray? {
        val other = SessionHello.otherVersion(payload)
        var seal: SealContext? = null
        try {
            val remoteHello = when {
                other == null -> SessionHello.parse(payload)
                other != LanTransport.VERSION -> return LanTransport.versionRefusal()
                else -> SealedHello.openInitiator(payload, identity).also { seal = it.second }.first
            }
            val pinned = peers(remoteHello.deviceId) ?: return null
            SessionHello.verify(remoteHello, pinned, groupId)
            counters.acceptInbound(remoteHello.counter, pinned.deviceId)
            // Downgrade: a pinned peer's verified clear-text hello gets only the refusal (spec 2.3, step 2).
            if (seal == null && pinned.deviceId in sealed) return LanTransport.versionRefusal()
            val localHello = SessionHello.make(
                identity, groupId, remoteHello.sessionId, counters.nextCounter(), random, remoteHello.version,
            )
            try {
                val answer = seal?.let { SealedHello.sealResponder(localHello, it) } ?: localHello.toBytes()
                channel = SecureChannel(
                    identity, pinned, groupId, remoteHello.sessionId, SecureChannel.Role.RESPONDER, localHello, remoteHello,
                )
                peer = pinned
                wasSealed = seal != null
                return answer
            } finally {
                localHello.ephemeralSecret?.wipe()
            }
        } finally {
            seal?.wipe()
        }
    }

    /** Opens the first encrypted frame; only then the peer is pinned (a sealed session) and [handler] answers. */
    fun request(frame: ByteArray): ByteArray? {
        val ch = channel ?: return null
        val p = peer ?: return null
        channel = null
        val plain = try {
            ch.open(frame)
        } catch (e: Exception) {
            return null
        }
        if (wasSealed) sealed.mark(p.deviceId)
        return ch.seal(handler(p, plain))
    }

    /** This responder as the [LanConnection] of one connection (tests): a closed connection throws as a socket would. */
    fun connection(): LanConnection = object : LanConnection {
        private var calls = 0

        override fun exchange(frame: ByteArray): ByteArray {
            calls += 1
            if (calls == 1) {
                val payload = LanTransport.decodeFrame(frame)
                val answer = first(payload) ?: throw LanPeerNotAnswering("connection closed")
                return LanTransport.encodeFrame(answer)
            }
            return request(frame)
                ?: throw LanTransportException(LanTransportException.Kind.MALFORMED, "connection closed")
        }
    }
}
