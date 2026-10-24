package app.localgatekeys.core.lan

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.SyncFormatException
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock

/**
 * The only I/O seam of LAN sync: one TCP connection to the peer. A [LanConnector] opens a new
 * connection for every request; the client calls [exchange] exactly twice on it (its hello, then
 * the sealed request) and drops it. Frames carry their 4-byte length prefix both ways.
 * Blocking: the app calls it off the main thread.
 */
interface LanConnection {
    fun exchange(frame: ByteArray): ByteArray
}

/**
 * Thrown by a connector or connection when the peer did not answer before anything of the request
 * was sent: the connect failed, or the hello exchange failed (desktop `transport.PeerNotAnswering`).
 * [LanClient] retries such a request once, with a NEW hello (new session id, higher counter).
 */
class LanPeerNotAnswering(val detail: String) : Exception("peer did not answer: $detail")

interface LanConnector {
    fun connect(peer: PinnedPeer): LanConnection
}

/**
 * The initiator of LAN sync (desktop `lan_sync.sync_with` and `SyncTransport.request`).
 * Counter state lives in the lock-protected [HelloCounterSource], which the app shares between all clients
 * of one store (one source per store), so hello counters never repeat across clients.
 */
class LanClient(
    val identity: DeviceIdentity,
    val groupKey: GroupKey,
    private val counters: HelloCounterSource,
    private val random: RandomSource,
    private val clock: UnixClock,
    private val retryDelayMillis: Long = DEFAULT_RETRY_DELAY_MILLIS,
    private val sleep: (Long) -> Unit = { Thread.sleep(it) },
) {
    /**
     * One connection: send a hello (fresh 16-byte session id, then a 32-byte hello nonce from
     * `random`), check the responder's hello (pinned keys, same session id, increasing counter),
     * send one sealed request and open the one sealed response. A responder that answers the hello
     * with a version refusal (or a signed hello of another version) stops the request with
     * [LanSyncException] `peer-update-needed` (it announced an older version) or `lan-update-needed`
     * (a newer one); there is never a retry with another version. The hello's ephemeral private key
     * is zeroed when the request ends, used or not.
     */
    fun request(plaintext: ByteArray, peer: PinnedPeer, connection: LanConnection): ByteArray {
        val sessionId = random.bytes(LanTransport.SESSION_ID_BYTES)
        val localHello = SessionHello.make(identity, groupKey.groupId, sessionId, counters.nextCounter(), random)
        try {
            val helloFrame = connection.exchange(LanTransport.encodeFrame(localHello.toBytes()))
            val helloPayload = LanTransport.decodeFrame(helloFrame)
            val announced = LanTransport.parseVersionRefusal(helloPayload) ?: SessionHello.otherVersion(helloPayload)
            if (announced != null) throw versionMismatch(announced)
            val remoteHello = SessionHello.parse(helloPayload)
            if (remoteHello.deviceId != peer.deviceId) {
                throw LanTransportException(LanTransportException.Kind.AUTHENTICATION, "Session peer is not the expected paired device")
            }
            SessionHello.verify(remoteHello, peer, groupKey.groupId)
            counters.acceptInbound(remoteHello.counter, peer.deviceId)
            if (!remoteHello.sessionId.contentEquals(sessionId)) {
                throw LanTransportException(LanTransportException.Kind.AUTHENTICATION, "Session hello is bound to another session")
            }
            val channel = SecureChannel(
                identity, peer, groupKey.groupId, sessionId, SecureChannel.Role.INITIATOR, localHello, remoteHello,
            )
            val response = connection.exchange(channel.seal(plaintext))
            return channel.open(response)
        } finally {
            localHello.ephemeralSecret?.wipe()
        }
    }

    /**
     * One request on a new connection (desktop `sync_with.call`). With [retry], a request the peer did
     * not answer ([LanPeerNotAnswering]: nothing was sent) is made again once after [retryDelayMillis],
     * on a new connection with a newly minted hello.
     */
    private fun call(m: LanMessage, peer: PinnedPeer, connector: LanConnector, retry: Boolean = true): LanMessage {
        val plain = LanMessages.encode(m)
        val raw = try {
            request(plain, peer, connector.connect(peer))
        } catch (e: LanPeerNotAnswering) {
            if (!retry) throw e
            sleep(retryDelayMillis)
            request(plain, peer, connector.connect(peer))
        }
        try {
            return LanMessages.parse(raw)
        } catch (e: LanSyncException) {
            throw LanSyncException(if (e.reason == "bad-message") "bad-reply" else e.reason)
        }
    }

    /**
     * One LAN sync with [peer]: send this device's view in chunks (each acknowledged but the
     * last), receive the peer's view (first chunk as the answer to the last one, the rest with
     * `next`) and return the peer's decoded states for the caller to merge. Refusals throw
     * [LanSyncException] with the desktop's issue codes. [ownCounter] is the stored view header counter
     * (informational on LAN, never reserved).
     */
    fun sync(peer: PinnedPeer, localStates: List<ItemState>, ownCounter: Long, connector: LanConnector): List<ItemState> {
        val raw = try {
            ViewFile.encode(groupKey, identity.deviceId, ownCounter, localStates, clock, random)
        } catch (e: SyncFormatException) {
            throw LanSyncException("too-large", e.reason)
        }
        val parts = LanMessages.splitView(raw)
        if (raw.size > LanMessages.MAX_VIEW_BYTES || parts.size.toLong() > LanMessages.MAX_CHUNKS) {
            throw LanSyncException("too-large", "view exceeds the LAN bound")
        }
        val transfer = Hex.lower(random.bytes(16))
        fun chunk(seq: Int): LanMessage = LanMessage.View(
            groupKey.groupId, groupKey.epoch, transfer, seq.toLong(), parts.size.toLong(), raw.size.toLong(),
            Base64Std.encode(parts[seq]),
        )
        var reply = call(chunk(0), peer, connector, retry = false) // unreachable: reported at once
        for (seq in 1 until maxOf(parts.size, 1)) {
            if (reply != LanMessage.Ack(transfer, (seq - 1).toLong())) throw replyIssue(reply)
            reply = call(chunk(seq), peer, connector)
        }
        return receiveView(reply, peer, connector)
    }

    private fun receiveView(first: LanMessage, peer: PinnedPeer, connector: LanConnector): List<ItemState> {
        if (first !is LanMessage.View) throw replyIssue(first)
        if (first.groupId != groupKey.groupId) throw LanSyncException("group-mismatch", peer.deviceId)
        if (first.epoch != groupKey.epoch) {
            throw LanSyncException(if (first.epoch > groupKey.epoch) "epoch-behind" else "peer-epoch-behind", peer.deviceId)
        }
        val transfer = first.transfer
        val total = first.total
        val size = first.size
        val parts = ArrayList<ByteArray>()
        var received = 0L
        var message: LanMessage = first
        while (true) {
            val m = message as? LanMessage.View ?: throw replyIssue(message)
            if (m.transfer != transfer || m.seq != parts.size.toLong()) throw LanSyncException("bad-reply", "chunk order")
            if (m.groupId != groupKey.groupId || m.epoch != groupKey.epoch) throw LanSyncException("bad-reply", "chunk group")
            if (m.total != total || m.size != size) throw LanSyncException("bad-chunk")
            val data = try {
                Base64Std.decodeStrict(m.view)
            } catch (e: Base64Exception) {
                throw LanSyncException("bad-reply")
            }
            if (data.isEmpty()) throw LanSyncException("bad-chunk")
            if (data.size > LanMessages.CHUNK_LIMIT) throw LanSyncException("too-large")
            parts.add(data)
            received += data.size
            if (received > size) throw LanSyncException("bad-chunk")
            if (m.seq == total - 1) break
            message = call(LanMessage.Next(transfer, parts.size.toLong()), peer, connector)
        }
        if (received != size) throw LanSyncException("bad-chunk")
        val whole = ByteArray(received.toInt())
        var at = 0
        for (p in parts) {
            p.copyInto(whole, at)
            at += p.size
        }
        try {
            return ViewFile.decode(whole, groupKey, peer.deviceId).second
        } catch (e: SyncFormatException) {
            throw LanSyncException(
                if (e.reason == "device-mismatch") "device-mismatch" else "bad-peer-data",
                "${peer.deviceId}: ${e.reason}",
            )
        }
    }

    companion object {
        /** Desktop `lan_sync.CHUNK_RETRY_DELAY = 0.05` s. */
        const val DEFAULT_RETRY_DELAY_MILLIS: Long = 50

        /**
         * Desktop `PeerVersionMismatch` as its issue: [announced] below this version means the PEER
         * needs an update (`peer-update-needed`), above it means THIS device does (`lan-update-needed`).
         */
        internal fun versionMismatch(announced: Long): LanSyncException {
            val peerOlder = announced < LanTransport.VERSION
            val who = if (peerOlder) "the other device" else "this device"
            return LanSyncException(
                if (peerOlder) "peer-update-needed" else "lan-update-needed",
                "update needed: $who runs an older LocalGateKeys (Wi-Fi sync version " +
                    "${minOf(announced, LanTransport.VERSION)} instead of ${maxOf(announced, LanTransport.VERSION)})",
            )
        }

        /** `_reply_issue`: a responder error or an unexpected message. */
        internal fun replyIssue(m: LanMessage): LanSyncException {
            if (m is LanMessage.Error) {
                val mapped = mapOf(
                    "epoch-behind" to "epoch-behind", "peer-epoch-behind" to "peer-epoch-behind",
                    "rejoin-required" to "peer-rejoin-required", "not-joined" to "peer-not-joined",
                )
                val kind = mapped[m.reason]
                if (kind != null) return LanSyncException(kind)
                return LanSyncException("peer-refused", m.reason)
            }
            return LanSyncException("bad-reply", m.toString())
        }
    }
}
