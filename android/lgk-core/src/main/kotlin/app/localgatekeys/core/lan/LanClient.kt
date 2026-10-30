package app.localgatekeys.core.lan

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.SyncFormatException
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.group.ViewHeader
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.sync.AttachmentRef
import app.localgatekeys.core.sync.AttachmentSync
import app.localgatekeys.core.sync.AttachmentSyncException
import app.localgatekeys.core.sync.Observation
import app.localgatekeys.core.sync.SyncIssue
import app.localgatekeys.core.sync.Witness
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
 * What this device publishes on one LAN exchange (desktop `lan_sync` "Format gating", 2026-10-29): its vault
 * generation and witness; [inline] sends them in a format-2 view (only to a peer in `witnessPeers`), otherwise the view
 * is format 1 and one `witness` message follows the exchange.
 */
data class LanPublish(val inline: Boolean, val vaultGeneration: Long, val witness: Map<String, Long>)

/**
 * One LAN exchange: the peer's [states], what it published ([observation], null when nothing), and [issue] when its
 * `witness` answer could not be used.
 */
class LanExchange(val states: List<ItemState>, val observation: Observation? = null, val issue: SyncIssue? = null)

/**
 * The files fetched after a view exchange (attachment sync, 2026-10-29): [blobs] by blob id, each checked against its
 * content address; [capable] true when the peer answered a `blob-get` (`no-blob` or a chunk), false when it refused the
 * message (`bad-message`, an older build), null when nothing told; [issues] for refused files.
 */
class BlobFetch(val blobs: Map<String, ByteArray> = emptyMap(), val capable: Boolean? = null, val issues: List<SyncIssue> = emptyList())

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
    fun sync(peer: PinnedPeer, localStates: List<ItemState>, ownCounter: Long, connector: LanConnector): List<ItemState> =
        exchange(peer, localStates, ownCounter, connector, null).states

    /**
     * [sync] with rollback witnesses: with [publish] inline, this device's view is format 2; otherwise, after the
     * format-1 exchange, one `witness` message (this device's witness file, counter [ownCounter]) is sent and the peer's
     * `witness` answer opened. A peer from before 2026-10-29 answers `bad-message`; that, any other answer, and any
     * error of that one request are silent (the views were exchanged already). A refusal of the view itself throws as
     * in [sync] (the caller counts a `bad-view` refusal of a format-2 view).
     */
    fun exchange(
        peer: PinnedPeer,
        localStates: List<ItemState>,
        ownCounter: Long,
        connector: LanConnector,
        publish: LanPublish?,
    ): LanExchange {
        val inline = publish?.inline == true
        val raw = try {
            if (inline) {
                ViewFile.encode(
                    groupKey, identity.deviceId, ownCounter, localStates, clock, random,
                    vaultGeneration = publish!!.vaultGeneration, witness = publish.witness,
                )
            } else {
                ViewFile.encode(groupKey, identity.deviceId, ownCounter, localStates, clock, random)
            }
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
        val (header, states) = receiveView(reply, peer, connector)
        val published = Witness.observation(header)
        if (published != null || publish == null || inline) return LanExchange(states, published)
        return exchangeWitness(peer, connector, ownCounter, publish, states)
    }

    /**
     * After a view exchange, fetches [refs] from [peer] one chunk per request (desktop `lan_sync` `_fetch_blobs`). With
     * no refs and [probe], sends one `blob-get` for the all-zero id to learn whether the peer supports documents. A file
     * that fails its checks is skipped (`attachment-refused`); a peer without a file answers `no-blob`.
     */
    fun fetchBlobs(peer: PinnedPeer, connector: LanConnector, refs: List<AttachmentRef>, probe: Boolean): BlobFetch {
        val out = LinkedHashMap<String, ByteArray>()
        val issues = ArrayList<SyncIssue>()
        var capable: Boolean? = null
        if (refs.isEmpty()) {
            if (!probe) return BlobFetch()
            val r = try {
                blobCall(AttachmentSync.blobGet(AttachmentSync.PROBE_ID), peer, connector)
            } catch (e: AttachmentSyncException) {
                return BlobFetch()
            }
            // Only `no-blob` or a valid chunk marks the peer capable; `bad-message` removes it; anything else: unchanged.
            @Suppress("UNCHECKED_CAST")
            val capableNow = when (r) {
                "no-blob" -> true
                "bad-message" -> false
                is String -> null
                else -> try {
                    AttachmentSync.parseMessage(r as Map<String, JsonValue>) != null
                } catch (e: AttachmentSyncException) {
                    false
                }.let { if (it) true else null }
            }
            return BlobFetch(capable = capableNow)
        }
        for (ref in refs) {
            val dl = AttachmentSync.BlobDownload(ref)
            try {
                while (true) {
                    val r = blobCall(AttachmentSync.blobGet(ref.blob, dl.nextSeq), peer, connector)
                    if (r is String) {
                        if (r == "bad-message") return BlobFetch(out, false, issues)
                        if (r == "no-blob") capable = true
                        break
                    }
                    @Suppress("UNCHECKED_CAST")
                    val whole = dl.add(r as Map<String, JsonValue>)
                    capable = true // a valid chunk
                    if (whole != null) {
                        out[ref.blob] = whole
                        break
                    }
                }
            } catch (e: AttachmentSyncException) {
                issues.add(SyncIssue("attachment-refused", "${ref.attachmentId}: ${e.reason}"))
            }
        }
        return BlobFetch(out, capable, issues)
    }

    /** One `blob-get`: the parsed reply object, or the reason String of an `error` reply. */
    private fun blobCall(message: ByteArray, peer: PinnedPeer, connector: LanConnector): Any {
        val raw = try {
            request(message, peer, connector.connect(peer))
        } catch (e: LanPeerNotAnswering) {
            sleep(retryDelayMillis)
            request(message, peer, connector.connect(peer))
        }
        if (raw.size > LanTransport.MAX_MESSAGE_BYTES) throw AttachmentSyncException("too-large")
        val o = try {
            (CanonicalJson.parse(raw) as? JsonValue.Obj)?.fields
        } catch (e: JsonException) {
            null
        } ?: throw AttachmentSyncException("bad-message")
        if (o["type"] == JsonValue.Str("error")) {
            if (o.keys != setOf("type", "reason")) throw AttachmentSyncException("bad-message")
            return (o["reason"] as? JsonValue.Str)?.v ?: throw AttachmentSyncException("bad-message")
        }
        return o
    }

    /** The `witness` message after a format-1 exchange (desktop `_exchange_witness`). */
    private fun exchangeWitness(
        peer: PinnedPeer,
        connector: LanConnector,
        ownCounter: Long,
        publish: LanPublish,
        states: List<ItemState>,
    ): LanExchange {
        val reply = try {
            val raw = ViewFile.encode(
                groupKey, identity.deviceId, ownCounter, emptyList(), clock, random,
                vaultGeneration = publish.vaultGeneration, witness = publish.witness,
            )
            call(LanMessage.Witness(groupKey.groupId, groupKey.epoch, Base64Std.encode(raw)), peer, connector)
        } catch (e: InterruptedException) {
            throw e
        } catch (e: Exception) {
            return LanExchange(states) // an older peer, a lost connection: silent
        }
        if (reply !is LanMessage.Witness) return LanExchange(states)
        return when (val opened = openWitness(peer.deviceId, reply)) {
            is Observation -> LanExchange(states, opened)
            else -> LanExchange(states, issue = opened as SyncIssue)
        }
    }

    /** The observation of a `witness` message from [peerId], or the issue it raises (desktop `_open_witness`). */
    fun openWitness(peerId: String, m: LanMessage.Witness): Any {
        if (m.groupId != groupKey.groupId) return SyncIssue("group-mismatch", peerId)
        if (m.epoch != groupKey.epoch) return SyncIssue(if (m.epoch > groupKey.epoch) "epoch-behind" else "peer-epoch-behind", peerId)
        val raw = try {
            Base64Std.decodeStrict(m.view)
        } catch (e: Base64Exception) {
            return SyncIssue("bad-peer-data", "$peerId: witness")
        }
        val view = try {
            ViewFile.decode(raw, groupKey, peerId, maxBytes = Witness.MAX_WITNESS_BYTES, maxRecords = 0).first
        } catch (e: SyncFormatException) {
            return SyncIssue(if (e.reason == "device-mismatch") "device-mismatch" else "bad-peer-data", "$peerId: witness ${e.reason}")
        }
        if (view.format != ViewFile.FORMAT_WITNESS) return SyncIssue("bad-peer-data", "$peerId: witness format")
        return Observation(peerId, view.vaultGeneration!!, view.witness)
    }

    private fun receiveView(first: LanMessage, peer: PinnedPeer, connector: LanConnector): Pair<ViewHeader, List<ItemState>> {
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
            return ViewFile.decode(whole, groupKey, peer.deviceId)
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
