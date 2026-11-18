package app.localgatekeys.core.lan

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.SyncFormatException
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.License
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.recovery.Heir
import app.localgatekeys.core.sync.AttachmentRef
import app.localgatekeys.core.sync.AttachmentSync
import app.localgatekeys.core.sync.AttachmentVault
import app.localgatekeys.core.sync.CollectionShares
import app.localgatekeys.core.sync.Documents
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.Observation
import app.localgatekeys.core.sync.PeerSeenAt
import app.localgatekeys.core.sync.RunReport
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import app.localgatekeys.core.sync.SyncIssue
import app.localgatekeys.core.sync.SyncRunner
import app.localgatekeys.core.sync.Witness
import app.localgatekeys.core.sync.WitnessMemory

/**
 * The host responder of LAN sync for a store (Swift `LanResponder`: desktop `transport._handle_inbound` for a session
 * hello plus `lan_sync.LanResponder.__call__` / `_serve`), serving the peers listed in [SyncGroupState.lanPeers].
 * Transport-agnostic: the listener hands it the first frame payload ([accept]), sends the hello it returns, then hands
 * it the sealed request ([respond]) and sends the sealed answer. A thrown exception means: close without an answer
 * (an unauthenticated peer gets no error text). Enrollment frames (`LGKENROLL1`) are not handled here
 * ([LanPeers.verifyEnrollment]).
 *
 * Thread-safe: requests are served one at a time under a lock (chunk buffers and store commits).
 */
class LanHostService(
    private val store: ItemStore,
    private val installId: String,
    private val counters: HelloCounterSource,
    private val random: RandomSource,
    private val clock: UnixClock,
    private val licenseKeys: Map<String, ByteArray> = emptyMap(),
    /** The unlock session's in-memory peer generations, shared with the initiator (the coordinator). */
    val witnessMemory: WitnessMemory = WitnessMemory(),
    /** This device's attachment files; null: documents are neither served nor applied. */
    private val attachments: AttachmentVault? = null,
    /**
     * Licence-only mode (a free host, desktop licence-only sync): of a peer's view only licence states (`lic:` ids) are
     * merged, and this device answers with a view of no states (it publishes nothing).
     */
    private val licenceOnly: () -> Boolean = { false },
    /** Personal collections (sub-plan 07): answers `features` and carries collection states with listed peers. */
    private val collections: Boolean = false,
    /** This device's share records, read from the very snapshot a merge uses. */
    private val collectionShares: (StoreSnapshot) -> CollectionShares = { CollectionShares.NONE },
) {
    sealed interface Opening {
        /** A hello of another protocol version (or a pinned peer's clear-text hello): send this payload, then close. */
        class Refuse(val payload: ByteArray) : Opening

        /** A listed peer: send [Connection.helloPayload], then read the request. */
        class Accepted(val connection: Connection) : Opening
    }

    /** One authenticated inbound connection after the hello exchange (one request, one response). */
    class Connection internal constructor(
        val peer: LanPeer,
        helloPayload: ByteArray,
        internal val channel: SecureChannel,
        /** The initiator sent a sealed version-3 hello: once its request opens, the peer is pinned to it. */
        val sealed: Boolean,
    ) {
        private val hello = helloPayload.copyOf()
        val helloPayload: ByteArray get() = hello.copyOf()
        internal var used = false

        override fun toString(): String = "Connection(peer=${peer.deviceId}, sealed=$sealed)"
    }

    private val lock = Any()
    private val sealedPeers = HashSet<String>()
    private val inbox = LanInbox()
    private val serving = LinkedHashMap<String, Pair<String, ByteArray>>()
    private var liveBlobs: Pair<Long, Map<String, AttachmentRef>>? = null
    private var report: RunReport? = null

    /** Peers that sent a `blob-get` in this unlock session (they read documents). */
    private val blobReaders = HashSet<String>()

    /** The report of the last request that merged or refused a view (desktop `last_report`). */
    val lastReport: RunReport? get() = synchronized(lock) { report }

    /** The last report, cleared: each served merge or refusal is reported once. */
    fun takeReport(): RunReport? = synchronized(lock) { report.also { report = null } }

    /** Transfers buffered in each direction (tests and diagnostics). */
    val bufferedTransfers: Pair<Int, Int> get() = synchronized(lock) { inbox.incomingCount to inbox.outgoingCount }

    /** Whether [deviceId] is pinned to the sealed hello in this responder's memory. */
    fun isSealed(deviceId: String): Boolean = synchronized(sealedPeers) { deviceId in sealedPeers }

    // ---- handshake --------------------------------------------------------------------------

    /**
     * The first frame payload of a connection (LAN protocol version 3, `docs/formats/LAN_SYNC_V3.md` 2.3). A sealed
     * version-3 hello is opened with this device's exchange key and answered with this device's sealed hello. A
     * clear-text version-2 hello is answered in clear text only for a peer not pinned to the sealed hello; a pinned
     * peer's verified clear-text hello gets the version refusal. A signed hello of any other version gets the version
     * refusal. A hello of a device that is not a listed, unrevoked peer of this group, a bad signature, unpinned keys or
     * a counter that did not increase throw.
     */
    fun accept(payload: ByteArray): Opening {
        if (payload.size > LanTransport.MAX_FIRST_FRAME_BYTES) throw LanTransportException(LanTransportException.Kind.MALFORMED, "first frame too large")
        val announced = SessionHello.otherVersion(payload)
        if (announced != null && announced != LanTransport.VERSION) return Opening.Refuse(LanTransport.versionRefusal())
        val state = store.load().sync
            ?: throw LanTransportException(LanTransportException.Kind.AUTHENTICATION, "A protected paired-device state is required")
        var seal: SealContext? = null
        try {
            val remote = if (announced == null) {
                SessionHello.parse(payload)
            } else {
                val opened = SealedHello.openInitiator(payload, state.identity)
                seal = opened.second
                opened.first
            }
            if (state.installId != installId) {
                throw LanTransportException(LanTransportException.Kind.AUTHENTICATION, "The sync state belongs to another install")
            }
            val peer = LanPeers.entry(state, remote.deviceId)
            if (peer == null || peer.deviceId == state.deviceId) {
                throw LanTransportException(LanTransportException.Kind.AUTHENTICATION, "Peer is not explicitly paired")
            }
            if (peer.revoked) throw LanTransportException(LanTransportException.Kind.AUTHENTICATION, "Peer device has been revoked")
            val pinned = peer.pinned
            SessionHello.verify(remote, pinned, state.groupId)
            counters.acceptInbound(remote.counter, peer.deviceId)
            if (seal == null && (peer.sealed || isSealed(peer.deviceId))) {
                // Downgrade: this peer has used the sealed hello, so its clear-text hello is refused (only after it
                // verified, so the answer tells nothing to anyone else).
                return Opening.Refuse(LanTransport.versionRefusal())
            }
            val local = SessionHello.make(state.identity, state.groupId, remote.sessionId, counters.nextCounter(), random, remote.version)
            try {
                val answer = seal?.let { SealedHello.sealResponder(local, it) } ?: local.toBytes()
                val channel = SecureChannel(
                    state.identity, pinned, state.groupId, remote.sessionId, SecureChannel.Role.RESPONDER, local, remote,
                )
                return Opening.Accepted(Connection(peer, answer, channel, seal != null))
            } finally {
                local.ephemeralSecret?.wipe()
            }
        } finally {
            seal?.wipe()
        }
    }

    /**
     * The sealed request frame (length prefix included) of [connection] -> the sealed answer frame. A connection that
     * came with a sealed hello pins its peer once the request opened (in memory, and `"hello":3` in its entry).
     */
    fun respond(connection: Connection, requestFrame: ByteArray): ByteArray {
        if (connection.used) throw LanTransportException(LanTransportException.Kind.MALFORMED, "one request per connection")
        connection.used = true
        val request = connection.channel.open(requestFrame)
        if (connection.sealed) pinSealed(connection.peer)
        return connection.channel.seal(serve(connection.peer, request))
    }

    private fun pinSealed(peer: LanPeer) {
        synchronized(sealedPeers) { sealedPeers.add(peer.deviceId) }
        if (!peer.sealed) LanPeers.pinSealed(peer.deviceId, store)
    }

    // ---- serving ----------------------------------------------------------------------------

    /**
     * One authenticated request from [peer] (plaintext in, plaintext out): `view` chunks are acknowledged but the last,
     * which is merged ([SyncRunner]) and committed, and answered with the first chunk of this device's view; `next`
     * hands out the rest. Refusals are `error` messages ([LanMessages.errorReasons]).
     */
    fun serve(peer: LanPeer, request: ByteArray): ByteArray = synchronized(lock) {
        val (reply, run) = serveLocked(peer, request)
        if (run != null) report = run
        reply
    }

    private fun encode(m: LanMessage): ByteArray = LanMessages.encode(m)

    private fun fail(reason: String, issue: SyncIssue? = null): Pair<ByteArray, RunReport?> =
        encode(LanMessage.Error(reason)) to issue?.let { RunReport(issues = listOf(it)) }

    private fun detail(e: Throwable): String = e.message ?: e.javaClass.simpleName

    /** Message types this host answers that [LanMessages.parse] does not read. */
    private sealed interface Extra {
        class BlobGet(val blob: String, val seq: Int) : Extra
        object HeirHello : Extra
    }

    /** A `blob-get` or `heir-hello` message, else null (left to [LanMessages.parse]). Throws `bad-message`/`too-large`. */
    private fun extra(request: ByteArray): Extra? {
        if (request.size > LanTransport.MAX_MESSAGE_BYTES) return null
        val o = try {
            (CanonicalJson.parse(request) as? JsonValue.Obj)?.fields
        } catch (e: JsonException) {
            null
        } ?: return null
        return when ((o["type"] as? JsonValue.Str)?.v) {
            "blob-get" -> {
                try {
                    AttachmentSync.parseMessage(o)
                } catch (e: Exception) {
                    throw LanSyncException("bad-message")
                }
                Extra.BlobGet((o["blob"] as JsonValue.Str).v, (o["seq"] as JsonValue.Int).v.toInt())
            }
            LanClient.HEIR_HELLO -> if (o.keys == setOf("type")) Extra.HeirHello else throw LanSyncException("bad-message")
            else -> null
        }
    }

    private fun serveLocked(peer: LanPeer, request: ByteArray): Pair<ByteArray, RunReport?> {
        val now = clock.now
        inbox.expire(now)
        val extra: Extra?
        val msg: LanMessage?
        try {
            extra = extra(request)
            msg = if (extra == null) LanMessages.parse(request) else null
        } catch (e: LanSyncException) {
            return fail(e.reason)
        } catch (e: Exception) {
            return fail("bad-message")
        }
        val snapshot = try {
            store.load()
        } catch (e: Exception) {
            return fail("local-data", SyncIssue("local-data", detail(e)))
        }
        val state = snapshot.sync ?: return fail("not-joined")
        if (state.installId != installId) return fail("rejoin-required", SyncIssue("rejoin-required", "install-mismatch"))
        val entry = LanPeers.entry(state, peer.deviceId)
        if (entry?.revoked == true) return fail("revoked", SyncIssue("peer-revoked", peer.deviceId))
        if (entry == null || !entry.signingPublic.contentEquals(peer.signingPublic) ||
            !entry.exchangePublic.contentEquals(peer.exchangePublic) || entry.groupId != peer.groupId || peer.revoked ||
            peer.groupId != state.groupId
        ) {
            return fail("unknown-peer", SyncIssue("unknown-peer", peer.deviceId))
        }
        val restricted = licenceOnly()
        when (extra) {
            is Extra.BlobGet -> return if (restricted) fail("no-blob") else serveBlob(snapshot, state, peer.deviceId, extra.blob, extra.seq, now) to null
            Extra.HeirHello -> {
                if (restricted) return fail("bad-message")
                // Desktop `_serve`: the initiator reads the emergency access plan, so it gets it in views from now on.
                setHeirPeer(peer.deviceId)
                return CanonicalJson.encode(JsonValue.Obj(mapOf("type" to JsonValue.Str(LanClient.HEIR_HELLO))), Dialect.ASCII) to null
            }
            null -> {}
        }
        val view: LanMessage.View = when (msg) {
            is LanMessage.Next -> return encode(inbox.next(peer.deviceId, msg.transfer, msg.seq)) to null
            is LanMessage.Witness -> {
                if (restricted) return fail("bad-message")
                return serveWitness(state, peer.deviceId, msg, now)
            }
            is LanMessage.Features -> {
                if (restricted || !collections) return fail("bad-message") // what an older app answers
                if (LanFeatures.setPeer(peer.deviceId, LanFeatures.readsCollections(msg.features), store) == null) {
                    return fail("local-data", SyncIssue("local-data", "collection peers could not be saved"))
                }
                return encode(LanMessage.Features(LanFeatures.OURS)) to null
            }
            is LanMessage.View -> msg
            else -> return fail("bad-message")
        }
        if (view.groupId != state.groupId) return fail("group-mismatch", SyncIssue("group-mismatch", peer.deviceId))
        if (view.epoch < state.epoch) return fail("epoch-behind", SyncIssue("peer-epoch-behind", peer.deviceId))
        if (view.epoch > state.epoch) return fail("peer-epoch-behind", SyncIssue("epoch-behind", peer.deviceId))
        val raw = try {
            inbox.receive(peer.deviceId, view.transfer, view.seq, view.total, view.size, view.view, now)
                ?: return encode(LanMessage.Ack(view.transfer, view.seq)) to null
        } catch (e: LanSyncException) {
            return fail(e.reason)
        } catch (e: Exception) {
            return fail("bad-chunk")
        }
        val gk = try {
            GroupKey(state.groupId, state.epoch, state.key)
        } catch (e: Exception) {
            return fail("local-data", SyncIssue("local-data", detail(e)))
        }
        val decoded = try {
            ViewFile.decode(raw, gk, peer.deviceId)
        } catch (e: SyncFormatException) {
            return if (e.reason == "device-mismatch") {
                fail("device-mismatch", SyncIssue("device-mismatch", "${peer.deviceId}: ${e.reason}"))
            } else {
                fail("bad-view", SyncIssue("bad-peer-data", "${peer.deviceId}: ${e.reason}"))
            }
        } catch (e: Exception) {
            return fail("bad-view", SyncIssue("bad-peer-data", "${peer.deviceId}: ${detail(e)}"))
        }
        val header = decoded.first
        // Licence-only: everything but licence states is dropped before the merge, so nothing else is stored.
        val states = if (restricted) decoded.second.filter { it.itemId.startsWith(License.ID_PREFIX) } else decoded.second
        // The same merge as the initiator (SyncCoordinator.lanRun): fold, then one commit when anything changed.
        val withCollections = collections && !restricted && peer.deviceId in state.collectionPeers
        val shares = try {
            collectionShares(snapshot)
        } catch (e: Exception) {
            return fail("local-data", SyncIssue("local-data", detail(e)))
        }
        val vault = attachments
        val present: ((AttachmentRef) -> Boolean)? = vault?.let { v -> { ref: AttachmentRef -> v.has(ref) } }
        var run = SyncRunner.run(
            snapshot, listOf(PeerView(peer.deviceId, states)), state.deviceId, now, licenseKeys, documents = present,
            collections = withCollections, shares = shares,
        )
        val allOwn = run.ownStates ?: return encode(LanMessage.Error("local-data")) to run
        // Documents only to a peer that asked for a blob (older builds refuse them).
        val documents = vault != null && (peer.deviceId in state.attachmentPeers || synchronized(blobReaders) { peer.deviceId in blobReaders })
        val own: List<ItemState> = if (restricted) emptyList() else Heir.publishable(Documents.publishable(allOwn, documents), peer.deviceId in state.heirPeers)
        val records = run.records ?: snapshot.records
        val meta = run.meta ?: snapshot.meta
        if (records != snapshot.records || meta != snapshot.meta) {
            try {
                store.commit(StoreChange(snapshot.revision, records, meta, snapshot.sync?.syncedWith(listOf(peer.deviceId), now)))
            } catch (e: Exception) {
                run = run.copy(issues = run.issues + SyncIssue("busy", detail(e)))
                return encode(LanMessage.Error("local-data")) to run
            }
        }
        PeerSeenAt.note(state.groupId, peer.deviceId, now) // synced now, even with no changes
        // Rollback witnesses: a format-2 request is checked, and answered in format 2 (never to a format-1 request).
        val inline = header.format == ViewFile.FORMAT_WITNESS && !restricted // a free host keeps no witnesses
        if (!restricted) {
            Witness.observation(header)?.let { obs -> run = run.copy(issues = run.issues + applyWitness(listOf(obs), now)) }
        }
        var generation: Long? = null
        var witness: Map<String, Long>? = null
        if (inline) {
            try {
                val latest = store.load()
                val latestState = latest.sync
                val g = Witness.generation(latest)
                if (latestState != null && g != null) {
                    generation = g
                    witness = publishedWitness(latestState)
                }
            } catch (_: Exception) {
            }
        }
        // This device's view: the stored own counter as is (LAN never checks view counters; nothing is reserved).
        val mine = try {
            if (generation != null) {
                ViewFile.encode(gk, state.deviceId, state.ownCounter, own, FixedNow(now), random, vaultGeneration = generation, witness = witness)
            } else {
                ViewFile.encode(gk, state.deviceId, state.ownCounter, own, FixedNow(now), random)
            }
        } catch (e: Exception) {
            run = run.copy(issues = run.issues + SyncIssue("too-large", detail(e)))
            return encode(LanMessage.Error("too-large")) to run
        }
        val parts = LanMessages.splitView(mine)
        if (mine.size > LanMessages.MAX_VIEW_BYTES || parts.size.toLong() > LanMessages.MAX_CHUNKS || parts.isEmpty()) {
            run = run.copy(issues = run.issues + SyncIssue("too-large", "view exceeds the LAN bound"))
            return encode(LanMessage.Error("too-large")) to run
        }
        val transfer = Hex.lower(random.bytes(16))
        val size = mine.size.toLong()
        inbox.store(if (parts.size > 1) LanInbox.Outgoing(transfer, parts, size, gk, now) else null, peer.deviceId)
        run = run.copy(wrote = true)
        return encode(LanInbox.viewMessage(gk, transfer, 0, parts, size)) to run
    }

    /** What this device publishes as its witness (Swift `Witness.publishedWitness`). */
    private fun publishedWitness(state: SyncGroupState): Map<String, Long> =
        Witness.ownWitness(witnessMemory.merged(state), Witness.witnessIds(state), state.deviceId)

    /** Swift `Witness.apply(store:observations:memory:)`: check, then commit when worth a save. */
    private fun applyWitness(observations: List<Observation>, now: Long): List<SyncIssue> = try {
        val snap = store.load()
        val state = snap.sync
        val generation = Witness.generation(snap)
        if (state == null || generation == null) {
            emptyList()
        } else {
            val (issues, changed) = Witness.applyLan(state, generation, observations, witnessMemory, emptyList(), now)
            if (changed != null) {
                try {
                    store.commit(StoreChange(snap.revision, snap.records, snap.meta, changed))
                    witnessMemory.markSaved(changed.peerGenerations.keys, now)
                } catch (_: Exception) {
                    // kept in memory; the run's flush saves it
                }
            }
            issues
        }
    } catch (e: Exception) {
        emptyList()
    }

    /**
     * A `witness` message after a format-1 exchange (desktop `_serve_witness`): check it, answer with this device's own
     * witness file.
     */
    private fun serveWitness(state: SyncGroupState, peerId: String, m: LanMessage.Witness, now: Long): Pair<ByteArray, RunReport?> {
        fun report(issues: List<SyncIssue>): RunReport? = if (issues.isEmpty()) null else RunReport(issues = issues)
        val gk = try {
            GroupKey(state.groupId, state.epoch, state.key)
        } catch (e: Exception) {
            return fail("local-data")
        }
        val obs: Observation = when (val opened = openWitness(gk, peerId, m)) {
            is Observation -> opened
            is SyncIssue -> {
                val reasons = mapOf(
                    "group-mismatch" to "group-mismatch", "device-mismatch" to "device-mismatch",
                    "epoch-behind" to "peer-epoch-behind", "peer-epoch-behind" to "epoch-behind",
                )
                return encode(LanMessage.Error(reasons[opened.kind] ?: "bad-view")) to report(listOf(opened))
            }
            else -> return fail("bad-view")
        }
        val issues = applyWitness(listOf(obs), now)
        val raw: ByteArray
        val latestState: SyncGroupState
        try {
            val latest = store.load()
            latestState = latest.sync ?: return encode(LanMessage.Error("local-data")) to report(issues)
            val generation = Witness.generation(latest) ?: return encode(LanMessage.Error("local-data")) to report(issues)
            raw = ViewFile.encode(
                GroupKey(latestState.groupId, latestState.epoch, latestState.key), latestState.deviceId, latestState.ownCounter,
                emptyList(), FixedNow(now), random, vaultGeneration = generation, witness = publishedWitness(latestState),
            )
        } catch (e: Exception) {
            return encode(LanMessage.Error("local-data")) to report(issues)
        }
        return encode(LanMessage.Witness(latestState.groupId, latestState.epoch, Base64Std.encode(raw))) to report(issues)
    }

    /** The observation of a `witness` message from [peerId], or the issue it raises (desktop `_open_witness`). */
    private fun openWitness(gk: GroupKey, peerId: String, m: LanMessage.Witness): Any {
        if (m.groupId != gk.groupId) return SyncIssue("group-mismatch", peerId)
        if (m.epoch != gk.epoch) return SyncIssue(if (m.epoch > gk.epoch) "epoch-behind" else "peer-epoch-behind", peerId)
        val raw = try {
            Base64Std.decodeStrict(m.view)
        } catch (e: Base64Exception) {
            return SyncIssue("bad-peer-data", "$peerId: witness")
        }
        val view = try {
            ViewFile.decode(raw, gk, peerId, maxBytes = Witness.MAX_WITNESS_BYTES, maxRecords = 0).first
        } catch (e: SyncFormatException) {
            return SyncIssue(if (e.reason == "device-mismatch") "device-mismatch" else "bad-peer-data", "$peerId: witness ${e.reason}")
        }
        if (view.format != ViewFile.FORMAT_WITNESS) return SyncIssue("bad-peer-data", "$peerId: witness format")
        return Observation(peerId, view.vaultGeneration!!, view.witness)
    }

    /**
     * A `blob-get` (desktop `_serve_blob`): one chunk of the blob of one of this device's own live documents, else
     * `no-blob`. Any `blob-get` marks the peer as reading documents.
     */
    private fun serveBlob(snapshot: StoreSnapshot, state: SyncGroupState, peerId: String, blobId: String, seq: Int, now: Long): ByteArray {
        synchronized(blobReaders) { blobReaders.add(peerId) }
        val vault = attachments
        if (vault != null && peerId !in state.attachmentPeers) setAttachmentPeer(peerId)
        val noBlob = encode(LanMessage.Error("no-blob"))
        if (vault == null) return noBlob
        var cached = serving[peerId]
        if (cached == null || cached.first != blobId || seq == 0) {
            serving.remove(peerId)
            // The refs of the live documents, recomputed only when the store changed.
            if (liveBlobs?.first != snapshot.revision) {
                val refs = try {
                    Documents.refs(SyncMeta.localView(snapshot.records, snapshot.meta, state.deviceId, now).states.values)
                } catch (e: Exception) {
                    emptyList()
                }
                liveBlobs = snapshot.revision to refs.associateBy { it.blob }
            }
            val ref = liveBlobs?.second?.get(blobId)
            if (blobId == AttachmentSync.PROBE_ID || ref == null) return noBlob
            val blob = try {
                vault.blob(ref)
            } catch (e: Exception) {
                null
            } ?: return noBlob
            cached = blobId to blob
            serving[peerId] = cached
            while (serving.size > 8) {
                val first = serving.keys.firstOrNull { it != peerId } ?: break
                serving.remove(first)
            }
        }
        val reply = try {
            AttachmentSync.blobChunk(cached.second, seq)
        } catch (e: Exception) {
            serving.remove(peerId)
            return encode(LanMessage.Error("bad-chunk"))
        }
        val total = (cached.second.size + AttachmentSync.CHUNK_BYTES - 1) / AttachmentSync.CHUNK_BYTES
        if (seq == total - 1) serving.remove(peerId)
        return reply
    }

    /** Desktop `attachment_peers`: [peerId] reads documents (persisted; a failed save is retried next `blob-get`). */
    private fun setAttachmentPeer(peerId: String) {
        try {
            val snap = store.load()
            val state = snap.sync ?: return
            if (peerId in state.attachmentPeers || !Identifier.isValid(peerId)) return
            store.commit(StoreChange(snap.revision, snap.records, snap.meta, state.copy(attachmentPeers = (state.attachmentPeers + peerId).sorted())))
        } catch (_: Exception) {
        }
    }

    /** Swift `Heir.setPeer`: [peerId] reads the emergency access plan (at most 64 listed). */
    private fun setHeirPeer(peerId: String) {
        try {
            val snap = store.load()
            val state = snap.sync ?: return
            if (peerId in state.heirPeers || state.heirPeers.size >= 64 || !Identifier.isValid(peerId)) return
            store.commit(StoreChange(snap.revision, snap.records, snap.meta, state.copy(heirPeers = (state.heirPeers + peerId).sorted())))
        } catch (_: Exception) {
        }
    }

    override fun toString(): String = "LanHostService"

    private class FixedNow(override val now: Long) : UnixClock
}
