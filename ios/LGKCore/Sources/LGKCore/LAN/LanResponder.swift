import Foundation

/// One authenticated inbound connection after the hello exchange: the pinned peer it belongs to and
/// the responder side of its channel (one request, one response).
public struct LanResponderConnection: Sendable {
    public let peer: LanPeer
    /// The responder's hello, framed: send it before reading the request.
    public let helloFrame: [UInt8]
    var channel: SecureChannel
}

/// The responder of LAN sync (desktop `transport._handle_inbound` for a session hello plus
/// `lan_sync.LanResponder.__call__` / `_serve`). Transport-agnostic: the listener hands it the first
/// frame (`accept`), sends the hello it returns, then hands it the sealed request (`respond`) and sends
/// the sealed answer. A thrown error means: close without an answer (the desktop sends no
/// unauthenticated error). Enrollment frames (`LGKENROLL1`) are not handled here (`LanPeers.verifyEnrollment`).
///
/// Thread-safe: requests are served one at a time under a lock (chunk buffers and store commits).
public final class LanResponder: @unchecked Sendable {
    public enum Opening: Sendable {
        /// A hello of another protocol version: send this frame (the version refusal), then close.
        case refuse([UInt8])
        /// A pinned peer: send `connection.helloFrame`, then read the request.
        case accepted(LanResponderConnection)
    }

    let store: any ItemStore
    let installID: String
    let counters: HelloCounterSource
    let random: any RandomSource
    let clock: any UnixClock
    let licenseKeys: [String: [UInt8]]
    /// The unlock session's in-memory peer generations, shared with the initiator (`SyncDependencies`).
    public let witnessMemory: WitnessMemory
    /// This device's own attachment files (attachment sync); nil: documents are neither served nor applied.
    let blobs: (any AttachmentBlobStore)?
    /// Peers that sent a `blob-get` (they read documents), shared with the initiator.
    public let attachmentPeers: AttachmentPeerMemory
    /// Licence-only mode (a free Mac host, desktop licence-only sync): of a peer's view only licence states
    /// (`lic:` ids) are merged, and this device answers with a view of no states (it publishes nothing).
    let licenceOnly: @Sendable () -> Bool
    private let lock = NSLock()
    var inbox = LanInbox()   // internal for tests (guarded by `lock`)
    /// The blob being served to each peer (desktop `inbox.blobs`), so later chunks do not re-read the file.
    private var serving: [String: (id: String, blob: [UInt8])] = [:]
    /// Live document blob ids at a store revision (guarded by `lock`).
    private var liveBlobs: (revision: Int64, ids: Set<String>)?
    private var report: RunReport?

    public init(store: any ItemStore, installID: String, counters: HelloCounterSource, random: any RandomSource,
                clock: any UnixClock, licenseKeys: [String: [UInt8]] = [:], witnessMemory: WitnessMemory = WitnessMemory(),
                blobs: (any AttachmentBlobStore)? = nil, attachmentPeers: AttachmentPeerMemory = AttachmentPeerMemory(),
                licenceOnly: @escaping @Sendable () -> Bool = { false }) {
        self.store = store; self.installID = installID; self.counters = counters
        self.random = random; self.clock = clock; self.licenseKeys = licenseKeys
        self.witnessMemory = witnessMemory
        self.blobs = blobs; self.attachmentPeers = attachmentPeers
        self.licenceOnly = licenceOnly
    }

    /// The report of the last request that merged or refused a view (desktop `last_report`).
    public var lastReport: RunReport? { lock.withLock { report } }
    /// The last report, cleared: each served merge or refusal is reported once (a host's sync run collects
    /// what peers did since the previous run without repeating it). `lastReport` is unchanged.
    public func takeReport() -> RunReport? { lock.withLock { defer { report = nil }; return report } }
    /// Transfers buffered in each direction (tests and diagnostics).
    public var bufferedTransfers: (incoming: Int, outgoing: Int) { lock.withLock { (inbox.incomingCount, inbox.outgoingCount) } }

    // MARK: handshake

    /// The first frame of a connection (4-byte length prefix included). A signed hello of another version
    /// gets the version refusal; a hello of a device that is not a listed, unrevoked peer of this group,
    /// a bad signature, unpinned keys or a counter that did not increase throw. Otherwise the counter is
    /// saved (`HelloCounterSource.acceptInbound`) and this device's hello (same session id, a new counter,
    /// a fresh ephemeral key) derives the responder channel.
    public func accept(helloFrame frame: [UInt8]) throws -> Opening {
        let payload = try LanTransport.decodeFrame(frame)
        if SessionHello.otherVersion(payload) != nil {
            return .refuse(try LanTransport.encodeFrame(try LanTransport.versionRefusal()))
        }
        let remote = try SessionHello.parse(payload)
        guard let state = try store.load().sync else { throw LanTransportError.authentication("A protected paired-device state is required") }
        guard state.installID == installID else { throw LanTransportError.authentication("The sync state belongs to another install") }
        guard let peer = LanPeers.entry(state, remote.deviceID), peer.deviceID != state.deviceID else {
            throw LanTransportError.authentication("Peer is not explicitly paired")
        }
        guard !peer.revoked else { throw LanTransportError.authentication("Peer device has been revoked") }
        let pinned = peer.pinned
        try SessionHello.verify(remote, pinned: pinned, groupID: state.groupID)
        try counters.acceptInbound(remote.counter, peer: peer.deviceID)
        let local = try SessionHello.make(identity: state.identity, groupID: state.groupID, sessionID: remote.sessionID,
                                          counter: try counters.nextCounter(), random: RandomBox(random))
        defer { local.ephemeralSecret?.wipe() }
        let channel = try SecureChannel(local: state.identity, remote: pinned, groupID: state.groupID, sessionID: remote.sessionID,
                                        role: .responder, localHello: local, remoteHello: remote)
        return .accepted(LanResponderConnection(peer: peer, helloFrame: try LanTransport.encodeFrame(try local.toBytes()), channel: channel))
    }

    /// The sealed request of `connection` -> the sealed answer frame.
    public func respond(_ connection: inout LanResponderConnection, requestFrame: [UInt8]) throws -> [UInt8] {
        let request = try connection.channel.open(requestFrame)
        return try connection.channel.seal(serve(peer: connection.peer, request: request))
    }

    // MARK: serving

    static func viewMessage(_ gk: GroupKey, transfer: String, seq: Int, parts: [[UInt8]], size: Int64) -> LanMessage {
        .view(groupID: gk.groupID, epoch: gk.epoch, transfer: transfer, seq: Int64(seq), total: Int64(parts.count),
              size: size, view: Base64.encode(parts[seq]))
    }

    /// One authenticated request from `peer` (plaintext in, plaintext out): `view` chunks are acknowledged
    /// but the last, which is merged (`SyncRunner`) and committed, and answered with the first chunk of this
    /// device's view; `next` hands out the rest. Refusals are `error` messages (`LanMessages.errorReasons`).
    public func serve(peer: LanPeer, request: [UInt8]) -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        let (reply, run) = serveLocked(peer: peer, request: request)
        if let run { report = run }
        // Every message here encodes (strings are ASCII-safe JSON); the fallback is never expected.
        return (try? LanMessages.encode(reply)) ?? Array(#"{"reason":"local-data","type":"error"}"#.utf8)
    }

    private func serveLocked(peer: LanPeer, request: [UInt8]) -> (LanMessage, RunReport?) {
        func fail(_ reason: String, _ issue: SyncIssue? = nil) -> (LanMessage, RunReport?) {
            var r: RunReport?
            if let issue { r = RunReport(); r?.issues = [issue] }
            return (.error(reason: reason), r)
        }
        let now = clock.now
        inbox.expire(now: now)
        let msg: LanMessage
        do { msg = try LanMessages.parse(request) } catch let e as LanSyncError { return fail(e.reason) } catch { return fail("bad-message") }
        let snapshot: StoreSnapshot
        do { snapshot = try store.load() } catch { return fail("local-data", SyncIssue("local-data", "\(error)")) }
        guard let state = snapshot.sync else { return fail("not-joined") }
        guard state.installID == installID else { return fail("rejoin-required", SyncIssue("rejoin-required", "install-mismatch")) }
        let entry = LanPeers.entry(state, peer.deviceID)
        if entry?.revoked == true { return fail("revoked", SyncIssue("peer-revoked", peer.deviceID)) }
        guard let entry, entry.signingPublic == peer.signingPublic, entry.exchangePublic == peer.exchangePublic,
              entry.groupID == peer.groupID, !peer.revoked, peer.groupID == state.groupID else {
            return fail("unknown-peer", SyncIssue("unknown-peer", peer.deviceID))
        }
        let view: (groupID: String, epoch: Int64, transfer: String, seq: Int64, total: Int64, size: Int64, text: String)
        switch msg {
        case let .next(transfer, seq): return (inbox.next(peer: peer.deviceID, transfer: transfer, seq: seq), nil)
        case .witness where licenceOnly(): return fail("bad-message")
        case let .witness(g, e, v): return serveWitness(state: state, peerID: peer.deviceID, groupID: g, epoch: e, view: v, now: now)
        case .blobGet where licenceOnly(): return (.error(reason: "no-blob"), nil)
        case let .blobGet(blob, seq): return (serveBlob(snapshot: snapshot, peerID: peer.deviceID, blobID: blob, seq: seq), nil)
        case let .view(g, e, t, s, tot, sz, v): view = (g, e, t, s, tot, sz, v)
        default: return fail("bad-message")
        }
        guard view.groupID == state.groupID else { return fail("group-mismatch", SyncIssue("group-mismatch", peer.deviceID)) }
        if view.epoch < state.epoch { return fail("epoch-behind", SyncIssue("peer-epoch-behind", peer.deviceID)) }
        if view.epoch > state.epoch { return fail("peer-epoch-behind", SyncIssue("epoch-behind", peer.deviceID)) }
        let raw: [UInt8]
        do {
            guard let whole = try inbox.receive(peer: peer.deviceID, transfer: view.transfer, seq: view.seq, total: view.total,
                                                size: view.size, view: view.text, now: now) else {
                return (.ack(transfer: view.transfer, seq: view.seq), nil)
            }
            raw = whole
        } catch let e as LanSyncError { return fail(e.reason) } catch { return fail("bad-chunk") }
        let gk: GroupKey
        do { gk = try state.groupKey() } catch { return fail("local-data", SyncIssue("local-data", "\(error)")) }
        let decoded: (header: ViewHeader, states: [ItemState])
        do { decoded = try ViewFile.decode(raw, key: gk, expectedDeviceID: peer.deviceID) } catch {
            let reason = (error as? SyncFormatError)?.reason ?? "\(error)"
            return reason == "device-mismatch"
                ? fail("device-mismatch", SyncIssue("device-mismatch", "\(peer.deviceID): \(reason)"))
                : fail("bad-view", SyncIssue("bad-peer-data", "\(peer.deviceID): \(reason)"))
        }
        let header = decoded.header
        // Licence-only: everything but licence states is dropped before the merge, so nothing else is stored.
        let restricted = licenceOnly()
        let states = restricted ? decoded.states.filter { $0.itemID.hasPrefix(License.idPrefix) } : decoded.states
        // The same merge as the initiator (SyncCoordinator.runLAN): fold, then one commit when anything changed.
        var run = SyncRunner.run(store: snapshot, views: [PeerView(deviceID: peer.deviceID, states: states)],
                                 device: state.deviceID, now: now, licenseKeys: licenseKeys, blobs: blobs)
        guard let allOwn = run.ownStates else { return (.error(reason: "local-data"), run) }
        // Documents only to a peer that asked for a blob this session (older builds refuse them).
        let own = restricted ? [] : AttachmentDocuments.publishable(allOwn, documents: blobs != nil
            && (state.attachmentPeers.contains(peer.deviceID) || attachmentPeers.contains(peer.deviceID)))
        let records = run.records ?? snapshot.records, meta = run.meta ?? snapshot.meta
        if records != snapshot.records || meta != snapshot.meta {
            do {
                try store.commit(StoreChange(baseRevision: snapshot.revision, records: records, meta: meta, sync: snapshot.sync?.synced(with: [peer.deviceID], now: now)))
            } catch {
                run.issues.append(SyncIssue("busy", "\(error)"))
                return (.error(reason: "local-data"), run)
            }
        }
        // Rollback witnesses: a format-2 request is checked, and answered in format 2 (never to a format-1 request).
        let inline = header.format == ViewFile.formatWitness && !restricted  // a free host keeps no witnesses
        if !restricted, let obs = Witness.observation(header) {
            run.issues += Witness.apply(store: store, observations: [obs], memory: witnessMemory)
        }
        var generation: Int64?
        var witness: [String: Int64]?
        if inline, let latest = try? store.load(), let latestState = latest.sync, let g = Witness.generation(latest) {
            generation = g
            witness = Witness.publishedWitness(latestState, memory: witnessMemory)
        }
        // This device's view: the stored own counter as is (LAN never checks view counters; nothing is reserved).
        let mine: [UInt8]
        do {
            mine = try ViewFile.encode(key: gk, deviceID: state.deviceID, counter: state.ownCounter, states: own,
                                       now: ClockValue(now: now), random: RandomBox(random),
                                       vaultGeneration: generation, witness: witness)
        } catch {
            run.issues.append(SyncIssue("too-large", "\(error)"))
            return (.error(reason: "too-large"), run)
        }
        let parts = LanMessages.splitView(mine)
        guard mine.count <= LanMessages.maxViewBytes, Int64(parts.count) <= LanMessages.maxChunks, !parts.isEmpty else {
            run.issues.append(SyncIssue("too-large", "view exceeds the LAN bound"))
            return (.error(reason: "too-large"), run)
        }
        let transfer = lowerHex(random.bytes(count: 16))
        let size = Int64(mine.count)
        inbox.store(parts.count > 1 ? LanInbox.Outgoing(transfer: transfer, parts: parts, size: size, groupKey: gk, started: now) : nil,
                    peer: peer.deviceID)
        run.wrote = true
        return (Self.viewMessage(gk, transfer: transfer, seq: 0, parts: parts, size: size), run)
    }

    /// A `blob-get` (desktop `_serve_blob`): one chunk of the blob of one of this device's own live documents,
    /// else `no-blob`. Any `blob-get` marks the peer as reading documents.
    private func serveBlob(snapshot: StoreSnapshot, peerID: String, blobID: String, seq: Int64) -> LanMessage {
        attachmentPeers.set(peerID, capable: true)
        if blobs != nil, snapshot.sync?.attachmentPeers.contains(peerID) == false {
            AttachmentDocuments.setPeer(peerID, capable: true, store: store)   // persisted (desktop `attachment_peers`)
        }
        let noBlob = LanMessage.error(reason: "no-blob")
        guard let blobs else { return noBlob }
        var cached = serving[peerID]
        if cached == nil || cached?.id != blobID || seq == 0 {
            serving[peerID] = nil
            // The blob ids of the live documents, recomputed only when the store changed (never a whole view).
            if liveBlobs?.revision != snapshot.revision {
                liveBlobs = (snapshot.revision, Set(AttachmentDocuments.storedRefs(snapshot).map(\.blob)))
            }
            guard blobID != AttachmentSync.probeBlob, liveBlobs?.ids.contains(blobID) == true,
                  let blob = blobs.read(blobID) else { return noBlob }
            cached = (blobID, blob)
            serving[peerID] = cached
            while serving.count > 8, let first = serving.keys.first(where: { $0 != peerID }) { serving[first] = nil }
        }
        guard let current = cached, let reply = try? AttachmentSync.chunk(current.blob, seq: Int(seq)) else {
            serving[peerID] = nil
            return .error(reason: "bad-chunk")
        }
        if case let .blob(_, s, total, _, _) = reply, s == total - 1 { serving[peerID] = nil }
        return reply
    }

    /// A `witness` message after a format-1 exchange (desktop `_serve_witness`): check it, answer with this
    /// device's own witness file.
    private func serveWitness(state: SyncGroupState, peerID: String, groupID: String, epoch: Int64, view: String,
                              now: Int64) -> (LanMessage, RunReport?) {
        func report(_ issues: [SyncIssue]) -> RunReport? {
            guard !issues.isEmpty else { return nil }
            var r = RunReport(); r.issues = issues
            return r
        }
        let obs: WitnessObservation
        switch Witness.openLanWitness(state, peerID: peerID, groupID: groupID, epoch: epoch, view: view) {
        case .success(let o): obs = o
        case .failure(let refusal):
            let reasons = ["group-mismatch": "group-mismatch", "device-mismatch": "device-mismatch",
                           "epoch-behind": "peer-epoch-behind", "peer-epoch-behind": "epoch-behind"]
            return (.error(reason: reasons[refusal.issue.kind] ?? "bad-view"), report([refusal.issue]))
        }
        let issues = Witness.apply(store: store, observations: [obs], memory: witnessMemory)
        guard let latest = try? store.load(), let latestState = latest.sync,
              let raw = try? Witness.lanWitnessFile(latest, memory: witnessMemory, now: ClockValue(now: now),
                                                     random: RandomBox(random)) else {
            return (.error(reason: "local-data"), report(issues))
        }
        return (.witness(groupID: latestState.groupID, epoch: latestState.epoch, view: Base64.encode(raw)), report(issues))
    }
}

private struct ClockValue: UnixClock { let now: Int64 }

private struct RandomBox: RandomSource {
    let base: any RandomSource
    init(_ b: any RandomSource) { base = b }
    func bytes(count: Int) -> [UInt8] { base.bytes(count: count) }
}
