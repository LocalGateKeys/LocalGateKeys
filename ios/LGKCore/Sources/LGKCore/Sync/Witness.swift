import Foundation

/// One peer's published generation and witness, from a format-2 view, a witness file or a LAN `witness`
/// message (desktop `witness.Observation`).
public struct WitnessObservation: Equatable, Sendable {
    public let peerID: String
    public let vaultGeneration: Int64
    public let witness: [String: Int64]

    public init(peerID: String, vaultGeneration: Int64, witness: [String: Int64] = [:]) {
        self.peerID = peerID; self.vaultGeneration = vaultGeneration; self.witness = witness
    }
}

/// What `Witness.check` found (desktop `witness.WitnessResult`).
public struct WitnessResult: Equatable, Sendable {
    public var issues: [SyncIssue]
    public var peerGenerations: [String: Int64]
    public var rollbackSuspected: Int64
    /// Peer ids that showed format-2 support in this check.
    public var capable: Set<String>
}

/// Rollback detection through sync peers (desktop `sync/witness.py`, plan 2026-10-22 Part B, update 2026-10-29).
///
/// Every device publishes its vault generation and, for each peer, the highest generation it has seen from that
/// peer (its witness). A device restored from an old copy publishes a lower generation than before; the peers
/// that were not restored notice (`peer-vault-rollback`), and their witness of it is higher than its own
/// generation, so it notices too (`vault-rollback`). The rules here are pure; the transports carry the values
/// (format-2 views, witness files, the LAN `witness` message).
///
/// * A peer generation below the remembered one gives `peer-vault-rollback` (detail: the peer id); the remembered
///   value is never lowered.
/// * A peer's `witness[ownID]` above `ownGeneration` raises `rollbackSuspected` to that value, unless it is more
///   than `maxWitnessJump` above (`witness-implausible`, never stored: a forged 2**53-1 cannot make it sticky).
/// * `rollbackSuspected` is sticky: while it is non-zero every run reports `vault-rollback` (no detail). Only the
///   user's "This was me" (`acknowledgeRollback`, after re-authentication) clears it; nothing does it on its own.
/// * A view without a generation (format 1 and no matching witness) is not checked: nothing is reported.
public enum Witness {
    public static let maxGeneration: Int64 = (1 << 53) - 1
    /// A witness of this vault more than this far above its own generation is ignored (`witness-implausible`).
    public static let maxWitnessJump: Int64 = 10_000
    /// Largest witness file (folder `witness/` and the LAN `witness` message).
    public static let maxWitnessBytes = 16 * 1024
    /// A peer's risen generation is saved at most this often during an unlock session (desktop
    /// `witness_memory.SAVE_INTERVAL_SECONDS`).
    public static let saveIntervalSeconds: Double = 600
    /// Consecutive `bad-view` refusals of a format-2 view that drop a peer's format-2 support.
    public static let formatRefusalsToDrop = 2

    /// A generation as a header value (0..2**53-1).
    public static func clamp(_ generation: Int64) -> Int64 { max(0, min(generation, maxGeneration)) }

    /// This vault's generation (plan B5): the committed store revision plus the state's `generationOffset`.
    /// Nil when the store is not in a sync group.
    public static func generation(_ snapshot: StoreSnapshot) -> Int64? {
        guard let state = snapshot.sync else { return nil }
        let (sum, overflow) = snapshot.revision.addingReportingOverflow(state.generationOffset)
        return clamp(overflow ? Int64.max : sum)
    }

    /// What a view publishes (desktop `observation`): its own format-2 header, else the matching witness file,
    /// else nil. A witness file counts only when it is format 2, holds no records, and names the same group,
    /// device, epoch and counter as the format-1 view.
    public static func observation(_ header: ViewHeader,
                                   witnessFile: (header: ViewHeader, records: Int)? = nil) -> WitnessObservation? {
        if header.format == ViewFile.formatWitness, let g = header.vaultGeneration {
            return WitnessObservation(peerID: header.deviceID, vaultGeneration: g, witness: header.witness)
        }
        guard let file = witnessFile, file.header.format == ViewFile.formatWitness, file.records == 0,
              let g = file.header.vaultGeneration else { return nil }
        let w = file.header
        guard w.groupID == header.groupID, w.deviceID == header.deviceID, w.epoch == header.epoch,
              w.counter == header.counter else { return nil }
        return WitnessObservation(peerID: header.deviceID, vaultGeneration: g, witness: w.witness)
    }

    /// Applies the rules above; returns the issues and the updated state (desktop `check`).
    public static func check(ownID: String, ownGeneration: Int64, observations: [WitnessObservation],
                             peerGenerations: [String: Int64], rollbackSuspected: Int64) -> WitnessResult {
        var remembered = peerGenerations
        var suspected = rollbackSuspected
        var issues: [SyncIssue] = []
        var capable = Set<String>()
        for obs in observations where obs.peerID != ownID {
            capable.insert(obs.peerID)
            if let last = remembered[obs.peerID], obs.vaultGeneration < last {
                issues.append(SyncIssue("peer-vault-rollback", obs.peerID))
            } else {
                remembered[obs.peerID] = obs.vaultGeneration
            }
            if let seen = obs.witness[ownID] {
                let (limit, overflow) = ownGeneration.addingReportingOverflow(maxWitnessJump)
                if !overflow && seen > limit {
                    issues.append(SyncIssue("witness-implausible", obs.peerID))
                } else if seen > ownGeneration {
                    suspected = max(suspected, seen)
                }
            }
        }
        if suspected > 0 { issues.append(SyncIssue("vault-rollback")) }
        return WitnessResult(issues: issues, peerGenerations: remembered, rollbackSuspected: suspected, capable: capable)
    }

    /// The witness this device publishes: remembered generations of `members` only (never its own), at most 64.
    public static func ownWitness(_ peerGenerations: [String: Int64], members: Set<String>, ownID: String) -> [String: Int64] {
        let keep = members.filter { $0 != ownID && Identifier.isValid($0) }
        return prune(peerGenerations.mapValues(clamp), keep: keep)
    }

    /// `peerGenerations` limited to the ids in `keep`, at most 64 entries (lowest ids first).
    public static func prune(_ peerGenerations: [String: Int64], keep: Set<String>) -> [String: Int64] {
        let kept = peerGenerations.filter { keep.contains($0.key) }.sorted { $0.key < $1.key }.prefix(ViewFile.maxWitness)
        return Dictionary(uniqueKeysWithValues: kept.map { ($0.key, $0.value) })
    }

    /// `ids` limited to `keep`, sorted, without duplicates, at most 64.
    public static func prune(ids: some Sequence<String>, keep: Set<String>) -> [String] {
        Array(Set(ids).filter { keep.contains($0) }.sorted().prefix(ViewFile.maxWitness))
    }

    /// Peers whose generations this device keeps and publishes (desktop `_witness_ids`): keyring members, LAN
    /// peers and `extra` (the iPhone's paired PC lives in the Keychain, not in the state), never itself.
    public static func witnessIDs(_ state: SyncGroupState, extra: Set<String> = []) -> Set<String> {
        var ids = Set(state.members).union(state.lanPeers.map(\.deviceID)).union(extra)
        ids.remove(state.deviceID)
        return ids
    }

    // MARK: store operations (desktop `vault_bridge.acknowledge_vault_rollback` / `forget_peer_generation`)

    /// The user confirmed (after re-authenticating) that this vault was restored on purpose (`vault-rollback`).
    ///
    /// Raises `generationOffset` so the generation is above every value a peer witnessed (`rollbackSuspected + 1`)
    /// and clears `rollbackSuspected` in the same commit, so the next published generation is above the witnesses
    /// and the warning stops. Returns false (and writes nothing) when nothing was suspected. Never called on its
    /// own: there is no automatic acknowledgement after a restore.
    @discardableResult
    public static func acknowledgeRollback(store: any ItemStore) throws -> Bool {
        let snapshot = try store.load()
        guard var state = snapshot.sync, state.rollbackSuspected > 0 else { return false }
        let target = min(state.rollbackSuspected, maxGeneration - 1) + 1
        let current = generation(snapshot) ?? 0
        if target > current {
            let (offset, overflow) = state.generationOffset.addingReportingOverflow(target - current)
            state.generationOffset = overflow ? Int64.max : offset
        }
        state.rollbackSuspected = 0
        try store.commit(StoreChange(baseRevision: snapshot.revision, records: snapshot.records, meta: snapshot.meta,
                                     sync: state))
        return true
    }

    /// The user dismissed `peer-vault-rollback` for `peerID`: its older copy is accepted from now on. Drops the
    /// remembered generation (stored and in memory). Returns whether one was dropped.
    @discardableResult
    public static func forgetPeerGeneration(store: any ItemStore, peerID: String, memory: WitnessMemory? = nil) throws -> Bool {
        let snapshot = try store.load()
        guard var state = snapshot.sync else { return false }
        memory?.forget(peerID, groupID: state.groupID, deviceID: state.deviceID)
        guard state.peerGenerations[peerID] != nil else { return false }
        state.peerGenerations[peerID] = nil
        try store.commit(StoreChange(baseRevision: snapshot.revision, records: snapshot.records, meta: snapshot.meta,
                                     sync: state))
        return true
    }

    // MARK: LAN (desktop `lan_sync.apply_witness`, `flush_witness`, `witness_file`, `_open_witness`)

    /// Checks `observations` against this vault and commits the witness state when it matters: a new peer, a
    /// change of `witnessPeers` or `rollbackSuspected`, or a risen generation of a peer not saved in the last
    /// `saveIntervalSeconds` (a LAN exchange otherwise saves nothing). The check uses the session's in-memory
    /// generations, never a stale stored value. `dropCapable` removes that peer from `witnessPeers`.
    public static func apply(store: any ItemStore, observations: [WitnessObservation], memory: WitnessMemory,
                             extra: Set<String> = [], dropCapable: String? = nil) -> [SyncIssue] {
        guard let snapshot = try? store.load(), let state = snapshot.sync, let own = generation(snapshot) else { return [] }
        let known = memory.merged(state.peerGenerations, groupID: state.groupID, deviceID: state.deviceID)
        let checked = check(ownID: state.deviceID, ownGeneration: own, observations: observations,
                            peerGenerations: known, rollbackSuspected: state.rollbackSuspected)
        let keep = witnessIDs(state, extra: extra)
        let generations = prune(checked.peerGenerations, keep: keep)
        var capable = Set(state.witnessPeers).union(checked.capable)
        if let dropCapable { capable.remove(dropCapable) }
        let capableIDs = prune(ids: capable, keep: keep)
        let stored = state.peerGenerations
        let now = memory.now()
        memory.setGenerations(generations, groupID: state.groupID, deviceID: state.deviceID)
        let risen = generations.filter { d, g in stored[d].map { g > $0 } ?? false }.map(\.key)
        let due = risen.contains { memory.secondsSinceSave($0, now: now) >= saveIntervalSeconds }
        let worth = checked.rollbackSuspected != state.rollbackSuspected || capableIDs != state.witnessPeers.sorted()
            || generations.keys.contains { stored[$0] == nil } || (!risen.isEmpty && due)
        if worth {
            var newState = state
            newState.peerGenerations = generations
            newState.rollbackSuspected = checked.rollbackSuspected
            newState.witnessPeers = capableIDs
            if (try? store.commit(StoreChange(baseRevision: snapshot.revision, records: snapshot.records,
                                              meta: snapshot.meta, sync: newState))) != nil {
                memory.markSaved(Array(generations.keys), now: now)
            }
        }
        return checked.issues
    }

    /// Commits the session's in-memory peer generations that are above the stored ones (desktop
    /// `flush_witness`). Called at the end of every sync run, so a lock loses at most one run's rises.
    @discardableResult
    public static func flush(store: any ItemStore, memory: WitnessMemory, extra: Set<String> = []) -> Bool {
        guard let snapshot = try? store.load(), var state = snapshot.sync else { return false }
        let merged = memory.merged(state.peerGenerations, groupID: state.groupID, deviceID: state.deviceID)
        let generations = prune(merged, keep: witnessIDs(state, extra: extra))
        guard generations != state.peerGenerations else { return false }
        state.peerGenerations = generations
        guard (try? store.commit(StoreChange(baseRevision: snapshot.revision, records: snapshot.records,
                                             meta: snapshot.meta, sync: state))) != nil else { return false }
        memory.markSaved(Array(generations.keys), now: memory.now())
        return true
    }

    /// This device's witness file for a LAN exchange (counter = the stored own counter; LAN never checks
    /// counters), or nil when the store has no generation.
    public static func lanWitnessFile(_ snapshot: StoreSnapshot, memory: WitnessMemory, extra: Set<String> = [],
                                      now: some UnixClock, random: some RandomSource) throws -> [UInt8]? {
        guard let state = snapshot.sync, let own = generation(snapshot) else { return nil }
        return try ViewFile.encode(key: try state.groupKey(), deviceID: state.deviceID, counter: state.ownCounter,
                                   states: [], now: now, random: random, vaultGeneration: own,
                                   witness: publishedWitness(state, memory: memory, extra: extra))
    }

    /// The witness this device publishes now: stored generations raised to the in-memory ones.
    public static func publishedWitness(_ state: SyncGroupState, memory: WitnessMemory, extra: Set<String> = []) -> [String: Int64] {
        ownWitness(memory.merged(state.peerGenerations, groupID: state.groupID, deviceID: state.deviceID),
                   members: witnessIDs(state, extra: extra), ownID: state.deviceID)
    }

    /// The observation of a LAN `witness` message from `peerID`, or the issue it raises (desktop `_open_witness`).
    public static func openLanWitness(_ state: SyncGroupState, peerID: String, groupID: String, epoch: Int64,
                                      view: String) -> Result<WitnessObservation, LanWitnessRefusal> {
        if groupID != state.groupID { return .failure(LanWitnessRefusal(SyncIssue("group-mismatch", peerID))) }
        if epoch != state.epoch {
            return .failure(LanWitnessRefusal(SyncIssue(epoch > state.epoch ? "epoch-behind" : "peer-epoch-behind", peerID)))
        }
        guard let raw = try? Base64.decodeStrict(view) else {
            return .failure(LanWitnessRefusal(SyncIssue("bad-peer-data", "\(peerID): witness")))
        }
        let decoded: (header: ViewHeader, states: [ItemState])
        do {
            decoded = try ViewFile.decode(raw, key: try state.groupKey(), expectedDeviceID: peerID,
                                          maxBytes: maxWitnessBytes, maxRecords: 0)
        } catch {
            let reason = (error as? SyncFormatError)?.reason ?? "\(error)"
            let kind = reason == "device-mismatch" ? "device-mismatch" : "bad-peer-data"
            return .failure(LanWitnessRefusal(SyncIssue(kind, "\(peerID): witness \(reason)")))
        }
        guard decoded.header.format == ViewFile.formatWitness, let g = decoded.header.vaultGeneration else {
            return .failure(LanWitnessRefusal(SyncIssue("bad-peer-data", "\(peerID): witness format")))
        }
        return .success(WitnessObservation(peerID: peerID, vaultGeneration: g, witness: decoded.header.witness))
    }
}

/// Why a LAN `witness` message was not accepted (the issue to report).
public struct LanWitnessRefusal: Error, Equatable, Sendable {
    public let issue: SyncIssue
    public init(_ issue: SyncIssue) { self.issue = issue }
}

/// In-memory witness state for one unlock session (desktop `witness_memory`, 2026-10-29 review fix).
///
/// A LAN exchange must not commit the store on every request, so the stored `peerGenerations` can lag behind
/// what this device has already checked. The highest generation checked from each peer is kept here for the
/// session and is what every check and every published witness uses; the stored value catches up when
/// `Witness.apply` commits (a new peer, capability or suspicion, or a rise at most once per
/// `Witness.saveIntervalSeconds` per peer), when a folder run commits its state, and in `Witness.flush` at the
/// end of every run. Bound to the group and device id it was filled for: another group or device starts empty.
/// Thread-safe. Create one per unlock (the coordinator's dependencies) and share it between initiator and responder.
public final class WitnessMemory: @unchecked Sendable {
    private let lock = NSLock()
    private var groupID = ""
    private var deviceID = ""
    private var generations: [String: Int64] = [:]
    private var savedAt: [String: Double] = [:]
    private var refusals: [String: Int] = [:]
    /// Monotonic seconds (tests replace it).
    public let now: @Sendable () -> Double

    public init(now: @escaping @Sendable () -> Double = { ProcessInfo.processInfo.systemUptime }) { self.now = now }

    /// Under the lock: start empty when the group or device changed.
    private func bind(_ group: String, _ device: String) {
        if group != groupID || device != deviceID {
            groupID = group; deviceID = device
            generations = [:]; savedAt = [:]; refusals = [:]
        }
    }

    /// `stored` raised to the remembered generations (never lowered).
    public func merged(_ stored: [String: Int64], groupID: String, deviceID: String) -> [String: Int64] {
        lock.withLock {
            bind(groupID, deviceID)
            var out = stored
            for (d, g) in generations where g > (out[d] ?? -1) { out[d] = g }
            return out
        }
    }

    /// The remembered generations become `values` (already merged and pruned by the caller).
    public func setGenerations(_ values: [String: Int64], groupID: String, deviceID: String) {
        lock.withLock { bind(groupID, deviceID); generations = values }
    }

    func forget(_ peer: String, groupID: String, deviceID: String) {
        lock.withLock { bind(groupID, deviceID); generations[peer] = nil }
    }

    func secondsSinceSave(_ peer: String, now: Double) -> Double {
        lock.withLock { savedAt[peer].map { now - $0 } ?? .infinity }
    }

    func markSaved(_ peers: [String], now: Double) {
        lock.withLock { for p in peers { savedAt[p] = now } }
    }

    /// One more `bad-view` refusal of a format-2 view by `peer`; returns the consecutive count.
    public func noteRefusal(_ peer: String, groupID: String, deviceID: String) -> Int {
        lock.withLock {
            bind(groupID, deviceID)
            let n = (refusals[peer] ?? 0) + 1
            refusals[peer] = n
            return n
        }
    }

    /// A format-2 exchange went through (or the peer was dropped): the refusal count starts again.
    public func clearRefusals(_ peer: String) { lock.withLock { refusals[peer] = nil } }
}
