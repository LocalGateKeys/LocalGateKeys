import Crypto

public struct MergeOutcome: Equatable, Sendable {
    public let upserts: [ItemState]
    public let deletes: [ItemState]
    /// (local, remote) pairs.
    public let conflicts: [(ItemState, ItemState)]
    /// Conflict copies not already held locally or in the remote batch.
    public let copies: [ItemState]

    public init(upserts: [ItemState], deletes: [ItemState], conflicts: [(ItemState, ItemState)], copies: [ItemState]) {
        self.upserts = upserts; self.deletes = deletes; self.conflicts = conflicts; self.copies = copies
    }

    public static func == (l: MergeOutcome, r: MergeOutcome) -> Bool {
        l.upserts == r.upserts && l.deletes == r.deletes && l.copies == r.copies
            && l.conflicts.count == r.conflicts.count
            && zip(l.conflicts, r.conflicts).allSatisfy { $0.0 == $1.0 && $0.1 == $1.1 }
    }
}

/// A peer's states, as decoded from its view.
public struct PeerView: Equatable, Sendable {
    public let deviceID: String
    public let states: [ItemState]
    public init(deviceID: String, states: [ItemState]) { self.deviceID = deviceID; self.states = states }
}

/// A peer record left out of a fold: `reason` is what the record check returned.
public struct FoldQuarantine: Equatable, Sendable {
    public let device: String
    public let item: String
    public let reason: String
    public init(device: String, item: String, reason: String) { self.device = device; self.item = item; self.reason = reason }
}

public struct FoldResult: Equatable, Sendable {
    /// Combined outcome against the original local map (sorted by id within each list).
    public let outcome: MergeOutcome
    /// Peer records removed and reported once each.
    public let quarantined: [FoldQuarantine]
    /// Device ids of views dropped as a whole (`bad-peer-data`; `"?"` for an invalid device id).
    public let badViews: [String]
}

/// Pure version-vector merge engine; mirrors `localvault.sync.engine` and `runner.run_merge`.
public enum Engine {
    static func sha256Hex(_ v: JSONValue) throws -> String {
        lowerHex(SHA256.hash(data: try CanonicalJSON.encode(v, dialect: .utf8)))
    }

    private static func canonical(_ v: JSONValue) -> [UInt8] {
        // ItemState validated that its item encodes.
        (try? CanonicalJSON.encode(v, dialect: .utf8)) ?? []
    }

    private static func identical(_ a: ItemState, _ b: ItemState) -> Bool {
        if a.deleted || b.deleted { return a.deleted && b.deleted }
        return canonical(a.item!) == canonical(b.item!)
    }

    private static func updatedAt(_ item: JSONValue) -> Int64 {
        if case .object(let o) = item, case .int(let n)? = o["updated_at"], (0...VersionVector.maxCounter).contains(n) {
            return n
        }
        return 0
    }

    /// True when `r` outranks `l`: larger updated_at, then larger sha256 hex of the canonical item.
    private static func outranks(_ r: ItemState, _ l: ItemState) throws -> Bool {
        let (ur, ul) = (updatedAt(r.item!), updatedAt(l.item!))
        if ur != ul { return ur > ul }
        return try sha256Hex(r.item!) > sha256Hex(l.item!)
    }

    /// Decide what to apply locally given remote states. Pure and order-independent.
    public static func merge(local: [String: ItemState], remote: [ItemState]) throws -> MergeOutcome {
        for (key, st) in local where st.itemID != key {
            throw EngineError("local state keyed \(key) is inconsistent")
        }
        var seen = Set<String>()
        for r in remote {
            guard seen.insert(r.itemID).inserted else { throw EngineError("duplicate remote item id: \(r.itemID)") }
        }
        var upserts: [ItemState] = [], deletes: [ItemState] = [], copies: [ItemState] = []
        var conflicts: [(ItemState, ItemState)] = []

        // Ids are ASCII, so String ordering equals Python's code point ordering.
        for r in remote.sorted(by: { $0.itemID < $1.itemID }) {
            guard let loc = local[r.itemID] else {
                if r.deleted { deletes.append(r) } else { upserts.append(r) }
                continue
            }
            let rel = try VersionVector.compare(loc.vv, r.vv)
            if rel == .a { continue }
            if rel == .b {
                if r.deleted { deletes.append(r) } else { upserts.append(r) }
                continue
            }
            let merged = VersionVector.max(loc.vv, r.vv)
            if loc.deleted && r.deleted {
                let stamps = [loc.deletedAt, r.deletedAt].compactMap { $0 }
                let at = stamps.max()
                if rel != .equal || at != loc.deletedAt { deletes.append(r.with(vv: merged, deletedAt: at)) }
                continue
            }
            let same = identical(loc, r)
            if rel == .equal && same { continue }
            if same {
                upserts.append(r.with(vv: merged, deletedAt: nil))
            } else if loc.deleted || r.deleted {
                let live = r.deleted ? loc : r
                upserts.append(live.with(vv: merged, deletedAt: nil))
                conflicts.append((loc, r))
            } else {
                let (win, lose) = try outranks(r, loc) ? (r, loc) : (loc, r)
                upserts.append(win.with(vv: merged, deletedAt: nil))
                let cid = try ConflictCopy.id(itemID: r.itemID, contentDigest: ConflictCopy.contentDigest(lose.item!))
                if local[cid] == nil && !seen.contains(cid) {
                    guard case .object(var body) = lose.item! else { throw EngineError("item must be a dict") }
                    body["id"] = .string(cid)
                    copies.append(try ItemState(itemID: cid, vv: lose.vv, deleted: false, deletedAt: nil, item: .object(body)))
                }
                conflicts.append((loc, r))
            }
        }
        return MergeOutcome(upserts: upserts, deletes: deletes, conflicts: conflicts, copies: copies)
    }

    /// Merge peer views one after another into `local`, mirroring desktop `runner.run_merge`.
    ///
    /// Views are merged in device-id order (stable). A conflict copy made earlier in the fold that a
    /// later view carries is replaced by that view's version before it merges. A view the engine
    /// rejects is dropped (`badViews`). `check` plays the vault bridge's role: a non-nil reason for a
    /// changed state quarantines the peer record that caused it (or drops the view when the same
    /// record fails again) and the fold restarts without it. Views from `ownDeviceID` are ignored.
    public static func fold(local: [String: ItemState], views: [PeerView], ownDeviceID: String? = nil,
                            check: (ItemState) -> String? = { _ in nil }) -> FoldResult {
        var bad: [String] = []
        var peers: [PeerView] = []
        for v in views {
            if !Identifier.isValid(v.deviceID) { bad.append("?") }
            else if v.deviceID != ownDeviceID { peers.append(v) }
        }
        peers = peers.enumerated().sorted { ($0.element.deviceID, $0.offset) < ($1.element.deviceID, $1.offset) }.map(\.element)

        var quarantined: [FoldQuarantine] = []
        var seenQuarantine = Set<[String]>()
        while true {
            let (outcome, origin, used) = combine(local, peers, &bad)
            peers = used
            var failing: (ItemState, String)?
            for s in outcome.upserts + outcome.deletes + outcome.copies {
                if let r = check(s) { failing = (s, r); break }
            }
            guard let (state, reason) = failing, let (dev, recordID) = origin[state.itemID] else {
                return FoldResult(outcome: outcome, quarantined: quarantined, badViews: bad)
            }
            var removed = false
            peers = peers.map { v in
                guard v.deviceID == dev else { return v }
                let kept = v.states.filter { $0.itemID != recordID }
                if kept.count != v.states.count { removed = true }
                return PeerView(deviceID: v.deviceID, states: kept)
            }
            if removed && seenQuarantine.insert([dev, recordID]).inserted {
                quarantined.append(FoldQuarantine(device: dev, item: recordID, reason: reason))
            } else {
                bad.append(dev)
                peers.removeAll { $0.deviceID == dev }
            }
        }
    }

    private static func combine(_ local: [String: ItemState], _ views: [PeerView], _ bad: inout [String])
        -> (MergeOutcome, [String: (String, String)], [PeerView]) {
        var working = local
        var pending = Set<String>()
        var origin: [String: (String, String)] = [:]
        var conflicts: [(ItemState, ItemState)] = []
        var used: [PeerView] = []
        for view in views {
            let dev = view.deviceID
            var trial = working, trialPending = pending
            for id in Set(view.states.map(\.itemID)).intersection(trialPending) {
                trial.removeValue(forKey: id)
                trialPending.remove(id)
            }
            let out: MergeOutcome
            var copyCause: [String: String] = [:]
            do {
                out = try merge(local: trial, remote: view.states)
                for (loc, remote) in out.conflicts {
                    for side in [loc, remote] {
                        if let item = side.item {
                            copyCause[try ConflictCopy.id(itemID: remote.itemID,
                                                          contentDigest: ConflictCopy.contentDigest(item))] = remote.itemID
                        }
                    }
                }
            } catch {
                bad.append(dev)
                continue
            }
            for s in out.upserts + out.deletes {
                trial[s.itemID] = s
                trialPending.remove(s.itemID)
                origin[s.itemID] = (dev, s.itemID)
            }
            for s in out.copies {
                trial[s.itemID] = s
                trialPending.insert(s.itemID)
                origin[s.itemID] = (dev, copyCause[s.itemID] ?? s.itemID)
            }
            working = trial; pending = trialPending
            conflicts.append(contentsOf: out.conflicts)
            used.append(view)
        }
        var upserts: [ItemState] = [], deletes: [ItemState] = [], copies: [ItemState] = []
        for id in working.keys.sorted() {
            let s = working[id]!
            if local[id] == s { continue }
            if pending.contains(id) { copies.append(s) } else if s.deleted { deletes.append(s) } else { upserts.append(s) }
        }
        return (MergeOutcome(upserts: upserts, deletes: deletes, conflicts: conflicts, copies: copies), origin, used)
    }
}
