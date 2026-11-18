import Crypto

/// Per-id sync metadata (desktop `payload["sync_meta"]["items"][id]`): what this device last published.
///
/// The phone stores each record as its synced wrapper (`records`: id -> wrapper JSON). A record the phone
/// does not edit is kept exactly as received, so its digest matches its meta and it is republished
/// byte for byte with an unchanged vector.
public struct SyncMeta: Equatable, Sendable {
    /// sha256 hex of the canonical wrapper; nil for a tombstone.
    public var digest: String?
    /// The same without `record.updated_at` and the wrapper rank; nil for a tombstone.
    public var body: String?
    /// The published `record.updated_at` (when it is an int).
    public var updatedAt: Int64?
    public var vv: [String: Int64]
    public var deleted: Bool
    public var deletedAt: Int64?

    public init(digest: String?, body: String?, updatedAt: Int64?, vv: [String: Int64], deleted: Bool, deletedAt: Int64?) {
        self.digest = digest; self.body = body; self.updatedAt = updatedAt
        self.vv = vv; self.deleted = deleted; self.deletedAt = deletedAt
    }

    public static let tombstoneMaxAgeDays: Int64 = 365
    public static let maxSyncLicenses = 16
    static let maxRecords = 20_000

    // MARK: digests

    static func hex(_ v: JSONValue) throws -> String {
        lowerHex(SHA256.hash(data: try CanonicalJSON.encode(v, dialect: .utf8)))
    }

    /// sha256 hex of the canonical JSON of a wrapper (desktop `wrapper_digest`).
    public static func digest(_ wrapper: JSONValue) throws -> String { try hex(wrapper) }

    /// Digest of `{"ns", "record" minus updated_at}` (desktop `_body_digest`).
    public static func bodyDigest(_ wrapper: JSONValue) throws -> String {
        guard case .object(let w) = wrapper, case .object(var r)? = w["record"] else { throw RecordError(nil, nil, "not a wrapper") }
        r["updated_at"] = nil
        return try hex(.object(["ns": w["ns"] ?? .null, "record": .object(r)]))
    }

    public static func live(_ wrapper: JSONValue, vv: [String: Int64]) throws -> SyncMeta {
        var stamp: Int64?
        if case .object(let w) = wrapper, case .object(let r)? = w["record"], case .int(let n)? = r["updated_at"] { stamp = n }
        return SyncMeta(digest: try digest(wrapper), body: try bodyDigest(wrapper), updatedAt: stamp, vv: vv, deleted: false,
                        deletedAt: nil)
    }

    public static func tomb(vv: [String: Int64], deletedAt: Int64) -> SyncMeta {
        SyncMeta(digest: nil, body: nil, updatedAt: nil, vv: vv, deleted: true, deletedAt: deletedAt)
    }

    /// Drops tombstones deleted more than 365 days before `now`.
    public static func prune(_ meta: [String: SyncMeta], now: Int64) -> [String: SyncMeta] {
        let cutoff = now - tombstoneMaxAgeDays * 86400
        return meta.filter { !($0.value.deleted && ($0.value.deletedAt ?? cutoff) < cutoff) }
    }

    static func checkCall(device: String, now: Int64) throws {
        guard Identifier.isValid(device) else { throw RecordError(nil, nil, "Sync device id is malformed") }
        guard (0...VersionVector.maxCounter).contains(now) else { throw RecordError(nil, nil, "Sync clock value is malformed") }
    }

    /// `skipped` reason of a record whose stored vector cannot be bumped (audit M-6).
    public static let counterOverflow = "version counter overflow"

    /// `bump(vv, device)`, or nil when this device's counter would overflow (desktop `_bumped`).
    static func bumped(_ vv: [String: Int64], device: String) throws -> [String: Int64]? {
        if (vv[device] ?? 0) >= VersionVector.maxCounter { return nil }
        return try VersionVector.bump(vv, device: device)
    }

    static func nsName(_ wrapper: JSONValue) -> String? {
        if case .object(let w) = wrapper, case .string(let s)? = w["ns"] { return s }
        return nil
    }

    static func recordOf(_ wrapper: JSONValue?) -> JSONValue? {
        if case .object(let o)? = wrapper { return o["record"] }
        return nil
    }

    /// A stored plan wrapper is published only when it is exactly the synced wrapper of a valid plan.
    static func heirReadable(_ wrapper: JSONValue) -> Bool {
        guard let synced = try? Heir.syncedRecord(recordOf(wrapper)),
              let a = try? digest(Wrapper.make(ns: .heir, record: synced)), let b = try? digest(wrapper) else { return false }
        return a == b
    }

    // MARK: local view

    /// Engine states for every stored record and tombstone (desktop `local_view`), plus the updated meta.
    ///
    /// A record whose digest differs from its meta (or that has none) is a local edit: its vector is
    /// bumped once for `device`. An id in meta that is no longer stored becomes a tombstone at `now`
    /// with a bumped vector; licence ids never do (a licence no longer stored just goes quiet).
    /// `skipped` lists stored records that cannot be published (id -> reason); their meta is untouched.
    ///
    /// Collection states (`CollectionStates.isReserved`) are left out of the loop above. Without `collections` they are
    /// never published or tombstoned, their meta untouched (desktop `local_view(collections=False)`, what every peer
    /// that does not read them gets). With it (every peer of the run reads them) they are added by
    /// `CollectionSync.addStates`; `shares` names the links this device speaks for. Item states are the same either way.
    public static func localView(records: [String: JSONValue], meta: [String: SyncMeta], device: String, now: Int64,
                                 collections: Bool = false, shares: CollectionShares = .none) throws
        -> (states: [String: ItemState], meta: [String: SyncMeta], skipped: [String: String]) {
        try checkCall(device: device, now: now)
        var meta = prune(meta, now: now)
        var states: [String: ItemState] = [:]
        var skipped: [String: String] = [:]
        do {
            for (id, wrapper) in records {
                if CollectionStates.isReserved(id, wrapper) { continue }
                let isLicense = nsName(wrapper) == Namespace.license.rawValue
                let isHeir = nsName(wrapper) == Namespace.heir.rawValue
                if !Identifier.isValid(id) || Wrapper.isLicenseID(id) != isLicense || Wrapper.isHeirID(id) != isHeir {
                    skipped[id] = "invalid-id"
                    continue
                }
                if isHeir && !heirReadable(wrapper) {
                    skipped[id] = "The emergency access plan is damaged" // never published, nor deleted elsewhere
                    continue
                }
                var m = meta[id]
                let d: String
                do { d = try digest(wrapper) } catch { skipped[id] = "unencodable"; continue }
                if m == nil || m!.deleted || m!.digest != d {
                    // A vector stored before the plausibility rule: skip only this record.
                    guard let vv = try bumped(m?.vv ?? [:], device: device) else {
                        skipped[id] = counterOverflow
                        continue
                    }
                    m = try live(wrapper, vv: vv)
                    meta[id] = m
                }
                states[id] = try ItemState(itemID: id, vv: m!.vv, deleted: false, deletedAt: nil, item: wrapper)
            }
            for (id, m) in meta where records[id] == nil {
                if Wrapper.isLicenseID(id) || !Identifier.isValid(id) || CollectionStates.isStateID(id) { continue }
                var t = m
                if !m.deleted {
                    // The delete cannot be recorded without an overflow: publish nothing for it.
                    guard let vv = try bumped(m.vv, device: device) else { continue }
                    t = tomb(vv: vv, deletedAt: now)
                    meta[id] = t
                }
                states[id] = try ItemState(itemID: id, vv: t.vv, deleted: true, deletedAt: t.deletedAt, item: nil)
            }
            if collections {
                meta = try CollectionSync.addStates(records: records, skipped: skipped, meta: meta, states: &states,
                                                    device: device, now: now, shares: shares)
            }
        } catch let e as EngineError {
            throw RecordError(nil, nil, "Vault content cannot be synced: \(e)")
        }
        if meta.count > maxRecords { throw RecordError(nil, nil, "Sync metadata exceeds its bound") }
        return (states, meta, skipped)
    }

    // MARK: apply

    public struct ApplyResult: Equatable, Sendable {
        public let records: [String: JSONValue]
        public let meta: [String: SyncMeta]
        public let applied: Int
        public let deleted: Int
        public let conflicts: Int
        /// Licence bundles received in this apply that verified (stored or already known).
        public let licenses: [JSONValue]
    }

    /// Applies a merge outcome to the stored records (desktop `apply`); pure, so a throw leaves the caller's
    /// store untouched. Remote records are stored exactly as received (never normalised); a conflict copy
    /// gets the copy id and the `" (sync conflict)"` suffix. A remote tombstone's `deleted_at` is capped at
    /// `now`; one older than 365 days is ignored. Licences are verified with `licenseKeys`, only ever added,
    /// and dropped without a word when this build knows no licence keys or as a conflict copy.
    /// Throws `RecordError` `vault-changed` when a record changed since its meta was written, and
    /// `bad-remote` / `update-needed` naming the first remote state that cannot be stored.
    ///
    /// Personal collections (sub-plan 07 Task 5d): collection states (and the engine's conflict copies of them) are
    /// never stored as records. With `collections` they are applied by `CollectionSync.Applier` (catalog rows before
    /// the items, memberships and links after) and are not counted as conflicts; without, they are dropped without a
    /// word. A removed item's membership record goes with it (the host's Recently deleted row keeps its collections).
    /// `shares.readOnly`, in every run: a remote edit or delete of an item in a collection this device holds
    /// read-only is refused and this device's version is republished above it (desktop `_Applier.protected`).
    public static func applyRemote(_ full: MergeOutcome, records: [String: JSONValue], meta: [String: SyncMeta],
                                   device: String, now: Int64, licenseKeys: [String: [UInt8]], collections: Bool = false,
                                   shares: CollectionShares = .none) throws -> ApplyResult {
        try checkCall(device: device, now: now)
        let all = full.upserts + full.deletes + full.copies
        let ids = all.map(\.itemID)
        if Set(ids).count != ids.count { throw RecordError(nil, nil, "Merge outcome names a record more than once") }
        if (full.upserts + full.copies).contains(where: \.deleted) || !full.deletes.allSatisfy(\.deleted) {
            throw RecordError(nil, nil, "Merge outcome is malformed")
        }
        let cutoff = now - tombstoneMaxAgeDays * 86400
        // Collection states are taken out first: they never go through the record paths below.
        let isCol: (ItemState) -> Bool = CollectionSync.isCollectionState
        var colUpserts: [ItemState] = [], colDeletes: [(ItemState, Int64)] = [], colCopies: [ItemState] = []
        if collections {
            colUpserts = full.upserts.filter(isCol)
            for s in full.deletes where CollectionStates.isStateID(s.itemID) {
                let at = min(s.deletedAt ?? now, now)
                if at >= cutoff { colDeletes.append((s, at)) }
            }
            colCopies = full.copies.filter(isCol)
        }
        let conflicts = full.conflicts.filter { !isCol($0.1) }.count
        let outcome = MergeOutcome(upserts: full.upserts.filter { !isCol($0) },
                                   deletes: full.deletes.filter { !CollectionStates.isStateID($0.itemID) },
                                   conflicts: full.conflicts, copies: full.copies.filter { !isCol($0) })
        var deletes: [(ItemState, Int64)] = []
        for s in outcome.deletes {
            let at = min(s.deletedAt ?? now, now)
            if at >= cutoff { deletes.append((s, at)) }
        }
        var stale = Set(outcome.deletes.map(\.itemID)).subtracting(deletes.map(\.0.itemID))
        let published = records.filter { Wrapper.isLicenseID($0.key) && nsName($0.value) == Namespace.license.rawValue }
        for (s, _) in deletes where Wrapper.isLicenseID(s.itemID) && published[s.itemID] == nil { stale.insert(s.itemID) }
        if licenseKeys.isEmpty {
            for s in outcome.upserts where Wrapper.isLicenseID(s.itemID) { stale.insert(s.itemID) }
        }
        for s in outcome.copies where s.item.flatMap(nsName) == Namespace.license.rawValue { stale.insert(s.itemID) }
        // A conflict copy of the emergency access plan is never stored; its refused ids join the local plan.
        let heirCopies = outcome.copies.filter { $0.item.flatMap(nsName) == Namespace.heir.rawValue }
        for s in heirCopies { stale.insert(s.itemID) }
        deletes.removeAll { stale.contains($0.0.itemID) }
        let liveIDs = (outcome.upserts + outcome.deletes + outcome.copies).map(\.itemID).filter { !stale.contains($0) }

        var records = records
        var meta = meta
        // Refuse to apply over a local change that the merged view did not include.
        for id in liveIDs where !Wrapper.isLicenseID(id) {
            let m = meta[id], current = records[id]
            let fresh: Bool
            if m == nil || m!.deleted { fresh = current == nil } else { fresh = try current.map { try digest($0) == m!.digest } ?? false }
            if !fresh { throw RecordError("vault-changed", id, "The vault changed since the sync view was taken; sync again") }
        }
        var col = CollectionSync.Applier(records: records, meta: meta, device: device, now: now, shares: shares)
        // A stored catalog row or membership this device cannot read is left alone (like an unreadable item).
        var colSkipped = Set<String>()
        for s in colUpserts + colDeletes.map(\.0) where CollectionStates.isStateID(s.itemID) {
            if col.unreadable(s.itemID) { colSkipped.insert(s.itemID) } else { try col.checkFresh(s.itemID) }
        }
        var applied = 0, deleted = 0
        var received: [JSONValue] = []
        func blame<T>(_ id: String, _ body: () throws -> T) throws -> T {
            do { return try body() } catch let e as RecordError {
                if e.reason != nil { throw e }
                throw RecordError("bad-remote", id, e.detail)
            } catch {
                throw RecordError("bad-remote", id, "Merge outcome cannot be applied: \(error)")
            }
        }
        let catalogPrefix = CollectionStates.catalogPrefix
        func isCatalog(_ s: ItemState) -> Bool { s.itemID.utf8.starts(with: catalogPrefix.utf8) }
        // Catalog rows first: memberships below may name a new collection.
        for (s, at) in colDeletes where isCatalog(s) && !colSkipped.contains(s.itemID) {
            if try blame(s.itemID, { try col.catalogDelete(s, at: at) }) { applied += 1 }
        }
        for s in colUpserts where isCatalog(s) && !colSkipped.contains(s.itemID) {
            if try blame(s.itemID, { try col.catalogUpsert(s, try CollectionStates.unwrap(s, isCopy: false)) }) { applied += 1 }
        }
        records = col.records
        meta = col.meta
        let readOnly = shares.readOnly
        /// A live item in a collection this device holds read-only: another of this person's devices cannot change it.
        func isProtected(_ id: String) -> Bool {
            guard !readOnly.isEmpty, let w = records[id], !CollectionStates.isReserved(id, w) else { return false }
            return CollectionCatalog.memberships(of: id, records: records).contains { readOnly.contains($0) }
        }
        for (s, at) in deletes {
            if Wrapper.isLicenseID(s.itemID) {
                // A licence is republished above the tombstone; an overflowing bump refuses only this state.
                meta[s.itemID] = try blame(s.itemID) { try live(published[s.itemID]!, vv: VersionVector.bump(s.vv, device: device)) }
                continue
            }
            if isProtected(s.itemID), let mine = records[s.itemID] {
                // In a read-only share on this device: only the owner removes it (through the share).
                meta[s.itemID] = try blame(s.itemID) { try live(mine, vv: VersionVector.bump(s.vv, device: device)) }
                continue
            }
            if records.removeValue(forKey: s.itemID) != nil {
                deleted += 1
                records[CollectionStates.membershipPrefix + s.itemID] = nil   // the trash row keeps its collections
            }
            meta[s.itemID] = tomb(vv: s.vv, deletedAt: at)
        }
        for s in outcome.upserts where !stale.contains(s.itemID) {
            try blame(s.itemID) {
                let (ns, record) = try Wrapper.unwrap(s, isCopy: false, licenseKeys: licenseKeys)
                if ns == .license {
                    let wrapper = Wrapper.make(ns: .license, record: record)
                    if let known = records[s.itemID] {
                        guard case .object(let k) = known,
                              try CanonicalJSON.encode(k["record"] ?? .null, dialect: .utf8) == CanonicalJSON.encode(record, dialect: .utf8) else {
                            throw RecordError(nil, nil, "Licence state differs from the licence stored under that id")
                        }
                    } else {
                        if records.keys.filter(Wrapper.isLicenseID).count >= maxSyncLicenses {
                            throw RecordError(nil, nil, "The vault holds as many synced licences as it keeps")
                        }
                        records[s.itemID] = wrapper
                    }
                    meta[s.itemID] = try live(wrapper, vv: s.vv)
                    received.append(record)
                    return
                }
                if ns == .heir {
                    // The same plan merges with this device's (denies union, stale either side's); a merged result
                    // that differs from the remote is a local edit, so it travels back.
                    let current = records[s.itemID]
                    if let current, nsName(current) != Namespace.heir.rawValue {
                        throw RecordError(nil, nil, "Record id is used by a different kind of record")
                    }
                    let stored: JSONValue
                    do {
                        stored = Wrapper.make(ns: .heir, record: try Heir.mergeSynced(local: recordOf(current), remote: record))
                    } catch is HeirError {
                        throw RecordError("bad-remote", s.itemID, "The emergency access plan cannot be merged")
                    }
                    if try current.map({ try digest($0) }) != digest(stored) { applied += 1 }
                    records[s.itemID] = stored
                    let same = try digest(stored) == digest(s.item!)
                    let vv: [String: Int64]? = same ? s.vv : try bumped(s.vv, device: device)
                    guard let vv else { throw RecordError(nil, nil, counterOverflow) }
                    meta[s.itemID] = try live(stored, vv: vv)
                    return
                }
                // The state was checked against Wrapper's rules, so its item is the wrapper itself:
                // store it verbatim so it is republished byte for byte.
                let stored = s.item!
                if isProtected(s.itemID), let mine = records[s.itemID], try digest(mine) != digest(stored) {
                    // Read-only share: another of this person's devices cannot change it here; this device's copy
                    // (the owner's version) is republished above it.
                    meta[s.itemID] = try live(mine, vv: VersionVector.bump(s.vv, device: device))
                    return
                }
                if let current = records[s.itemID], nsName(current) != ns.rawValue {
                    throw RecordError(nil, nil, "Record id is used by a different kind of record")
                }
                if try records[s.itemID].map({ try digest($0) }) != digest(stored) { applied += 1 }
                records[s.itemID] = stored
                meta[s.itemID] = try live(stored, vv: s.vv)
            }
        }
        for s in outcome.copies where !stale.contains(s.itemID) && records[s.itemID] == nil {
            try blame(s.itemID) {
                let (ns, record) = try Wrapper.unwrap(s, isCopy: true, licenseKeys: licenseKeys)
                guard case .object(var r) = record else { throw RecordError(nil, nil, "malformed copy") }
                let field = ns == .entry ? "label" : "title"
                if case .string(let t)? = r[field] { r[field] = .string(ConflictSuffix.apply(t, limit: ConflictSuffix.limit)) }
                var stored = Wrapper.make(ns: ns, record: .object(r))
                // A document's copy keeps its file reference (the same file, a second item).
                if case .object(let src)? = s.item, let attachment = src["attachment"], case .object(var w) = stored {
                    w["attachment"] = attachment
                    stored = .object(w)
                }
                records[s.itemID] = stored
                applied += 1
                meta[s.itemID] = try live(stored, vv: s.vv)
            }
        }
        for s in heirCopies {
            try blame(s.itemID) {
                let (_, record) = try Wrapper.unwrap(s, isCopy: true, licenseKeys: licenseKeys)
                let local = records[Heir.stateID]
                let localRecord = recordOf(local)
                var samePlan = false
                if case .object(let l)? = localRecord, case .object(let r) = record { samePlan = l["plan_id"] == r["plan_id"] }
                if let local, nsName(local) == Namespace.heir.rawValue, samePlan,
                   let merged = try? Heir.mergeSynced(local: localRecord, remote: record) {
                    // The next local view publishes the union as an edit; a copy that re-keys the plan is ignored.
                    records[Heir.stateID] = Wrapper.make(ns: .heir, record: merged)
                }
            }
        }
        if collections {
            col.records = records
            col.meta = meta
            let membershipPrefix = CollectionStates.membershipPrefix, linkPrefix = CollectionStates.linkPrefix
            for (s, at) in colDeletes where !colSkipped.contains(s.itemID) {
                if s.itemID.utf8.starts(with: membershipPrefix.utf8) {
                    if try blame(s.itemID, { try col.membershipDelete(s, at: at) }) { applied += 1 }
                } else if s.itemID.utf8.starts(with: linkPrefix.utf8) {
                    if try blame(s.itemID, { try col.linkDelete(s, at: at) }) { applied += 1 }
                }
            }
            for s in colUpserts where CollectionStates.isStateID(s.itemID) && !isCatalog(s) && !colSkipped.contains(s.itemID) {
                let changed = try blame(s.itemID) { () throws -> Bool in
                    let record = try CollectionStates.unwrap(s, isCopy: false)
                    if record["kind"] == .string("membership") { return try col.membershipUpsert(s, record) }
                    return try col.linkUpsert(s, record)
                }
                if changed { applied += 1 }
            }
            for s in colCopies {
                // Two devices changed one membership at once: this device keeps both (a union), never a copy. A losing
                // catalog row or link is dropped (the winner was applied).
                let changed = try blame(s.itemID) { () throws -> Bool in
                    let record = try CollectionStates.unwrap(s, isCopy: true)
                    guard record["kind"] == .string("membership") else { return false }
                    return try col.membershipUpsert(s, record, union: true)
                }
                if changed { applied += 1 }
            }
            records = col.records
            meta = col.meta
        }
        // The cap counts items and entries; collection states never push past it (they wait, `Applier.room`).
        if records.lazy.filter({ !CollectionStates.isReserved($0.key, $0.value) }).count > maxRecords {
            throw RecordError(nil, nil, "The vault would hold more records than sync supports")
        }
        return ApplyResult(records: records, meta: meta, applied: applied, deleted: deleted,
                           conflicts: conflicts, licenses: received)
    }
}
