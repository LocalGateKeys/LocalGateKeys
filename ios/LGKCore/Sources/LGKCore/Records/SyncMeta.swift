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

    static func nsName(_ wrapper: JSONValue) -> String? {
        if case .object(let w) = wrapper, case .string(let s)? = w["ns"] { return s }
        return nil
    }

    // MARK: local view

    /// Engine states for every stored record and tombstone (desktop `local_view`), plus the updated meta.
    ///
    /// A record whose digest differs from its meta (or that has none) is a local edit: its vector is
    /// bumped once for `device`. An id in meta that is no longer stored becomes a tombstone at `now`
    /// with a bumped vector; licence ids never do (a licence no longer stored just goes quiet).
    /// `skipped` lists stored records that cannot be published (id -> reason); their meta is untouched.
    public static func localView(records: [String: JSONValue], meta: [String: SyncMeta], device: String,
                                 now: Int64) throws -> (states: [String: ItemState], meta: [String: SyncMeta], skipped: [String: String]) {
        try checkCall(device: device, now: now)
        var meta = prune(meta, now: now)
        var states: [String: ItemState] = [:]
        var skipped: [String: String] = [:]
        do {
            for (id, wrapper) in records {
                let isLicense = nsName(wrapper) == Namespace.license.rawValue
                if !Identifier.isValid(id) || Wrapper.isLicenseID(id) != isLicense {
                    skipped[id] = "invalid-id"
                    continue
                }
                var m = meta[id]
                let d: String
                do { d = try digest(wrapper) } catch { skipped[id] = "unencodable"; continue }
                if m == nil || m!.deleted || m!.digest != d {
                    m = try live(wrapper, vv: VersionVector.bump(m?.vv ?? [:], device: device))
                    meta[id] = m
                }
                states[id] = try ItemState(itemID: id, vv: m!.vv, deleted: false, deletedAt: nil, item: wrapper)
            }
            for (id, m) in meta where records[id] == nil {
                if Wrapper.isLicenseID(id) || !Identifier.isValid(id) { continue }
                var t = m
                if !m.deleted {
                    t = tomb(vv: try VersionVector.bump(m.vv, device: device), deletedAt: now)
                    meta[id] = t
                }
                states[id] = try ItemState(itemID: id, vv: t.vv, deleted: true, deletedAt: t.deletedAt, item: nil)
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
    public static func applyRemote(_ outcome: MergeOutcome, records: [String: JSONValue], meta: [String: SyncMeta],
                                   device: String, now: Int64, licenseKeys: [String: [UInt8]]) throws -> ApplyResult {
        try checkCall(device: device, now: now)
        let all = outcome.upserts + outcome.deletes + outcome.copies
        let ids = all.map(\.itemID)
        if Set(ids).count != ids.count { throw RecordError(nil, nil, "Merge outcome names a record more than once") }
        if (outcome.upserts + outcome.copies).contains(where: \.deleted) || !outcome.deletes.allSatisfy(\.deleted) {
            throw RecordError(nil, nil, "Merge outcome is malformed")
        }
        let cutoff = now - tombstoneMaxAgeDays * 86400
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
        deletes.removeAll { stale.contains($0.0.itemID) }
        let liveIDs = ids.filter { !stale.contains($0) }

        var records = records
        var meta = meta
        // Refuse to apply over a local change that the merged view did not include.
        for id in liveIDs where !Wrapper.isLicenseID(id) {
            let m = meta[id], current = records[id]
            let fresh: Bool
            if m == nil || m!.deleted { fresh = current == nil } else { fresh = try current.map { try digest($0) == m!.digest } ?? false }
            if !fresh { throw RecordError("vault-changed", id, "The vault changed since the sync view was taken; sync again") }
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
        for (s, at) in deletes {
            if Wrapper.isLicenseID(s.itemID) {
                // A licence is republished above the tombstone.
                meta[s.itemID] = try live(published[s.itemID]!, vv: VersionVector.bump(s.vv, device: device))
                continue
            }
            if records.removeValue(forKey: s.itemID) != nil { deleted += 1 }
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
                // The state was checked against Wrapper's rules, so its item is the wrapper itself:
                // store it verbatim so it is republished byte for byte.
                let stored = s.item!
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
                let stored = Wrapper.make(ns: ns, record: .object(r))
                records[s.itemID] = stored
                applied += 1
                meta[s.itemID] = try live(stored, vv: s.vv)
            }
        }
        if records.count > maxRecords { throw RecordError(nil, nil, "The vault would hold more records than sync supports") }
        return ApplyResult(records: records, meta: meta, applied: applied, deleted: deleted,
                           conflicts: outcome.conflicts.count, licenses: received)
    }
}
