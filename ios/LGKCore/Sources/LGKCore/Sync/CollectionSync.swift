/// What this device's share records say for personal collection sync (sub-plan 07 Task 5d; desktop
/// `share_group.share_links` and `read_only_collection_ids`). Only a mode and a role per collection ever reach the
/// personal group: never a group id, key, keyring, member, folder or owner key.
public struct CollectionShares: Equatable, Sendable {
    /// What a `csl:` share link says: `read`/`edit` and this device's role, `owner`/`member`.
    public struct Link: Equatable, Sendable {
        public let mode: String
        public let role: String
        public init(mode: String, role: String) { self.mode = mode; self.role = role }
    }

    /// Collections shared on this device: this device speaks for their `csl:` link, and a catalog tombstone from
    /// another device never deletes them here (their row is republished). nil: the share store could not be read; then
    /// no link is published, tombstoned or replaced and no catalog tombstone is applied (they wait).
    public var links: [String: Link]?
    /// Collections this device holds as a member of a read-only share (`ShareAccess.readOnlyCollectionIDs`, which fails
    /// closed): another of this person's devices never edits, deletes, moves or renames them here; this device's copy
    /// is republished above the change. Applies in every personal run, with or without collections.
    public var readOnly: Set<String>

    public init(links: [String: Link]? = [:], readOnly: Set<String> = []) { self.links = links; self.readOnly = readOnly }

    /// No share on this device (every device before share sync, desktop `share_links` == {}).
    public static let none = CollectionShares()
}

/// Personal collection sync (sub-plan 07 Task 5d; desktop `vault_bridge` "Personal collections", `_collection_view`,
/// `_collection_states` and `_Collections`; module docs of `CollectionStates`). The store holds the `col:`/`cm:`/`csl:`
/// states as records (`CollectionCatalog`), so:
///
/// - Published (`addStates`): every well-formed catalog row; the membership of every live item (`ns` `item`); a share
///   link for each collection shared on this device (`CollectionShares.links`, only for a row this device has); the
///   links learned from another device, relayed only exactly as received. A state this device no longer has becomes a
///   tombstone; an unreadable record is left alone (no state, meta untouched). Collection states never push the view
///   past the record cap: then none is published and their meta stays (they wait; everything else still syncs).
/// - Applied (`Applier`), in the order catalog, then items, then memberships and links:
///   - two collections of one name: the larger id gets " (n)", the same on every device, `updated_at` untouched;
///   - a catalog tombstone deletes the row and takes it out of every membership (the items stay), unless it is shared
///     on this device (republished); a change of a read-only share's row is refused the same way;
///   - a membership waits (no meta) until its item and every named collection are here; collections this device
///     holds read-only are never added or removed by another device (`target`);
///   - two devices changing one membership at once keep the union (the engine's conflict copy is never stored and
///     never counted as a conflict); a losing catalog row or link copy is dropped (the winner was applied);
///   - a link of a collection shared on this device is this device's own: it is republished above anything else.
enum CollectionSync {
    typealias States = CollectionStates

    static func hasPrefix(_ id: String, _ prefix: String) -> Bool { id.utf8.starts(with: prefix.utf8) }

    /// A collection state, or a conflict copy of one (its id is a plain uuid; desktop `_is_collection_state`).
    static func isCollectionState(_ state: ItemState) -> Bool {
        if States.isStateID(state.itemID) { return true }
        if case .object(let w)? = state.item, w["ns"] == .string(States.namespace) { return true }
        return false
    }

    /// Whether `id` is a live item (a typed item, namespace `item`) in `records`.
    static func isLiveItem(_ id: String, _ records: [String: JSONValue]) -> Bool {
        guard let w = records[id], !States.isReserved(id, w) else { return false }
        return SyncMeta.nsName(w) == Namespace.item.rawValue
    }

    /// The well-formed catalog rows: collection id -> checked record.
    static func rows(_ records: [String: JSONValue]) -> [String: [String: JSONValue]] {
        var out: [String: [String: JSONValue]] = [:]
        for (id, wrapper) in records where hasPrefix(id, States.catalogPrefix) {
            guard let r = CollectionCatalog.checked(id, wrapper) else { continue }
            out[String(id.dropFirst(States.catalogPrefix.count))] = r
        }
        return out
    }

    /// The `csl:` wrapper this device publishes for its own share of `collectionID`, nil when `link` is malformed.
    static func linkWrapper(_ collectionID: String, _ link: CollectionShares.Link) -> JSONValue? {
        let record = States.link(collectionID: collectionID, mode: link.mode, role: link.role)
        guard (try? States.checkRecord(States.linkPrefix + collectionID, record)) != nil else { return nil }
        return States.wrapper(record)
    }

    /// Whether link record `mine` wins over `theirs` when two of this person's devices share one collection
    /// (re-review wave B, B1; desktop `_link_beats`, lgk-core `CollectionSync.linkBeats`): the owner role over a
    /// member's, then the larger canonical record. The same on every device, so the two stop republishing over each
    /// other: only the winner's link is published, the loser relays it as received.
    static func linkBeats(_ mine: JSONValue, _ theirs: JSONValue) throws -> Bool {
        func owner(_ r: JSONValue) -> Bool {
            if case .object(let o) = r, o["role"] == .string("owner") { return true }
            return false
        }
        if owner(mine) != owner(theirs) { return owner(mine) }
        let a = try CanonicalJSON.encode(mine, dialect: .utf8)
        let b = try CanonicalJSON.encode(theirs, dialect: .utf8)
        return b.lexicographicallyPrecedes(a)
    }

    /// Whether this device's own link `mine` is published over the `stored` link of another device (nil: none).
    static func ownWins(_ mine: JSONValue, over stored: JSONValue?) throws -> Bool {
        guard let stored, try SyncMeta.digest(stored) != SyncMeta.digest(mine) else { return true }
        guard case .object(let m) = mine, let a = m["record"], case .object(let t) = stored, let b = t["record"] else {
            return true
        }
        return try linkBeats(a, b)
    }

    // MARK: - local view

    /// Adds the collection states to `states` (desktop `_collection_states`) and returns the meta to keep: `meta` as
    /// it was when the view would exceed the record cap.
    static func addStates(records: [String: JSONValue], skipped: [String: String], meta: [String: SyncMeta],
                          states: inout [String: ItemState], device: String, now: Int64,
                          shares: CollectionShares) throws -> [String: SyncMeta] {
        var own: [String: JSONValue] = [:]     // states this device stands for (bumped when they change)
        var relay: [String: JSONValue] = [:]   // links learned from another device: republished only as received
        var quiet = Set<String>()              // unreadable here: no state, meta untouched
        var rowIDs = Set<String>()
        for (id, wrapper) in records where States.isStateID(id) {
            guard let r = CollectionCatalog.checked(id, wrapper) else { quiet.insert(id); continue }
            if hasPrefix(id, States.catalogPrefix) {
                own[id] = States.wrapper(.object(r))
                rowIDs.insert(String(id.dropFirst(States.catalogPrefix.count)))
            } else if hasPrefix(id, States.membershipPrefix) {
                let item = String(id.dropFirst(States.membershipPrefix.count))
                if skipped[item] != nil { quiet.insert(id); continue }
                // The membership of an item that is not live here (deleted, or a login) is not published.
                if isLiveItem(item, records) { own[id] = States.wrapper(.object(r)) }
            } else {
                relay[id] = States.wrapper(.object(r))
            }
        }
        if let links = shares.links {
            for (cid, link) in links where rowIDs.contains(cid) {
                guard let wrapper = linkWrapper(cid, link) else { continue }
                // Another of this person's devices shares it too and its link wins: relayed as received (B1).
                guard try ownWins(wrapper, over: relay[States.linkPrefix + cid]) else { continue }
                own[States.linkPrefix + cid] = wrapper
                relay[States.linkPrefix + cid] = nil
            }
        }
        var work = meta
        var found: [String: ItemState] = [:]
        for (id, wrapper) in own {
            var m = work[id]
            let d = try SyncMeta.digest(wrapper)
            if m == nil || m!.deleted || m!.digest != d {
                guard let vv = try SyncMeta.bumped(m?.vv ?? [:], device: device) else { continue }
                m = try SyncMeta.live(wrapper, vv: vv)
                work[id] = m
            }
            found[id] = try ItemState(itemID: id, vv: m!.vv, deleted: false, deletedAt: nil, item: wrapper)
        }
        for (id, wrapper) in relay {
            let d = try SyncMeta.digest(wrapper)
            guard let m = work[id], !m.deleted, m.digest == d else { continue }
            found[id] = try ItemState(itemID: id, vv: m.vv, deleted: false, deletedAt: nil, item: wrapper)
        }
        for (id, m) in work where States.isStateID(id) && own[id] == nil && relay[id] == nil && !quiet.contains(id) {
            // A relayed link that changed here goes quiet until it comes again; own links are unknown without shares.
            if hasPrefix(id, States.linkPrefix) && shares.links == nil { continue }
            guard Identifier.isValid(id) else { continue }
            var t = m
            if !m.deleted {
                guard let vv = try SyncMeta.bumped(m.vv, device: device) else { continue }
                t = SyncMeta.tomb(vv: vv, deletedAt: now)
                work[id] = t
            }
            found[id] = try ItemState(itemID: id, vv: t.vv, deleted: true, deletedAt: t.deletedAt, item: nil)
        }
        if states.count + found.count > SyncMeta.maxRecords || work.count > SyncMeta.maxRecords { return meta }
        states.merge(found) { _, new in new }
        return work
    }

    // MARK: - apply

    /// Applies the collection states of one personal-group outcome (desktop `_Collections`). Pure: works on its own
    /// copies of the records and meta, which the caller takes back.
    struct Applier {
        var records: [String: JSONValue]
        var meta: [String: SyncMeta]
        var rows: [String: [String: JSONValue]]
        let device: String
        let now: Int64
        let shares: CollectionShares

        init(records: [String: JSONValue], meta: [String: SyncMeta], device: String, now: Int64, shares: CollectionShares) {
            self.records = records; self.meta = meta; self.device = device; self.now = now; self.shares = shares
            rows = CollectionSync.rows(records)
        }

        var readOnly: Set<String> { shares.readOnly }

        func room(_ id: String) -> Bool { meta[id] != nil || meta.count < SyncMeta.maxRecords }

        func bump(_ vv: [String: Int64]) throws -> [String: Int64] { try VersionVector.bump(vv, device: device) }

        func digest(_ v: JSONValue) throws -> String { try SyncMeta.digest(v) }

        func memberships(of item: String) -> [String] { CollectionCatalog.memberships(of: item, records: records) }

        /// What this device publishes now for the catalog row or membership `id` (desktop `_Collections._current`).
        func current(_ id: String) -> JSONValue? {
            if CollectionSync.hasPrefix(id, States.catalogPrefix) {
                return rows[String(id.dropFirst(States.catalogPrefix.count))].map { States.wrapper(.object($0)) }
            }
            let item = String(id.dropFirst(States.membershipPrefix.count))
            guard CollectionSync.isLiveItem(item, records), let w = records[id], let r = CollectionCatalog.checked(id, w) else { return nil }
            return States.wrapper(.object(r))
        }

        /// A stored catalog row or membership this device cannot read: incoming states for it are left out.
        func unreadable(_ id: String) -> Bool {
            guard let w = records[id] else { return false }
            return CollectionCatalog.checked(id, w) == nil
        }

        /// `vault-changed` when the catalog row or membership `id` changed since the view was taken.
        func checkFresh(_ id: String) throws {
            if CollectionSync.hasPrefix(id, States.linkPrefix) { return }   // links change only here and through the share actions
            let m = meta[id], published = self.current(id)
            let fresh: Bool
            if m == nil || m!.deleted {
                fresh = published == nil
            } else {
                fresh = try published.map { try digest($0) == m!.digest } ?? false
            }
            if !fresh { throw RecordError("vault-changed", id, "The vault changed since the sync view was taken; sync again") }
        }

        // MARK: catalog rows

        mutating func storeRow(_ cid: String, _ record: [String: JSONValue]) throws {
            guard case .string(let name)? = record["name"], case .string(let description)? = record["description"],
                  case .int(let created)? = record["created_at"], case .int(let updated)? = record["updated_at"] else {
                throw RecordError(nil, nil, "malformed collection row")
            }
            let wrapper = try CollectionCatalog.catalogWrapper(id: cid, name: name, description: description,
                                                               createdAt: created, updatedAt: updated)
            guard case .object(let w) = wrapper, case .object(let stored)? = w["record"] else {
                throw RecordError(nil, nil, "malformed collection row")
            }
            records[States.catalogPrefix + cid] = wrapper
            rows[cid] = stored
        }

        mutating func catalogUpsert(_ s: ItemState, _ record: [String: JSONValue]) throws -> Bool {
            let sid = s.itemID
            let cid = String(sid.dropFirst(States.catalogPrefix.count))
            let row = rows[cid]
            if (row == nil && rows.count >= CollectionCatalog.maxCollections) || !room(sid) { return false }   // waits
            let incoming = States.wrapper(.object(record))
            if let row, readOnly.contains(cid) {
                // A read-only share's row never changes from another device: this device's row is republished. (Only
                // the same-name rule below may still number it, as on every device; the share does not carry names.)
                let mine = States.wrapper(.object(row))
                meta[sid] = try SyncMeta.live(mine, vv: try digest(mine) == digest(incoming) ? s.vv : bump(s.vv))
                return false
            }
            var new = record
            guard case .string(let name)? = record["name"] else { throw RecordError(nil, nil, "malformed collection row") }
            let folded = Casefold.fold(name)
            // The smallest such id when duplicates already exist, so the choice never depends on dictionary order.
            if let match = rows.filter({ !CollectionCatalog.same($0.key, cid) && Self.sameName($0.value, folded) })
                .min(by: { scalarOrder($0.key, $1.key) }),
               case .string(let otherName)? = match.value["name"] {
                let otherID = match.key, other = match.value
                // Two collections of one name (made on two devices): the larger id gets a number, the same on every
                // device, and its updated_at stays, so devices that rename alike agree.
                let names = rows.filter { !CollectionCatalog.same($0.key, cid) && !CollectionCatalog.same($0.key, otherID) }
                    .compactMap { entry -> String? in
                        if case .string(let n)? = entry.value["name"] { return n }
                        return nil
                    }
                if scalarOrder(otherID, cid) {
                    new["name"] = .string(CollectionCatalog.uniqueName(name, taken: names + [otherName]))
                } else {
                    var renamed = other
                    renamed["name"] = .string(CollectionCatalog.uniqueName(otherName, taken: names + [name]))
                    try storeRow(otherID, renamed)
                }
            }
            try storeRow(cid, new)
            let stored = States.wrapper(.object(rows[cid]!))
            meta[sid] = try SyncMeta.live(stored, vv: try digest(stored) == digest(incoming) ? s.vv : bump(s.vv))
            guard let row else { return true }
            return try digest(States.wrapper(.object(row))) != digest(stored)
        }

        static func sameName(_ row: [String: JSONValue], _ folded: String) -> Bool {
            guard case .string(let n)? = row["name"] else { return false }
            return CollectionCatalog.same(Casefold.fold(n), folded)
        }

        mutating func catalogDelete(_ s: ItemState, at: Int64) throws -> Bool {
            let sid = s.itemID
            let cid = String(sid.dropFirst(States.catalogPrefix.count))
            let row = rows[cid]
            // Whether it is shared on this device cannot be told without the share records: decide nothing now.
            guard let links = shares.links else { return false }
            if let row, links[cid] != nil || readOnly.contains(cid) {
                // Shared on this device: only leaving the share removes it here; this row is republished.
                meta[sid] = try SyncMeta.live(States.wrapper(.object(row)), vv: try bump(s.vv))
                return false
            }
            guard room(sid) else { return false }
            meta[sid] = SyncMeta.tomb(vv: s.vv, deletedAt: at)
            guard row != nil else { return false }
            rows[cid] = nil
            records[sid] = nil
            // As `CollectionCatalog.delete`: the items stay, only their membership goes (their meta is untouched, so
            // the next view publishes the change). Recently deleted rows are the host's: a restore re-adds only
            // collections that still exist.
            for (mid, wrapper) in records where CollectionSync.hasPrefix(mid, States.membershipPrefix) {
                guard let r = CollectionCatalog.checked(mid, wrapper), case .string(let item)? = r["item_id"] else { continue }
                let ids = CollectionCatalog.strings(r["collection_ids"])
                guard ids.contains(where: { CollectionCatalog.same($0, cid) }) else { continue }
                records[mid] = try CollectionCatalog.membershipWrapper(itemID: item, ids: ids.filter { !CollectionCatalog.same($0, cid) })
            }
            records[States.linkPrefix + cid] = nil
            return true
        }

        // MARK: memberships

        /// The membership to store: `wanted` minus unknown and read-only-share collections, plus this device's own
        /// read-only-share ones; nil while a wanted collection is not known here yet (or past 20).
        func target(_ wanted: [String], current: [String]) -> [String]? {
            var known: [String] = []
            for cid in wanted {
                if rows[cid] != nil { known.append(cid); continue }
                let m = meta[States.catalogPrefix + cid]
                if m == nil || !m!.deleted { return nil }   // its catalog row has not arrived yet: wait (no meta)
            }
            let kept = current.filter { readOnly.contains($0) }
            let added = ShareKeyring.sortedIDs(known).filter { c in
                !readOnly.contains(c) && !kept.contains(where: { CollectionCatalog.same($0, c) })
            }
            let target = ShareKeyring.sortedIDs(kept + added)
            return target.count <= States.maxMemberships ? target : nil
        }

        mutating func membershipUpsert(_ s: ItemState, _ record: [String: JSONValue], union: Bool = false) throws -> Bool {
            guard case .string(let item)? = record["item_id"] else { throw RecordError(nil, nil, "malformed membership") }
            let sid = States.membershipPrefix + item
            guard CollectionSync.isLiveItem(item, records), room(sid) else { return false }   // the item is not here (yet): it waits
            let have = memberships(of: item)
            let incoming = CollectionCatalog.strings(record["collection_ids"])
            guard let next = self.target(union ? have + incoming : incoming, current: have) else { return false }
            let changed = ShareKeyring.sortedIDs(have) != next
            if changed { records[sid] = try CollectionCatalog.membershipWrapper(itemID: item, ids: next) }
            let stored = try CollectionCatalog.membershipWrapper(itemID: item, ids: next)
            if union {
                // Both sides' collections are kept: published above both as this device's own change.
                if changed {
                    let vv = try bump(meta[sid]?.vv ?? [:])
                    meta[sid] = try stored.map { try SyncMeta.live($0, vv: vv) } ?? SyncMeta.tomb(vv: vv, deletedAt: now)
                }
                return changed
            }
            if let stored {
                let same = try digest(stored) == digest(States.wrapper(.object(record)))
                meta[sid] = try SyncMeta.live(stored, vv: same ? s.vv : bump(s.vv))
            } else {
                meta[sid] = SyncMeta.tomb(vv: try bump(s.vv), deletedAt: now)
            }
            return changed
        }

        mutating func membershipDelete(_ s: ItemState, at: Int64) throws -> Bool {
            let sid = s.itemID
            guard room(sid) else { return false }
            let item = String(sid.dropFirst(States.membershipPrefix.count))
            guard CollectionSync.isLiveItem(item, records) else {
                records[sid] = nil   // the stale membership of an item that is gone
                meta[sid] = SyncMeta.tomb(vv: s.vv, deletedAt: at)
                return false
            }
            let have = memberships(of: item)
            let kept = ShareKeyring.sortedIDs(have.filter { readOnly.contains($0) })
            let changed = ShareKeyring.sortedIDs(have) != kept
            if changed { records[sid] = try CollectionCatalog.membershipWrapper(itemID: item, ids: kept) }
            if let stored = try CollectionCatalog.membershipWrapper(itemID: item, ids: kept) {
                meta[sid] = try SyncMeta.live(stored, vv: try bump(s.vv))   // its read-only collections stay
            } else {
                meta[sid] = SyncMeta.tomb(vv: s.vv, deletedAt: at)
            }
            return changed
        }

        // MARK: share links

        mutating func linkUpsert(_ s: ItemState, _ record: [String: JSONValue]) throws -> Bool {
            let sid = s.itemID
            let cid = String(sid.dropFirst(States.linkPrefix.count))
            // No room, or this device's own shares cannot be read: decide nothing now.
            guard room(sid), let links = shares.links else { return false }
            let incoming = States.wrapper(.object(record))
            if let link = links[cid], rows[cid] != nil {
                guard let mine = CollectionSync.linkWrapper(cid, link) else { return false }
                if try digest(mine) == digest(incoming) {
                    // The same link: no other device shares it differently (any such link stored here goes).
                    let changed = records.removeValue(forKey: sid) != nil
                    meta[sid] = try SyncMeta.live(mine, vv: s.vv)
                    return changed
                }
                // Shared from two of this person's devices (re-review wave B, B1). Both keep the other's link (the
                // share page warns); only the winner's is published: the winner republishes its own above, the loser
                // records the peer's vector and relays the winner's link as received, so the two stop.
                let changed = try records[sid].map { try digest($0) != digest(incoming) } ?? true
                records[sid] = incoming
                if try CollectionSync.ownWins(mine, over: incoming) {
                    meta[sid] = try SyncMeta.live(mine, vv: try bump(s.vv))
                } else {
                    meta[sid] = try SyncMeta.live(incoming, vv: s.vv)
                }
                return changed
            }
            let changed = try records[sid].map { try digest($0) != digest(incoming) } ?? true
            records[sid] = incoming
            meta[sid] = try SyncMeta.live(incoming, vv: s.vv)
            return changed
        }

        mutating func linkDelete(_ s: ItemState, at: Int64) throws -> Bool {
            let sid = s.itemID
            let cid = String(sid.dropFirst(States.linkPrefix.count))
            guard room(sid), let links = shares.links else { return false }
            if let link = links[cid], rows[cid] != nil {
                // This device speaks for its own share; another device's link of it, if one was stored, is gone.
                guard let mine = CollectionSync.linkWrapper(cid, link) else { return false }
                let changed = records.removeValue(forKey: sid) != nil
                meta[sid] = try SyncMeta.live(mine, vv: try bump(s.vv))
                return changed
            }
            let changed = records.removeValue(forKey: sid) != nil
            meta[sid] = SyncMeta.tomb(vv: s.vv, deletedAt: at)
            return changed
        }
    }
}
