/// The share view of the vault for one share group (sub-plan 07 "Storage design"; desktop `vault_bridge` "Shared
/// collections" with a share scope). A share run sees only this; `commit` writes what the run changed back into the
/// main store in ONE commit (items, their memberships and the share's own state and meta).
///
/// What the share view holds (`load`):
/// - only live typed items whose membership (`cm:`) names the collection: never logins, documents (so no attachment
///   file), licences, collection states, the trash, other items or settings;
/// - each as `ShareView.wrapper`: `collection_ids == [collection]` (this person's other collections stay private),
///   `revision`, `tags`, `favorite` and `payload.document_ids` left out (each person keeps their own). When only such
///   local fields changed, the last published `updated_at` is kept (desktop `_view_wrapper`), so it is no share edit;
/// - the share's own sync meta and state (`ShareRecord`), never the personal group's.
///
/// An item that leaves the collection (untagged or deleted here) becomes a tombstone in the share only: members lose
/// it, this device keeps it. An item that cannot be read is left alone (no state, meta untouched, nothing applied over
/// it). Read-only (a member of a `read` share): a local change (edit, new tagged item, untag, delete) is never
/// published and its meta is left alone; the owner's version replaces it on the next run.
///
/// What comes in (`filter`, then `commit`):
/// - a live state must be a typed item claiming exactly `[collection]` (`ShareView.checkIncoming`), else
///   `bad-peer-record` (`update-needed` for a newer schema), and only that state is left out;
/// - it may replace or restore only an item of the collection, or one this share last saw live: an id of a personal
///   item (live, or in Recently deleted outside the collection) is `bad-peer-record`, and a tombstone for one is
///   recorded in the share's meta without touching the vault;
/// - an edit of an item this device untagged meanwhile is skipped quietly (the tombstone stays published);
/// - an incoming item lands in the collection with this device's own other collections, tags and favourite (none for
///   a new item); a remote tombstone takes the item out of the store, which the host's store moves to Recently deleted.
public final class ShareItemStore: ItemStore {
    public let base: any ItemStore
    public let groupID: String
    public let trash: ShareTrash

    public init(base: any ItemStore, groupID: String, trash: ShareTrash) {
        self.base = base; self.groupID = groupID; self.trash = trash
    }

    /// The share view (records, the share's meta and state) at the main store's revision.
    public func load() throws -> StoreSnapshot { try projection().snapshot }

    func projection() throws -> ShareProjection {
        try ShareProjection(main: try base.load(), groupID: groupID, trash: trash)
    }

    /// Writes a share run's result: `change.records`/`change.meta` are the share view after the run, `change.sync` the
    /// share's new state (its group, device, epoch, key and keyring never change here: `bad-state`). Refused
    /// (`store-changed`) when the main store moved since `change.baseRevision`, and (`bad-remote`) for anything that
    /// would reach outside the collection.
    public func commit(_ change: StoreChange) throws {
        let main = try base.load()
        guard main.revision == change.baseRevision else {
            throw ShareGroupError("store-changed", "the vault changed since the share view was taken; sync again")
        }
        let p = try ShareProjection(main: main, groupID: groupID, trash: trash)
        try base.commit(try p.mainChange(change))
    }
}

/// One share group's view of a main store snapshot, and the way back (`ShareItemStore`).
struct ShareProjection {
    let main: StoreSnapshot
    let groupID: String
    let record: ShareRecord
    let collectionID: String
    /// What the share run sees.
    let snapshot: StoreSnapshot
    /// Stored share meta the run does not see (unreadable items; read-only local changes): written back unchanged
    /// unless the run settled the id.
    let hidden: [String: SyncMeta]
    /// Live items of the collection that the share can carry (typed, not a document), readable or not.
    let tagged: Set<String>
    /// Tagged items that cannot be read: id -> why.
    let skipped: [String: String]
    /// Live items this device took out of the collection (a tombstone in the share): incoming edits skipped quietly.
    let quiet: Set<String>
    /// Ids no share peer may write (personal items, live or in Recently deleted).
    let personal: Set<String>
    /// Recently deleted as the run started (an item brought back keeps this device's own fields).
    let trash: ShareTrash

    static func same(_ a: String, _ b: String) -> Bool { Array(a.utf8) == Array(b.utf8) }

    init(main: StoreSnapshot, groupID: String, trash: ShareTrash) throws {
        guard let record = try ShareGroups.records(in: main)[groupID] else {
            throw ShareGroupError("not-joined", "this vault is not in that share group")
        }
        let cid = record.collectionID
        let stored = record.meta
        var records: [String: JSONValue] = [:]
        var meta = stored
        var hidden: [String: SyncMeta] = [:]
        var tagged = Set<String>()
        var skipped: [String: String] = [:]
        var quiet = Set<String>()
        var personal = Set<String>()
        let items = main.itemRecords
        for (id, w) in items {
            guard SyncMeta.nsName(w) == Namespace.item.rawValue, case .object(let wo) = w, case .object(var r)? = wo["record"] else {
                continue
            }
            let ids = CollectionCatalog.memberships(of: id, records: main.records)
            guard ids.contains(where: { ShareProjection.same($0, cid) }) else { continue }
            r["collection_ids"] = .array(ids.map { JSONValue.string($0) })
            guard ShareView.isShared(.object(r), collectionID: cid) else { continue }   // a document never travels
            tagged.insert(id)
            guard Identifier.isValid(id) else { skipped[id] = "invalid-id"; continue }
            do {
                records[id] = try ShareProjection.keepingSyncedTime(try ShareView.wrapper(.object(r), collectionID: cid), stored[id])
            } catch {
                skipped[id] = "\(error)"
            }
        }
        for id in skipped.keys {
            if let m = meta.removeValue(forKey: id) { hidden[id] = m }
        }
        if record.isReadOnly {
            // A local change is never published: neither the change (no bump) nor a tombstone. Without its meta the
            // run takes the owner's version as new, which then replaces the local one.
            for (id, m) in stored where meta[id] != nil {
                let current = records[id]
                let changed: Bool
                if m.deleted {
                    changed = current != nil
                } else if let current {
                    changed = (try? SyncMeta.digest(current)) != m.digest
                } else {
                    changed = true
                }
                if changed {
                    hidden[id] = m
                    meta[id] = nil
                    records[id] = nil
                }
            }
            for id in Array(records.keys) where meta[id] == nil { records[id] = nil }   // new here: never published
        }
        for (id, w) in items where !tagged.contains(id) {
            let m = stored[id]
            if let m, m.deleted || !record.isReadOnly {
                // Untagged (or never shareable) here and a tombstone in the share, now or after this run's view.
                quiet.insert(id)
                continue
            }
            let restorable = m.map { !$0.deleted } ?? false
            let isItem = SyncMeta.nsName(w) == Namespace.item.rawValue
            let room = CollectionCatalog.memberships(of: id, records: main.records).count < CollectionStates.maxMemberships
            if !(restorable && isItem && room) { personal.insert(id) }
        }
        for (id, ids) in trash.collections where items[id] == nil {
            let inCollection = ids.contains { ShareProjection.same($0, cid) }
            let restorable = stored[id].map { !$0.deleted } ?? false
            if !inCollection && !restorable { personal.insert(id) }
        }
        self.main = main
        self.groupID = groupID
        self.record = record
        self.collectionID = cid
        self.snapshot = StoreSnapshot(records: records, meta: meta, sync: record.state, revision: main.revision)
        self.hidden = hidden
        self.tagged = tagged
        self.skipped = skipped
        self.quiet = quiet
        self.personal = personal
        self.trash = trash
    }

    /// The share wrapper with the last published `updated_at` when nothing but local fields changed (desktop
    /// `_view_wrapper`).
    static func keepingSyncedTime(_ wrapper: JSONValue, _ m: SyncMeta?) throws -> JSONValue {
        guard let m, !m.deleted, case .object(var w) = wrapper, case .object(var r)? = w["record"] else { return wrapper }
        var stamp: Int64?
        if case .int(let n)? = r["updated_at"] { stamp = n }
        if stamp == m.updatedAt { return wrapper }
        let body = try SyncMeta.bodyDigest(wrapper)
        if body != m.body { return wrapper }
        if let u = m.updatedAt { r["updated_at"] = .int(u) } else { r["updated_at"] = nil }
        w["record"] = .object(r)
        w["updated_at"] = .int(Wrapper.rank(.object(r)))
        return .object(w)
    }

    /// The peers' views without what the share must not apply: states of unreadable items (dropped quietly), edits of
    /// items untagged here (dropped quietly), live states for personal ids and live states that are not an item of the
    /// collection (each reported and left out alone).
    func filter(_ views: [PeerView]) -> (views: [PeerView], issues: [SyncIssue]) {
        var issues: [SyncIssue] = []
        var out: [PeerView] = []
        for view in views {
            var kept: [ItemState] = []
            for s in view.states {
                let id = s.itemID
                if skipped[id] != nil { continue }
                if s.deleted { kept.append(s); continue }
                if quiet.contains(id) { continue }
                // Every shared item (and every conflict copy) has a canonical uuid id: its membership needs one.
                if personal.contains(id) || !ShareKeyring.isCanonicalUUID(id) {
                    issues.append(SyncIssue("bad-peer-record", "\(view.deviceID):\(id)"))
                    continue
                }
                do {
                    _ = try ShareView.checkIncoming(s, collectionID: collectionID)
                } catch let e as RecordError {
                    issues.append(SyncIssue(e.reason == "update-needed" ? "update-needed" : "bad-peer-record", "\(view.deviceID):\(id)"))
                    continue
                } catch {
                    issues.append(SyncIssue("bad-peer-record", "\(view.deviceID):\(id)"))
                    continue
                }
                kept.append(s)
            }
            out.append(kept.count == view.states.count ? view : PeerView(deviceID: view.deviceID, states: kept))
        }
        return (out, issues)
    }

    static func badRemote(_ id: String) -> ShareGroupError {
        ShareGroupError("bad-remote", "\(id): reaches outside the shared collection")
    }

    /// The main store change for a share run's result (see `ShareItemStore.commit`).
    func mainChange(_ change: StoreChange) throws -> StoreChange {
        let old = record.state
        guard let state = change.sync, Self.same(state.groupID, old.groupID), Self.same(state.deviceID, old.deviceID),
              state.identity == old.identity, state.epoch == old.epoch, state.key == old.key, state.keyring == old.keyring,
              Self.same(state.installID, old.installID) else {
            throw ShareGroupError("bad-state", "a share run cannot change the group, device, key or keyring")
        }
        let cid = collectionID
        var records = main.records
        var meta = change.meta
        for (id, m) in hidden where meta[id] == nil { meta[id] = m }
        // A remote tombstone the run applied: the item leaves the store (the host moves it to Recently deleted).
        for id in tagged where change.records[id] == nil && skipped[id] == nil {
            let shared = snapshot.records[id] != nil || hidden[id] != nil
            if shared && change.meta[id]?.deleted == true {
                records[id] = nil
                records[CollectionStates.membershipPrefix + id] = nil
            }
        }
        // Incoming items, changed or new (conflict copies included).
        for (id, w) in change.records {
            if let before = snapshot.records[id], ShareKeyring.sameJSON(before, w) { continue }
            guard !CollectionStates.isStateID(id), !personal.contains(id), !quiet.contains(id), skipped[id] == nil,
                  case .object(let wo) = w, wo["ns"] == .string(Namespace.item.rawValue),
                  case .object(var r)? = wo["record"] else { throw Self.badRemote(id) }
            var local: [String: JSONValue]?
            var ids = CollectionCatalog.memberships(of: id, records: main.records)
            if let current = main.records[id] {
                guard !CollectionStates.isReserved(id, current), SyncMeta.nsName(current) == Namespace.item.rawValue,
                      case .object(let co) = current, case .object(let cr)? = co["record"] else { throw Self.badRemote(id) }
                local = cr
            } else if let deleted = trash.records[id] {
                // Back from Recently deleted: this device's own fields and its collections that still exist come back.
                local = deleted
                let known = Set(CollectionCatalog.collections(in: main).map { Array($0.id.utf8) })
                ids = ShareKeyring.sortedIDs(ids + CollectionCatalog.strings(deleted["collection_ids"])
                    .filter { known.contains(Array($0.utf8)) })
            }
            r["collection_ids"] = nil
            r["revision"] = nil
            // Tags and favourites are personal: this device's own (none for a new item), never the peer's.
            r["tags"] = local?["tags"] ?? .array([])
            r["favorite"] = local?["favorite"] ?? .bool(false)
            if case .object(var payload)? = r["payload"] {
                payload["document_ids"] = nil
                if case .object(let lp)? = local?["payload"], let docs = lp["document_ids"] { payload["document_ids"] = docs }
                r["payload"] = .object(payload)
            }
            records[id] = Wrapper.make(ns: .item, record: .object(r))
            if !ids.contains(where: { Self.same($0, cid) }) { ids.append(cid) }
            guard ids.count <= CollectionStates.maxMemberships,
                  let membership = try CollectionCatalog.membershipWrapper(itemID: id, ids: ids) else { throw Self.badRemote(id) }
            records[CollectionStates.membershipPrefix + id] = membership
            // What this device publishes for it from now on: when the stored form differs from what the peer sent (a
            // field this device normalises), that is this device's own edit (desktop: `bump` unless stored == remote).
            var shared = r
            shared["collection_ids"] = .array(ShareKeyring.sortedIDs(ids).map { JSONValue.string($0) })
            if let m = meta[id], !m.deleted, let mine = try? ShareView.wrapper(.object(shared), collectionID: cid),
               !ShareKeyring.sameJSON(mine, w), let vv = try SyncMeta.bumped(m.vv, device: state.deviceID) {
                // An overflowing counter (only a vector stored before the bounds) leaves the peer's meta: never the run.
                meta[id] = try SyncMeta.live(mine, vv: vv)
            }
        }
        guard meta.count <= SyncMeta.maxRecords else { throw ShareGroupError("bad-state", "share meta exceeds its bound") }
        var all = try ShareGroups.records(in: main)
        var updated = record
        updated.state = state
        updated.meta = meta
        all[groupID] = updated
        return StoreChange(baseRevision: main.revision, records: records, meta: main.meta, sync: main.sync,
                           shares: .set(ShareRecord.encode(all)))
    }
}
