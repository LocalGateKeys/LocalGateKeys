import Foundation

/// Personal collections kept in the item store (sub-plan 07 Task 5c): the catalog rows are `col:` records and the
/// memberships `cm:` records, stored as their collection-state wrappers (`CollectionStates`), so the store is the one
/// source of truth that sync later relays byte for byte. Item records keep their v1 shape: an item never carries
/// `collection_ids` in the store (a Recently deleted row does, as Windows' trash entry does).
///
/// The Windows rules (`collections.py`, `item_schema.py`): collections are free; at most 500; a name is 1...100 code
/// points, stored stripped and unique ignoring case (Python `casefold`); a description is at most 500; an item is in
/// at most 20 collections; logins (`web`, `desktop`) and documents are never added; deleting a collection keeps its
/// items and removes it from every membership and every Recently deleted row. Starters: Personal, Work, Travel,
/// Emergency (`ensure_starters`). Read-only shares refuse through `ShareAccess.checkWritable`.
///
/// Pure: every builder returns the `StoreChange` to commit (records only; meta and sync state untouched), or nil when
/// nothing changes. Every reader that lists or counts items uses `StoreSnapshot.itemRecords`, which leaves the
/// collection states out.
public enum CollectionCatalog {
    public static let maxCollections = 500
    public static let starterNames = ["Personal", "Work", "Travel", "Emergency"]

    /// The name to show for a collection: a starter keeps its English name in the store (every platform adds and
    /// matches starters by it), so it is translated only on screen. Any other name is shown as typed.
    public static func displayName(_ name: String) -> String {
        switch name {
        case "Personal": String(localized: "collection.starter.Personal", defaultValue: "Personal", bundle: .module)
        case "Work": String(localized: "collection.starter.Work", defaultValue: "Work", bundle: .module)
        case "Travel": String(localized: "collection.starter.Travel", defaultValue: "Travel", bundle: .module)
        case "Emergency": String(localized: "collection.starter.Emergency", defaultValue: "Emergency", bundle: .module)
        default: name
        }
    }
    /// Item kinds that are never added to a collection (Windows logins have no `collection_ids`; documents never
    /// enter a share).
    public static let nonMemberKinds: Set<String> = ["web", "desktop", "document"]
    static let loginKinds: Set<String> = ["web", "desktop"]

    public enum Failure: Error, Equatable, Sendable, CustomStringConvertible {
        /// 500 collections already.
        case limit
        case emptyName, longName, duplicateName, longDescription
        /// A name or description with a NUL character.
        case invalidText
        /// A new collection id that is malformed or already used (never with random UUIDs).
        case invalidID
        /// No such collection or item.
        case notFound
        /// A login or a document cannot be added to a collection.
        case notMember
        /// More than 20 collections on one item.
        case tooMany
        /// A membership names a collection this vault does not know.
        case unknownCollection
        /// The collection is shared on this device or read-only here: stop sharing (or leave) first.
        case shared
        /// A collection-state id (`col:`/`cm:`/`csl:`) where an item id was expected.
        case reserved

        public var description: String {
            switch self {
            case .limit: "collection-limit"
            case .emptyName: "empty-name"
            case .longName: "long-name"
            case .duplicateName: "duplicate-name"
            case .longDescription: "long-description"
            case .invalidText: "invalid-text"
            case .invalidID: "invalid-id"
            case .notFound: "not-found"
            case .notMember: "not-member"
            case .tooMany: "too-many"
            case .unknownCollection: "unknown-collection"
            case .shared: "shared"
            case .reserved: "reserved"
            }
        }
    }

    /// One catalog row (`col:` record).
    public struct Collection: Equatable, Sendable {
        public let id: String
        public let name: String
        public let description: String
        public let createdAt: Int64
        public let updatedAt: Int64
        public init(id: String, name: String, description: String, createdAt: Int64, updatedAt: Int64) {
            self.id = id; self.name = name; self.description = description
            self.createdAt = createdAt; self.updatedAt = updatedAt
        }
    }

    // MARK: - Reads

    /// The well-formed catalog rows, by name ignoring case, then id. A malformed `col:` record is not shown.
    public static func collections(in snapshot: StoreSnapshot) -> [Collection] {
        var out: [Collection] = []
        for (id, wrapper) in snapshot.records where id.utf8.starts(with: CollectionStates.catalogPrefix.utf8) {
            guard let r = checked(id, wrapper), case .string(let cid)? = r["collection_id"],
                  case .string(let name)? = r["name"], case .string(let description)? = r["description"],
                  case .int(let created)? = r["created_at"], case .int(let updated)? = r["updated_at"] else { continue }
            out.append(Collection(id: cid, name: name, description: description, createdAt: created, updatedAt: updated))
        }
        return out.sorted { a, b in
            let fa = Casefold.fold(a.name), fb = Casefold.fold(b.name)
            if !same(fa, fb) { return scalarOrder(fa, fb) }
            return scalarOrder(a.id, b.id)
        }
    }

    /// The collection ids `itemID` belongs to (sorted; ids of collections this vault does not know are kept).
    public static func memberships(of itemID: String, in snapshot: StoreSnapshot) -> [String] {
        memberships(of: itemID, records: snapshot.records)
    }

    /// The live items in `collectionID`, sorted by id.
    public static func items(in collectionID: String, snapshot: StoreSnapshot) -> [String] {
        let live = snapshot.itemRecords
        var out: [String] = []
        for (id, wrapper) in snapshot.records where id.utf8.starts(with: CollectionStates.membershipPrefix.utf8) {
            guard let r = checked(id, wrapper), case .string(let item)? = r["item_id"], live[item] != nil,
                  snapshot.meta[item]?.deleted != true, case .array(let ids)? = r["collection_ids"],
                  ids.contains(where: { if case .string(let s) = $0 { return same(s, collectionID) }; return false })
            else { continue }
            out.append(item)
        }
        return out.sorted(by: scalarOrder)
    }

    /// Collections another of this person's devices holds as a member of a read-only share (`csl:` links with mode
    /// `read` and role `member`): edits there are refused here too (desktop `linked_read_only_collection_ids`).
    public static func linkedReadOnlyIDs(in snapshot: StoreSnapshot) -> Set<String> {
        var out = Set<String>()
        for (id, wrapper) in snapshot.records where id.utf8.starts(with: CollectionStates.linkPrefix.utf8) {
            guard let r = checked(id, wrapper), case .string(let cid)? = r["collection_id"],
                  r["mode"] == .string("read"), r["role"] == .string("member") else { continue }
            out.insert(cid)
        }
        return out
    }

    // MARK: - Catalog changes

    /// Creates a collection (`CollectionService.create`): the change and the new id.
    public static func create(name raw: String, description: String = "", in snapshot: StoreSnapshot, now: Int64,
                              newID: () -> String = { UUID().uuidString.lowercased() }) throws -> (change: StoreChange, id: String) {
        let existing = collections(in: snapshot)
        guard existing.count < maxCollections else { throw Failure.limit }
        let name = try checkedName(raw, among: existing, except: nil)
        try checkDescription(description)
        let id = newID()
        guard ShareKeyring.isCanonicalUUID(id), snapshot.records[CollectionStates.catalogPrefix + id] == nil else {
            throw Failure.invalidID
        }
        let at = max(0, now)
        var records = snapshot.records
        records[CollectionStates.catalogPrefix + id] = try catalogWrapper(id: id, name: name, description: description,
                                                                          createdAt: at, updatedAt: at)
        return (change(snapshot, records), id)
    }

    /// Renames a collection and, when `description` is given, replaces its description. Nil when nothing changes.
    /// `updated_at` never goes back (the newest edit wins in sync). A collection another of this person's devices holds
    /// as a member of a read-only share (`linkedReadOnlyIDs`) is refused (`.shared`): that device would republish its
    /// own row over the change anyway (`CollectionSync`).
    public static func rename(_ id: String, to raw: String, description: String? = nil, in snapshot: StoreSnapshot,
                              now: Int64) throws -> StoreChange? {
        let existing = collections(in: snapshot)
        guard let row = existing.first(where: { same($0.id, id) }) else { throw Failure.notFound }
        if linkedReadOnlyIDs(in: snapshot).contains(where: { same($0, id) }) { throw Failure.shared }
        let name = try checkedName(raw, among: existing, except: id)
        let newDescription = description ?? row.description
        try checkDescription(newDescription)
        if same(name, row.name) && same(newDescription, row.description) { return nil }
        var records = snapshot.records
        records[CollectionStates.catalogPrefix + id] = try catalogWrapper(
            id: id, name: name, description: newDescription, createdAt: row.createdAt,
            updatedAt: max(now, row.updatedAt, row.createdAt))
        return change(snapshot, records)
    }

    /// Deletes a collection: its id leaves every membership and every Recently deleted row; the items stay. Returns the
    /// new trash rows too (nil when none changed).
    ///
    /// A shared collection is never deleted (`.shared`: it is left or stopped first), so no share group is ever
    /// orphaned, on this device or, once collections sync, on the device that holds the share. Refused when it has a
    /// `csl:` share link (whichever of this person's devices shares it) or is in `protected` (the collections of this
    /// device's share records, and read-only ones). `protected` has no default: the caller always passes them.
    public static func delete(_ id: String, in snapshot: StoreSnapshot, trash: [LocalData.TrashRow],
                              protected: Set<String>) throws -> (change: StoreChange, trash: [LocalData.TrashRow]?) {
        guard collections(in: snapshot).contains(where: { same($0.id, id) }) else { throw Failure.notFound }
        if protected.contains(where: { same($0, id) }) || snapshot.records[CollectionStates.linkPrefix + id] != nil {
            throw Failure.shared
        }
        var records = snapshot.records
        records[CollectionStates.catalogPrefix + id] = nil
        for (sid, wrapper) in snapshot.records where sid.utf8.starts(with: CollectionStates.membershipPrefix.utf8) {
            guard let r = checked(sid, wrapper), case .string(let item)? = r["item_id"] else { continue }
            let ids = strings(r["collection_ids"])
            guard ids.contains(where: { same($0, id) }) else { continue }
            records[sid] = try membershipWrapper(itemID: item, ids: ids.filter { !same($0, id) })
        }
        var rows = trash
        var touched = false
        for i in rows.indices {
            guard case .object(var r)? = try? rows[i].record(), case .array(let list)? = r["collection_ids"] else { continue }
            let kept = list.filter { if case .string(let s) = $0 { return !same(s, id) }; return true }
            guard kept.count != list.count else { continue }
            if kept.isEmpty { r["collection_ids"] = nil } else { r["collection_ids"] = .array(kept) }
            rows[i] = try LocalData.TrashRow(record: .object(r), deletedAt: rows[i].deletedAt)
            touched = true
        }
        return (change(snapshot, records), touched ? rows : nil)
    }

    /// The starter collections that are missing by name (`ensure_starters`): the change (nil when all exist) and the
    /// ids it creates (keep them in `LocalData.starterCollectionIDs`; the flag never syncs).
    public static func starters(in snapshot: StoreSnapshot, now: Int64,
                                newID: () -> String = { UUID().uuidString.lowercased() }) throws -> (change: StoreChange?, ids: [String]) {
        var current = snapshot
        var made: [String] = []
        for name in starterNames {
            let existing = collections(in: current)
            if existing.contains(where: { same(Casefold.fold($0.name), Casefold.fold(name)) }) { continue }
            guard existing.count < maxCollections else { break }
            let (c, id) = try create(name: name, in: current, now: now, newID: newID)
            current.records = c.records
            made.append(id)
        }
        let result: StoreChange? = made.isEmpty ? nil : change(snapshot, current.records)
        return (result, made)
    }

    // MARK: - Memberships

    /// Sets which collections the item `itemID` (of `kind`) belongs to (`CollectionService.set_membership`). Nil when
    /// nothing changes. Ids this vault does not know are kept only when the item already had them (from another
    /// device); any other must name a known collection. Logins and documents are never added (removing an old
    /// membership is allowed). `readOnly`: collections this device may not change (`ShareAccess`): an item in one is
    /// neither moved in nor out. The read-only links from this person's other devices (`linkedReadOnlyIDs`) always
    /// count too.
    public static func setMemberships(itemID: String, kind: String, to wanted: [String], in snapshot: StoreSnapshot,
                                      readOnly: Set<String> = []) throws -> StoreChange? {
        if CollectionStates.isStateID(itemID) { throw Failure.reserved }
        guard let item = snapshot.records[itemID], !CollectionStates.isReserved(itemID, item),
              snapshot.meta[itemID]?.deleted != true else { throw Failure.notFound }
        let current = memberships(of: itemID, records: snapshot.records)
        let next = ShareKeyring.sortedIDs(wanted)
        if next == current { return nil }
        let known = Set(collections(in: snapshot).map(\.id))
        for id in next where !known.contains(id) && !current.contains(where: { same($0, id) }) {
            throw Failure.unknownCollection
        }
        if nonMemberKinds.contains(kind), !next.allSatisfy({ n in current.contains(where: { same($0, n) }) }) {
            throw Failure.notMember
        }
        guard next.count <= CollectionStates.maxMemberships else { throw Failure.tooMany }
        try ShareAccess.checkWritable(readOnly.union(linkedReadOnlyIDs(in: snapshot)),
                                      .object(["collection_ids": .array(current.map { .string($0) })]),
                                      .object(["collection_ids": .array(next.map { .string($0) })]))
        var records = snapshot.records
        records[CollectionStates.membershipPrefix + itemID] = try membershipWrapper(itemID: itemID, ids: next)
        return change(snapshot, records)
    }

    // MARK: - Recently deleted

    /// The trash copy of `record` (the item `itemID` being deleted): its memberships ride along as `collection_ids`,
    /// as on Windows. Remove the membership from the store in the same commit (`withoutMembership`).
    public static func trashRecord(_ record: JSONValue, itemID: String, in snapshot: StoreSnapshot) -> JSONValue {
        let ids = memberships(of: itemID, records: snapshot.records)
        guard !ids.isEmpty, case .object(var r) = record else { return record }
        r["collection_ids"] = .array(ids.map { .string($0) })
        return .object(r)
    }

    /// `records` without the membership of `itemID`.
    public static func withoutMembership(_ itemID: String, records: [String: JSONValue]) -> [String: JSONValue] {
        var out = records
        out[CollectionStates.membershipPrefix + itemID] = nil
        return out
    }

    /// A Recently deleted record going back live: the record without `collection_ids` (the store form) and the
    /// records with its membership back, for the collections that still exist (at most 20).
    public static func restored(_ record: [String: JSONValue], itemID: String,
                                records: [String: JSONValue]) -> (record: [String: JSONValue], records: [String: JSONValue]) {
        var r = record
        // A login never has collections, even if an old row says so.
        var ids = strings(r["collection_ids"])
        if case .string(let kind)? = r["kind"], loginKinds.contains(kind) { ids = [] }
        r["collection_ids"] = nil
        var out = records
        let known = Set(collections(in: StoreSnapshot(records: records)).map(\.id))
        let kept = ShareKeyring.sortedIDs(ids.filter { known.contains($0) } + memberships(of: itemID, records: records))
        if !kept.isEmpty, kept.count <= CollectionStates.maxMemberships,
           let wrapper = try? membershipWrapper(itemID: itemID, ids: kept) {
            out[CollectionStates.membershipPrefix + itemID] = wrapper
        }
        return (r, out)
    }

    /// A full restore replaces the items: the catalog rows and share links of `current` stay, and each membership
    /// whose item is live in `restored`. A backup carries no collection states. A Mac safety copy (a whole store) does:
    /// then its own catalog and memberships come back as they were, and only `current`'s share links are added (they
    /// stand for share records this device holds now). A reserved id holding anything but a collection state is
    /// dropped.
    public static func carriedOver(from current: [String: JSONValue], into restored: [String: JSONValue]) -> [String: JSONValue] {
        var out = restored.filter { !CollectionStates.isReserved($0.key, $0.value) }
        let wholeStore = restored.contains { CollectionStates.isStateID($0.key) && checked($0.key, $0.value) != nil }
        let fromCurrent = wholeStore ? current.filter { $0.key.utf8.starts(with: CollectionStates.linkPrefix.utf8) } : current
        for source in [restored, fromCurrent] {
            for (id, wrapper) in source where CollectionStates.isStateID(id) && out[id] == nil {
                guard checked(id, wrapper) != nil else { continue }
                if id.utf8.starts(with: CollectionStates.membershipPrefix.utf8) {
                    let item = String(id.dropFirst(CollectionStates.membershipPrefix.count))
                    guard let w = out[item], !CollectionStates.isReserved(item, w) else { continue }
                }
                out[id] = wrapper
            }
        }
        return out
    }

    // MARK: - Mac migration

    /// What `migrate` did.
    public struct Migration: Equatable, Sendable {
        /// The store change (nil: the store already holds everything).
        public var change: StoreChange?
        /// The local data to save after the store: collections and memberships cleared, starter ids kept,
        /// memberships of deleted items moved into their Recently deleted rows.
        public var local: LocalData
        /// Collections added to the store, and how many of them were renamed " (n)" next to a store collection of
        /// the same name.
        public var collections: Int
        public var renamed: Int
        /// Memberships moved into the store and into Recently deleted rows.
        public var memberships: Int
        public var trashMemberships: Int
        /// Memberships that could not be kept: of a login, of an item that is neither live nor deleted, or past 20.
        public var dropped: Int
    }

    /// Moves the Mac's `LocalData` collections and memberships into the store (sub-plan 07 "Storage design"). Nil when
    /// there is nothing to move. Lossless and idempotent: a collection whose `col:` record exists already is kept as
    /// the store has it, memberships are merged with the store's, so a run interrupted after the store commit and run
    /// again changes nothing more. Commit `change` first, then save `local` (`CollectionMigration.run`).
    public static func migrate(from local: LocalData, into snapshot: StoreSnapshot) throws -> Migration? {
        guard !local.collections.isEmpty || !local.memberships.isEmpty else { return nil }
        var records = snapshot.records
        var out = local
        var added = 0, renamed = 0, moved = 0, toTrash = 0, dropped = 0
        var starters = local.starterCollectionIDs
        for c in local.collections.sorted(by: { scalarOrder($0.id, $1.id) }) {
            if c.starter && !starters.contains(c.id) { starters.append(c.id) }
            let sid = CollectionStates.catalogPrefix + c.id
            if records[sid] != nil { continue }
            let taken = collections(in: StoreSnapshot(records: records)).map(\.name)
            // An old name that strips to nothing (the Mac checked it before stripping) gets a plain one.
            let stripped = Normalise.pyStrip(c.name)
            let name = uniqueName(stripped.unicodeScalars.isEmpty ? "Collection" : stripped, taken: taken)
            if !same(name, c.name) { renamed += 1 }
            records[sid] = try catalogWrapper(id: c.id, name: name, description: c.description, createdAt: c.createdAt,
                                              updatedAt: max(c.updatedAt, c.createdAt))
            added += 1
        }
        // Where each deleted item's rows are (an item can be deleted more than once).
        var trashed: [String: [Int]] = [:]
        for (i, row) in local.trash.enumerated() {
            if case .object(let r)? = try? row.record(), case .string(let id)? = r["id"] { trashed[id.lowercased(), default: []].append(i) }
        }
        let live = snapshot.itemRecords
        for item in local.memberships.keys.sorted(by: scalarOrder) {
            let ids = ShareKeyring.sortedIDs(local.memberships[item] ?? [])
            if ids.isEmpty { continue }
            if let wrapper = live[item], snapshot.meta[item]?.deleted != true {
                guard case .object(let w) = wrapper, w["ns"] == .string(Namespace.item.rawValue) else { dropped += 1; continue }
                guard let merged = CollectionStates.union(ids, memberships(of: item, records: records)) else { dropped += 1; continue }
                records[CollectionStates.membershipPrefix + item] = try membershipWrapper(itemID: item, ids: merged)
                moved += 1
            } else if let rows = trashed[item] {
                // Only typed items keep collections (a login's row never gets them); counted once per item.
                var kept = false
                for i in rows {
                    guard case .object(var r)? = try? out.trash[i].record(), case .string(let kind)? = r["kind"],
                          !CollectionCatalog.loginKinds.contains(kind),
                          let merged = CollectionStates.union(ids, strings(r["collection_ids"])) else { continue }
                    r["collection_ids"] = .array(merged.map { .string($0) })
                    out.trash[i] = try LocalData.TrashRow(record: .object(r), deletedAt: out.trash[i].deletedAt)
                    kept = true
                }
                if kept { toTrash += 1 } else { dropped += 1 }
            } else {
                dropped += 1
            }
        }
        out.collections = []
        out.memberships = [:]
        out.starterCollectionIDs = starters.filter { records[CollectionStates.catalogPrefix + $0] != nil }
        let storeChange: StoreChange? = records == snapshot.records ? nil : change(snapshot, records)
        return Migration(change: storeChange, local: out, collections: added, renamed: renamed, memberships: moved,
                         trashMemberships: toTrash, dropped: dropped)
    }

    // MARK: - Rules

    /// The stored name (Python `strip`), or why it can't be used: 1...100 code points, unique ignoring case.
    public static func checkedName(_ raw: String, among existing: [Collection], except id: String?) throws -> String {
        guard !raw.unicodeScalars.contains("\u{0}") else { throw Failure.invalidText }
        let name = Normalise.pyStrip(raw)
        guard !name.unicodeScalars.isEmpty else { throw Failure.emptyName }
        guard name.unicodeScalars.count <= CollectionStates.maxName else { throw Failure.longName }
        let folded = Casefold.fold(name)
        if existing.contains(where: { c in !(id.map { same($0, c.id) } ?? false) && same(Casefold.fold(c.name), folded) }) {
            throw Failure.duplicateName
        }
        return name
    }

    static func checkDescription(_ d: String) throws {
        guard !d.unicodeScalars.contains("\u{0}") else { throw Failure.invalidText }
        guard d.unicodeScalars.count <= CollectionStates.maxDescription else { throw Failure.longDescription }
    }

    /// `name`, or `name` with the first free " (n)" suffix (desktop `_unique_name`).
    static func uniqueName(_ name: String, taken: [String]) -> String {
        let used = Set(taken.map { Array(Casefold.fold($0).unicodeScalars.map(\.value)) })
        func key(_ s: String) -> [UInt32] { Array(Casefold.fold(s).unicodeScalars.map(\.value)) }
        var candidate = name
        var n = 2
        while used.contains(key(candidate)) {
            let suffix = " (\(n))"
            let head = String(String.UnicodeScalarView(name.unicodeScalars.prefix(CollectionStates.maxName - suffix.unicodeScalars.count)))
            candidate = pyRStrip(head) + suffix
            n += 1
        }
        return candidate
    }

    static func pyRStrip(_ s: String) -> String {
        var a = Array(s.unicodeScalars)
        while let l = a.last, Origin.isPySpace(l) { a.removeLast() }
        return String(String.UnicodeScalarView(a))
    }

    // MARK: - Helpers

    static func same(_ a: String, _ b: String) -> Bool { Array(a.utf8) == Array(b.utf8) }

    static func strings(_ v: JSONValue?) -> [String] {
        guard case .array(let a)? = v else { return [] }
        return a.compactMap { if case .string(let s) = $0 { return s }; return nil }
    }

    /// The checked record of the collection state `id` stored as `wrapper`, or nil.
    static func checked(_ id: String, _ wrapper: JSONValue) -> [String: JSONValue]? {
        guard case .object(let w) = wrapper, w["ns"] == .string(CollectionStates.namespace) else { return nil }
        return try? CollectionStates.checkRecord(id, w["record"])
    }

    static func memberships(of itemID: String, records: [String: JSONValue]) -> [String] {
        let sid = CollectionStates.membershipPrefix + itemID
        guard let w = records[sid], let r = checked(sid, w) else { return [] }
        return strings(r["collection_ids"])
    }

    static func catalogWrapper(id: String, name: String, description: String, createdAt: Int64,
                               updatedAt: Int64) throws -> JSONValue {
        let record = CollectionStates.catalog(collectionID: id, name: name, description: description, createdAt: createdAt,
                                              updatedAt: updatedAt)
        try CollectionStates.checkRecord(CollectionStates.catalogPrefix + id, record)
        return CollectionStates.wrapper(record)
    }

    /// The membership wrapper, or nil (no record) for no collection.
    static func membershipWrapper(itemID: String, ids: [String]) throws -> JSONValue? {
        if ids.isEmpty { return nil }
        let record = CollectionStates.membership(itemID: itemID, collectionIDs: ids)
        try CollectionStates.checkRecord(CollectionStates.membershipPrefix + itemID, record)
        return CollectionStates.wrapper(record)
    }

    static func change(_ snapshot: StoreSnapshot, _ records: [String: JSONValue]) -> StoreChange {
        StoreChange(baseRevision: snapshot.revision, records: records, meta: snapshot.meta, sync: snapshot.sync)
    }
}

/// Runs the Mac migration once (sub-plan 07): the store is committed first, then the local data is saved without its
/// collections.
///
/// - The store commit fails: nothing changed; `local` and the saved copy keep the old collections.
/// - The store commit works: `local` (the host's in-memory copy) is replaced by the cleared copy at once, before the
///   save, so a failed save never leaves the old collections in memory where a later local write (a trash row, an
///   event) would write them back and a later run would bring back what the person deleted or removed meanwhile.
///   The host keeps using `local` for every later write (the next successful one stores the cleared copy); a run
///   from the still-old saved copy before that only merges into the store (`migrate`).
/// - The store commit also writes the "migration done" marker (`StoreSnapshot.collectionsMigrated`), so once it is
///   there the store is never merged into again: a run from a local data file that still holds the old collections
///   (the app quit before any later local write) only clears that copy, and a collection deleted meanwhile stays
///   deleted. Nothing to move writes no marker (no commit at all).
public enum CollectionMigration {
    /// Nil when there was nothing to move (also when the marker says it was moved before; the local copy is then only
    /// cleared and saved).
    @discardableResult
    public static func run(store: any ItemStore, local: inout LocalData,
                           saveLocal: (LocalData) throws -> Void) throws -> CollectionCatalog.Migration? {
        let snapshot = try store.load()
        guard let m = try CollectionCatalog.migrate(from: local, into: snapshot) else { return nil }
        if snapshot.collectionsMigrated {
            // Moved before: the store already holds what this copy has, and may have changed since. Only the local copy
            // is cleared (its Recently deleted rows keep their collections, as `migrate` wrote them).
            local = m.local
            try saveLocal(m.local)
            return nil
        }
        var change = m.change ?? StoreChange(baseRevision: snapshot.revision, records: snapshot.records,
                                             meta: snapshot.meta, sync: snapshot.sync)
        change.collectionsMigrated = true
        try store.commit(change)
        local = m.local
        try saveLocal(m.local)
        return m
    }
}

extension CollectionStates {
    /// A collection state as stored: a reserved id (`col:`/`cm:`/`csl:`), or a wrapper of namespace `collection`.
    public static func isReserved(_ id: String, _ wrapper: JSONValue?) -> Bool {
        if isStateID(id) { return true }
        if case .object(let w)? = wrapper, w["ns"] == .string(namespace) { return true }
        return false
    }
}

extension StoreSnapshot {
    /// Every stored record but the collection states: what item lists, search, counts, AutoFill, Safari, the Watch,
    /// the security check, exports, backups, restores and the trash read (sub-plan 07 "Storage design").
    public var itemRecords: [String: JSONValue] {
        records.filter { !CollectionStates.isReserved($0.key, $0.value) }
    }
}
