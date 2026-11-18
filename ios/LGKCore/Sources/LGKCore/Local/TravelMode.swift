import Foundation

/// Travel mode (feature pack contract §2): hide chosen collections and tags on this device only. Never synced
/// (`LocalData.travelMode`, key `travel_mode`), never removes anything: hidden items keep syncing both ways.
///
/// `hidden(record) = on && ((typed item && any collection of the item ∈ collections) || any fold(tag) ∈ fold(tags))`.
/// Logins never belong to collections, so they are hidden by tag only (a stale collection on an old login row is
/// ignored).
public struct TravelMode: Codable, Sendable, Equatable {
    public static let maxCollections = 20
    public static let maxTags = 20

    public var on: Bool
    /// Canonical lower-case UUIDs of `col:` collections; unknown ids are kept and ignored.
    public var collections: [String]
    /// Normalised with the tag rules (`Normalise.tags`); compared with `fold`.
    public var tags: [String]
    /// When it was last turned on (Unix seconds).
    public var since: Int64
    /// The stored setting could not be read (scan 2026-11-15 S-L4): while on, every item is hidden (fail closed).
    /// Written as `unreadable: true` only when set, and cleared when travel mode is turned off.
    public var unreadable: Bool

    public init(on: Bool = false, collections: [String] = [], tags: [String] = [], since: Int64 = 0,
                unreadable: Bool = false) {
        self.on = on; self.collections = collections; self.tags = tags; self.since = since
        self.unreadable = unreadable
    }

    public static let off = TravelMode()

    /// The setting used when the stored one exists but can't be read: on, hiding every item until the owner turns
    /// travel mode off (which needs the owner check, as always).
    public static let unreadableSetting = TravelMode(on: true, unreadable: true)

    private enum CodingKeys: String, CodingKey { case on, collections, tags, since, unreadable }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        on = try c.decode(Bool.self, forKey: .on)
        collections = try c.decode([String].self, forKey: .collections)
        tags = try c.decode([String].self, forKey: .tags)
        since = try c.decode(Int64.self, forKey: .since)
        unreadable = try c.decodeIfPresent(Bool.self, forKey: .unreadable) ?? false
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(on, forKey: .on)
        try c.encode(collections, forKey: .collections)
        try c.encode(tags, forKey: .tags)
        try c.encode(since, forKey: .since)
        if unreadable { try c.encode(true, forKey: .unreadable) }
    }

    /// One item as the rule sees it (the vectors' neutral input `{id, kind, tags, collections}`).
    public struct Subject: Equatable, Sendable {
        public let id: String
        public let kind: String
        public let tags: [String]
        public let collections: [String]
        public init(id: String, kind: String, tags: [String], collections: [String]) {
            self.id = id; self.kind = kind; self.tags = tags; self.collections = collections
        }
    }

    static let loginKinds: Set<String> = ["web", "desktop"]

    /// `TravelMode.hiddenIDs`: the ids the setting hides; empty when it is off.
    public func hiddenIDs(_ subjects: [Subject]) -> Set<String> {
        guard on else { return [] }
        if unreadable { return Set(subjects.map(\.id)) }
        let wantedCollections = Set(collections.map { $0.lowercased() })
        let wantedTags = Set(tags.map(RecordDigest.foldKey))
        var out = Set<String>()
        for s in subjects {
            let byCollection = !Self.loginKinds.contains(s.kind)
                && s.collections.contains { wantedCollections.contains($0.lowercased()) }
            let byTag = s.tags.contains { wantedTags.contains(RecordDigest.foldKey($0)) }
            if byCollection || byTag { out.insert(s.id) }
        }
        return out
    }

    /// The live records of `snapshot` this setting hides (memberships from `CollectionCatalog`).
    public func hiddenIDs(in snapshot: StoreSnapshot) -> Set<String> {
        guard on else { return [] }
        return hiddenIDs(Self.subjects(in: snapshot))
    }

    /// The ids of the Recently deleted records this setting hides. Each row is checked on its own record, whose
    /// memberships ride along as `collection_ids` (Windows `hidden_id_set` checks its trash entries the same way).
    public func hiddenIDs(trashRecords records: [JSONValue]) -> Set<String> {
        guard on else { return [] }
        return hiddenIDs(records.compactMap { value -> Subject? in
            guard case .object(let r) = value, case .string(let id)? = r["id"], !id.isEmpty else { return nil }
            return Self.subject(id: id, record: r, collections: CollectionCatalog.strings(r["collection_ids"]))
        })
    }

    /// Every live item of `snapshot` as a `Subject` (licences and collection states left out).
    public static func subjects(in snapshot: StoreSnapshot) -> [Subject] {
        snapshot.itemRecords.compactMap { id, wrapper in
            guard snapshot.meta[id]?.deleted != true, case .object(let w) = wrapper,
                  w["ns"] != .string(Namespace.license.rawValue), case .object(let r)? = w["record"],
                  case .string? = r["kind"] else { return nil }
            return subject(id: id, record: r, collections: CollectionCatalog.memberships(of: id, in: snapshot))
        }
    }

    /// A record as a `Subject`, with its memberships given by the caller.
    public static func subject(id: String, record: [String: JSONValue], collections: [String]) -> Subject {
        let kind: String = if case .string(let k)? = record["kind"] { k } else { "" }
        let tags: [String] = if case .array(let a)? = record["tags"] {
            a.compactMap { if case .string(let s) = $0 { return s }; return nil }
        } else { [] }
        return Subject(id: id, kind: kind, tags: tags, collections: collections)
    }

    /// The setting checked for saving: at most 20 canonical collection ids (duplicates dropped) and at most 20 tags
    /// through the tag rules.
    public func validated() throws -> TravelMode {
        var out = self
        guard collections.count <= Self.maxCollections else { throw LocalDataError.invalid("travel mode lists too many collections") }
        var seen = Set<String>()
        out.collections = try collections.compactMap { id in
            let u: String
            do { u = try Normalise.uuid(.string(id), "travel collection id") } catch { throw LocalDataError.invalid("travel collection id is malformed") }
            return seen.insert(u).inserted ? u : nil
        }
        do { out.tags = try Normalise.tags(tags) } catch { throw LocalDataError.invalid("travel tags are malformed") }
        guard out.tags.count <= Self.maxTags else { throw LocalDataError.invalid("travel mode lists too many tags") }
        guard since >= 0 else { throw LocalDataError.invalid("travel mode time is malformed") }
        if !out.on { out.unreadable = false }   // turned off: the next turn on starts from the chosen set
        return out
    }

    /// Whether changing from `self` to `next` can show an item `self` hides (scan 2026-11-15 W-M2 / S-M4): travel mode
    /// goes off, or a collection or tag leaves the hidden set while it stays on. Such a change needs the same owner
    /// check as turning it off. Compared on the setting rather than on today's items, so an item with a dropped tag
    /// that syncs in later is covered too.
    public func revealsHidden(to next: TravelMode) -> Bool {
        guard on else { return false }
        guard next.on else { return true }
        if unreadable && !next.unreadable { return true }
        let nextCollections = Set(next.collections.map { $0.lowercased() })
        if collections.contains(where: { !nextCollections.contains($0.lowercased()) }) { return true }
        let nextTags = Set(next.tags.map(RecordDigest.foldKey))
        return tags.contains { !nextTags.contains(RecordDigest.foldKey($0)) }
    }

    /// Whether changing from `self` to `next` needs Pro: turning on or changing the set does; turning off never does.
    public func changeNeedsPro(to next: TravelMode) -> Bool {
        if !next.on { return false }
        return next != self
    }
}
