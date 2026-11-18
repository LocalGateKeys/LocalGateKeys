import Foundation

/// Data that stays on this device and never syncs: Recently deleted, activity history, reminders and which collections
/// are starters. Schemas and limits follow the desktop app (`item_schema.py`, `activity.py`, `vault.py`, `settings.py`).
///
/// Collections and memberships live in the item store since sub-plan 07 (`CollectionCatalog`). `collections` and
/// `memberships` are the Mac's older local copies: read only by `CollectionCatalog.migrate`, which empties them.
public struct LocalData: Codable, Sendable, Equatable {
    public static let maxTrash = 20_000
    public static let maxEvents = 5_000
    public static let eventRetentionDays: Int64 = 90
    public static let maxReminders = 20_000
    public static let maxCollections = 500
    public static let maxCollectionName = 100
    public static let maxCollectionDescription = 500
    public static let maxCollectionMemberships = 20
    public static let starterCollections = ["Personal", "Work", "Travel", "Emergency"]

    public var trash: [TrashRow]
    public var events: [ActivityEvent]
    public var reminders: [Reminder]
    /// The Mac's collections from before sub-plan 07 (now `col:` records in the store): read for migration only.
    public var collections: [Collection]
    public var preferences: LocalPreferences
    /// The Mac's memberships from before sub-plan 07, item id → collection ids (now `cm:` records in the store):
    /// read for migration only (`CollectionCatalog.migrate`).
    public var memberships: [String: [String]]
    /// The store collections (`col:` ids) this device made as starters (`CollectionCatalog.starters`, Windows
    /// `starter`): the flag never syncs, so it stays here.
    public var starterCollectionIDs: [String]
    /// The access log chain (`activity.py` `events_chain`): the checkpoint left by pruning and the newest hash.
    /// nil in files written before the chain existed.
    public var eventsChain: EventsChain?
    /// Item history (feature pack §1): snapshots of replaced versions, pruned with `ItemHistory.prune`. Key
    /// `item_history`; never synced, not in phone backups.
    public var itemHistory: [ItemHistory.Row]
    /// Travel mode (feature pack §2), key `travel_mode`; nil when it was never set.
    public var travelMode: TravelMode?
    /// The last import's undo journal (feature pack §6.1), key `last_import`.
    public var lastImport: ImportJournal?
    /// Passkey upgrade prompt dismissals (feature pack §6.3): registrable domain → Unix seconds.
    public var passkeyUpgradeDismissed: [String: Int64]

    /// Most items that can carry memberships at once (the trash bound).
    public static let maxMembershipItems = 20_000

    public init(trash: [TrashRow] = [], events: [ActivityEvent] = [], reminders: [Reminder] = [],
                collections: [Collection] = [], preferences: LocalPreferences = LocalPreferences(),
                memberships: [String: [String]] = [:], starterCollectionIDs: [String] = [],
                eventsChain: EventsChain? = nil, itemHistory: [ItemHistory.Row] = [], travelMode: TravelMode? = nil,
                lastImport: ImportJournal? = nil, passkeyUpgradeDismissed: [String: Int64] = [:]) {
        self.trash = trash; self.events = events; self.reminders = reminders
        self.collections = collections; self.preferences = preferences; self.memberships = memberships
        self.starterCollectionIDs = starterCollectionIDs
        self.eventsChain = eventsChain
        self.itemHistory = itemHistory; self.travelMode = travelMode; self.lastImport = lastImport
        self.passkeyUpgradeDismissed = passkeyUpgradeDismissed
    }

    enum CodingKeys: String, CodingKey {
        case trash, events, reminders, collections, preferences, memberships
        case starterCollectionIDs = "starter_collection_ids"
        case eventsChain = "events_chain"
        case itemHistory = "item_history", travelMode = "travel_mode", lastImport = "last_import"
        case passkeyUpgradeDismissed = "passkey_upgrade_dismissed"
    }

    /// Files written before memberships (or starter ids) existed have no such key.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        trash = try c.decode([TrashRow].self, forKey: .trash)
        events = try c.decode([ActivityEvent].self, forKey: .events)
        reminders = try c.decode([Reminder].self, forKey: .reminders)
        collections = try c.decode([Collection].self, forKey: .collections)
        preferences = try c.decode(LocalPreferences.self, forKey: .preferences)
        memberships = try c.decodeIfPresent([String: [String]].self, forKey: .memberships) ?? [:]
        starterCollectionIDs = try c.decodeIfPresent([String].self, forKey: .starterCollectionIDs) ?? []
        eventsChain = try c.decodeIfPresent(EventsChain.self, forKey: .eventsChain)
        // Feature pack 2026-11-15: files from older builds have none of these. A damaged travel setting or import
        // journal never blocks the rest of the local data.
        itemHistory = try c.decodeIfPresent([ItemHistory.Row].self, forKey: .itemHistory) ?? []
        // A travel setting that is there but can't be read hides every item (scan 2026-11-15 S-L4: fail closed).
        do {
            travelMode = try c.decodeIfPresent(TravelMode.self, forKey: .travelMode)
        } catch {
            travelMode = .unreadableSetting
        }
        lastImport = try? c.decodeIfPresent(ImportJournal.self, forKey: .lastImport)
        passkeyUpgradeDismissed = (try? c.decodeIfPresent([String: Int64].self, forKey: .passkeyUpgradeDismissed)) ?? [:]
    }

    /// The travel setting in force (off when never set).
    public var travel: TravelMode { travelMode ?? .off }

    /// Most history rows kept at once whatever the plan (a bound on a damaged file).
    public static let maxHistoryRows = 20_000

    /// `{checkpoint, head}`: each a 64-hex SHA-256 or nil.
    public struct EventsChain: Codable, Sendable, Equatable {
        public var checkpoint: String?
        public var head: String?
        public init(checkpoint: String? = nil, head: String? = nil) { self.checkpoint = checkpoint; self.head = head }
    }

    public static let empty = LocalData()

    // MARK: - Rows

    /// One Recently deleted row: the full record as stored, kept as its canonical JSON text (UTF-8, as the
    /// desktop writes it) so a restore gives back exactly the same bytes; and when it was deleted (Unix seconds).
    public struct TrashRow: Codable, Sendable, Equatable {
        public var recordJSON: String
        public var deletedAt: Int64
        public init(record: JSONValue, deletedAt: Int64) throws {
            self.recordJSON = String(decoding: try CanonicalJSON.encode(record, dialect: .utf8), as: UTF8.self)
            self.deletedAt = deletedAt
        }
        public init(recordJSON: String, deletedAt: Int64) { self.recordJSON = recordJSON; self.deletedAt = deletedAt }
        /// The deleted record, parsed back with the canonical parser.
        public func record() throws -> JSONValue { try CanonicalJSON.parse(Array(recordJSON.utf8)) }
        enum CodingKeys: String, CodingKey { case recordJSON = "record", deletedAt = "deleted_at" }
    }

    /// A content-free activity event (`activity.py`): "domain.action", a result word and a count, never content.
    public struct ActivityEvent: Codable, Sendable, Equatable {
        public var id: String
        public var eventType: String
        public var timestamp: Int64
        public var itemID: String?
        public var result: String
        public var count: Int64
        /// SHA-256 of the previous event's canonical JSON (`ActivityChain`); nil for events from older builds.
        public var prevHash: String?
        public init(id: String, eventType: String, timestamp: Int64, itemID: String? = nil, result: String = "ok",
                    count: Int64 = 0, prevHash: String? = nil) {
            self.id = id; self.eventType = eventType; self.timestamp = timestamp
            self.itemID = itemID; self.result = result; self.count = count; self.prevHash = prevHash
        }
        enum CodingKeys: String, CodingKey {
            case id, eventType = "event_type", timestamp, itemID = "item_id", result, count, prevHash = "prev_hash"
        }
        /// The event as the chain hashes it.
        public var chainEvent: ActivityChain.Event {
            ActivityChain.Event(id: id, eventType: eventType, timestamp: timestamp, itemID: itemID, result: result,
                                count: count, prevHash: prevHash)
        }

        public static let domains: Set<String> = [
            "activity", "agent", "attachment", "auth", "backup", "collection", "credential",
            "document", "import", "item", "reminder", "session", "settings", "template", "vault",
        ]
        public static let actions: Set<String> = [
            "add", "backup", "change", "check", "clear", "close", "complete", "copy",
            "create", "delete", "deny", "export", "fill", "import", "lock", "open", "request",
            "prune", "read", "restore", "reveal", "search", "signin", "sign_in",
            "snooze", "start", "stop", "test", "unlock", "update", "view",
        ]
        public static let results: Set<String> = [
            "cancelled", "canceled", "cleared", "completed", "conflict", "created", "deleted",
            "denied", "error", "failed", "failure", "locked", "missing", "not_found", "ok",
            "open", "present", "pruned", "skipped", "snoozed", "success", "updated",
        ]
        public static let forbiddenTokens: Set<String> = [
            "attachment_name", "body", "clipboard", "content", "license", "note", "password",
            "raw", "secret", "serial", "url", "username", "value",
        ]
    }

    public struct Reminder: Codable, Sendable, Equatable {
        public enum Status: String, Codable, Sendable { case pending, snoozed, dismissed }
        public var id: String
        public var itemID: String
        /// "YYYY-MM-DD".
        public var dueDate: String
        public var leadDays: Int
        public var status: Status
        /// "" or "YYYY-MM-DD".
        public var snoozeUntil: String
        public var lastNotified: String
        public init(id: String, itemID: String, dueDate: String, leadDays: Int = 0, status: Status = .pending,
                    snoozeUntil: String = "", lastNotified: String = "") {
            self.id = id; self.itemID = itemID; self.dueDate = dueDate; self.leadDays = leadDays
            self.status = status; self.snoozeUntil = snoozeUntil; self.lastNotified = lastNotified
        }
        enum CodingKeys: String, CodingKey {
            case id, itemID = "item_id", dueDate = "due_date", leadDays = "lead_days", status
            case snoozeUntil = "snooze_until", lastNotified = "last_notified"
        }
    }

    public struct Collection: Codable, Sendable, Equatable {
        public var id: String
        public var name: String
        public var description: String
        public var createdAt: Int64
        public var updatedAt: Int64
        public var revision: Int64
        public var starter: Bool
        public init(id: String, name: String, description: String = "", createdAt: Int64, updatedAt: Int64,
                    revision: Int64 = 1, starter: Bool = false) {
            self.id = id; self.name = name; self.description = description
            self.createdAt = createdAt; self.updatedAt = updatedAt; self.revision = revision; self.starter = starter
        }
        enum CodingKeys: String, CodingKey {
            case id, name, description, createdAt = "created_at", updatedAt = "updated_at", revision, starter
        }
    }

    public struct LocalPreferences: Codable, Sendable, Equatable {
        public var trashRetentionDays: Int
        public var trashAutoPurge: Bool
        public var reminderDefaultLeadDays: Int
        public init(trashRetentionDays: Int = 30, trashAutoPurge: Bool = true, reminderDefaultLeadDays: Int = 0) {
            self.trashRetentionDays = trashRetentionDays; self.trashAutoPurge = trashAutoPurge
            self.reminderDefaultLeadDays = reminderDefaultLeadDays
        }
        enum CodingKeys: String, CodingKey {
            case trashRetentionDays = "trash_retention_days", trashAutoPurge = "trash_auto_purge"
            case reminderDefaultLeadDays = "reminder_default_lead_days"
        }
    }

    // MARK: - Validation

    /// Checks every limit and returns a copy with ids re-rendered (lower-case UUIDs) and names stripped.
    public func validated() throws -> LocalData {
        do { return try validate() } catch let NormaliseError.rejected(detail) { throw LocalDataError.invalid(detail) }
    }

    private func validate() throws -> LocalData {
        var out = self
        // Trash
        guard trash.count <= Self.maxTrash else { throw LocalDataError.invalid("trash exceeds its limit") }
        for row in trash {
            guard case .object? = try? row.record() else { throw LocalDataError.invalid("trash record must be a JSON object") }
            guard row.deletedAt >= 0 else { throw LocalDataError.invalid("trash deleted_at is malformed") }
        }
        // Events
        guard events.count <= Self.maxEvents else { throw LocalDataError.invalid("activity history exceeds its bound") }
        out.events = try events.map { e in
            var e = e
            e.id = try Normalise.uuid(.string(e.id), "event id")
            if let item = e.itemID { e.itemID = try Normalise.uuid(.string(item), "event item id") }
            e.eventType = try Self.safeEventType(e.eventType)
            e.result = try Self.safeResult(e.result)
            guard (0...Int64(Int32.max)).contains(e.count) else { throw LocalDataError.invalid("activity event count is malformed") }
            guard e.timestamp >= 0 else { throw LocalDataError.invalid("event timestamp is malformed") }
            if let prev = e.prevHash, !Self.isHash(prev) { throw LocalDataError.invalid("event prev_hash is malformed") }
            return e
        }
        // Reminders
        guard reminders.count <= Self.maxReminders else { throw LocalDataError.invalid("reminders exceed the limit") }
        var seen = Set<String>()
        out.reminders = try reminders.map { r in
            var r = r
            r.id = try Normalise.uuid(.string(r.id), "reminder id")
            guard seen.insert(r.id).inserted else { throw LocalDataError.invalid("duplicate reminder IDs") }
            r.itemID = try Normalise.uuid(.string(r.itemID), "reminder item id")
            guard Self.isISODate(r.dueDate) else { throw LocalDataError.invalid("reminder due date is malformed") }
            guard (0...3650).contains(r.leadDays) else { throw LocalDataError.invalid("reminder lead_days is malformed") }
            guard r.snoozeUntil.isEmpty || Self.isISODate(r.snoozeUntil) else {
                throw LocalDataError.invalid("reminder snooze_until is malformed")
            }
            if !r.lastNotified.isEmpty { _ = try Normalise.text(.string(r.lastNotified), "reminder last_notified", 32, allowEmpty: false) }
            return r
        }
        // Collections
        guard collections.count <= Self.maxCollections else { throw LocalDataError.invalid("collections exceed the limit") }
        var ids = Set<String>(), names = Set<String>()
        out.collections = try collections.map { c in
            var c = c
            c.id = try Normalise.uuid(.string(c.id), "collection id")
            guard ids.insert(c.id).inserted else { throw LocalDataError.invalid("Duplicate collection IDs") }
            c.name = Normalise.pyStrip(try Normalise.text(.string(c.name), "collection name", Self.maxCollectionName, allowEmpty: false))
            guard names.insert(Casefold.fold(c.name)).inserted else { throw LocalDataError.invalid("Duplicate collection names") }
            _ = try Normalise.text(.string(c.description), "collection description", Self.maxCollectionDescription, allowEmpty: true)
            guard c.createdAt >= 0, c.updatedAt >= 0 else { throw LocalDataError.invalid("collection timestamp is malformed") }
            guard c.updatedAt >= c.createdAt else { throw LocalDataError.invalid("collection updated_at cannot precede created_at") }
            guard c.revision >= 1 else { throw LocalDataError.invalid("collection revision is malformed") }
            return c
        }
        // Memberships (empty lists are dropped)
        guard memberships.count <= Self.maxMembershipItems else { throw LocalDataError.invalid("memberships exceed the limit") }
        var kept: [String: [String]] = [:]
        for (item, ids) in memberships where !ids.isEmpty {
            let key = try Normalise.uuid(.string(item), "membership item id")
            guard kept[key] == nil else { throw LocalDataError.invalid("duplicate membership item IDs") }
            kept[key] = try Self.validatedMemberships(ids)
        }
        out.memberships = kept
        // Starter ids
        guard starterCollectionIDs.count <= Self.maxCollections else { throw LocalDataError.invalid("starter collections exceed the limit") }
        var starters = Set<String>()
        out.starterCollectionIDs = try starterCollectionIDs.compactMap { (id: String) -> String? in
            let u = try Normalise.uuid(.string(id), "starter collection id")
            return starters.insert(u).inserted ? u : nil
        }
        // Feature pack 2026-11-15
        guard itemHistory.count <= Self.maxHistoryRows else { throw LocalDataError.invalid("item history exceeds its bound") }
        for row in itemHistory {
            guard row.createdAt >= 0, row.ns == Namespace.entry.rawValue || row.ns == Namespace.item.rawValue else {
                throw LocalDataError.invalid("item history row is malformed")
            }
        }
        if let travel = travelMode { out.travelMode = try travel.validated() }
        guard passkeyUpgradeDismissed.count <= PasskeyUpgrade.maxEntries else {
            throw LocalDataError.invalid("passkey prompt dismissals exceed the limit")
        }
        // Preferences
        guard (1...365).contains(preferences.trashRetentionDays) else { throw LocalDataError.invalid("trash retention is malformed") }
        guard (0...3650).contains(preferences.reminderDefaultLeadDays) else {
            throw LocalDataError.invalid("reminder default lead days is malformed")
        }
        return out
    }

    /// `ActivityService._safe_event_type`: "domain.action" from the fixed vocabulary, no forbidden token.
    public static func safeEventType(_ value: String) throws -> String {
        let trimmed = Normalise.pyStrip(value)
        guard !trimmed.isEmpty, Normalise.len(value) <= 64 else { throw LocalDataError.invalid("activity event type is malformed") }
        let folded = Casefold.fold(trimmed)
        let parts = folded.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 2, ActivityEvent.domains.contains(parts[0]), ActivityEvent.actions.contains(parts[1]),
              !parts.contains(where: ActivityEvent.forbiddenTokens.contains) else {
            throw LocalDataError.invalid("activity event type cannot describe secret content")
        }
        return folded
    }

    public static func safeResult(_ value: String) throws -> String {
        let trimmed = Normalise.pyStrip(value)
        guard !trimmed.isEmpty, Normalise.len(value) <= 32, ActivityEvent.results.contains(Casefold.fold(trimmed)) else {
            throw LocalDataError.invalid("activity result is malformed")
        }
        return Casefold.fold(trimmed)
    }

    /// The per-item membership rule (`collection_ids` on typed items: at most 20, unique UUIDs). Items live in
    /// the synced store, so `validated()` can't see them; the item editor calls this before saving.
    public static func validatedMemberships(_ ids: [String]) throws -> [String] {
        guard ids.count <= maxCollectionMemberships else { throw LocalDataError.invalid("too many collections on one item") }
        var seen = Set<String>()
        return try ids.map { id in
            let u: String
            do { u = try Normalise.uuid(.string(id), "collection id") }
            catch let NormaliseError.rejected(d) { throw LocalDataError.invalid(d) }
            guard seen.insert(u).inserted else { throw LocalDataError.invalid("duplicate collection membership") }
            return u
        }
    }

    /// Strict "YYYY-MM-DD" that names a real calendar day.
    public static func isISODate(_ s: String) -> Bool {
        let u = Array(s.utf8)
        guard u.count == 10, u[4] == 0x2D, u[7] == 0x2D else { return false }
        let digits = u.enumerated().filter { $0.offset != 4 && $0.offset != 7 }.map(\.element)
        guard digits.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return false }
        guard let y = Int(s.prefix(4)), let m = Int(s.dropFirst(5).prefix(2)), let d = Int(s.suffix(2)),
              y >= 1, (1...12).contains(m), d >= 1 else { return false }
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        let days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]
        return d <= days
    }

    // MARK: - Housekeeping

    /// Drops Recently deleted rows older than the retention period, when auto-purge is on.
    public mutating func purgeExpiredTrash(now: Int64) {
        guard preferences.trashAutoPurge else { return }
        let days = Int64(min(max(preferences.trashRetentionDays, 1), 365))
        let cutoff = now - days * 86_400
        trash.removeAll { $0.deletedAt < cutoff }
    }

    /// Drops the item history of items deleted for good (scan 2026-11-15 W-M5, A-M3): rows whose item is neither live
    /// in `snapshot` nor in Recently deleted (purged, emptied, auto-purged, deleted with no trash, or a tombstone).
    /// Returns true when any row went. Run after every purge and at unlock, with the store's current snapshot.
    @discardableResult
    public mutating func forgetHistoryOfPurgedItems(_ snapshot: StoreSnapshot) -> Bool {
        guard !itemHistory.isEmpty else { return false }
        var keep = Set<String>()
        for row in trash {
            if case .object(let r)? = try? row.record(), case .string(let id)? = r["id"] { keep.insert(id) }
        }
        for id in snapshot.records.keys where snapshot.meta[id]?.deleted != true { keep.insert(id) }
        let before = itemHistory.count
        itemHistory.removeAll { !keep.contains($0.itemID) }
        return itemHistory.count != before
    }

    /// Keeps the last 90 days of events, at most 5,000 (the newest). Events go from the front only, and the
    /// chain checkpoint becomes the hash of the last one dropped (`activity.py` `_store`).
    public mutating func trimEvents(now: Int64) {
        let cutoff = now - Self.eventRetentionDays * 86_400
        var drop = events.prefix { $0.timestamp < cutoff }.count
        drop = max(drop, events.count - Self.maxEvents)
        guard drop > 0 else { return }
        let last = events[drop - 1]
        events.removeFirst(drop)
        if eventsChain != nil || last.prevHash != nil {
            var chain = eventsChain ?? EventsChain()
            chain.checkpoint = ActivityChain.hash(last.chainEvent)
            if events.isEmpty { chain.head = chain.checkpoint }
            eventsChain = chain
        }
    }

    /// Appends `event` linked to the newest one (or the checkpoint) and moves the head to it.
    public mutating func appendChained(_ event: ActivityEvent) {
        var e = event
        e.prevHash = ActivityChain.link(after: events.suffix(1).map(\.chainEvent), checkpoint: eventsChain?.checkpoint)
        events.append(e)
        var chain = eventsChain ?? EventsChain()
        chain.head = ActivityChain.hash(e.chainEvent)
        eventsChain = chain
    }

    /// The Security centre's "Access log verified" check.
    public func verifyEventsChain() -> ActivityChain.Report {
        ActivityChain.verify(events.map(\.chainEvent), checkpoint: eventsChain?.checkpoint, head: eventsChain?.head)
    }

    static func isHash(_ s: String) -> Bool {
        s.utf8.count == 64 && s.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }

    /// Adds the starter collections (Personal, Work, Travel, Emergency) that are missing by name.
    /// Returns true when anything was added.
    @discardableResult
    public mutating func ensureStarterCollections(now: Int64, newID: () -> String = { UUID().uuidString.lowercased() }) -> Bool {
        let existing = Set(collections.map { Casefold.fold($0.name) })
        var added = false
        for name in Self.starterCollections where !existing.contains(Casefold.fold(name)) {
            guard collections.count < Self.maxCollections else { break }
            collections.append(Collection(id: newID(), name: name, createdAt: now, updatedAt: now, starter: true))
            added = true
        }
        return added
    }
}

public enum LocalDataError: Error, Equatable, Sendable { case invalid(String) }

