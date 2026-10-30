import Foundation

/// Data that stays on this Mac and never syncs: Recently deleted, activity history, reminders and collections.
/// Schemas and limits follow the desktop app (`item_schema.py`, `activity.py`, `vault.py`, `settings.py`).
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
    public var collections: [Collection]
    public var preferences: LocalPreferences
    /// Collection memberships, item id → collection ids. The desktop keeps `collection_ids` on the typed record
    /// but never syncs it (`vault_bridge.py`), and the synced store's normal form drops the field, so on the Mac
    /// memberships live here, keyed by item id. Ids of collections this Mac doesn't know are kept, never shown.
    public var memberships: [String: [String]]

    /// Most items that can carry memberships at once (the trash bound).
    public static let maxMembershipItems = 20_000

    public init(trash: [TrashRow] = [], events: [ActivityEvent] = [], reminders: [Reminder] = [],
                collections: [Collection] = [], preferences: LocalPreferences = LocalPreferences(),
                memberships: [String: [String]] = [:]) {
        self.trash = trash; self.events = events; self.reminders = reminders
        self.collections = collections; self.preferences = preferences; self.memberships = memberships
    }

    enum CodingKeys: String, CodingKey { case trash, events, reminders, collections, preferences, memberships }

    /// Files written before memberships existed have no `memberships` key.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        trash = try c.decode([TrashRow].self, forKey: .trash)
        events = try c.decode([ActivityEvent].self, forKey: .events)
        reminders = try c.decode([Reminder].self, forKey: .reminders)
        collections = try c.decode([Collection].self, forKey: .collections)
        preferences = try c.decode(LocalPreferences.self, forKey: .preferences)
        memberships = try c.decodeIfPresent([String: [String]].self, forKey: .memberships) ?? [:]
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
        public init(id: String, eventType: String, timestamp: Int64, itemID: String? = nil, result: String = "ok",
                    count: Int64 = 0) {
            self.id = id; self.eventType = eventType; self.timestamp = timestamp
            self.itemID = itemID; self.result = result; self.count = count
        }
        enum CodingKeys: String, CodingKey {
            case id, eventType = "event_type", timestamp, itemID = "item_id", result, count
        }

        public static let domains: Set<String> = [
            "activity", "attachment", "auth", "backup", "collection", "credential",
            "document", "import", "item", "reminder", "session", "settings", "template", "vault",
        ]
        public static let actions: Set<String> = [
            "add", "backup", "change", "check", "clear", "close", "complete", "copy",
            "create", "delete", "deny", "export", "fill", "import", "lock", "open",
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

    /// Keeps the last 90 days of events, at most 5,000 (the newest).
    public mutating func trimEvents(now: Int64) {
        let cutoff = now - Self.eventRetentionDays * 86_400
        events.removeAll { $0.timestamp < cutoff }
        if events.count > Self.maxEvents { events.removeFirst(events.count - Self.maxEvents) }
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

