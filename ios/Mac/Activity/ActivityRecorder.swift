import Foundation
import Observation
import LGKCore
import AppSharedMac

/// Where the Mac-local data lives while the vault is open (the lock model; tests use `InMemoryLocalData`).
@MainActor
protocol LocalDataHosting: AnyObject {
    /// The current data, nil while locked.
    var localData: LocalData? { get }
    /// Validates and saves `data`, then makes it current. Throws (and changes nothing) when it can't be saved.
    func commitLocalData(_ data: LocalData) throws
}

/// Local data kept in memory only (tests, and the debug window preview).
@MainActor @Observable
final class InMemoryLocalData: LocalDataHosting {
    private(set) var localData: LocalData?
    /// Tests: makes every save fail.
    @ObservationIgnored var failSaves = false
    init(_ data: LocalData? = LocalData()) { localData = data }
    func commitLocalData(_ data: LocalData) throws {
        if failSaves { throw LocalDataError.invalid("save failed") }
        localData = try data.validated()
    }
}

/// The one place the Mac writes activity history (`activity.py`): a fixed event type, a result word, a count
/// and at most an item id. Titles, usernames, passwords and other content are never passed in, so they can
/// never be stored. Recording is best effort: a failed save never blocks what the person did.
@MainActor
final class ActivityRecorder {
    /// The only events the Mac records.
    enum Event: String, CaseIterable, Sendable {
        case itemCreate = "item.create", itemUpdate = "item.update", itemDelete = "item.delete", itemRestore = "item.restore"
        /// Permanently deleted from Recently deleted.
        case itemClear = "item.clear"
        case credentialCopy = "credential.copy"
        /// Recovery codes, hidden custom field values or a previous password shown.
        case credentialReveal = "credential.reveal"
        case sessionUnlock = "session.unlock", sessionLock = "session.lock"
        case reminderCreate = "reminder.create", reminderUpdate = "reminder.update", reminderComplete = "reminder.complete"
        case reminderSnooze = "reminder.snooze", reminderDelete = "reminder.delete"
        case collectionCreate = "collection.create", collectionUpdate = "collection.update", collectionDelete = "collection.delete"
    }

    enum Result: String, Sendable { case ok, deleted, failed, cancelled }

    private weak var host: (any LocalDataHosting)?
    private let clock: () -> Date
    private let newID: () -> String

    init(host: any LocalDataHosting, clock: @escaping () -> Date = Date.init,
         newID: @escaping () -> String = { UUID().uuidString.lowercased() }) {
        self.host = host; self.clock = clock; self.newID = newID
    }

    /// Appends one event (keeping 90 days and at most 5,000) and saves. `itemID` is kept only when it is a UUID.
    func record(_ event: Event, itemID: String? = nil, result: Result = .ok, count: Int = 0) {
        guard let host, var data = host.localData else { return }
        let now = Int64(clock().timeIntervalSince1970)
        let item = itemID.flatMap { UUID(uuidString: $0) != nil ? $0.lowercased() : nil }
        data.events.append(LocalData.ActivityEvent(id: newID(), eventType: event.rawValue, timestamp: now, itemID: item,
                                                   result: result.rawValue, count: Int64(max(0, min(count, Int(Int32.max))))))
        data.trimEvents(now: now)
        try? host.commitLocalData(data)
    }
}

/// The Activity page's rows (`ActivityService.list`), newest first.
enum ActivityList {
    static let title = String(localized: "Activity history")
    static let subtitle = String(localized: "Only bounded event types, results, counts, and item IDs are shown; secrets are never logged.")
    static let emptyText = String(localized: "No activity yet.")

    struct Row: Identifiable, Equatable {
        let id: String
        let when: String
        let event: String
        let result: String
        let count: Int64
    }

    static func rows(_ events: [LocalData.ActivityEvent], timeZone: TimeZone = .current) -> [Row] {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_GB_POSIX")
        f.timeZone = timeZone
        f.dateFormat = "yyyy-MM-dd HH:mm"
        return events.reversed().map {
            Row(id: $0.id, when: f.string(from: Date(timeIntervalSince1970: TimeInterval($0.timestamp))),
                event: $0.eventType, result: $0.result, count: $0.count)
        }
    }
}
