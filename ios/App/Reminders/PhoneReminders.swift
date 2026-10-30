import Foundation
import Observation
import UserNotifications
import AppShared

/// Day arithmetic for reminders (the Mac `OverviewModel` helpers, Windows `reminders.py`): "YYYY-MM-DD" dates,
/// day numbers since 1970-01-01, effective date = due − lead (a snoozed one not before its snooze date).
enum ReminderDays {
    static func day(_ date: Date, calendar: Calendar = .current) -> String {
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }

    static func dayNumber(_ s: String) -> Int? {
        let parts = s.split(separator: "-")
        guard parts.count == 3, let y = Int(parts[0]), let m = Int(parts[1]), let d = Int(parts[2]) else { return nil }
        guard let date = utc.date(from: DateComponents(year: y, month: m, day: d)), utc.component(.day, from: date) == d else {
            return nil
        }
        return Int((date.timeIntervalSince1970 / 86_400).rounded(.down))
    }

    static func text(day: Int) -> String {
        let c = utc.dateComponents([.year, .month, .day], from: Date(timeIntervalSince1970: TimeInterval(day) * 86_400))
        return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }

    static func effectiveDay(_ r: LocalData.Reminder) -> Int? {
        guard var day = dayNumber(r.dueDate) else { return nil }
        day -= r.leadDays
        if r.status == .snoozed, let snooze = dayNumber(r.snoozeUntil) { day = max(day, snooze) }
        return day
    }

    /// The last day of a card's "MM/YY" (or "MM/YYYY") expiry month, nil when it isn't one.
    static func cardExpiryDay(_ expiry: String) -> String? {
        let parts = expiry.replacingOccurrences(of: " ", with: "").split(separator: "/")
        guard parts.count == 2, let m = Int(parts[0]), (1...12).contains(m), var y = Int(parts[1]) else { return nil }
        if parts[1].count == 2 { y += 2000 } else if parts[1].count != 4 { return nil }
        guard let first = utc.date(from: DateComponents(year: y, month: m, day: 1)),
              let range = utc.range(of: .day, in: .month, for: first) else { return nil }
        return String(format: "%04d-%02d-%02d", y, m, range.count)
    }

    private static var utc: Calendar {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        return c
    }
}

/// The notification centre as the reminders see it (tests use a fake).
@MainActor
protocol PhoneNotificationScheduling: AnyObject {
    func requestAuthorization() async -> Bool
    func isDenied() async -> Bool
    func pendingIdentifiers() async -> [String]
    func add(identifier: String, body: String, fireAt: DateComponents?) async throws
    func removePending(identifiers: [String])
}

@MainActor
final class PhoneNotificationCentre: PhoneNotificationScheduling {
    private var centre: UNUserNotificationCenter { .current() }
    func requestAuthorization() async -> Bool { (try? await centre.requestAuthorization(options: [.alert, .sound])) ?? false }
    func isDenied() async -> Bool { await centre.notificationSettings().authorizationStatus == .denied }
    func pendingIdentifiers() async -> [String] { await centre.pendingNotificationRequests().map(\.identifier) }
    func add(identifier: String, body: String, fireAt: DateComponents?) async throws {
        let content = UNMutableNotificationContent()
        content.title = "LocalGateKeys"
        content.body = body
        content.sound = .default
        let trigger: UNNotificationTrigger = fireAt.map { UNCalendarNotificationTrigger(dateMatching: $0, repeats: false) }
            ?? UNTimeIntervalNotificationTrigger(timeInterval: 5, repeats: false)
        try await centre.add(UNNotificationRequest(identifier: identifier, content: content, trigger: trigger))
    }
    func removePending(identifiers: [String]) { centre.removePendingNotificationRequests(withIdentifiers: identifiers) }
}

/// Expiry reminders on the iPhone (UX plan workstream 10), the Mac `RemindersModel` rules on the shared
/// `LocalData.reminders`: content-free rows (item id, due date, lead days, state) for typed items, never logins
/// (Windows' rule). Each change re-plans one local notification per active reminder at 09:00 on its effective
/// date. Notification text never holds a secret, and names the item only when Settings says so (off by default).
@MainActor @Observable
final class PhoneReminders {
    struct Row: Identifiable, Equatable {
        let id: String
        let itemID: String
        let title: String
        let due: String
        let effectiveDay: Int
        let overdue: Bool
    }

    nonisolated static let prefix = "lgk.reminder."
    nonisolated static let hour = 9
    nonisolated static var anonymousBody: String { String(localized: "A reminder is due") }
    nonisolated static var saveFailedText: String { String(localized: "The reminder could not be saved on this iPhone.") }
    nonisolated static let leadChoices = [0, 1, 7, 14, 30, 60, 90]

    enum Failure: Error, Equatable { case locked, notTyped, invalidDate, save }

    /// The vault's live items (kept current by the app).
    var items: [VaultItem] = [] { didSet { if oldValue != items { reschedule() } } }
    private(set) var message: String?
    private(set) var notificationsDenied = false

    @ObservationIgnored private let local: any PhoneLocalHosting
    @ObservationIgnored private let centre: (any PhoneNotificationScheduling)?
    @ObservationIgnored private let settings: AppSettings
    @ObservationIgnored private let clock: () -> Date
    @ObservationIgnored private let calendar: Calendar
    @ObservationIgnored private let newID: () -> String
    @ObservationIgnored private var scheduling: Task<Void, Never>?

    init(local: any PhoneLocalHosting, centre: (any PhoneNotificationScheduling)?, settings: AppSettings = .shared,
         clock: @escaping () -> Date = Date.init, calendar: Calendar = .current,
         newID: @escaping () -> String = { UUID().uuidString.lowercased() }) {
        self.local = local; self.centre = centre; self.settings = settings; self.clock = clock
        self.calendar = calendar; self.newID = newID
    }

    var today: String { ReminderDays.day(clock(), calendar: calendar) }

    nonisolated static func canHaveReminder(_ item: VaultItem) -> Bool { !item.isLogin }

    nonisolated static func body(title: String, showNames: Bool) -> String {
        showNames && !title.isEmpty ? String(localized: "\(title) is due") : anonymousBody
    }

    private var stored: [LocalData.Reminder] {
        let live = Set(items.filter(Self.canHaveReminder).map(\.id))
        return (local.localData?.reminders ?? []).filter { live.contains($0.itemID) }
    }

    /// Overdue first, then upcoming within `days` (default: ten years), by effective date.
    func rows(within days: Int = 3650) -> [Row] {
        guard let t = ReminderDays.dayNumber(today) else { return [] }
        let titles = Dictionary(items.map { ($0.id, $0.title.isEmpty ? $0.kindLabel : $0.title) }, uniquingKeysWith: { a, _ in a })
        return stored.compactMap { r -> Row? in
            guard r.status != .dismissed, let e = ReminderDays.effectiveDay(r), e <= t + days else { return nil }
            return Row(id: r.id, itemID: r.itemID, title: titles[r.itemID] ?? String(localized: "Item"), due: r.dueDate, effectiveDay: e, overdue: e < t)
        }
        .sorted { ($0.effectiveDay, $0.id) < ($1.effectiveDay, $1.id) }
    }

    func reminder(for itemID: String) -> LocalData.Reminder? {
        stored.first { $0.itemID == itemID && $0.status != .dismissed }
    }

    /// A card's suggested due date (the last day of its expiry month), when it has no reminder yet.
    func suggestion(for item: VaultItem) -> String? {
        guard item.kind == "card", reminder(for: item.id) == nil,
              let expiry = item.record["payload"]?.objectValue?["expiry"]?.stringValue ?? item.record["expiry"]?.stringValue,
              let day = ReminderDays.cardExpiryDay(expiry), let n = ReminderDays.dayNumber(day),
              let t = ReminderDays.dayNumber(today), n >= t else { return nil }
        return day
    }

    // MARK: changes

    /// Adds a reminder, or replaces the item's active one.
    func set(itemID: String, dueDate: String, leadDays: Int) throws {
        guard var data = local.localData else { throw Failure.locked }
        guard let item = items.first(where: { $0.id == itemID }), Self.canHaveReminder(item) else { throw Failure.notTyped }
        guard ReminderDays.dayNumber(dueDate) != nil else { throw Failure.invalidDate }
        data.reminders.removeAll { $0.itemID == itemID && $0.status != .dismissed }
        data.reminders.append(LocalData.Reminder(id: newID(), itemID: itemID, dueDate: dueDate,
                                                 leadDays: min(max(leadDays, 0), 3650)))
        try save(data)
        Task { _ = await centre?.requestAuthorization(); await refreshPermission() }
        reschedule()
    }

    func complete(_ id: String) { change(id) { $0.status = .dismissed; $0.snoozeUntil = "" } }

    func snooze(_ id: String, days: Int = 1) {
        guard let t = ReminderDays.dayNumber(today) else { return }
        let until = ReminderDays.text(day: t + days)
        change(id) { $0.status = .snoozed; $0.snoozeUntil = until }
    }

    func delete(_ id: String) {
        guard var data = local.localData else { return }
        data.reminders.removeAll { $0.id == id }
        try? save(data)
        reschedule()
    }

    private func change(_ id: String, _ edit: (inout LocalData.Reminder) -> Void) {
        guard var data = local.localData, let i = data.reminders.firstIndex(where: { $0.id == id }) else { return }
        edit(&data.reminders[i])
        try? save(data)
        reschedule()
    }

    private func save(_ data: LocalData) throws {
        do { try local.commitLocalData(data); message = nil } catch { message = Self.saveFailedText; throw Failure.save }
    }

    // MARK: notifications

    struct Planned: Equatable {
        let identifier: String
        let body: String
        /// nil: in a few seconds (became due today after 09:00).
        let fireAt: DateComponents?
    }

    /// One request per not-dismissed reminder whose effective date is today or later.
    nonisolated static func plan(_ reminders: [LocalData.Reminder], items: [VaultItem], today: String, pastNine: Bool,
                                 showNames: Bool) -> [Planned] {
        guard let t = ReminderDays.dayNumber(today) else { return [] }
        let live = Dictionary(items.filter(canHaveReminder).map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        return reminders.compactMap { r in
            guard r.status != .dismissed, let item = live[r.itemID], let day = ReminderDays.effectiveDay(r), day >= t else { return nil }
            let fireAt: DateComponents?
            if day == t && pastNine {
                guard r.lastNotified != today else { return nil }
                fireAt = nil
            } else {
                let parts = ReminderDays.text(day: day).split(separator: "-").compactMap { Int($0) }
                fireAt = DateComponents(year: parts[0], month: parts[1], day: parts[2], hour: hour, minute: 0)
            }
            let title = item.title.isEmpty ? item.kindLabel : item.title
            return Planned(identifier: prefix + r.id, body: body(title: title, showNames: showNames), fireAt: fireAt)
        }
    }

    /// Replaces this app's pending reminder notifications with the current plan (the newest call wins).
    func reschedule() {
        guard let centre else { return }
        let previous = scheduling
        previous?.cancel()
        let now = clock()
        let planned = Self.plan(stored, items: items, today: today, pastNine: calendar.component(.hour, from: now) >= Self.hour,
                                showNames: settings.showItemNamesInPhoneReminders)
        // A "soon" request fires once a day: remember it in `lastNotified`.
        let soon = Set(planned.filter { $0.fireAt == nil }.map { String($0.identifier.dropFirst(Self.prefix.count)) })
        if !soon.isEmpty, var data = local.localData {
            let day = today
            for i in data.reminders.indices where soon.contains(data.reminders[i].id) { data.reminders[i].lastNotified = day }
            try? local.commitLocalData(data)
        }
        scheduling = Task {
            await previous?.value
            guard !Task.isCancelled else { return }
            let pending = await centre.pendingIdentifiers().filter { $0.hasPrefix(Self.prefix) }
            centre.removePending(identifiers: pending)
            for p in planned {
                guard !Task.isCancelled else { return }
                try? await centre.add(identifier: p.identifier, body: p.body, fireAt: p.fireAt)
            }
        }
    }

    func refreshPermission() async {
        guard let centre else { return }
        notificationsDenied = await centre.isDenied()
    }

    /// Waits for the last re-plan (tests).
    func settle() async { await scheduling?.value }
}
