import Foundation
import Observation
import LGKCore
import AppSharedMac

/// Reminders (Windows `reminders.py` and `RemindersService`): content-free rows in the Mac-local data that point
/// at a live typed item (never a login) with a due date, lead days and a state. Queries match Windows:
/// effective date = due − lead, a snoozed one not before its snooze date; due, overdue and upcoming leave out
/// dismissed ones; a reminder whose item is gone is pruned when read. Each change re-plans the notifications.
@MainActor @Observable
final class RemindersModel {
    nonisolated static let title = String(localized: "Reminders")
    nonisolated static let subtitle = String(localized: "Due dates stay encrypted. This view shows only safe titles and reminder state.")
    nonisolated static let emptyText = String(localized: "Nothing coming up.")
    nonisolated static let deletedItem = String(localized: "Deleted item")
    nonisolated static let notificationsOffText = String(localized: "Notifications are off for LocalGateKeys.")
    nonisolated static let saveFailedText = String(localized: "The reminder could not be saved on this Mac.")

    struct Row: Identifiable, Equatable {
        let id: String
        let itemID: String
        let title: String
        let due: String
        let status: String
    }

    enum Failure: Error, Equatable { case locked, notTyped, invalidDate, save }

    /// The vault's live items (kept current by the window).
    var items: [VaultItem] = []
    /// The selected row on the Reminders page.
    var picked: String?
    /// The last failure line.
    var message: String?
    /// The person turned notifications off (or never allowed them); reminders still work in the app.
    private(set) var notificationsDenied = false

    @ObservationIgnored private let local: any LocalDataHosting
    @ObservationIgnored private let notifier: ReminderNotifier?
    @ObservationIgnored private let activity: ActivityRecorder?
    @ObservationIgnored private let clock: () -> Date
    @ObservationIgnored private let newID: () -> String
    @ObservationIgnored private var askedPermission = false
    @ObservationIgnored private var scheduling: Task<Void, Never>?
    @ObservationIgnored private var permission: Task<Void, Never>?

    init(local: any LocalDataHosting, notifier: ReminderNotifier?, activity: ActivityRecorder?,
         clock: @escaping () -> Date = Date.init, newID: @escaping () -> String = { UUID().uuidString.lowercased() }) {
        self.local = local; self.notifier = notifier; self.activity = activity; self.clock = clock; self.newID = newID
    }

    var today: String { OverviewModel.day(clock()) }

    // MARK: - Rules and queries (pure)

    /// Windows: reminders reference typed catalog items only, never logins.
    nonisolated static func canHaveReminder(_ item: VaultItem) -> Bool { !item.isLogin }

    /// Drops reminders whose item is not a live typed item (Windows `_records`).
    nonisolated static func pruned(_ reminders: [LocalData.Reminder], items: [VaultItem]) -> [LocalData.Reminder] {
        let live = Set(items.filter(canHaveReminder).map(\.id))
        return reminders.filter { live.contains($0.itemID) }
    }

    nonisolated static func due(_ reminders: [LocalData.Reminder], on day: String) -> [LocalData.Reminder] {
        guard let t = OverviewModel.dayNumber(day) else { return [] }
        return reminders.filter { $0.status != .dismissed && OverviewModel.effectiveDay($0) == t }
    }

    nonisolated static func overdue(_ reminders: [LocalData.Reminder], on day: String) -> [LocalData.Reminder] {
        guard let t = OverviewModel.dayNumber(day) else { return [] }
        return reminders.filter { r in r.status != .dismissed && (OverviewModel.effectiveDay(r).map { $0 < t } ?? false) }
    }

    nonisolated static func upcoming(_ reminders: [LocalData.Reminder], days: Int = 7, from day: String) -> [LocalData.Reminder] {
        guard let t = OverviewModel.dayNumber(day) else { return [] }
        return reminders.filter { r in
            guard r.status != .dismissed, let e = OverviewModel.effectiveDay(r) else { return false }
            return t <= e && e <= t + days
        }
    }

    /// The page's rows: overdue first, then the next ten years (Windows lists `upcoming(3650)`; overdue ones are
    /// kept on the Mac so they can still be completed), by effective date.
    nonisolated static func rows(_ reminders: [LocalData.Reminder], items: [VaultItem], today: String) -> [Row] {
        let titles = Dictionary(items.map { ($0.id, $0.title.isEmpty ? $0.kindLabel : $0.title) }, uniquingKeysWith: { a, _ in a })
        let live = pruned(reminders, items: items)
        let shown = overdue(live, on: today) + upcoming(live, days: 3650, from: today)
        return shown
            .sorted { (OverviewModel.effectiveDay($0) ?? 0, $0.id) < (OverviewModel.effectiveDay($1) ?? 0, $1.id) }
            .map { Row(id: $0.id, itemID: $0.itemID, title: titles[$0.itemID] ?? deletedItem, due: $0.dueDate, status: $0.status.rawValue) }
    }

    // MARK: - Reading

    private var stored: [LocalData.Reminder] { local.localData?.reminders ?? [] }

    var rows: [Row] { Self.rows(stored, items: items, today: today) }

    /// The item's reminder that is still active (not dismissed), if any.
    func reminder(for itemID: String) -> LocalData.Reminder? {
        Self.pruned(stored, items: items).first { $0.itemID == itemID && $0.status != .dismissed }
    }

    var defaultLeadDays: Int { local.localData?.preferences.reminderDefaultLeadDays ?? 0 }

    /// Saves the pruned list when reminders point at items that are gone, then re-plans notifications.
    func prune() {
        guard var data = local.localData else { return }
        let kept = Self.pruned(data.reminders, items: items)
        if kept.count != data.reminders.count {
            data.reminders = kept
            try? local.commitLocalData(data)
        }
        reschedule()
    }

    // MARK: - Changes

    func add(itemID: String, dueDate: String, leadDays: Int) throws {
        guard var data = local.localData else { throw Failure.locked }
        guard let item = items.first(where: { $0.id == itemID }), Self.canHaveReminder(item) else { throw Failure.notTyped }
        guard OverviewModel.dayNumber(dueDate) != nil else { throw Failure.invalidDate }
        data.reminders = Self.pruned(data.reminders, items: items)
        data.reminders.append(LocalData.Reminder(id: newID(), itemID: itemID, dueDate: dueDate,
                                                 leadDays: min(max(leadDays, 0), 3650)))
        try save(data)
        activity?.record(.reminderCreate, itemID: itemID, count: 1)
        requestPermissionOnce()
        reschedule()
    }

    func complete(_ id: String) {
        change(id, event: .reminderComplete) { $0.status = .dismissed; $0.snoozeUntil = "" }
    }

    /// Snooze 1 day (from today, as Windows).
    func snooze(_ id: String, days: Int = 1) {
        guard let t = OverviewModel.dayNumber(today) else { return }
        let until = ReminderNotifier.components(day: t + days)
        let text = String(format: "%04d-%02d-%02d", until.year ?? 0, until.month ?? 0, until.day ?? 0)
        change(id, event: .reminderSnooze) { $0.status = .snoozed; $0.snoozeUntil = text }
    }

    func delete(_ id: String) {
        guard var data = local.localData, let index = data.reminders.firstIndex(where: { $0.id == id }) else { return }
        let itemID = data.reminders[index].itemID
        data.reminders.remove(at: index)
        do { try save(data) } catch { return }
        if picked == id { picked = nil }
        activity?.record(.reminderDelete, itemID: itemID, count: 1)
        reschedule()
    }

    private func change(_ id: String, event: ActivityRecorder.Event, _ edit: (inout LocalData.Reminder) -> Void) {
        guard var data = local.localData, let index = data.reminders.firstIndex(where: { $0.id == id }) else { return }
        edit(&data.reminders[index])
        let itemID = data.reminders[index].itemID
        do { try save(data) } catch { return }
        if event == .reminderComplete, picked == id { picked = nil }
        activity?.record(event, itemID: itemID, count: 1)
        reschedule()
    }

    private func save(_ data: LocalData) throws {
        do { try local.commitLocalData(data); message = nil } catch { message = Self.saveFailedText; throw Failure.save }
    }

    // MARK: - Notifications

    /// Re-plans every pending notification (the newest call wins).
    func reschedule() {
        guard let notifier else { return }
        let previous = scheduling
        previous?.cancel()
        // Chained: the previous run is finished (or stopped before its next add) before this one starts.
        scheduling = Task { [weak self] in
            await previous?.value
            guard let self, !Task.isCancelled else { return }
            let outcome = await notifier.reschedule(self.stored, items: self.items)
            self.apply(outcome)
        }
    }

    /// Records today's "soon" notifications in `lastNotified` (once a day) and surfaces a failed add.
    private func apply(_ outcome: ReminderNotifier.Outcome) {
        if outcome.failed { message = ReminderNotifier.scheduleFailedText }
        guard !outcome.notifiedToday.isEmpty, var data = local.localData else { return }
        let ids = Set(outcome.notifiedToday), day = today
        for i in data.reminders.indices where ids.contains(data.reminders[i].id) { data.reminders[i].lastNotified = day }
        do { try local.commitLocalData(data) } catch { message = Self.saveFailedText }
    }

    /// Waits for the last re-plan (tests).
    func settle() async { await permission?.value; await scheduling?.value }

    private func requestPermissionOnce() {
        guard let notifier, !askedPermission else { return }
        askedPermission = true
        permission = Task {
            _ = await notifier.requestAuthorization()
            notificationsDenied = await notifier.isDenied()
        }
    }

    func refreshPermission() async {
        guard let notifier else { return }
        notificationsDenied = await notifier.isDenied()
    }
}
