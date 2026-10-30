import Foundation
import UserNotifications
import LGKCore
import AppSharedMac

/// When a request fires.
enum NotificationTrigger: Equatable, Sendable {
    /// Local calendar date and time.
    case at(DateComponents)
    /// Seconds from now (a reminder that became due today after 09:00).
    case after(TimeInterval)
}

/// The notification centre as the reminders see it, so tests (and unsigned builds, which may never get
/// permission) exercise the scheduling without the real `UNUserNotificationCenter`.
@MainActor
protocol NotificationScheduling: AnyObject {
    /// Asks for permission to alert; true when granted.
    func requestAuthorization() async -> Bool
    /// True when the person turned notifications off for the app (or never allowed them).
    func isDenied() async -> Bool
    /// The identifiers of the pending requests this app scheduled.
    func pendingIdentifiers() async -> [String]
    /// The identifiers of the notifications still shown in Notification Centre.
    func deliveredIdentifiers() async -> [String]
    func add(identifier: String, body: String, trigger: NotificationTrigger) async throws
    func removePending(identifiers: [String])
    func removeDelivered(identifiers: [String])
}

/// The real centre (the app only; never created by the unhosted tests).
@MainActor
final class SystemNotificationCentre: NotificationScheduling {
    private var centre: UNUserNotificationCenter { .current() }

    func requestAuthorization() async -> Bool {
        (try? await centre.requestAuthorization(options: [.alert, .sound])) ?? false
    }

    func isDenied() async -> Bool {
        await centre.notificationSettings().authorizationStatus == .denied
    }

    func pendingIdentifiers() async -> [String] { await centre.pendingNotificationRequests().map(\.identifier) }
    func deliveredIdentifiers() async -> [String] { await centre.deliveredNotifications().map(\.request.identifier) }

    func add(identifier: String, body: String, trigger: NotificationTrigger) async throws {
        let content = UNMutableNotificationContent()
        content.title = "LocalGateKeys"
        content.body = body
        content.sound = .default
        let unTrigger: UNNotificationTrigger = switch trigger {
        case .at(let c): UNCalendarNotificationTrigger(dateMatching: c, repeats: false)
        case .after(let s): UNTimeIntervalNotificationTrigger(timeInterval: max(1, s), repeats: false)
        }
        try await centre.add(UNNotificationRequest(identifier: identifier, content: content, trigger: unTrigger))
    }

    func removePending(identifiers: [String]) { centre.removePendingNotificationRequests(withIdentifiers: identifiers) }
    func removeDelivered(identifiers: [String]) { centre.removeDeliveredNotifications(withIdentifiers: identifiers) }
}

/// Keeps one local notification per active reminder: 09:00 local time on its effective date, body
/// "{title} is due" (or "A reminder is due" when Settings › Privacy hides item names). No secret ever goes in:
/// only the item's title, which the person can hide. A reminder that becomes due today after 09:00 fires
/// a few seconds later, once a day (`lastNotified`).
@MainActor
final class ReminderNotifier {
    nonisolated static let prefix = "lgk.reminder."
    nonisolated static let hour = 9
    nonisolated static let anonymousBody = String(localized: "A reminder is due")
    nonisolated static let soonSeconds: TimeInterval = 5
    nonisolated static let scheduleFailedText = String(localized: "Couldn\u{2019}t schedule a reminder notification.")

    /// Scheduling starts only once the vault has been unlocked since launch (the reminders are encrypted).
    private(set) var unlockedSinceLaunch = false
    private let centre: any NotificationScheduling
    private let settings: AppSettings
    private let clock: () -> Date
    private let calendar: Calendar
    /// Bumped by every reschedule and `removeAll`; an older run stops before its next add.
    private var generation = 0
    /// What this notifier added (removed again even if the centre hasn't listed them yet).
    private var added: Set<String> = []
    /// "Soon" requests this notifier added that may not have fired yet; kept across reschedules.
    private var soon: Set<String> = []

    init(centre: any NotificationScheduling, settings: AppSettings, clock: @escaping () -> Date = Date.init,
         calendar: Calendar = .current) {
        self.centre = centre; self.settings = settings; self.clock = clock; self.calendar = calendar
    }

    func markUnlocked() { unlockedSinceLaunch = true }

    struct Planned: Equatable {
        let reminderID: String
        let identifier: String
        let body: String
        let trigger: NotificationTrigger
    }

    /// The outcome of a reschedule.
    struct Outcome: Equatable {
        /// Reminders given a "soon" trigger: their `lastNotified` becomes today.
        var notifiedToday: [String] = []
        var failed = false
    }

    nonisolated static func body(title: String, showNames: Bool) -> String {
        showNames && !title.isEmpty ? String(localized: "\(title) is due") : anonymousBody
    }

    /// What should be pending: every not-dismissed reminder of a live typed item whose effective date is today
    /// or later (an earlier one shows in the app as overdue). Effective today and already past 09:00: fires in a
    /// few seconds, unless it was already notified today.
    nonisolated static func plan(_ reminders: [LocalData.Reminder], items: [VaultItem], today: String, pastNine: Bool,
                                 showNames: Bool, ignoreNotified: Bool = false) -> [Planned] {
        guard let t = OverviewModel.dayNumber(today) else { return [] }
        let live = Dictionary(items.filter(RemindersModel.canHaveReminder).map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        return reminders.compactMap { r in
            guard r.status != .dismissed, let item = live[r.itemID], let day = OverviewModel.effectiveDay(r), day >= t else {
                return nil
            }
            let trigger: NotificationTrigger
            if day == t && pastNine {
                guard ignoreNotified || r.lastNotified != today else { return nil }
                trigger = .after(soonSeconds)
            } else {
                var c = Self.components(day: day)
                c.hour = hour; c.minute = 0
                trigger = .at(c)
            }
            let title = item.title.isEmpty ? item.kindLabel : item.title
            return Planned(reminderID: r.id, identifier: prefix + r.id, body: body(title: title, showNames: showNames), trigger: trigger)
        }
    }

    /// Year, month and day of a day number (days since 1970-01-01).
    nonisolated static func components(day: Int) -> DateComponents {
        var utc = Calendar(identifier: .gregorian)
        utc.timeZone = TimeZone(identifier: "UTC")!
        let date = Date(timeIntervalSince1970: TimeInterval(day) * 86_400)
        return utc.dateComponents([.year, .month, .day], from: date)
    }

    /// Replaces this app's notifications with the current plan. A newer reschedule supersedes this one before
    /// any further add, so a reminder removed meanwhile is never re-added.
    func reschedule(_ reminders: [LocalData.Reminder], items: [VaultItem]) async -> Outcome {
        guard unlockedSinceLaunch else { return Outcome() }
        generation += 1
        let mine = generation
        let now = clock()
        let today = OverviewModel.day(now, calendar: calendar)
        let pastNine = calendar.component(.hour, from: now) >= Self.hour
        let planned = Self.plan(reminders, items: items, today: today, pastNine: pastNine,
                                showNames: settings.showItemNamesInReminders)
        let pending = await centre.pendingIdentifiers().filter { $0.hasPrefix(Self.prefix) }
        let delivered = await centre.deliveredIdentifiers().filter { $0.hasPrefix(Self.prefix) }
        guard mine == generation, !Task.isCancelled else { return Outcome() }
        // Live reminders (pending or not) keep a notification already shown; gone ones lose it too.
        let liveIDs = Set(reminders.filter { $0.status != .dismissed }.map { Self.prefix + $0.id })
        // A "soon" request still waiting to fire stays while its reminder is live and due today.
        let dueSoon = Set(Self.plan(reminders, items: items, today: today, pastNine: pastNine, showNames: true, ignoreNotified: true)
            .filter { $0.trigger == .after(Self.soonSeconds) }.map(\.identifier))
        let keepSoon = soon.intersection(dueSoon).intersection(Set(pending).union(added))
        soon = keepSoon
        centre.removeDelivered(identifiers: delivered.filter { !liveIDs.contains($0) })
        // Every pending one is removed; the plan is added again so a new date, title or setting takes effect.
        centre.removePending(identifiers: Array(Set(pending).union(added).subtracting(keepSoon)))
        added = keepSoon
        var outcome = Outcome()
        for p in planned {
            guard mine == generation, !Task.isCancelled else { return outcome }
            do {
                try await centre.add(identifier: p.identifier, body: p.body, trigger: p.trigger)
                if mine == generation {
                    added.insert(p.identifier)
                    if case .after = p.trigger { soon.insert(p.identifier); outcome.notifiedToday.append(p.reminderID) }
                } else if !added.contains(p.identifier) {
                    // Superseded while adding: undone unless the newer run added it too.
                    centre.removePending(identifiers: [p.identifier])
                }
            } catch {
                outcome.failed = true
            }
        }
        return outcome
    }

    /// The vault was erased or replaced: every reminder notification goes, pending and delivered.
    func removeAll() async {
        generation += 1
        let pending = await centre.pendingIdentifiers().filter { $0.hasPrefix(Self.prefix) }
        let delivered = await centre.deliveredIdentifiers().filter { $0.hasPrefix(Self.prefix) }
        centre.removePending(identifiers: Array(Set(pending).union(added)))
        centre.removeDelivered(identifiers: delivered)
        added = []; soon = []
    }

    func requestAuthorization() async -> Bool { await centre.requestAuthorization() }
    func isDenied() async -> Bool { await centre.isDenied() }
}
