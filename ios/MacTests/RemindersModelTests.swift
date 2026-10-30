import XCTest
import LGKCore
@testable import AppSharedMac

/// Reminders: Windows date rules, typed items only, pruning, and the notifications planned through a fake centre.
@MainActor
final class RemindersModelTests: XCTestCase {
    /// Records what would reach the notification centre.
    final class FakeCentre: NotificationScheduling {
        var pending: [String: (body: String, at: NotificationTrigger)] = [:]
        var delivered: Set<String> = []
        var authorizationRequests = 0
        var denied = false
        var failAdds = false
        /// Runs inside the next add, before it lands (to interleave a second reschedule).
        var duringAdd: (() async -> Void)?
        func requestAuthorization() async -> Bool { authorizationRequests += 1; return !denied }
        func isDenied() async -> Bool { denied }
        func pendingIdentifiers() async -> [String] { Array(pending.keys) }
        func deliveredIdentifiers() async -> [String] { Array(delivered) }
        func add(identifier: String, body: String, trigger: NotificationTrigger) async throws {
            if failAdds { throw CocoaError(.featureUnsupported) }
            if let hook = duringAdd { duringAdd = nil; await hook() }
            pending[identifier] = (body, trigger)
        }
        func removePending(identifiers: [String]) { for id in identifiers { pending[id] = nil } }
        func removeDelivered(identifiers: [String]) { for id in identifiers { delivered.remove(id) } }
    }

    private typealias R = LocalData.Reminder
    private var local: InMemoryLocalData!
    private var centre: FakeCentre!
    private var settings: AppSettings!
    private var suite: String!
    // 2026-10-25 12:00 UTC.
    private let now = Date(timeIntervalSince1970: 1_792_929_600)

    private var utc: Calendar { var c = Calendar(identifier: .gregorian); c.timeZone = TimeZone(identifier: "UTC")!; return c }
    private let noteID = "6f1d2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"
    private let loginID = "7a1d2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"
    private let goneID = "8b1d2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"

    override func setUp() async throws {
        local = InMemoryLocalData()
        centre = FakeCentre()
        suite = "lgk-reminders-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
    }

    override func tearDown() async throws { UserDefaults().removePersistentDomain(forName: suite) }

    private var items: [VaultItem] {
        [VaultItem(id: noteID, record: ["kind": .string("note"), "title": .string("Passport")])!,
         VaultItem(id: loginID, record: ["kind": .string("web"), "label": .string("Bank"), "password": .string("hunter2-secret")])!]
    }

    private func model() -> RemindersModel {
        let notifier = ReminderNotifier(centre: centre, settings: settings, clock: { [now] in now }, calendar: utc)
        notifier.markUnlocked()
        let m = RemindersModel(local: local, notifier: notifier, activity: ActivityRecorder(host: local, clock: { [now] in now }),
                               clock: { [now] in now })
        m.items = items
        return m
    }

    private func r(_ n: Int, due: String, lead: Int = 0, status: R.Status = .pending, snooze: String = "") -> R {
        R(id: String(format: "00000000-0000-4000-8000-%012d", n), itemID: noteID, dueDate: due, leadDays: lead,
          status: status, snoozeUntil: snooze)
    }

    func testEffectiveDateAndSnooze() throws {
        let day = OverviewModel.dayNumber
        XCTAssertEqual(OverviewModel.effectiveDay(r(1, due: "2026-11-10", lead: 3)), day("2026-11-07"))
        // Snoozed: not before the snooze date, but never earlier than due − lead.
        XCTAssertEqual(OverviewModel.effectiveDay(r(2, due: "2026-11-10", lead: 3, status: .snoozed, snooze: "2026-11-09")), day("2026-11-09"))
        XCTAssertEqual(OverviewModel.effectiveDay(r(3, due: "2026-11-10", lead: 3, status: .snoozed, snooze: "2026-11-01")), day("2026-11-07"))
        // A pending reminder ignores a leftover snooze date.
        XCTAssertEqual(OverviewModel.effectiveDay(r(4, due: "2026-11-10", snooze: "2026-12-01")), day("2026-11-10"))

        // Snooze 1 day from today (2026-10-25), as Windows.
        let m = model()
        try m.add(itemID: noteID, dueDate: "2026-10-25", leadDays: 0)
        let id = try XCTUnwrap(local.localData?.reminders.first?.id)
        m.snooze(id)
        let snoozed = try XCTUnwrap(local.localData?.reminders.first)
        XCTAssertEqual(snoozed.status, .snoozed)
        XCTAssertEqual(snoozed.snoozeUntil, "2026-10-26")
        XCTAssertEqual(RemindersModel.due(local.localData!.reminders, on: "2026-10-26").map(\.id), [id])
        XCTAssertEqual(local.localData?.events.map(\.eventType), ["reminder.create", "reminder.snooze"])
    }

    func testOverdueUpcomingExcludeDismissed() {
        let list = [r(1, due: "2026-10-20"), r(2, due: "2026-10-25"), r(3, due: "2026-10-30"), r(4, due: "2026-11-30"),
                    r(5, due: "2026-10-20", status: .dismissed), r(6, due: "2026-10-27", status: .dismissed)]
        func ids(_ x: [R]) -> [Int] { x.map { Int($0.id.suffix(12))! } }
        XCTAssertEqual(ids(RemindersModel.overdue(list, on: "2026-10-25")), [1])
        XCTAssertEqual(ids(RemindersModel.due(list, on: "2026-10-25")), [2])
        XCTAssertEqual(ids(RemindersModel.upcoming(list, days: 7, from: "2026-10-25")), [2, 3])
        let rows = RemindersModel.rows(list, items: items, today: "2026-10-25")
        XCTAssertEqual(rows.map { Int($0.id.suffix(12))! }, [1, 2, 3, 4])
        XCTAssertEqual(rows.first?.title, "Passport")
        XCTAssertEqual(rows.first?.status, "pending")
    }

    func testOnlyTypedItems() throws {
        let m = model()
        XCTAssertThrowsError(try m.add(itemID: loginID, dueDate: "2026-11-01", leadDays: 0)) {
            XCTAssertEqual($0 as? RemindersModel.Failure, .notTyped)
        }
        XCTAssertThrowsError(try m.add(itemID: goneID, dueDate: "2026-11-01", leadDays: 0))
        XCTAssertEqual(local.localData?.reminders, [])
        XCTAssertFalse(RemindersModel.canHaveReminder(items[1]))
        XCTAssertTrue(RemindersModel.canHaveReminder(items[0]))
        try m.add(itemID: noteID, dueDate: "2026-11-01", leadDays: 2)
        XCTAssertEqual(m.reminder(for: noteID)?.leadDays, 2)
        // A login reminder from elsewhere is never shown or notified.
        let stray = R(id: "00000000-0000-4000-8000-000000000099", itemID: loginID, dueDate: "2026-11-01")
        XCTAssertTrue(RemindersModel.rows([stray], items: items, today: "2026-10-25").isEmpty)
        XCTAssertTrue(ReminderNotifier.plan([stray], items: items, today: "2026-10-25", pastNine: false, showNames: true).isEmpty)
    }

    func testPrunesDeletedItems() async throws {
        let m = model()
        try m.add(itemID: noteID, dueDate: "2026-11-01", leadDays: 0)
        await m.settle()
        XCTAssertEqual(centre.pending.count, 1)
        var data = try XCTUnwrap(local.localData)
        data.reminders.append(R(id: "00000000-0000-4000-8000-000000000042", itemID: goneID, dueDate: "2026-11-02"))
        try local.commitLocalData(data)
        XCTAssertEqual(m.rows.count, 1, "a reminder whose item is gone is not read")
        m.prune()
        XCTAssertEqual(local.localData?.reminders.count, 1)
        // The item is deleted: its reminder and notification go.
        m.items = items.filter { $0.id != noteID }
        m.prune()
        await m.settle()
        XCTAssertEqual(local.localData?.reminders, [])
        XCTAssertTrue(centre.pending.isEmpty)
    }

    func testNotificationBodyHasNoSecrets() async throws {
        let m = model()
        try m.add(itemID: noteID, dueDate: "2026-11-05", leadDays: 2)
        await m.settle()
        XCTAssertEqual(centre.authorizationRequests, 1, "permission is asked when the first reminder is added")
        let (id, entry) = try XCTUnwrap(centre.pending.first)
        XCTAssertTrue(id.hasPrefix(ReminderNotifier.prefix))
        XCTAssertEqual(entry.body, "Passport is due")
        XCTAssertEqual(entry.at, .at(DateComponents(year: 2026, month: 11, day: 3, hour: 9, minute: 0)))
        XCTAssertFalse(entry.body.contains("hunter2"))
        // Names hidden: the body says nothing about the item.
        settings.showItemNamesInReminders = false
        m.reschedule(); await m.settle()
        XCTAssertEqual(centre.pending.first?.value.body, ReminderNotifier.anonymousBody)
        // Completing removes the notification; the activity history stays content-free.
        m.complete(try XCTUnwrap(local.localData?.reminders.first?.id))
        await m.settle()
        XCTAssertTrue(centre.pending.isEmpty)
        let events = try XCTUnwrap(local.localData?.events)
        XCTAssertEqual(events.map(\.eventType), ["reminder.create", "reminder.complete"])
        XCTAssertTrue(events.allSatisfy { $0.itemID == noteID })
    }

    func testDefaultOnShowsNamesAndNothingBeforeUnlock() async throws {
        XCTAssertTrue(settings.showItemNamesInReminders)
        let notifier = ReminderNotifier(centre: centre, settings: settings, clock: { [now] in now }, calendar: utc)
        _ = await notifier.reschedule([r(1, due: "2026-11-01")], items: items)
        XCTAssertTrue(centre.pending.isEmpty, "nothing is scheduled until the vault has been unlocked")
        // Overdue reminders are not scheduled (they would never fire).
        notifier.markUnlocked()
        _ = await notifier.reschedule([r(1, due: "2026-11-01"), r(2, due: "2026-10-01")], items: items)
        XCTAssertEqual(Array(centre.pending.keys), [ReminderNotifier.prefix + r(1, due: "").id])
    }

    func testDueTodayAfterNineFiresSoonOnce() async throws {
        // 12:00 UTC on 2026-10-25: past 09:00.
        let m = model()
        try m.add(itemID: noteID, dueDate: "2026-10-25", leadDays: 0)
        await m.settle()
        let id = try XCTUnwrap(local.localData?.reminders.first?.id)
        XCTAssertEqual(centre.pending[ReminderNotifier.prefix + id]?.at, .after(ReminderNotifier.soonSeconds))
        XCTAssertEqual(local.localData?.reminders.first?.lastNotified, "2026-10-25")
        // Fired: it is not scheduled again today.
        centre.pending = [:]
        m.reschedule(); await m.settle()
        XCTAssertTrue(centre.pending.isEmpty)
        // Before 09:00 the same reminder gets the 09:00 trigger.
        let early = ReminderNotifier(centre: centre, settings: settings,
                                     clock: { Date(timeIntervalSince1970: 1_792_908_000) }, calendar: utc) // 06:00 UTC
        early.markUnlocked()
        _ = await early.reschedule([r(1, due: "2026-10-25")], items: items)
        XCTAssertEqual(centre.pending.first?.value.at, .at(DateComponents(year: 2026, month: 10, day: 25, hour: 9, minute: 0)))
    }

    func testSoonRequestSurvivesImmediateReschedule() async throws {
        let m = model()
        try m.add(itemID: noteID, dueDate: "2026-10-25", leadDays: 0)
        await m.settle()
        let key = ReminderNotifier.prefix + (try XCTUnwrap(local.localData?.reminders.first?.id))
        XCTAssertEqual(centre.pending[key]?.at, .after(ReminderNotifier.soonSeconds))
        // Within the 5 s window: a prune (item list changed) and a second reminder.
        m.prune(); await m.settle()
        try m.add(itemID: noteID, dueDate: "2026-12-01", leadDays: 0); await m.settle()
        XCTAssertEqual(centre.pending[key]?.at, .after(ReminderNotifier.soonSeconds), "the unfired soon request is kept")
        // Completed: it goes.
        m.complete(String(key.dropFirst(ReminderNotifier.prefix.count))); await m.settle()
        XCTAssertNil(centre.pending[key])
    }

    func testUndoneSoonAddDoesNotMarkNotified() async throws {
        let notifier = ReminderNotifier(centre: centre, settings: settings, clock: { [now] in now }, calendar: utc)
        notifier.markUnlocked()
        let a = r(1, due: "2026-10-25")
        var second: Task<ReminderNotifier.Outcome, Never>?
        centre.duringAdd = { second = Task { await notifier.reschedule([], items: self.items) }; await Task.yield() }
        let first = await notifier.reschedule([a], items: items)
        _ = await second?.value
        XCTAssertEqual(first.notifiedToday, [], "a superseded add is not recorded as notified")
        XCTAssertTrue(centre.pending.isEmpty)
    }

    func testOverlappingReschedulesDoNotReAddRemoved() async throws {
        let notifier = ReminderNotifier(centre: centre, settings: settings, clock: { [now] in now }, calendar: utc)
        notifier.markUnlocked()
        let a = r(1, due: "2026-11-01"), b = r(2, due: "2026-11-02")
        // The first run is mid-add when the second (b removed) starts.
        var second: Task<ReminderNotifier.Outcome, Never>?
        centre.duringAdd = { second = Task { await notifier.reschedule([a], items: self.items) } ; await Task.yield() }
        _ = await notifier.reschedule([a, b], items: items)
        _ = await second?.value
        XCTAssertEqual(Set(centre.pending.keys), [ReminderNotifier.prefix + a.id])
    }

    func testRemoveAllClearsPendingAndDelivered() async throws {
        let notifier = ReminderNotifier(centre: centre, settings: settings, clock: { [now] in now }, calendar: utc)
        notifier.markUnlocked()
        _ = await notifier.reschedule([r(1, due: "2026-11-01")], items: items)
        centre.delivered = [ReminderNotifier.prefix + "old", "other.app"]
        await notifier.removeAll()
        XCTAssertTrue(centre.pending.isEmpty)
        XCTAssertEqual(centre.delivered, ["other.app"])
    }

    func testCompletedLosesDeliveredAndFailedAddIsShown() async throws {
        let m = model()
        try m.add(itemID: noteID, dueDate: "2026-11-01", leadDays: 0)
        await m.settle()
        let id = try XCTUnwrap(local.localData?.reminders.first?.id)
        centre.delivered = [ReminderNotifier.prefix + id]
        m.complete(id); await m.settle()
        XCTAssertTrue(centre.delivered.isEmpty)
        centre.failAdds = true
        try m.add(itemID: noteID, dueDate: "2026-11-03", leadDays: 0)
        await m.settle()
        XCTAssertEqual(m.message, "Couldn\u{2019}t schedule a reminder notification.")
    }

    func testDeleteRemovesReminderAndNotification() async throws {
        let m = model()
        try m.add(itemID: noteID, dueDate: "2026-11-01", leadDays: 0)
        await m.settle()
        m.delete(try XCTUnwrap(m.reminder(for: noteID)?.id))
        await m.settle()
        XCTAssertNil(m.reminder(for: noteID))
        XCTAssertTrue(centre.pending.isEmpty)
        XCTAssertEqual(local.localData?.events.last?.eventType, "reminder.delete")
    }
}
