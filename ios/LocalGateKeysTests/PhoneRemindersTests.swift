import XCTest
import AppShared
@testable import LocalGateKeys

@MainActor
final class FakePhoneCentre: PhoneNotificationScheduling {
    var pending: [String: (body: String, fireAt: DateComponents?)] = [:]
    var asked = 0
    func requestAuthorization() async -> Bool { asked += 1; return true }
    func isDenied() async -> Bool { false }
    func pendingIdentifiers() async -> [String] { Array(pending.keys) }
    func add(identifier: String, body: String, fireAt: DateComponents?) async throws { pending[identifier] = (body, fireAt) }
    func removePending(identifiers: [String]) { for i in identifiers { pending[i] = nil } }
}

/// UX plan workstream 10: expiry reminders on the iPhone, with a fake clock and notification centre.
@MainActor
final class PhoneRemindersTests: XCTestCase {
    let cardID = "33333333-3333-4333-8333-333333333333"
    let loginID = "44444444-4444-4444-8444-444444444444"
    var utc: Calendar { var c = Calendar(identifier: .gregorian); c.timeZone = TimeZone(identifier: "UTC")!; return c }

    private func items() -> [VaultItem] {
        let card = rec(["id": .string(cardID), "kind": .string("card"), "title": .string("Travel card"),
                        "payload": rec(["expiry": .string("08/27"), "number": .string("4111111111111111"), "cvv": .string("123")])])
        let login = rec(["id": .string(loginID), "kind": .string("web"), "label": .string("Bank"), "password": .string("hunter2"),
                         "scope": rec(["origin": .string("https://bank.example.com")])])
        return VaultItem.items(from: snapshot([card, login]))
    }

    /// 2027-08-01 08:00 UTC.
    private func model(_ centre: FakePhoneCentre, names: Bool = false, hour: Int = 8) -> PhoneReminders {
        let settings = AppSettings(defaults: UserDefaults(suiteName: "rem-\(UUID().uuidString)")!)
        settings.showItemNamesInPhoneReminders = names
        let now = utc.date(from: DateComponents(year: 2027, month: 8, day: 1, hour: hour))!
        let m = PhoneReminders(local: InMemoryPhoneLocal(), centre: centre, settings: settings, clock: { now }, calendar: utc,
                               newID: { "55555555-5555-4555-8555-555555555555" })
        m.items = items()
        return m
    }

    func testCardExpiryIsTheLastDayOfTheMonth() {
        XCTAssertEqual(ReminderDays.cardExpiryDay("08/27"), "2027-08-31")
        XCTAssertEqual(ReminderDays.cardExpiryDay("02/2028"), "2028-02-29")
        XCTAssertNil(ReminderDays.cardExpiryDay("13/27"))
        XCTAssertNil(ReminderDays.cardExpiryDay("soon"))
    }

    func testCardSuggestsItsExpiryUntilAReminderExists() throws {
        let m = model(FakePhoneCentre())
        let card = try XCTUnwrap(m.items.first { $0.id == cardID })
        XCTAssertEqual(m.suggestion(for: card), "2027-08-31")
        try m.set(itemID: cardID, dueDate: "2027-08-31", leadDays: 30)
        XCTAssertNil(m.suggestion(for: card))
    }

    func testLoginsCannotHaveReminders() {
        let m = model(FakePhoneCentre())
        XCTAssertThrowsError(try m.set(itemID: loginID, dueDate: "2027-09-01", leadDays: 0))
    }

    func testSchedulesAt9OnTheEffectiveDayWithoutNames() async throws {
        let centre = FakePhoneCentre()
        let m = model(centre)
        try m.set(itemID: cardID, dueDate: "2027-08-31", leadDays: 7)
        await m.settle()
        let p = try XCTUnwrap(centre.pending[PhoneReminders.prefix + "55555555-5555-4555-8555-555555555555"])
        XCTAssertEqual(p.fireAt, DateComponents(year: 2027, month: 8, day: 24, hour: 9, minute: 0))
        XCTAssertEqual(p.body, PhoneReminders.anonymousBody)
        // Never a secret: no card number, code or title.
        XCTAssertFalse(p.body.contains("4111") || p.body.contains("123") || p.body.contains("Travel"))
    }

    func testNamesOnlyWhenTurnedOn() async throws {
        let centre = FakePhoneCentre()
        let m = model(centre, names: true)
        try m.set(itemID: cardID, dueDate: "2027-08-31", leadDays: 0)
        await m.settle()
        XCTAssertEqual(centre.pending.values.first?.body, "Travel card is due")
    }

    func testDoneRemovesTheNotificationAndSnoozeMovesIt() async throws {
        let centre = FakePhoneCentre()
        let m = model(centre)
        try m.set(itemID: cardID, dueDate: "2027-08-01", leadDays: 0)
        await m.settle()
        let id = try XCTUnwrap(m.rows().first?.id)
        m.snooze(id)
        await m.settle()
        XCTAssertEqual(centre.pending.values.first?.fireAt?.day, 2)
        m.complete(id)
        await m.settle()
        XCTAssertTrue(centre.pending.isEmpty)
        XCTAssertTrue(m.rows().isEmpty)
    }

    func testOverdueRowsComeFirst() throws {
        let m = model(FakePhoneCentre())
        try m.set(itemID: cardID, dueDate: "2027-07-20", leadDays: 0)
        XCTAssertEqual(m.rows(within: 30).first?.overdue, true)
    }
}
