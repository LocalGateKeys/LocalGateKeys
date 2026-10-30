import XCTest
import LGKCore
@testable import AppSharedMac

@MainActor
final class OverviewModelTests: XCTestCase {
    private func login(_ id: String, title: String? = nil, user: String = "", password: String = "",
                       totp: [String: JSONValue]? = nil, strict: Bool = false, kind: String = "web") -> VaultItem {
        var r: [String: JSONValue] = ["kind": .string(kind), "title": .string(title ?? id), "username": .string(user),
                                      "password": .string(password), "updated_at": .int(1_700_000_000)]
        if let totp { r["totp"] = .object(totp) }
        if strict { r["policy"] = .object(["require_master_password": .bool(true)]) }
        return VaultItem(id: id, record: r)!
    }

    private let strong = "correct horse battery staple"
    private let secret: [String: JSONValue] = ["secret": .string("JBSWY3DPEHPK3PXP")]

    private func model(_ items: [VaultItem], now: Date = Date(timeIntervalSince1970: 1_790_000_000)) async -> OverviewModel {
        let m = OverviewModel(cache: StrengthCache(), now: { now })
        m.items = items
        await m.recomputeHealth()
        return m
    }

    /// A login made from a 2FA QR code holds a generated placeholder password (tag needs-password): it is left
    /// out of the weak, reused and breach checks, so the placeholder never reaches HIBP.
    func testNeedsPasswordLoginsAreLeftOutOfHealthAndBreachChecks() async {
        var placeholder = login("p", password: "abc", totp: secret)
        var r = placeholder.record; r["tags"] = .array([.string("needs-password")])
        placeholder = VaultItem(id: "p", record: r)!
        let twin = login("t", password: "abc", totp: secret)
        XCTAssertEqual(OverviewModel.healthLogins([placeholder, twin]).map(\.id), ["t"])
        let m = await model([placeholder, twin])
        XCTAssertFalse(m.health?.weak.contains("p") ?? true)
        XCTAssertTrue(m.health?.reused.isEmpty ?? false, "the placeholder does not make its twin look reused")
        XCTAssertTrue(OverviewModel.healthLogins([placeholder]).isEmpty, "Check this password has nothing to send")
    }

    func testCardsFromHealth() async {
        let empty = await model([])
        XCTAssertEqual(empty.healthCard, .init(score: nil, label: "No logins yet", pills: []))

        let m = await model([
            login("a", password: "password"),                       // weak
            login("b", password: strong, totp: secret),             // reused
            login("c", password: strong),                           // reused
            login("d", password: "Tr0ub4dor&3 lighthouse", totp: secret),
            VaultItem(id: "n", record: ["kind": .string("note"), "title": .string("Note")])!,
        ])
        XCTAssertEqual(m.healthCard.score, "25")
        XCTAssertEqual(m.healthCard.label, " / 100 · Poor")
        XCTAssertEqual(m.healthCard.pills, ["1 weak", "2 reused", "2 no 2FA"])
        XCTAssertEqual(m.backupText, "No backup yet")
    }

    func testComingUpOrderAndMeta() {
        typealias R = LocalData.Reminder
        let items = [login("a", title: "Alpha"), login("b", title: "Bravo"), login("c", title: "Charlie"),
                     login("d", title: "Delta"), login("e", title: "Echo")]
        let reminders = [
            R(id: "1", itemID: "a", dueDate: "2026-11-10"),                     // 10 days
            R(id: "2", itemID: "b", dueDate: "2026-10-20"),                     // overdue
            R(id: "3", itemID: "c", dueDate: "2026-10-31"),                     // today
            R(id: "4", itemID: "d", dueDate: "2026-11-01", status: .dismissed),
            R(id: "5", itemID: "e", dueDate: "2027-03-01"),                     // > 90 days
            R(id: "6", itemID: "e", dueDate: "2027-03-01", leadDays: 100),      // effective within 90
            R(id: "7", itemID: "zz", dueDate: "2026-11-01"),                    // item gone
        ]
        let lines = OverviewModel.comingUp(reminders, items: items, today: "2026-10-31")
        XCTAssertEqual(lines.map(\.label), ["Bravo", "Charlie", "Alpha"])
        XCTAssertEqual(lines.map(\.date), ["OCT 20", "OCT 31", "NOV 10"])
        XCTAssertEqual(lines.map(\.meta), ["overdue", "today", "10 days"])
        XCTAssertEqual(lines.map(\.overdue), [true, false, false])
        XCTAssertEqual(OverviewModel.comingUp([R(id: "x", itemID: "a", dueDate: "2026-11-01")], items: items, today: "2026-10-31")
            .map(\.meta), ["1 day"])
        // Snoozed: not before the snooze date.
        let snoozed = R(id: "s", itemID: "a", dueDate: "2026-10-01", status: .snoozed, snoozeUntil: "2027-06-01")
        XCTAssertTrue(OverviewModel.comingUp([snoozed], items: items, today: "2026-10-31").isEmpty)
        XCTAssertTrue(OverviewModel.comingUp([], items: items, today: "2026-10-31").isEmpty)
    }

    func testCodesOrderAndCollapse() {
        let items = [
            login("1", title: "github", user: "zed", totp: secret),
            login("2", title: "GitHub", user: "amy", totp: secret),
            login("3", title: "Bank", totp: secret, strict: true),
            login("4", title: "Apple", totp: ["secret": .string("not base32 !!")]),
            login("5", title: "Mail", totp: secret, kind: "desktop"),
            login("6", title: "None"),
            VaultItem(id: "7", record: ["kind": .string("api_key"), "title": .string("Key"), "totp": .object(secret)])!,
        ]
        let codes = OverviewModel.codeEntries(items)
        XCTAssertEqual(codes.map(\.id), ["4", "3", "2", "1", "5"])
        XCTAssertEqual(codes[1].setup, .hidden)
        XCTAssertNil(codes[0].code(at: 1_000), "invalid setup key")
        let live = codes[2].code(at: 59)
        XCTAssertEqual(live?.remaining, 1)
        XCTAssertEqual(live?.code.count, 6)

        let collapsed = OverviewModel.visibleCodes(codes, expanded: false)
        XCTAssertEqual(collapsed.shown.count, 4)
        XCTAssertEqual(collapsed.toggle, "Show all 5")
        XCTAssertEqual(OverviewModel.visibleCodes(codes, expanded: true).toggle, "Show fewer")
        XCTAssertNil(OverviewModel.visibleCodes(Array(codes.prefix(4)), expanded: false).toggle)
    }

    func testChipsHideZeroAndClearSelection() async {
        let now = Date(timeIntervalSince1970: 1_790_000_000)
        let today = OverviewModel.day(now)
        let m = await model([login("a", password: "password"), login("b", password: strong, totp: secret)], now: now)
        XCTAssertEqual(m.chips.map(\.chip), [.attention, .noTwoFactor])
        XCTAssertEqual(m.chips.map(\.count), [1, 1])
        XCTAssertEqual(OverviewModel.chipLabel(.attention, count: 1), "Needs attention · 1")

        m.reminders = [LocalData.Reminder(id: "r", itemID: "b", dueDate: today)]
        XCTAssertEqual(m.chips.map(\.chip), [.attention, .noTwoFactor, .expiring])
        m.activeChip = .expiring
        XCTAssertEqual(m.applyChip(m.items).map(\.id), ["b"])

        m.activeChip = .attention
        m.items = [login("b", password: strong, totp: secret)]
        await m.recomputeHealth()
        XCTAssertNil(m.activeChip, "a chip with nothing left goes back to All")
        XCTAssertEqual(m.chips.map(\.chip), [.expiring])
    }

    func testRowTagPriority() async {
        let m = OverviewModel(cache: StrengthCache())
        m.items = [login("a", password: "password"), login("b", password: "password"),
                   login("c", password: strong), login("d", password: strong), login("e", password: "Tr0ub4dor&3 lighthouse")]
        m.breached = ["a", "c"]
        await m.recomputeHealth()
        XCTAssertEqual(m.tag(for: "a"), "Breached")
        XCTAssertEqual(m.tag(for: "b"), "Weak")
        XCTAssertEqual(m.tag(for: "c"), "Breached")
        XCTAssertEqual(m.tag(for: "d"), "Reused")
        XCTAssertNil(m.tag(for: "e"))
    }

    func testRecentIs30() {
        XCTAssertEqual(SidebarModel.recentLimit, 30)
        let items = (0..<40).map { i in
            VaultItem(id: "i\(i)", record: ["kind": .string("note"), "title": .string("n"), "updated_at": .int(Int64(i))])!
        }
        let recent = SidebarModel.filter(items, by: .recent)
        XCTAssertEqual(recent.count, 30)
        XCTAssertEqual(recent.first?.id, "i39")
    }
}
