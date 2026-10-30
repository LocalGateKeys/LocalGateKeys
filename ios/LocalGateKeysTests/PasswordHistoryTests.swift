import XCTest
import AppShared
@testable import LocalGateKeys

/// UX plan workstream 8: password history on the iPhone (list, restore round trip, cap and 365 days).
@MainActor
final class PasswordHistoryTests: XCTestCase {
    let clock = TestClock(1_800_000_000)

    private func history(_ rows: [(String, Int64)]) -> JSONValue {
        .array(rows.map { .object(["password": .string($0.0), "changed_at": .int($0.1)]) })
    }

    private func login(history rows: [(String, Int64)]) -> JSONValue {
        guard case .object(var o) = webLogin else { return webLogin }
        o["password_history"] = history(rows)
        return .object(o)
    }

    func testEntriesNewestFirstAndReadsReplacedAt() {
        let record: [String: JSONValue] = ["password_history": .array([
            .object(["password": .string("b"), "changed_at": .int(20)]),
            .object(["password": .string("a"), "replaced_at": .int(10)]),
        ])]
        XCTAssertEqual(PasswordHistory.entries(record).map(\.password), ["b", "a"])
        XCTAssertEqual(PasswordHistory.entries(record).map(\.changedAt), [20, 10])
    }

    func testRestoreSwapsThePasswordAndKeepsTheCurrentOneInHistory() throws {
        let store = MemoryStore(snapshot([login(history: [("Older-Pass-1", 1_799_000_000)])]))
        let entry = try XCTUnwrap(PasswordHistory.entries(VaultItem.items(from: store.snapshot)[0].record).first)
        XCTAssertEqual(PasswordHistory.restore(entry, id: "w1", store: store, clock: clock, background: FakeBackgroundTasks()), .saved)
        let item = try XCTUnwrap(VaultItem.items(from: store.snapshot).first { $0.id == "w1" })
        XCTAssertEqual(item.record["password"]?.stringValue, "Older-Pass-1")
        XCTAssertEqual(PasswordHistory.entries(item.record).map(\.password), ["Maple-Orbit-7731", "Older-Pass-1"])
        // Restoring the password it already has changes nothing.
        let again = try XCTUnwrap(PasswordHistory.entries(item.record).last)
        XCTAssertEqual(PasswordHistory.restore(again, id: "w1", store: store, clock: clock, background: FakeBackgroundTasks()), .unchanged)
    }

    func testHistoryDropsRowsOlderThanAYearAndIsCapped() {
        let old: [(String, Int64)] = [("year-old", 1_800_000_000 - 366 * 86_400)]
        var out = EditorModel.withPasswordHistory(["password": .string("new"), "password_history": history(old)],
                                                  original: ["password": .string("current")], now: 1_800_000_000)
        XCTAssertEqual(PasswordHistory.entries(out).map(\.password), ["current"])
        let many = (1...12).map { ("p\($0)", Int64(1_799_000_000 + $0)) }
        out = EditorModel.withPasswordHistory(["password": .string("new"), "password_history": history(many)],
                                              original: ["password": .string("current")], now: 1_800_000_000)
        XCTAssertEqual(PasswordHistory.entries(out).count, EditorModel.historyWriteLimit)
        XCTAssertEqual(PasswordHistory.entries(out).first?.password, "current")
    }

    func testTheCoreReadsTenRowsAndRefusesEleven() throws {
        XCTAssertEqual(Normalise.passwordHistoryLimit, 10)
        let ten = login(history: (1...10).map { ("p\($0)", Int64(1_799_000_000 + $0)) })
        XCTAssertNoThrow(try Normalise.normalForm(ns: .entry, record: ten))
        let eleven = login(history: (1...11).map { ("p\($0)", Int64(1_799_000_000 + $0)) })
        XCTAssertThrowsError(try Normalise.normalForm(ns: .entry, record: eleven))
    }

    func testTheIPhoneEditorNowKeepsHistory() throws {
        let store = MemoryStore(snapshot([webLogin]))
        let item = try XCTUnwrap(VaultItem.items(from: store.snapshot).first)
        let m = EditorModel(store: store, pro: ProModel(purchases: FakePurchases()), editing: item, kind: .web, clock: clock,
                            random: SystemRandomSource(), background: FakeBackgroundTasks(), keepsPasswordHistory: true)
        m.set("password", "Brand-New-Lantern-4410")
        XCTAssertEqual(m.save(), .saved)
        let saved = try XCTUnwrap(VaultItem.items(from: store.snapshot).first)
        XCTAssertEqual(PasswordHistory.entries(saved.record).first?.password, "Maple-Orbit-7731")
    }
}
