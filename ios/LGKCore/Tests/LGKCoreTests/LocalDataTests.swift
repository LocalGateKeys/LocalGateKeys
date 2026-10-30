import XCTest
@testable import LGKCore

final class LocalDataTests: XCTestCase {
    private func uuid() -> String { UUID().uuidString.lowercased() }
    private func event(_ type: String = "item.create", result: String = "ok", at t: Int64 = 1_000) -> LocalData.ActivityEvent {
        LocalData.ActivityEvent(id: uuid(), eventType: type, timestamp: t, itemID: uuid(), result: result, count: 1)
    }
    private func collection(_ name: String) -> LocalData.Collection {
        LocalData.Collection(id: uuid(), name: name, createdAt: 10, updatedAt: 10)
    }
    private func reminder() -> LocalData.Reminder { LocalData.Reminder(id: uuid(), itemID: uuid(), dueDate: "2026-02-28") }

    private func assertRejected(_ d: LocalData, _ why: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try d.validated(), why, file: file, line: line)
    }

    func testLimitsEnforced() throws {
        let row = try LocalData.TrashRow(record: .object(["id": .string(uuid())]), deletedAt: 1)
        XCTAssertNoThrow(try LocalData(trash: Array(repeating: row, count: 20_000)).validated())
        assertRejected(LocalData(trash: Array(repeating: row, count: 20_001)), "trash 20,001")

        let events = (0..<5_000).map { _ in event() }
        XCTAssertNoThrow(try LocalData(events: events).validated())
        assertRejected(LocalData(events: events + [event()]), "events 5,001")

        let reminders = (0..<20_000).map { _ in reminder() }
        XCTAssertNoThrow(try LocalData(reminders: reminders).validated())
        assertRejected(LocalData(reminders: reminders + [reminder()]), "reminders 20,001")

        let cols = (0..<500).map { collection("C\($0)") }
        XCTAssertNoThrow(try LocalData(collections: cols).validated())
        assertRejected(LocalData(collections: cols + [collection("C500")]), "collections 501")

        XCTAssertNoThrow(try LocalData(collections: [collection(String(repeating: "n", count: 100))]).validated())
        assertRejected(LocalData(collections: [collection(String(repeating: "n", count: 101))]), "name 101")
        assertRejected(LocalData(collections: [collection("Work"), collection("wORK")]), "duplicate name, case-insensitive")
        var desc = collection("D"); desc.description = String(repeating: "d", count: 501)
        assertRejected(LocalData(collections: [desc]), "description 501")

        var lead = reminder(); lead.leadDays = 3650
        XCTAssertNoThrow(try LocalData(reminders: [lead]).validated())
        lead.leadDays = 3651
        assertRejected(LocalData(reminders: [lead]), "lead days 3651")
        var bad = reminder(); bad.dueDate = "2026-02-29"
        assertRejected(LocalData(reminders: [bad]), "not a real date")

        assertRejected(LocalData(trash: [.init(recordJSON: "[1]", deletedAt: 1)]), "trash record not an object")
        assertRejected(LocalData(trash: [.init(recordJSON: "{", deletedAt: 1)]), "trash record not JSON")
        XCTAssertNoThrow(try LocalData.validatedMemberships((0..<20).map { _ in uuid() }))
        XCTAssertThrowsError(try LocalData.validatedMemberships((0..<21).map { _ in uuid() }), "21 memberships")
        let one = uuid()
        XCTAssertThrowsError(try LocalData.validatedMemberships([one, one]), "duplicate membership")
        XCTAssertEqual(try LocalData(memberships: [one: [], uuid(): [one]]).validated().memberships.count, 1, "empty lists dropped")
        assertRejected(LocalData(memberships: ["not-a-uuid": [one]]), "membership key not a UUID")
        assertRejected(LocalData(memberships: [one: (0..<21).map { _ in uuid() }]), "21 memberships on one item")
        let old = #"{"trash":[],"events":[],"reminders":[],"collections":[],"preferences":{"trash_retention_days":30,"trash_auto_purge":true,"reminder_default_lead_days":0}}"#
        XCTAssertEqual(try JSONDecoder().decode(LocalData.self, from: Data(old.utf8)).memberships, [:], "files without memberships still load")

        var e = event(); e.count = Int64(Int32.max) + 1
        assertRejected(LocalData(events: [e]), "count over 2^31-1")

        XCTAssertNoThrow(try LocalData(preferences: .init(trashRetentionDays: 365)).validated())
        assertRejected(LocalData(preferences: .init(trashRetentionDays: 366)), "retention 366")
        assertRejected(LocalData(preferences: .init(trashRetentionDays: 0)), "retention 0")
    }

    func testEventForbiddenTokensRejected() {
        for type in ["item.password", "password.copy", "item.url", "item.value", "item.secret", "item.content"] {
            assertRejected(LocalData(events: [event(type)]), type)
        }
        assertRejected(LocalData(events: [event("item")]), "no action")
        assertRejected(LocalData(events: [event("item.copy.extra")]), "three parts")
        assertRejected(LocalData(events: [event(result: "great")]), "unknown result")
        XCTAssertEqual(try LocalData(events: [event(" Item.Copy ", result: "OK")]).validated().events[0].eventType, "item.copy")
    }

    func testPurgeExpiredTrash() {
        let now: Int64 = 100 * 86_400
        func row(_ age: Int64) -> LocalData.TrashRow { .init(recordJSON: "{}", deletedAt: now - age * 86_400) }
        var d = LocalData(trash: [row(31), row(30), row(1)])
        d.purgeExpiredTrash(now: now)
        XCTAssertEqual(d.trash.count, 2)
        d.preferences.trashRetentionDays = 7
        d.purgeExpiredTrash(now: now)
        XCTAssertEqual(d.trash.count, 1)
        var off = LocalData(trash: [row(400)]); off.preferences.trashAutoPurge = false
        off.purgeExpiredTrash(now: now)
        XCTAssertEqual(off.trash.count, 1, "auto-purge off keeps everything")
    }

    func testTrimEvents90Days() {
        let now: Int64 = 200 * 86_400
        var d = LocalData(events: [event(at: now - 91 * 86_400), event(at: now - 90 * 86_400), event(at: now)])
        d.trimEvents(now: now)
        XCTAssertEqual(d.events.map(\.timestamp), [now - 90 * 86_400, now])
        var many = LocalData(events: (0..<5_010).map { event(at: now - 5_010 + Int64($0)) })
        many.trimEvents(now: now)
        XCTAssertEqual(many.events.count, 5_000)
        XCTAssertEqual(many.events.last?.timestamp, now - 1, "keeps the newest")
    }

    func testStarterCollections() throws {
        var d = LocalData(collections: [collection("work")])
        XCTAssertTrue(d.ensureStarterCollections(now: 5))
        XCTAssertEqual(d.collections.map(\.name), ["work", "Personal", "Travel", "Emergency"])
        XCTAssertFalse(d.ensureStarterCollections(now: 6))
        XCTAssertNoThrow(try d.validated())
    }

    func testTrashRecordRoundTripsByteIdentical() throws {
        let original = Array(#"{"amount":1.0,"big":9007199254740993,"id":"x","name":"caf\u00e9 é","nested":{"z":[1.5e-7,true,null]}}"#.utf8)
        let canonical = try CanonicalJSON.encode(try CanonicalJSON.parse(original), dialect: .utf8)
        let d = LocalData(trash: [try .init(record: try CanonicalJSON.parse(canonical), deletedAt: 9)],
                          events: [event()], reminders: [reminder()], collections: [collection("Home")])
        let back = try JSONDecoder().decode(LocalData.self, from: JSONEncoder().encode(d.validated()))
        XCTAssertEqual(back, d)
        let restored = try back.trash[0].record()
        XCTAssertEqual(try CanonicalJSON.encode(restored, dialect: .utf8), canonical, "byte-identical after restore")
        XCTAssertEqual(Array(back.trash[0].recordJSON.utf8), canonical)
        guard case .object(let o) = restored else { return XCTFail() }
        XCTAssertEqual(o["amount"], .float(1.0))
        XCTAssertEqual(o["big"], .int(9007199254740993))
    }
}
