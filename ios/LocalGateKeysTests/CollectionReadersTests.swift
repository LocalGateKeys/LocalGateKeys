import XCTest
import AppShared
@testable import LocalGateKeys

/// Sub-plan 07 Task 5c: collection states (`col:`/`cm:`/`csl:`) live in the item store. Every app reader that lists,
/// counts, exports or deletes items leaves them out (`StoreSnapshot.itemRecords`): the vault list and search, the
/// security check, CSV/CXF/backup export, import duplicate checks, deletes arriving from a restore, and Recently
/// deleted (which keeps an item's collections in its row and brings them back on restore).
@MainActor
final class CollectionReadersTests: XCTestCase {
    static let family = "3f2a6c1e-8b4d-4e7a-9c05-d1e2f3a4b5c6"
    static let noteID = "11111111-1111-4111-8111-111111111111"
    static let loginID = "22222222-2222-4222-8222-222222222222"
    static let passkeyID = "33333333-3333-4333-8333-333333333333"
    let clock = TestClock(1_800_000_000)

    static let loginRecord = rec(["id": .string(loginID), "kind": .string("web"), "label": .string("Bank"),
                                  "username": .string("sam"), "password": .string("hunter2"),
                                  "scope": rec(["origin": .string("https://bank.example")]), "updated_at": .int(1_790_000_000)])
    static let noteRecord = rec(["id": .string(noteID), "kind": .string("note"), "title": .string("Cabin"),
                                 "payload": rec(["body": .string("x"), "fields": .array([])]),
                                 "created_at": .int(1_790_000_000), "updated_at": .int(1_790_000_000)])
    static let passkeyRecord = rec(["id": .string(passkeyID), "kind": .string("passkey"), "title": .string("example.com"),
                                    "payload": rec(["relying_party_id": .string("example.com"), "credential_id": .string("AQID"),
                                                    "user_name": .string("sam")]),
                                    "updated_at": .int(1_790_000_000)])

    /// A login, a note in "Family", a passkey, the three collection states, and records planted under reserved ids that
    /// look like a login, a note and a passkey (only the shared filter keeps them out).
    static func planted() -> StoreSnapshot {
        func plant(_ record: JSONValue, as id: String) -> JSONValue {
            guard case .object(var r) = record else { return record }
            r["id"] = .string(id)
            if case .string(let k)? = r["kind"], k == "web" { return Wrapper.make(ns: .entry, record: .object(r)) }
            return Wrapper.make(ns: .item, record: .object(r))
        }
        var snap = snapshot([loginRecord, noteRecord, passkeyRecord])
        snap.records[CollectionStates.catalogPrefix + family] = CollectionStates.wrapper(CollectionStates.catalog(
            collectionID: family, name: "Family", description: "", createdAt: 1, updatedAt: 1))
        snap.records[CollectionStates.membershipPrefix + noteID] = CollectionStates.wrapper(CollectionStates.membership(
            itemID: noteID, collectionIDs: [family]))
        snap.records[CollectionStates.linkPrefix + family] = CollectionStates.wrapper(CollectionStates.link(
            collectionID: family, mode: "edit", role: "owner"))
        snap.records["col:login"] = plant(loginRecord, as: "col:login")
        snap.records["cm:note"] = plant(noteRecord, as: "cm:note")
        snap.records["csl:passkey"] = plant(passkeyRecord, as: "csl:passkey")
        return snap
    }

    static let live: Set<String> = [loginID, noteID, passkeyID]

    func testTheVaultListSearchAndSecurityCheckShowOnlyItems() {
        let items = VaultItem.items(from: Self.planted())
        XCTAssertEqual(Set(items.map(\.id)), Self.live)
        XCTAssertEqual(VaultSearch.rank(items, query: "").count, 3)
        XCTAssertEqual(SecurityCheckModel.healthLogins(items).map(\.id), [Self.loginID])
    }

    func testExportsLeaveCollectionStatesOut() async throws {
        let store = MemoryStore(Self.planted())
        let exporter = VaultExporter(store: store, isPro: { false }, appVersion: "1.2.0",
                                     fallbackDeviceID: { "0123456789abcdef0123456789abcdef" },
                                     now: { Date(timeIntervalSince1970: 1_800_000_000) }, random: SystemRandomSource())
        let csv = try exporter.csvText()
        XCTAssertTrue(csv.contains("bank.example"))
        XCTAssertFalse(csv.contains("col:login"))
        XCTAssertEqual(csv.components(separatedBy: "hunter2").count - 1, 1, "one login row, not the planted copy")
        XCTAssertEqual(Set(try exporter.cxfChoices().map(\.id)), Self.live)
        let password = "correct horse battery"
        let data = try await exporter.encryptedBackupData(password: password, confirmation: password)
        let payload = try PhoneBackup.open(data, password: password)
        XCTAssertEqual(Set(payload.states.map(\.id)), Self.live)
    }

    func testImportDuplicateChecksNeverMatchACollectionState() {
        var snap = Self.planted()
        snap.records[Self.loginID] = nil
        snap.records[Self.passkeyID] = nil
        // Only the planted copies remain: nothing matches them.
        XCTAssertNil(ImportReviewModel.match(origin: "https://bank.example", username: "sam", in: snap))
        let p = PasskeyFields(rpID: "example.com", userName: "sam", userDisplayName: "", userHandle: Data([1]),
                              credentialID: Data([1, 2, 3]), pkcs8: Data())
        XCTAssertNil(ImportReviewModel.passkeyID(p, in: snap))
        XCTAssertEqual(ImportReviewModel.match(origin: "https://bank.example", username: "sam", in: Self.planted()), Self.loginID)
    }

    func testAVaultHoldingOnlyCollectionsStillTakesItsOwnBackup() {
        let device = "d4444444-0000-4000-8000-00000000000d"
        let backup = BackupPayload(createdAt: 1, platform: "ios", appVersion: "1.0.0", deviceID: device, proHint: false, states: [])
        var onlyCollections = StoreSnapshot()
        for (id, w) in Self.planted().records where id.hasPrefix(CollectionStates.catalogPrefix + "3f2a") {
            onlyCollections.records[id] = w
        }
        XCTAssertEqual(onlyCollections.records.count, 1)
        // Empty apart from the collections (e.g. the starters): restored as if from another device.
        XCTAssertNotEqual(ImportExportModel.restorable(backup, into: onlyCollections, device: device).deviceID, device)
        // With an item it is this device's own data: nothing to restore (`sameDevice`).
        XCTAssertEqual(ImportExportModel.restorable(backup, into: Self.planted(), device: device).deviceID, device)
    }

    func testDeletesFromARestoreNeverPutCollectionStatesInRecentlyDeleted() throws {
        let before = Self.planted()
        // Everything disappears: only the three items become trash rows; the note's keeps its collection.
        let rows = ImportExportModel.trashRows(before: before, records: [:], meta: [:], now: 5)
        let ids = try rows.map { row -> String in
            guard case .object(let r) = try row.record(), case .string(let id)? = r["id"] else { return "" }
            return id
        }
        XCTAssertEqual(Set(ids), Self.live)
        let note = try XCTUnwrap(rows.first { (try? $0.record())?.objectValue?["id"] == .string(Self.noteID) })
        XCTAssertEqual(try note.record().objectValue?["collection_ids"], .array([.string(Self.family)]))
    }

    func testRecentlyDeletedKeepsTheCollectionsAndRestoresThem() throws {
        let store = MemoryStore(Self.planted())
        let local = InMemoryPhoneLocal()
        let trash = PhoneTrash(local: local, store: store, isPro: { true }, clock: clock, background: FakeBackgroundTasks())
        XCTAssertEqual(trash.moveToTrash(id: "col:" + Self.family), .unchanged, "a collection state is never an item")
        XCTAssertEqual(trash.moveToTrash(id: Self.noteID), .saved)
        XCTAssertNil(store.snapshot.records[Self.noteID])
        XCTAssertNil(store.snapshot.records[CollectionStates.membershipPrefix + Self.noteID], "the membership leaves with the item")
        let row = try XCTUnwrap(local.localData?.trash.first)
        XCTAssertEqual(try row.record().objectValue?["collection_ids"], .array([.string(Self.family)]))
        XCTAssertEqual(trash.undoLastDelete(isPro: true), .restored)
        XCTAssertEqual(store.snapshot.records[Self.noteID], Self.planted().records[Self.noteID], "the record keeps its v1 shape")
        XCTAssertEqual(store.snapshot.records[CollectionStates.membershipPrefix + Self.noteID],
                       Self.planted().records[CollectionStates.membershipPrefix + Self.noteID])
    }

    func testADeleteWithoutRecentlyDeletedDropsTheMembership() {
        let store = MemoryStore(Self.planted())
        XCTAssertEqual(EditorModel.delete(id: CollectionStates.catalogPrefix + Self.family, store: store, clock: clock,
                                          background: FakeBackgroundTasks()), .unchanged)
        XCTAssertEqual(EditorModel.delete(id: Self.noteID, store: store, clock: clock, background: FakeBackgroundTasks()), .saved)
        XCTAssertNil(store.snapshot.records[CollectionStates.membershipPrefix + Self.noteID])
        XCTAssertNotNil(store.snapshot.records[CollectionStates.catalogPrefix + Self.family], "the collection stays")
    }
}
