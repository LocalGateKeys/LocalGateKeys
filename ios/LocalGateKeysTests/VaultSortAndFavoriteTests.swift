import XCTest
import AppShared
@testable import LocalGateKeys

/// The shared sort vectors (`tests/vectors/vault_sort/cases.json`, written by `scripts/make_sort_vectors.py`).
enum VaultSortVector {
    static let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../../tests/vectors/vault_sort/cases.json").standardized

    struct Case { let option: String; let favoritesFirst: Bool; let expected: [String] }

    static func load() throws -> (items: [VaultItem], cases: [Case]) {
        let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let rawItems = try XCTUnwrap(root["items"] as? [[String: Any]])
        let items: [VaultItem] = try rawItems.map { o in
            var r: [String: JSONValue] = ["kind": .string("note"), "title": .string(o["title"] as? String ?? "")]
            r["favorite"] = .bool(o["favorite"] as? Bool ?? false)
            for key in ["created_at", "updated_at"] {
                if let n = o[key] as? NSNumber { r[key] = .int(n.int64Value) }
            }
            return try XCTUnwrap(VaultItem(id: try XCTUnwrap(o["id"] as? String), record: r))
        }
        let cases = try XCTUnwrap(root["cases"] as? [[String: Any]]).map { c in
            Case(option: c["option"] as? String ?? "", favoritesFirst: c["favorites_first"] as? Bool ?? false,
                 expected: c["expected"] as? [String] ?? [])
        }
        return (items, cases)
    }
}

@MainActor
final class VaultSortAndFavoriteTests: XCTestCase {
    let clock = TestClock(1_800_000_000)

    // MARK: sort

    func test_sort_matches_the_shared_vectors() throws {
        let (items, cases) = try VaultSortVector.load()
        XCTAssertEqual(cases.count, 8)
        for c in cases {
            let option = try XCTUnwrap(VaultSortOption(rawValue: c.option), c.option)
            // Input order must not matter.
            for input in [items, items.reversed()] {
                XCTAssertEqual(VaultSort.sorted(input, by: option, favoritesFirst: c.favoritesFirst).map(\.id), c.expected,
                               "\(c.option) favorites_first=\(c.favoritesFirst)")
            }
        }
    }

    func test_title_key_folds_accents_width_and_case() {
        XCTAssertEqual(VaultSort.titleKey("Éclair"), VaultSort.titleKey("eclair"))
        XCTAssertEqual(VaultSort.titleKey("Ｚoom"), VaultSort.titleKey("zoom"))
        XCTAssertEqual(VaultSort.titleKey(""), [])
    }

    func test_sort_setting_is_stored_per_device_and_grouped_by_default() throws {
        let suite = "VaultSortAndFavoriteTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = MemoryStore(snapshot([webLogin, deskLogin, note, card]))
        let model = VaultListModel(store: store, defaults: defaults)
        model.reload()
        XCTAssertNil(model.sort)
        XCTAssertNil(model.sortedItems(filter: .all), "no sort chosen: the grouped view")
        model.sort = .titleAsc
        model.favoritesFirst = true
        XCTAssertEqual(model.sortedItems(filter: .all)?.map(\.id), ["d1", "n1", "w1", "c1"])
        XCTAssertEqual(model.sortedItems(filter: .favorites)?.map(\.id), ["d1", "n1"])
        let again = VaultListModel(store: store, defaults: defaults)
        XCTAssertEqual(again.sort, .titleAsc)
        XCTAssertTrue(again.favoritesFirst)
        // The setting never reaches the synced store.
        XCTAssertEqual(store.commits, 0)
        again.sort = nil
        XCTAssertNil(VaultListModel(store: store, defaults: defaults).sort)
    }

    func test_search_keeps_relevance_order() {
        let store = MemoryStore(snapshot([webLogin, deskLogin, note, card]))
        let model = VaultListModel(store: store, defaults: UserDefaults(suiteName: "VaultSortSearch.\(UUID().uuidString)")!)
        model.reload()
        model.sort = .titleDesc
        model.query = "example"
        XCTAssertEqual(model.visibleItems.map(\.id), VaultSearch.rank(model.items, query: "example").map(\.id))
    }

    // MARK: favorite

    let fullNote = rec(["id": .string("99999999-aaaa-4000-8000-000000000009"), "kind": .string("note"), "title": .string("Locker code"),
                        "created_at": .int(1_700_000_000), "updated_at": .int(1_700_000_100), "favorite": .bool(false),
                        "tags": .array([]), "payload": rec(["body": .string("12-34"), "fields": .array([])])])

    func test_set_favorite_writes_the_flag_and_bumps_updated_at() throws {
        let store = MemoryStore(snapshot([fullNote, webLogin]))
        let background = FakeBackgroundTasks()
        for id in ["99999999-aaaa-4000-8000-000000000009", "w1"] {
            XCTAssertEqual(VaultListModel.setFavorite(true, id: id, store: store, clock: clock, background: background), .saved, id)
            let item = try XCTUnwrap(VaultItem.items(from: store.snapshot).first { $0.id == id })
            XCTAssertTrue(item.favorite)
            XCTAssertEqual(item.updatedAt, clock.now)
            // The wrapper's rank follows the record, so sync sees the newer edit.
            guard case .object(let w)? = store.snapshot.records[id] else { return XCTFail("no wrapper") }
            XCTAssertEqual(w["updated_at"], .int(clock.now))
        }
        XCTAssertEqual(store.commits, 2)
        XCTAssertEqual(background.begun.count, background.ended.count)
        // Already a favorite: nothing written.
        XCTAssertEqual(VaultListModel.setFavorite(true, id: "99999999-aaaa-4000-8000-000000000009", store: store, clock: clock, background: background), .unchanged)
        XCTAssertEqual(store.commits, 2)
        // Unmark.
        clock.now += 60
        XCTAssertEqual(VaultListModel.setFavorite(false, id: "99999999-aaaa-4000-8000-000000000009", store: store, clock: clock, background: background), .saved)
        let item = try XCTUnwrap(VaultItem.items(from: store.snapshot).first { $0.id == "99999999-aaaa-4000-8000-000000000009" })
        XCTAssertFalse(item.favorite)
        XCTAssertEqual(item.updatedAt, clock.now)
        XCTAssertEqual(item.title, "Locker code")
    }

    func test_set_favorite_on_a_missing_item_writes_nothing() {
        let store = MemoryStore(snapshot([fullNote]))
        XCTAssertEqual(VaultListModel.setFavorite(true, id: "gone", store: store, clock: clock, background: FakeBackgroundTasks()),
                       .unchanged)
        XCTAssertEqual(store.commits, 0)
    }
}
