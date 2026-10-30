import XCTest
import LGKCore
@testable import AppSharedMac

@MainActor
final class ItemListFilterTests: XCTestCase {
    private func item(_ id: String, _ kind: String, title: String? = nil, user: String = "", favourite: Bool = false,
                      updated: Int64 = 0) -> VaultItem {
        VaultItem(id: id, record: ["kind": .string(kind), "title": .string(title ?? id), "username": .string(user),
                                   "favorite": .bool(favourite), "updated_at": .int(updated)])!
    }

    private lazy var items = [
        item("a", "web", title: "GitHub", user: "alex", favourite: true, updated: 5),
        item("b", "web", title: "GitLab", user: "sam", updated: 4),
        item("c", "api_key", title: "Git token", updated: 3),
        item("d", "note", title: "Groceries", favourite: true, updated: 2),
    ]

    func testFilterBySidebarSelection() {
        XCTAssertEqual(ItemListFilter.apply(items, selection: .all, query: "").map(\.id), ["a", "b", "c", "d"])
        XCTAssertEqual(ItemListFilter.apply(items, selection: .favourites, query: "").map(\.id), ["a", "d"])
        XCTAssertEqual(ItemListFilter.apply(items, selection: .kind("web"), query: "").map(\.id), ["a", "b"])
        XCTAssertEqual(ItemListFilter.apply(items, selection: .kind("passkey"), query: "").map(\.id), [])
        XCTAssertEqual(ItemListFilter.apply(items, selection: .tool(.settings), query: "").map(\.id), ["a", "b", "c", "d"])
    }

    func testSearchWithinSelection() {
        XCTAssertEqual(ItemListFilter.apply(items, selection: .all, query: "git").map(\.id), ["a", "b", "c"])
        XCTAssertEqual(ItemListFilter.apply(items, selection: .kind("web"), query: "git").map(\.id), ["a", "b"])
        XCTAssertEqual(ItemListFilter.apply(items, selection: .favourites, query: "git").map(\.id), ["a"])
        XCTAssertEqual(ItemListFilter.apply(items, selection: .kind("web"), query: "user:sam").map(\.id), ["b"])
        XCTAssertEqual(ItemListFilter.apply(items, selection: .kind("note"), query: "git").map(\.id), [])
        // Recently used: the search runs within the recent items, not the other way round.
        var many = (0..<SidebarModel.recentLimit + 2).map { item("r\($0)", "note", title: "Note \($0)", updated: Int64(100 + $0)) }
        many.append(item("old", "note", title: "Old note", updated: 1))
        XCTAssertEqual(ItemListFilter.apply(many, selection: .recent, query: "old").map(\.id), [])
    }

    func testFavouriteToggleSaves() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-fav-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        store.limitHints = nil
        try DemoData.seed(into: store, now: 1_800_000_000)
        let id = try XCTUnwrap(VaultItem.items(from: try store.load()).first { !$0.favorite && $0.kind == "web" }?.id)
        try ItemActions.setFavourite(id: id, true, store: store, clock: FixedUnixClock(now: 1_800_000_100))
        let after = try XCTUnwrap(VaultItem.items(from: try store.load()).first { $0.id == id })
        XCTAssertTrue(after.favorite)
        XCTAssertEqual(after.updatedAt, 1_800_000_100)
    }
}

private struct FixedUnixClock: UnixClock { let now: Int64 }
