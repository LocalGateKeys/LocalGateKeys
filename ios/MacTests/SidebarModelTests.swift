import XCTest
import LGKCore
@testable import AppSharedMac

@MainActor
final class SidebarModelTests: XCTestCase {
    private func item(_ id: String, _ kind: String, favourite: Bool = false, updated: Int64 = 0) -> VaultItem {
        VaultItem(id: id, record: ["kind": .string(kind), "title": .string(id), "favorite": .bool(favourite),
                                   "updated_at": .int(updated)])!
    }

    func testCountsPerKind() {
        let model = SidebarModel(items: [item("a", "web"), item("b", "web"), item("c", "api_key"), item("d", "note")])
        XCTAssertEqual(model.count(for: .all), 4)
        XCTAssertEqual(model.count(for: .kind("web")), 2)
        XCTAssertEqual(model.count(for: .kind("api_key")), 1)
        XCTAssertEqual(model.count(for: .kind("passkey")), 0)
        XCTAssertNil(model.count(for: .tool(.settings)))
    }

    func testFavouritesAndRecentCounts() {
        let model = SidebarModel(items: [item("a", "web", favourite: true), item("b", "web"), item("c", "note", favourite: true)])
        XCTAssertEqual(model.count(for: .favourites), 2)
        XCTAssertNil(model.count(for: .recent), "Recently used shows no count, as on Windows")
    }

    func testKindsHiddenWhenEmpty() {
        let model = SidebarModel(items: [item("a", "web"), item("b", "card")])
        XCTAssertEqual(model.kindsPresent, ["web", "card"])
        model.items = []
        XCTAssertEqual(model.kindsPresent, [])
    }

    func testOrderMatchesWindows() {
        let kinds = ["wifi", "passkey", "document", "note", "api_key", "desktop", "web", "card"]
        let model = SidebarModel(items: kinds.enumerated().map { item("i\($0.offset)", $0.element) })
        XCTAssertEqual(model.kindsPresent, ["web", "desktop", "api_key", "document", "passkey", "note", "card", "wifi"])
        XCTAssertEqual(SidebarModel.label(forKind: "web"), "Logins")
        XCTAssertEqual(SidebarModel.label(forKind: "desktop"), "Desktop apps")
        XCTAssertEqual(SidebarModel.label(forKind: "api_key"), "API keys")
        XCTAssertEqual(SidebarModel.label(forKind: "card"), "Payment cards")
    }

    func testFilteringFollowsSelection() {
        let model = SidebarModel(items: [item("a", "web", favourite: true, updated: 1), item("b", "note", updated: 5)])
        model.selection = .favourites
        XCTAssertEqual(model.filtered(model.items).map(\.id), ["a"])
        model.selection = .recent
        XCTAssertEqual(model.filtered(model.items).map(\.id), ["b", "a"])
        model.selection = .kind("note")
        XCTAssertEqual(model.filtered(model.items).map(\.id), ["b"])
    }
}
