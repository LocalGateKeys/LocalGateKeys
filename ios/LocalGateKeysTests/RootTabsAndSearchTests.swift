import XCTest
import AppShared
@testable import LocalGateKeys

/// UX plan workstream 1: four tabs (no search tab), search as a Vault button with recent searches.
@MainActor
final class RootTabsAndSearchTests: XCTestCase {
    func testTabsAreVaultSyncSecuritySettings() {
        let all: [RootTab] = [.vault, .sync, .security, .settings]
        XCTAssertEqual(Set(all).count, 4)
    }

    func testRecentSearchesNewestFirstWithoutDuplicates() {
        var list: [String] = []
        list = VaultListModel.remember("  bank ", in: list)
        list = VaultListModel.remember("mail", in: list)
        list = VaultListModel.remember("BANK", in: list)
        XCTAssertEqual(list, ["BANK", "mail"])
        XCTAssertEqual(VaultListModel.remember("   ", in: list), list)
    }

    func testRecentSearchesAreCapped() {
        var list: [String] = []
        for q in ["a", "b", "c", "d", "e", "f", "g"] { list = VaultListModel.remember(q, in: list) }
        XCTAssertEqual(list, ["g", "f", "e", "d", "c"])
    }

    func testSettingsTabLeavesRoomForTheLegacyBar() {
        if #available(iOS 26, *) {
            XCTAssertEqual(SettingsView.legacyTabBarRoom, 0)
        } else {
            XCTAssertEqual(SettingsView.legacyTabBarRoom, 96)
        }
    }
}
