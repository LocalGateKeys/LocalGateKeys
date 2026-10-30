import XCTest
@testable import AppSharedMac

@MainActor
final class CopyShortcutTests: XCTestCase {
    func testCopyOnlyFromItemList() {
        XCTAssertTrue(CopyShortcutPolicy.intercepts(key: "c", shift: false, responder: .itemList, listShown: true))
        XCTAssertTrue(CopyShortcutPolicy.intercepts(key: "c", shift: true, responder: .itemList, listShown: true))
        // Selected detail text or the search field: the system copies the selection.
        XCTAssertFalse(CopyShortcutPolicy.intercepts(key: "c", shift: false, responder: .text, listShown: true))
        XCTAssertFalse(CopyShortcutPolicy.intercepts(key: "c", shift: true, responder: .text, listShown: true))
        XCTAssertFalse(CopyShortcutPolicy.intercepts(key: "c", shift: false, responder: .other, listShown: true))
    }

    func testCodeShortcut() {
        XCTAssertTrue(CopyShortcutPolicy.intercepts(key: "t", shift: false, responder: .itemList, listShown: true))
        XCTAssertTrue(CopyShortcutPolicy.intercepts(key: "t", shift: false, responder: .other, listShown: true))
        XCTAssertFalse(CopyShortcutPolicy.intercepts(key: "t", shift: false, responder: .text, listShown: true))
        XCTAssertFalse(CopyShortcutPolicy.intercepts(key: "v", shift: false, responder: .itemList, listShown: true))
    }

    /// A sidebar tool (Settings, Generator, placeholders) replaces the list: no shortcut copies anything.
    func testNothingCopiedWhileToolShown() {
        for r in [CopyShortcutPolicy.Responder.itemList, .other, .text] {
            for (k, sh) in [("c", false), ("c", true), ("t", false)] {
                XCTAssertFalse(CopyShortcutPolicy.intercepts(key: k, shift: sh, responder: r, listShown: false))
            }
        }
        XCTAssertFalse(MainWindow.menuCopyAllowed(listShown: false, listFocused: true))
        XCTAssertTrue(MainWindow.menuCopyAllowed(listShown: true, listFocused: true))
    }
}
