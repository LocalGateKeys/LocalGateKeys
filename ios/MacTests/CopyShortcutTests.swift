import AppKit
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

    func testShortcutKeyFallsBackToPhysicalKeyOnNonLatinLayouts() {
        XCTAssertEqual(MainWindow.shortcutKey(characters: "c", keyCode: 8), "c")
        XCTAssertEqual(MainWindow.shortcutKey(characters: "C", keyCode: 8), "c")
        XCTAssertEqual(MainWindow.shortcutKey(characters: "ψ", keyCode: 8), "c")   // Greek
        XCTAssertEqual(MainWindow.shortcutKey(characters: "с", keyCode: 8), "c")   // Cyrillic
        XCTAssertEqual(MainWindow.shortcutKey(characters: "τ", keyCode: 17), "t")
        XCTAssertEqual(MainWindow.shortcutKey(characters: "е", keyCode: 17), "t")
        // A Latin letter on another physical key (Dvorak) keeps its character.
        XCTAssertEqual(MainWindow.shortcutKey(characters: "j", keyCode: 8), "j")
    }

    /// Found by MacPendingChecksUITests 2026-11-16: ⌘C in the search field copied nothing (Edit › Copy did), because
    /// SwiftUI took the Item menu's greyed-out ⌘C first. The window's key monitor now sends copy: to the field itself.
    func testCommandCInATextFieldIsSentAsCopy() {
        XCTAssertEqual(MainWindow.textFieldAction(key: "c", modifiers: [.command], inTextField: true), #selector(NSText.copy(_:)))
        XCTAssertNil(MainWindow.textFieldAction(key: "c", modifiers: [.command], inTextField: false), "the list keeps Copy password")
        XCTAssertNil(MainWindow.textFieldAction(key: "c", modifiers: [.command, .shift], inTextField: true))
        XCTAssertNil(MainWindow.textFieldAction(key: "t", modifiers: [.command], inTextField: true))
        // Greek layout: the physical C key maps to "c" first (shortcutKey), so the field copies there too.
        let key = MainWindow.shortcutKey(characters: "ψ", keyCode: 8) ?? ""
        XCTAssertEqual(MainWindow.textFieldAction(key: key, modifiers: [.command], inTextField: true), #selector(NSText.copy(_:)))
    }

    @MainActor
    func testWindowWithAttachedSheetIsObstructed() {
        let window = NSWindow(contentRect: .init(x: 0, y: 0, width: 200, height: 200), styleMask: [.titled], backing: .buffered, defer: true)
        XCTAssertTrue(MainWindow.isUnobstructed(window))
    }
}
