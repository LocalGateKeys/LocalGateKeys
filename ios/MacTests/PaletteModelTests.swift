import XCTest
import AppKit
import LGKCore
@testable import AppSharedMac

@MainActor
final class PaletteModelTests: XCTestCase {
    private func item(_ id: String, _ kind: String = "web", title: String? = nil, tags: [String] = [],
                      user: String = "") -> VaultItem {
        VaultItem(id: id, record: ["kind": .string(kind), "title": .string(title ?? id), "username": .string(user),
                                   "tags": .array(tags.map { .string($0) }), "updated_at": .int(0)])!
    }

    private func titles(_ rows: [PaletteRow]) -> [String] { rows.map(\.title) }

    func testPrefixes() {
        let items = [item("a", "note", title: "Lock box", tags: ["home"]), item("b", "note", title: "Work wifi", tags: ["work"]),
                     item("c", "web", title: "Locksmith", tags: ["home"])]
        // > actions only.
        let actions = PaletteModel.results(">lock", items: items, unlocked: true)
        XCTAssertEqual(titles(actions), ["Lock now"])
        XCTAssertTrue(actions.allSatisfy { $0.group == .actions })
        // # → tag:x, items only.
        let tagged = PaletteModel.results("#home", items: items, unlocked: true)
        XCTAssertEqual(Set(titles(tagged)), ["Lock box", "Locksmith"])
        XCTAssertTrue(tagged.allSatisfy { $0.group == .items })
        // @ → items in collections whose name matches (typed items only), at most 12.
        let cols = [LocalData.Collection(id: "c1", name: "Household", createdAt: 0, updatedAt: 0), LocalData.Collection(id: "c2", name: "Office", createdAt: 0, updatedAt: 0)]
        var many = items
        var members: [String: [String]] = ["a": ["c1"], "b": ["c2"], "c": ["c1"]]
        for i in 0..<20 { many.append(item("n\(i)", "note", title: "Note \(i)")); members["n\(i)"] = ["c1"] }
        let house = PaletteModel.results("@house", items: many, collections: cols, memberships: members, unlocked: true)
        XCTAssertEqual(house.count, 12)
        XCTAssertFalse(titles(house).contains("Locksmith"), "logins are never collection members")
        XCTAssertFalse(titles(house).contains("Work wifi"))
        XCTAssertEqual(titles(PaletteModel.results("@off", items: many, collections: cols, memberships: members, unlocked: true)),
                       ["Work wifi"])
        // Plain text: every group, Actions, Items, Settings, Help in order.
        let plain = PaletteModel.results("lock", items: items, unlocked: true)
        XCTAssertEqual(titles(plain), ["Lock now", "Lock box", "Locksmith", "Locking", "Unlocking"])
        XCTAssertEqual(PaletteModel.placeholder, "Search items and actions — > actions, # tags, @ collections")
    }

    func testRowLimitsAndItemReserve() {
        let items = (0..<30).map { item("i\($0)", "note", title: "Settings note \($0)") }
        // Empty query: commands only, at most 12.
        let empty = PaletteModel.results("", items: items, unlocked: true)
        XCTAssertEqual(empty.count, 12)
        XCTAssertTrue(empty.allSatisfy { $0.group != .items })
        // A broad query keeps at least 4 item rows, 12 rows in all.
        let broad = PaletteModel.results("s", items: items, unlocked: true)
        XCTAssertEqual(broad.count, 12)
        XCTAssertGreaterThanOrEqual(broad.filter { $0.group == .items }.count, 4)
        // Group order holds.
        let order = broad.map(\.group).reduce(into: [PaletteModel.Group]()) { if $0.last != $1 { $0.append($1) } }
        XCTAssertEqual(order, PaletteModel.Group.allCases.filter(order.contains))
        // Items take what commands leave.
        let one = PaletteModel.results("settings note", items: items, unlocked: true)
        XCTAssertEqual(one.filter { $0.group == .items }.count, 12)
        // Fewer items than the reserve: only those.
        let two = PaletteModel.results("s", items: Array(items.prefix(2)), unlocked: true)
        XCTAssertEqual(two.filter { $0.group == .items }.count, 2)
        XCTAssertEqual(two.count, 12)
    }

    func testActionsHiddenWhenLocked() {
        let items = [item("a", "note", title: "Lock box")]
        let locked = PaletteModel.results("", items: items, unlocked: false)
        XCTAssertEqual(titles(locked), ["Keyboard shortcuts"])
        XCTAssertEqual(titles(PaletteModel.results("lock", items: items, unlocked: false)), [])
        XCTAssertEqual(PaletteModel.results("@x", items: items, unlocked: false), [])
        XCTAssertEqual(PaletteModel.results("#x", items: items, unlocked: false), [])

        var unlocked = true
        let model = PaletteModel(items: { items }, isUnlocked: { unlocked })
        model.query = "lock"
        let lockRow = try! XCTUnwrap(model.rows.first { $0.title == "Lock now" })
        let itemRow = try! XCTUnwrap(model.rows.first { $0.title == "Lock box" })
        XCTAssertTrue(model.allows(lockRow))
        unlocked = false   // the vault locked while the palette was open
        XCTAssertFalse(model.allows(lockRow))
        XCTAssertFalse(model.allows(itemRow))
        XCTAssertTrue(model.rows.isEmpty)
        XCTAssertTrue(model.allows(PaletteModel.commandRow(PaletteModel.commands.last!)), "Keyboard shortcuts")

        // The Mac's actions, settings and help rows (brief).
        XCTAssertEqual(PaletteModel.commands.filter { $0.group == .actions }.map(\.title),
                       ["Generate password", "New item", "Scan QR code", "Lock now", "Change master password", "Security centre",
                        "Security check", "Reminders", "Trash", "Activity", "Devices & connections", "Sync", "Sync status",
                        "Receive a shared item…", "Import…", "Export…", "Recovery centre"])
        XCTAssertEqual(PaletteModel.commands.filter { $0.group == .settings }.map(\.title),
                       ["Settings", "Locking", "Unlocking", "Privacy", "Appearance", "Plan"])
        XCTAssertEqual(PaletteModel.commands.filter { $0.group == .help }.map(\.title), ["Show setup", "Keyboard shortcuts"])
        // Windows parity (tests/test_palette_parity.py): the plan's commands exist on the Mac too.
        let ids = Set(PaletteModel.commands.map(\.id))
        XCTAssertTrue(ids.isSuperset(of: ["security-check", "trash", "sync-status", "show-setup"]))
    }

    func testShortcutsListMatchesCommands() {
        XCTAssertEqual(MacShortcuts.title, "Keyboard shortcuts")
        XCTAssertEqual(MacShortcuts.subtitle, "Press Esc to close.")
        XCTAssertEqual(MacShortcuts.groups, ["Main window", "Saved items", "Anywhere"])
        let keys = Set(MacShortcuts.rows.map(\.keys))
        // Every menu key equivalent (Commands.swift binds these MacKey values) is listed.
        for key in [MacKey.palette, .find, .newItem, .lock, .edit, .save] {
            XCTAssertTrue(keys.contains(key.label), key.label)
        }
        XCTAssertEqual(MacKey.palette.label, "⌘K")
        XCTAssertEqual(MacKey.shortcuts.label, "⌘/")
        XCTAssertTrue(keys.contains("⌘/ or ?"))
        // The window's key monitor: ⌘C, ⇧⌘C and ⌘T from the item list; ⌫ moves to Recently deleted.
        XCTAssertTrue(keys.isSuperset(of: ["⌘C", "⇧⌘C", "⌘T", "⌫", "⌘,", "Return or Space", "Double-click"]))
        XCTAssertTrue(CopyShortcutPolicy.intercepts(key: "c", shift: false, responder: .itemList, listShown: true))
        XCTAssertTrue(CopyShortcutPolicy.intercepts(key: "c", shift: true, responder: .itemList, listShown: true))
        XCTAssertTrue(CopyShortcutPolicy.intercepts(key: "t", shift: false, responder: .itemList, listShown: true))
        XCTAssertTrue(MainWindow.isDeleteKey(51))
        XCTAssertEqual(MacShortcuts.rows.first { $0.keys == "⌫" }?.description, "Move the selected item to Recently deleted.")
        // ? opens the sheet only outside text fields.
        XCTAssertTrue(MainWindow.opensShortcuts(characters: "?", modifiers: .shift, inTextField: false))
        XCTAssertTrue(MainWindow.opensShortcuts(characters: "?", modifiers: [], inTextField: false))
        XCTAssertFalse(MainWindow.opensShortcuts(characters: "?", modifiers: .shift, inTextField: true))
        XCTAssertFalse(MainWindow.opensShortcuts(characters: "/", modifiers: [], inTextField: false))
        XCTAssertEqual(StatusLine.hint, "⌘K search · ⌘N new · ⌘L lock · ⌘/ all shortcuts")
    }

    func testNoLockStateCountsAsLocked() {
        XCTAssertFalse(MainWindow.isUnlocked(nil))
        let model = PaletteModel(items: { [] }, isUnlocked: { MainWindow.isUnlocked(nil) })
        XCTAssertEqual(model.rows.map(\.title), ["Keyboard shortcuts"])
        XCTAssertFalse(model.allows(PaletteModel.commandRow(PaletteModel.commands[0])))
    }
}
