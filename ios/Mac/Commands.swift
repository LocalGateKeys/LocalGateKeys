import SwiftUI

/// What the unlocked window lets the menus do; nil entries are greyed out.
struct MacWindowActions {
    var search: () -> Void
    var palette: () -> Void
    var shortcuts: () -> Void
    var newItem: () -> Void
    var copyUsername: (() -> Void)?
    var copyPassword: (() -> Void)?
    var copyCode: (() -> Void)?
    var edit: (() -> Void)?
    var save: (() -> Void)?
    /// File › Receive a Shared Item… (a `.lgkshare` file or pasted QR text).
    var receiveShare: () -> Void = {}
}

extension FocusedValues {
    @Entry var macWindowActions: MacWindowActions?
}

/// The menu bar: every Phase 1 shortcut is listed in a menu. ⌘, is the Settings scene's own item.
/// ⌘C, ⇧⌘C and ⌘T are bound only by the window's key monitor (CopyShortcutPolicy); the Item menu lists them
/// as text, so Edit › Copy is the menu bar's only ⌘C.
struct MacCommands: Commands {
    let lock: MacLockModel
    @FocusedValue(\.macWindowActions) private var actions

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("New Item") { actions?.newItem() }
                .keyboardShortcut(MacKey.newItem.shortcut)
                .disabled(actions == nil)
        }
        CommandGroup(after: .appSettings) {
            Button("Lock") { lock.lock() }
                .keyboardShortcut(MacKey.lock.shortcut)
                .disabled(lock.state != .unlocked)
        }
        CommandGroup(after: .textEditing) {
            Button("Find") { actions?.search() }
                .keyboardShortcut(MacKey.find.shortcut)
                .disabled(actions == nil)
            Button("Receive a Shared Item…") { actions?.receiveShare() }
                .disabled(actions == nil)
            Button("Search Everything…") { actions?.palette() }
                .keyboardShortcut(MacKey.palette.shortcut)
                .disabled(actions == nil)
        }
        CommandGroup(before: .help) {
            Button("Keyboard Shortcuts") { actions?.shortcuts() }
                .keyboardShortcut(MacKey.shortcuts.shortcut)
                .disabled(actions == nil)
        }
        CommandMenu(String(localized: "Item")) {
            // No key equivalents: ⌘C, ⇧⌘C and ⌘T belong to the window's key monitor (CopyShortcutPolicy) only,
            // and these items are enabled only while the item list has focus.
            Button("Copy Username  ⇧⌘C") { actions?.copyUsername?() }
                .disabled(actions?.copyUsername == nil)
            Button("Copy Password  ⌘C") { actions?.copyPassword?() }
                .disabled(actions?.copyPassword == nil)
            Button("Copy 2FA Code  ⌘T") { actions?.copyCode?() }
                .disabled(actions?.copyCode == nil)
            Divider()
            Button("Edit") { actions?.edit?() }
                .keyboardShortcut(MacKey.edit.shortcut)
                .disabled(actions?.edit == nil)
            Button("Save") { actions?.save?() }
                .keyboardShortcut(MacKey.save.shortcut)
                .disabled(actions?.save == nil)
        }
    }
}
