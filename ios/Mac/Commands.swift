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
/// ⌘C, ⇧⌘C and ⌘T are handled first by the window's key monitor (CopyShortcutPolicy); the Item menu carries them
/// as key equivalents too, enabled only while the item list has focus.
struct MacCommands: Commands {
    let lock: MacLockModel
    let session: MacProfileSession
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
            // Locks, then shows the profile chooser on the lock screen.
            if session.canUseProfiles {
                // Sub-plan 12: with several vaults, the menu says which one is open (a label, not an action).
                if session.hasSeveral {
                    Button("Vault: \(session.active.name)") {}
                        .disabled(true)
                }
                Button("Switch Profile…") {
                    if lock.state == .unlocked { lock.lock() }
                    session.message = nil
                    session.choosing = true
                }
                .disabled(lock.isBusy)
            }
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
            // Real key equivalents (shown right-aligned, found by Help search, read by VoiceOver, remappable in
            // System Settings). The window's key monitor (CopyShortcutPolicy) still runs first; these items are
            // enabled only while the item list has focus, so elsewhere Edit › Copy (earlier in the bar) keeps ⌘C.
            Button("Copy username") { actions?.copyUsername?() }
                .keyboardShortcut("c", modifiers: [.command, .shift])
                .disabled(actions?.copyUsername == nil)
            Button("Copy password") { actions?.copyPassword?() }
                .keyboardShortcut("c", modifiers: .command)
                .disabled(actions?.copyPassword == nil)
            Button("Copy 2FA code") { actions?.copyCode?() }
                .keyboardShortcut("t", modifiers: .command)
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
