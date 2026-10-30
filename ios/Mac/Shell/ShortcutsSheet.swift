import SwiftUI

/// A key the menus bind (Commands.swift reads these, so the sheet and the menus cannot drift apart).
struct MacKey: Sendable {
    let key: Character
    let shift: Bool

    @MainActor var shortcut: KeyboardShortcut {
        KeyboardShortcut(KeyEquivalent(key), modifiers: shift ? [.command, .shift] : .command)
    }
    /// "⌘K", "⇧⌘C" (Apple's modifier order).
    var label: String { (shift ? "⇧" : "") + "⌘" + String(key).uppercased() }

    static let palette = MacKey(key: "k", shift: false)
    static let find = MacKey(key: "f", shift: false)
    static let newItem = MacKey(key: "n", shift: false)
    static let lock = MacKey(key: "l", shift: false)
    static let shortcuts = MacKey(key: "/", shift: false)
    static let edit = MacKey(key: "e", shift: false)
    static let save = MacKey(key: "s", shift: false)
}

/// The shortcuts sheet's rows, in Windows' groups (`shortcut_cheat_sheet_rows`) with the Mac's keys.
enum MacShortcuts {
    struct Row: Hashable, Sendable { let group: String; let keys: String; let description: String }

    static let title = String(localized: "Keyboard shortcuts")
    static let subtitle = String(localized: "Press Esc to close.")

    static let rows: [Row] = [
        Row(group: String(localized: "Main window"), keys: MacKey.palette.label, description: String(localized: "Search everything: items, actions and settings.")),
        Row(group: String(localized: "Main window"), keys: MacKey.find.label, description: String(localized: "Jump to the search box.")),
        Row(group: String(localized: "Main window"), keys: MacKey.newItem.label, description: String(localized: "Choose what to add: login, card, note, key and more.")),
        Row(group: String(localized: "Main window"), keys: "⇧⌘C", description: String(localized: "Copy the selected login's username.")),
        Row(group: String(localized: "Main window"), keys: "⌘T", description: String(localized: "Copy the selected login's current two-factor code.")),
        Row(group: String(localized: "Main window"), keys: "⌘,", description: String(localized: "Open Settings.")),
        Row(group: String(localized: "Main window"), keys: MacKey.lock.label, description: String(localized: "Lock the vault.")),
        Row(group: String(localized: "Main window"), keys: String(localized: "\(MacKey.shortcuts.label) or ?"), description: String(localized: "Show this list of shortcuts.")),
        Row(group: String(localized: "Saved items"), keys: String(localized: "Return or Space"), description: String(localized: "Open the selected item.")),
        Row(group: String(localized: "Saved items"), keys: String(localized: "Double-click"), description: String(localized: "Open the item under the pointer.")),
        Row(group: String(localized: "Saved items"), keys: "⌘C", description: String(localized: "Copy the selected login's password (asks for confirmation).")),
        Row(group: String(localized: "Saved items"), keys: MacKey.edit.label, description: String(localized: "Edit the selected item.")),
        Row(group: String(localized: "Saved items"), keys: MacKey.save.label, description: String(localized: "Save the item being edited.")),
        Row(group: String(localized: "Saved items"), keys: "⌫", description: String(localized: "Move the selected item to Recently deleted.")),
        Row(group: String(localized: "Saved items"), keys: String(localized: "↓ (from search)"), description: String(localized: "Move into the results list.")),
        Row(group: String(localized: "Anywhere"), keys: QuickAccessSettings.hotKeyLabel, description: String(localized: "Bring LocalGateKeys forward with Search everything (Settings › Menu bar & startup).")),
    ]

    static var groups: [String] { rows.reduce(into: [String]()) { if !$0.contains($1.group) { $0.append($1.group) } } }
}

/// "Keyboard shortcuts" — ⌘/, ? outside text fields, or the palette's Help row.
struct ShortcutsSheet: View {
    let onClose: () -> Void
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 2) {
                Text(MacShortcuts.title).font(.system(size: 19, weight: .semibold)).foregroundStyle(theme.text)
                Text(MacShortcuts.subtitle).font(.system(size: 12)).foregroundStyle(theme.textMuted)
            }
            ForEach(MacShortcuts.groups, id: \.self) { group in
                VStack(alignment: .leading, spacing: 6) {
                    Text(group.uppercased()).font(.system(size: 11, weight: .semibold)).foregroundStyle(theme.textFaint)
                    VStack(spacing: 0) {
                        ForEach(MacShortcuts.rows.filter { $0.group == group }, id: \.self) { row in
                            HStack(alignment: .firstTextBaseline, spacing: 12) {
                                Text(row.keys).font(.system(size: 13, weight: .medium)).foregroundStyle(theme.text)
                                    .frame(width: 140, alignment: .leading)
                                Text(row.description).font(.system(size: 13)).foregroundStyle(theme.textMuted)
                                Spacer(minLength: 0)
                            }
                            .padding(.horizontal, 12).padding(.vertical, 6)
                        }
                    }
                    .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
                }
            }
            HStack { Spacer(); Button("Done", action: onClose).keyboardShortcut(.defaultAction) }
        }
        .padding(22)
        .frame(width: 560)
        .onExitCommand(perform: onClose)
    }
}
