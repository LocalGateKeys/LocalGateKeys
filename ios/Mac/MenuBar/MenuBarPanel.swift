import SwiftUI
import AppSharedMac

/// The menu bar icon's panel (Windows' tray menu and quick access): search the vault and copy a username,
/// password or one-time code without opening the window. Copies go through the main window (QuickAccessBridge).
struct MenuBarPanel: View {
    let lock: MacLockModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismiss) private var dismiss
    @Environment(\.macTheme) private var theme
    @State private var query = ""
    @State private var list: VaultListModel?
    @FocusState private var searchFocused: Bool

    static let maxResults = 8

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if lock.state == .unlocked {
                TextField("Search your vault", text: $query)
                    .textFieldStyle(.roundedBorder).focused($searchFocused)
                    .onSubmit { if let first = results.first { copy(first, defaultCopy(first)) } }
                if results.isEmpty {
                    Text(query.isEmpty ? String(localized: "No items yet.") : String(localized: "Nothing matches."))
                        .font(.system(size: 12)).foregroundStyle(theme.textMuted).padding(.vertical, 6)
                } else {
                    VStack(spacing: 2) { ForEach(results) { row($0) } }
                }
            } else {
                Label(lock.state == .noVault ? String(localized: "No vault on this Mac yet.") : String(localized: "LocalGateKeys is locked."),
                      systemImage: "lock.fill")
                    .font(.system(size: 13)).foregroundStyle(theme.text)
            }
            Divider()
            HStack {
                Button(lock.state == .locked ? String(localized: "Unlock…") : String(localized: "Open LocalGateKeys")) { showWindow() }
                Spacer()
                if lock.state == .unlocked { Button("Lock") { lock.lock() } }
                Button("Quit") { NSApp.terminate(nil) }
            }
            .buttonStyle(.borderless).font(.system(size: 12))
        }
        .padding(12).frame(width: 320)
        .onAppear { reload(); searchFocused = true }
        .onChange(of: lock.state) { _, _ in reload() }
    }

    private var results: [VaultItem] {
        guard let items = list?.items else { return [] }
        let ranked = query.isEmpty ? items.filter(\.favorite) + items.filter { !$0.favorite } : VaultSearch.rank(items, query: query)
        return Array(ranked.prefix(Self.maxResults))
    }

    private func row(_ item: VaultItem) -> some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title.isEmpty ? item.kindLabel : item.title).font(.system(size: 13)).lineLimit(1)
                Text(item.listSubtitle).font(.system(size: 11)).foregroundStyle(theme.textMuted).lineLimit(1)
            }
            Spacer(minLength: 6)
            if item.isLogin, !item.username.isEmpty {
                iconButton("person", help: String(localized: "Copy username")) { copy(item, .username) }
            }
            if MainWindow.password(of: item) != nil {
                iconButton("key", help: String(localized: "Copy password")) { copy(item, .password) }
            }
            if MainWindow.hasCode(item) {
                iconButton("clock", help: String(localized: "Copy 2FA code")) { copy(item, .code) }
            }
        }
        .padding(.horizontal, 6).padding(.vertical, 4)
        .contentShape(Rectangle())
    }

    private func iconButton(_ symbol: String, help: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) { Image(systemName: symbol).frame(width: 22, height: 22) }
            .buttonStyle(.borderless).help(help).accessibilityLabel(help)
    }

    /// Return copies the first result's password, else its code, else its username.
    private func defaultCopy(_ item: VaultItem) -> QuickAccessBridge.Copy {
        if MainWindow.password(of: item) != nil { return .password }
        return MainWindow.hasCode(item) ? .code : .username
    }

    private func copy(_ item: VaultItem, _ kind: QuickAccessBridge.Copy) {
        QuickAccessBridge.shared.copy(item.id, kind)
        if QuickAccessBridge.shared.openWindows == 0 { openWindow(id: MacAppInfo.mainWindowID) }
        dismiss()
    }

    private func showWindow() {
        if QuickAccessBridge.shared.openWindows == 0 { openWindow(id: MacAppInfo.mainWindowID) }
        QuickAccessBridge.activate()
        dismiss()
    }

    private func reload() {
        guard lock.state == .unlocked, let store = lock.store else { list = nil; return }
        let model = list ?? VaultListModel(store: store)
        model.reload(); list = model
    }
}
