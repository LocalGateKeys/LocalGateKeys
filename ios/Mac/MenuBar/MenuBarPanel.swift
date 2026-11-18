import SwiftUI
import AppSharedMac

/// The menu bar icon's panel (Windows' tray menu and quick access): search the vault and copy a username,
/// password or one-time code without opening the window. Copies go through the main window (QuickAccessBridge).
/// Keyboard (UX refresh 2026-11-12): ↑/↓ move the selection, Return copies the password, ⌘U the username,
/// ⌘T the one-time code. Rows with a 2FA key show the live code inline (hidden for logins that need the master
/// password).
struct MenuBarPanel: View {
    let lock: MacLockModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismiss) private var dismiss
    @Environment(\.macTheme) private var theme
    @State private var query = ""
    @State private var list: VaultListModel?
    /// The lock model's session the list was made in.
    @State private var listGeneration = -1
    /// The highlighted row (falls back to the first result).
    @State private var selectedID: String?
    @FocusState private var searchFocused: Bool

    static let maxResults = 8

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if lock.state == .unlocked {
                TextField("Search your vault", text: $query)
                    .textFieldStyle(.roundedBorder).focused($searchFocused)
                    .onSubmit { if let item = selected { copy(item, MainWindow.password(of: item) != nil ? .password : defaultCopy(item)) } }
                    .onKeyPress(.downArrow) { move(1); return .handled }
                    .onKeyPress(.upArrow) { move(-1); return .handled }
                    .onChange(of: query) { _, _ in selectedID = nil }
                if results.isEmpty {
                    Text(query.isEmpty ? String(localized: "No items yet.") : String(localized: "Nothing matches."))
                        .font(.system(size: 12)).foregroundStyle(theme.textMuted).padding(.vertical, 6)
                } else {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let now = Int64(context.date.timeIntervalSince1970)
                        VStack(spacing: 2) { ForEach(results) { row($0, now: now) } }
                    }
                }
                shortcutButtons
            } else {
                Label(lock.state == .noVault ? String(localized: "No vault on this Mac yet.") : String(localized: "LocalGateKeys is locked."),
                      systemImage: "lock.fill")
                    .font(.system(size: 13)).foregroundStyle(theme.text)
            }
            Divider()
            if lock.state == .unlocked && !results.isEmpty {
                Text(String(localized: "menubar.hints", defaultValue: "↑↓ select · ↩ password · ⌘U username · ⌘T code"))
                    .font(.system(size: 11)).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button(lock.state == .locked ? String(localized: "Unlock…") : String(localized: "Open LocalGateKeys")) { showWindow() }
                Spacer()
                if lock.state == .unlocked { Button("Lock") { lock.lock() } }
                Button("Quit") { NSApp.terminate(nil) }
            }
            .buttonStyle(.borderless).font(.system(size: 12))
        }
        .padding(12).frame(width: 340)
        .onAppear { reload(); searchFocused = true }
        .onChange(of: lock.state) { _, _ in reload() }
    }

    /// ⌘U and ⌘T as key equivalents, so the search field's own handling never takes them.
    private var shortcutButtons: some View {
        ZStack {
            Button("") { if let item = selected, item.isLogin, !item.username.isEmpty { copy(item, .username) } }
                .keyboardShortcut("u", modifiers: .command)
            Button("") { if let item = selected, MainWindow.hasCode(item) { copy(item, .code) } }
                .keyboardShortcut("t", modifiers: .command)
        }
        .opacity(0).frame(width: 0, height: 0).accessibilityHidden(true)
    }

    private var results: [VaultItem] {
        guard let items = list?.items else { return [] }
        let ranked = query.isEmpty ? items.filter(\.favorite) + items.filter { !$0.favorite } : VaultSearch.rank(items, query: query)
        return Array(ranked.prefix(Self.maxResults))
    }

    /// The highlighted result: the chosen one while it is listed, else the first.
    private var selected: VaultItem? {
        let shown = results
        return shown.first { $0.id == selectedID } ?? shown.first
    }

    private func move(_ step: Int) {
        let shown = results
        guard !shown.isEmpty else { return }
        let current = shown.firstIndex { $0.id == selected?.id } ?? 0
        selectedID = shown[min(max(current + step, 0), shown.count - 1)].id
    }

    private func row(_ item: VaultItem, now: Int64) -> some View {
        let isSelected = item.id == selected?.id
        return HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title.isEmpty ? item.kindLabel : item.title).font(.system(size: 13)).lineLimit(1)
                Text(item.listSubtitle).font(.system(size: 11)).foregroundStyle(theme.textMuted).lineLimit(1)
            }
            Spacer(minLength: 6)
            if MainWindow.hasCode(item) { inlineCode(item, now: now) }
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
        .background(isSelected ? theme.selection : .clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        .contentShape(Rectangle())
        .onTapGesture { selectedID = item.id }
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    /// The live code beside the copy buttons; "Hidden" for logins that need the master password first.
    @ViewBuilder private func inlineCode(_ item: VaultItem, now: Int64) -> some View {
        if StrictItemGate.isStrict(item) {
            Text(String(localized: "Hidden")).font(.system(size: 11)).foregroundStyle(theme.textMuted)
        } else if let code = Self.code(of: item, now: now) {
            Text(DetailPanel.grouped(code)).font(.system(size: 13, weight: .semibold, design: .monospaced))
                .foregroundStyle(theme.text).fixedSize()
                .accessibilityLabel(String(localized: "menubar.code", defaultValue: "One-time code \(code)"))
        }
    }

    /// The item's current code, as the main window computes it for copying.
    static func code(of item: VaultItem, now: Int64) -> String? {
        guard case .object(let t)? = item.record["totp"], let secret = t["secret"]?.stringValue else { return nil }
        func int(_ k: String, _ d: Int) -> Int { if case .int(let n)? = t[k] { return Int(n) }; return d }
        return try? TOTP.code(secret: secret, algorithm: t["algorithm"]?.stringValue ?? "SHA1", digits: int("digits", 6),
                              period: int("period", 30), at: now)
    }

    private func iconButton(_ symbol: String, help: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) { Image(systemName: symbol).frame(width: 22, height: 22) }
            .buttonStyle(.borderless).help(help).accessibilityLabel(help)
    }

    /// Return falls back to the code, else the username, for items without a password.
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
        // A list from an earlier unlock session is never reused (a lock missed while the panel was closed): after a
        // duress unlock it would still read the real vault's store.
        if listGeneration != lock.sessionGeneration { list = nil; listGeneration = lock.sessionGeneration }
        let model = list ?? VaultListModel(store: store)
        model.hidden = MacAccess.travelHidden   // travel mode (feature pack §2)
        model.reload(); list = model
    }
}
