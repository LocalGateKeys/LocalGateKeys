import SwiftUI
import AppSharedMac

/// What the middle panel lists: the sidebar row's items, then the search within them (desktop ranking).
enum ItemListFilter {
    static func apply(_ items: [VaultItem], selection: SidebarSelection, query: String,
                      memberships: [String: [String]] = [:]) -> [VaultItem] {
        VaultSearch.rank(SidebarModel.filter(items, by: selection, memberships: memberships), query: query)
    }
}

/// Small record edits made outside the editor.
enum ItemActions {
    /// `readOnly`: the item is in a collection shared with this vault as view only (sub-plan 07; Windows
    /// `check_writable` runs after a favourite change too).
    enum Failure: Error { case notFound, readOnly }

    /// Stars or un-stars an item: the record's `favorite` field, as the iPhone and Windows store it, saved
    /// through the store like the editor's saves (normal form, wrapper, `updated_at` stamped).
    static func setFavourite(id: String, _ on: Bool, store: any ItemStore, clock: any UnixClock) throws {
        var snap = try store.load()
        guard case .object(let w)? = snap.records[id], case .string(let nsRaw)? = w["ns"],
              let ns = Namespace(rawValue: nsRaw), ns != .heir, case .object(var record)? = w["record"] else { throw Failure.notFound }
        guard record["favorite"] != .bool(on) else { return }
        if EditorModel.itemIsReadOnly(id, in: snap) { throw Failure.readOnly }
        record["favorite"] = .bool(on)
        record["updated_at"] = .int(clock.now)
        let normal = try Normalise.normalForm(ns: ns, record: .object(record))
        snap.records[id] = Wrapper.make(ns: ns, record: normal)
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
    }

    /// The item's first web address: a login's page address (`VaultItem.pageAddress`: its origin, or an imported
    /// full address on it), a bookmark's URL, else a `url` field. http(s) only.
    static func website(_ item: VaultItem) -> URL? {
        let candidates = [VaultItem.pageAddress(item.record["scope"]?.objectValue),
                          item.record["payload"]?.objectValue?["url"]?.stringValue,
                          item.record["url"]?.stringValue]
        for case let s? in candidates {
            if let url = URL(string: s.trimmingCharacters(in: .whitespaces)),
               let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http", url.host != nil { return url }
        }
        return nil
    }
}

/// What a list row offers (selected row's buttons, right-click menu). Each returns nil when the item has nothing to
/// do there, so the entry is left out.
struct ItemRowActions {
    var copyUsername: @MainActor (VaultItem) -> (() -> Void)? = { _ in nil }
    var copyPassword: @MainActor (VaultItem) -> (() -> Void)? = { _ in nil }
    var copyCode: @MainActor (VaultItem) -> (() -> Void)? = { _ in nil }
    var edit: @MainActor (VaultItem) -> (() -> Void)? = { _ in nil }
    var moveToTrash: @MainActor (VaultItem) -> (() -> Void)? = { _ in nil }
}

/// The item list of the middle panel. ↑/↓ move the selection (the detail panel follows), Return or Space
/// (or a double-click) opens the item in the detail panel.
struct ItemListView: View {
    let items: [VaultItem]
    @Binding var selection: String?
    var focused: FocusState<Bool>.Binding
    var onOpen: (String) -> Void = { _ in }
    /// The row's health tag (Breached / Weak / Reused).
    var tag: (String) -> String? = { _ in nil }
    /// Scrolls with the list, above it: the overview, title and chips.
    var header: AnyView = AnyView(EmptyView())
    /// Copy buttons on the selected row and the right-click menu (nil: neither).
    var rowActions: ItemRowActions? = nil
    /// Shown instead of the rows when there are none.
    var emptyText: String = ""
    @Environment(\.macTheme) private var theme

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                header
                if items.isEmpty {
                    Text(emptyText).foregroundStyle(theme.textMuted)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 2)
                } else {
                    LazyVStack(spacing: 0) {
                        ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                            if index > 0 { Rectangle().fill(theme.line).frame(height: 1) }
                            let selected = item.id == selection
                            ItemRow(item: item, selected: selected, tag: tag(item.id),
                                    onCopyUsername: selected ? rowActions?.copyUsername(item) : nil,
                                    onCopyPassword: selected ? rowActions?.copyPassword(item) : nil)
                                .id(item.id)
                                .onTapGesture { selection = item.id; focused.wrappedValue = true }
                                .simultaneousGesture(TapGesture(count: 2).onEnded { selection = item.id; onOpen(item.id) })
                                .contextMenu { if let rowActions { contextMenu(item, rowActions) } }
                                .accessibilityActions { if let rowActions { accessibilityActions(item, rowActions) } }
                        }
                    }
                    .background(theme.card, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                }
            }
            .scrollIndicators(.automatic)
            .softBottomEdge()
            .focusable()
            .focusEffectDisabled()
            .focused(focused)
            .onKeyPress(.downArrow) { move(1, proxy); return .handled }
            .onKeyPress(.upArrow) { move(-1, proxy); return .handled }
            .onKeyPress(.return) { open(); return .handled }
            .onKeyPress(.space) { open(); return .handled }
            .onChange(of: selection) { _, id in if let id { withAnimation(.easeOut(duration: 0.12)) { proxy.scrollTo(id) } } }
        }
    }

    /// VoiceOver actions on every row (VO-⌘-Space), so copying needs no trip into the detail panel.
    @ViewBuilder private func accessibilityActions(_ item: VaultItem, _ actions: ItemRowActions) -> some View {
        if let user = actions.copyUsername(item) { Button(String(localized: "Copy username"), action: user) }
        if let password = actions.copyPassword(item) { Button(String(localized: "Copy password"), action: password) }
        if let code = actions.copyCode(item) { Button(String(localized: "Copy one-time code"), action: code) }
    }

    /// Right-click on a row: copy username, password, 2FA code; Edit; Move to trash (entries the item lacks are left out).
    @ViewBuilder private func contextMenu(_ item: VaultItem, _ actions: ItemRowActions) -> some View {
        let user = actions.copyUsername(item)
        let password = actions.copyPassword(item)
        let code = actions.copyCode(item)
        let edit = actions.edit(item)
        let trash = actions.moveToTrash(item)
        if let user { Button(String(localized: "Copy username"), action: user) }
        if let password { Button(String(localized: "Copy password"), action: password) }
        if let code { Button(String(localized: "Copy one-time code"), action: code) }
        if user != nil || password != nil || code != nil, edit != nil || trash != nil { Divider() }
        if let edit { Button(String(localized: "Edit"), action: edit) }
        if let trash { Button(String(localized: "Move to Recently deleted"), action: trash) }
    }

    private func move(_ step: Int, _ proxy: ScrollViewProxy) {
        guard !items.isEmpty else { return }
        let current = items.firstIndex { $0.id == selection }
        let next = current.map { min(max($0 + step, 0), items.count - 1) } ?? 0
        selection = items[next].id
    }

    private func open() {
        if selection == nil { selection = items.first?.id }
        if let selection { onOpen(selection) }
    }
}
