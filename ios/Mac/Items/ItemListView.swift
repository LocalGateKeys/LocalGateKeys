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
    enum Failure: Error { case notFound }

    /// Stars or un-stars an item: the record's `favorite` field, as the iPhone and Windows store it, saved
    /// through the store like the editor's saves (normal form, wrapper, `updated_at` stamped).
    static func setFavourite(id: String, _ on: Bool, store: any ItemStore, clock: any UnixClock) throws {
        var snap = try store.load()
        guard case .object(let w)? = snap.records[id], case .string(let nsRaw)? = w["ns"],
              let ns = Namespace(rawValue: nsRaw), case .object(var record)? = w["record"] else { throw Failure.notFound }
        guard record["favorite"] != .bool(on) else { return }
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
                            ItemRow(item: item, selected: item.id == selection, tag: tag(item.id))
                                .id(item.id)
                                .onTapGesture { selection = item.id; focused.wrappedValue = true }
                                .simultaneousGesture(TapGesture(count: 2).onEnded { selection = item.id; onOpen(item.id) })
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
