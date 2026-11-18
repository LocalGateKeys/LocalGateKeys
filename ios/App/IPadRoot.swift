import SwiftUI
import AppShared

/// A row of the iPad sidebar (UX refresh section 8): the vault views, the types and collections, then the other
/// screens of the tab layout.
enum SidebarEntry: Hashable {
    case all, favorites, codes, kind(String), collection(String)
    case sync, security, settings

    /// The tab-layout screen this row stands for; nil for the vault rows.
    var screen: RootTab? {
        switch self {
        case .sync: .sync
        case .security: .security
        case .settings: .settings
        default: nil
        }
    }

    /// The items this vault row lists (the collection is applied by the model's own Collections filter).
    @MainActor func items(_ model: VaultListModel) -> [VaultItem] {
        switch self {
        case .favorites: model.listItems.filter(\.favorite)
        case .codes: model.items.filter(\.hasTOTP)
        case .kind(let k): model.listItems.filter { $0.kind == k }
        default: model.listItems
        }
    }
}

/// The regular-width root on iPad: sidebar, item list (search and +) and item detail in a `NavigationSplitView`.
/// Sync, Security and Settings show in the detail column of a two-column split. The sheets, deep links, setup
/// and lock stay on `RootTabs`, which hosts this view.
struct IPadRoot: View {
    let model: VaultListModel
    let store: any ItemStore
    let pro: ProModel
    let sync: SyncCoordinator
    let lock: AppLockModel
    @Binding var tab: RootTab
    @Binding var section: SidebarEntry
    /// The Sync, Security and Settings screens of the tab layout.
    let screen: (RootTab) -> AnyView
    /// Vault › Collections (Manage collections), shown as a sheet.
    let collectionsScreen: () -> AnyView
    let openImport: () -> Void

    @State private var selection: String?
    @State private var query = ""
    @State private var searchPresented = false
    @State private var newKind: EditorKind?
    @State private var showUpgrade = false
    @State private var showCollections = false
    @State private var scanning: TwoFactorScanModel?
    @State private var scannedLogin: ScannedLogin?
    @State private var pendingLogin: ScannedLogin?
    @State private var addingFile = false
    @State private var columns: NavigationSplitViewVisibility = .all

    var body: some View {
        Group {
            if let screenTab = tab == .vault ? nil : tab {
                NavigationSplitView {
                    sidebar
                } detail: {
                    screen(screenTab)
                }
            } else {
                NavigationSplitView(columnVisibility: $columns) {
                    sidebar
                } content: {
                    // About as wide as the detail column on a 13-inch iPad in landscape (system default: about 320 pt).
                    itemList.navigationSplitViewColumnWidth(min: 340, ideal: 530, max: 640)
                } detail: {
                    detail
                }
            }
        }
        .background { shortcuts }
        .sheet(item: $newKind) { kind in
            EditorView(model: EditorModel(store: store, pro: pro, editing: nil, kind: kind, clock: SystemClock(),
                                          random: SystemRandomSource()),
                       pro: pro) { _ in edited() }
        }
        .sheet(isPresented: $showUpgrade) { UpgradeView(pro: pro, itemsUsed: model.liveCount) }
        .sheet(isPresented: $showCollections, onDismiss: edited) { NavigationStack { collectionsScreen() } }
        .modifier(AddFileFlow(isPresented: $addingFile, store: store, pro: pro,
                              onNeedsPro: { showUpgrade = true }, onAdded: edited))
        .sheet(item: $scanning, onDismiss: {
            if let login = pendingLogin { pendingLogin = nil; scannedLogin = login }
        }) { scan in
            TwoFactorScanView(model: scan, onNewLogin: { pendingLogin = ScannedLogin(editor: $0) }, onSaved: edited)
        }
        .onChange(of: TwoFactorLinkRoute.shared.pending, initial: true) { _, link in
            guard link != nil, let link = TwoFactorLinkRoute.shared.take() else { return }
            openTwoFactorLink(link)
        }
        .sheet(item: $scannedLogin) { login in
            EditorView(model: login.editor, pro: pro) { _ in edited() }
        }
        .onAppear {
            reload()
            #if DEBUG
            // `-LGKScreen item` (screenshots): the favourite opens in the detail column; `-LGKScreen codes` also lists the codes.
            if [.item, .edit, .codes].contains(ScreenshotScreen.requested) {
                selection = (model.items.first(where: \.favorite) ?? model.items.first)?.id
            }
            if ScreenshotScreen.requested == .codes { section = .codes }
            // `-LGKSelect <title>` opens that item instead.
            if let title = UserDefaults.standard.string(forKey: "LGKSelect") {
                selection = model.items.first(where: { $0.title == title })?.id
            }
            #endif
            // The Collections filter chosen in the tab layout shows as its sidebar row.
            if let id = model.collectionFilter, section.screen == nil { section = .collection(id) }
        }
        .onChange(of: sync.completedRuns) { reload() }
        .onChange(of: section) { _, new in
            if case .collection(let id) = new { model.collectionFilter = id } else if new.screen == nil { model.collectionFilter = nil }
        }
        .onChange(of: model.items) { _, items in
            // The selected item was deleted (here or by a sync): the detail goes back to "Select an item".
            if let id = selection, !items.contains(where: { $0.id == id }) { selection = nil }
        }
    }

    // MARK: Columns

    private var sidebarSelection: Binding<SidebarEntry?> {
        Binding(get: { tab == .vault ? section : SidebarEntry.screenEntry(tab) },
                set: { new in
                    guard let new else { return }
                    if let screenTab = new.screen { tab = screenTab } else { section = new; tab = .vault }
                })
    }

    private var sidebar: some View {
        List(selection: sidebarSelection) {
            Section("Vault") {
                Label("All items", systemImage: "tray.full").tag(SidebarEntry.all)
                Label("Favorites", systemImage: "star").tag(SidebarEntry.favorites)
                Label("Codes", systemImage: "number").tag(SidebarEntry.codes)
            }
            let kinds = VaultSearch.filterOptions(model.items).compactMap { option -> String? in
                if case .kind(let k) = option { return k } else { return nil }
            }
            if !kinds.isEmpty {
                Section("Types") {
                    ForEach(kinds, id: \.self) { kind in
                        Label(VaultFilter.kind(kind).label, systemImage: VaultRow.icon(kind)).tag(SidebarEntry.kind(kind))
                    }
                }
            }
            Section("Collections") {
                ForEach(model.collections, id: \.id) { collection in
                    Label { Text(verbatim: CollectionCatalog.displayName(collection.name)) } icon: { Image(systemName: "folder") }
                        .tag(SidebarEntry.collection(collection.id))
                }
                Button { showCollections = true } label: { Label("Manage collections", systemImage: "folder.badge.gearshape") }
            }
            Section {
                Label("Sync", systemImage: "arrow.triangle.2.circlepath").tag(SidebarEntry.sync)
                Label("Security", systemImage: "checkmark.shield").tag(SidebarEntry.security)
                Label("Settings", systemImage: "gearshape").tag(SidebarEntry.settings)
            }
        }
        .listStyle(.sidebar)
        .navigationTitle("Vault")
    }

    private var listedItems: [VaultItem] {
        VaultSearch.apply(section.items(model), query: query, filter: .all)
    }

    private var itemList: some View {
        let items = listedItems
        return List(selection: $selection) {
            if let error = model.loadError {
                Text(error).foregroundStyle(Palette.danger)
            }
            // The phone's Codes row above the items (All items and Favorites; Codes lists them itself).
            let codes = model.items.filter(\.hasTOTP)
            if [.all, .favorites].contains(section), query.isEmpty, !codes.isEmpty, AppSettings.shared.showCodesRow {
                CodesRow(items: codes)
                    .listRowSeparator(.hidden).listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                    .selectionDisabled()
            }
            ForEach(items) { item in
                VaultRow(item: item)
                    .tag(item.id)
                    .contextMenu { QuickActionsMenu(item: item, onFavorite: toggleFavorite) }
            }
            if model.items.isEmpty && model.loadError == nil {
                Text("No items yet. Tap + to add one.").foregroundStyle(Palette.secondaryText)
                Button("Restore from a backup", action: openImport).foregroundStyle(Palette.accentText)
            } else if items.isEmpty && model.loadError == nil {
                Text("No items of this type.").foregroundStyle(Palette.secondaryText)
            }
        }
        .listStyle(.plain)
        .searchable(text: $query, isPresented: $searchPresented)
        .refreshable { await sync.sync(.pullToRefresh); reload() }
        .navigationTitle(title)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                NewItemMenu(onPick: { kind in
                    if ItemLimit.allows(.create, snapshot: model.snapshot, isPro: pro.isPro) { newKind = kind } else { showUpgrade = true }
                }, onScan: startScan, onAddFile: {
                    if pro.isPro { addingFile = true } else { showUpgrade = true }
                }) {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("New item")
            }
        }
    }

    @ViewBuilder private var detail: some View {
        if let id = selection, let item = model.items.first(where: { $0.id == id }) {
            NavigationStack {
                ItemDetailView(item: item, store: store, pro: pro, onChange: edited)
            }
            .id(item.id)
        } else {
            Text("Select an item").font(.title3).foregroundStyle(Palette.secondaryText)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private var title: String {
        switch section {
        case .all: String(localized: "All items")
        case .favorites: String(localized: "Favorites")
        case .codes: String(localized: "Codes")
        case .kind(let k): VaultFilter.kind(k).label
        case .collection: model.collectionFilterName ?? String(localized: "Collections")
        case .sync, .security, .settings: String(localized: "Vault")
        }
    }

    // MARK: Hardware keyboard

    /// Cmd-N new item, Cmd-F search, Cmd-L lock, Shift-Cmd-C copy the selected item's password. Hidden buttons
    /// (the pattern of the Vault header's Cmd-K) so the shortcuts work whatever has focus.
    private var shortcuts: some View {
        Group {
            Button("New item") { newItem() }.keyboardShortcut("n", modifiers: .command)
            Button("Search") { tab = .vault; searchPresented = true }.keyboardShortcut("f", modifiers: .command)
            Button("Lock now") { lock.lock() }.keyboardShortcut("l", modifiers: .command)
            Button("Copy password") { copySelectedPassword() }.keyboardShortcut("c", modifiers: [.command, .shift])
        }
        .frame(width: 0, height: 0).opacity(0)
        .accessibilityHidden(true)
    }

    private func newItem() {
        if ItemLimit.allows(.create, snapshot: model.snapshot, isPro: pro.isPro) { newKind = .web } else { showUpgrade = true }
    }

    private func copySelectedPassword() {
        guard tab == .vault, let id = selection, let item = model.items.first(where: { $0.id == id }),
              let password = item.copyablePassword else { return }
        Task {
            guard await AccessGate.shared.mayCopy(item) else { return }
            QuickActionsMenu.copy(password, String(localized: "Password copied"), clearAfterAtMost: AccessGate.shared.copyLimit(item))
        }
    }

    // MARK: Actions (as on the Vault tab)

    private func toggleFavorite(_ item: VaultItem) {
        let r = VaultListModel.setFavorite(!item.favorite, id: item.id, store: store, clock: SystemClock())
        if r == .saved { edited() }
        if r == .invalid { CopyToast.shared.show(EditorModel.readOnlyItemText, for: .seconds(3)) }
    }

    private func startScan() {
        guard pro.isPro else { showUpgrade = true; return }
        scanning = TwoFactorScanModel(store: store, pro: pro)
    }

    /// An `otpauth` link opened from outside: the scan flow at its next step, or the new login's editor.
    private func openTwoFactorLink(_ link: String) {
        guard let (scan, editor) = TwoFactorLinkRoute.scanFlow(link, store: store, pro: pro) else { showUpgrade = true; return }
        if let editor { scannedLogin = ScannedLogin(editor: editor) } else { scanning = scan }
    }

    private func edited() {
        reload()
        sync.noteLocalEdit()
    }

    private func reload() {
        model.reload()
        pro.update(from: model.snapshot)
    }
}

extension SidebarEntry {
    static func screenEntry(_ tab: RootTab) -> SidebarEntry? {
        switch tab {
        case .vault: nil
        case .sync: .sync
        case .security: .security
        case .settings: .settings
        }
    }
}
