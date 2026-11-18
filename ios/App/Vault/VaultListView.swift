import SwiftUI
import AppShared

/// The Vault tab: large "Vault" title with the glass scan, search, sort and + buttons, a pinned Codes row, then grouped
/// solid sections. Content never sits on glass.
struct VaultListView: View {
    let model: VaultListModel
    let store: any ItemStore
    let pro: ProModel
    let sync: SyncCoordinator
    let lock: AppLockModel
    let onActivity: () -> Void
    /// The search screen is pushed on this tab's stack (the magnifying-glass button).
    @Binding var searching: Bool
    /// Switches to the Settings tab on Import & Export (the empty vault's import card and Restore from a backup).
    var openImport: () -> Void = {}
    /// Switches to the Sync tab (the Sync status sheet's Open sync settings).
    var openSync: () -> Void = {}
    /// The Sync status sheet (a tap on the header's sync pill, workstream 6).
    @State private var showSyncStatus = false
    /// Flipped on each appearance so the hidden navigation bar is applied again: closing the search from code
    /// while its field was active left the system bar (a second "Vault" title) showing over the header.
    @State private var barVisibility: Visibility = .hidden
    /// The "Finish setting up · n of 5" card (workstream 4); nil hides it.
    var onboarding: Onboarding? = nil
    /// `>` actions that leave the Vault tab (Security, Settings, Trash, AutoFill, setup); workstream 5.
    var onNavigate: (PhoneCommand) -> Void = { _ in }
    /// The Collections menu's "Manage collections": pushes Vault › Collections (sub-plan 07).
    var openCollections: () -> Void = {}
    /// "Generate password" from the `>` actions: the generator sheet (Use copies the value).
    @State private var showGenerator = false
    @State private var newKind: EditorKind?
    @State private var showUpgrade = false
    @Bindable private var settings: AppSettings = .shared
    /// "Scan QR code": the scan sheet, then (after it has gone) the prefilled new login it asked for.
    @State private var scanning: TwoFactorScanModel?
    @State private var scannedLogin: ScannedLogin?
    @State private var pendingLogin: ScannedLogin?
    /// The list's own type filter (the Search tab keeps its own).
    @State private var filter: VaultFilter = .all
    /// "Attach a file": Files, Photos or the camera (`AddFileFlow`).
    @State private var addingFile = false
    #if DEBUG
    @State private var screenshotItem: VaultItem?
    #endif

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                if let error = model.loadError {
                    Text(error).foregroundStyle(Palette.danger).padding(.horizontal, 4)
                }
                // The setup progress is a chip on the header's status line (UX refresh §4).
                let codes = model.items.filter(\.hasTOTP)
                if !codes.isEmpty, AppSettings.shared.showCodesRow { CodesRow(items: codes) }
                // The type chips offer only the types in the chosen collection; the Codes row above stays every code.
                if !model.items.isEmpty { VaultFilterBar(filter: $filter, options: listFilterOptions).padding(.top, 4) }
                if let name = model.collectionFilterName {
                    // The Collections filter in use: a tap shows All items again.
                    Button { model.collectionFilter = nil } label: {
                        Label("Collection: \(name)", systemImage: "xmark.circle.fill").font(.subheadline)
                            .padding(.horizontal, 12).padding(.vertical, 6)
                            .foregroundStyle(Palette.onAccent)
                            .background(Palette.accent, in: Capsule())
                    }
                    .buttonStyle(.plain)
                    .accessibilityHint(Text("All items"))
                }
                if model.collectionFilter != nil && model.listItems.isEmpty && !model.items.isEmpty {
                    Text("No items in this collection.").foregroundStyle(Palette.secondaryText).frame(maxWidth: .infinity).padding(.top, 24)
                } else if let sorted = model.sortedItems(filter: filter) {
                    // A chosen sort shows one flat list in that order (no Logins / Cards and notes / Other groups).
                    if sorted.isEmpty {
                        if !model.items.isEmpty {
                            Text("No items of this type.").foregroundStyle(Palette.secondaryText).frame(maxWidth: .infinity).padding(.top, 24)
                        }
                    } else {
                        VaultGroupView(items: sorted, onFavorite: toggleFavorite)
                    }
                } else if filter == .all {
                    ForEach(VaultGroup.groups(model.listItems)) { group in
                        SectionHeader(title: group.title)
                        VaultGroupView(items: group.items, onFavorite: toggleFavorite)
                    }
                } else {
                    let matches = VaultSearch.apply(model.listItems, query: "", filter: filter)
                    if matches.isEmpty {
                        Text("No items of this type.").foregroundStyle(Palette.secondaryText).frame(maxWidth: .infinity).padding(.top, 24)
                    } else {
                        VaultGroupView(items: matches, onFavorite: toggleFavorite)
                    }
                }
                if model.items.isEmpty && model.loadError == nil && !settings.importCardDismissed {
                    ImportCard(onImport: openImport,
                               onNotNow: { settings.importCardDismissed = true })
                        .padding(.top, 16)
                }
                if model.items.isEmpty && model.loadError == nil {
                    Text("No items yet. Tap + to add one.").foregroundStyle(Palette.secondaryText).padding(.top, 24)
                        .frame(maxWidth: .infinity)
                    // A reinstalled iPhone or a new phone: the backup is restored from Import & Export.
                    Button("Restore from a backup", action: openImport)
                        .foregroundStyle(Palette.accentText).frame(maxWidth: .infinity)
                }
            }
            .padding(.horizontal, 16)
            .modifier(LegacyTabBarInset())
        }
        // The title and the + / avatar buttons sit in a top bar: rows start below it and fade out as they
        // scroll under it, and the buttons never cover (or take taps meant for) a row.
        .modifier(VaultHeaderBar(header: header))
        .lgkAuroraBackground()
        .toolbar(barVisibility, for: .navigationBar)
        .navigationTitle("Vault")
        .navigationDestination(for: VaultItem.self) { ItemDetailView(item: $0, store: store, pro: pro, onChange: edited) }
        .sheet(item: $newKind) { kind in
            EditorView(model: EditorModel(store: store, pro: pro, editing: nil, kind: kind, clock: SystemClock(),
                                          random: SystemRandomSource()),
                       pro: pro) { _ in edited() }
        }
        .sheet(isPresented: $showUpgrade) { UpgradeView(pro: pro, itemsUsed: model.liveCount) }
        .sheet(isPresented: $showSyncStatus) { SyncStatusSheet(sync: sync, openSettings: openSync) }
        .sheet(isPresented: $showGenerator) { GeneratorView { SecretClipboard.shared.copy($0) } }
        .modifier(AddFileFlow(isPresented: $addingFile, store: store, pro: pro,
                              onNeedsPro: { showUpgrade = true }, onAdded: edited))
        .sheet(item: $scanning, onDismiss: {
            // Two sheets cannot change in one update: the new login opens once the scan sheet has gone.
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
        .navigationDestination(for: VaultSearchRoute.self) { _ in
            VaultSearchView(model: model, store: store, pro: pro, sync: sync, onActivity: onActivity, onCommand: run)
        }
        .refreshable { await sync.sync(.pullToRefresh); reload() }
        .onAppear {
            reload()
            barVisibility = .automatic
            Task { @MainActor in barVisibility = .hidden }
        }
        .onChange(of: sync.completedRuns) { reload() }
        .onChange(of: listFilterOptions) { if !listFilterOptions.contains(filter) { filter = .all } }
        #if DEBUG
        .navigationDestination(item: $screenshotItem) { ItemDetailView(item: $0, store: store, pro: pro, onChange: edited) }
        .task { openScreenshotScreen() }
        #endif
    }

    #if DEBUG
    /// `-LGKScreen`: opens the requested screen once the list has loaded.
    private func openScreenshotScreen() {
        switch ScreenshotScreen.requested {
        case .item, .edit: screenshotItem = model.items.first(where: \.favorite) ?? model.items.first
        case .new: newKind = .web
        case .upgrade: showUpgrade = true
        default: break
        }
    }
    #endif

    /// UX refresh §4: title, one "more" menu and the + button (the only accent-filled control); the search field
    /// below; then the sync status and the setup progress on one line.
    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Vault").font(.largeTitle.bold()).foregroundStyle(Palette.text)
                    .lineLimit(1).minimumScaleFactor(0.5)
                    .accessibilityAddTraits(.isHeader)
                Spacer()
                headerButtons
            }
            .frame(minHeight: 48)
            searchField
            statusLine
        }
        .padding(.horizontal, 16)
        .padding(.top, 8).padding(.bottom, 8)
    }

    private var headerButtons: some View {
            LGKGlassContainer(spacing: 12) {
                HStack(spacing: 12) {
                    moreMenu
                    NewItemMenu(onPick: { kind in
                        // Creating needs a free slot or Pro; existing items are never blocked.
                        if ItemLimit.allows(.create, snapshot: model.snapshot, isPro: pro.isPro) { newKind = kind } else { showUpgrade = true }
                    }, onScan: startScan, onAddFile: {
                        // Adding a file is a Pro feature; files already in the vault always open.
                        if pro.isPro { addingFile = true } else { showUpgrade = true }
                    }) {
                        Image(systemName: "plus").font(.system(size: 20, weight: .semibold))
                            .foregroundStyle(Palette.onAccent)
                            .frame(width: 48, height: 48)
                            .background(Palette.accent, in: Circle())
                            .contentShape(Circle())
                            .accessibilityShowsLargeContentViewer()
                    }
                    .accessibilityLabel("New item")
                }
            }
    }

    /// A field-shaped button that opens the search screen (its filters and `>` actions are unchanged).
    private var searchField: some View {
        Button { searching = true } label: {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(Palette.secondaryText)
                Text("Search your vault").foregroundStyle(Palette.secondaryText).lineLimit(1)
                Spacer(minLength: 0)
            }
            .font(.body)
            .padding(.horizontal, 14).frame(minHeight: 44)
            .lgkGlass(in: Capsule())
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Search")
        .accessibilityAddTraits(.isSearchField)
        .keyboardShortcut("f", modifiers: .command)
        .background {
            // ⌘K on a hardware keyboard: the search, already listing the `>` actions.
            Button("Actions") { model.query = "> "; searching = true }
                .keyboardShortcut("k", modifiers: .command)
                .frame(width: 0, height: 0).opacity(0)
                .accessibilityHidden(true)
        }
    }

    /// "Synced 2 min ago · 3 devices" (workstream 6; absent while this iPhone does not sync) and the
    /// "Finish setting up · n of 5" chip (opens the setup pages; long press hides it) on one line. At large text
    /// sizes the two stack.
    private var statusLine: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 8) { syncPill; setupChip; Spacer(minLength: 0) }
            VStack(alignment: .leading, spacing: 6) { syncPill; setupChip }
        }
    }

    private var syncPill: some View {
        SyncStatusPill(sync: sync) { showSyncStatus = true }
    }

    @ViewBuilder private var setupChip: some View {
        if let onboarding, let text = onboarding.cardText {
            Button { onboarding.showAgain() } label: {
                HStack(spacing: 6) {
                    Image(systemName: "checklist").foregroundStyle(Palette.accentText)
                    Text(text).font(.subheadline).foregroundStyle(Palette.text).lineLimit(1)
                }
                .padding(.horizontal, 14).frame(minHeight: 44)
                .lgkGlass(in: Capsule())
                .contentShape(Capsule())
            }
            .buttonStyle(.plain)
            .contextMenu {
                Button(Onboarding.hide) { onboarding.hideCard() }
            }
        }
    }

    /// The one "more" menu: Sort (the default groups, or one flat list by title or date, with Favorites first;
    /// stored on this device), Collections (sub-plan 07: All items or one collection; Manage collections opens
    /// Vault › Collections) and Scan QR code.
    private var moreMenu: some View {
        Menu {
            Menu {
                Picker("Sort by", selection: Binding(get: { model.sort }, set: { model.sort = $0 })) {
                    Text("Grouped by type").tag(VaultSortOption?.none)
                    ForEach(VaultSortOption.allCases) { option in
                        Text(option.label).tag(VaultSortOption?.some(option))
                    }
                }
                Toggle("Favorites first", isOn: Binding(get: { model.favoritesFirst }, set: { model.favoritesFirst = $0 }))
                    .disabled(model.sort == nil)
            } label: { Label("Sort", systemImage: "arrow.up.arrow.down") }
            Menu {
                Picker("Collections", selection: Binding(get: { model.collectionFilter }, set: { model.collectionFilter = $0 })) {
                    Text("All items").tag(String?.none)
                    ForEach(model.collections, id: \.id) { collection in
                        Text(verbatim: CollectionCatalog.displayName(collection.name)).tag(String?.some(collection.id))
                    }
                }
                Divider()
                Button("Manage collections", action: openCollections)
            } label: {
                Label("Collections", systemImage: model.collectionFilter == nil ? "folder" : "folder.fill")
            }
            Button(action: startScan) { Label("Scan QR code", systemImage: "qrcode.viewfinder") }
        } label: {
            GlassCircleLabel { Image(systemName: "ellipsis").font(.system(size: 19, weight: .medium)) }
        }
        .buttonStyle(.plain)
        .accessibilityLabel("More")
    }

    /// The type chips for the list as filtered by collection.
    private var listFilterOptions: [VaultFilter] { VaultSearch.filterOptions(model.listItems) }

    /// A `>` action from the search (workstream 5): the search closes, then the action runs.
    private func run(_ command: PhoneCommand) {
        searching = false
        switch command {
        case .newItem:
            if ItemLimit.allows(.create, snapshot: model.snapshot, isPro: pro.isPro) { newKind = .web } else { showUpgrade = true }
        case .generatePassword: showGenerator = true
        case .scanQR: startScan()
        case .lockNow: lock.lock()
        case .syncNow: Task { await sync.syncNow() }
        case .syncStatus: showSyncStatus = true
        case .securityCheck, .trash, .settings, .importExport, .autoFill, .syncSettings, .showSetup: onNavigate(command)
        }
    }

    /// Long-press Favorite / Unfavorite on a row: writes the record (synced) and reloads.
    private func toggleFavorite(_ item: VaultItem) {
        let r = VaultListModel.setFavorite(!item.favorite, id: item.id, store: store, clock: SystemClock())
        if r == .saved { edited() }
        // A view-only shared item keeps its star: say why instead of doing nothing.
        if r == .invalid { CopyToast.shared.show(EditorModel.readOnlyItemText, for: .seconds(3)) }
    }

    /// 2FA keys are Pro (the editor's rule): the free plan gets the upgrade screen instead of the scanner.
    private func startScan() {
        guard pro.isPro else { showUpgrade = true; return }
        scanning = TwoFactorScanModel(store: store, pro: pro)
    }

    /// An `otpauth` link opened from outside: the scan flow at its next step, or the new login's editor.
    private func openTwoFactorLink(_ link: String) {
        guard let (scan, editor) = TwoFactorLinkRoute.scanFlow(link, store: store, pro: pro) else { showUpgrade = true; return }
        if let editor { scannedLogin = ScannedLogin(editor: editor) } else { scanning = scan }
    }

    /// A local create, edit or delete: reload, then sync once editing has paused.
    private func edited() {
        reload()
        sync.noteLocalEdit()
    }

    private func reload() {
        model.reload()
        pro.update(from: model.snapshot)
    }
}

/// iOS 26: the header goes in a safe-area bar with the system soft scroll-edge effect. iOS 17–25: a
/// safe-area inset with a short fade from the background to clear below it.
struct VaultHeaderBar<Header: View>: ViewModifier {
    let header: Header
    func body(content: Content) -> some View {
        if #available(iOS 26, *) {
            content
                .safeAreaBar(edge: .top) { header }
                .scrollEdgeEffectStyle(.soft, for: .top)
        } else {
            content.safeAreaInset(edge: .top, spacing: 0) {
                header.background(alignment: .top) {
                    VStack(spacing: 0) {
                        Palette.background
                        LinearGradient(colors: [Palette.background, Palette.background.opacity(0)],
                                       startPoint: .top, endPoint: .bottom).frame(height: 20)
                    }
                    .padding(.bottom, -20)
                    .ignoresSafeArea(edges: .top)
                    .allowsHitTesting(false)
                }
            }
        }
    }
}

/// A 48 pt glass circle (text on glass uses the accent *text* colour).
struct GlassCircleLabel<Content: View>: View {
    @ViewBuilder let content: () -> Content
    var body: some View {
        content()
            .foregroundStyle(Palette.accentText)
            .frame(width: 48, height: 48)
            .lgkGlass(in: Circle())
            .contentShape(Circle())
            // Fixed-size circles: a long press at large text sizes shows the symbol in the large content viewer.
            .accessibilityShowsLargeContentViewer()
    }
}

struct SectionHeader: View {
    let title: String
    var body: some View {
        Text(title).font(.subheadline).foregroundStyle(Palette.secondaryText)
            .padding(.horizontal, 12).padding(.top, 14).padding(.bottom, 2)
            .accessibilityAddTraits(.isHeader)
    }
}

/// The list's sections: Logins, Cards and notes, then everything else.
struct VaultGroup: Identifiable, Equatable {
    let title: String
    let items: [VaultItem]
    var id: String { title }

    static let cardsAndNotes: Set<String> = ["card", "note", "identity", "bank_account"]

    static func groups(_ items: [VaultItem]) -> [VaultGroup] {
        let sorted = VaultSearch.apply(items, query: "", filter: .all)
        let out = [
            VaultGroup(title: String(localized: "Logins"), items: sorted.filter(\.isLogin)),
            VaultGroup(title: String(localized: "Cards and notes"), items: sorted.filter { cardsAndNotes.contains($0.kind) }),
            VaultGroup(title: String(localized: "Other"), items: sorted.filter { !$0.isLogin && !cardsAndNotes.contains($0.kind) }),
        ]
        return out.filter { !$0.items.isEmpty }
    }
}

/// One solid grouped section of rows.
struct VaultGroupView: View {
    let items: [VaultItem]
    /// Adds Favorite / Unfavorite to each row's long-press menu.
    var onFavorite: ((VaultItem) -> Void)? = nil
    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(items.enumerated()), id: \.element.id) { i, item in
                let password = item.isLogin ? item.copyablePassword : nil
                HStack(spacing: 0) {
                    NavigationLink(value: item) {
                        HStack {
                            VaultRow(item: item)
                            if password == nil {
                                Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(Palette.secondaryText)
                                    .accessibilityHidden(true)
                            }
                        }
                        .padding(.leading, 14).padding(.trailing, password == nil ? 14 : 4).padding(.vertical, 10)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    if let password {
                        // UX refresh §4: copy without opening the item (the same clipboard and auto-clear path
                        // as the long-press menu).
                        Button {
                            Task {
                                guard await AccessGate.shared.mayCopy(item) else { return }
                                QuickActionsMenu.copy(password, String(localized: "Password copied"),
                                                      clearAfterAtMost: AccessGate.shared.copyLimit(item))
                            }
                        } label: {
                            Image(systemName: "doc.on.doc").font(.body.weight(.medium)).foregroundStyle(Palette.accentText)
                                .frame(width: 44, height: 44)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .padding(.trailing, 6)
                        .accessibilityLabel("Copy password")
                        .accessibilityShowsLargeContentViewer()
                    }
                }
                .contextMenu { QuickActionsMenu(item: item, onFavorite: onFavorite) }
                if i < items.count - 1 { Rectangle().fill(Palette.separator).frame(height: 1).padding(.leading, 70) }
            }
        }
        .lgkGroupSurface()
    }
}

extension VaultItem: Hashable {
    func hash(into h: inout Hasher) { h.combine(id); h.combine(updatedAt) }
    var hasTOTP: Bool { if case .object(let t)? = record["totp"], t["secret"] != nil { return true }; return false }
}

struct VaultRow: View {
    let item: VaultItem
    @Environment(\.dynamicTypeSize) private var typeSize
    var body: some View {
        HStack(spacing: 14) {
            ItemAvatar(item: item)
            VStack(alignment: .leading, spacing: 2) {
                // Rows wrap instead of clipping at accessibility text sizes.
                Text(item.title.isEmpty ? item.kindLabel : item.title).font(.headline).foregroundStyle(Palette.text)
                    .lineLimit(typeSize.isAccessibilitySize ? 3 : 1)
                Text(item.listSubtitle).font(.subheadline).foregroundStyle(Palette.secondaryText)
                    .lineLimit(typeSize.isAccessibilitySize ? 3 : 1)
            }
            Spacer()
            if item.hasTOTP {
                // Which logins have a one-time code (the Codes row lists the same items).
                Text("2FA").font(.caption2.weight(.semibold)).foregroundStyle(Palette.accentText)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .overlay(Capsule().strokeBorder(Palette.accentText.opacity(0.5)))
                    .accessibilityLabel(Text("Has a 2FA code"))
            }
            if item.favorite {
                Image(systemName: "star.fill").font(.caption).foregroundStyle(Palette.warning).accessibilityLabel("Favorite")
            }
        }
        .accessibilityElement(children: .combine)
    }

    static func tint(_ kind: String) -> Color {
        switch kind {
        case "card", "bank_account", "purchase", "subscription", "warranty": Palette.success
        case "note", "license": Palette.warning
        case "identity": Palette.identityTint
        case "passkey": Palette.accent
        default: Palette.accentText
        }
    }

    static func icon(_ kind: String) -> String {
        switch kind {
        case "web": "globe"
        case "desktop": "desktopcomputer"
        case "note": "note.text"
        case "card": "creditcard"
        case "identity": "person.text.rectangle"
        case "bookmark": "bookmark"
        case "wifi": "wifi"
        case "passkey": "person.badge.key"
        case "ssh_key": "terminal"
        case "api_key": "chevron.left.forwardslash.chevron.right"
        case "license": "key.horizontal"
        case "purchase": "bag"
        case "subscription": "repeat.circle"
        case "warranty": "checkmark.shield"
        case "bank_account": "building.columns"
        case "document": "paperclip"
        default: "doc"
        }
    }
}

/// The pinned Codes row (Settings can hide it): one solid tile per TOTP item; tap copies (local-only, the
/// Settings clipboard time).
struct CodesRow: View {
    let items: [VaultItem]
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader(title: String(localized: "Codes"))
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 12) { ForEach(items) { CodeTile(item: $0) } }.padding(14)
            }
            .lgkGroupSurface()
        }
    }
}

struct CodeTile: View {
    let item: VaultItem
    @State private var model: ItemDetailModel
    init(item: VaultItem) {
        self.item = item
        _model = State(initialValue: Self.model(for: item, current: nil))
    }

    /// The tile keeps its model while the item is the same; an edited item (a new TOTP secret, say) gets a
    /// fresh model so the tile never shows or copies the old code.
    static func model(for item: VaultItem, current: ItemDetailModel?, clipboard: SecretClipboard = .shared,
                      clock: any UnixClock = SystemClock()) -> ItemDetailModel {
        if let current, current.item == item { return current }
        return ItemDetailModel(item: item, clipboard: clipboard, clock: clock)
    }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let _ = context.date
            Button {
                // Feature pack §4: the same access-rule check as the detail screen's copy (view only refuses,
                // re-authenticate and copy once ask the owner).
                Task {
                    guard await AccessGate.shared.mayCopy(model.item) else { return }
                    if model.copyTOTP(clearAfterAtMost: AccessGate.shared.copyLimit(model.item)) {
                        CopyToast.shared.show(String(localized: "Code copied"))
                    }
                }
            } label: {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 6) {
                        ItemAvatar(item: model.item, size: 20)
                        Text(model.item.title.isEmpty ? model.item.kindLabel : model.item.title)
                            .font(.subheadline).foregroundStyle(Palette.secondaryText).lineLimit(1)
                    }
                    if let t = model.totp {
                        Text(Self.grouped(t.code)).font(.system(.title2, design: .monospaced).weight(.semibold))
                            .foregroundStyle(Palette.accentText)
                        CountdownBar(fraction: t.fractionRemaining, tint: Self.progressTint(secondsRemaining: t.secondsRemaining))
                    } else {
                        Text("—").foregroundStyle(Palette.secondaryText)
                    }
                }
                .padding(14)
                .frame(width: 160, alignment: .leading)
                .background(Palette.innerTile, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            }
            .buttonStyle(.plain)
            .onChange(of: context.date) { model.tick() }
        }
        .accessibilityHint("Copies the code")
        .onChange(of: item) { _, new in model = Self.model(for: new, current: model) }
    }

    /// Blue normally, orange in the last 7 seconds.
    static func progressTint(secondsRemaining: Int) -> Color {
        secondsRemaining <= 7 ? Palette.glowOrange : Palette.accent
    }

    static func grouped(_ code: String) -> String {
        guard code.count == 6 else { return code }
        return String(code.prefix(3)) + " " + String(code.suffix(3))
    }
}

/// iOS 17–25 draw a custom floating tab bar over the content, so scrolling content needs 96 pt of room
/// below it. iOS 26 uses the system TabView, which insets content itself.
struct LegacyTabBarInset: ViewModifier {
    func body(content: Content) -> some View {
        if #available(iOS 26, *) { content } else { content.padding(.bottom, 96) }
    }
}

/// The 2FA countdown: a 5 pt rounded bar (the system progress bar is a hairline).
struct CountdownBar: View {
    let fraction: Double
    let tint: Color
    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(Palette.separator)
                Capsule().fill(tint).frame(width: max(5, g.size.width * min(max(fraction, 0), 1)))
                    .animation(.linear(duration: 1), value: fraction)
            }
        }
        .frame(height: 5)
        .accessibilityHidden(true)
    }
}

/// Long-press on a row: copy what the item holds without opening it, and open its website.
struct QuickActionsMenu: View {
    let item: VaultItem
    var onFavorite: ((VaultItem) -> Void)? = nil
    @Environment(\.openURL) private var openURL

    var body: some View {
        if !item.username.isEmpty {
            // The username is not a secret: copy once neither counts it nor asks for it (feature pack §4.1).
            Button { Task { if await AccessGate.shared.mayCopy(item, secret: false) { Self.copy(item.username, String(localized: "Username copied")) } } } label: { Label("Copy username", systemImage: "person") }
        }
        if let password = item.copyablePassword {
            Button {
                Task {
                    guard await AccessGate.shared.mayCopy(item) else { return }
                    Self.copy(password, String(localized: "Password copied"), clearAfterAtMost: AccessGate.shared.copyLimit(item))
                }
            } label: { Label("Copy password", systemImage: "key") }
        }
        if item.hasTOTP {
            Button {
                Task {
                    guard await AccessGate.shared.mayCopy(item) else { return }
                    let m = ItemDetailModel(item: item, clipboard: SecretClipboard.shared, clock: SystemClock())
                    if m.copyTOTP(clearAfterAtMost: AccessGate.shared.copyLimit(item)) { CopyToast.shared.show(String(localized: "Code copied")) }
                }
            } label: { Label("Copy 2FA code", systemImage: "number") }
        }
        if let url = item.openableURL {
            Button { openURL(url) } label: { Label("Open website", systemImage: "safari") }
        }
        if let onFavorite {
            Button { onFavorite(item) } label: {
                Label(item.favorite ? String(localized: "Unfavorite") : String(localized: "Favorite"), systemImage: item.favorite ? "star.slash" : "star")
            }
        }
    }

    /// `limit`: cleared after at most that many seconds (copy once, feature pack §4.1); nil: the user's setting.
    @MainActor static func copy(_ text: String, _ message: String, clearAfterAtMost limit: Int64? = nil) {
        if let limit { SecretClipboard.shared.copy(text, clearAfterAtMost: limit) } else { SecretClipboard.shared.copy(text) }
        CopyToast.shared.show(message)
    }
}

extension VaultItem {
    /// The password the long-press menu and the row's copy button copy: a login's password, or a Wi-Fi
    /// network's; nil when empty.
    var copyablePassword: String? {
        let payload = record["payload"]?.objectValue ?? [:]
        guard let password = record["password"]?.stringValue ?? (kind == "wifi" ? payload["password"]?.stringValue : nil),
              !password.isEmpty else { return nil }
        return password
    }

    /// An http(s) address to open in Safari: a web login's site or a bookmark.
    var openableURL: URL? {
        let raw: String?
        switch kind {
        case "web": raw = Self.pageAddress(record["scope"]?.objectValue)
        case "bookmark": raw = record["payload"]?.objectValue?["url"]?.stringValue
        default: raw = nil
        }
        guard let raw, let url = URL(string: raw), url.scheme == "https" || url.scheme == "http", url.host() != nil else { return nil }
        return url
    }
}


/// The type chips above the Vault list.
struct VaultFilterBar: View {
    @Binding var filter: VaultFilter
    let options: [VaultFilter]

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(options, id: \.self) { option in
                    Button { filter = option } label: {
                        Text(option.label).font(.subheadline)
                            .padding(.horizontal, 12).padding(.vertical, 6)
                            .foregroundStyle(filter == option ? Palette.onAccent : Color.primary)
                            .background(filter == option ? AnyShapeStyle(Palette.accent) : AnyShapeStyle(.thinMaterial),
                                        in: Capsule())
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(filter == option ? .isSelected : [])
                }
            }
        }
        .padding(.bottom, 4)
    }
}

/// The empty vault's "Import your passwords" card: Import opens Settings › Import & Export; Not now hides
/// it on this iPhone. It goes away by itself once the vault has an item.
struct ImportCard: View {
    let onImport: () -> Void
    let onNotNow: () -> Void

    static let title = String(localized: "Import your passwords")
    static let text = String(localized: "Bring your logins over from another password manager or browser. On iOS 26, open Apple Passwords and choose Export Data to Another App, or import a file exported from Bitwarden, 1Password, KeePass and others.")

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(Self.title).font(.headline).foregroundStyle(Palette.text)
            Text(Self.text).font(.subheadline).foregroundStyle(Palette.secondaryText)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 12) {
                Button("Import", action: onImport).buttonStyle(.borderedProminent).tint(Palette.accent).foregroundStyle(Palette.onAccent)
                Button("Not now", action: onNotNow).buttonStyle(.bordered)
            }
            .padding(.top, 4)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.groupSurface, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .accessibilityElement(children: .contain)
    }
}

/// The Vault tab's search screen as a navigation value (RootTabs pushes it when `searching` turns on).
struct VaultSearchRoute: Hashable {}
