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
    /// Switches to the Settings tab on Import & Export (the empty vault's import card).
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
                if let onboarding, let text = onboarding.cardText {
                    SetupCard(text: text, onOpen: { onboarding.showAgain() }, onHide: { onboarding.hideCard() })
                }
                let codes = model.items.filter(\.hasTOTP)
                if !codes.isEmpty, AppSettings.shared.showCodesRow { CodesRow(items: codes) }
                if !model.items.isEmpty { VaultFilterBar(filter: $filter, options: model.filterOptions).padding(.top, 4) }
                if let sorted = model.sortedItems(filter: filter) {
                    // A chosen sort shows one flat list in that order (no Logins / Cards and notes / Other groups).
                    if sorted.isEmpty {
                        if !model.items.isEmpty {
                            Text("No items of this type.").foregroundStyle(Palette.secondaryText).frame(maxWidth: .infinity).padding(.top, 24)
                        }
                    } else {
                        VaultGroupView(items: sorted, onFavorite: toggleFavorite)
                    }
                } else if filter == .all {
                    ForEach(VaultGroup.groups(model.items)) { group in
                        SectionHeader(title: group.title)
                        VaultGroupView(items: group.items, onFavorite: toggleFavorite)
                    }
                } else {
                    let matches = VaultSearch.apply(model.items, query: "", filter: filter)
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
        .onChange(of: model.filterOptions) { if !model.filterOptions.contains(filter) { filter = .all } }
        #if DEBUG
        .navigationDestination(item: $screenshotItem) { ItemDetailView(item: $0, store: store, pro: pro, onChange: edited) }
        .task { openScreenshotScreen() }
        #endif
    }

    #if DEBUG
    /// `-LGKScreen`: opens the requested screen once the list has loaded.
    private func openScreenshotScreen() {
        switch ScreenshotScreen.requested {
        case .item: screenshotItem = model.items.first(where: \.favorite) ?? model.items.first
        case .new: newKind = .web
        case .upgrade: showUpgrade = true
        default: break
        }
    }
    #endif

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Vault").font(.largeTitle.bold()).foregroundStyle(Palette.text)
                    .lineLimit(1).minimumScaleFactor(0.5)
                    .accessibilityAddTraits(.isHeader)
                Spacer()
                headerButtons
            }
            .frame(minHeight: 48)
            // "Synced 2 min ago · 3 devices" (workstream 6); absent while this iPhone does not sync.
            SyncStatusPill(sync: sync) { showSyncStatus = true }
        }
        .padding(.horizontal, 16)
        .padding(.top, 8).padding(.bottom, 8)
    }

    private var headerButtons: some View {
            LGKGlassContainer(spacing: 12) {
                HStack(spacing: 12) {
                    Button(action: startScan) {
                        GlassCircleLabel { Image(systemName: "qrcode.viewfinder").font(.system(size: 19, weight: .medium)) }
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Scan QR code")
                    Button { searching = true } label: {
                        GlassCircleLabel { Image(systemName: "magnifyingglass").font(.system(size: 19, weight: .medium)) }
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Search")
                    .keyboardShortcut("f", modifiers: .command)
                    .background {
                        // ⌘K on a hardware keyboard: the search, already listing the `>` actions.
                        Button("Actions") { model.query = "> "; searching = true }
                            .keyboardShortcut("k", modifiers: .command)
                            .frame(width: 0, height: 0).opacity(0)
                            .accessibilityHidden(true)
                    }
                    sortMenu
                    NewItemMenu(onPick: { kind in
                        // Creating needs a free slot or Pro; existing items are never blocked.
                        if ItemLimit.allows(.create, snapshot: model.snapshot, isPro: pro.isPro) { newKind = kind } else { showUpgrade = true }
                    }, onScan: startScan, onAddFile: {
                        // Adding a file is a Pro feature; files already in the vault always open.
                        if pro.isPro { addingFile = true } else { showUpgrade = true }
                    }) {
                        GlassCircleLabel { Image(systemName: "plus").font(.system(size: 20, weight: .medium)) }
                    }
                    .accessibilityLabel("New item")
                }
            }
    }

    /// The list order: the default groups, or one flat list sorted by title or date, with Favorites first.
    /// Stored on this device only.
    private var sortMenu: some View {
        Menu {
            Picker("Sort by", selection: Binding(get: { model.sort }, set: { model.sort = $0 })) {
                Text("Grouped by type").tag(VaultSortOption?.none)
                ForEach(VaultSortOption.allCases) { option in
                    Text(option.label).tag(VaultSortOption?.some(option))
                }
            }
            Toggle("Favorites first", isOn: Binding(get: { model.favoritesFirst }, set: { model.favoritesFirst = $0 }))
                .disabled(model.sort == nil)
        } label: {
            GlassCircleLabel { Image(systemName: "arrow.up.arrow.down").font(.system(size: 18, weight: .medium)) }
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Sort")
    }

    /// A `>` action from the search (workstream 5): the search closes, then the action runs.
    private func run(_ command: PhoneCommand) {
        searching = false
        switch command {
        case .newItem:
            if ItemLimit.allows(.create, snapshot: model.snapshot, isPro: pro.isPro) { newKind = .web } else { showUpgrade = true }
        case .generatePassword: showGenerator = true
        case .scanQR: startScan()
        case .lockNow: lock.lock()
        case .syncNow: Task { await sync.sync(.manual) }
        case .syncStatus: showSyncStatus = true
        case .securityCheck, .trash, .settings, .importExport, .autoFill, .syncSettings, .showSetup: onNavigate(command)
        }
    }

    /// Long-press Favorite / Unfavorite on a row: writes the record (synced) and reloads.
    private func toggleFavorite(_ item: VaultItem) {
        let r = VaultListModel.setFavorite(!item.favorite, id: item.id, store: store, clock: SystemClock())
        if r == .saved { edited() }
    }

    /// 2FA keys are Pro (the editor's rule): the free plan gets the upgrade screen instead of the scanner.
    private func startScan() {
        guard pro.isPro else { showUpgrade = true; return }
        scanning = TwoFactorScanModel(store: store, pro: pro)
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
                NavigationLink(value: item) {
                    HStack {
                        VaultRow(item: item)
                        Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(Palette.secondaryText)
                            .accessibilityHidden(true)
                    }
                    .padding(.horizontal, 14).padding(.vertical, 10)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
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
            Button { if model.copyTOTP() { CopyToast.shared.show(String(localized: "Code copied")) } } label: {
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
        let payload = item.record["payload"]?.objectValue ?? [:]
        if !item.username.isEmpty {
            Button { copy(item.username, String(localized: "Username copied")) } label: { Label("Copy username", systemImage: "person") }
        }
        if let password = item.record["password"]?.stringValue ?? (item.kind == "wifi" ? payload["password"]?.stringValue : nil),
           !password.isEmpty {
            Button { copy(password, String(localized: "Password copied")) } label: { Label("Copy password", systemImage: "key") }
        }
        if item.hasTOTP {
            Button {
                let m = ItemDetailModel(item: item, clipboard: SecretClipboard.shared, clock: SystemClock())
                if m.copyTOTP() { CopyToast.shared.show(String(localized: "Code copied")) }
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

    private func copy(_ text: String, _ message: String) {
        SecretClipboard.shared.copy(text)
        CopyToast.shared.show(message)
    }
}

extension VaultItem {
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
