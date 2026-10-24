import SwiftUI
import AppShared

/// The Vault tab: large "Vault" title with the glass + and avatar buttons, a pinned Codes row, then grouped
/// solid sections. Content never sits on glass.
struct VaultListView: View {
    let model: VaultListModel
    let store: any ItemStore
    let pro: ProModel
    let sync: SyncCoordinator
    let lock: AppLockModel
    let onActivity: () -> Void
    /// Switches to the Sync tab (from Settings).
    var openSync: () -> Void = {}
    @State private var newKind: EditorKind?
    @State private var showUpgrade = false
    @State private var showSettings = false
    #if DEBUG
    @State private var screenshotItem: VaultItem?
    #endif

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                if let error = model.loadError {
                    Text(error).foregroundStyle(Palette.danger).padding(.horizontal, 4)
                }
                let codes = model.items.filter(\.hasTOTP)
                if !codes.isEmpty, AppSettings.shared.showCodesRow { CodesRow(items: codes) }
                ForEach(VaultGroup.groups(model.items)) { group in
                    SectionHeader(title: group.title)
                    VaultGroupView(items: group.items)
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
        .toolbar(.hidden, for: .navigationBar)
        .navigationTitle("Vault")
        .navigationDestination(for: VaultItem.self) { ItemDetailView(item: $0, store: store, pro: pro, onChange: edited) }
        .sheet(item: $newKind) { kind in
            EditorView(model: EditorModel(store: store, pro: pro, editing: nil, kind: kind, clock: SystemClock(),
                                          random: SystemRandomSource()),
                       pro: pro) { _ in edited() }
        }
        .sheet(isPresented: $showUpgrade) { UpgradeView(pro: pro, itemsUsed: model.liveCount) }
        .sheet(isPresented: $showSettings, onDismiss: reload) { SettingsView(pro: pro, lock: lock, sync: sync, openSync: openSync) }
        .refreshable { await sync.sync(.pullToRefresh); reload() }
        .onAppear { reload() }
        .onChange(of: sync.completedRuns) { reload() }
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
        case .settings: showSettings = true
        case .upgrade: showUpgrade = true
        default: break
        }
    }
    #endif

    private var header: some View {
        HStack {
            Text("Vault").font(.largeTitle.bold()).foregroundStyle(Palette.text)
                .accessibilityAddTraits(.isHeader)
            Spacer()
            headerButtons
        }
        .frame(height: 48)
        .padding(.horizontal, 16)
        .padding(.top, 8).padding(.bottom, 8)
    }

    private var headerButtons: some View {
            LGKGlassContainer(spacing: 12) {
                HStack(spacing: 12) {
                    NewItemMenu { kind in
                        // Creating needs a free slot or Pro; existing items are never blocked.
                        if ItemLimit.allows(.create, snapshot: model.snapshot, isPro: pro.isPro) { newKind = kind } else { showUpgrade = true }
                    } label: {
                        GlassCircleLabel { Image(systemName: "plus").font(.system(size: 20, weight: .medium)) }
                    }
                    .accessibilityLabel("New item")
                    Button { showSettings = true } label: {
                        GlassCircleLabel {
                            if let initials = AvatarInitials.from(AppSettings.shared.initials) {
                                Text(initials).font(.system(size: 17, weight: .semibold))
                            } else {
                                Image(systemName: "person.fill").font(.system(size: 18, weight: .semibold))
                            }
                        }
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Settings")
                }
            }
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
            VaultGroup(title: "Logins", items: sorted.filter(\.isLogin)),
            VaultGroup(title: "Cards and notes", items: sorted.filter { cardsAndNotes.contains($0.kind) }),
            VaultGroup(title: "Other", items: sorted.filter { !$0.isLogin && !cardsAndNotes.contains($0.kind) }),
        ]
        return out.filter { !$0.items.isEmpty }
    }
}

/// One solid grouped section of rows.
struct VaultGroupView: View {
    let items: [VaultItem]
    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(items.enumerated()), id: \.element.id) { i, item in
                NavigationLink(value: item) {
                    HStack {
                        VaultRow(item: item)
                        Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(Palette.secondaryText)
                    }
                    .padding(.horizontal, 14).padding(.vertical, 10)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .contextMenu { QuickActionsMenu(item: item) }
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
    var body: some View {
        HStack(spacing: 14) {
            ItemAvatar(item: item)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title.isEmpty ? item.kindLabel : item.title).font(.headline).foregroundStyle(Palette.text).lineLimit(1)
                Text(item.listSubtitle).font(.subheadline).foregroundStyle(Palette.secondaryText).lineLimit(1)
            }
            Spacer()
            if item.favorite { Image(systemName: "star.fill").font(.caption).foregroundStyle(Palette.warning) }
        }
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
            SectionHeader(title: "Codes")
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
            Button { if model.copyTOTP() { CopyToast.shared.show("Code copied") } } label: {
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
    @Environment(\.openURL) private var openURL

    var body: some View {
        let payload = item.record["payload"]?.objectValue ?? [:]
        if !item.username.isEmpty {
            Button { copy(item.username, "Username copied") } label: { Label("Copy username", systemImage: "person") }
        }
        if let password = item.record["password"]?.stringValue ?? (item.kind == "wifi" ? payload["password"]?.stringValue : nil),
           !password.isEmpty {
            Button { copy(password, "Password copied") } label: { Label("Copy password", systemImage: "key") }
        }
        if item.hasTOTP {
            Button {
                let m = ItemDetailModel(item: item, clipboard: .shared, clock: SystemClock())
                if m.copyTOTP() { CopyToast.shared.show("Code copied") }
            } label: { Label("Copy 2FA code", systemImage: "number") }
        }
        if let url = item.openableURL {
            Button { openURL(url) } label: { Label("Open website", systemImage: "safari") }
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
        case "web": raw = record["scope"]?.objectValue?["origin"]?.stringValue
        case "bookmark": raw = record["payload"]?.objectValue?["url"]?.stringValue
        default: raw = nil
        }
        guard let raw, let url = URL(string: raw), url.scheme == "https" || url.scheme == "http", url.host() != nil else { return nil }
        return url
    }
}
