import SwiftUI
import AppShared

enum RootTab: Hashable { case vault, sync, security, settings }

/// Vault, Sync, Security and Settings (UX plan workstream 1). Search is a button on the Vault tab.
/// iOS 26+: the system `TabView` (Liquid Glass). iOS 17–25: the same four tabs drawn as a centred floating
/// capsule with `.lgkGlass`.
struct RootTabs: View {
    @State var model: VaultListModel
    let store: any ItemStore
    let pro: ProModel
    let sync: SyncCoordinator
    let lock: AppLockModel
    @State private var tab: RootTab = .vault
    /// The Vault tab's search screen is pushed (the toolbar button, or `-LGKScreen search`).
    @State private var searching = false
    /// The Vault tab's stack. Search is a value route like items: a presentation-driven search destination
    /// under value-pushed items popped the item straight away (iOS 27 simulator).
    @State private var vaultPath = NavigationPath()
    /// The path depth the search sits at, while it is pushed.
    @State private var searchDepth: Int?
    /// Settings opens on Import & Export (the empty vault's import card).
    @State private var settingsOpensImport = false
    /// This iPhone's never-synced data (Recently deleted, reminders), open while unlocked.
    @State private var local: PhoneLocalData?
    @State private var trash: PhoneTrash?
    @State private var reminders: PhoneReminders?
    /// Setup on this iPhone (workstream 4): the pages on first run, the vault card, Settings › Show setup again.
    @State private var onboarding = Onboarding()
    @State private var autoFillStatus = AutoFillStatusModel.live()
    /// Recently deleted from the search's `>` actions (workstream 5).
    @State private var showTrash = false
    /// "What's new" after an update (once per version, after the setup pages).
    @State private var showWhatsNew = false

    var body: some View {
        tabs.copyToastHost()
            .undoToastHost()
            .environment(\.phoneTrash, trash)
            .environment(\.phoneReminders, reminders)
            .onChange(of: model.items) { _, items in reminders?.items = items }
            .onAppear(perform: openLocalData)
            .task { await detectSetup() }
            .sheet(isPresented: Binding(get: { showTrash && trash != nil }, set: { if !$0 { showTrash = false } })) {
                if let trash {
                    NavigationStack {
                        TrashView(trash: trash, pro: pro, onRestored: trash.onRestored)
                            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Done") { showTrash = false } } }
                    }
                }
            }
            .fullScreenCover(isPresented: Binding(get: { onboarding.pagesOpen && showsSetupPages },
                                                  set: { if !$0 { onboarding.closePages() } })) {
                OnboardingPages(onboarding: onboarding, onAction: runSetupStep)
            }
            .sheet(isPresented: $showWhatsNew, onDismiss: { AppSettings.shared.whatsNewSeen = WhatsNew.version }) {
                WhatsNewSheet { showWhatsNew = false }
            }
            .task(id: onboarding.pagesOpen) { checkWhatsNew() }
            .onDisappear { UndoToast.shared.dismiss() }
            #if DEBUG
            .onAppear {
                switch ScreenshotScreen.requested {
                case .search: searching = true
                case .sync: tab = .sync
                case .settings: tab = .settings
                case .security: tab = .security
                default: break
                }
            }
            #endif
    }

    @ViewBuilder private var tabs: some View {
        if #available(iOS 26, *) {
            TabView(selection: $tab) {
                Tab("Vault", systemImage: "lock", value: RootTab.vault) { vault }
                Tab("Sync", systemImage: "arrow.triangle.2.circlepath", value: RootTab.sync) { syncScreen }
                Tab("Security", systemImage: "checkmark.shield", value: RootTab.security) { security }
                Tab("Settings", systemImage: "gearshape", value: RootTab.settings) { settingsScreen }
            }
        } else {
            TabView(selection: $tab) {
                vault.tag(RootTab.vault).toolbar(.hidden, for: .tabBar)
                syncScreen.tag(RootTab.sync).toolbar(.hidden, for: .tabBar)
                security.tag(RootTab.security).toolbar(.hidden, for: .tabBar)
                settingsScreen.tag(RootTab.settings).toolbar(.hidden, for: .tabBar)
            }
            .safeAreaInset(edge: .bottom) { FloatingTabBar(selection: $tab) }
        }
    }

    private var vault: some View {
        NavigationStack(path: $vaultPath) {
            VaultListView(model: model, store: store, pro: pro, sync: sync, lock: lock, onActivity: lock.noteActivity,
                          searching: $searching,
                          openImport: { settingsOpensImport = true; tab = .settings },
                          openSync: { tab = .sync },
                          onboarding: onboarding,
                          onNavigate: navigate)
        }
        .onChange(of: searching, initial: true) { _, open in
            if open, searchDepth == nil {
                searchDepth = vaultPath.count + 1
                vaultPath.append(VaultSearchRoute())
            } else if !open, let depth = searchDepth {
                searchDepth = nil
                vaultPath.removeLast(max(0, vaultPath.count - depth + 1))
            }
        }
        .onChange(of: vaultPath.count) { _, count in
            // Back (or a swipe) from the search: it is closed.
            if let depth = searchDepth, count < depth { searchDepth = nil; searching = false }
        }
    }

    private var security: some View {
        NavigationStack {
            SecurityCheckView(model: SecurityCheckModel(store: store), store: store, pro: pro,
                              onChange: { model.reload(); sync.noteLocalEdit() })
        }
    }

    private var settingsScreen: some View {
        SettingsView(pro: pro, lock: lock, sync: sync, openSync: { tab = .sync }, openImport: settingsOpensImport,
                     inTab: true, onImportOpened: { settingsOpensImport = false },
                     showSetup: { tab = .vault; onboarding.showAgain() })
            .onChange(of: tab) { _, new in if new == .vault { model.reload(); pro.update(from: model.snapshot) } }
    }

    /// Opens the local data once per unlock (this view goes when the vault locks) and purges expired trash.
    private func openLocalData() {
        guard local == nil, let opened = PhoneLocalData.open(for: store) else { return }
        local = opened
        let bin = PhoneTrash(local: opened, store: store, isPro: { [pro] in pro.isPro })
        bin.onRestored = { [model, sync, pro] in model.reload(); pro.update(from: model.snapshot); sync.noteLocalEdit() }
        bin.purgeExpired()
        trash = bin
        let planner = PhoneReminders(local: opened, centre: PhoneNotificationCentre())
        planner.items = model.items
        reminders = planner
    }

    private var syncScreen: some View { SyncScreen(coordinator: sync, showsDone: false) }

    /// Screenshot runs (`-LGKScreen`) never show the setup pages.
    private var showsSetupPages: Bool {
        #if DEBUG
        return ScreenshotScreen.requested == nil
        #else
        return true
        #endif
    }

    private func checkWhatsNew() {
        let settings = AppSettings.shared
        #if DEBUG
        if ScreenshotScreen.requested != nil { return }
        #endif
        // The stored vault, not `model.items`: the list may not have loaded yet when this runs.
        guard let snapshot = try? store.load() else { return }
        let count = ItemLimit.liveCount(snapshot)
        if WhatsNew.skipsForever(seen: settings.whatsNewSeen, itemCount: count) {
            settings.whatsNewSeen = WhatsNew.version
        } else if WhatsNew.shouldShow(seen: settings.whatsNewSeen, itemCount: count,
                                      setupPagesOpen: onboarding.pagesOpen && showsSetupPages) {
            showWhatsNew = true
        }
    }

    /// Steps finished elsewhere count as done: an app password (its recovery phrase was confirmed when it was
    /// turned on) and LocalGateKeys as the AutoFill provider.
    private func detectSetup() async {
        if AppPasswordStore.shared()?.isOn == true { onboarding.complete(.phrase) }
        await autoFillStatus.refresh()
        if autoFillStatus.enabled == true { onboarding.complete(.autofill) }
    }

    /// A `>` action that leaves the Vault tab (workstream 5).
    private func navigate(_ command: PhoneCommand) {
        switch command {
        case .securityCheck: tab = .security
        case .trash: showTrash = true
        case .settings: tab = .settings
        case .importExport: settingsOpensImport = true; tab = .settings
        case .autoFill: Task { await autoFillStatus.openSettings() }
        case .syncSettings: tab = .sync
        case .showSetup: onboarding.showAgain()
        case .newItem, .generatePassword, .scanQR, .lockNow, .syncNow, .syncStatus: break
        }
    }

    /// A setup page's action, after the pages closed.
    private func runSetupStep(_ step: SetupStep) {
        switch step {
        case .vault, .unlock: break
        case .importItems: settingsOpensImport = true; tab = .settings
        case .phrase: tab = .settings
        case .autofill: Task { await autoFillStatus.openSettings() }
        }
    }
}

/// The iOS 17–25 tab bar: a centred capsule of glass. The selected tab gets an accent-tinted pill.
struct FloatingTabBar: View {
    @Binding var selection: RootTab
    /// At accessibility text sizes the capsule shows icons only; a long press shows the large content viewer.
    @Environment(\.dynamicTypeSize) private var typeSize

    var body: some View {
        HStack(spacing: 4) {
            item(.vault, String(localized: "Vault"), "lock")
            item(.sync, String(localized: "Sync"), "arrow.triangle.2.circlepath")
            item(.security, String(localized: "Security"), "checkmark.shield")
            item(.settings, String(localized: "Settings"), "gearshape")
        }
        .padding(6)
        .lgkGlass(in: Capsule())
        .shadow(color: .black.opacity(0.12), radius: 16, y: 6)
        .padding(.bottom, 4)
    }

    private func item(_ tab: RootTab, _ title: String, _ icon: String) -> some View {
        let selected = selection == tab
        return Button { selection = tab } label: {
            VStack(spacing: 2) {
                Image(systemName: icon).font(.system(size: typeSize.isAccessibilitySize ? 22 : 18, weight: .semibold))
                if !typeSize.isAccessibilitySize {
                    Text(title).font(.caption).lineLimit(1).minimumScaleFactor(0.8)
                }
            }
            .frame(width: 76, height: 50)
            .foregroundStyle(selected ? Palette.accentText : Palette.text)
            .background { if selected { Capsule().fill(Palette.accent.opacity(0.18)) } }
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityShowsLargeContentViewer { Label(title, systemImage: icon) }
        .accessibilityLabel(title)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

