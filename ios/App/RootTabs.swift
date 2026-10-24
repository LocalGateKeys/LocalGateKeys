import SwiftUI
import AppShared

enum RootTab: Hashable { case vault, search, sync }

/// Vault, Search and Sync. iOS 26+: the system `TabView` (Liquid Glass, search role). iOS 17–25: the same
/// three tabs drawn as a centred floating capsule with `.lgkGlass`.
struct RootTabs: View {
    @State var model: VaultListModel
    let store: any ItemStore
    let pro: ProModel
    let sync: SyncCoordinator
    let lock: AppLockModel
    @State private var tab: RootTab = .vault

    var body: some View {
        tabs.copyToastHost()
            #if DEBUG
            .onAppear {
                switch ScreenshotScreen.requested {
                case .search: tab = .search
                case .sync: tab = .sync
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
                Tab(value: RootTab.search, role: .search) { search }
            }
        } else {
            TabView(selection: $tab) {
                vault.tag(RootTab.vault).toolbar(.hidden, for: .tabBar)
                search.tag(RootTab.search).toolbar(.hidden, for: .tabBar)
                syncScreen.tag(RootTab.sync).toolbar(.hidden, for: .tabBar)
            }
            .safeAreaInset(edge: .bottom) { FloatingTabBar(selection: $tab) }
        }
    }

    private var vault: some View {
        NavigationStack {
            VaultListView(model: model, store: store, pro: pro, sync: sync, lock: lock, onActivity: lock.noteActivity,
                          openSync: { tab = .sync })
        }
    }

    private var search: some View {
        NavigationStack {
            VaultSearchView(model: model, store: store, pro: pro, sync: sync, onActivity: lock.noteActivity)
        }
    }

    private var syncScreen: some View { SyncScreen(coordinator: sync, showsDone: false) }
}

/// The iOS 17–25 tab bar: a centred capsule of glass. The selected tab gets an accent-tinted pill.
struct FloatingTabBar: View {
    @Binding var selection: RootTab

    var body: some View {
        HStack(spacing: 4) {
            item(.vault, "Vault", "lock")
            item(.search, "Search", "magnifyingglass")
            item(.sync, "Sync", "arrow.triangle.2.circlepath")
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
                Image(systemName: icon).font(.system(size: 18, weight: .semibold))
                Text(title).font(.caption)
            }
            .frame(width: 84, height: 50)
            .foregroundStyle(selected ? Palette.accentText : Palette.text)
            .background { if selected { Capsule().fill(Palette.accent.opacity(0.18)) } }
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}
