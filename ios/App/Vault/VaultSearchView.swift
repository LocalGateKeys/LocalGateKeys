import SwiftUI
import AppShared

/// The Search tab: search plus type filters over the same list model.
struct VaultSearchView: View {
    @Bindable var model: VaultListModel
    let store: any ItemStore
    let pro: ProModel
    let sync: SyncCoordinator
    let onActivity: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                if model.visibleItems.isEmpty {
                    Text(model.query.isEmpty ? "No items." : "No matches.").foregroundStyle(Palette.secondaryText)
                        .frame(maxWidth: .infinity).padding(.top, 24)
                } else {
                    VaultGroupView(items: model.visibleItems)
                }
            }
            .padding(.horizontal, 16).modifier(LegacyTabBarInset())
        }
        .lgkAuroraBackground()
        .navigationTitle("Search")
        .navigationDestination(for: VaultItem.self) {
            ItemDetailView(item: $0, store: store, pro: pro) { model.reload(); sync.noteLocalEdit() }
        }
        .searchable(text: $model.query, prompt: "Search")
        .onChange(of: model.query) { onActivity() }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Picker("Type", selection: $model.filter) {
                        ForEach(model.filterOptions, id: \.self) { Text($0.label).tag($0) }
                    }
                } label: {
                    Label(model.filter.label, systemImage: "line.3.horizontal.decrease.circle")
                }
            }
        }
        .onAppear { model.reload() }
    }
}
