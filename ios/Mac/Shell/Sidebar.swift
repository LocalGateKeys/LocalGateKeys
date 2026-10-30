import SwiftUI

/// The sidebar on the colour wash (mockup `.sb`): Vault, Types (only kinds with items), Collections (with
/// counts and a Manage button) and Tools.
struct Sidebar: View {
    @Bindable var model: SidebarModel
    /// Opens the collections manager; nil hides the Collections group (no local data).
    var onManageCollections: (() -> Void)? = nil
    /// The sync pill at the bottom (workstream 6); nil hides it (sync unavailable).
    var syncCoordinator: SyncCoordinator? = nil
    var onSyncStatus: () -> Void = {}
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(spacing: 6) {
            brand
            list
            if let syncCoordinator {
                SyncStatusSidebarPill(coordinator: syncCoordinator, onTap: onSyncStatus).padding(.horizontal, 6).padding(.bottom, 6)
            }
        }
    }

    /// The logo and app name above All items, as on Windows.
    private var brand: some View {
        HStack(spacing: 9) {
            Image("BrandMark").resizable().aspectRatio(contentMode: .fit).frame(width: 28, height: 28)
                .accessibilityHidden(true)
            (Text(verbatim: "Local") + Text(verbatim: "Gate").foregroundColor(theme.accent) + Text(verbatim: "Keys"))
                .font(.system(size: 16, weight: .bold)).foregroundStyle(theme.text)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(EdgeInsets(top: 8, leading: 16, bottom: 10, trailing: 10))
        .overlay(alignment: .bottom) { Rectangle().fill(theme.textFaint.opacity(0.35)).frame(height: 0.5).padding(.horizontal, 12) }
        .accessibilityElement(children: .ignore).accessibilityLabel("LocalGateKeys")
    }

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                header(String(localized: "Vault"), top: 2)
                row(String(localized: "All items"), .all)
                row(String(localized: "Favourites"), .favourites)
                row(String(localized: "Recently used"), .recent)
                if !model.kindsPresent.isEmpty {
                    header(String(localized: "Types"))
                    ForEach(model.kindsPresent, id: \.self) { row(SidebarModel.label(forKind: $0), .kind($0)) }
                }
                if let onManageCollections {
                    HStack {
                        header(String(localized: "Collections"))
                        Spacer()
                        Button(action: onManageCollections) {
                            Image(systemName: "ellipsis.circle").font(.system(size: 12)).foregroundStyle(theme.textFaint)
                        }
                        .buttonStyle(.plain).padding(.top, 12).padding(.trailing, 10)
                        .help("Manage collections").accessibilityLabel("Manage collections")
                    }
                    ForEach(model.sortedCollections, id: \.id) { row($0.name, .collection($0.id)) }
                }
                header(String(localized: "Tools"))
                ForEach(Tool.allCases, id: \.self) { row($0.title, .tool($0)) }
            }
            .padding(.horizontal, 6).padding(.vertical, 4)
        }
        .scrollIndicators(.automatic)
        .softBottomEdge()
    }

    private func header(_ title: String, top: CGFloat = 16) -> some View {
        Text(title).font(.system(size: 12)).foregroundStyle(theme.textFaint)
            .padding(EdgeInsets(top: top, leading: 10, bottom: 4, trailing: 10))
    }

    private func row(_ title: String, _ selection: SidebarSelection) -> some View {
        let on = model.selection == selection
        return Button { model.selection = selection } label: {
            HStack {
                Text(title).foregroundStyle(theme.text).lineLimit(1)
                Spacer(minLength: 4)
                if let n = model.count(for: selection) {
                    Text("\(n)").font(.system(size: 12)).foregroundStyle(theme.textFaint)
                }
            }
            .font(.system(size: 14))
            .padding(.horizontal, 10).padding(.vertical, 7)
            .background {
                if on {
                    RoundedRectangle(cornerRadius: 8, style: .continuous).fill(theme.selection)
                        .overlay(alignment: .leading) { Rectangle().fill(theme.accent).frame(width: 3) }
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(on ? .isSelected : [])
    }
}
