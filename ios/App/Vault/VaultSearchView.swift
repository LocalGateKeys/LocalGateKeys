import SwiftUI
import AppShared

/// Search, pushed from the Vault tab's magnifying-glass button (UX plan workstream 1): the field is focused
/// on arrival; while it is empty, recent searches and recently changed items show. Item rows push onto the
/// Vault tab's stack, which owns the item destination.
struct VaultSearchView: View {
    @Bindable var model: VaultListModel
    let store: any ItemStore
    let pro: ProModel
    let sync: SyncCoordinator
    let onActivity: () -> Void
    /// A `>` action picked from the list (workstream 5); the Vault tab runs it.
    var onCommand: (PhoneCommand) -> Void = { _ in }
    @State private var fieldPresented = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                if let commands = PhoneCommand.matches(model.query) {
                    commandList(commands)
                } else if model.query.isEmpty {
                    if !model.recentSearches.isEmpty {
                        SectionHeader(title: String(localized: "Recent searches"))
                        VStack(spacing: 0) {
                            ForEach(model.recentSearches, id: \.self) { q in
                                Button { model.query = q } label: {
                                    Label(q, systemImage: "clock.arrow.circlepath")
                                        .foregroundStyle(Palette.text)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .padding(.horizontal, 14).padding(.vertical, 12)
                                        .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                                .accessibilityHint("Searches again")
                            }
                        }
                        .lgkGroupSurface()
                    }
                    let recent = model.recentItems
                    if !recent.isEmpty {
                        SectionHeader(title: String(localized: "Recent items"))
                        VaultGroupView(items: recent)
                    } else if model.recentSearches.isEmpty {
                        Text("No items.").foregroundStyle(Palette.secondaryText).frame(maxWidth: .infinity).padding(.top, 24)
                    }
                } else if model.visibleItems.isEmpty {
                    Text("No matches.").foregroundStyle(Palette.secondaryText)
                        .frame(maxWidth: .infinity).padding(.top, 24)
                } else {
                    VaultGroupView(items: model.visibleItems)
                }
            }
            .padding(.horizontal, 16).modifier(LegacyTabBarInset())
        }
        .lgkAuroraBackground()
        .navigationTitle("Search")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.visible, for: .navigationBar)
        .searchable(text: $model.query, isPresented: $fieldPresented,
                    placement: .navigationBarDrawer(displayMode: .always), prompt: "Search, or > for actions")
        .onSubmit(of: .search) {
            // Return on a `>` query runs the first action; it is never kept as a recent search.
            if let commands = PhoneCommand.matches(model.query) {
                if let first = commands.first { onCommand(first) }
            } else {
                model.noteSearch()
            }
        }
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
                .accessibilityLabel("Filter by type")
            }
        }
        .onAppear {
            model.reload()
            fieldPresented = true
        }
        .onDisappear {
            if PhoneCommand.filter(model.query) == nil { model.noteSearch() }
            model.query = ""
        }
    }

    @ViewBuilder private func commandList(_ commands: [PhoneCommand]) -> some View {
        SectionHeader(title: String(localized: "Actions"))
        if commands.isEmpty {
            Text("No matching actions.").foregroundStyle(Palette.secondaryText).frame(maxWidth: .infinity).padding(.top, 24)
        } else {
            VStack(spacing: 0) {
                ForEach(commands) { command in
                    Button { onCommand(command) } label: {
                        Label(command.title, systemImage: command.icon)
                            .foregroundStyle(Palette.text)
                            .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                            .padding(.horizontal, 14).padding(.vertical, 4)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier("command-\(command.rawValue)")
                }
            }
            .lgkGroupSurface()
        }
    }
}
