import SwiftUI
import AppShared

/// Vault › Collections (sub-plan 07 task 5f): every collection with its item count; + creates one, a swipe or a long
/// press renames or deletes it (after a confirmation; its items stay). The starters can be added while any is missing.
/// Shared collections show a people icon and a Shared badge and are never deleted here; view-only ones show a lock and
/// are not renamed. Each row has Share (task 5h, `CollectionShareSheet`); Join a shared collection is at the bottom. A
/// collection this device was removed from says its items went to the trash.
struct CollectionsView: View {
    @State private var model: CollectionsModel
    /// Shared collections (nil: no Share or Join, as in previews).
    let sync: SyncCoordinator?
    let pro: ProModel?
    /// After a change: the Vault list reloads and a sync is scheduled.
    let onChange: () -> Void
    @State private var creating = false
    @State private var newName = ""
    @State private var renaming: CollectionsModel.Row?
    @State private var renameText = ""
    @State private var deleting: CollectionsModel.Row?
    @State private var sharing: ShareTarget?

    /// The Share sheet of a collection, or the Join sheet (`collectionID` nil).
    struct ShareTarget: Identifiable {
        let id = UUID()
        let collectionID: String?
    }

    init(model: CollectionsModel, sync: SyncCoordinator? = nil, pro: ProModel? = nil, onChange: @escaping () -> Void = {}) {
        _model = State(initialValue: model)
        self.sync = sync
        self.pro = pro
        self.onChange = onChange
    }

    var body: some View {
        List {
            Section {
                if model.rows.isEmpty {
                    Text("No collections yet.").foregroundStyle(Palette.secondaryText)
                }
                ForEach(model.rows) { row in
                    HStack(spacing: 10) {
                        Image(systemName: row.isShared ? "person.2" : "folder").foregroundStyle(Palette.accentText)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(CollectionCatalog.displayName(row.name)).foregroundStyle(Palette.text)
                            if row.isShared || row.isReadOnly {
                                HStack(spacing: 6) {
                                    if row.isShared { badge(CollectionShareSheet.Words.sharedBadge) }
                                    if row.isReadOnly {
                                        Label("View only", systemImage: "lock").labelStyle(.titleAndIcon).font(.caption)
                                            .foregroundStyle(Palette.secondaryText)
                                    }
                                }
                            }
                            if sync?.removedShares[row.id] != nil {
                                Text(CollectionShareModel.removedBadgeText).font(.caption).foregroundStyle(Palette.warning)
                            }
                        }
                        Spacer()
                        Text(row.count, format: .number).monospacedDigit().foregroundStyle(Palette.secondaryText)
                        if sync != nil {
                            Button { sharing = ShareTarget(collectionID: row.id) } label: {
                                Image(systemName: "person.crop.circle.badge.plus").foregroundStyle(Palette.accentText)
                            }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(CollectionShareSheet.Words.share)
                        }
                    }
                    .accessibilityElement(children: .contain)
                    .swipeActions(edge: .trailing) {
                        if !row.isShared {
                            Button("Delete") { deleting = row }.tint(Palette.danger)
                        }
                        if !row.isReadOnly {
                            Button("Rename") { startRename(row) }.tint(Palette.accent)
                        }
                    }
                    .contextMenu {
                        if sync != nil {
                            Button { sharing = ShareTarget(collectionID: row.id) } label: {
                                Label(CollectionShareSheet.Words.share, systemImage: "person.crop.circle.badge.plus")
                            }
                        }
                        if !row.isReadOnly {
                            Button { startRename(row) } label: { Label("Rename", systemImage: "pencil") }
                        }
                        if !row.isShared {
                            Button(role: .destructive) { deleting = row } label: { Label("Delete", systemImage: "trash") }
                        }
                    }
                }
            } footer: {
                Text("Notes, cards and other typed items can be added to collections. Logins can't.")
            }
            .listRowBackground(Palette.groupSurface)
            if model.missingStarters {
                Section {
                    Button("Add starter collections") { if model.addStarters() { onChange() } }
                        .foregroundStyle(Palette.accentText)
                } footer: {
                    Text(verbatim: CollectionCatalog.starterNames.joined(separator: ", "))
                }
                .listRowBackground(Palette.groupSurface)
            }
            if let message = model.message {
                Section { Text(message).foregroundStyle(Palette.danger) }.listRowBackground(Palette.groupSurface)
            }
            if sync != nil {
                Section {
                    Button(CollectionShareSheet.Words.joinTitle) { sharing = ShareTarget(collectionID: nil) }
                        .foregroundStyle(Palette.accentText)
                }
                .listRowBackground(Palette.groupSurface)
            }
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Collections")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button { newName = ""; creating = true } label: { Image(systemName: "plus") }
                    .accessibilityLabel("New collection")
            }
        }
        .alert("New collection", isPresented: $creating) {
            TextField("Name", text: $newName)
            Button("Create") { if model.create(name: newName) != nil { onChange() } }
            Button("Cancel", role: .cancel) {}
        }
        .alert("Rename", isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
            TextField("Name", text: $renameText)
            Button("Save") {
                if let row = renaming, model.rename(row.id, to: renameText) { onChange() }
                renaming = nil
            }
            Button("Cancel", role: .cancel) { renaming = nil }
        }
        // An alert with a visible Cancel, as for items (tester feedback 1).
        .alert("Delete collection?", isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }),
               presenting: deleting) { row in
            Button("Delete", role: .destructive) {
                if model.delete(row.id) { onChange() }
                deleting = nil
            }
            Button("Cancel", role: .cancel) { deleting = nil }
        } message: { _ in
            Text("The items in it are kept.")
        }
        .sheet(item: $sharing, onDismiss: { model.reload() }) { target in
            if let sync {
                CollectionShareSheet(collectionID: target.collectionID, sync: sync, pro: pro,
                                     onChange: { model.reload(); onChange() })
            }
        }
        .onAppear { model.reload() }
    }

    private func badge(_ text: String) -> some View {
        Text(text).font(.caption).padding(.horizontal, 6).padding(.vertical, 1)
            .foregroundStyle(Palette.accentText)
            .background(Capsule().fill(Palette.innerTile))
    }

    private func startRename(_ row: CollectionsModel.Row) {
        renameText = row.name
        renaming = row
    }
}
