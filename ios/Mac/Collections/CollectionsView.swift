import SwiftUI
import LGKCore
import AppSharedMac

/// "Manage collections" (Windows collections dialog; sub-plan 07 task 5i): create, rename, delete (the items stay), the
/// starters while any is missing, and sharing. Shared collections show a Shared badge and are never deleted here (stop
/// sharing or leave first); view-only ones show a lock and are never renamed. Each row has Share… (the Mac share page,
/// `MacCollectionSharePage`, shown in this sheet); Join a shared collection is at the bottom. A collection this Mac was
/// removed from says its items went to the trash.
struct CollectionsView: View {
    let model: MacCollectionsModel
    /// Shared collections (nil: no Share or Join, as in previews and tests).
    let sync: SyncCoordinator?
    /// The window's master password prompt: sharing asks it first, and any prompt shows here while this sheet is open.
    let gate: StrictItemGate?
    let pro: ProModel?
    /// After a change: the window's list follows.
    let onChange: () -> Void
    let onClose: () -> Void
    @State private var newName = ""
    @State private var renaming: String?
    @State private var renameText = ""
    @State private var confirmingDelete: CollectionsModel.Row?
    /// The share page shown in place of the list: a collection's, or Join (`collectionID` nil).
    @State private var sharing: ShareTarget?
    @Environment(\.macTheme) private var theme

    struct ShareTarget: Identifiable {
        let id = UUID()
        let collectionID: String?
    }

    init(model: MacCollectionsModel, sync: SyncCoordinator? = nil, gate: StrictItemGate? = nil, pro: ProModel? = nil,
         onChange: @escaping () -> Void = {}, onClose: @escaping () -> Void) {
        self.model = model; self.sync = sync; self.gate = gate; self.pro = pro
        self.onChange = onChange; self.onClose = onClose
    }

    var body: some View {
        content
            .padding(20)
            .frame(width: 520)
            .foregroundStyle(theme.text)
            .font(.system(size: 14))
            .onAppear { model.message = nil; model.reload() }
            .alert("Delete collection?", isPresented: Binding(get: { confirmingDelete != nil }, set: { if !$0 { confirmingDelete = nil } })) {
                Button("Delete", role: .destructive) {
                    if let row = confirmingDelete, model.delete(row.id) { onChange() }
                    confirmingDelete = nil
                }
                Button("Cancel", role: .cancel) { confirmingDelete = nil }
            } message: { Text("The items in it are kept.") }
            .sheet(item: Binding(get: { gate?.pending }, set: { if $0 == nil { gate?.cancel() } })) { request in
                if let gate { StrictItemSheet(gate: gate, request: request).macThemed() }
            }
    }

    @ViewBuilder private var content: some View {
        if let target = sharing, let sync {
            MacCollectionSharePage(collectionID: target.collectionID, sync: sync, gate: gate, pro: pro,
                                   onChange: { model.reload(); onChange() },
                                   onBack: { sharing = nil; model.reload() })
                .id(target.id)
        } else {
            list
        }
    }

    private var list: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Collections").font(.system(size: 18, weight: .semibold))
            Text("Notes, cards and other typed items can be added to collections. Logins can't.")
                .font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
            HStack(spacing: 8) {
                TextField("New collection", text: $newName).glassField().onSubmit(create)
                Button("Create", action: create).buttonStyle(PillButtonStyle(primary: true))
                    .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            if let message = model.message {
                Text(message).font(.system(size: 12)).foregroundStyle(theme.danger).fixedSize(horizontal: false, vertical: true)
            }
            ScrollView {
                VStack(spacing: 0) {
                    if model.rows.isEmpty {
                        Text("No collections yet.").foregroundStyle(theme.textMuted)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(10)
                    }
                    ForEach(model.rows) { row($0) }
                }
                .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
            }
            .frame(minHeight: 160, maxHeight: 340)
            HStack(spacing: 12) {
                if model.missingStarters {
                    Button("Add starter collections") { if model.addStarters() { onChange() } }
                        .buttonStyle(.plain).foregroundStyle(theme.link)
                        .help(Text(verbatim: CollectionCatalog.starterNames.map(CollectionCatalog.displayName).joined(separator: ", ")))
                }
                if sync != nil {
                    Button(CollectionShareModel.Words.joinTitle) { sharing = ShareTarget(collectionID: nil) }
                        .buttonStyle(.plain).foregroundStyle(theme.link)
                }
                Spacer()
                Button("Done", action: onClose).buttonStyle(PillButtonStyle(primary: false)).keyboardShortcut(.cancelAction)
            }
        }
    }

    private func row(_ c: CollectionsModel.Row) -> some View {
        HStack(spacing: 10) {
            if renaming == c.id {
                TextField("Name", text: $renameText).glassField().onSubmit { rename(c.id) }
                Button("Save") { rename(c.id) }.buttonStyle(.plain).foregroundStyle(theme.link)
                Button("Cancel") { renaming = nil }.buttonStyle(.plain).foregroundStyle(theme.link)
            } else {
                Image(systemName: c.isShared ? "person.2" : "folder").foregroundStyle(theme.textMuted)
                VStack(alignment: .leading, spacing: 3) {
                    Text(CollectionCatalog.displayName(c.name)).lineLimit(1)
                    if c.isShared || c.isReadOnly {
                        HStack(spacing: 6) {
                            if c.isShared { badge(CollectionShareModel.Words.sharedBadge) }
                            if c.isReadOnly {
                                Label("View only", systemImage: "lock").font(.system(size: 11.5)).foregroundStyle(theme.textMuted)
                            }
                        }
                    }
                    if sync?.removedShares[c.id] != nil {
                        Text(CollectionShareModel.removedBadgeText).font(.system(size: 11.5)).foregroundStyle(theme.warning)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                Text("\(c.count)").font(.system(size: 12)).foregroundStyle(theme.textFaint)
                if sync != nil {
                    Button(CollectionShareModel.Words.share + "…") { sharing = ShareTarget(collectionID: c.id) }
                        .buttonStyle(.plain).foregroundStyle(theme.link)
                }
                if !c.isReadOnly {
                    Button("Rename") { renaming = c.id; renameText = c.name }
                        .buttonStyle(.plain).foregroundStyle(theme.link)
                }
                if !c.isShared {
                    Button("Delete") { confirmingDelete = c }.buttonStyle(.plain).foregroundStyle(theme.danger)
                }
            }
        }
        .padding(.vertical, 7).padding(.horizontal, 10)
    }

    private func badge(_ text: String) -> some View {
        Text(text).font(.system(size: 11)).padding(.horizontal, 6).padding(.vertical, 1)
            .foregroundStyle(theme.link)
            .background(Capsule().fill(theme.chip))
    }

    private func create() {
        if model.create(name: newName) != nil { newName = ""; onChange() }
    }

    private func rename(_ id: String) {
        if model.rename(id, to: renameText) { renaming = nil; onChange() }
    }
}

/// The editor's collections picker for typed items: a checkbox per collection. A view-only collection is locked (an
/// item is neither moved into nor out of it here).
struct CollectionsPicker: View {
    let collections: [CollectionCatalog.Collection]
    var readOnly: Set<String> = []
    @Binding var chosen: Set<String>
    @Environment(\.macTheme) private var theme

    var body: some View {
        if collections.isEmpty {
            Text("No collections yet.").foregroundStyle(theme.textMuted)
        } else {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 140), alignment: .leading)], alignment: .leading, spacing: 6) {
                ForEach(collections, id: \.id) { c in
                    let locked = readOnly.contains(c.id)
                    Toggle(isOn: Binding(get: { chosen.contains(c.id) },
                                         set: { if $0 { chosen.insert(c.id) } else { chosen.remove(c.id) } })) {
                        if locked { Label(CollectionCatalog.displayName(c.name), systemImage: "lock") } else { Text(CollectionCatalog.displayName(c.name)) }
                    }
                    .toggleStyle(.checkbox).lineLimit(1)
                    .disabled(locked)
                    .help(locked ? EditorModel.readOnlyCollectionText : "")
                }
            }
        }
    }
}
