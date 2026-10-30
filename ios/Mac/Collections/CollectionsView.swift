import SwiftUI
import LGKCore
import AppSharedMac

/// "Manage collections" (Windows collections dialog): create, rename and delete. Deleting removes the
/// collection from its items; the items stay.
struct CollectionsView: View {
    @Bindable var model: CollectionsModel
    let onClose: () -> Void
    @State private var newName = ""
    @State private var renaming: String?
    @State private var renameText = ""
    @State private var confirmingDelete: LocalData.Collection?
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Collections").font(.system(size: 18, weight: .semibold))
            Text("Collections stay on this Mac. An item can be in up to 20.")
                .font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
            HStack(spacing: 8) {
                TextField("New collection", text: $newName).glassField().onSubmit(create)
                Button("Create", action: create).buttonStyle(PillButtonStyle(primary: true))
                    .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            if let message = model.message {
                Text(message).font(.system(size: 12)).foregroundStyle(theme.danger)
            }
            ScrollView {
                VStack(spacing: 0) {
                    ForEach(model.collections, id: \.id) { c in
                        HStack(spacing: 10) {
                            if renaming == c.id {
                                TextField("Name", text: $renameText).glassField().onSubmit { rename(c.id) }
                                Button("Save") { rename(c.id) }.buttonStyle(.plain).foregroundStyle(theme.link)
                                Button("Cancel") { renaming = nil }.buttonStyle(.plain).foregroundStyle(theme.link)
                            } else {
                                Text(c.name).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
                                Text("\(model.count(of: c.id))").font(.system(size: 12)).foregroundStyle(theme.textFaint)
                                Button("Rename") { renaming = c.id; renameText = c.name }
                                    .buttonStyle(.plain).foregroundStyle(theme.link)
                                Button("Delete") { confirmingDelete = c }.buttonStyle(.plain).foregroundStyle(theme.danger)
                            }
                        }
                        .padding(.vertical, 7).padding(.horizontal, 10)
                    }
                }
                .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
            }
            .frame(minHeight: 160, maxHeight: 320)
            HStack { Spacer(); Button("Done", action: onClose).buttonStyle(PillButtonStyle(primary: false)).keyboardShortcut(.cancelAction) }
        }
        .padding(20)
        .frame(width: 440)
        .foregroundStyle(theme.text)
        .font(.system(size: 14))
        .onAppear { model.message = nil }
        .alert("Delete collection?", isPresented: Binding(get: { confirmingDelete != nil }, set: { if !$0 { confirmingDelete = nil } })) {
            Button("Delete", role: .destructive) { if let c = confirmingDelete { try? model.delete(c.id) }; confirmingDelete = nil }
            Button("Cancel", role: .cancel) { confirmingDelete = nil }
        } message: { Text("The items in it are kept.") }
    }

    private func create() {
        if (try? model.create(name: newName)) != nil { newName = "" }
    }

    private func rename(_ id: String) {
        if (try? model.rename(id, to: renameText)) != nil { renaming = nil }
    }
}

/// The editor's collections picker for typed items: a toggle per known collection.
struct CollectionsPicker: View {
    let collections: [LocalData.Collection]
    @Binding var chosen: Set<String>
    @Environment(\.macTheme) private var theme

    var body: some View {
        if collections.isEmpty {
            Text("No collections yet.").foregroundStyle(theme.textMuted)
        } else {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 140), alignment: .leading)], alignment: .leading, spacing: 6) {
                ForEach(collections, id: \.id) { c in
                    Toggle(c.name, isOn: Binding(get: { chosen.contains(c.id) },
                                                 set: { if $0 { chosen.insert(c.id) } else { chosen.remove(c.id) } }))
                        .toggleStyle(.checkbox).lineLimit(1)
                }
            }
        }
    }
}
