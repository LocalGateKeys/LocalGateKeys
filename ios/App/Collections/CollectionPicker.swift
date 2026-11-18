import SwiftUI
import AppShared

/// Which collections an item is in (the editor's Collections row; typed items only, never logins). At most 20: a
/// collection past that cannot be ticked. Ids of collections this iPhone does not know stay in `selection` untouched.
struct CollectionPicker: View {
    let collections: [CollectionCatalog.Collection]
    /// View-only collections: shown with a lock, never ticked or unticked here.
    var readOnly: Set<String> = []
    @Binding var selection: Set<String>

    var body: some View {
        List {
            Section {
                if collections.isEmpty {
                    Text("No collections yet.").foregroundStyle(Palette.secondaryText)
                }
                ForEach(collections, id: \.id) { collection in
                    let picked = selection.contains(collection.id)
                    let locked = readOnly.contains(collection.id)
                    Button { toggle(collection.id) } label: {
                        HStack {
                            Text(CollectionCatalog.displayName(collection.name)).foregroundStyle(Palette.text)
                            if locked {
                                Image(systemName: "lock").foregroundStyle(Palette.secondaryText).accessibilityLabel("View only")
                            }
                            Spacer()
                            if picked { Image(systemName: "checkmark").foregroundStyle(Palette.accentText) }
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .disabled(locked || (!picked && selection.count >= CollectionStates.maxMemberships))
                    .accessibilityAddTraits(picked ? .isSelected : [])
                }
            } footer: {
                Text("An item can be in up to 20 collections.")
            }
            .listRowBackground(Palette.groupSurface)
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Collections")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func toggle(_ id: String) {
        if readOnly.contains(id) { return }
        if selection.contains(id) {
            selection.remove(id)
        } else if selection.count < CollectionStates.maxMemberships {
            selection.insert(id)
        }
    }
}
