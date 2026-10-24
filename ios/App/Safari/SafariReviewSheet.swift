import SwiftUI
import AppShared

/// Asks before logins saved in Safari go into the vault (audit 2026-10-24 L-18). The Safari extension saves
/// without Face ID and a page script could drive its prompt, so nothing it saved is imported until the user
/// says yes here, in the unlocked app. Every row starts selected; unselected ones are deleted, "Decide later"
/// keeps them all for the next unlock. Passwords are never shown.
struct SafariReviewSheet: View {
    let pending: [SafariPendingSave]
    let onSave: (Set<String>) -> Void
    let onLater: () -> Void
    @State private var selected: Set<String>

    init(pending: [SafariPendingSave], onSave: @escaping (Set<String>) -> Void, onLater: @escaping () -> Void) {
        self.pending = pending; self.onSave = onSave; self.onLater = onLater
        _selected = State(initialValue: Set(pending.map(\.id)))
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(pending) { item in
                        Button { toggle(item.id) } label: { row(item) }
                            .accessibilityAddTraits(selected.contains(item.id) ? .isSelected : [])
                    }
                } footer: {
                    Text("Saved from Safari since you last opened LocalGateKeys. Only the logins you keep selected are saved; the others are deleted.")
                }
            }
            .navigationTitle("Save from Safari?")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Decide later") { onLater() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(selected.isEmpty ? "Delete all" : "Save \(selected.count)") { onSave(selected) }
                }
            }
        }
        // Swiping the sheet away must not count as an answer either way.
        .interactiveDismissDisabled()
    }

    private func toggle(_ id: String) {
        if selected.contains(id) { selected.remove(id) } else { selected.insert(id) }
    }

    private func row(_ item: SafariPendingSave) -> some View {
        HStack(spacing: 12) {
            Image(systemName: selected.contains(item.id) ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(selected.contains(item.id) ? Palette.accent : Palette.secondaryText)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(OriginLabel.friendly(item.origin)).font(.body.weight(.semibold)).foregroundStyle(Palette.text)
                Text(item.username).font(.subheadline).foregroundStyle(Palette.secondaryText).lineLimit(1)
                Text(Self.detail(item)).font(.footnote).foregroundStyle(Palette.secondaryText).lineLimit(2)
            }
        }
    }

    /// "New login · https://accounts.example.com" or "Updates the saved password · ...": the full origin, so a
    /// look-alike host is visible.
    static func detail(_ item: SafariPendingSave) -> String {
        (item.change == .new ? "New login" : "Updates the saved password") + " \u{00B7} " + item.origin
    }
}
