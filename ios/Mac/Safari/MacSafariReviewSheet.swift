import SwiftUI
import AppSharedMac

/// The Mac's "Save from Safari?" sheet (the iPhone's `SafariReviewSheet`, same words from `SafariReviewCopy`):
/// nothing the Safari extension saved reaches the vault without a yes here. Every row starts selected;
/// unselected ones are deleted, "Decide later" keeps them all for the next unlock. Passwords are never shown.
struct MacSafariReviewSheet: View {
    let pending: [SafariPendingSave]
    let onSave: (Set<String>) -> Void
    let onLater: () -> Void
    @State private var selected: Set<String>
    @Environment(\.macTheme) private var theme

    init(pending: [SafariPendingSave], onSave: @escaping (Set<String>) -> Void, onLater: @escaping () -> Void) {
        self.pending = pending; self.onSave = onSave; self.onLater = onLater
        _selected = State(initialValue: Set(pending.map(\.id)))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "safari").font(.system(size: 22)).foregroundStyle(theme.accent)
                Text(SafariReviewCopy.title).font(.system(size: 19, weight: .semibold)).foregroundStyle(theme.text)
            }
            ScrollView {
                VStack(spacing: 0) {
                    ForEach(pending) { item in
                        Button { toggle(item.id) } label: { row(item) }
                            .buttonStyle(.plain)
                            .accessibilityAddTraits(selected.contains(item.id) ? .isSelected : [])
                    }
                }
                .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
            }
            .frame(maxHeight: 320)
            Text(SafariReviewCopy.footer)
                .font(.callout).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button(SafariReviewCopy.later, action: onLater)
                    .buttonStyle(GlassButtonStyle())
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(SafariReviewCopy.save(selected.count)) { onSave(selected) }
                    .buttonStyle(AccentButtonStyle())
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(width: 460)
        .background(WashBackground())
        // Closing the sheet any other way must not count as an answer either way.
        .interactiveDismissDisabled()
    }

    private func toggle(_ id: String) {
        if selected.contains(id) { selected.remove(id) } else { selected.insert(id) }
    }

    private func row(_ item: SafariPendingSave) -> some View {
        HStack(spacing: 12) {
            Image(systemName: selected.contains(item.id) ? "checkmark.circle.fill" : "circle")
                .font(.system(size: 16))
                .foregroundStyle(selected.contains(item.id) ? theme.accent : theme.textMuted)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(OriginLabel.friendly(item.origin)).font(.system(size: 13, weight: .semibold)).foregroundStyle(theme.text)
                Text(item.username).font(.system(size: 12)).foregroundStyle(theme.textMuted).lineLimit(1)
                Text(SafariReviewCopy.detail(item)).font(.system(size: 11)).foregroundStyle(theme.textFaint).lineLimit(2)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .contentShape(Rectangle())
    }
}
