import SwiftUI

/// "All" plus the Needs attention / No 2FA / Expiring chips that have items (Windows `Chips.svelte`,
/// mockup `.filters`).
struct FilterChips: View {
    @Bindable var model: OverviewModel
    @Environment(\.macTheme) private var theme

    var body: some View {
        HStack(spacing: 6) {
            chip(String(localized: "All"), on: model.activeChip == nil) { model.activeChip = nil }
            ForEach(model.chips, id: \.chip) { entry in
                chip(OverviewModel.chipLabel(entry.chip, count: entry.count), on: model.activeChip == entry.chip) {
                    model.activeChip = entry.chip
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Quick filters")
    }

    private func chip(_ title: String, on: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title).font(.system(size: 13)).lineLimit(1)
                .padding(.horizontal, 12).padding(.vertical, 4)
                .foregroundStyle(on ? theme.washBase : theme.text)
                .background(on ? theme.text : .clear, in: Capsule())
                .overlay(Capsule().strokeBorder(on ? .clear : theme.panelBorder))
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(on ? .isSelected : [])
    }
}
