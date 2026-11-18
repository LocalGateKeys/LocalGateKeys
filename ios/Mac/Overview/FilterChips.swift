import SwiftUI
import AppSharedMac

/// "All" plus the Needs attention / No 2FA / Expiring chips that have items (Windows `Chips.svelte`,
/// mockup `.filters`).
struct FilterChips: View {
    @Bindable var model: OverviewModel
    /// "Finish setting up · 1 of 5" while setup is unfinished (Windows `button.setup`), with ✕ to hide it.
    var setup: String? = nil
    var onSetup: () -> Void = {}
    var onHideSetup: () -> Void = {}
    @Environment(\.macTheme) private var theme

    var body: some View {
        // Wraps onto a second line when the labels do not fit (Windows `.chips`: flex-wrap).
        FlowRow(spacing: 6) {
            chip(String(localized: "All"), on: model.activeChip == nil) { model.activeChip = nil }
            ForEach(model.chips, id: \.chip) { entry in
                chip(OverviewModel.chipLabel(entry.chip, count: entry.count), on: model.activeChip == entry.chip) {
                    model.activeChip = entry.chip
                }
            }
            if let setup {
                Button(action: onSetup) {
                    Text(setup).font(.system(size: 13)).lineLimit(1).foregroundStyle(theme.link)
                        .padding(.horizontal, 12).padding(.vertical, 4)
                        .overlay(Capsule().strokeBorder(theme.panelBorder))
                        .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                Button(action: onHideSetup) {
                    Image(systemName: "xmark").font(.system(size: 10, weight: .semibold)).foregroundStyle(theme.textMuted)
                        .frame(width: 24, height: 24)
                        .overlay(Circle().strokeBorder(theme.panelBorder))
                        .contentShape(Circle())
                }
                .buttonStyle(.plain)
                .help(Onboarding.hide).accessibilityLabel(Onboarding.hide)
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
