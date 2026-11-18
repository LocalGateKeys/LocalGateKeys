import SwiftUI
import AppSharedMac

/// "One-time codes" (Windows `CodesCard.svelte`, mockup `.codes`): a live code per login with a 2FA secret,
/// two per row, four until "Show all N". Clicking a tile copies its code (concealed); a login that needs the
/// master password shows "Hidden · click to copy" and asks for it first.
struct CodesStrip: View {
    @Bindable var model: OverviewModel
    let items: [VaultItem]
    let onCopy: (CodeEntry) -> Void
    @Environment(\.macTheme) private var theme
    /// Folded shows only the header with the count; no code is computed and the item list gets the space.
    /// Remembered per profile (the default profile keeps the old unprefixed key).
    @AppStorage private var folded: Bool

    init(model: OverviewModel, items: [VaultItem], onCopy: @escaping (CodeEntry) -> Void) {
        _model = Bindable(wrappedValue: model); self.items = items; self.onCopy = onCopy
        _folded = AppStorage(wrappedValue: false, ProfileScope.defaultsPrefix + OverviewModel.codesFoldedKey)
    }

    var body: some View {
        let all = model.codes
        if !all.isEmpty {
            let visible = OverviewModel.visibleCodes(all, expanded: model.codesExpanded)
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .firstTextBaseline) {
                    Button { folded.toggle() } label: {
                        HStack(spacing: 6) {
                            Image(systemName: folded ? "chevron.right" : "chevron.down")
                                .font(.system(size: 11, weight: .semibold)).foregroundStyle(theme.textMuted)
                                .frame(width: 12)
                            (folded ? Text("One-time codes · \(all.count)") : Text("One-time codes"))
                                .font(.system(size: 14, weight: .semibold))
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(folded ? Text("Expand one-time codes") : Text("Collapse one-time codes"))
                    .accessibilityAddTraits(.isHeader)
                    .help(folded ? Text("Expand one-time codes") : Text("Collapse one-time codes"))
                    Spacer()
                    if !folded, let toggle = visible.toggle {
                        Button(toggle) { model.codesExpanded.toggle() }
                            .buttonStyle(.plain).font(.system(size: 12.5)).foregroundStyle(theme.link)
                    }
                }
                .padding(.horizontal, 2)
                if !folded {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let now = Int64(context.date.timeIntervalSince1970)
                        LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 10) {
                            ForEach(visible.shown) { entry in
                                CodeTile(entry: entry, item: items.first { $0.id == entry.id }, now: now) { onCopy(entry) }
                            }
                        }
                    }
                }
            }
            .foregroundStyle(theme.text)
        }
    }
}

private struct CodeTile: View {
    let entry: CodeEntry
    let item: VaultItem?
    let now: Int64
    let action: () -> Void
    @Environment(\.macTheme) private var theme

    var body: some View {
        let live = entry.code(at: now)
        Button(action: action) {
            HStack(spacing: 10) {
                if let item { ItemLogo(item: item, size: 28) }
                VStack(alignment: .leading, spacing: 1) {
                    Text(entry.title).font(.system(size: 13)).foregroundStyle(theme.textMuted).lineLimit(1)
                    if entry.setup == .hidden {
                        Text("Hidden · click to copy").font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                    } else if let live {
                        Text(DetailPanel.grouped(live.code))
                            .font(.system(size: 17, weight: .semibold, design: .monospaced)).tracking(1)
                    } else {
                        Text("Invalid setup key").font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                    }
                }
                Spacer(minLength: 4)
                if let live { Ring(remaining: live.remaining, period: live.period) }
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            .frame(maxWidth: .infinity, minHeight: 52, alignment: .leading)
            .background(theme.card, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(entry.setup != .hidden && live == nil)
        .help("Copy the one-time code")
        .accessibilityLabel("Copy 2FA code for \(entry.title)")
    }
}

/// The seconds left: green, amber at 5 s or less.
private struct Ring: View {
    let remaining: Int
    let period: Int
    @Environment(\.macTheme) private var theme

    var body: some View {
        ZStack {
            Circle().stroke(theme.line, lineWidth: 2)
            Circle().trim(from: 0, to: Double(remaining) / Double(max(period, 1)))
                .stroke(remaining <= 5 ? theme.warning : theme.live, style: StrokeStyle(lineWidth: 2, lineCap: .round))
                .rotationEffect(.degrees(-90))
        }
        .frame(width: 16, height: 16)
        .help("Refreshes in \(remaining) s")
        .accessibilityLabel("Refreshes in \(remaining) s")
    }
}
