import SwiftUI

/// ⌘K: one field over items, actions, settings and help (Windows `Palette.svelte`). ↑/↓ move, Return runs,
/// Esc or a click outside closes.
struct CommandPalette: View {
    @Bindable var model: PaletteModel
    let onRun: (PaletteRow) -> Void
    let onClose: () -> Void
    @FocusState private var fieldFocused: Bool
    @Environment(\.macTheme) private var theme

    var body: some View {
        let rows = model.rows
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(theme.textFaint)
                TextField(PaletteModel.placeholder, text: $model.query)
                    .textFieldStyle(.plain).font(.system(size: 15)).focused($fieldFocused)
                    .onKeyPress(.downArrow) { model.move(1); return .handled }
                    .onKeyPress(.upArrow) { model.move(-1); return .handled }
                    .onSubmit { if let row = model.highlightedRow { onRun(row) } }
                    .onExitCommand(perform: onClose)
            }
            .padding(.horizontal, 16).padding(.vertical, 12)
            Rectangle().fill(theme.panelBorder).frame(height: 1)
            if rows.isEmpty {
                Text("No matches").font(.system(size: 13)).foregroundStyle(theme.textMuted)
                    .padding(16)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                            if index == 0 || rows[index - 1].group != row.group {
                                Text(row.group.title.uppercased())
                                    .font(.system(size: 11, weight: .semibold)).foregroundStyle(theme.textFaint)
                                    .padding(.horizontal, 16).padding(.top, index == 0 ? 8 : 12).padding(.bottom, 4)
                            }
                            rowView(row, highlighted: index == model.highlighted)
                                .contentShape(Rectangle())
                                .onTapGesture { onRun(row) }
                                .onHover { if $0 { model.highlighted = index } }
                        }
                    }
                    .padding(.bottom, 8)
                }
                .frame(maxHeight: 440)
            }
        }
        .frame(width: 600)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(theme.panelBorder))
        .shadow(color: .black.opacity(0.3), radius: 24, y: 10)
        .onAppear { fieldFocused = true }
    }

    private func rowView(_ row: PaletteRow, highlighted: Bool) -> some View {
        HStack(spacing: 10) {
            Text(row.title).font(.system(size: 14)).foregroundStyle(highlighted ? theme.onAccent : theme.text)
            Text(row.subtitle).font(.system(size: 12)).foregroundStyle(highlighted ? theme.onAccent.opacity(0.8) : theme.textMuted)
                .lineLimit(1)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12).padding(.vertical, 7)
        .background(highlighted ? theme.accent : .clear, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .padding(.horizontal, 6)
    }
}
