import SwiftUI
import LGKCore
import AppSharedMac

/// The sidebar's Trash (Windows `TrashPage.svelte`): the retention note with a Settings link, the deleted
/// items newest first with a checkbox each, and the counts with Empty trash, Delete selected and Restore selected.
struct TrashView: View {
    @Bindable var model: TrashModel
    let onSettings: () -> Void
    @Environment(\.macTheme) private var theme
    /// The rows a permanent delete is waiting to be confirmed for.
    @State private var confirmingPurge: Set<String>?

    var body: some View {
        let rows = model.rows
        VStack(alignment: .leading, spacing: 10) {
            Text(TrashModel.title).font(.system(size: 19, weight: .semibold))
            Text(model.retentionText)
                .font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            Button("Change in settings", action: onSettings).buttonStyle(.link).font(.system(size: 12.5))
            if let message = model.message {
                Text(message).font(.system(size: 12.5)).foregroundStyle(theme.success)
            }
            ForEach(model.failures, id: \.self) { Text($0).font(.system(size: 12.5)).foregroundStyle(theme.danger) }
            if rows.isEmpty {
                Text(TrashModel.emptyText).foregroundStyle(theme.textMuted)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                            if index > 0 { Rectangle().fill(theme.line).frame(height: 1) }
                            rowView(row)
                        }
                    }
                }
                .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
            }
            footer(rows)
        }
        .foregroundStyle(theme.text)
        .padding(18)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .alert("Permanently delete?", isPresented: Binding(get: { confirmingPurge != nil }, set: { if !$0 { confirmingPurge = nil } })) {
            Button("Delete", role: .destructive) { if let ids = confirmingPurge { model.purge(ids) }; confirmingPurge = nil }
            Button("Cancel", role: .cancel) { confirmingPurge = nil }
        } message: { Text(confirmingPurge.map(model.purgeConfirmText) ?? "") }
    }

    private func rowView(_ row: TrashModel.Row) -> some View {
        HStack(spacing: 10) {
            Toggle("", isOn: Binding(get: { model.selected.contains(row.id) }, set: { _ in model.toggle(row.id) }))
                .toggleStyle(.checkbox).labelsHidden()
                .accessibilityLabel("Select \(row.title)")
            Text(row.title).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
            Text(row.detail).font(.system(size: 12.5)).foregroundStyle(theme.textMuted).lineLimit(1)
            Text(Self.day(row.deletedAt)).font(.system(size: 12.5).monospacedDigit()).foregroundStyle(theme.textMuted)
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
        .contentShape(Rectangle())
        .onTapGesture { model.toggle(row.id) }
    }

    private func footer(_ rows: [TrashModel.Row]) -> some View {
        let picked = model.selected.intersection(rows.map(\.id))
        return HStack(spacing: 8) {
            Text(model.countText).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
            Spacer()
            Button("Empty trash") { confirmingPurge = Set(rows.map(\.id)) }
                .buttonStyle(PillButtonStyle(primary: false)).foregroundStyle(theme.danger)
                .disabled(rows.isEmpty)
            Button("Delete selected") { confirmingPurge = picked }
                .buttonStyle(PillButtonStyle(primary: false)).foregroundStyle(theme.danger)
                .disabled(picked.isEmpty)
            Button("Restore selected") { model.restore(picked) }
                .buttonStyle(PillButtonStyle(primary: true))
                .disabled(picked.isEmpty)
        }
    }

    /// "2026-10-25 14:03", local time (Windows shows the same shape).
    static func day(_ seconds: Int64) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_GB_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm"
        return f.string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
    }
}
