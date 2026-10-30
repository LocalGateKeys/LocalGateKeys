import SwiftUI
import AppSharedMac

/// The sidebar's Devices & connections page (Windows `ConnectionsPage.svelte`).
struct ConnectionsView: View {
    @Bindable var model: ConnectionsModel
    var onOpenSync: () -> Void = {}
    @Environment(\.macTheme) private var theme

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text(ConnectionsModel.title).font(.system(size: 19, weight: .semibold))
                Text(ConnectionsModel.subtitle).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.headline).font(.system(size: 16, weight: .semibold))
                    Text(model.summary).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("● \(model.status)").font(.system(size: 12.5, weight: .semibold))
                        .foregroundStyle(model.tone == .success ? theme.success : model.tone == .warning ? theme.warning : theme.textMuted).padding(.top, 2)
                }
                .padding(14).frame(maxWidth: .infinity, alignment: .leading)
                .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
                VStack(spacing: 0) {
                    ForEach(Array(model.rows.enumerated()), id: \.element.id) { index, row in
                        if index > 0 { Rectangle().fill(theme.line).frame(height: 1) }
                        rowView(row)
                    }
                }
                .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
                if let message = model.message { Text(message).font(.system(size: 12.5)).foregroundStyle(theme.warning) }
                HStack { Button("Refresh") { Task { await model.refresh() } }.buttonStyle(PillButtonStyle(primary: false)) }
                Text(ConnectionsModel.footer).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .foregroundStyle(theme.text)
            .padding(18)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .task { await model.refresh() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await model.refresh() }
        }
    }

    private func rowView(_ row: ConnectionsModel.Row) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(row.title).frame(width: 130, alignment: .leading)
            Text(row.state).font(.system(size: 12.5, weight: row.ok == nil ? .regular : .semibold))
                .foregroundStyle(row.ok == nil ? theme.textMuted : (row.ok == true ? theme.success : theme.warning))
                .frame(maxWidth: .infinity, alignment: .leading)
            if let action = row.action {
                Button(action) {
                    switch row.id {
                    case "safari": Task { await model.openSafariSettings() }
                    case "wifi": onOpenSync()
                    default: model.openAutoFillSettings()
                    }
                }
                    .buttonStyle(PillButtonStyle(primary: false))
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }
}
