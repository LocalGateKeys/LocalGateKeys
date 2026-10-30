import SwiftUI

extension SyncStatusSummary.Dot {
    func color(_ theme: MacTheme) -> Color {
        switch self {
        case .green: theme.success
        case .orange: theme.warning
        case .red: theme.danger
        }
    }
}

/// The sidebar's bottom pill (UX plan workstream 6, Windows sidebar pill): "Synced 2 min ago · 3 devices" with a
/// green, orange or red dot. Hidden while this Mac does not sync. The text refreshes every 30 s.
struct SyncStatusSidebarPill: View {
    let coordinator: SyncCoordinator
    let onTap: () -> Void
    @Environment(\.macTheme) private var theme

    var body: some View {
        TimelineView(.periodic(from: .now, by: 30)) { context in
            if let summary = coordinator.statusSummary(now: Int64(context.date.timeIntervalSince1970)) {
                Button(action: onTap) {
                    HStack(spacing: 8) {
                        Circle().fill(summary.dot.color(theme)).frame(width: 8, height: 8)
                        Text(summary.pill).font(.system(size: 12)).foregroundStyle(theme.text).lineLimit(1)
                            .truncationMode(.tail)
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, 12).padding(.vertical, 8)
                    .glassField()
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help(SyncStatusSummary.title)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(summary.pill). \(SyncStatusSummary.dotDescription(summary.dot))")
                .accessibilityHint("Shows the sync status of each device")
                .accessibilityAddTraits(.isButton)
            }
        }
    }
}

/// The Sync status sheet: this Mac, then each device with its route and last-synced time, warnings, Sync now and
/// Open sync settings.
struct MacSyncStatusSheet: View {
    let coordinator: SyncCoordinator
    let onOpenSettings: () -> Void
    let onClose: () -> Void
    @Environment(\.macTheme) private var theme

    var body: some View {
        TimelineView(.periodic(from: .now, by: 30)) { context in
            let now = Int64(context.date.timeIntervalSince1970)
            VStack(alignment: .leading, spacing: 14) {
                Text(SyncStatusSummary.title).font(.title2.weight(.semibold)).foregroundStyle(theme.text)
                if let summary = coordinator.statusSummary(now: now) {
                    HStack(spacing: 12) {
                        Image(systemName: "laptopcomputer").font(.system(size: 18)).frame(width: 26).foregroundStyle(theme.accent)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(SyncStatusSummary.thisDevice).font(.system(size: 13.5, weight: .semibold)).foregroundStyle(theme.text)
                            Text(summary.pill).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                        }
                        Spacer()
                        Circle().fill(summary.dot.color(theme)).frame(width: 10, height: 10)
                            .accessibilityLabel(SyncStatusSummary.dotDescription(summary.dot))
                    }
                    ForEach(summary.devices) { device in row(device, now: now) }
                    ForEach(coordinator.issues) { issue in
                        Text(issue.text).font(.system(size: 12))
                            .foregroundStyle(issue.severity == .error ? theme.danger : theme.textMuted)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } else {
                    Text("Sync is not set up on this Mac.").font(.system(size: 13)).foregroundStyle(theme.textMuted)
                }
                HStack {
                    Button(SyncStatusSummary.syncNow) { Task { await coordinator.sync(.manual) } }
                        .buttonStyle(PillButtonStyle(primary: true))
                        .disabled(coordinator.phase != .idle || !coordinator.membership.joined)
                    Button(SyncStatusSummary.openSettings, action: onOpenSettings).buttonStyle(PillButtonStyle(primary: false))
                    Spacer()
                    Button("Done", action: onClose).buttonStyle(PillButtonStyle(primary: false)).keyboardShortcut(.cancelAction)
                }
            }
            .padding(22)
            .frame(width: 460)
        }
    }

    private func row(_ device: SyncStatusSummary.Device, now: Int64) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: device.route == .folder ? "folder" : "wifi").font(.system(size: 16)).frame(width: 26)
                .foregroundStyle(theme.accent)
            VStack(alignment: .leading, spacing: 2) {
                Text(device.name).font(.system(size: 13.5, weight: .semibold)).foregroundStyle(theme.text)
                Text("\(device.route.label) · \(SyncStatusSummary.lastSyncedText(device.lastSynced, now: now))")
                    .font(.system(size: 12)).foregroundStyle(theme.textMuted)
                if let warning = device.warning {
                    Text(warning).font(.system(size: 12)).foregroundStyle(theme.warning)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}
