import SwiftUI
import AppShared

extension SyncStatusSummary.Dot {
    var color: Color {
        switch self {
        case .green: Palette.success
        case .orange: Palette.warning
        case .red: Palette.danger
        }
    }
}

/// The vault header's sync pill (UX plan workstream 6): "Synced 2 min ago · 3 devices" with a green, orange or red
/// dot. Hidden while this iPhone does not sync. The text refreshes every 30 s.
struct SyncStatusPill: View {
    let sync: SyncCoordinator
    let onTap: () -> Void

    var body: some View {
        TimelineView(.periodic(from: .now, by: 30)) { context in
            let now = Int64(context.date.timeIntervalSince1970)
            if let summary = sync.statusSummary(now: now) {
                Button(action: onTap) {
                    HStack(spacing: 8) {
                        Circle().fill(summary.dot.color).frame(width: 9, height: 9)
                        Text(summary.pill).font(.subheadline).foregroundStyle(Palette.text).lineLimit(1)
                            .minimumScaleFactor(0.8)
                    }
                    .padding(.horizontal, 14).frame(minHeight: 44)
                    .lgkGlass(in: Capsule())
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(summary.pill). \(SyncStatusSummary.dotDescription(summary.dot))")
                .accessibilityHint("Shows the sync status of each device")
                .accessibilityIdentifier("sync-status-pill")
            }
        }
    }
}

/// Tap on the pill: this iPhone, then each device with its route and last-synced time, warnings, Sync now and
/// Open sync settings.
struct SyncStatusSheet: View {
    let sync: SyncCoordinator
    let openSettings: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            TimelineView(.periodic(from: .now, by: 30)) { context in
                let now = Int64(context.date.timeIntervalSince1970)
                List {
                    if let summary = sync.statusSummary(now: now) {
                        Section {
                            HStack(spacing: 12) {
                                Image(systemName: "iphone").frame(width: 26).foregroundStyle(Palette.accentText)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(SyncStatusSummary.thisDevice).foregroundStyle(Palette.text)
                                    Text(summary.pill).font(.footnote).foregroundStyle(Palette.secondaryText)
                                }
                                Spacer()
                                Circle().fill(summary.dot.color).frame(width: 10, height: 10)
                                    .accessibilityLabel(SyncStatusSummary.dotDescription(summary.dot))
                            }
                            .accessibilityElement(children: .combine)
                        }
                        .listRowBackground(Palette.groupSurface)
                        if !summary.devices.isEmpty {
                            Section("Devices") {
                                ForEach(summary.devices) { device in row(device, now: now) }
                            }
                            .listRowBackground(Palette.groupSurface)
                        }
                        if !sync.issues.isEmpty {
                            Section {
                                ForEach(sync.issues) { issue in
                                    Text(issue.text).font(.footnote)
                                        .foregroundStyle(issue.severity == .error ? Palette.danger : Palette.text)
                                }
                            }
                            .listRowBackground(Palette.groupSurface)
                        }
                    } else {
                        Text("Sync is not set up on this iPhone.").foregroundStyle(Palette.secondaryText)
                            .listRowBackground(Palette.groupSurface)
                    }
                    Section {
                        Button(SyncStatusSummary.syncNow) { Task { await sync.sync(.manual) } }
                            .disabled(sync.phase != .idle || !sync.membership.joined)
                            .foregroundStyle(Palette.accentText)
                        Button(SyncStatusSummary.openSettings) { dismiss(); openSettings() }
                            .foregroundStyle(Palette.accentText)
                    }
                    .listRowBackground(Palette.groupSurface)
                }
                .scrollContentBackground(.hidden)
            }
            .lgkAuroraBackground()
            .navigationTitle(SyncStatusSummary.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } } }
        }
    }

    private func row(_ device: SyncStatusSummary.Device, now: Int64) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: device.route == .folder ? "folder" : "wifi").frame(width: 26).foregroundStyle(Palette.accentText)
            VStack(alignment: .leading, spacing: 2) {
                Text(device.name).foregroundStyle(Palette.text)
                Text(device.route.label).font(.footnote).foregroundStyle(Palette.secondaryText)
                Text(SyncStatusSummary.lastSyncedText(device.lastSynced, now: now)).font(.footnote)
                    .foregroundStyle(Palette.secondaryText)
                if let warning = device.warning {
                    Text(warning).font(.footnote).foregroundStyle(Palette.warning)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}
