import SwiftUI
import AppShared

/// Settings › Recently deleted: rows with days left, Restore, swipe to delete forever, Empty (confirmed), and
/// how long items are kept.
struct TrashView: View {
    let trash: PhoneTrash
    let pro: ProModel
    /// After a restore (the vault list reloads and a sync is scheduled).
    let onRestored: () -> Void
    @State private var confirmEmpty = false
    @State private var purgeRow: PhoneTrash.Row?
    @State private var message: String?
    @State private var showUpgrade = false
    @State private var retention = 30

    static let retentionChoices = [1, 7, 14, 30, 60, 90, 180, 365]

    var body: some View {
        List {
            Section {
                let rows = trash.rows
                if rows.isEmpty {
                    Text(PhoneTrash.emptyText).foregroundStyle(Palette.secondaryText)
                }
                ForEach(rows) { row in
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(row.title).foregroundStyle(Palette.text)
                            Text("\(row.detail) · \(Self.daysLeftText(trash.daysLeft(row)))")
                                .font(.subheadline).foregroundStyle(Palette.secondaryText)
                        }
                        Spacer()
                        Button("Restore") { restore(row) }
                            .buttonStyle(.bordered).tint(Palette.accent)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityAction(named: "Restore") { restore(row) }
                    .accessibilityAction(named: "Delete forever") { purgeRow = row }
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button("Delete forever", role: .destructive) { purgeRow = row }
                    }
                }
            } footer: {
                if let message { Text(message) } else if let load = (trash.local as? PhoneLocalData)?.loadMessage { Text(load) }
            }
            .listRowBackground(Palette.groupSurface)
            Section {
                Picker("Keep deleted items for", selection: $retention) {
                    ForEach(Self.retentionChoices, id: \.self) { Text(Self.daysText($0)).tag($0) }
                }
                .onChange(of: retention) { _, days in
                    do { try trash.setRetentionDays(days) } catch { message = PhoneTrash.saveFailedText }
                }
                Button("Empty Recently deleted", role: .destructive) { confirmEmpty = true }
                    .disabled(trash.rows.isEmpty)
            } footer: {
                Text("Deleted items stay encrypted on this iPhone and are removed for good after this time. They don't count toward the free plan's items. Older backups may still contain them.")
            }
            .listRowBackground(Palette.groupSurface)
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle(PhoneTrash.title)
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            trash.purgeExpired()
            let days = trash.retentionDays
            retention = Self.retentionChoices.contains(days) ? days : 30
        }
        // Alerts, not confirmation dialogs: iOS 26 drops a dialog's Cancel button on iPhone.
        .alert("Empty Recently deleted?", isPresented: $confirmEmpty) {
            Button("Delete forever", role: .destructive) {
                do { try trash.emptyAll(); message = nil } catch { message = PhoneTrash.saveFailedText }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Every item here is deleted for good. This cannot be undone.")
        }
        .alert("Delete forever?", isPresented: Binding(get: { purgeRow != nil }, set: { if !$0 { purgeRow = nil } })) {
            Button("Delete forever", role: .destructive) {
                if let row = purgeRow {
                    do { try trash.purge([row.id]); message = nil } catch { message = PhoneTrash.saveFailedText }
                }
                purgeRow = nil
            }
            Button("Cancel", role: .cancel) { purgeRow = nil }
        } message: {
            Text("\u{2018}\(purgeRow?.title ?? "")\u{2019} is deleted for good. This cannot be undone.")
        }
        .sheet(isPresented: $showUpgrade) { UpgradeView(pro: pro) }
    }

    private func restore(_ row: PhoneTrash.Row) {
        switch trash.restore(row.id, isPro: pro.isPro) {
        case .restored: message = nil; onRestored(); CopyToast.shared.show(String(localized: "Item restored"))
        case .limit: showUpgrade = true
        case .failed(let why): message = why
        }
    }

    nonisolated static func daysLeftText(_ days: Int) -> String {
        switch days {
        case 0: String(localized: "removed soon")
        default: String(localized: "\(days) days left")
        }
    }

    nonisolated static func daysText(_ days: Int) -> String { String(localized: "\(days) days") }
}
