import SwiftUI
import LGKCore
import AppSharedMac

/// The sidebar's Reminders (Windows `WorkspacePages.svelte`, kind "reminders"): safe titles, due dates and
/// states; select a row for Snooze 1 day or Complete.
struct RemindersView: View {
    @Bindable var model: RemindersModel
    @Environment(\.macTheme) private var theme

    var body: some View {
        let rows = model.rows
        VStack(alignment: .leading, spacing: 10) {
            Text(RemindersModel.title).font(.system(size: 19, weight: .semibold))
            Text(RemindersModel.subtitle).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            if let message = model.message {
                Text(message).font(.system(size: 12.5)).foregroundStyle(theme.danger)
            }
            if rows.isEmpty {
                Text(RemindersModel.emptyText).foregroundStyle(theme.textMuted)
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
                .accessibilityLabel("Reminders")
            }
            HStack(spacing: 8) {
                Spacer()
                Button("Snooze 1 day") { if let id = model.picked { model.snooze(id) } }
                    .buttonStyle(PillButtonStyle(primary: false))
                    .disabled(model.picked == nil)
                Button("Complete") { if let id = model.picked { model.complete(id) } }
                    .buttonStyle(PillButtonStyle(primary: true))
                    .disabled(model.picked == nil)
            }
        }
        .foregroundStyle(theme.text)
        .padding(18)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear { model.prune() }
    }

    private func rowView(_ row: RemindersModel.Row) -> some View {
        let on = model.picked == row.id
        return HStack(spacing: 10) {
            Text(row.title).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
            Text(row.due).font(.system(size: 12.5).monospacedDigit()).foregroundStyle(theme.textMuted)
            Text(Self.statusText(row.status)).font(.system(size: 11.5, weight: .medium))
                .padding(.horizontal, 8).padding(.vertical, 2)
                .background(theme.line, in: Capsule())
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
        .background(on ? theme.line.opacity(0.7) : Color.clear)
        .contentShape(Rectangle())
        .onTapGesture { model.picked = row.id }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(on ? [.isButton, .isSelected] : .isButton)
    }
}

/// The detail panel's Reminder section for typed items: the active reminder with Complete, Snooze and Delete,
/// or "Add reminder" with a date and lead days.
struct ReminderSection: View {
    let item: VaultItem
    @Bindable var model: RemindersModel
    @State private var adding = false
    @State private var date = Date()
    @State private var leadDays = 0
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Reminder").font(.system(size: 12)).foregroundStyle(theme.textFaint)
                .padding(.top, 14).padding(.bottom, 4).accessibilityAddTraits(.isHeader)
            if let r = model.reminder(for: item.id) {
                HStack(spacing: 10) {
                    Text(Self.summary(r)).frame(maxWidth: .infinity, alignment: .leading)
                    Button("Complete") { model.complete(r.id) }.buttonStyle(.plain).foregroundStyle(theme.link)
                    Button("Snooze") { model.snooze(r.id) }.buttonStyle(.plain).foregroundStyle(theme.link)
                        .help("Snooze 1 day")
                    Button("Delete") { model.delete(r.id) }.buttonStyle(.plain).foregroundStyle(theme.danger)
                }
                .padding(.vertical, 6)
            } else if adding {
                HStack(spacing: 10) {
                    DatePicker("Due", selection: $date, displayedComponents: .date).fixedSize()
                    Stepper("Remind \(Self.leadText(leadDays))", value: $leadDays, in: 0...3650).fixedSize()
                    Spacer()
                    Button("Cancel") { adding = false }.buttonStyle(PillButtonStyle(primary: false))
                    Button("Add") {
                        if (try? model.add(itemID: item.id, dueDate: OverviewModel.day(date), leadDays: leadDays)) != nil { adding = false }
                    }
                    .buttonStyle(PillButtonStyle(primary: true))
                }
                .padding(.vertical, 6)
            } else {
                Button("Add reminder") { leadDays = model.defaultLeadDays; date = Date(); adding = true }
                    .buttonStyle(.plain).foregroundStyle(theme.link).padding(.vertical, 6)
            }
            if model.notificationsDenied {
                Text(RemindersModel.notificationsOffText).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
            }
            if let message = model.message {
                Text(message).font(.system(size: 12.5)).foregroundStyle(theme.danger)
            }
        }
        .task { await model.refreshPermission() }
    }

    /// The stored status ("pending", "snoozed", "dismissed") as shown.
    static func statusText(_ status: String) -> String {
        switch status {
        case "pending": String(localized: "pending")
        case "snoozed": String(localized: "snoozed")
        case "dismissed": String(localized: "dismissed")
        default: status
        }
    }

    /// "on the due date" / "1 day before" / "3 days before".
    static func leadText(_ days: Int) -> String {
        days == 0 ? String(localized: "on the due date") : days == 1 ? String(localized: "1 day before") : String(localized: "\(days) days before")
    }

    /// "Due 2026-11-30 · 3 days before" (snoozed: "· snoozed until …").
    static func summary(_ r: LocalData.Reminder) -> String {
        var s = String(localized: "Due \(r.dueDate)")
        if r.leadDays > 0 { s += String(localized: " · \(leadText(r.leadDays))") }
        if r.status == .snoozed, !r.snoozeUntil.isEmpty { s += String(localized: " · snoozed until \(r.snoozeUntil)") }
        return s
    }
}
