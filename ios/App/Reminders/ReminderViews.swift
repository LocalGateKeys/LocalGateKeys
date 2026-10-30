import SwiftUI
import AppShared

private struct PhoneRemindersKey: EnvironmentKey {
    static let defaultValue: PhoneReminders? = nil
}

extension EnvironmentValues {
    /// Expiry reminders while unlocked (nil: hidden).
    var phoneReminders: PhoneReminders? {
        get { self[PhoneRemindersKey.self] }
        set { self[PhoneRemindersKey.self] = newValue }
    }
}

/// The item detail's Reminder section (typed items only): the active reminder, or Add (a card suggests its
/// expiry month).
struct ItemReminderSection: View {
    let reminders: PhoneReminders
    let item: VaultItem
    @State private var editing = false

    var body: some View {
        if PhoneReminders.canHaveReminder(item) {
            Section {
                if let r = reminders.reminder(for: item.id) {
                    LabeledContent("Due", value: ReminderText.date(r.dueDate))
                    if r.leadDays > 0 { LabeledContent("Remind me", value: ReminderText.lead(r.leadDays)) }
                    Button("Change reminder") { editing = true }.foregroundStyle(Palette.accentText)
                    Button("Remove reminder", role: .destructive) { reminders.delete(r.id) }
                } else if let suggested = reminders.suggestion(for: item) {
                    Text("This card expires \(ReminderText.date(suggested)).").foregroundStyle(Palette.secondaryText)
                    Button("Remind me before it expires") { editing = true }.foregroundStyle(Palette.accentText)
                } else {
                    Button("Add reminder") { editing = true }.foregroundStyle(Palette.accentText)
                }
                if let message = reminders.message { Text(message).font(.footnote).foregroundStyle(Palette.danger) }
            } header: {
                Text("Reminder")
            }
            .listRowBackground(Palette.groupSurface)
            .sheet(isPresented: $editing) { ReminderEditor(reminders: reminders, item: item) }
        }
    }
}

/// Due date and how many days before to be reminded.
struct ReminderEditor: View {
    let reminders: PhoneReminders
    let item: VaultItem
    @State private var due = Date()
    @State private var lead = 0
    @State private var failed = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    DatePicker("Due date", selection: $due, displayedComponents: .date)
                    Picker("Remind me", selection: $lead) {
                        ForEach(PhoneReminders.leadChoices, id: \.self) { Text(ReminderText.lead($0)).tag($0) }
                    }
                } footer: {
                    Text("A notification comes at 9:00 on the day. It says only \u{201C}A reminder is due\u{201D} unless Settings › Reminders shows item names. Reminders stay on this iPhone and never sync.")
                }
                .listRowBackground(Palette.groupSurface)
                if failed {
                    Text(PhoneReminders.saveFailedText).foregroundStyle(Palette.danger).listRowBackground(Palette.groupSurface)
                }
            }
            .scrollContentBackground(.hidden)
            .lgkAuroraBackground()
            .navigationTitle(item.title.isEmpty ? item.kindLabel : item.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        do {
                            try reminders.set(itemID: item.id, dueDate: ReminderDays.day(due), leadDays: lead)
                            dismiss()
                        } catch { failed = true }
                    }
                }
            }
            .onAppear {
                if let r = reminders.reminder(for: item.id) {
                    due = ReminderText.localDate(r.dueDate) ?? Date(); lead = r.leadDays
                } else if let s = reminders.suggestion(for: item) {
                    due = ReminderText.localDate(s) ?? Date(); lead = 30
                }
            }
        }
    }
}

/// The Security tab's Upcoming section: overdue and the next 30 days, swipe for Done or Snooze.
struct UpcomingRemindersSection: View {
    let reminders: PhoneReminders

    var body: some View {
        let rows = reminders.rows(within: 30)
        Section {
            if rows.isEmpty {
                Text("Nothing coming up in the next 30 days.").foregroundStyle(Palette.secondaryText)
            }
            ForEach(rows) { row in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(row.title).foregroundStyle(Palette.text)
                        Text(row.overdue ? String(localized: "Overdue · due \(ReminderText.date(row.due))") : String(localized: "Due \(ReminderText.date(row.due))"))
                            .font(.subheadline).foregroundStyle(row.overdue ? Palette.danger : Palette.secondaryText)
                    }
                    Spacer()
                }
                .accessibilityElement(children: .combine)
                .accessibilityAction(named: "Done") { reminders.complete(row.id) }
                .accessibilityAction(named: "Snooze one day") { reminders.snooze(row.id) }
                .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                    Button("Done") { reminders.complete(row.id) }.tint(Palette.success)
                    Button("Snooze") { reminders.snooze(row.id) }.tint(Palette.warning)
                }
            }
            if reminders.notificationsDenied {
                Text("Notifications are off for LocalGateKeys. Reminders still show here.")
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
            }
        } header: {
            Text("Upcoming")
        }
        .listRowBackground(Palette.groupSurface)
        .task { await reminders.refreshPermission() }
    }
}

enum ReminderText {
    static func lead(_ days: Int) -> String {
        switch days {
        case 0: String(localized: "On the day")
        default: String(localized: "\(days) days before")
        }
    }

    /// "YYYY-MM-DD" as a local calendar date (noon, so no time zone moves it to another day).
    static func localDate(_ day: String) -> Date? {
        let p = day.split(separator: "-").compactMap { Int($0) }
        guard p.count == 3 else { return nil }
        return Calendar.current.date(from: DateComponents(year: p[0], month: p[1], day: p[2], hour: 12))
    }

    static func date(_ day: String) -> String {
        localDate(day)?.formatted(date: .abbreviated, time: .omitted) ?? day
    }
}
