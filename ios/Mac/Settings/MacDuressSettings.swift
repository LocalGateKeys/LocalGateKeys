import SwiftUI
import AppSharedMac

/// Settings › Duress password (sub-plan 08): what the page needs from the lock model.
@MainActor
protocol DuressService: AnyObject {
    /// The hours a duress unlock holds the vault for; nil shows "Not set up." (always inside the second session).
    var duressStatusHours: Int? { get }
    func setUpDuress(masterPassword: String, duressPassword: String, confirm: String, hours: Int, isPro: Bool) async throws
    func removeDuress() throws
}

/// The Mac's duress wording: the master password where the iPhone says app password (Windows `duress.*`).
enum MacDuressText {
    static let title = DuressText.section
    static let note = String(localized: "A second master password for when someone forces you to unlock. It opens a separate vault with a few sample items. After it is used, this vault refuses its master password, Touch ID and the recovery phrase for the hours you choose.")
    static let current = String(localized: "Master password")
    static let hoursLabel = String(localized: "Hours to refuse the master password")
    static let generic = DuressText.generic

    static func statusOn(hours: Int) -> String {
        String(localized: "Set up. After the duress password is used, your vault refuses its master password for \(hours) hours.")
    }

    static func setUpDone(hours: Int) -> String {
        String(localized: "Duress password set up. After it is used, your vault refuses its master password for \(hours) hours.")
    }

    static func describe(_ e: DuressError) -> String {
        switch e.code {
        case "same": String(localized: "The duress password must be different from your master password.")
        case "close": String(localized: "The duress password is too close to your master password. Change more than one character.")
        case "near_duress": String(localized: "This master password is too close to your duress password. Choose one that differs in more than one character.")
        case "current": String(localized: "Enter your current master password.")
        default: DuressText.message(e)   // mismatch, hours, exists, pro, unavailable, generic
        }
    }
}

/// The Duress password card's one row: status, Set up or Remove. Its own section, apart from Unlocking.
struct MacDuressSection: View {
    let service: any DuressService
    let pro: ProModel
    @Environment(\.macTheme) private var theme
    @State private var settingUp = false
    @State private var confirmingRemove = false
    @State private var message: String?

    static var terms: SettingsRowText { SettingsRowText(title: MacDuressText.title, detail: MacDuressText.note) }

    private var status: String {
        service.duressStatusHours.map(MacDuressText.statusOn(hours:)) ?? DuressText.statusOff
    }

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(MacDuressText.title).font(.system(size: 13)).foregroundStyle(theme.text)
                Text(MacDuressText.note).font(.system(size: 11)).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                Text(status).font(.system(size: 11, weight: .medium)).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                if let message {
                    Text(message).font(.system(size: 11)).foregroundStyle(theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            if service.duressStatusHours == nil {
                Button(DuressText.setUp) { message = nil; settingUp = true }
                    .buttonStyle(PillButtonStyle(primary: false))
            } else {
                Button(String(localized: "Remove…")) { message = nil; confirmingRemove = true }
                    .buttonStyle(PillButtonStyle(primary: false))
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .sheet(isPresented: $settingUp) {
            MacDuressSetupSheet(service: service, pro: pro) { done in message = done }
                .macThemed()
        }
        .alert(DuressText.removeTitle, isPresented: $confirmingRemove) {
            Button(DuressText.remove, role: .destructive) { remove() }
            Button(String(localized: "Cancel"), role: .cancel) {}
        } message: {
            Text(DuressText.removeText)
        }
    }

    private func remove() {
        do {
            try service.removeDuress()
            message = DuressText.removed
        } catch {
            message = MacLockModel.describe(error, now: Date()) ?? MacDuressText.generic
        }
    }
}

/// Set up: the master password, the duress password twice and the hours (iPhone `DuressSetupSheet`).
struct MacDuressSetupSheet: View {
    let service: any DuressService
    let pro: ProModel
    let onDone: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @Environment(\.macTheme) private var theme
    @State private var current = ""
    @State private var password = ""
    @State private var confirm = ""
    @State private var hours = PhoneDuress.defaultHours
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(MacDuressText.title).font(.system(size: 15, weight: .semibold)).foregroundStyle(theme.text)
            Text(MacDuressText.note).font(.system(size: 11)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            SecureField(MacDuressText.current, text: $current)
            SecureField(DuressText.password, text: $password)
            SecureField(DuressText.confirm, text: $confirm)
            Picker(MacDuressText.hoursLabel, selection: $hours) {
                ForEach(PhoneDuress.hourChoices, id: \.self) { Text("\($0)").tag($0) }
            }
            if let error {
                Text(error).font(.system(size: 11)).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button(String(localized: "Cancel")) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .buttonStyle(PillButtonStyle(primary: false))
                Button(DuressText.setUp) { Task { await setUp() } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(PillButtonStyle(primary: true))
                    .disabled(current.isEmpty || password.isEmpty || confirm.isEmpty)
            }
        }
        .disabled(busy)
        .padding(20)
        .frame(width: 420)
    }

    private func setUp() async {
        guard !busy else { return }
        busy = true; error = nil
        defer { busy = false }
        do {
            try await service.setUpDuress(masterPassword: current, duressPassword: password, confirm: confirm,
                                          hours: hours, isPro: pro.isPro)
            current = ""; password = ""; confirm = ""
            onDone(MacDuressText.setUpDone(hours: hours))
            dismiss()
        } catch is CancellationError {
            dismiss()
        } catch {
            self.error = MacLockModel.describe(error, now: Date()) ?? MacDuressText.generic
        }
    }
}
