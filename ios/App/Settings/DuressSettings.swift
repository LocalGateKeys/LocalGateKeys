import SwiftUI
import AppShared

/// Settings › Duress password (sub-plan 08, Task 5c; Android `DuressScreens`). Pro and the app password are needed.
/// Inside a duress session it looks not set up, and setting it up there ends with the plain "couldn't save".
struct DuressSection: View {
    let lock: AppLockModel
    let pro: ProModel
    @State private var status: (on: Bool, hours: Int) = (false, PhoneDuress.defaultHours)
    @State private var settingUp = false
    @State private var removing = false
    @State private var message: String?
    @State private var busy = false

    private var controller: AppPasswordController? {
        guard let store = AppPasswordStore.shared(), let kc = lock.keychain else { return nil }
        return AppPasswordController(store: store, keychain: kc, factors: lock.factors, secondSession: lock.secondSession)
    }

    private var appPasswordOn: Bool { AppPasswordStore.shared()?.isOn ?? false }

    private var footer: String {
        if let message { return message }
        if !pro.isPro { return DuressText.proOnly }
        if !appPasswordOn { return DuressText.needsAppPassword }
        return status.on ? DuressText.statusOn(hours: status.hours) : DuressText.statusOff
    }

    var body: some View {
        Section {
            Text(DuressText.note).font(.footnote).foregroundStyle(Palette.secondaryText)
            if status.on {
                Button(DuressText.remove, role: .destructive) { removing = true }
                    .foregroundStyle(Palette.danger).disabled(busy)
            } else {
                Button(DuressText.setUp) { message = nil; settingUp = true }
                    .foregroundStyle(Palette.accentText)
                    .disabled(busy || !pro.isPro || !appPasswordOn)
            }
        } header: {
            Text(DuressText.section)
        } footer: {
            Text(footer)
        }
        .listRowBackground(Palette.groupSurface)
        .onAppear { reload() }
        .sheet(isPresented: $settingUp, onDismiss: reload) {
            DuressSetupSheet { current, password, confirm, hours in
                guard let controller, let store = lock.store else { return DuressText.generic }
                do {
                    try await controller.setUpDuress(current: current, password: password, confirm: confirm, hours: hours,
                                                     isPro: pro.isPro, real: try store.load())
                    return nil
                } catch let e as DuressError {
                    return DuressText.message(e)
                } catch {
                    return AppLockModel.message(for: error) ?? DuressText.generic
                }
            }
        }
        .alert(DuressText.removeTitle, isPresented: $removing) {
            Button(DuressText.remove, role: .destructive) { remove() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(DuressText.removeText)
        }
    }

    private func reload() { status = controller?.duressStatus() ?? (false, PhoneDuress.defaultHours) }

    private func remove() {
        busy = true
        defer { busy = false; reload() }
        do { try controller?.removeDuress(); message = DuressText.removed } catch let e as DuressError {
            message = DuressText.message(e)
        } catch { message = DuressText.generic }
    }
}

/// The current app password, the duress password twice and the hours. `submit` returns the problem, nil when done.
struct DuressSetupSheet: View {
    let submit: (String, String, String, Int) async -> String?
    @State private var current = ""
    @State private var password = ""
    @State private var confirm = ""
    @State private var hours = PhoneDuress.defaultHours
    @State private var problem: String?
    @State private var busy = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField(DuressText.current, text: $current).textContentType(.password)
                    SecureField(DuressText.password, text: $password).textContentType(.newPassword)
                    SecureField(DuressText.confirm, text: $confirm).textContentType(.newPassword)
                    Picker(DuressText.hoursLabel, selection: $hours) {
                        ForEach(PhoneDuress.hourChoices, id: \.self) { Text("\($0)").tag($0) }
                    }
                } footer: {
                    Text(problem ?? DuressText.note)
                }
                Button(DuressText.setUp) { run() }
                    .disabled(busy || current.isEmpty || password.isEmpty || confirm.isEmpty)
            }
            .navigationTitle(DuressText.section)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy) } }
        }
    }

    private func run() {
        let (c, p, f, h) = (current, password, confirm, hours)
        current = ""; password = ""; confirm = ""
        busy = true; problem = nil
        Task {
            let result = await submit(c, p, f, h)
            busy = false
            if let result { problem = result } else { dismiss() }
        }
    }
}
