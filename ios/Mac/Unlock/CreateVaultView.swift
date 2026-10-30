import SwiftUI

/// First run: choose the master password (twice) and optionally Touch ID.
struct CreateVaultView: View {
    @Bindable var model: MacLockModel
    let touchIDAvailable: Bool
    @Environment(\.macTheme) private var theme
    @State private var password = ""
    @State private var confirm = ""
    @State private var touchID = false

    var body: some View {
        LockPanel(title: String(localized: "Create your vault"), subtitle: String(localized: "Choose a master password. It opens your vault on this Mac.")) {
            SecureField("Master password", text: $password).glassField().disabled(model.isBusy)
            SecureField("Confirm master password", text: $confirm).glassField().disabled(model.isBusy)
                .onSubmit(submit)
            if touchIDAvailable {
                Toggle("Unlock with Touch ID", isOn: $touchID)
                    .toggleStyle(.switch).foregroundStyle(theme.text).disabled(model.isBusy)
            }
            Text("There is no way to reset this password. If you forget it, your vault cannot be opened, so keep it somewhere safe.")
                .font(.caption).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            MessageLine(text: model.message)
            Button(action: submit) {
                if model.isBusy { ProgressView().controlSize(.small).tint(theme.onAccent) } else { Text("Create vault") }
            }
            .buttonStyle(AccentButtonStyle())
            .keyboardShortcut(.defaultAction)
            .disabled(model.isBusy || password.isEmpty || confirm.isEmpty)
        }
    }

    private func submit() {
        guard !model.isBusy, !password.isEmpty, !confirm.isEmpty else { return }
        let (p, c, t) = (password, confirm, touchID)
        Task { await model.create(password: p, confirm: c, touchID: t) }
    }
}
