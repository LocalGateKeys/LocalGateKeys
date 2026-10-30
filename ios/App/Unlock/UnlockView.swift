import SwiftUI
import AppShared

struct UnlockView: View {
    let model: AppLockModel
    /// "Start fresh anyway": 0 none, 1 first confirmation, 2 second.
    @State private var freshStep = 0

    var body: some View {
        ZStack {
            AuroraBackground()
            VStack(spacing: 24) {
                Spacer()
                Image("BrandMark")
                    .resizable().interpolation(.high).aspectRatio(contentMode: .fit)
                    .frame(width: 96, height: 96)
                    .shadow(color: .black.opacity(0.25), radius: 16, y: 6)
                    .accessibilityHidden(true)
                Text("LocalGateKeys").font(.title.bold()).foregroundStyle(Palette.text)
                if let message = model.errorMessage {
                    Text(message).font(.callout).foregroundStyle(Palette.secondaryText)
                        .multilineTextAlignment(.center).padding(.horizontal, 32)
                }
                if model.offersStartFresh {
                    Button("Start fresh anyway", role: .destructive) { freshStep = 1 }
                        .disabled(model.state == .unlocking)
                }
                Spacer()
                if model.needsPassword {
                    AppPasswordUnlockPanel(model: model).padding(.horizontal, 32).padding(.bottom, 32)
                } else {
                    Button {
                        Task { await model.unlock() }
                    } label: {
                        Label("Unlock", systemImage: "faceid").frame(maxWidth: .infinity).padding(.vertical, 6)
                    }
                    .buttonStyle(.borderedProminent).tint(Palette.accent).foregroundStyle(Palette.onAccent)
                    .disabled(model.state == .unlocking)
                    .padding(.horizontal, 32).padding(.bottom, 48)
                }
            }
        }
        // Alerts, so Cancel stays visible on iOS 26 (tester feedback 1, as Erase).
        .alert(AppLockModel.startFreshConfirm1, isPresented: step(1)) {
            Button("Start fresh", role: .destructive) { freshStep = 2 }
            Button("Cancel", role: .cancel) { freshStep = 0 }
        }
        .alert(AppLockModel.startFreshConfirm2, isPresented: step(2)) {
            Button("Start fresh now", role: .destructive) {
                freshStep = 0
                Task { await model.startFreshAnyway() }
            }
            Button("Cancel", role: .cancel) { freshStep = 0 }
        }
    }

    private func step(_ n: Int) -> Binding<Bool> {
        Binding(get: { freshStep == n }, set: { if !$0, freshStep == n { freshStep = 0 } })
    }
}

/// Task 7: the password field, the Face ID shortcut and "Forgot app password?" (24 words + a new password).
/// The typed text lives only in this view's state and is cleared after each try.
struct AppPasswordUnlockPanel: View {
    let model: AppLockModel
    @State private var password = ""
    @State private var recovering = false
    @State private var phrase = ""
    @State private var newPassword = ""
    @State private var confirm = ""
    @State private var problem: String?

    var body: some View {
        VStack(spacing: 12) {
            if !recovering {
                SecureField("App password", text: $password)
                    .textContentType(.password).textFieldStyle(.roundedBorder)
                    .submitLabel(.go).onSubmit(submit)
                Button(action: submit) {
                    Text("Unlock").frame(maxWidth: .infinity).padding(.vertical, 6)
                }
                .buttonStyle(.borderedProminent).tint(Palette.accent).foregroundStyle(Palette.onAccent)
                .disabled(model.state == .unlocking || password.isEmpty)
                if model.biometricShortcut {
                    Button("Use Face ID") { Task { await model.unlock() } }
                        .disabled(model.state == .unlocking)
                }
                Button("Forgot app password?") { recovering = true }
            } else {
                Text("Type your 24-word recovery phrase, then choose a new app password.")
                    .font(.callout).foregroundStyle(Palette.secondaryText)
                TextField("Recovery phrase", text: $phrase, axis: .vertical)
                    .lineLimit(3...6).textInputAutocapitalization(.never).autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)
                SecureField("New app password", text: $newPassword).textContentType(.newPassword).textFieldStyle(.roundedBorder)
                SecureField("Confirm new app password", text: $confirm).textContentType(.newPassword).textFieldStyle(.roundedBorder)
                if let problem { Text(problem).font(.callout).foregroundStyle(Palette.danger) }
                Button {
                    if let p = AppPasswordRules.problem(newPassword, confirm: confirm) { problem = p; return }
                    let (ph, pw) = (phrase, newPassword)
                    phrase = ""; newPassword = ""; confirm = ""; problem = nil
                    Task { await model.recover(phrase: ph, newPassword: pw) }
                } label: {
                    Text("Unlock and set password").frame(maxWidth: .infinity).padding(.vertical, 6)
                }
                .buttonStyle(.borderedProminent).tint(Palette.accent).foregroundStyle(Palette.onAccent)
                .disabled(model.state == .unlocking || phrase.isEmpty || newPassword.isEmpty)
                Button("Back") { recovering = false; problem = nil }
            }
        }
    }

    private func submit() {
        guard !password.isEmpty, model.state != .unlocking else { return }
        let pw = password
        password = ""
        Task { await model.unlock(password: pw) }
    }
}
