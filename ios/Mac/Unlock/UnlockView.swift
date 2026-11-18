import SwiftUI
import LGKCore

/// The lock screen: master password, Unlock, and Touch ID when it is turned on.
struct UnlockView: View {
    @Bindable var model: MacLockModel
    @Bindable var session: MacProfileSession
    @Environment(\.macTheme) private var theme
    @State private var password = ""
    @State private var recovering = false
    @FocusState private var focused: Bool

    var body: some View {
        LockPanel(title: String(localized: "LocalGateKeys is locked"), subtitle: String(localized: "Enter your master password to open your vault.")) {
            ProfileHeader(session: session)
            SecureField("Master password", text: $password)
                .glassField()
                .focused($focused)
                .onSubmit(submit)
                .disabled(model.isBusy)
            factorRows
            YubiKeyTouchBanner(prompt: model.yubiKeyPrompt)
            MessageLine(text: model.message)
            Button(action: submit) {
                if model.isBusy { ProgressView().controlSize(.small).tint(theme.onAccent) } else { Text("Unlock") }
            }
            .buttonStyle(AccentButtonStyle())
            .keyboardShortcut(.defaultAction)
            .disabled(model.isBusy || password.isEmpty)
            if model.touchIDEnabled {
                Button { Task { await model.unlockWithTouchID() } } label: { Label("Use Touch ID", systemImage: "touchid") }
                    .buttonStyle(GlassButtonStyle())
                    .disabled(model.isBusy)
            }
            if model.hasRecoveryPhrase {
                Button("Forgot your master password?") { model.message = nil; recovering = true }
                    .buttonStyle(.link)
                    .frame(maxWidth: .infinity)
                    .disabled(model.isBusy)
            }
            LockScreenLinks(session: session)
        }
        .sheet(isPresented: $recovering) {
            RecoverWithPhraseSheet(model: model, onClose: { recovering = false }).macThemed()
        }
        .onAppear { focused = true }
        .onChange(of: session.active.id) { _, _ in password = ""; focused = true }
        .task { if model.takeLaunchTouchIDPrompt() { await model.unlockWithTouchID() } }
    }

    /// The key file (picked or remembered, "Remember this key file on this Mac") and the YubiKey this vault also needs.
    @ViewBuilder private var factorRows: some View {
        let specs = model.unlockFactorSpecs
        if specs.contains(where: { $0.kind == .keyFile }) {
            HStack(spacing: 8) {
                Image(systemName: "doc").foregroundStyle(theme.textMuted).accessibilityHidden(true)
                Text(model.keyFileName.map { MacFactors.keyFileChosen($0) } ?? MacFactors.noKeyFileChosen)
                    .font(.callout).foregroundStyle(theme.text).lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 8)
                Button(MacFactors.chooseKeyFileButton) { model.chooseKeyFile() }
                    .buttonStyle(GlassButtonStyle())
                    .disabled(model.isBusy)
            }
            Toggle(MacFactors.rememberOnThisMac, isOn: $model.rememberKeyFile)
                .toggleStyle(.checkbox).font(.callout)
                .disabled(model.isBusy)
        }
        if let spec = specs.first(where: { $0.kind == .yubiKeyHMAC }), model.yubiKeyPrompt.waitingSlot == nil {
            Label(MacFactors.yubiKeyNeeded(slot: spec.slot ?? MacFactors.defaultSlot), systemImage: "key")
                .font(.callout).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func submit() {
        guard !model.isBusy, !password.isEmpty else { return }
        let attempt = password
        Task {
            await model.unlock(password: attempt)
            password = ""
            focused = true
        }
    }
}

/// The centred glass panel shared by the lock and create screens.
struct LockPanel<Content: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder var content: Content
    @Environment(\.macTheme) private var theme

    var body: some View {
        ZStack {
            WashBackground()
            GlassPanel {
                VStack(alignment: .leading, spacing: MacTheme.gap) {
                    Image("BrandMark").resizable().aspectRatio(contentMode: .fit)
                        .frame(width: 56, height: 56).frame(maxWidth: .infinity)
                        .accessibilityHidden(true)
                    Text(title).font(.title2.weight(.semibold)).foregroundStyle(theme.text)
                        .frame(maxWidth: .infinity)
                    Text(subtitle).font(.callout).foregroundStyle(theme.textMuted)
                        .multilineTextAlignment(.center).frame(maxWidth: .infinity)
                    content
                }
                .padding(28)
                .frame(width: 380)
            }
        }
    }
}

/// The error line; keeps its height so the panel does not jump.
struct MessageLine: View {
    let text: String?
    @Environment(\.macTheme) private var theme
    var body: some View {
        Text(text ?? " ").font(.callout).foregroundStyle(theme.danger)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityHidden(text == nil)
    }
}
