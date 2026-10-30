import SwiftUI
import AppSharedMac

/// The master password field and an optional Touch ID button, on the aurora with glass controls. Used for
/// the unlock and, with `touchID: false`, for a strict login's master password prompt.
struct AutoFillPasswordPrompt: View {
    let title: String
    let detail: String
    let touchID: Bool
    let message: String?
    let busy: Bool
    let onTouchID: () -> Void
    let onSubmit: (String) -> Void
    let onCancel: () -> Void
    @State private var password = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "lock.fill").font(.system(size: 30)).foregroundStyle(Palette.accent)
            Text(title).font(.title3.weight(.semibold)).foregroundStyle(Palette.text)
            Text(detail).font(.callout).foregroundStyle(Palette.secondaryText).multilineTextAlignment(.center)
            if touchID {
                Button(action: onTouchID) {
                    Label("Unlock with Touch ID", systemImage: "touchid").frame(maxWidth: .infinity).padding(.vertical, 6)
                }
                .buttonStyle(.plain).foregroundStyle(Palette.text)
                .padding(.horizontal, 12).lgkGlass(in: Capsule())
                .disabled(busy)
            }
            SecureField("Master password", text: $password)
                .textFieldStyle(.plain).padding(.horizontal, 12).padding(.vertical, 8)
                .lgkGlass(in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                .focused($focused)
                .onSubmit { submit() }
                .disabled(busy)
            if let message {
                Text(message).font(.callout).foregroundStyle(Palette.danger).multilineTextAlignment(.center)
            }
            HStack {
                Button("Cancel", role: .cancel, action: onCancel).keyboardShortcut(.cancelAction)
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button("Unlock") { submit() }.keyboardShortcut(.defaultAction).disabled(busy || password.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 360)
        .onAppear { focused = !touchID }
    }

    private func submit() {
        guard !password.isEmpty else { return }
        let p = password
        password = ""
        onSubmit(p)
    }
}

/// The extension's unlock: Touch ID (if the app stored the item) or the master password.
struct AutoFillUnlockView: View {
    let model: MacAutoFillModel

    var body: some View {
        AutoFillPasswordPrompt(
            title: String(localized: "Unlock LocalGateKeys"),
            detail: model.isOneTimeCode ? String(localized: "Unlock to fill a verification code.") : String(localized: "Unlock to fill a password."),
            touchID: model.touchIDAvailable, message: model.message, busy: model.busy,
            onTouchID: { Task { await model.unlockWithTouchID() } },
            onSubmit: { p in Task { await model.unlock(password: p) } },
            onCancel: { model.cancel() })
    }
}
