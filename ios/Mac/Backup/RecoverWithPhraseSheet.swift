import SwiftUI
import AppSharedMac

/// The lock screen's "Forgot your master password?": the 24-word recovery phrase and a new master password. A wrong
/// phrase counts against the same throttle as passwords; recovering turns Touch ID off (Ruling 9).
struct RecoverWithPhraseSheet: View {
    static let intro = String(localized: "Enter your 24-word recovery phrase and choose a new master password. Touch ID is turned off until you turn it on again in Settings.")

    @Bindable var model: MacLockModel
    let onClose: () -> Void
    @Environment(\.macTheme) private var theme
    @State private var phrase = ""
    @State private var new = ""
    @State private var confirm = ""

    var body: some View {
        VStack(alignment: .leading, spacing: MacTheme.gap) {
            Text("Recover with your recovery phrase").font(.title3.weight(.semibold)).foregroundStyle(theme.text)
            Text(Self.intro).font(.callout).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            TextEditor(text: $phrase)
                .font(.body.monospaced())
                .autocorrectionDisabled()
                .scrollContentBackground(.hidden)
                .frame(height: 90)
                .padding(6)
                .background(RoundedRectangle(cornerRadius: 8).stroke(theme.panelBorder))
                .privacySensitive()
                .accessibilityLabel("Recovery phrase")
            SecureField("New master password", text: $new).glassField()
            SecureField("Repeat new master password", text: $confirm).glassField().onSubmit(submit)
            MessageLine(text: model.message)
            HStack {
                Button("Cancel", action: close).buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button(action: submit) {
                    if model.isBusy { ProgressView().controlSize(.small) } else { Text("Recover") }
                }
                .buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(model.isBusy || phrase.isEmpty || new.isEmpty || confirm.isEmpty)
            }
        }
        .disabled(model.isBusy)
        .padding(24).frame(width: 440)
        .background(WashBackground())
        .onAppear { model.message = nil }
        .onDisappear { phrase = ""; new = ""; confirm = "" }
    }

    private func submit() {
        guard !model.isBusy, !phrase.isEmpty, !new.isEmpty else { return }
        let (typed, password, repeated) = (phrase, new, confirm)
        Task {
            if await model.recover(phrase: typed, newPassword: password, confirm: repeated) {
                phrase = ""; new = ""; confirm = ""
                onClose()
            } else {
                new = ""; confirm = ""
            }
        }
    }

    private func close() {
        phrase = ""; new = ""; confirm = ""
        model.message = nil
        onClose()
    }
}
