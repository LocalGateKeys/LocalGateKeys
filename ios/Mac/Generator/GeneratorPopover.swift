import SwiftUI
import AppSharedMac

/// The password generator: from the password field (a popover with Use) and from the sidebar's Generator
/// entry (copy only). Options are the desktop's and are remembered as the new defaults.
struct GeneratorPopover: View {
    var onUse: (@MainActor (String) -> Void)?
    var onClose: (() -> Void)?
    @State private var model = GeneratorModel()
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Password generator").font(.system(size: 15, weight: .semibold))
            valueCard
            HStack(spacing: 8) {
                Button("Regenerate") { model.regenerate() }.buttonStyle(PillButtonStyle(primary: false))
                Button(model.copied ? String(localized: "Copied") : String(localized: "Copy")) { model.copy() }
                    .buttonStyle(PillButtonStyle(primary: onUse == nil)).disabled(model.value.isEmpty)
                if let onUse {
                    Spacer(minLength: 0)
                    Button("Use password") { model.use(dismiss: { onClose?() }, deliver: { onUse($0) }) }
                        .buttonStyle(PillButtonStyle(primary: true)).disabled(!model.canUse)
                }
            }
            Picker("Type", selection: $model.options.mode) {
                Text("Password").tag(GeneratorOptions.Mode.password)
                Text("Passphrase").tag(GeneratorOptions.Mode.passphrase)
            }
            .pickerStyle(.segmented).labelsHidden()
            if model.options.mode == .password { passwordOptions } else { passphraseOptions }
        }
        .padding(16)
        .frame(width: 360, alignment: .leading)
        .foregroundStyle(theme.text)
        .font(.system(size: 13))
        .onAppear { model.start() }
    }

    private var valueCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(model.value.isEmpty ? (model.error ?? " ") : model.value)
                .font(.system(size: 15, design: .monospaced))
                .foregroundStyle(model.value.isEmpty ? theme.danger : theme.text)
                .textSelection(.enabled)
                .lineLimit(3).fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: 4) {
                ForEach(0..<4, id: \.self) { i in
                    Capsule().fill(i < model.strength.segments ? strengthColour : theme.line).frame(height: 4)
                }
                Text(model.strength.label).font(.system(size: 12)).foregroundStyle(theme.textMuted).padding(.leading, 6)
            }
        }
        .padding(12)
        .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
    }

    private var strengthColour: Color {
        switch model.strength {
        case .weak: theme.danger
        case .fair: theme.warning
        case .strong, .veryStrong: theme.live
        }
    }

    private var passwordOptions: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Length")
                Slider(value: Binding(get: { Double(model.options.length) }, set: { model.options.length = Int($0.rounded()) }),
                       in: 8...64, step: 1)
                Text("\(model.options.length)").monospacedDigit().frame(width: 28, alignment: .trailing)
            }
            Toggle("Lowercase (a–z)", isOn: $model.options.lowercase)
            Toggle("Uppercase (A–Z)", isOn: $model.options.uppercase)
            Toggle("Digits (0–9)", isOn: $model.options.digits)
            Toggle("Symbols", isOn: $model.options.symbols)
            Toggle("Avoid look-alike characters", isOn: $model.options.avoidAmbiguous)
        }
        .toggleStyle(.checkbox)
    }

    private var passphraseOptions: some View {
        VStack(alignment: .leading, spacing: 8) {
            Stepper("Words: \(model.options.words)", value: $model.options.words, in: 3...16)
            Picker("Separator", selection: $model.options.separator) {
                Text("Dash").tag("-"); Text("Space").tag(" "); Text("Dot").tag("."); Text("Underscore").tag("_"); Text("None").tag("")
            }
            .fixedSize()
            Toggle("Capitalise words", isOn: $model.options.capitalize)
            Toggle("Add a number", isOn: $model.options.appendNumber)
        }
        .toggleStyle(.checkbox)
    }
}
