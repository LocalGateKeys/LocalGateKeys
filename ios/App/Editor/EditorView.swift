import SwiftUI
import AppShared

struct EditorView: View {
    @State var model: EditorModel
    let pro: ProModel
    /// Called after a save or delete that changed the store.
    let onDone: (SaveResult) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var generatorFor: String?
    @State private var confirmDelete = false
    @State private var scanningTOTP = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ForEach(model.kind.fields) { field in fieldRow(field) }
                }
                .listRowBackground(Palette.groupSurface)
                if let error = model.error {
                    Section { Text(error).foregroundStyle(Palette.danger) }.listRowBackground(Palette.groupSurface)
                }
                if !model.isNew {
                    Section {
                        Button("Delete item", role: .destructive) { confirmDelete = true }
                    }
                    .listRowBackground(Palette.groupSurface)
                }
            }
            .scrollContentBackground(.hidden)
            .lgkAuroraBackground()
            .navigationTitle(model.isNew ? "New \(model.kind.label.lowercased())" : "Edit \(model.kind.label.lowercased())")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        let r = model.save()
                        if r == .saved || r == .unchanged { onDone(r); dismiss() }
                    }
                }
            }
            .confirmationDialog("Delete this item?", isPresented: $confirmDelete, titleVisibility: .visible) {
                Button("Delete", role: .destructive) {
                    if model.delete() == .saved { onDone(.saved); dismiss() }
                }
            } message: {
                Text("It is removed from this iPhone and from your other devices at the next sync.")
            }
            .alert(EditorModel.alreadyRemovedMessage,
                   isPresented: Binding(get: { model.alreadyRemoved }, set: { if !$0 { model.clearAlreadyRemoved() } })) {
                // The list reloads (the item is gone) and the sheet closes.
                Button("OK") { onDone(.saved); dismiss() }
            }
            .sheet(item: Binding(get: { generatorFor.map(GeneratorTarget.init) }, set: { generatorFor = $0?.key })) { target in
                GeneratorView { model.set(target.key, $0) }
            }
            .sheet(isPresented: $model.showUpgrade) { UpgradeView(pro: pro) }
            .sheet(isPresented: $scanningTOTP) {
                NavigationStack {
                    QRScanner(onCode: { code in scanningTOTP = false; model.scanTOTP(code) },
                              onUnavailable: { scanningTOTP = false; model.totpCameraUnavailable() })
                        .ignoresSafeArea()
                        .navigationTitle("Scan 2FA QR code")
                        .navigationBarTitleDisplayMode(.inline)
                        .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { scanningTOTP = false } } }
                }
            }
        }
    }

    @ViewBuilder
    private func fieldRow(_ field: EditorKind.Field) -> some View {
        let binding = Binding(get: { model.value(field.key) }, set: { model.set(field.key, $0) })
        switch field.control {
        case .toggle:
            Toggle(field.label, isOn: Binding(get: { model.value(field.key) == "true" },
                                              set: { model.set(field.key, $0 ? "true" : "false") }))
                .tint(Palette.accent)
        case .choice(let options):
            Picker(field.label, selection: binding) {
                ForEach(options, id: \.self) { Text(EditorKind.choiceLabel($0)).tag($0) }
            }
            .pickerStyle(.menu)
        case .date:
            VStack(alignment: .leading, spacing: 4) {
                OptionalDateField(label: field.label, text: binding)
            }
        case .text, .amount:
            textRow(field, binding)
        }
    }

    @ViewBuilder
    private func textRow(_ field: EditorKind.Field, _ binding: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(field.label).font(.caption).foregroundStyle(Palette.secondaryText)
            HStack {
                if field.multiline && field.secret {
                    SecretMultilineField(label: field.label, text: binding)
                } else if field.multiline {
                    TextField(field.label, text: binding, axis: .vertical).lineLimit(3...10)
                } else if field.secret {
                    SecretField(label: field.label, text: binding, keyboard: Self.keyboard(field.keyboard))
                } else {
                    TextField(field.label, text: binding).textContentType(VaultInputTraits.contentType(for: field))
                }
                if field.key == "password" {
                    Button { generatorFor = field.key } label: { Image(systemName: "wand.and.stars") }
                        .buttonStyle(.borderless).accessibilityLabel("Generate password")
                }
                if field.key == "totp" {
                    Button { scanningTOTP = true } label: { Image(systemName: "qrcode.viewfinder") }
                        .buttonStyle(.borderless).accessibilityLabel("Scan QR code")
                }
            }
            .textInputAutocapitalization(Self.capitalization(field.caps))
            .autocorrectionDisabled(field.caps != .sentences)
            .keyboardType(Self.keyboard(field.keyboard))
            if let hint = field.hint {
                Text(hint).font(.footnote).foregroundStyle(Palette.secondaryText)
            }
            if field.control == .amount, let amountError = model.amountError {
                Text(amountError).font(.footnote).foregroundStyle(Palette.danger)
            }
            if field.key == "url" && model.needsPunycode {
                Text("This address has non-ASCII letters. Type the domain in its xn-- form, for example https://xn--bcher-kva.example.")
                    .font(.footnote).foregroundStyle(Palette.warning)
            }
            if field.key == "totp", let totpError = model.totpError {
                Text(totpError).font(.footnote).foregroundStyle(Palette.danger)
            }
            if field.key == "totp" && model.totpNeedsPro && model.totpError == nil {
                Text(ProFeatures.totpMessage).font(.footnote).foregroundStyle(Palette.secondaryText)
            }
            if field.key == "origin", let websiteError = model.websiteError {
                Text(websiteError).font(.footnote).foregroundStyle(Palette.danger)
            }
            if field.key == "origin" && model.needsPunycode {
                Text("This address has non-ASCII letters. Type the domain as it appears in its xn-- form, for example https://xn--bcher-kva.example.")
                    .font(.footnote).foregroundStyle(Palette.warning)
            }
        }
    }

    static func keyboard(_ k: EditorKind.Keyboard) -> UIKeyboardType {
        switch k {
        case .text: .default
        case .url: .URL
        case .email: .emailAddress
        case .number: .numberPad
        case .phone: .phonePad
        case .decimal: .decimalPad
        }
    }

    static func capitalization(_ c: EditorKind.Caps) -> TextInputAutocapitalization {
        switch c {
        case .none: .never
        case .words: .words
        case .sentences: .sentences
        case .characters: .characters
        }
    }
}

/// Text content types for the vault's own fields. Nothing here may be `.username`, `.password` or
/// `.newPassword` (or email): iOS treats such fields as a login form and offers to save what was typed into
/// Apple Passwords. A `SecureField` with no type is still guessed to be a password, so secret fields are
/// tagged `.oneTimeCode`, which iOS never offers to save.
enum VaultInputTraits {
    static let secretContentType: UITextContentType = .oneTimeCode
    static let forbidden: Set<UITextContentType> = [.username, .password, .newPassword, .emailAddress]

    static func contentType(for field: EditorKind.Field) -> UITextContentType? {
        field.secret ? secretContentType : nil
    }
}

private struct GeneratorTarget: Identifiable { let key: String; var id: String { key } }

/// One edit to a secure field, applied by the app (UTF-16 ranges, as UIKit hands them over). `caret` is the
/// UTF-16 offset after the inserted text. An out-of-range edit changes nothing.
enum SecureEdit {
    static func apply(to text: String, range: NSRange, replacement: String) -> (text: String, caret: Int) {
        let ns = text as NSString
        guard range.location != NSNotFound, range.location >= 0, range.length >= 0,
              range.location + range.length <= ns.length else { return (text, min(max(range.location, 0), ns.length)) }
        let out = ns.replacingCharacters(in: range, with: replacement)
        return (out, range.location + (replacement as NSString).length)
    }
}

/// A secret field that keeps every secure-entry protection (`isSecureTextEntry`: the system keyboard only,
/// hidden from screenshots and recordings, VoiceOver does not read it) but never wipes the stored value when
/// someone types into it again: the delegate applies each edit itself and refuses UIKit's own.
struct SecureInputField: UIViewRepresentable {
    let placeholder: String
    @Binding var text: String
    var revealed: Bool
    var keyboard: UIKeyboardType = .default

    static func makeTextField(placeholder: String, keyboard: UIKeyboardType) -> UITextField {
        let tf = UITextField()
        tf.isSecureTextEntry = true
        tf.textContentType = VaultInputTraits.secretContentType
        tf.autocorrectionType = .no
        tf.spellCheckingType = .no
        tf.smartQuotesType = .no
        tf.smartDashesType = .no
        tf.smartInsertDeleteType = .no
        tf.autocapitalizationType = .none
        tf.clearsOnBeginEditing = false
        tf.keyboardType = keyboard
        tf.font = UIFont.monospacedSystemFont(ofSize: UIFont.preferredFont(forTextStyle: .body).pointSize, weight: .regular)
        tf.adjustsFontForContentSizeCategory = true
        tf.textColor = UIColor(Palette.text)
        tf.attributedPlaceholder = NSAttributedString(string: placeholder,
                                                      attributes: [.foregroundColor: UIColor(Palette.secondaryText)])
        tf.setContentHuggingPriority(.defaultLow, for: .horizontal)
        tf.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return tf
    }

    final class Coordinator: NSObject, UITextFieldDelegate {
        var text: () -> String
        var set: (String) -> Void
        init(text: @escaping () -> String, set: @escaping (String) -> Void) { self.text = text; self.set = set }

        /// Only a masked field, with no composition (marked text) in progress, needs its edits applied by hand:
        /// that is where UIKit would clear the value. A revealed field, or IME composition (Japanese, Korean,
        /// Chinese input), is left to UIKit, and `editingChanged` syncs the binding.
        nonisolated static func appliesEditItself(secure: Bool, composing: Bool) -> Bool { secure && !composing }

        func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange,
                       replacementString string: String) -> Bool {
            guard Self.appliesEditItself(secure: textField.isSecureTextEntry,
                                         composing: textField.markedTextRange != nil) else { return true }
            let edit = SecureEdit.apply(to: textField.text ?? text(), range: range, replacement: string)
            textField.text = edit.text
            if let pos = textField.position(from: textField.beginningOfDocument, offset: edit.caret) {
                textField.selectedTextRange = textField.textRange(from: pos, to: pos)
            }
            set(edit.text)
            // Applied here, so UIKit posts nothing: tell the idle-lock activity monitor about the typing.
            NotificationCenter.default.post(name: UITextField.textDidChangeNotification, object: textField)
            return false
        }

        /// UIKit applied the edit (revealed field or composition): copy it to the binding.
        @objc func editingChanged(_ textField: UITextField) {
            set(textField.text ?? "")
            NotificationCenter.default.post(name: UITextField.textDidChangeNotification, object: textField)
        }

        func textFieldShouldReturn(_ textField: UITextField) -> Bool { textField.resignFirstResponder(); return true }
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: { text }, set: { text = $0 }) }

    func makeUIView(context: Context) -> UITextField {
        let tf = Self.makeTextField(placeholder: placeholder, keyboard: keyboard)
        tf.delegate = context.coordinator
        tf.addTarget(context.coordinator, action: #selector(Coordinator.editingChanged(_:)), for: .editingChanged)
        tf.text = text
        tf.isSecureTextEntry = !revealed
        tf.accessibilityLabel = placeholder
        return tf
    }

    func updateUIView(_ tf: UITextField, context: Context) {
        context.coordinator.text = { text }
        context.coordinator.set = { text = $0 }
        if tf.text != text { tf.text = text }   // e.g. the generator filled it
        if tf.isSecureTextEntry == revealed {
            tf.isSecureTextEntry = !revealed
            // Toggling secure entry drops the text's rendering on some iOS versions: set it again.
            let current = tf.text; tf.text = nil; tf.text = current
        }
        if tf.keyboardType != keyboard { tf.keyboardType = keyboard }
    }
}

struct SecretField: View {
    let label: String
    @Binding var text: String
    var keyboard: UIKeyboardType = .default
    @State private var revealed = false

    var body: some View {
        // Masked again, and not revealable, while the screen is recorded or mirrored (audit 2026-10-24 L-8).
        let captured = ScreenCaptureMonitor.shared.isCaptured
        HStack {
            SecureInputField(placeholder: label, text: $text, revealed: revealed && !captured, keyboard: keyboard)
                .frame(minHeight: 22)
            Button { revealed.toggle() } label: { Image(systemName: revealed ? "eye.slash" : "eye") }
                .buttonStyle(.borderless).accessibilityLabel(revealed ? "Hide" : "Reveal")
                .disabled(captured)
        }
        .onChange(of: captured) { _, now in if now { revealed = false } }
    }
}

/// Picks the kind of a new item.
struct NewItemMenu<MenuLabel: View>: View {
    let onPick: (EditorKind) -> Void
    @ViewBuilder let label: () -> MenuLabel
    var body: some View {
        Menu {
            ForEach(Array(EditorKind.menuSections.enumerated()), id: \.offset) { _, section in
                Section {
                    ForEach(section) { k in
                        Button { onPick(k) } label: { Label(k.label, systemImage: VaultRow.icon(k.rawValue)) }
                    }
                }
            }
        } label: { label() }
    }
}

/// A multi-line secret (an SSH private key): masked until revealed, then edited as plain text. A secure
/// `UITextField` is single-line and would mangle a pasted PEM block.
struct SecretMultilineField: View {
    let label: String
    @Binding var text: String
    @State private var revealed = false

    var body: some View {
        // Masked again, and not revealable, while the screen is recorded or mirrored (audit 2026-10-24 L-8).
        let captured = ScreenCaptureMonitor.shared.isCaptured
        HStack(alignment: .top) {
            if revealed && !captured {
                TextField(label, text: $text, axis: .vertical).lineLimit(3...12)
                    .font(.system(.footnote, design: .monospaced))
            } else {
                Text(text.isEmpty ? "Empty. Tap the eye to paste or type it." : "•••••••• (\(text.split(whereSeparator: \.isNewline).count) lines)")
                    .foregroundStyle(Palette.secondaryText)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            Button { revealed.toggle() } label: { Image(systemName: revealed ? "eye.slash" : "eye") }
                .buttonStyle(.borderless).accessibilityLabel(revealed ? "Hide" : "Reveal")
                .disabled(captured)
        }
        .onChange(of: captured) { _, now in if now { revealed = false } }
    }
}

/// An optional ISO date (`YYYY-MM-DD`): "Add" sets today, the picker changes it, the x clears it. A stored
/// value in another ISO form (a week date from the desktop, say) stays editable as text.
struct OptionalDateField: View {
    let label: String
    @Binding var text: String

    static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.calendar = Calendar(identifier: .gregorian)
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    var body: some View {
        if text.isEmpty {
            HStack {
                Text(label)
                Spacer()
                Button("Add") { text = Self.formatter.string(from: Date()) }.buttonStyle(.borderless)
            }
        } else if let date = Self.formatter.date(from: text), Self.formatter.string(from: date) == text {
            HStack {
                DatePicker(label, selection: Binding(get: { date }, set: { text = Self.formatter.string(from: $0) }),
                           displayedComponents: .date)
                    .environment(\.timeZone, TimeZone(identifier: "UTC")!)
                Button { text = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(Palette.secondaryText) }
                    .buttonStyle(.borderless).accessibilityLabel("Clear \(label.lowercased())")
            }
        } else {
            VStack(alignment: .leading, spacing: 4) {
                Text(label).font(.caption).foregroundStyle(Palette.secondaryText)
                TextField("YYYY-MM-DD", text: $text).keyboardType(.numbersAndPunctuation)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
            }
        }
    }
}
