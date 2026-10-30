import SwiftUI
import AppSharedMac

/// The login detail's Recovery codes, Custom fields and Password history sections (Windows detail panel).
/// Everything secret is masked until revealed through `LoginExtrasModel` (strict logins: master password
/// each time); copies go through `MacClipboard` concealed.
struct LoginExtrasSections: View {
    let item: VaultItem
    @Bindable var model: LoginExtrasModel
    let gate: StrictItemGate
    let clipboard: MacClipboard
    let store: (any ItemStore)?
    let onCopied: (String) -> Void
    let onSaved: () -> Void
    let onRevealed: () -> Void
    @Environment(\.macTheme) private var theme

    private var strict: Bool { StrictItemGate.isStrict(item) }
    private var revealedHere: Bool { model.itemID == item.id }

    var body: some View {
        recoverySection
        customFieldsSection
        historySection
        if revealedHere, let error = model.error {
            Text(error).font(.system(size: 12.5)).foregroundStyle(theme.danger).padding(.top, 6)
        }
    }

    // MARK: recovery codes

    @ViewBuilder private var recoverySection: some View {
        SectionLabel(String(localized: "Recovery codes"))
        if revealedHere, model.codes != nil {
            let codes = Binding(get: { model.codes ?? [] }, set: { model.codes = $0 })
            ForEach(codes.indices, id: \.self) { i in
                HStack(spacing: 10) {
                    TextField("Code", text: codes[i]).textFieldStyle(.roundedBorder)
                        .font(.system(size: 13, design: .monospaced))
                    CopyButton(label: String(localized: "Recovery code")) {
                        let code = codes.wrappedValue.indices.contains(i) ? codes.wrappedValue[i] : ""
                        guard !code.isEmpty else { return }
                        gate.release(item, action: String(localized: "Copy recovery code")) {
                            clipboard.copy(code, concealed: true); onCopied(String(localized: "Recovery code"))
                        }
                    }
                    Button { model.codes?.remove(at: i) } label: { Image(systemName: "minus.circle") }
                        .buttonStyle(.plain).foregroundStyle(theme.textMuted).help("Remove this code")
                }
                .padding(.vertical, 3)
            }
            HStack(spacing: 12) {
                Button("Add code") { model.codes?.append("") }
                    .buttonStyle(.plain).foregroundStyle(theme.link)
                    .disabled((model.codes?.count ?? 0) >= LoginExtrasModel.maxRecoveryCodes)
                Spacer()
                Button("Hide") { model.codes = nil }.buttonStyle(PillButtonStyle(primary: false))
                Button("Save codes") {
                    guard let store else { return }
                    model.saveCodes(item, store: store, clock: SystemClock(), gate: gate, onSaved: onSaved)
                }
                .buttonStyle(PillButtonStyle(primary: false)).disabled(store == nil)
            }
            .padding(.vertical, 6)
        } else {
            HStack(spacing: 12) {
                Text(LoginExtrasModel.recoveryText(item)).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                Button("Reveal") { model.revealCodes(item, gate: gate, onRevealed: onRevealed) }
                    .buttonStyle(PillButtonStyle(primary: false))
            }
            .padding(.vertical, 6)
        }
    }

    // MARK: custom fields

    @ViewBuilder private var customFieldsSection: some View {
        SectionLabel(String(localized: "Custom fields"))
        if revealedHere, model.fields != nil {
            let fields = Binding(get: { model.fields ?? [] }, set: { model.fields = $0 })
            ForEach(fields) { $field in
                HStack(spacing: 8) {
                    TextField("Name", text: $field.name).textFieldStyle(.roundedBorder).frame(width: 130)
                    if field.hidden {
                        SecureField("Value", text: $field.value).textFieldStyle(.roundedBorder)
                    } else {
                        TextField("Value", text: $field.value).textFieldStyle(.roundedBorder)
                    }
                    Toggle("Hidden", isOn: $field.hidden).toggleStyle(.checkbox).font(.system(size: 12.5))
                    CopyButton(label: field.name.isEmpty ? String(localized: "Value") : field.name) {
                        let value = field.value, hidden = field.hidden
                        gate.release(item, action: (field.name.isEmpty ? String(localized: "Copy value") : String(localized: "Copy \(field.name)"))) {
                            clipboard.copy(value, concealed: hidden); onCopied(field.name)
                        }
                    }
                    Button { model.removeField(field.id) } label: { Image(systemName: "minus.circle") }
                        .buttonStyle(.plain).foregroundStyle(theme.textMuted).help("Remove this field")
                }
                .padding(.vertical, 3)
            }
        } else if strict {
            Text(LoginExtrasModel.customFieldsLockedText).foregroundStyle(theme.textMuted).padding(.vertical, 6)
        } else {
            ForEach(Array(LoginExtrasModel.customFields(of: item).enumerated()), id: \.offset) { _, field in
                KeyValueRow(label: field.name) {
                    if field.hidden {
                        Text("••••••••").font(.system(size: 14, design: .monospaced))
                    } else {
                        Text(field.value).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                    }
                } actions: {
                    CopyButton(label: field.name) {
                        let copy = { clipboard.copy(field.value, concealed: field.hidden); onCopied(field.name) }
                        if field.hidden { gate.releaseRoutine(item, action: String(localized: "Copy \(field.name)"), perform: copy) } else { copy() }
                    }
                }
            }
        }
        HStack(spacing: 12) {
            Text(LoginExtrasModel.customFieldsHelp).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            if !(revealedHere && model.fields != nil) && (strict || LoginExtrasModel.customFields(of: item).contains { $0.hidden }) {
                Button("Reveal") { model.revealFields(item, gate: gate, onRevealed: onRevealed) }
                    .buttonStyle(.plain).foregroundStyle(theme.link)
            }
            Button("Add field") {
                if revealedHere, model.fields != nil { model.addField() }
                else { model.revealFields(item, gate: gate, onRevealed: { model.addField() }) }
            }
            .buttonStyle(.plain).foregroundStyle(theme.link)
            .disabled(LoginExtrasModel.customFields(of: item).count >= LoginExtrasModel.maxCustomFields
                      && !(revealedHere && model.fields != nil))
            Button("Save fields") {
                guard let store else { return }
                model.saveFields(item, store: store, clock: SystemClock(), gate: gate, onSaved: onSaved)
            }
            .buttonStyle(PillButtonStyle(primary: false))
            .disabled(store == nil || !(revealedHere && model.fields != nil))
        }
        .padding(.vertical, 6)
    }

    // MARK: password history

    @ViewBuilder private var historySection: some View {
        let rows = LoginExtrasModel.history(of: item)
        SectionLabel(String(localized: "Password history"))
        if rows.isEmpty {
            Text(LoginExtrasModel.historyEmptyText).foregroundStyle(theme.textMuted).padding(.vertical, 6)
        }
        ForEach(Array(rows.prefix(LoginExtrasModel.maxHistory).enumerated()), id: \.offset) { i, row in
            let shown = revealedHere && model.historyShown(i)
            KeyValueRow(label: Self.date(row.changedAt)) {
                Text(shown ? row.password : "••••••••••••").font(.system(size: 14, design: .monospaced))
                    .lineLimit(1).truncationMode(.middle).textSelection(.disabled)
            } actions: {
                Button(shown ? String(localized: "Hide") : String(localized: "Show")) {
                    if shown { model.hideHistory(i) } else { model.showHistory(i, of: item, gate: gate, onRevealed: onRevealed) }
                }
                .buttonStyle(.plain).foregroundStyle(theme.link)
                CopyButton(label: String(localized: "Previous password")) {
                    gate.releaseRoutine(item, action: String(localized: "Copy previous password")) {
                        clipboard.copy(row.password, concealed: true); onCopied(String(localized: "Previous password"))
                    }
                }
            }
        }
    }

    /// "12 Mar 2026"; unknown dates show as "Earlier".
    static func date(_ at: Int64) -> String {
        guard at > 0 else { return String(localized: "Earlier") }
        return Date(timeIntervalSince1970: TimeInterval(at)).formatted(.dateTime.day().month(.abbreviated).year())
    }
}
