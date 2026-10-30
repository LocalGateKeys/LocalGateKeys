import SwiftUI
import AppSharedMac

/// The column step for a generic CSV (Windows column mapping, `GenericCSV.suggestMapping` prefilled): which
/// column holds the title, website, username, password, notes and one-time password. A password or notes
/// column is required.
struct GenericMappingSheet: View {
    let model: ImportExportModel
    let request: ImportExportModel.MappingRequest
    @State private var mapping: GenericCSVMapping
    @Environment(\.macTheme) private var theme

    init(model: ImportExportModel, request: ImportExportModel.MappingRequest) {
        self.model = model; self.request = request
        _mapping = State(initialValue: request.mapping)
    }

    static let intro = String(localized: "This CSV file isn't from a password manager LocalGateKeys knows. Choose which column holds each field.")
    static let fields: [(label: String, path: WritableKeyPath<GenericCSVMapping, Int?>)] = [
        (String(localized: "Title"), \.title), (String(localized: "Website"), \.url), (String(localized: "Username"), \.username), (String(localized: "Password"), \.password),
        (String(localized: "Notes"), \.notes), (String(localized: "One-time password"), \.totp),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Choose columns").font(.title3.weight(.semibold))
            Text(request.fileName).font(.system(size: 12)).foregroundStyle(theme.textMuted)
            Text(Self.intro).font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true)
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                ForEach(Self.fields, id: \.label) { field in
                    GridRow {
                        Text(field.label).font(.system(size: 13))
                        Picker("", selection: binding(field.path)) {
                            Text("Not in this file").tag(-1)
                            ForEach(Array(request.header.enumerated()), id: \.offset) { i, name in
                                Text(name.isEmpty ? String(localized: "Column \(i + 1)") : name).tag(i)
                            }
                        }
                        .labelsHidden().frame(width: 240)
                    }
                }
            }
            if mapping.password == nil && mapping.notes == nil {
                Text("Choose the password column (or a notes column).").font(.system(size: 12.5)).foregroundStyle(theme.warning)
            }
            if let m = model.message { Text(m).font(.system(size: 12.5)).foregroundStyle(theme.warning) }
            HStack {
                Spacer()
                Button("Cancel") { model.reset() }.buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button("Continue") {
                    let chosen = mapping   // captured before the Task runs
                    Task { await model.applyMapping(chosen) }
                }
                .buttonStyle(PillButtonStyle(primary: true)).keyboardShortcut(.defaultAction)
                .disabled(model.busy || (mapping.password == nil && mapping.notes == nil))
            }
        }
        .padding(24).frame(width: 480).background(WashBackground()).foregroundStyle(theme.text)
    }

    private func binding(_ path: WritableKeyPath<GenericCSVMapping, Int?>) -> Binding<Int> {
        Binding(get: { mapping[keyPath: path] ?? -1 }, set: { mapping[keyPath: path] = $0 < 0 ? nil : $0 })
    }
}
