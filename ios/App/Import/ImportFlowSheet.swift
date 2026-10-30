import SwiftUI
import AppShared

/// The import steps after a file is picked (the Mac's password prompt, `GenericMappingSheet` and
/// `ImportReviewSheet`, in one iPhone sheet): the file's password, then a generic CSV's columns, then the review.
struct ImportFlowSheet: View {
    let model: ImportExportModel

    var body: some View {
        NavigationStack {
            Group {
                if let review = model.review {
                    ImportReviewList(model: model, review: review)
                } else if let request = model.mappingRequest {
                    ImportMappingForm(model: model, request: request)
                } else if let request = model.passwordRequest {
                    ImportPasswordForm(model: model, request: request)
                }
            }
            .scrollContentBackground(.hidden)
            .lgkAuroraBackground()
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

/// Asks for the export's password (Bitwarden password-protected JSON, KeePass `.kdbx`); a wrong one asks again.
/// The field is cleared after each try and when the sheet closes.
private struct ImportPasswordForm: View {
    let model: ImportExportModel
    let request: ImportExportModel.PasswordRequest
    @State private var password = ""

    var body: some View {
        Form {
            Section {
                SecureField("File password", text: $password)
                    .textContentType(.password)
                    .submitLabel(.go)
                    .onSubmit(submit)
            } header: {
                Text(request.fileName)
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    Text(request.prompt)
                    if let error = request.error { Text(error).foregroundStyle(Palette.warning) }
                }
            }
            .listRowBackground(Palette.groupSurface)
            if model.busy {
                HStack(spacing: 12) {
                    ProgressView()
                    Text("Opening the file…").foregroundStyle(Palette.secondaryText)
                }
                .listRowBackground(Palette.groupSurface)
            }
        }
        .disabled(model.busy)
        .navigationTitle("Password")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { password = ""; model.reset() }.disabled(model.busy)
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Open", action: submit).disabled(password.isEmpty || model.busy)
            }
        }
        .onDisappear { password = "" }
    }

    private func submit() {
        let p = password
        password = ""
        guard !p.isEmpty else { return }
        Task { await model.submitPassword(p) }
    }
}

/// The column step for a generic CSV (`GenericCSV.suggestMapping` prefilled). A password or notes column is required.
private struct ImportMappingForm: View {
    let model: ImportExportModel
    let request: ImportExportModel.MappingRequest
    @State private var mapping: GenericCSVMapping

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
        Form {
            Section {
                ForEach(Self.fields, id: \.label) { field in
                    Picker(field.label, selection: binding(field.path)) {
                        Text("Not in this file").tag(-1)
                        ForEach(Array(request.header.enumerated()), id: \.offset) { i, name in
                            Text(name.isEmpty ? String(localized: "Column \(i + 1)") : name).tag(i)
                        }
                    }
                }
            } header: {
                Text(request.fileName)
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    Text(Self.intro)
                    if mapping.password == nil && mapping.notes == nil {
                        Text("Choose the password column (or a notes column).").foregroundStyle(Palette.warning)
                    }
                    if let m = model.message { Text(m).foregroundStyle(Palette.warning) }
                }
            }
            .listRowBackground(Palette.groupSurface)
        }
        .disabled(model.busy)
        .navigationTitle("Choose columns")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { model.reset() }.disabled(model.busy)
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Continue") {
                    let chosen = mapping   // captured before the Task runs
                    Task { await model.applyMapping(chosen) }
                }
                .disabled(model.busy || (mapping.password == nil && mapping.notes == nil))
            }
        }
    }

    private func binding(_ path: WritableKeyPath<GenericCSVMapping, Int?>) -> Binding<Int> {
        Binding(get: { mapping[keyPath: path] ?? -1 }, set: { mapping[keyPath: path] = $0 < 0 ? nil : $0 })
    }
}

/// The review (the Mac's `ImportReviewSheet`): one row per record with what will happen to it (Add, Skip,
/// Replace, Merge, Keep both; "Needs Pro" past the free slots), the summary and the messages, then Import.
/// Passwords are never shown.
private struct ImportReviewList: View {
    let model: ImportExportModel
    @ObservedObject var review: ImportReviewModel
    @State private var showingMessages = false

    static let footer = String(localized: "Nothing is written until you choose Import. Replace and merge keep the previous password in encrypted history. Delete the export file from Files afterwards.")

    var body: some View {
        List {
            Section {
                Text("\(model.reviewSource) · \(review.rows.count) records. New records default to Add; duplicates and conflicts default to Skip (Keep both saves the imported copy too).")
                    .font(.footnote).foregroundStyle(Palette.secondaryText)
                Menu("Change all") {
                    Button("Add all new") { setAll { $0.base == .new ? .create : nil } }
                    Button("Skip all") { setAll { _ in .skip } }
                    Button("Keep both for duplicates") { setAll { $0.base != .new && !$0.isSkippedSource ? .keepBoth : nil } }
                }
                .foregroundStyle(Palette.accentText)
            }
            .listRowBackground(Palette.groupSurface)
            Section {
                ForEach(review.rows) { row in rowView(row) }
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    Text(review.summary).fontWeight(.medium)
                    Text(Self.footer)
                    if let m = model.message { Text(m).foregroundStyle(Palette.warning) }
                }
            }
            .listRowBackground(Palette.groupSurface)
            if !review.issues.isEmpty {
                Section {
                    DisclosureGroup("Messages (\(review.issues.count))", isExpanded: $showingMessages) {
                        ForEach(Array(review.issues.enumerated()), id: \.offset) { _, line in
                            Text(line).font(.footnote).foregroundStyle(Palette.secondaryText)
                        }
                    }
                }
                .listRowBackground(Palette.groupSurface)
            }
        }
        .navigationTitle("Review import")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { model.cancelReview() }.disabled(model.busy)
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(model.busy ? String(localized: "Importing…") : String(localized: "Import")) { Task { await model.commitReview() } }
                    .disabled(model.busy || !review.rows.contains { $0.decision != .skip && !$0.limited })
            }
        }
    }

    private func setAll(_ pick: (ImportRow) -> ImportDecision?) {
        for row in review.rows { if let d = pick(row) { review.set(d, for: row.id) } }
    }

    private func rowView(_ row: ImportRow) -> some View {
        HStack(spacing: 12) {
            Image(systemName: Self.icon(row.kind)).foregroundStyle(Palette.secondaryText).frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(row.title.isEmpty ? String(localized: "Untitled") : row.title).lineLimit(1)
                Text(Self.detail(row)).font(.footnote).foregroundStyle(Palette.secondaryText).lineLimit(2)
                Text(Self.statusLabel(row)).font(.caption)
                    .foregroundStyle(row.limited ? Palette.warning : Palette.secondaryText)
            }
            Spacer(minLength: 8)
            let options = Self.options(for: row)
            if options.count > 1 && !row.limited {
                Picker("", selection: Binding(get: { row.decision }, set: { review.set($0, for: row.id) })) {
                    ForEach(options, id: \.label) { option in Text(option.label).tag(option.decision) }
                }
                .labelsHidden().pickerStyle(.menu)
            } else {
                Text(row.limited ? String(localized: "Not imported") : row.stateLabel).font(.footnote).foregroundStyle(Palette.secondaryText)
            }
        }
        .foregroundStyle(Palette.text)
    }

    struct Option { let label: String; let decision: ImportDecision }

    /// The decisions Windows offers a row (`ImportReviewModel.set` refuses the rest); as on the Mac.
    static func options(for row: ImportRow) -> [Option] {
        if row.isSkippedSource { return [] }
        if row.base == .new { return [Option(label: String(localized: "Add"), decision: .create), Option(label: String(localized: "Skip"), decision: .skip)] }
        var out = [Option(label: String(localized: "Skip"), decision: .skip)]
        if let t = row.targetID, !row.inImportDuplicate, row.kind != .passkey {
            out += [Option(label: String(localized: "Replace"), decision: .replace(t)), Option(label: String(localized: "Merge"), decision: .merge(t))]
        }
        if row.kind != .passkey { out.append(Option(label: String(localized: "Keep both"), decision: .keepBoth)) }
        return out
    }

    static func statusLabel(_ row: ImportRow) -> String {
        switch row.status {
        case .new: String(localized: "New")
        case .duplicate: row.inImportDuplicate ? String(localized: "Repeated in file") : String(localized: "Already here")
        case .conflict: String(localized: "Different password")
        case .limited: String(localized: "Needs Pro")
        case .skipped: String(localized: "Unreadable")
        }
    }

    static func detail(_ row: ImportRow) -> String {
        if case .skipped(let m) = row.base { return m }
        let parts = [row.origin.isEmpty ? "" : OriginLabel.friendly(row.origin), row.username].filter { !$0.isEmpty }
        return parts.isEmpty ? row.kind.rawValue.capitalized : parts.joined(separator: " · ")
    }

    static func icon(_ kind: ImportDraft.Kind) -> String {
        switch kind {
        case .login: "globe"
        case .note: "note.text"
        case .card: "creditcard"
        case .identity: "person.text.rectangle"
        case .passkey: "person.badge.key"
        }
    }
}
