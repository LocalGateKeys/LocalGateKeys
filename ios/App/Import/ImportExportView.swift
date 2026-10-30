import SwiftUI
import UniformTypeIdentifiers
import AppShared

/// Settings › Import & Export (the Mac's `ImportExportModel`, iPhone flavour): a file picked in Files is
/// detected with `ImportDetect`, asks for its password (Bitwarden password-protected JSON, KeePass `.kdbx`)
/// or its columns (a generic CSV) when needed, then opens the review (`ImportReviewModel`, shared with the
/// Mac); nothing is written until the review is accepted.
@MainActor @Observable
final class ImportExportModel {
    static let maxFileBytes = ImportSource.maxArchiveBytes
    static let unknownFormatMessage = String(localized: "This file isn't an export LocalGateKeys can read. Export again from your password manager (CSV, JSON, .1pux, .kdbx, .xml or .zip) and choose that file.")
    static let unreadableFile = String(localized: "That file could not be read.")
    static let importHelp = String(localized: "Choose an export from Safari, Chrome, Edge, Brave, Firefox, Bitwarden, 1Password, LastPass, KeePass, Proton Pass or Dashlane, or any CSV file. You review every row before anything is saved.")

    static let csvWarning = String(localized: "This file is not encrypted. Anyone who gets it can read every password in it.")
    static let passkeysNotInCSV = String(localized: "Passkeys can't go in a CSV file. Only website logins are exported.")

    /// The picker's file types: CSV, JSON, 1Password `.1pux`, KeePass `.kdbx`/`.xml`, and `.zip` (Dashlane, Proton Pass).
    /// `.data` last: `.1pux` and `.kdbx` are not declared types, so Files could grey them out; `ImportDetect`
    /// reads the content and refuses anything else.
    static var importTypes: [UTType] {
        var types: [UTType] = [.commaSeparatedText, .json, .xml, .zip, .plainText, .data]
        for ext in ["1pux", "kdbx", "csv"] {
            if let t = UTType(filenameExtension: ext), !types.contains(t) { types.append(t) }
        }
        return types
    }

    /// The file waiting for its password.
    struct PasswordRequest: Identifiable, Equatable {
        let id = UUID()
        let fileName: String
        let prompt: String
        var error: String?
    }

    /// A generic CSV waiting for its columns.
    struct MappingRequest: Identifiable, Equatable {
        let id = UUID()
        let fileName: String
        let header: [String]
        var mapping: GenericCSVMapping
    }

    private struct PendingFile {
        let name: String
        let data: Data
        let format: ImportFormat
    }

    private let importer: VaultImporter
    private let exporter: VaultExporter?
    var message: String?
    var exportMessage: String?
    /// True while the backup is being sealed.
    var exporting = false
    /// True while a file is read or the review is saved.
    private(set) var busy = false
    private(set) var review: ImportReviewModel?
    /// The format label of the file under review.
    private(set) var reviewSource = ""
    var passwordRequest: PasswordRequest?
    var mappingRequest: MappingRequest?
    @ObservationIgnored private var pending: PendingFile?

    init(importer: VaultImporter, exporter: VaultExporter? = nil) { self.importer = importer; self.exporter = exporter }

    var canExport: Bool { exporter != nil }

    /// Drops the file, the password request, the columns and the review (Cancel).
    func reset() {
        pending = nil; review = nil; reviewSource = ""; passwordRequest = nil; mappingRequest = nil
    }

    // MARK: import

    /// Reads the picked file (under its security scope), detects it, then asks for a password or columns when
    /// needed, then opens the review.
    func importFile(url: URL) async {
        reset()
        message = nil
        let name = url.lastPathComponent
        let data: Data
        do {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard size <= Self.maxFileBytes else { message = ImportError.tooLarge.message; return }
            data = try Data(contentsOf: url)
        } catch { message = Self.unreadableFile; return }
        guard let format = ImportDetect.detect(data: data, filename: name) else {
            message = Self.unknownFormatMessage
            return
        }
        pending = PendingFile(name: name, data: data, format: format)
        if format == .generic {
            do {
                let header = try GenericCSV.header(from: data)
                mappingRequest = MappingRequest(fileName: name, header: header,
                                                mapping: GenericCSV.suggestMapping(header: header))
            } catch let e as ImportError { message = e.message; pending = nil } catch { message = Self.unreadableFile; pending = nil }
            return
        }
        await run(format: format, options: ImportOptions())
    }

    /// The password for the pending encrypted file; a wrong one asks again.
    func submitPassword(_ password: String) async {
        guard let file = pending, passwordRequest != nil, !busy else { return }
        guard !password.isEmpty else { passwordRequest?.error = String(localized: "Enter the file's password."); return }
        await run(format: file.format, options: ImportOptions(password: password))
    }

    /// The columns chosen for a generic CSV.
    func applyMapping(_ mapping: GenericCSVMapping) async {
        guard let file = pending, file.format == .generic, mappingRequest != nil, !busy else { return }
        await run(format: .generic, options: ImportOptions(mapping: mapping))
    }

    private func run(format: ImportFormat, options: ImportOptions) async {
        guard let file = pending else { return }
        busy = true
        defer { busy = false }
        let data = file.data
        let outcome = await Task.detached(priority: .userInitiated) { () -> Result<LGKCore.ImportResult, ImportError> in
            do { return .success(try ImportSource.candidates(from: data, format: format, options: options)) }
            catch let e as ImportError { return .failure(e) }
            catch { return .failure(.malformed(String(localized: "The file could not be imported."))) }
        }.value
        switch outcome {
        case .success(let result):
            passwordRequest = nil
            mappingRequest = nil
            pending = nil
            openReview(result, source: ImportReviewModel.formatLabel(format))
        case .failure(let error):
            if ImportReviewModel.asksPasswordAgain(error) {
                if passwordRequest != nil {
                    passwordRequest?.error = error.message
                } else {
                    passwordRequest = PasswordRequest(fileName: file.name, prompt: ImportReviewModel.passwordPrompt(for: format),
                                                      error: error == .needsPassword ? nil : error.message)
                }
            } else if mappingRequest != nil, case .malformed = error {
                if let m = options.mapping { mappingRequest?.mapping = m }
                message = error.message
            } else {
                passwordRequest = nil; mappingRequest = nil; pending = nil
                message = ImportReviewModel.message(for: error, format: format)
            }
        }
    }

    private func openReview(_ result: LGKCore.ImportResult, source: String) {
        do {
            let snap = try importer.store.load()
            review = ImportReviewModel(result: result, snapshot: snap,
                                       freeSlots: ImportReviewModel.freeSlots(snapshot: snap, isPro: importer.isPro()),
                                       now: importer.now, random: importer.random)
            reviewSource = source
        } catch {
            message = String(localized: "The vault could not be read for the import.")
        }
    }

    /// Writes the reviewed rows (one commit) and closes the review.
    @discardableResult
    func commitReview() async -> ImportOutcome? {
        guard let review, !busy else { return nil }
        busy = true
        defer { busy = false }
        do {
            let out = try await review.commit(to: importer.store)
            self.review = nil
            reviewSource = ""
            message = Self.summary(out, limitNote: review.limitNote)
            if out.created + out.updated > 0 { importer.afterCommit() }
            return out
        } catch let e as ImportReviewError {
            message = e.message
        } catch LocalStoreError.stale {
            message = String(localized: "The vault changed while importing. Try again.")
        } catch {
            message = String(localized: "The import could not be saved.")
        }
        return nil
    }

    func cancelReview() { reset() }

    /// A password, columns or review step is waiting (the import sheet is on screen).
    var hasImportStep: Bool { passwordRequest != nil || mappingRequest != nil || review != nil }

    /// The Mac's summary line.
    static func summary(_ o: ImportOutcome, limitNote: String) -> String {
        var text = String(localized: "\(o.created + o.updated) record(s) written. Added \(o.created), updated \(o.updated), skipped \(o.skipped).")
        if o.limited > 0 { text += " " + (limitNote.isEmpty ? String(localized: "\(o.limited) row(s) need Pro.") : limitNote + ".") }
        return text
    }

    // MARK: export

    /// Seals an encrypted backup to a temporary file; nil (and `exportMessage` set) on failure.
    func exportBackup(password: String, confirmation: String) async -> URL? {
        guard let exporter, !exporting else { return nil }
        exporting = true
        defer { exporting = false }
        exportMessage = nil
        do {
            let file = try await exporter.encryptedBackupFile(password: password, confirmation: confirmation)
            if file.filesLeftOut > 0 { exportMessage = VaultExporter.filesLeftOutMessage(file.filesLeftOut) }
            return file.url
        } catch VaultExporter.Error.weakPassword {
            exportMessage = String(localized: "Use at least \(VaultExporter.minPasswordLength) characters.")
        } catch VaultExporter.Error.mismatch {
            exportMessage = String(localized: "The passwords don't match.")
        } catch LocalStoreError.stale {
            exportMessage = String(localized: "The vault changed while exporting. Try again.")
        } catch {
            exportMessage = String(localized: "The backup could not be created.")
        }
        return nil
    }

    /// Writes the CSV to a temporary file; nil (and `exportMessage` set) on failure.
    func exportCSV() -> URL? {
        guard let exporter else { return nil }
        exportMessage = nil
        do { return try exporter.csv() } catch {
            exportMessage = String(localized: "The CSV file could not be created.")
            return nil
        }
    }
}

/// Settings › Import & Export.
struct ImportExportView: View {
    @State private var model: ImportExportModel
    @State private var picking = false
    @State private var askingPassword = false
    /// Receive a shared item by QR (UX workstream 9); the app's Receive sheet takes it from there.
    @State private var scanningShare = false
    /// The scanned package, delivered only once the scanner sheet has gone (the Receive sheet comes next).
    @State private var scannedShare: String?
    @Environment(\.shareInbox) private var shareInbox
    @State private var confirmingCSV = false
    @State private var shared: SharedFile?
    /// The temporary file on screen, deleted when the share sheet closes.
    @State private var exported: URL?

    init(model: ImportExportModel) { _model = State(initialValue: model) }

    static let applePasswordsHelp = String(localized: "In Apple Passwords (or another app that supports it), choose Export Data to Another App, then pick LocalGateKeys. This is the quickest way, and no file is left behind.")
    static let needsNewerIOS = String(localized: "Needs iOS 26. Use an exported file instead.")

    private var supportsExchange: Bool {
        if #available(iOS 26, *) { return true }
        return false
    }

    var body: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Import from Apple Passwords or another app")
                    Text(supportsExchange ? Self.applePasswordsHelp : Self.needsNewerIOS)
                        .font(.footnote).foregroundStyle(Palette.secondaryText)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Button("Import from a file") { picking = true }
                        .foregroundStyle(Palette.accentText).disabled(model.busy)
                    Text(ImportExportModel.importHelp)
                        .font(.footnote).foregroundStyle(Palette.secondaryText)
                }
                if shareInbox != nil {
                    VStack(alignment: .leading, spacing: 4) {
                        Button("Receive a shared item") { scanningShare = true }
                            .foregroundStyle(Palette.accentText)
                        Text("Scan the QR another LocalGateKeys shows, or open a .lgkshare file from AirDrop or Files.")
                            .font(.footnote).foregroundStyle(Palette.secondaryText)
                    }
                }
            } header: {
                Text("Import")
            } footer: {
                if let message = model.message, model.review == nil, model.mappingRequest == nil { Text(message) }
            }
            .listRowBackground(Palette.groupSurface)
            Section {
                Button("Export encrypted backup") { askingPassword = true }
                    .foregroundStyle(Palette.accentText)
                VStack(alignment: .leading, spacing: 4) {
                    Button("Export as CSV") { confirmingCSV = true }
                        .foregroundStyle(Palette.accentText)
                    Text(ImportExportModel.passkeysNotInCSV)
                        .font(.footnote).foregroundStyle(Palette.secondaryText)
                }
            } header: {
                Text("Export")
            } footer: {
                if let message = model.exportMessage { Text(message) }
                else { Text("An encrypted backup can be restored in the desktop app.") }
            }
            .disabled(!model.canExport)
            .listRowBackground(Palette.groupSurface)
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Import & Export")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $scanningShare, onDismiss: {
            if let text = scannedShare { scannedShare = nil; shareInbox?.deliver(text: text) }
        }) {
            NavigationStack {
                QRScanner(onCode: { text in scannedShare = text; scanningShare = false },
                          onUnavailable: { scanningShare = false })
                    .ignoresSafeArea()
                    .navigationTitle("Scan QR code")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { scanningShare = false } } }
            }
        }
        .sheet(isPresented: $askingPassword) {
            BackupPasswordSheet(model: model) { url in
                askingPassword = false
                shared = SharedFile(url: url)
            }
            .interactiveDismissDisabled(model.exporting)
        }
        .alert("Export as CSV?", isPresented: $confirmingCSV) {
            Button("Export", role: .destructive) {
                if let url = model.exportCSV() { shared = SharedFile(url: url) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(ImportExportModel.csvWarning)
        }
        .sheet(item: $shared, onDismiss: { VaultExporter.discard(exported); exported = nil }) { file in
            ShareSheet(url: file.url) { shared = nil }
        }
        .sheet(isPresented: Binding(get: { model.hasImportStep },
                                    set: { if !$0, !model.busy { model.reset() } })) {
            ImportFlowSheet(model: model).interactiveDismissDisabled(model.busy)
        }
        .onChange(of: shared?.url) { _, url in if let url { exported = url } }
        .onDisappear { VaultExporter.discard(exported); exported = nil }
        .fileImporter(isPresented: $picking, allowedContentTypes: ImportExportModel.importTypes) { result in
            switch result {
            case .success(let url): Task { await model.importFile(url: url) }
            case .failure: model.message = String(localized: "The file could not be opened.")
            }
        }
    }
}

/// A temporary export file shown in the share sheet.
struct SharedFile: Identifiable {
    let url: URL
    var id: URL { url }
}

/// Asks for the backup password twice. The fields are cleared on export and on cancel.
private struct BackupPasswordSheet: View {
    let model: ImportExportModel
    let done: (URL) -> Void
    @State private var password = ""
    @State private var confirmation = ""
    @Environment(\.dismiss) private var dismiss

    private var ready: Bool {
        password.count >= VaultExporter.minPasswordLength && !confirmation.isEmpty && !model.exporting
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Backup password", text: $password).textContentType(.newPassword)
                    SecureField("Repeat password", text: $confirmation).textContentType(.newPassword)
                } footer: {
                    if let message = model.exportMessage { Text(message) }
                    else {
                        Text("At least \(VaultExporter.minPasswordLength) characters. You'll need this password to restore the backup; it can't be recovered.")
                    }
                }
                if model.exporting {
                    HStack(spacing: 12) {
                        ProgressView()
                        Text("Encrypting the backup…").foregroundStyle(Palette.secondaryText)
                    }
                }
            }
            .disabled(model.exporting)
            .navigationTitle("Encrypted backup")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { clear(); dismiss() }.disabled(model.exporting)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Export") {
                        let (p, c) = (password, confirmation)
                        Task {
                            let url = await model.exportBackup(password: p, confirmation: c)
                            clear()
                            if let url { done(url) }
                        }
                    }
                    .disabled(!ready)
                }
            }
        }
        .onDisappear { clear() }
    }

    private func clear() { password = ""; confirmation = "" }
}

/// The system share sheet for one file; `finished` runs when it closes (shared or cancelled).
private struct ShareSheet: UIViewControllerRepresentable {
    let url: URL
    let finished: () -> Void

    func makeUIViewController(context: Context) -> UIActivityViewController {
        let vc = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        vc.completionWithItemsHandler = { _, _, _, _ in finished() }
        return vc
    }

    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}
