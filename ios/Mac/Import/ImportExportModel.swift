import Foundation
import Observation
import AppSharedMac

/// The Mac Import & export page (Windows `app/import_export.py` and `app/phone_backup_web.py`, the iPhone's
/// `ImportExportView`): a picked file is detected, asks for its password or its columns when it needs them,
/// then opens the review (`ImportReviewModel`); nothing is written until the review is accepted. A phone
/// backup (`.lgkm`) merges through the same sheet (sync rules: version vectors and tombstones kept, never a
/// wipe). Export writes an encrypted `.lgkm` or an Apple Passwords CSV to the file chosen in the save panel;
/// both ask for the master password first, and the CSV only after its plain-text warning.
@MainActor @Observable
final class ImportExportModel {
    // MARK: copy

    nonisolated static let title = String(localized: "Import & export")
    nonisolated static let intro = String(localized: "Bring passwords in from another password manager or a phone backup, or write a copy of this vault to a file. Nothing leaves this Mac unless you move the file.")
    nonisolated static let importHelp = String(localized: "Choose an export from Safari, Chrome, Edge, Brave, Firefox, Bitwarden, 1Password, LastPass, KeePass, Proton Pass or Dashlane, or any CSV file. You review every row before anything is saved.")
    nonisolated static let applePasswordsHelp = String(localized: "In the Passwords app, choose File › Export Data to Another App, then pick LocalGateKeys.")
    nonisolated static let restoreHelp = String(localized: "Restore a backup made on your phone (.lgkm). It is merged into this vault like a sync: nothing here is deleted unless the phone deleted it, and nothing newer is overwritten.")
    nonisolated static let exportIntro = String(localized: "Writes a copy of every login and exportable item in this vault to a file you choose. Nothing leaves this Mac unless you move the file.")
    nonisolated static let encryptedHelp = String(localized: "Every item, encrypted with a password you choose. Restore it on a phone or in the desktop app.")
    nonisolated static let passkeysNotInCSV = String(localized: "Passkeys can't go in a CSV file. Only website logins are exported.")
    /// Windows `ExportWarning.PLAINTEXT`, `SPREADSHEET` and `DELETE_AFTER` ("Bin" on the Mac).
    nonisolated static let csvWarning = String(localized: "This export stores every password, note and one-time password secret as plain text. Anyone who can read the file can read your passwords.\n\nDo not open the CSV in a spreadsheet application; values beginning with =, +, - or @ can be interpreted as formulas and the file may be cached in temporary locations.\n\nImport the file into the destination application right away, then delete it and empty the Bin. Cloud-synced folders and backups may keep copies.")
    nonisolated static let exportGateTitle = String(localized: "Exporting passwords")
    nonisolated static let unknownFormatMessage = ImportError.unknownFormat.message
    nonisolated static let unreadableFile = String(localized: "That file could not be read.")
    nonisolated static let backupPasswordPrompt = String(localized: "Enter the backup password (it is used once and not stored):")
    /// Windows `phone_backup.py` messages.
    nonisolated static let wrongBackupPassword = String(localized: "Wrong password, or the file is damaged.")
    nonisolated static let sameDeviceMessage = String(localized: "This backup was made on this Mac, so there is nothing to restore.")
    nonisolated static let restoredMessage = String(localized: "Phone backup restored.")
    nonisolated static let staleMessage = String(localized: "The vault changed while importing. Try again.")
    nonisolated static func backupMessage(_ e: PhoneBackup.Error) -> String {
        switch e {
        case .tooLarge: String(localized: "This file is too large to be a phone backup.")
        case .notABackup: String(localized: "This is not a LocalGateKeys phone backup.")
        case .unsupportedVersion: String(localized: "This backup was made by a newer version of LocalGateKeys. Update the app and try again.")
        case .badKDF: String(localized: "This backup uses unsupported password-protection settings.")
        case .wrongPassword: wrongBackupPassword
        case .badPayload: String(localized: "The backup was opened but its contents are not valid.")
        }
    }

    /// Apple Passwords (Credential Exchange) needs macOS 26; the row is hidden below it.
    nonisolated static func showsApplePasswords(_ version: OperatingSystemVersion) -> Bool { version.majorVersion >= 26 }
    var showsApplePasswords: Bool { Self.showsApplePasswords(ProcessInfo.processInfo.operatingSystemVersion) }

    // MARK: state

    /// The file waiting for its password (an encrypted export or a phone backup).
    struct PasswordRequest: Identifiable, Equatable {
        let id = UUID()
        let fileName: String
        let prompt: String
        let isPhoneBackup: Bool
        var error: String?
    }

    /// A generic CSV waiting for its columns.
    struct MappingRequest: Identifiable, Equatable {
        let id = UUID()
        let fileName: String
        let header: [String]
        var mapping: GenericCSVMapping
    }

    /// A phone backup ready to restore: Windows' preview lines, then Restore.
    struct RestorePreview: Identifiable, Equatable {
        let id = UUID()
        let fileName: String
        let lines: [String]
    }

    private struct PendingFile {
        let name: String
        let data: Data
        let format: ImportFormat?
    }

    private(set) var review: ImportReviewModel?
    /// The format label of the file under review.
    private(set) var reviewSource = ""
    var passwordRequest: PasswordRequest?
    var mappingRequest: MappingRequest?
    private(set) var restore: RestorePreview?
    /// The last import or restore notice (or why it failed).
    var message: String?
    /// The last export notice (or why it failed).
    var exportMessage: String?
    private(set) var busy = false
    /// The CSV plain-text warning on screen.
    var confirmingCSV = false
    /// The running export (tests wait on it).
    @ObservationIgnored private(set) var exportTask: Task<Bool, Never>?
    /// Credential Exchange token handed over by the Passwords app (memory only).
    private(set) var pendingExchangeToken: UUID?

    @ObservationIgnored private var pending: PendingFile?
    @ObservationIgnored private var backup: BackupPayload?
    /// Set only by the CSV warning plus the master password, used by one export.
    @ObservationIgnored private var csvAuthorised = false
    /// Set only by the master password, used by one encrypted export.
    @ObservationIgnored private var encryptedAuthorised = false
    /// Recently deleted: items a restored phone backup deletes land here (nil only in tests without local data).
    @ObservationIgnored private let local: (any LocalDataHosting)?

    @ObservationIgnored private let store: any ItemStore
    @ObservationIgnored private let isPro: () -> Bool
    @ObservationIgnored private let gate: StrictItemGate
    @ObservationIgnored private let fallbackDeviceID: () throws -> String
    @ObservationIgnored private let appVersion: String
    @ObservationIgnored private let licenseKeys: [String: [UInt8]]
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private let random: any RandomSource
    @ObservationIgnored private let exchangeFetch: CredentialExchangeModel.Fetch?
    /// This Mac's attachment files: a backup carries its documents' files, a restore stores the backup's (format 2).
    @ObservationIgnored private let blobs: (any AttachmentBlobStore)?
    /// Runs after each write (reload the list, refresh Pro from the store).
    @ObservationIgnored var afterChange: () -> Void = {}

    init(store: any ItemStore, isPro: @escaping () -> Bool, gate: StrictItemGate,
         fallbackDeviceID: @escaping () throws -> String, appVersion: String = ImportExportModel.bundleVersion(),
         licenseKeys: [String: [UInt8]] = LicenseKeys.production, now: @escaping () -> Date = Date.init,
         random: any RandomSource = SystemRandomSource(), exchangeFetch: CredentialExchangeModel.Fetch? = nil,
         local: (any LocalDataHosting)? = nil, blobs: (any AttachmentBlobStore)? = nil) {
        self.local = local
        self.blobs = blobs
        self.store = store; self.isPro = isPro; self.gate = gate; self.fallbackDeviceID = fallbackDeviceID
        self.appVersion = appVersion; self.licenseKeys = licenseKeys; self.now = now; self.random = random
        self.exchangeFetch = exchangeFetch
    }

    /// `CFBundleShortVersionString` when it fits the backup's `app_version` (printable ASCII, 1-32), else "1.0".
    nonisolated static func bundleVersion(_ bundle: Bundle = .main) -> String {
        let v = bundle.infoDictionary?["CFBundleShortVersionString"] as? String ?? ""
        let ok = (1...32).contains(v.utf8.count) && v.utf8.allSatisfy { (0x20...0x7E).contains($0) }
        return ok ? v : "1.0"
    }

    private var exporter: VaultExporter {
        VaultExporter(store: store, isPro: isPro, appVersion: appVersion, fallbackDeviceID: fallbackDeviceID,
                      now: now, random: random, blobs: blobs)
    }

    /// Drops everything held in memory (files, passwords asked for, the review): on lock and on Cancel.
    func reset() {
        pending = nil; backup = nil; review = nil; reviewSource = ""; passwordRequest = nil; mappingRequest = nil
        restore = nil; csvAuthorised = false; encryptedAuthorised = false; confirmingCSV = false
    }

    // MARK: import

    /// Reads the picked file (under its security scope) and starts the import: an `.lgkm` asks for its backup
    /// password; any other file is detected, then asks for a password or columns when needed, then opens the review.
    func importFile(url: URL) async {
        reset()
        message = nil
        let name = url.lastPathComponent
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let data: Data
        do {
            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard size <= ImportSource.maxArchiveBytes else { message = ImportError.tooLarge.message; return }
            data = try Data(contentsOf: url)
        } catch { message = Self.unreadableFile; return }
        if url.pathExtension.lowercased() == "lgkm" || Self.looksLikePhoneBackup(data) {
            pending = PendingFile(name: name, data: data, format: nil)
            passwordRequest = PasswordRequest(fileName: name, prompt: Self.backupPasswordPrompt, isPhoneBackup: true)
            return
        }
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

    nonisolated static func looksLikePhoneBackup(_ data: Data) -> Bool {
        data.prefix(32).starts(with: Array(#"{"ciphertext":"#.utf8))
    }

    /// The password for the pending encrypted file or phone backup; a wrong one asks again.
    func submitPassword(_ password: String) async {
        guard let file = pending, let request = passwordRequest, !busy else { return }
        if request.isPhoneBackup {
            _ = await openBackup(file, password: password)
        } else if let format = file.format {
            await run(format: format, options: ImportOptions(password: password))
        }
    }

    /// The columns chosen for a generic CSV.
    func applyMapping(_ mapping: GenericCSVMapping) async {
        guard let file = pending, file.format == .generic, mappingRequest != nil else { return }
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
                                                      isPhoneBackup: false, error: error == .needsPassword ? nil : error.message)
                }
            } else if mappingRequest != nil, case .malformed = error {
                mappingRequest?.mapping = options.mapping ?? mappingRequest!.mapping
                message = error.message
            } else {
                passwordRequest = nil; mappingRequest = nil; pending = nil
                message = ImportReviewModel.message(for: error, format: format)
            }
        }
    }

    private func openReview(_ result: LGKCore.ImportResult, source: String) {
        do {
            let snap = try store.load()
            review = ImportReviewModel(result: result, snapshot: snap,
                                       freeSlots: ImportReviewModel.freeSlots(snapshot: snap, isPro: isPro()),
                                       now: now, random: random)
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
            let out = try await review.commit(to: store)
            self.review = nil
            reviewSource = ""
            message = Self.summary(out, limitNote: review.limitNote)
            afterChange()
            return out
        } catch let e as ImportReviewError {
            message = e.message
        } catch LocalStoreError.stale {
            message = Self.staleMessage
        } catch {
            message = String(localized: "The import could not be saved.")
        }
        return nil
    }

    func cancelReview() { reset() }

    /// Windows `import_summary_text`, shortened.
    nonisolated static func summary(_ o: ImportOutcome, limitNote: String) -> String {
        var text = String(localized: "\(o.created + o.updated) record(s) written. Added \(o.created), updated \(o.updated), skipped \(o.skipped).")
        if o.limited > 0 { text += " " + (limitNote.isEmpty ? String(localized: "\(o.limited) row(s) need Pro.") : limitNote + ".") }
        return text
    }

    // MARK: Apple Passwords (Credential Exchange)

    /// The Passwords app opened the app with an export token; it is kept until the import runs.
    func receivedExchange(token: UUID) { pendingExchangeToken = token }

    /// Reads what the Passwords app handed over and opens the review. macOS 26 only.
    func importFromApplePasswords() async {
        guard showsApplePasswords || exchangeFetch != nil, let token = pendingExchangeToken, !busy else { return }
        reset()
        message = nil
        busy = true
        defer { busy = false }
        do {
            let r = try await (exchangeFetch ?? CredentialExchangeModel.liveFetch)(token)
            pendingExchangeToken = nil
            let skipped = r.unsupported > 0
                ? [ImportSkip(message: (r.unsupported == 1 ? String(localized: "1 item of an unsupported type were not imported.")
                    : String(localized: "\(r.unsupported) items of an unsupported type were not imported.")))]
                : []
            openReview(LGKCore.ImportResult(candidates: r.candidates, skipped: skipped),
                       source: ImportReviewModel.formatLabel(.cxf))
        } catch is CancellationError {
            return
        } catch CredentialExchangeModel.FetchError.unreadable {
            pendingExchangeToken = nil
            message = CredentialExchangeModel.unreadableMessage
        } catch {
            pendingExchangeToken = nil
            message = CredentialExchangeModel.exchangeFailedMessage
        }
    }

    // MARK: phone backup restore

    /// Opens the phone backup with its password and shows what restoring it does (the review sheet's restore
    /// step). Nothing is written until `commitRestore`. Returns the planned counts (created = new items,
    /// updated, skipped = unreadable, limited = held back by the free plan), or nil.
    @discardableResult
    func restorePhoneBackup(url: URL, password: String) async -> ImportOutcome? {
        if pending == nil || passwordRequest?.isPhoneBackup != true || pending?.name != url.lastPathComponent {
            reset()
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            guard let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize else { message = Self.unreadableFile; return nil }
            guard size <= PhoneBackup.maxFileBytes else { message = Self.backupMessage(.tooLarge); return nil }
            guard let data = try? Data(contentsOf: url) else { message = Self.unreadableFile; return nil }
            pending = PendingFile(name: url.lastPathComponent, data: data, format: nil)
            passwordRequest = PasswordRequest(fileName: url.lastPathComponent, prompt: Self.backupPasswordPrompt, isPhoneBackup: true)
        }
        guard let file = pending else { return nil }
        return await openBackup(file, password: password)
    }

    private func openBackup(_ file: PendingFile, password: String) async -> ImportOutcome? {
        guard !password.isEmpty else { passwordRequest?.error = String(localized: "Enter the backup password."); return nil }
        busy = true
        defer { busy = false }
        let data = file.data
        let opened = await Task.detached(priority: .userInitiated) { () -> Result<BackupPayload, PhoneBackup.Error> in
            do { return .success(try PhoneBackup.open(data, password: password)) }
            catch let e as PhoneBackup.Error { return .failure(e) }
            catch { return .failure(.notABackup) }
        }.value
        switch opened {
        case .failure(let e):
            if e == .wrongPassword { passwordRequest?.error = Self.backupMessage(e); return nil }
            reset()
            message = Self.backupMessage(e)
            return nil
        case .success(let payload):
            do {
                let plan = try plan(payload)
                backup = payload
                pending = nil
                passwordRequest = nil
                restore = RestorePreview(fileName: file.name, lines: Self.previewLines(plan))
                return ImportOutcome(created: plan.new, updated: plan.updated, skipped: plan.skipped, limited: plan.heldBack)
            } catch {
                reset()
                message = Self.restoreMessage(error)
                return nil
            }
        }
    }

    private func plan(_ payload: BackupPayload, snapshot: StoreSnapshot? = nil) throws -> (PhoneRestorePlan) {
        let snap = try snapshot ?? store.load()
        let device = try VaultExporter.deviceID(snapshot: snap, installID: fallbackDeviceID)
        let pro = isPro()
        return try PhoneBackup.restoreStates(payload, into: snap, device: device, now: Int64(now().timeIntervalSince1970),
                                             freeSlots: ImportReviewModel.freeSlots(snapshot: snap, isPro: pro),
                                             totpAllowed: pro, licenseKeys: licenseKeys, blobs: blobs)
    }

    /// Merges the opened backup into the vault (planned again against the store as it is now; once more on a
    /// stale store). Never wipes: every item already here is kept unless the phone deleted it.
    @discardableResult
    func commitRestore() async -> ImportOutcome? {
        guard let payload = backup, restore != nil, !busy else { return nil }
        busy = true
        defer { busy = false }
        for attempt in 0..<2 {
            do {
                let snap = try store.load()
                // Documents restore only with their files: verify and store the backup's files first, then plan
                // again against this Mac's files alone, so a refused file leaves its document out.
                var stored = 0, refused = 0
                var p = try plan(payload, snapshot: snap)
                if !p.files.isEmpty, let blobs {
                    let result = PhoneBackup.storeFiles(p, into: blobs)
                    stored = result.stored
                    refused = result.refused.count
                }
                if !payload.files.isEmpty {
                    var withoutFiles = payload
                    withoutFiles.files = [:]
                    p = try plan(withoutFiles, snapshot: snap)
                }
                if p.changes { try commitMovingDeletionsToTrash(snap, p) }
                reset()
                var text = Self.restoredMessage + " " + Self.previewLines(p, done: true).joined(separator: " · ") + "."
                text += Self.fileLines(stored: stored, refused: refused, missing: max(0, p.filesMissing - refused))
                if p.skipped > 0 { text += String(localized: " \(p.skipped) items this version cannot read were skipped.") }
                message = text
                afterChange()
                return ImportOutcome(created: p.new, updated: p.updated, skipped: p.skipped, limited: p.heldBack)
            } catch LocalStoreError.stale where attempt == 0 {
                continue
            } catch {
                message = Self.restoreMessage(error)
                return nil
            }
        }
        return nil
    }

    func cancelRestore() { reset() }

    /// Windows `vault_bridge`: remote deletes move records to the trash and never purge. Every live item the
    /// restore removes is saved to Recently deleted first, then the store is committed; a failed commit takes out
    /// only the rows it added (other saves made meanwhile stay), so an item is never lost from both.
    private func commitMovingDeletionsToTrash(_ snap: StoreSnapshot, _ p: PhoneRestorePlan) throws {
        let change = StoreChange(baseRevision: snap.revision, records: p.records, meta: p.meta, sync: snap.sync)
        let at = Int64(now().timeIntervalSince1970)
        guard let local else {
            guard RemoteDeletes.trashRows(before: snap, records: p.records, meta: p.meta, now: at).isEmpty else {
                throw ImportExportModel.TrashUnavailable()
            }
            try store.commit(change)
            return
        }
        try RemoteDeletes.commit(change, before: snap, local: local, now: at) { try store.commit($0) }
    }

    struct TrashUnavailable: Error {}

    nonisolated static func restoreMessage(_ error: Error) -> String {
        switch error {
        case PhoneBackup.RestoreError.sameDevice: sameDeviceMessage
        case LocalStoreError.stale: String(localized: "Nothing was restored: the vault changed while restoring. Try again.")
        case is TrashUnavailable, is LocalDataError: String(localized: "Nothing was restored: Recently deleted couldn't be updated.")
        default: String(localized: "Nothing was restored: the vault could not be updated.")
        }
    }

    /// Windows `PhoneBackupService.preview` lines.
    nonisolated static func previewLines(_ p: PhoneRestorePlan, done: Bool = false) -> [String] {
        var lines = [String(localized: "\(p.new) new items"), String(localized: "\(p.updated) items updated from the backup")]
        if !done { lines.append(String(localized: "\(p.unchanged) already up to date")) }
        if p.deleted > 0 { lines.append(String(localized: "\(p.deleted) items moved to Recently deleted (deleted on the phone)")) }
        if !done, !p.files.isEmpty { lines.append(String(localized: "\(p.files.count) document files from the backup")) }
        if !done, p.filesMissing > 0 { lines.append(missingFilesLine(p.filesMissing, future: true)) }
        if !done, p.skipped > 0 { lines.append(String(localized: "\(p.skipped) items this version cannot read will be skipped")) }
        if p.heldBack > 0 { lines.append(String(localized: "\(p.heldBack) items held back by the free plan's \(ItemLimit.freeItems)-item limit")) }
        if p.totpAsField > 0 { lines.append(String(localized: "\(p.totpAsField) two-factor keys kept as hidden fields (two-factor codes need Pro)")) }
        return lines
    }

    /// Windows `_missing_text`.
    nonisolated static func missingFilesLine(_ count: Int, future: Bool) -> String {
        switch (count == 1, future) {
        case (true, true): String(localized: "1 document will not be restored: its file is not in this backup")
        case (true, false): String(localized: "1 document was not restored: its file is not in this backup")
        case (false, true): String(localized: "\(count) documents will not be restored: their files are not in this backup")
        case (false, false): String(localized: "\(count) documents were not restored: their files are not in this backup")
        }
    }

    /// The restore report's document file sentences (Windows `PhoneBackupService.commit`).
    nonisolated static func fileLines(stored: Int, refused: Int, missing: Int) -> String {
        var text = ""
        if stored > 0 { text += String(localized: " \(stored) document files restored.") }
        if refused > 0 { text += String(localized: " \(refused) document files were damaged and not restored.") }
        if missing > 0 { text += " " + missingFilesLine(missing, future: false) + "." }
        return text
    }

    // MARK: export

    /// Encrypted `.lgkm` export: checks the password, then asks for the master password, then the save panel.
    func requestEncryptedExport(password: String, confirmation: String, choose: @escaping @MainActor () -> URL?) -> Bool {
        guard checkBackupPassword(password, confirmation: confirmation) else { return false }
        let asked = gate.confirmMasterPassword(title: Self.exportGateTitle, action: String(localized: "Export encrypted backup")) { [weak self] in
            guard let self, let url = choose() else { return }
            self.encryptedAuthorised = true
            self.exportTask = Task { await self.exportEncrypted(to: url, password: password, confirmation: confirmation) }
        }
        if !asked { exportMessage = Self.promptBusyMessage }
        return asked
    }

    /// Another master password prompt is still open (the export was not started).
    nonisolated static let promptBusyMessage = String(localized: "Another password prompt is open. Finish it, then export again.")

    /// The backup password rules (at least 12 characters, both entries equal); `exportMessage` says what is wrong.
    func checkBackupPassword(_ password: String, confirmation: String) -> Bool {
        exportMessage = nil
        guard password.count >= VaultExporter.minPasswordLength else {
            exportMessage = String(localized: "Use at least \(VaultExporter.minPasswordLength) characters."); return false
        }
        guard password.utf8.elementsEqual(confirmation.utf8) else { exportMessage = String(localized: "The passwords don't match."); return false }
        return true
    }

    /// Seals every record (tombstones included) as an `LGKMBAK1` backup and writes it to `url`.
    @discardableResult
    func exportEncrypted(to url: URL, password: String, confirmation: String? = nil) async -> Bool {
        guard encryptedAuthorised else {
            exportMessage = String(localized: "Confirm your master password first.")
            return false
        }
        encryptedAuthorised = false
        exportMessage = nil
        busy = true
        defer { busy = false }
        do {
            let sealed = try await exporter.sealedBackup(password: password, confirmation: confirmation ?? password)
            try write(sealed.data, to: url)
            var text = String(localized: "Encrypted backup saved to \(url.lastPathComponent). It is encrypted with the password you chose.")
            if sealed.filesLeftOut > 0 { text += " " + VaultExporter.filesLeftOutMessage(sealed.filesLeftOut) }
            exportMessage = text
            return true
        } catch VaultExporter.Error.weakPassword {
            exportMessage = String(localized: "Use at least \(VaultExporter.minPasswordLength) characters.")
        } catch VaultExporter.Error.mismatch {
            exportMessage = String(localized: "The passwords don't match.")
        } catch LocalStoreError.stale {
            exportMessage = String(localized: "The vault changed while exporting. Try again.")
        } catch {
            exportMessage = String(localized: "The backup could not be created.")
        }
        return false
    }

    /// Shows the CSV plain-text warning.
    func requestCSVExport() { exportMessage = nil; confirmingCSV = true }

    /// The warning was accepted: the master password next, then the save panel, then the export.
    func acceptCSVWarning(choose: @escaping @MainActor () -> URL?) {
        confirmingCSV = false
        let asked = gate.confirmMasterPassword(title: Self.exportGateTitle, action: String(localized: "Export as CSV")) { [weak self] in
            guard let self else { return }
            guard let url = choose() else { return }
            self.csvAuthorised = true
            self.exportTask = Task { await self.exportCSV(to: url) }
        }
        if !asked { exportMessage = Self.promptBusyMessage }
    }

    /// Writes the Apple Passwords CSV; refused unless the warning and the master password came first (once).
    @discardableResult
    func exportCSV(to url: URL) async -> Bool {
        guard csvAuthorised else {
            exportMessage = String(localized: "Confirm the plain-text warning and your master password first.")
            return false
        }
        csvAuthorised = false
        do {
            try write(Data(try exporter.csvText().utf8), to: url)
            exportMessage = String(localized: "Saved \(url.lastPathComponent). The file is plain text: import it into the destination now, then delete it.")
            return true
        } catch {
            exportMessage = String(localized: "The CSV file could not be created.")
            return false
        }
    }

    private func write(_ data: Data, to url: URL) throws {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        try data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    static func exportFileName(csv: Bool, date: Date = Date()) -> String {
        csv ? "LocalGateKeys-Export-\(VaultExporter.day(date)).csv" : "LocalGateKeys-Backup-\(VaultExporter.day(date)).lgkm"
    }

    #if DEBUG
    /// `LGK_MAC_IMPORT_PREVIEW=review|restore` (screenshots): fixed contents, nothing read or written.
    func showPreview(_ kind: String) {
        reset()
        if kind == "restore" {
            restore = RestorePreview(fileName: "LocalGateKeys-Backup-2026-10-24.lgkm",
                                     lines: ["6 new items", "2 items updated from the backup", "3 already up to date",
                                             "1 items removed (deleted on the phone)"])
            return
        }
        func login(_ title: String, _ host: String, _ user: String, _ pw: String) -> ImportCandidate {
            ImportCandidate(title: title, kind: .login(LoginFields(url: "https://\(host)/", username: user, password: pw,
                                                                  notes: "", otpauth: nil)))
        }
        let result = LGKCore.ImportResult(candidates: [
            login("Example Mail", "mail.example.com", "ada@example.com", "pw-1"),
            login("Shop", "shop.example.net", "ada", "pw-2"),
            login("Shop", "shop.example.net", "ada", "pw-3"),
            login("Bank", "bank.example.org", "ada.l", "pw-4"),
            ImportCandidate(title: "Wi-Fi at home", kind: .note(NoteFields(notes: "Router behind the door"))),
        ], skipped: [ImportSkip(row: 7, message: "Row 7: no password or notes; skipped.")])
        openReview(result, source: ImportReviewModel.formatLabel(.bitwarden))
    }
    #endif
}
