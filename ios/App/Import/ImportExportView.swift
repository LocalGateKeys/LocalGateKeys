import SwiftUI
import UniformTypeIdentifiers
import LocalAuthentication
import AppShared

/// Settings › Import & Export (the Mac's `ImportExportModel`, iPhone flavour): a file picked in Files is
/// detected with `ImportDetect`, asks for its password (Bitwarden password-protected JSON, KeePass `.kdbx`)
/// or its columns (a generic CSV) when needed, then opens the review (`ImportReviewModel`, shared with the
/// Mac); nothing is written until the review is accepted. A phone backup (`.lgkm`, made on an iPhone or an
/// Android phone) asks for its password, shows what restoring it does, then merges like a sync (the Mac's
/// `restorePhoneBackup`): nothing is wiped, items the backup deleted move to Recently deleted.
@MainActor @Observable
final class ImportExportModel {
    static let maxFileBytes = ImportSource.maxArchiveBytes
    static let unknownFormatMessage = String(localized: "This file isn't an export LocalGateKeys can read. Export again from your password manager (CSV, JSON, .1pux, .kdbx, .xml or .zip) and choose that file.")
    static let unreadableFile = String(localized: "That file could not be read.")
    static let importHelp = String(localized: "Choose an export from Safari, Chrome, Edge, Brave, Firefox, Bitwarden, 1Password, LastPass, KeePass, Proton Pass or Dashlane, or any CSV file. You review every row before anything is saved.")

    static let csvWarning = String(localized: "This file is not encrypted. Anyone who gets it can read every password in it.")
    static let passkeysNotInCSV = String(localized: "Passkeys can't go in a CSV file. Only website logins are exported.")
    static let cxfHelp = String(localized: "Writes the items you choose to a Credential Exchange (CXF) file that other password managers can import. The file is not encrypted.")
    static let cxfPasskeyWarning = String(localized: "Passkey private keys are written as plain text too: anyone who can read the file can sign in with your passkeys.")
    static let cxfDeleteAfter = String(localized: "Import the file into the destination app right away, then delete it. Cloud-synced folders and backups may keep copies.")
    static let cxfDeclined = String(localized: "The Face ID, Touch ID or passcode check did not succeed; nothing was exported.")
    static let cxfReason = String(localized: "Export to a CXF file")

    /// The picker's file types: CSV, JSON, 1Password `.1pux`, KeePass `.kdbx`/`.xml`, and `.zip` (Dashlane, Proton Pass).
    /// `.data` last: `.1pux` and `.kdbx` are not declared types, so Files could grey them out; `ImportDetect`
    /// reads the content and refuses anything else.
    static var importTypes: [UTType] {
        var types: [UTType] = [.commaSeparatedText, .json, .xml, .zip, .plainText, .data]
        for ext in ["1pux", "kdbx", "csv", "lgkm"] {
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
        var isPhoneBackup = false
    }

    /// A phone backup ready to restore: the preview lines, then Restore.
    struct RestorePreview: Identifiable, Equatable {
        let id = UUID()
        let fileName: String
        let lines: [String]
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
        /// nil: a phone backup.
        let format: ImportFormat?
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
    /// The switch report of the import just saved (feature pack §6.1), shown in the import sheet until Done.
    private(set) var report: ImportReport?
    /// The format label of the file under review.
    private(set) var reviewSource = ""
    var passwordRequest: PasswordRequest?
    var mappingRequest: MappingRequest?
    private(set) var restore: RestorePreview?
    @ObservationIgnored private var pending: PendingFile?
    @ObservationIgnored private var backup: BackupPayload?
    /// The keychain install id (a backup outside a sync group carries a UUID5 of it); the exporter's when nil.
    @ObservationIgnored private let fallbackDeviceID: (() throws -> String)?
    /// Recently deleted: items a restored backup deletes land here first (nil: none, deletions are refused).
    @ObservationIgnored private let local: (any PhoneLocalHosting)?
    /// This iPhone's attachment files: a restore stores the backup's document files here (format 2).
    @ObservationIgnored private let blobs: (any AttachmentBlobStore)?
    @ObservationIgnored private let licenseKeys: [String: [UInt8]]
    /// Face ID, Touch ID or the passcode, asked before a CXF file is made (its reason is shown in the prompt).
    @ObservationIgnored private let confirmOwner: @MainActor (String) async -> Bool
    /// What a CXF file can hold (titles only), loaded when its sheet opens.
    private(set) var cxfChoices: [VaultExporter.CXFChoice] = []
    /// Why the CXF export made nothing (shown in its sheet).
    var cxfMessage: String?

    init(importer: VaultImporter, exporter: VaultExporter? = nil, fallbackDeviceID: (() throws -> String)? = nil,
         local: (any PhoneLocalHosting)? = nil, blobs: (any AttachmentBlobStore)? = nil,
         licenseKeys: [String: [UInt8]] = LicenseKeys.production,
         confirmOwner: (@MainActor (String) async -> Bool)? = nil) {
        self.importer = importer; self.exporter = exporter
        self.fallbackDeviceID = fallbackDeviceID ?? exporter?.fallbackDeviceID
        self.local = local; self.blobs = blobs; self.licenseKeys = licenseKeys
        self.confirmOwner = confirmOwner ?? { reason in await ImportExportModel.deviceOwnerCheck(reason) }
    }

    /// `.deviceOwnerAuthentication`: Face ID or Touch ID, with the passcode as fallback. False without a passcode.
    /// With the app password on, `AppPasswordGate` instead (never the passcode).
    static func deviceOwnerCheck(_ reason: String) async -> Bool {
        await AppPasswordGate.confirmOwner(reason)   // says why when it cannot run (review L3)
    }

    var canExport: Bool { exporter != nil }

    /// Drops the file, the password request, the columns and the review (Cancel).
    func reset() {
        pending = nil; review = nil; reviewSource = ""; passwordRequest = nil; mappingRequest = nil; report = nil
        restore = nil; backup = nil; cxfChoices = []; cxfMessage = nil
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
            let isBackupName = url.pathExtension.lowercased() == "lgkm"
            guard size <= (isBackupName ? PhoneBackup.maxFileBytes : Self.maxFileBytes) else {
                message = isBackupName ? Self.backupMessage(.tooLarge) : ImportError.tooLarge.message; return
            }
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

    /// The password for the pending encrypted file; a wrong one asks again.
    func submitPassword(_ password: String) async {
        guard let file = pending, let request = passwordRequest, !busy else { return }
        if request.isPhoneBackup { _ = await openBackup(file, password: password); return }
        guard !password.isEmpty else { passwordRequest?.error = String(localized: "Enter the file's password."); return }
        guard let format = file.format else { return }
        await run(format: format, options: ImportOptions(password: password))
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
            review?.source = format.rawValue
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
            // The switch report (feature pack §6.1): counts read back from the store, and the journal for the undo.
            if let journal = review.journal { Self.saveJournal(journal, local: local) }
            if let committed = try? importer.store.load() {
                report = ImportUndo.report(review.journal, committed: committed, skipped: review.skipReasons,
                                           now: Int64(importer.now().timeIntervalSince1970))
            }
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

    /// A password, columns, review or report step is waiting (the import sheet is on screen).
    var hasImportStep: Bool {
        passwordRequest != nil || mappingRequest != nil || review != nil || restore != nil || report != nil
    }

    // MARK: import report and undo (feature pack §6.1)

    func closeReport() { report = nil }

    /// Keeps `journal` as this device's last import (a new import that wrote something replaces the earlier one).
    static func saveJournal(_ journal: ImportJournal, local: (any PhoneLocalHosting)?) {
        guard let local, var data = local.localData else { return }
        data.lastImport = journal
        try? local.commitLocalData(data)
    }

    /// The last import while it can still be undone (one level, 7 days).
    var undoableImport: ImportJournal? {
        guard let j = local?.localData?.lastImport, j.isUndoable(now: Int64(importer.now().timeIntervalSince1970)) else {
            return nil
        }
        return j
    }

    /// Undoes the last import: what it added moves to Recently deleted, what it replaced gets its earlier version
    /// back, and anything changed since is kept. The journal is removed afterwards.
    func undoLastImport(trash: PhoneTrash?) {
        guard let local, let journal = undoableImport, let trash, !busy else { return }
        let outcome = ImportUndo.undo(journal, store: importer.store, now: Int64(importer.now().timeIntervalSince1970),
                                      moveToTrash: { trash.moveToTrash(ids: $0) })
        if !outcome.failed, var data = local.localData {
            data.lastImport = nil
            try? local.commitLocalData(data)
        }
        if outcome.trashed + outcome.restored > 0 { importer.afterCommit() }
        report = nil
        message = ImportUndo.message(outcome)
    }

    /// The Mac's summary line.
    static func summary(_ o: ImportOutcome, limitNote: String) -> String {
        var text = String(localized: "\(o.created + o.updated) record(s) written. Added \(o.created), updated \(o.updated), skipped \(o.skipped).")
        if o.limited > 0 { text += " " + (limitNote.isEmpty ? String(localized: "\(o.limited) row(s) need Pro.") : limitNote + ".") }
        return text
    }

    // MARK: phone backup restore

    static let restoreHelp = String(localized: "Restore a phone backup made with LocalGateKeys (.lgkm). It is merged into this vault like a sync: nothing here is deleted unless the backup deleted it, and nothing newer is overwritten.")
    static let backupPasswordPrompt = String(localized: "Enter the backup password (it is used once and not stored):")
    static let wrongBackupPassword = String(localized: "Wrong password, or the file is damaged.")
    static let sameDeviceMessage = DeviceText.isPad ? String(localized: "ipad.importExportView.backupWasMadeSo", defaultValue: "This backup was made on this iPad, so there is nothing to restore.") : String(localized: "This backup was made on this iPhone, so there is nothing to restore.")
    static let restoredMessage = String(localized: "Phone backup restored.")

    static func backupMessage(_ e: PhoneBackup.Error) -> String {
        switch e {
        case .tooLarge: String(localized: "This file is too large to be a phone backup.")
        case .notABackup: String(localized: "This is not a LocalGateKeys phone backup.")
        case .unsupportedVersion: String(localized: "This backup was made by a newer version of LocalGateKeys. Update the app and try again.")
        case .badKDF: String(localized: "This backup uses unsupported password-protection settings.")
        case .wrongPassword: wrongBackupPassword
        case .badPayload: String(localized: "The backup was opened but its contents are not valid.")
        }
    }

    /// The backup envelope's first bytes (the Mac's `looksLikePhoneBackup`), so a renamed file is still found.
    nonisolated static func looksLikePhoneBackup(_ data: Data) -> Bool {
        data.prefix(32).starts(with: Array(#"{"ciphertext":"#.utf8))
    }

    /// Opens the backup with its password and shows what restoring it does. Nothing is written until
    /// `commitRestore`. Returns the planned counts (created = new items, limited = held back by the free plan).
    @discardableResult
    func restorePhoneBackup(url: URL, password: String) async -> ImportOutcome? {
        if pending == nil || passwordRequest?.isPhoneBackup != true || pending?.name != url.lastPathComponent {
            reset()
            message = nil
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

    /// The backup as it is merged here. A backup this iPhone made (same device id) restores nothing into a vault
    /// that has data (`sameDevice`); into an empty vault (the app was reinstalled, or the vault erased) it is
    /// restored as if from another device, under a stable id derived from its own.
    nonisolated static func restorable(_ payload: BackupPayload, into snapshot: StoreSnapshot, device: String) -> BackupPayload {
        // Empty: no item and no licence (collection states alone, e.g. the starters, don't count).
        guard payload.deviceID == device, snapshot.itemRecords.isEmpty else { return payload }
        var copy = payload
        copy.deviceID = UUID5.string(UUID5.make(namespace: VaultExporter.deviceNamespace, name: "restored:" + payload.deviceID))
        return copy
    }

    private func plan(_ payload: BackupPayload, snapshot: StoreSnapshot? = nil) throws -> PhoneRestorePlan {
        let snap = try snapshot ?? importer.store.load()
        guard let fallbackDeviceID else { throw PhoneBackup.RestoreError.failed("no-device") }
        let device = try VaultExporter.deviceID(snapshot: snap, installID: fallbackDeviceID)
        let pro = importer.isPro()
        return try PhoneBackup.restoreStates(Self.restorable(payload, into: snap, device: device), into: snap, device: device,
                                             now: Int64(importer.now().timeIntervalSince1970),
                                             freeSlots: ImportReviewModel.freeSlots(snapshot: snap, isPro: pro),
                                             totpAllowed: pro, licenseKeys: licenseKeys, blobs: blobs)
    }

    /// Merges the opened backup into the vault (planned again against the store as it is now; once more on a
    /// stale store). Never wipes: every item already here is kept unless the backup deleted it.
    @discardableResult
    func commitRestore() async -> ImportOutcome? {
        guard let payload = backup, restore != nil, !busy else { return nil }
        busy = true
        defer { busy = false }
        for attempt in 0..<2 {
            do {
                let snap = try importer.store.load()
                // Documents restore only with their files: verify and store the backup's files first, then plan
                // again against this iPhone's files alone, so a refused file leaves its document out.
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
                if p.changes { importer.afterCommit() }
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

    struct TrashUnavailable: Error {}

    /// Live logins and typed items in `before` that `records`/`meta` no longer hold live, as trash rows (the Mac's
    /// `RemoteDeletes.trashRows`).
    nonisolated static func trashRows(before: StoreSnapshot, records: [String: JSONValue], meta: [String: SyncMeta],
                                      now: Int64) -> [LocalData.TrashRow] {
        RemovedItems.trashRows(before: before, records: records, meta: meta, now: now)
    }

    /// Every live item the restore removes is saved to Recently deleted first, then the store is committed; a
    /// failed commit takes out only the rows it added, so an item is never lost from both (the Mac's
    /// `RemoteDeletes.commit`).
    private func commitMovingDeletionsToTrash(_ snap: StoreSnapshot, _ p: PhoneRestorePlan) throws {
        let change = StoreChange(baseRevision: snap.revision, records: p.records, meta: p.meta, sync: snap.sync)
        let rows = Self.trashRows(before: snap, records: p.records, meta: p.meta, now: Int64(importer.now().timeIntervalSince1970))
        guard !rows.isEmpty else { try importer.store.commit(change); return }
        guard let local, var data = local.localData else { throw TrashUnavailable() }
        data.trash += rows
        try local.commitLocalData(data)
        do { try importer.store.commit(change) } catch {
            if var back = local.localData {
                for row in rows { if let i = back.trash.lastIndex(of: row) { back.trash.remove(at: i) } }
                try? local.commitLocalData(back)
            }
            throw error
        }
    }

    static func restoreMessage(_ error: Error) -> String {
        switch error {
        case PhoneBackup.RestoreError.sameDevice: sameDeviceMessage
        case LocalStoreError.stale: String(localized: "Nothing was restored: the vault changed while restoring. Try again.")
        case is TrashUnavailable, is LocalDataError: String(localized: "Nothing was restored: Recently deleted couldn't be updated.")
        default: String(localized: "Nothing was restored: the vault could not be updated.")
        }
    }

    /// The Mac's preview lines (Windows `PhoneBackupService.preview`).
    static func previewLines(_ p: PhoneRestorePlan, done: Bool = false) -> [String] {
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

    static func missingFilesLine(_ count: Int, future: Bool) -> String {
        switch (count == 1, future) {
        case (true, true): String(localized: "1 document will not be restored: its file is not in this backup")
        case (true, false): String(localized: "1 document was not restored: its file is not in this backup")
        case (false, true): String(localized: "\(count) documents will not be restored: their files are not in this backup")
        case (false, false): String(localized: "\(count) documents were not restored: their files are not in this backup")
        }
    }

    static func fileLines(stored: Int, refused: Int, missing: Int) -> String {
        var text = ""
        if stored > 0 { text += String(localized: " \(stored) document files restored.") }
        if refused > 0 { text += String(localized: " \(refused) document files were damaged and not restored.") }
        if missing > 0 { text += " " + missingFilesLine(missing, future: false) + "." }
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

    /// The same owner check as the CXF export before the CSV is written: the app password (or its Face ID
    /// shortcut) when it is on, otherwise Face ID, Touch ID or the passcode (audit 2026-11-10, scan APL-I2).
    func confirmCSVExport() async -> Bool {
        await confirmOwner(String(localized: "Export as CSV"))
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

    /// Lists the logins, notes and passkeys a CXF file can hold (nothing selected).
    func loadCXFChoices() {
        cxfMessage = nil
        guard let exporter else { cxfChoices = []; return }
        do { cxfChoices = try exporter.cxfChoices() } catch {
            cxfChoices = []
            cxfMessage = VaultExporter.cxfFailedMessage
        }
    }

    /// Writes the selected items (`ids`, only those) to a temporary CXF file, after Face ID, Touch ID or the
    /// passcode; nil (and `cxfMessage` set) when the check is declined or the export fails: nothing is written
    /// then. What the file left out goes to `exportMessage`.
    func exportCXF(ids: [String]) async -> URL? {
        guard let exporter, !exporting else { return nil }
        cxfMessage = nil
        exporting = true
        defer { exporting = false }
        do {
            try exporter.cxfCheck(ids: ids)
        } catch let e as CXFExport.Failure {
            cxfMessage = VaultExporter.cxfFailure(e); return nil
        } catch {
            cxfMessage = VaultExporter.cxfFailedMessage; return nil
        }
        guard await confirmOwner(Self.cxfReason) else {
            cxfMessage = Self.cxfDeclined; return nil
        }
        do {
            let file = try exporter.cxf(ids: ids)
            let notes = file.diagnostics.map { VaultExporter.cxfDiagnostic($0) }
            exportMessage = notes.isEmpty ? nil : notes.joined(separator: "\n")
            return file.url
        } catch let e as CXFExport.Failure {
            cxfMessage = VaultExporter.cxfFailure(e)
        } catch {
            cxfMessage = VaultExporter.cxfFailedMessage
        }
        return nil
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
    @State private var choosingCXF = false
    @State private var shared: SharedFile?
    /// The temporary file on screen, deleted when the share sheet closes.
    @State private var exported: URL?
    /// Recently deleted: an import's undo moves what it added there.
    @Environment(\.phoneTrash) private var trash
    @State private var confirmingUndo = false

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
                VStack(alignment: .leading, spacing: 4) {
                    Button("Restore from a backup") { picking = true }
                        .foregroundStyle(Palette.accentText).disabled(model.busy)
                    Text(ImportExportModel.restoreHelp)
                        .font(.footnote).foregroundStyle(Palette.secondaryText)
                }
                if model.undoableImport != nil, trash != nil {
                    VStack(alignment: .leading, spacing: 4) {
                        Button(ImportReport.undoLabel) { confirmingUndo = true }
                            .foregroundStyle(Palette.accentText).disabled(model.busy)
                        Text(ImportReport.undoHelp)
                            .font(.footnote).foregroundStyle(Palette.secondaryText)
                    }
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
                if let message = model.message, model.review == nil, model.mappingRequest == nil, model.restore == nil { Text(message) }
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
                VStack(alignment: .leading, spacing: 4) {
                    Button("Export to a CXF file…") { choosingCXF = true }
                        .foregroundStyle(Palette.accentText)
                    Text(ImportExportModel.cxfHelp)
                        .font(.footnote).foregroundStyle(Palette.secondaryText)
                }
            } header: {
                Text("Export")
            } footer: {
                if let message = model.exportMessage { Text(message) }
                else { Text("Restore an encrypted backup on any phone or computer with LocalGateKeys.") }
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
        .sheet(isPresented: $choosingCXF) {
            CXFExportSheet(model: model) { url in
                choosingCXF = false
                shared = SharedFile(url: url)
            }
            .interactiveDismissDisabled(model.exporting)
        }
        .confirmationDialog(ImportReport.undoLabel, isPresented: $confirmingUndo, titleVisibility: .visible) {
            Button(ImportReport.undoLabel, role: .destructive) { model.undoLastImport(trash: trash) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(ImportReport.undoHelp)
        }
        .alert("Export as CSV?", isPresented: $confirmingCSV) {
            Button("Export", role: .destructive) {
                Task {
                    guard await model.confirmCSVExport() else { return }
                    if let url = model.exportCSV() { shared = SharedFile(url: url) }
                }
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

/// Export to a CXF file: the plain-text warnings, the logins, notes and passkeys to choose (titles only), then
/// Export: Face ID, Touch ID or the passcode, then the share sheet. Declined: nothing is written.
private struct CXFExportSheet: View {
    let model: ImportExportModel
    let done: (URL) -> Void
    @State private var selected: Set<String> = []
    @Environment(\.dismiss) private var dismiss

    private var allSelected: Bool { !model.cxfChoices.isEmpty && selected.count == model.cxfChoices.count }
    private var passkeySelected: Bool { model.cxfChoices.contains { $0.kind == .passkey && selected.contains($0.id) } }

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
            List {
                Section {
                    Text(ImportExportModel.csvWarning)
                    if passkeySelected { Text(ImportExportModel.cxfPasskeyWarning) }
                    Text(ImportExportModel.cxfDeleteAfter)
                }
                .font(.footnote)
                .listRowBackground(Palette.groupSurface)
                // At the top, not in a footer below every item: a declined Face ID or a failed export must be seen.
                if let message = model.cxfMessage {
                    Section {
                        Label(message, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(Palette.danger)
                            .accessibilityIdentifier("cxf-export-message")
                    }
                    .id("cxf-export-message")
                    .listRowBackground(Palette.groupSurface)
                }
                if model.cxfChoices.isEmpty {
                    Section {
                        Text("There are no logins, notes or passkeys to export.").foregroundStyle(Palette.secondaryText)
                    }
                    .listRowBackground(Palette.groupSurface)
                } else {
                    Section {
                        Button(allSelected ? String(localized: "Select none") : String(localized: "Select all")) {
                            selected = allSelected ? [] : Set(model.cxfChoices.map(\.id))
                        }
                        .foregroundStyle(Palette.accentText)
                        ForEach(model.cxfChoices) { choice in row(choice) }
                    } header: {
                        Text("Choose the items to export to the CXF file.")
                    }
                    .listRowBackground(Palette.groupSurface)
                }
                if model.exporting {
                    ProgressView().frame(maxWidth: .infinity).listRowBackground(Color.clear)
                }
            }
            .scrollContentBackground(.hidden)
            .onChange(of: model.cxfMessage) { _, message in
                guard let message else { return }
                withAnimation { proxy.scrollTo("cxf-export-message", anchor: .top) }
                AccessibilityNotification.Announcement(message).post()
            }
            }
            .lgkAuroraBackground()
            .disabled(model.exporting)
            .navigationTitle("Export to CXF")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(model.exporting)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Export") {
                        let ids = model.cxfChoices.map(\.id).filter { selected.contains($0) }
                        Task {
                            if let url = await model.exportCXF(ids: ids) { done(url) }
                        }
                    }
                    .disabled(selected.isEmpty || model.exporting)
                }
            }
        }
        .onAppear { selected = []; model.loadCXFChoices() }
    }

    private func row(_ choice: VaultExporter.CXFChoice) -> some View {
        let on = selected.contains(choice.id)
        return Button {
            if on { selected.remove(choice.id) } else { selected.insert(choice.id) }
            model.cxfMessage = nil
        } label: {
            HStack(spacing: 12) {
                Image(systemName: on ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(on ? Palette.accentText : Palette.secondaryText)
                Image(systemName: Self.symbol(choice.kind)).foregroundStyle(Palette.secondaryText).frame(width: 22)
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: choice.title).foregroundStyle(Palette.text)
                    if !choice.detail.isEmpty {
                        Text(verbatim: choice.detail).font(.footnote).foregroundStyle(Palette.secondaryText)
                    }
                }
                Spacer(minLength: 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(on ? .isSelected : [])
    }

    static func symbol(_ kind: VaultExporter.CXFChoice.Kind) -> String {
        switch kind {
        case .login: "key"
        case .note: "note.text"
        case .passkey: "person.badge.key"
        }
    }
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
