import Foundation
import Darwin
import Observation
import CryptoKit
import AppSharedMac

/// Full backups on the Mac (Windows `recovery.py` `create_recovery_backup` / `verify_recovery_backup` /
/// restore, `backup.py` full backup v2). A Mac full backup holds a Windows-format `vault.json` sealed with the
/// master password (Ruling 1), Windows' `settings.json` and the attachment sidecars, so Windows restores it with
/// its own code; `<file>.sha256.json` is written beside it.
///
/// Restore replaces the whole vault (Ruling 2: "as a new profile" comes with profiles). It is explicit: preview
/// first, then the master password through the strict gate, then `stage` (the restored records, sealed, plus the
/// attachments and `desktop-profile.bin`, written to a staging folder and read back), then the swap:
///
/// 1. a safety copy of the vault as it is goes to `Backups/before-restore-<ms>/` (Windows
///    `_full_make_pre_restore_backup`), sealed under the vault's key; the newest 5 are kept, never deleted at unlock,
///    and each can be restored through the same gated path (`safetyCopies`, `requestRestore(safetyCopy:)`);
/// 2. `restore-in-progress.json` is written;
/// 3. the attachment folder and `desktop-profile.bin` are swapped in;
/// 4. the records are committed through `lock.store` (the commit point; items the backup lacks go to Recently
///    deleted); a failed commit puts step 3 back;
/// 5. the marker is removed. After a crash between 2 and 5, the next unlock (`finishInterruptedRestore`) keeps the
///    restore if the store's revision shows the commit landed, else puts the attachments and profile file back from
///    the safety copy.
///
/// Restored records are not sanitised yet: Windows (`backup.py` `_sanitize_restored_session`) sets every login's
/// `policy.sign_in` to `never` and drops desktop fill approvals. The Mac has no automatic sign-in, so changing them
/// would only make every record look edited to sync; once the Mac gains automatic sign-in, restore must do the same.
///
/// Sandbox: the backup and its `.sha256.json` sit side by side, so the caller passes a file inside a folder the
/// app may write (an `NSOpenPanel` folder or a bookmarked folder), not a lone `NSSavePanel` file.
@MainActor @Observable
final class MacFullBackup {
    nonisolated static let backupsName = "Backups"
    nonisolated static let safetyPrefix = "before-restore-"
    nonisolated static let safetyKeep = 5
    nonisolated static let markerName = "restore-in-progress.json"
    nonisolated static let stagingPrefix = "restore-staging-"
    nonisolated static let sameDiskWarning = String(localized: "The backup destination appears to be on the same disk as the live profile.")
    nonisolated static let restoreGateTitle = String(localized: "Restoring a full backup")
    nonisolated static let promptBusyMessage = String(localized: "Another password prompt is open. Finish it, then restore again.")
    nonisolated static let notAuthorised = RecoveryError(String(localized: "Confirm your master password first."))
    nonisolated static let busyMessage = String(localized: "A backup or restore is already running")
    nonisolated static let restoredMessage = String(localized: "Full backup restored. A safety copy of the vault as it was is kept on this Mac.")
    /// The desktop data kept from a restored Windows backup can't be read (`desktop-profile.bin` damaged).
    nonisolated static let keptDataUnreadable = RecoveryError(
        String(localized: "The Windows data kept on this Mac (attachments, documents and settings from a restored Windows backup) can't be read. You can back up without it: every item is still included."))
    /// Windows' rollback check (`vault._check_rollback`): a vault from another device starts at generation 1.
    nonisolated static let otherDeviceNote = String(localized: "When you restore this backup on a Windows PC, LocalGateKeys asks you to confirm once more, because the backup was made on another device.")
    nonisolated static let restoreGuide = RecoveryKit.defaultRestoreGuide + " " + otherDeviceNote

    /// Windows `default_backup_filename`: `LocalGateKeys-backup-YYYY-MM-DD-HHMMSS.lgk`, local time.
    nonisolated static func defaultFileName(now: Date = Date()) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd-HHmmss"
        return "LocalGateKeys-backup-\(f.string(from: now)).lgk"
    }

    /// A restore written into the staging folder and read back, not yet swapped in.
    struct StagedRestore: Sendable {
        let folder: URL
        let preview: RestorePreview?
        let records: [String: JSONValue]
        let contents: DesktopProfileStore.Contents
    }

    /// A copy of the vault kept before a restore (newest first from `safetyCopies`).
    struct SafetyCopy: Equatable, Sendable {
        let folder: URL
        /// Unix milliseconds.
        let createdAtMillis: Int64
        var name: String { folder.lastPathComponent }
    }

    /// Test seam: where a simulated crash stops a restore (nothing after it runs, nothing is put back).
    #if DEBUG
    enum CrashPoint: Sendable { case afterPiecesSwapped, afterCommit }
    struct SimulatedCrash: Error {}
    #endif

    /// One backup or restore at a time across every instance (the window's and the schedule's).
    private static var inFlight = false
    private(set) var busy = false { didSet { Self.inFlight = busy } }
    /// True while any instance is making a backup or restoring one.
    static var anyInFlight: Bool { inFlight }
    #if DEBUG
    /// Tests: a backup or restore in flight without running one.
    static func setInFlightForTesting(_ on: Bool) { inFlight = on }
    #endif
    /// The last notice (or why it failed).
    var message: String?
    /// The running gated restore (tests wait on it).
    @ObservationIgnored private(set) var restoreTask: Task<Bool, Never>?

    @ObservationIgnored private let store: any ItemStore
    @ObservationIgnored private let profile: DesktopProfileStore
    @ObservationIgnored private let passwords: any MasterPasswordService
    @ObservationIgnored private let gate: StrictItemGate
    @ObservationIgnored private let local: (any LocalDataHosting)?
    @ObservationIgnored private let deviceName: String
    @ObservationIgnored private let licenseKeys: [String: [UInt8]]
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private let random: any RandomSource
    @ObservationIgnored private let kdf: FullBackupV2.KDF
    @ObservationIgnored private let vaultKDF: FullBackupV2.KDF
    /// This Mac's attachment files (task 12): `AttachmentFiles.localFolder()` in the app, a temporary folder in
    /// tests, nil to leave documents out of backups (and keep restored ones as desktop data).
    @ObservationIgnored private let attachmentFolder: BlobFolder?
    #if DEBUG
    /// Test seam: runs after the staging folder is verified, before the swap.
    @ObservationIgnored var beforeSwap: () throws -> Void = {}
    @ObservationIgnored var crashPoint: CrashPoint?
    #endif
    /// Runs after a restore (reload the list, refresh Pro).
    @ObservationIgnored var afterChange: () -> Void = {}
    /// Set only by the strict gate, used by one restore.
    @ObservationIgnored private var restoreAuthorised = false

    /// `kdf`/`vaultKDF` other than `.default` are for tests.
    init(store: any ItemStore, profile: DesktopProfileStore, passwords: any MasterPasswordService, gate: StrictItemGate,
         local: (any LocalDataHosting)?, deviceName: String = MacSyncEnvironment.deviceName(),
         licenseKeys: [String: [UInt8]] = LicenseKeys.production,
         now: @escaping () -> Date = Date.init, random: any RandomSource = SystemRandomSource(),
         kdf: FullBackupV2.KDF = .default, vaultKDF: FullBackupV2.KDF = .default,
         attachmentFolder: BlobFolder? = nil) {
        self.store = store; self.profile = profile; self.passwords = passwords; self.gate = gate; self.local = local
        self.deviceName = deviceName; self.licenseKeys = licenseKeys; self.now = now; self.random = random
        self.kdf = kdf; self.vaultKDF = vaultKDF
        self.attachmentFolder = attachmentFolder
    }

    private var unixNow: Int64 { Int64(now().timeIntervalSince1970) }
    private var directory: URL { profile.directory }

    // MARK: create

    /// Writes a full backup of this vault to `url` and `<url>.sha256.json`, after checking the master password (the
    /// unlock throttle applies) and that the backup password is a different one. The file is written to a staging
    /// name beside `url`, opened and checked in full, then renamed into place; an existing good backup at `url`
    /// stays until then. When the kept Windows data can't be read this throws `keptDataUnreadable`; with
    /// `withoutKeptData` (the person confirmed) the backup goes ahead with the items only.
    func create(to url: URL, backupPassword: String, masterPassword: String,
                withoutKeptData: Bool = false) async throws -> BackupInventory {
        guard !backupPassword.utf8.elementsEqual(masterPassword.utf8) else { throw RecoveryError.samePassword }
        guard !Self.inFlight else { throw RecoveryError(Self.busyMessage) }
        busy = true
        defer { busy = false }
        // Checks the master password; with a recovery phrase enrolled, the backup's vault.json opens with it too (Ruling 9).
        var recoveryKey = try await passwords.recoveryVaultKey(password: masterPassword)
        defer { recoveryKey?.wipe() }
        let inventory = try await write(to: url, encryption: .password(backupPassword), vault: .password(masterPassword),
                                        recovery: recoveryKey, withoutKeptData: withoutKeptData)
        message = String(localized: "Full backup saved to \(url.lastPathComponent) and checked.") + " " + Self.otherDeviceNote
        return inventory
    }

    /// How the backup's `vault.json` is sealed and opened: the master password, or a key derived from it earlier
    /// (scheduled backups, which run unattended).
    enum VaultCredential: Sendable {
        case password(String)
        case key(DesktopVaultFile.PasswordKey)
    }

    /// How the backup itself is encrypted: a backup password (manual backups, full backup v2, unchanged) or the
    /// public backup key record (scheduled backups, full backup v3; design `backup-public-key-2026-10-31.md`).
    enum Encryption: Sendable {
        case password(String)
        case publicKey(BackupKeyRecord)
    }

    /// A scheduled backup (Task 9): a full backup **v3** to the record's public key, with the `vault.json` sealed by
    /// the stored password key (and the stored recovery key), written to a staging name, checked without any password
    /// (design 9.1: the wrap with the ephemeral key, every member with the data key, the vault layer with the password
    /// key), renamed, then its `.sha256.json`. Nothing is asked: the schedule's record was checked when it was set.
    func createScheduled(to url: URL, record: BackupKeyRecord, passwordKey: DesktopVaultFile.PasswordKey,
                         recovery: RecoveryWrapper.VaultKey?) async throws -> BackupInventory {
        guard !Self.inFlight else { throw RecoveryError(Self.busyMessage) }
        busy = true
        defer { busy = false }
        return try await write(to: url, encryption: .publicKey(record), vault: .key(passwordKey), recovery: recovery,
                               withoutKeptData: false)
    }

    private func write(to url: URL, encryption: Encryption, vault credential: VaultCredential,
                       recovery recoveryKey: RecoveryWrapper.VaultKey?, withoutKeptData: Bool) async throws -> BackupInventory {
        let snap = try store.load()
        var kept = DesktopProfileStore.Contents.empty
        var attachments: [(id: String, data: Data)] = []
        do {
            kept = try profile.load()
            attachments = try profile.attachments()
        } catch {
            guard withoutKeptData else { throw Self.keptDataUnreadable }
            kept = .empty
            attachments = []
        }
        // A profile restored before minor 7 was fixed may still keep Windows share secrets: never export them.
        var payload = Self.withoutDeviceSecrets(kept.payload)
        // This Mac's documents (task 12): each file as a Windows sidecar plus its catalog row, as Windows' full
        // backups carry them, so a Windows restore finds every document's file. A document whose file is not on
        // this Mac is left out (Windows refuses a document without its catalog row).
        var skippedDocuments = Set<String>()
        let documents = snap.itemRecords.sorted(by: { $0.key < $1.key }).filter {
            Self.isLiveItem($0.value, snap) && AttachmentDocuments.isDocument($0.value)
        }.map { (record: Self.record($0.value), wrapper: $0.value) }
        if !documents.isEmpty {
            if let blobs = attachmentFolder {
                let storeID: String
                if case .string(let s)? = payload["attachment_store_id"], AttachmentSync.isCanonicalUUID(s) { storeID = s } else {
                    storeID = UUID().uuidString.lowercased()
                    payload["attachment_store_id"] = .string(storeID)
                }
                var rows: [JSONValue] = { if case .array(let a)? = payload["attachments"] { return a }; return [] }()
                let existing = Set(rows.compactMap { row -> String? in
                    if case .object(let o) = row, case .string(let id)? = o["id"] { return id }; return nil
                })
                let made = DesktopAttachmentSidecar.backupRows(documents: documents, existing: existing, storeID: storeID,
                                                               blobs: blobs, random: self.random)
                rows += made.rows
                payload["attachments"] = .array(rows)
                attachments += made.sidecars
                skippedDocuments = made.skipped
            } else {
                skippedDocuments = Set(documents.compactMap { if case .object(let r) = $0.record, case .string(let id)? = r["id"] { return id }; return nil })
            }
        }
        var items: [JSONValue] = kept.unsynced
        for (id, wrapper) in snap.itemRecords.sorted(by: { $0.key < $1.key }) where Self.isLiveItem(wrapper, snap) && !skippedDocuments.contains(id) {
            if case .object(let w) = wrapper, let r = w["record"] { items.append(r) }
        }
        // This Mac's licence goes in as the catalog's licence copy, as Windows keeps it (`vault.py` `license`).
        if let licence = Self.licenceBundle(snap) { payload["license"] = licence }
        let settings = kept.settings ?? Data("{}".utf8)
        let name = kept.profileName ?? deviceName
        let (random, kdf, vaultKDF, created) = (self.random, self.kdf, self.vaultKDF, unixNow)
        let backupItems = items
        let backupAttachments = attachments
        let backupPayload = payload
        let backupRecovery = recoveryKey
        var (data, written) = try await Task.detached(priority: .userInitiated) { () throws -> (Data, FullBackupV3.Written?) in
            let vault: Data
            switch credential {
            case .password(let masterPassword):
                vault = try DesktopVaultFile.seal(items: backupItems, settings: .object(backupPayload), password: masterPassword,
                                                  random: random, now: created, kdf: vaultKDF, recovery: backupRecovery)
            case .key(let key):
                vault = try DesktopVaultFile.seal(items: backupItems, settings: .object(backupPayload), passwordKey: key,
                                                  random: random, now: created, recovery: backupRecovery)
            }
            switch encryption {
            case .password(let backupPassword):
                return (try FullBackupV2.write(vault: vault, settings: settings, attachments: backupAttachments, password: backupPassword,
                                               random: random, progress: { _, _, _ in }, cancel: { false },
                                               profileName: name, createdAt: created, kdf: kdf), nil)
            case .publicKey(let record):
                let w = try FullBackupV3.write(vault: vault, settings: settings, attachments: backupAttachments, record: record,
                                               random: random, progress: { _, _, _ in }, cancel: { false },
                                               profileName: name, createdAt: created)
                return (w.data, w)
            }
        }.value
        // The writer keeps dk and esk only until the self-verify below has run (design 9.1).
        defer { written?.wipe() }
        let folder = url.deletingLastPathComponent()
        let staging = folder.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).staging")
        defer { try? FileManager.default.removeItem(at: staging) }
        do { try data.write(to: staging, options: .withoutOverwriting) } catch { throw RecoveryError(String(localized: "Could not create the recovery backup")) }
        data = Data()
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: staging.path)
        // Authenticate every member and the vault layer before reporting success (Windows `_preflight`).
        var inventory: BackupInventory
        switch encryption {
        case .password(let backupPassword):
            inventory = try await Self.check(staging, backupPassword: backupPassword, vault: credential, expectedItems: backupItems.count)
        case .publicKey(let record):
            guard let written else { throw RecoveryError(String(localized: "The recovery backup could not be checked")) }
            inventory = try await Self.checkWritten(staging, written: written, record: record, vault: credential,
                                                    expectedItems: backupItems.count)
        }
        guard rename(staging.path, url.path) == 0 else { throw RecoveryError(String(localized: "Could not create the recovery backup")) }
        inventory.path = url.path
        inventory.createdAt = created
        inventory.verifiedAt = unixNow
        inventory.manifestPath = ChecksumManifest.url(for: url).path
        if Self.sameVolume(url, directory) { inventory.sameDisk = true; inventory.warnings = [Self.sameDiskWarning] }
        try ChecksumManifest.write(for: url, inventory: inventory, now: unixNow)
        return inventory
    }

    /// The recovery kit for a backup made here: Windows' format, with the restore guide noting Windows' extra
    /// confirmation for a backup from another device.
    func writeRecoveryKit(to destination: URL, backup: URL, inventory: BackupInventory?, appVersion: String) throws {
        try RecoveryKit.write(to: destination, backup: backup, inventory: inventory, appVersion: appVersion, now: unixNow,
                              restoreGuide: Self.restoreGuide)
    }

    /// The first live licence bundle in the store (sorted by state id), if any.
    nonisolated static func licenceBundle(_ snap: StoreSnapshot) -> JSONValue? {
        for (_, wrapper) in snap.records.sorted(by: { $0.key < $1.key }) where ns(wrapper) == Namespace.license.rawValue {
            if case .object = record(wrapper) { return record(wrapper) }
        }
        return nil
    }

    // MARK: verify

    /// Opens and decrypts the backup (backup password, then the vault's master password from backup time), checks
    /// `<file>.sha256.json` when it is there and every item. Writes nothing. A vault with key-file / YubiKey factors
    /// (a Windows v4 vault) takes them from `factors`; without them it throws `FactorError.required` (ask for them, or
    /// for the recovery phrase), and a wrong one `FactorError.mismatch`.
    func verify(url: URL, password: String, vaultPassword: String,
                factors: FactorSecrets = FactorSecrets()) async throws -> BackupInventory {
        try await Self.verifyFile(url: url, password: password, vaultPassword: vaultPassword, factors: factors, now: unixNow)
    }

    /// `verify` without an open vault (the lock screen's Backup & restore).
    nonisolated static func verifyFile(url: URL, password: String, vaultPassword: String,
                                       factors: FactorSecrets = FactorSecrets(),
                                       now: Int64 = Int64(Date().timeIntervalSince1970)) async throws -> BackupInventory {
        guard !password.utf8.elementsEqual(vaultPassword.utf8) else { throw RecoveryError.samePassword }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        try Self.checkManifestIfPresent(url)
        var inventory = try await Self.check(url, backupPassword: password, vault: .password(vaultPassword), expectedItems: nil,
                                             factors: factors)
        inventory.verifiedAt = now
        if FileManager.default.fileExists(atPath: ChecksumManifest.url(for: url).path) {
            inventory.manifestPath = ChecksumManifest.url(for: url).path
        }
        return inventory
    }

    /// The key-file / YubiKey factors the vault inside `url` asks for (a Windows v4 vault; empty for any other), read
    /// with the backup password only, so the Recovery centre can ask for them (and name the YubiKey's slot).
    func vaultFactors(url: URL, password: String) async throws -> [FactorSpec] {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        return try await Task.detached(priority: .userInitiated) { () throws -> [FactorSpec] in
            let (contents, _) = try Self.openContainer(url, password: password)
            do { return try DesktopVaultFile.factors(in: contents.vault) } catch let e as DesktopVaultError { throw RecoveryError(e.message) }
        }.value
    }

    // MARK: restore

    /// What restoring `url` by replacing would do. Writes nothing. `factors` as in `verify`.
    func previewRestore(url: URL, password: String, vaultPassword: String,
                        factors: FactorSecrets = FactorSecrets()) async throws -> RestorePreview {
        let opened = try await open(url, password: password, vaultPassword: vaultPassword, factors: factors)
        // A preview writes nothing: converted documents are sealed into a throwaway in-memory store.
        let previewBlobs: (any AttachmentBlobStore)? = attachmentFolder == nil ? nil : PreviewBlobs()
        return try plan(opened, snapshot: try store.load(), blobs: previewBlobs).preview
    }

    /// Asks for the master password (strict gate), then restores. False when another prompt is open.
    @discardableResult
    func requestRestore(url: URL, password: String, vaultPassword: String, factors: FactorSecrets = FactorSecrets(),
                        then finished: (@MainActor (Bool) -> Void)? = nil) -> Bool {
        gated(then: finished) {
            try await self.restoreReplacing(url: url, password: password, vaultPassword: vaultPassword, factors: factors)
        }
    }

    /// Asks for the master password (strict gate), then puts a safety copy back (the same swap, so the vault as it
    /// is now gets its own safety copy first).
    @discardableResult
    func requestRestore(safetyCopy: SafetyCopy, then finished: (@MainActor (Bool) -> Void)? = nil) -> Bool {
        gated(then: finished) { try await self.restoreSafetyCopy(safetyCopy) }
    }

    /// `finished` runs once with this restore's result, after the gate approved it (never if it is cancelled).
    private func gated(then finished: (@MainActor (Bool) -> Void)?, _ body: @escaping @MainActor () async throws -> Void) -> Bool {
        let asked = gate.confirmMasterPassword(title: Self.restoreGateTitle, action: String(localized: "Replace this vault with the backup")) { [weak self] in
            guard let self else { return }
            self.restoreAuthorised = true
            self.restoreTask = Task {
                let ok: Bool
                do { try await body(); ok = true }
                catch { self.message = Self.describe(error); ok = false }
                finished?(ok)
                return ok
            }
        }
        if !asked { message = Self.promptBusyMessage }
        return asked
    }

    /// Replaces this vault with the backup: stage, verify, swap. Refused unless the strict gate came first (once).
    func restoreReplacing(url: URL, password: String, vaultPassword: String,
                          factors: FactorSecrets = FactorSecrets()) async throws {
        try takeAuthorisation()
        busy = true
        defer { busy = false }
        let staged = try await stage(url: url, password: password, vaultPassword: vaultPassword, factors: factors)
        try finish(staged)
    }

    /// The lock screen's restore: the vault was created a moment ago, empty, with the backup's master password (that
    /// creation is the confirmation the strict gate asks for), and the backup goes into it.
    func restoreIntoNewVault(url: URL, password: String, vaultPassword: String) async throws {
        // Empty: no item and no licence (collection states alone, e.g. the starters, don't count).
        guard try store.load().itemRecords.isEmpty else { throw Self.notAuthorised }
        restoreAuthorised = true
        try await restoreReplacing(url: url, password: password, vaultPassword: vaultPassword)
    }

    /// Puts a safety copy back (gated like a restore).
    func restoreSafetyCopy(_ copy: SafetyCopy) async throws {
        try takeAuthorisation()
        busy = true
        defer { busy = false }
        let records: [String: JSONValue]
        let contents: DesktopProfileStore.Contents
        let attachments: [(id: String, data: Data)]
        do {
            records = try profile.openRecords(copy.folder.appendingPathComponent("records.bin")).records
            contents = try profile.read(copy.folder.appendingPathComponent(DesktopProfileStore.fileName))
            attachments = try DesktopProfileStore.attachments(in: copy.folder.appendingPathComponent(DesktopProfileStore.attachmentsName))
        } catch { throw RecoveryError(String(localized: "That safety copy can't be read.")) }
        let live = records.filter { Self.ns($0.value) != Namespace.license.rawValue }
        let staged = try writeStaging(records: live, contents: contents, attachments: attachments, preview: nil)
        try finish(staged)
    }

    private func takeAuthorisation() throws {
        guard restoreAuthorised else { throw Self.notAuthorised }
        restoreAuthorised = false
        guard !Self.inFlight else { throw RecoveryError(Self.busyMessage) }
    }

    private func finish(_ staged: StagedRestore) throws {
        defer { try? FileManager.default.removeItem(at: staged.folder) }
        #if DEBUG
        try beforeSwap()
        #endif
        try swap(staged)
        // The removal watch belongs to the vault as it was: forgotten, as Leave does, so a notice for that vault never
        // erases the restored one (the next folder run writes it again while the group is still joined).
        try? FileManager.default.removeItem(at: SyncDependencies.watchFileURL(in: directory))
        message = Self.restoredMessage
        afterChange()
    }

    /// Opens the backup and writes what it restores into a fresh staging folder in the vault directory (the records,
    /// sealed under this vault's key, the attachments, `desktop-profile.bin`), then reads all of it back. The live
    /// vault is not touched. (Phase 6 restores "as a new profile" from here.)
    func stage(url: URL, password: String, vaultPassword: String,
               factors: FactorSecrets = FactorSecrets()) async throws -> StagedRestore {
        let opened = try await open(url, password: password, vaultPassword: vaultPassword, factors: factors)
        let (preview, records, contents) = try plan(opened, snapshot: try store.load(), blobs: attachmentFolder)
        return try writeStaging(records: records, contents: contents,
                                attachments: opened.contents.attachments.map { (id: $0.id, data: $0.data) }, preview: preview)
    }

    private func writeStaging(records: [String: JSONValue], contents: DesktopProfileStore.Contents,
                              attachments: [(id: String, data: Data)], preview: RestorePreview?) throws -> StagedRestore {
        let fm = FileManager.default
        let folder = directory.appendingPathComponent(Self.stagingPrefix + UUID().uuidString, isDirectory: true)
        do {
            try fm.createDirectory(at: folder, withIntermediateDirectories: false)
            let recordsFile = folder.appendingPathComponent("records.bin")
            try profile.sealRecords(records, revision: 0).write(to: recordsFile, options: .withoutOverwriting)
            let attachmentsFolder = folder.appendingPathComponent(DesktopProfileStore.attachmentsName, isDirectory: true)
            try fm.createDirectory(at: attachmentsFolder, withIntermediateDirectories: false)
            for a in attachments {
                try a.data.write(to: attachmentsFolder.appendingPathComponent("\(a.id).blob"), options: .withoutOverwriting)
            }
            let profileFile = folder.appendingPathComponent(DesktopProfileStore.fileName)
            try profile.seal(contents).write(to: profileFile, options: .withoutOverwriting)
            // Read everything back before anything live changes.
            func digests(_ list: [(id: String, data: Data)]) -> [String] {
                list.map { "\($0.id)|\(SHA256.hash(data: $0.data).map { String(format: "%02x", $0) }.joined())" }.sorted()
            }
            guard try profile.openRecords(recordsFile).records == records,
                  try profile.read(profileFile) == contents,
                  digests(try DesktopProfileStore.attachments(in: attachmentsFolder)) == digests(attachments) else {
                throw RecoveryError(String(localized: "The restored vault could not be checked"))
            }
            return StagedRestore(folder: folder, preview: preview, records: records, contents: contents)
        } catch {
            try? fm.removeItem(at: folder)
            if error is RecoveryError { throw error }
            throw RecoveryError(String(localized: "Full backup restore failed"))
        }
    }

    /// Safety copy, marker, attachments and `desktop-profile.bin` swapped in, records committed (the commit point),
    /// marker removed. A failed commit puts the pieces back.
    private func swap(_ staged: StagedRestore) throws {
        let fm = FileManager.default
        let snap = try store.load()
        let safety = try keepSafetyCopy(snap)
        let marker = directory.appendingPathComponent(Self.markerName)
        do {
            try Data(CanonicalJSON.encode(.object(["safety": .string(safety.name), "base_revision": .int(snap.revision)]),
                                          dialect: .utf8)).write(to: marker, options: .atomic)
        } catch { throw RecoveryError(String(localized: "Nothing was restored: the vault as it is could not be kept first")) }
        let liveAttachments = profile.attachmentsURL
        let stagedAttachments = staged.folder.appendingPathComponent(DesktopProfileStore.attachmentsName, isDirectory: true)
        let hadAttachments = fm.fileExists(atPath: liveAttachments.path)
        /// Puts the pieces back from the safety copy; the marker goes only once that worked, else the next unlock retries.
        func undoAll() {
            if Self.putBack(from: safety.folder, into: directory) { try? fm.removeItem(at: marker) }
        }
        let r = hadAttachments ? renamex_np(stagedAttachments.path, liveAttachments.path, UInt32(RENAME_SWAP))
                               : rename(stagedAttachments.path, liveAttachments.path)
        guard r == 0 else { undoAll(); throw RecoveryError(String(localized: "Full backup restore failed")) }
        guard rename(staged.folder.appendingPathComponent(DesktopProfileStore.fileName).path, profile.fileURL.path) == 0 else {
            undoAll()
            throw RecoveryError(String(localized: "Full backup restore failed"))
        }
        #if DEBUG
        if crashPoint == .afterPiecesSwapped { throw SimulatedCrash() }
        #endif
        // Licences stay: they belong to this Mac's purchase. A backup's licence copy is added when it verifies.
        // Collections stay too (the catalog, share links, and the memberships of items the backup brings back), and the
        // items of collections shared on this Mac stay as they are now (`keepingShared`). The share groups themselves
        // are never touched (`StoreChange.shares` `.keep`).
        var records = Self.keepingShared(current: snap, restored: CollectionCatalog.carriedOver(from: snap.records, into: staged.records))
        for (id, wrapper) in snap.records where Self.ns(wrapper) == Namespace.license.rawValue { records[id] = wrapper }
        if case .object? = staged.contents.payload["license"], let bundle = staged.contents.payload["license"],
           let info = try? License.verify(bundle: bundle, keys: licenseKeys) {
            let id = License.stateID(licenseID: info.licenseID)
            if records[id] == nil { records[id] = Wrapper.make(ns: .license, record: bundle) }
        }
        let change = StoreChange(baseRevision: snap.revision, records: records, meta: snap.meta, sync: snap.sync)
        do {
            if let local {
                try RemoteDeletes.commit(change, before: snap, local: local, now: unixNow) { try store.commit($0) }
            } else {
                try store.commit(change)
            }
        } catch {
            undoAll()
            throw error
        }
        #if DEBUG
        if crashPoint == .afterCommit { throw SimulatedCrash() }
        #endif
        try? fm.removeItem(at: marker)
    }

    // MARK: safety copies

    nonisolated static func backupsFolder(_ directory: URL) -> URL {
        directory.appendingPathComponent(backupsName, isDirectory: true)
    }

    /// The safety copies kept before restores, newest first.
    /// The copies the Recovery centre can put back, newest first: the safety copies and the automatic copies made as
    /// the vault is saved (`MacAutomaticBackups`, Settings › Backups) that still open under the vault's key.
    func safetyCopies() -> [SafetyCopy] {
        (Self.safetyCopies(in: directory) + MacAutomaticBackups.restorable(in: profile)).sorted { $0.createdAtMillis > $1.createdAtMillis }
    }

    /// Safety copies a key rotation couldn't read and set aside (`<name>.unreadable`, `MacVault.lastRotationSetAside`).
    func setAsideCopies() -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: Self.backupsFolder(directory).path)) ?? [])
            .filter { $0.hasPrefix(Self.safetyPrefix) && $0.hasSuffix(".unreadable") }.sorted()
    }

    nonisolated static func safetyCopies(in directory: URL) -> [SafetyCopy] {
        let folder = backupsFolder(directory)
        let names = (try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? []
        return names.compactMap { name -> SafetyCopy? in
            guard name.hasPrefix(safetyPrefix), let ms = Int64(name.dropFirst(safetyPrefix.count)),
                  FileManager.default.fileExists(atPath: folder.appendingPathComponent(name).appendingPathComponent("records.bin").path)
            else { return nil }
            return SafetyCopy(folder: folder.appendingPathComponent(name, isDirectory: true), createdAtMillis: ms)
        }.sorted { $0.createdAtMillis > $1.createdAtMillis }
    }

    /// `Backups/before-restore-<ms>/`: the records (sealed), `desktop-profile.bin` and `Attachments/` as they are now.
    /// Written under a temporary name and renamed when complete; older copies beyond the newest 5 are pruned.
    private func keepSafetyCopy(_ snap: StoreSnapshot) throws -> SafetyCopy {
        let fm = FileManager.default
        let backups = Self.backupsFolder(directory)
        var ms = Int64(now().timeIntervalSince1970 * 1000)
        while fm.fileExists(atPath: backups.appendingPathComponent(Self.safetyPrefix + "\(ms)").path) { ms += 1 }
        let target = backups.appendingPathComponent(Self.safetyPrefix + "\(ms)", isDirectory: true)
        let tmp = backups.appendingPathComponent(".\(Self.safetyPrefix)\(UUID().uuidString)", isDirectory: true)
        do {
            try fm.createDirectory(at: tmp, withIntermediateDirectories: true)
            try profile.sealRecords(snap.records, revision: snap.revision).write(to: tmp.appendingPathComponent("records.bin"))
            if fm.fileExists(atPath: profile.fileURL.path) {
                try fm.copyItem(at: profile.fileURL, to: tmp.appendingPathComponent(DesktopProfileStore.fileName))
            }
            if fm.fileExists(atPath: profile.attachmentsURL.path) {
                try fm.copyItem(at: profile.attachmentsURL, to: tmp.appendingPathComponent(DesktopProfileStore.attachmentsName))
            }
            try fm.moveItem(at: tmp, to: target)
        } catch {
            try? fm.removeItem(at: tmp)
            throw RecoveryError(String(localized: "Nothing was restored: the vault as it is could not be kept first"))
        }
        for old in Self.safetyCopies(in: directory).dropFirst(Self.safetyKeep) { try? fm.removeItem(at: old.folder) }
        return SafetyCopy(folder: target, createdAtMillis: ms)
    }

    #if DEBUG
    /// Test seam: makes `putBack` fail (as a failed copy or rename would).
    nonisolated(unsafe) static var failPutBackForTests = false
    #endif
    nonisolated static let putBackSuffix = ".putback"

    /// True when `copy` is a complete safety copy (written under a temp name, so `records.bin` means complete).
    nonisolated static func isComplete(_ copy: URL) -> Bool {
        FileManager.default.fileExists(atPath: copy.appendingPathComponent("records.bin").path)
    }

    /// Puts `Attachments/` and `desktop-profile.bin` back from a complete safety copy (absent there: removed here).
    /// Returns false, touching nothing, when the copy is missing or incomplete, and false when a copy, rename or
    /// removal failed (the caller keeps the marker so the next unlock retries).
    @discardableResult
    nonisolated static func putBack(from copy: URL, into directory: URL) -> Bool {
        guard isComplete(copy) else { return false }
        let fm = FileManager.default
        var ok = true
        for name in [DesktopProfileStore.attachmentsName, DesktopProfileStore.fileName] {
            let live = directory.appendingPathComponent(name)
            let kept = copy.appendingPathComponent(name)
            #if DEBUG
            if failPutBackForTests { ok = false; continue }
            #endif
            if fm.fileExists(atPath: kept.path) {
                let tmp = directory.appendingPathComponent(".\(name).\(UUID().uuidString)\(putBackSuffix)")
                guard (try? fm.copyItem(at: kept, to: tmp)) != nil else { try? fm.removeItem(at: tmp); ok = false; continue }
                if fm.fileExists(atPath: live.path) {
                    if renamex_np(tmp.path, live.path, UInt32(RENAME_SWAP)) == 0 { try? fm.removeItem(at: tmp) }
                    else { try? fm.removeItem(at: tmp); ok = false }
                } else if rename(tmp.path, live.path) != 0 {
                    try? fm.removeItem(at: tmp); ok = false
                }
            } else if fm.fileExists(atPath: live.path) {
                if (try? fm.removeItem(at: live)) == nil { ok = false }
            }
        }
        return ok
    }

    /// At unlock: finishes a restore a crash interrupted (`restore-in-progress.json`). If the store moved past the
    /// revision the restore started from, its commit landed and the restore stands; otherwise the attachments and
    /// `desktop-profile.bin` go back to the safety copy. The marker is removed only when that is settled: a missing or
    /// incomplete safety copy leaves the live files and the marker alone, and a failed put-back is retried next unlock.
    /// Staging folders and temp files left behind are swept. Safety copies stay.
    nonisolated static func finishInterruptedRestore(in directory: URL) {
        let fm = FileManager.default
        let marker = directory.appendingPathComponent(markerName)
        var referenced: String?
        if let data = try? Data(contentsOf: marker) {
            if case .object(let o)? = try? CanonicalJSON.parse(Array(data)), case .string(let name)? = o["safety"],
               case .int(let base)? = o["base_revision"], !name.contains("/") {
                referenced = name
                let committed = LocalStore.committedRevision(directory: directory) ?? 0
                if committed > base {
                    try? fm.removeItem(at: marker)
                } else if putBack(from: backupsFolder(directory).appendingPathComponent(name, isDirectory: true), into: directory) {
                    try? fm.removeItem(at: marker)
                }
            }
            // An unreadable marker is kept: nothing can be decided from it.
        }
        for name in (try? fm.contentsOfDirectory(atPath: directory.path)) ?? []
        where name.hasPrefix(stagingPrefix) || (name.hasPrefix(".") && name.hasSuffix(putBackSuffix)) {
            try? fm.removeItem(at: directory.appendingPathComponent(name))
        }
        let backups = backupsFolder(directory)
        for name in (try? fm.contentsOfDirectory(atPath: backups.path)) ?? []
        where name.hasPrefix(".\(safetyPrefix)") && name != referenced {
            try? fm.removeItem(at: backups.appendingPathComponent(name))
        }
    }

    // MARK: reading a backup

    struct Opened: Sendable {
        let contents: FullBackupContents
        let payload: [String: JSONValue]
        let recoveryEnrolled: Bool
        /// The container's `header.version` (2, or 3 for a scheduled backup to a public key).
        var version: Int64 = FullBackupV2.version
    }

    private func open(_ url: URL, password: String, vaultPassword: String,
                      factors: FactorSecrets = FactorSecrets()) async throws -> Opened {
        guard !password.utf8.elementsEqual(vaultPassword.utf8) else { throw RecoveryError.samePassword }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        try Self.checkManifestIfPresent(url)
        return try await Task.detached(priority: .userInitiated) { () async throws -> Opened in
            try await Self.openAsync(url, password: password, vault: .password(vaultPassword), factors: factors)
        }.value
    }

    nonisolated private static func openSync(_ url: URL, password: String, vault credential: VaultCredential) throws -> Opened {
        let (contents, version) = try openContainer(url, password: password)
        do {
            let (payload, recovery) = try openVault(contents.vault, credential)
            return Opened(contents: contents, payload: payload, recoveryEnrolled: recovery, version: version)
        } catch let e as DesktopVaultError {
            throw RecoveryError(e.message)
        }
    }

    /// `openSync`, with a master password whose vault may ask for key-file / YubiKey factors (a Windows v4 vault):
    /// they are taken from `factors`. `FactorError` (required or mismatch) reaches the caller as it is, so the UI can
    /// ask for the factors or offer the recovery phrase; it is never a wrong password.
    nonisolated private static func openAsync(_ url: URL, password: String, vault credential: VaultCredential,
                                              factors: FactorSecrets) async throws -> Opened {
        guard case .password(let vaultPassword) = credential else { return try openSync(url, password: password, vault: credential) }
        let (contents, version) = try openContainer(url, password: password)
        do {
            let (payload, recovery) = try await DesktopVaultFile.openPayload(contents.vault, password: vaultPassword, factors: factors)
            return Opened(contents: contents, payload: payload, recoveryEnrolled: recovery, version: version)
        } catch let e as DesktopVaultError {
            throw RecoveryError(e.message)
        }
    }

    /// The backup file decrypted with the backup password, and its container version.
    nonisolated private static func openContainer(_ url: URL, password: String) throws -> (contents: FullBackupContents, version: Int64) {
        let data: Data
        do { data = try Data(contentsOf: url, options: .alwaysMapped) } catch { throw RecoveryError(String(localized: "Recovery backup is not readable")) }
        guard data.count <= FullBackupV2.maxBackupBytes else { throw RecoveryError(String(localized: "Full backup is too large")) }
        do {
            // Version 3 (scheduled, public key) goes to its own reader; every other file to the v2 reader, unchanged.
            let version = FullBackup.headerVersion(data) == FullBackupV3.version ? FullBackupV3.version : FullBackupV2.version
            return (try FullBackup.open(data, password: password), version)
        } catch let e as FullBackupError {
            throw RecoveryError(e.message)
        }
    }

    nonisolated private static func openVault(_ vault: Data, _ credential: VaultCredential) throws -> ([String: JSONValue], Bool) {
        switch credential {
        case .password(let vaultPassword): return try DesktopVaultFile.openPayload(vault, password: vaultPassword)
        case .key(let key): return try DesktopVaultFile.openPayload(vault, passwordKey: key)
        }
    }

    /// Opens a backup file and checks every record of its vault; the inventory Windows reports.
    nonisolated private static func check(_ url: URL, backupPassword: String, vault credential: VaultCredential,
                                          expectedItems: Int?, factors: FactorSecrets = FactorSecrets()) async throws -> BackupInventory {
        try await Task.detached(priority: .userInitiated) { () async throws -> BackupInventory in
            try inventory(url, try await openAsync(url, password: backupPassword, vault: credential, factors: factors),
                          expectedItems: expectedItems)
        }.value
    }

    /// Design 9.1 for a scheduled v3 file just written (or re-locked): no password. The header, the wrap (with the
    /// ephemeral key and the record's public key), every member (with the data key) and the vault layer (with the
    /// stored password key) are checked as a restore preflight would.
    nonisolated static func checkWritten(_ url: URL, written: FullBackupV3.Written, record: BackupKeyRecord,
                                         vault credential: VaultCredential, expectedItems: Int?) async throws -> BackupInventory {
        try await Task.detached(priority: .userInitiated) { () throws -> BackupInventory in
            try inventory(url, try openWritten(url, written: written, record: record, vault: credential), expectedItems: expectedItems)
        }.value
    }

    /// `checkWritten` without the inventory (re-lock checks files that have no vault key at hand: `vault` nil).
    nonisolated static func openWritten(_ url: URL, written: FullBackupV3.Written, record: BackupKeyRecord,
                                        vault credential: VaultCredential?) throws -> Opened {
        let data: Data
        do { data = try Data(contentsOf: url, options: .alwaysMapped) } catch { throw RecoveryError(String(localized: "Recovery backup is not readable")) }
        do {
            let contents = try FullBackupV3.verifyWritten(data, dataKey: written.dataKey, ephemeralSecret: written.ephemeralSecret,
                                                          record: record)
            guard let credential else { return Opened(contents: contents, payload: [:], recoveryEnrolled: false, version: FullBackupV3.version) }
            let (payload, recovery) = try openVault(contents.vault, credential)
            return Opened(contents: contents, payload: payload, recoveryEnrolled: recovery, version: FullBackupV3.version)
        } catch let e as FullBackupError {
            throw RecoveryError(e.message)
        } catch let e as DesktopVaultError {
            throw RecoveryError(e.message)
        }
    }

    /// The inventory of an opened backup, after checking every record id is unique (and the count, when known).
    nonisolated private static func inventory(_ url: URL, _ opened: Opened, expectedItems: Int?) throws -> BackupInventory {
        do {
            let records = Self.records(opened.payload)
            var ids = Set<String>()
            for r in records {
                guard case .object(let o) = r, case .string(let id)? = o["id"], ids.insert(id).inserted else {
                    throw RecoveryError(String(localized: "Full backup contains an invalid encrypted vault"))
                }
            }
            if let expectedItems, records.count != expectedItems { throw RecoveryError(String(localized: "The recovery backup could not be checked")) }
            let size = try ChecksumManifest.fileSize(url)
            let mtime = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate)
                .map { Int64($0.timeIntervalSince1970) } ?? 0
            return BackupInventory(version: opened.version, path: url.path, profileName: opened.contents.profileName,
                                   entries: opened.contents.entries.count, attachmentCount: opened.contents.attachments.count,
                                   attachmentBytes: opened.contents.attachments.reduce(0) { $0 + $1.sidecarSize },
                                   backupBytes: size, backupSHA256: try ChecksumManifest.sha256(of: url),
                                   createdAt: opened.contents.createdAt ?? mtime, verified: true,
                                   recoveryPhraseEnrolled: opened.recoveryEnrolled)
        }
    }

    nonisolated private static func checkManifestIfPresent(_ url: URL) throws {
        let manifest = ChecksumManifest.url(for: url)
        // Readable only when the folder is (sandbox): a manifest that can't be read is not checked.
        guard let data = try? Data(contentsOf: manifest) else { return }
        try ChecksumManifest.verify(backup: url, manifest: data)
    }

    nonisolated private static func records(_ payload: [String: JSONValue]) -> [JSONValue] {
        var out: [JSONValue] = []
        for key in ["entries", "items"] { if case .array(let rows)? = payload[key] { out += rows } }
        return out
    }

    // MARK: plan

    /// Kinds Windows keeps that never sync: restored into `desktop-profile.bin`, not the store.
    nonisolated static let keptKinds: Set<String> = ["document"]

    /// Every shared collection this vault knows of: those this Mac's share records name (as owner or member) and those
    /// another of this person's devices shares (their `csl:` links, any mode and role), whose edits reach the members
    /// through that device. A share store that cannot be read counts every collection it might protect
    /// (`ShareGroups.protectedCollectionIDs`), so a restore keeps more, never less.
    nonisolated static func sharedCollectionIDs(_ snap: StoreSnapshot) -> Set<String> {
        var out = Set<String>()
        let prefix = CollectionStates.linkPrefix
        for (id, wrapper) in snap.records where id.hasPrefix(prefix) {
            if case .object(let w) = wrapper, case .object(let r)? = w["record"], case .string(let cid)? = r["collection_id"] {
                out.insert(cid)
            } else {
                out.insert(String(id.dropFirst(prefix.count)))
            }
        }
        guard snap.shares != nil else { return out }
        if let all = try? ShareGroups.records(in: snap) { return out.union(all.values.map(\.collectionID)) }
        return out.union(ShareGroups.protectedCollectionIDs(in: snap))
    }

    /// The live items now in a shared collection (`sharedCollectionIDs`): a restore keeps them as they are.
    nonisolated static func sharedItemIDs(_ snap: StoreSnapshot) -> Set<String> {
        var keep = Set<String>()
        for cid in sharedCollectionIDs(snap) { keep.formUnion(CollectionCatalog.items(in: cid, snapshot: snap)) }
        return keep
    }

    /// `restored` with the items of every collection shared on this Mac kept exactly as they are in `current` (their
    /// records and `cm:` memberships), as `CollectionCatalog.carriedOver` keeps the catalog (sub-plan 07, 5e review):
    /// a restore never takes a shared item out (which would tombstone it for every member) and never puts an older copy
    /// over other people's edits. An item the backup brings back that is not in such a collection now is not put back in
    /// it either (the shared ids leave its membership), so nothing old is republished to the others. The shared
    /// collections' own catalog rows and share links stay as they are now too: a Mac safety copy (a whole store, whose
    /// own catalog `carriedOver` brings back) may hold an older name for them, or predate them.
    nonisolated static func keepingShared(current: StoreSnapshot, restored: [String: JSONValue]) -> [String: JSONValue] {
        let shared = sharedCollectionIDs(current)
        guard !shared.isEmpty else { return restored }
        let keep = sharedItemIDs(current)
        var out = restored
        for cid in shared {
            for prefix in [CollectionStates.catalogPrefix, CollectionStates.linkPrefix] {
                out[prefix + cid] = current.records[prefix + cid]
            }
        }
        let prefix = CollectionStates.membershipPrefix
        // Memberships the restore would bring into a shared collection for an item that is not in it now.
        for (sid, _) in restored where sid.hasPrefix(prefix) {
            let item = String(sid.dropFirst(prefix.count))
            guard !keep.contains(item) else { continue }
            let ids = CollectionCatalog.memberships(of: item, in: StoreSnapshot(records: restored))
            guard ids.contains(where: shared.contains) else { continue }
            let left = ids.filter { !shared.contains($0) }
            out[sid] = left.isEmpty ? nil : CollectionStates.wrapper(CollectionStates.membership(itemID: item, collectionIDs: left))
        }
        // The shared items as they are now.
        for item in keep {
            out[item] = current.records[item]
            out[prefix + item] = current.records[prefix + item]
        }
        return out
    }

    /// `blobs`: where converted documents' files are sealed (the real folder only once the restore is confirmed).
    private func plan(_ opened: Opened, snapshot snap: StoreSnapshot, blobs: (any AttachmentBlobStore)?) throws
        -> (preview: RestorePreview, records: [String: JSONValue], contents: DesktopProfileStore.Contents) {
        var records: [String: JSONValue] = [:]
        var kept: [JSONValue] = []
        var logins = 0, others = 0
        // Documents (task 12): one whose catalog row and sidecar open becomes a document of this Mac (its file
        // sealed as a sync blob into this Mac's attachment folder); any other stays kept for the desktop app.
        let catalog: [JSONValue] = { if case .array(let a)? = opened.payload["attachments"] { return a }; return [] }()
        let storeID: String? = { if case .string(let s)? = opened.payload["attachment_store_id"] { return s }; return nil }()
        let sidecars = Dictionary(opened.contents.attachments.map { ($0.id, $0.data) }, uniquingKeysWith: { a, _ in a })
        for r in Self.records(opened.payload) {
            // No item may use a collection-state id (`col:`/`cm:`/`csl:`), also in a backup made before collections synced.
            guard case .object(let o) = r, case .string(let id)? = o["id"], records[id] == nil,
                  !CollectionStates.isStateID(id) else {
                throw RecoveryError(String(localized: "Full backup contains an invalid encrypted vault"))
            }
            let kind: String? = { if case .string(let k)? = o["kind"] { return k }; return nil }()
            if kind == AttachmentDocuments.kind, let storeID, let blobs,
               let wrapper = DesktopAttachmentSidecar.restoredDocument(record: r, catalog: catalog, sidecars: sidecars,
                                                                       storeID: storeID, blobs: blobs) {
                others += 1
                records[id] = wrapper
                continue
            }
            if let kind, Self.keptKinds.contains(kind) { kept.append(r); continue }
            let isLogin = kind == "web" || kind == "desktop"
            if isLogin { logins += 1 } else { others += 1 }
            records[id] = Wrapper.make(ns: isLogin ? .entry : .item, record: r)
        }
        var payload = Self.withoutDeviceSecrets(opened.payload)
        for key in ["version", "catalog", "generation", "entries", "items", "created_at", "updated_at"] { payload[key] = nil }
        let contents = DesktopProfileStore.Contents(payload: payload, unsynced: kept, settings: opened.contents.settings,
                                                    profileName: opened.contents.profileName)
        let live = snap.itemRecords.filter { Self.isLiveItem($0.value, snap) }
        let added = records.keys.filter { live[$0] == nil }.count
        // Items in a shared collection stay as they are now (`keepingShared`): neither replaced nor removed.
        let sharedItems = Self.sharedItemIDs(snap)
        let replaced = records.filter { live[$0.key] != nil && live[$0.key] != $0.value && !sharedItems.contains($0.key) }.count
        let unchanged = records.filter { live[$0.key] == $0.value || (live[$0.key] != nil && sharedItems.contains($0.key)) }.count
        let removed = live.keys.filter { records[$0] == nil && !sharedItems.contains($0) }.count
        let newest = live.values.map { Wrapper.rank(Self.record($0)) }.max()
        var newer: Bool?
        if let created = opened.contents.createdAt, let newest, newest > 0 { newer = created > newest }
        let preview = RestorePreview(profileName: opened.contents.profileName, createdAt: opened.contents.createdAt,
                                     logins: logins, otherItems: others, keptOnly: kept.count,
                                     attachments: opened.contents.attachments.count,
                                     recoveryPhraseEnrolled: opened.recoveryEnrolled, currentItems: live.count,
                                     added: added, replaced: replaced, unchanged: unchanged, removed: removed,
                                     backupIsNewer: newer, syncs: snap.sync != nil,
                                     sharedCollections: Self.sharedCollectionIDs(snap).count)
        return (preview, records, contents)
    }

    /// Catalog fields of a Windows profile that never stay on, nor leave from, this Mac (final review minor 7): the
    /// Windows share groups (owner signing key, group key, keyring), their bookkeeping and links, the Windows personal
    /// device sync group. With the "shared" marks on the collection rows they would otherwise sit in
    /// `desktop-profile.bin` and go back out in every later Mac full backup, and restoring that on the PC would bring
    /// stale share records back (Windows ruling F3: share records never go into a backup).
    nonisolated static let deviceOnlyPayloadKeys = ["share_groups", "share_sync_meta", "collection_links", "sync_group"]

    /// `payload` without `deviceOnlyPayloadKeys` and without `shared_group_id` on its collection rows.
    nonisolated static func withoutDeviceSecrets(_ payload: [String: JSONValue]) -> [String: JSONValue] {
        var out = payload
        for key in deviceOnlyPayloadKeys { out[key] = nil }
        if case .array(let rows)? = out["collections"] {
            out["collections"] = .array(rows.map { row -> JSONValue in
                guard case .object(var o) = row else { return row }
                o["shared_group_id"] = nil
                return .object(o)
            })
        }
        return out
    }

    nonisolated static func ns(_ wrapper: JSONValue) -> String? {
        if case .object(let w) = wrapper, case .string(let s)? = w["ns"] { return s }
        return nil
    }

    nonisolated static func record(_ wrapper: JSONValue) -> JSONValue {
        if case .object(let w) = wrapper, let r = w["record"] { return r }
        return .null
    }

    /// A live login or typed item (not a licence, not deleted).
    nonisolated static func isLiveItem(_ wrapper: JSONValue, _ snap: StoreSnapshot) -> Bool {
        guard let ns = ns(wrapper), ns == Namespace.entry.rawValue || ns == Namespace.item.rawValue,
              case .object(let r) = record(wrapper), case .string(let id)? = r["id"] else { return false }
        return snap.meta[id]?.deleted != true
    }

    nonisolated static func sameVolume(_ a: URL, _ b: URL) -> Bool {
        func volume(_ u: URL) -> NSObject? {
            (try? u.deletingLastPathComponent().resourceValues(forKeys: [.volumeIdentifierKey]).volumeIdentifier) as? NSObject
        }
        guard let va = volume(a), let vb = volume(b.appendingPathComponent("x")) else { return false }
        return va.isEqual(vb)
    }

    /// The message for a failed backup, verify or restore.
    nonisolated static func describe(_ error: Error, slot: Int = 2) -> String {
        // A Windows v4 vault's key file / YubiKey (a cancelled touch says nothing).
        if let line = MacFactors.describe(error, slot: slot) { return line ?? "" }
        return switch error {
        case let e as RecoveryError: e.message
        case MacVaultError.wrongPassword: String(localized: "The master password is wrong.")
        case LocalStoreError.stale: String(localized: "Nothing was restored: the vault changed while restoring. Try again.")
        case is LocalDataError: String(localized: "Nothing was restored: Recently deleted couldn't be updated.")
        case is DesktopProfileStore.Failure: keptDataUnreadable.message
        default: String(localized: "Full backup restore failed")
        }
    }
}

/// The restore preview's blob store: counts what a restore would seal, keeps it in memory, writes no file.
final class PreviewBlobs: AttachmentBlobStore, @unchecked Sendable {
    private var stored: [String: [UInt8]] = [:]
    private let lock = NSLock()
    func has(_ blobID: String) -> Bool { lock.withLock { stored[blobID] != nil } }
    func read(_ blobID: String) -> [UInt8]? { lock.withLock { stored[blobID] } }
    @discardableResult func write(_ blob: [UInt8]) throws -> String {
        let id = AttachmentSync.blobID(try AttachmentSync.checkBlobShape(blob))
        lock.withLock { stored[id] = blob }
        return id
    }
    func ids() -> Set<String> { lock.withLock { Set(stored.keys) } }
}
