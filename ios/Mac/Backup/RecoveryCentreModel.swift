import Foundation
import Observation
import LGKCore
import AppSharedMac

/// When this Mac last made and last checked a full backup (dates only; nothing secret). Kept in the app's
/// defaults, as the Mac has one vault (profiles come in Phase 6).
struct BackupHistory {
    nonisolated static let lastBackupKey = "recoveryCentre.lastBackupAt"
    nonisolated static let lastVerifiedKey = "recoveryCentre.lastVerifiedAt"
    let defaults: UserDefaults

    init(defaults: UserDefaults = AppSettings.shared.defaults) { self.defaults = defaults }

    var lastBackup: Date? {
        get { date(Self.lastBackupKey) }
        nonmutating set { set(newValue, Self.lastBackupKey) }
    }

    var lastVerified: Date? {
        get { date(Self.lastVerifiedKey) }
        nonmutating set { set(newValue, Self.lastVerifiedKey) }
    }

    /// A new vault starts with no backup dates.
    func reset() { lastBackup = nil; lastVerified = nil }

    private func date(_ key: String) -> Date? {
        guard let s = defaults.object(forKey: key) as? Double, s > 0 else { return nil }
        return Date(timeIntervalSince1970: s)
    }

    private func set(_ date: Date?, _ key: String) {
        if let date { defaults.set(date.timeIntervalSince1970, forKey: key) } else { defaults.removeObject(forKey: key) }
    }
}

/// The Scheduled backups card's line (Task 9's `BackupScheduleModel.status` fills it).
struct ScheduleSummary: Equatable, Sendable {
    /// `off`, `daily` or `weekly` (Windows `backup_schedule.py`).
    var frequency: String
    var text: String
    var warning: String?

    nonisolated static let off = ScheduleSummary(frequency: "off", text: String(localized: "Off"), warning: nil)
}

/// What the Recovery centre, the overview's Backup & recovery card and the Security centre's Backups panel show.
struct RecoveryStatus: Equatable, Sendable {
    var lastBackup: Date?
    var lastVerified: Date?
    var phraseEnrolled: Bool
    var schedule: ScheduleSummary
    var warnings: [String]
    /// No backup, or the last one is older than Windows `STALE_BACKUP_SECONDS`.
    var stale: Bool
}

/// Windows `plan_backup_rotation`: the newest `keep` `.lgk` files in a folder (by modification time) stay, the rest and
/// checksum files without their backup go, after a confirmation.
struct BackupCleanupPlan: Equatable, Identifiable {
    let folder: URL
    let keep: Int
    let retained: [String]
    let remove: [String]
    let orphanManifests: [String]
    var requiresConfirmation: Bool { !remove.isEmpty || !orphanManifests.isEmpty }
    var id: String { folder.path + "|" + remove.joined(separator: "|") + "|" + orphanManifests.joined(separator: "|") }
}

/// The Recovery centre (Windows `app/recovery_center.py`, `app/recovery.py`): recovery phrase, full backup (create,
/// verify, restore, recovery kit), scheduled backups and old backups, in the Windows order.
@MainActor @Observable
final class RecoveryCentreModel {
    // Copy from Windows `app/recovery.py`, `shell/security_model.py`, `app/home.py`, with "this Mac".
    nonisolated static let title = String(localized: "Recovery centre")
    nonisolated static let intro = String(localized: "Backups are encrypted files saved on this Mac or a location you choose. To restore one, you need its backup password and the master password in use when it was created.")
    nonisolated static let phraseTitle = String(localized: "Recovery phrase")
    nonisolated static let phraseSetText = String(localized: "Set · unlocks if you forget the master password")
    nonisolated static let phraseNotSetText = String(localized: "Not set")
    nonisolated static let fullBackupTitle = String(localized: "Full backup")
    nonisolated static let fullBackupText = String(localized: "One encrypted file with every item, attachment and setting. It restores on this Mac and in LocalGateKeys for Windows. A checksum file is saved beside it.")
    nonisolated static let scheduleTitle = String(localized: "Scheduled backups")
    nonisolated static let scheduleText = String(localized: "Runs while unlocked. A run missed while the app was closed happens at the next unlock.")
    nonisolated static let oldBackupsTitle = String(localized: "Old backups")
    nonisolated static let oldBackupsText = String(localized: "Keeps the newest \(rotationKeep) backups in a folder you choose and deletes the older ones and checksum files left without their backup. You are asked first.")
    nonisolated static let safetyText = String(localized: "Before each restore, a copy of the vault as it was is kept on this Mac (the newest \(MacFullBackup.safetyKeep)). You can put one back.")
    nonisolated static let setAsideText = String(localized: "Set aside because it couldn't be read after a key change:")
    nonisolated static let noBackupWarning = String(localized: "No backup yet")
    nonisolated static let staleWarning = String(localized: "Your last backup is more than 7 days old. Back up again.")
    nonisolated static let noPhraseWarning = String(localized: "No recovery phrase is set. Without one, a forgotten master password can't be replaced.")
    nonisolated static let enterCreate = String(localized: "Enter both passwords and confirm the backup password.")
    nonisolated static let enterBoth = String(localized: "Enter both passwords.")
    nonisolated static let mismatch = String(localized: "Backup passwords do not match.")
    nonisolated static let tooShort = String(localized: "Backup password must contain at least 12 characters")
    nonisolated static let verifiedText = String(localized: "Backup verified. No profile data was changed.")
    nonisolated static let kitSavedText = String(localized: "Recovery kit saved. Keep it with your encrypted backup.")
    nonisolated static let kitNeedsBackup = String(localized: "Create or verify a backup first; the recovery kit describes that backup.")
    nonisolated static let folderUnusable = String(localized: "Backup directory must be a regular local directory")
    nonisolated static let minimumBackupPassword = 12
    /// Windows `DEFAULT_ROTATION_COUNT`.
    nonisolated static let rotationKeep = 3
    /// Windows `STALE_BACKUP_SECONDS` (`app/home.py`).
    nonisolated static let staleSeconds: TimeInterval = 7 * 86_400

    /// Every fixed line the page shows (checked for Mac wording).
    nonisolated static var copy: [String] {
        [title, intro, phraseTitle, phraseSetText, phraseNotSetText, fullBackupTitle, fullBackupText, scheduleTitle,
         scheduleText, oldBackupsTitle, oldBackupsText, safetyText, setAsideText, noBackupWarning, staleWarning,
         noPhraseWarning, enterCreate, enterBoth, mismatch, tooShort, verifiedText, kitSavedText, kitNeedsBackup,
         folderUnusable, RecoveryPhraseSheet.intro, RecoveryPhraseSheet.cardIntro, RecoveryPhraseSheet.removeIntro,
         MacFullBackup.restoredMessage, MacFullBackup.keptDataUnreadable.message]
    }

    /// Where the page should start when opened from a Security centre row.
    enum Initial: String, Equatable, Sendable { case create, verify, restore, kit }

    /// A backup chosen for verify or restore, waiting for its passwords.
    struct PasswordForm: Identifiable, Equatable {
        enum Kind: Equatable { case create(folder: URL), verify(URL), restore(URL) }
        let id = UUID()
        let kind: Kind
    }

    /// A restore preview, shown before the master password is asked.
    struct PendingRestore: Identifiable, Equatable {
        let id = UUID()
        let url: URL
        let password: String
        let vaultPassword: String
        let preview: RestorePreview
    }

    @ObservationIgnored let backup: MacFullBackup?
    @ObservationIgnored let passwords: (any MasterPasswordService)?
    @ObservationIgnored private let history: BackupHistory
    @ObservationIgnored private let hasPhrase: () -> Bool
    @ObservationIgnored private let schedule: () -> ScheduleSummary
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private let appVersion: String
    /// Keeps the folder of each manual backup as a bookmark, so access survives a relaunch.
    @ObservationIgnored private let rememberFolder: (URL) -> Void
    /// Scheduled backups (the card's controls); nil in tests and previews without them.
    @ObservationIgnored let scheduleModel: BackupScheduleModel?

    /// Changes whenever the status might have (a backup, a check, a phrase change).
    private(set) var revision = 0
    var message: String?
    var error: String?
    private(set) var working = false
    var form: PasswordForm?
    var pendingRestore: PendingRestore?
    /// A preview made while the password sheet is still up; shown once that sheet is gone (`showReadyPreview`).
    private(set) var readyPreview: PendingRestore?
    /// A restore the preview approved; the page asks the gate once the preview sheet is gone.
    var approvedRestore: PendingRestore?
    var pendingCleanup: BackupCleanupPlan?
    /// Takes (and clears) the stored passwords for "Back up items only"; every exit path clears them.
    func takeWithoutKeptData() -> (folder: URL, password: String, master: String)? {
        defer { askWithoutKeptData = nil }
        return askWithoutKeptData
    }

    /// "Back up without the Windows data?" after `keptDataUnreadable`.
    var askWithoutKeptData: (folder: URL, password: String, master: String)?
    /// Where the last backup was saved this session (the default for cleanup).
    private(set) var lastFolder: URL?
    /// The last backup made or checked this session, for the recovery kit.
    private(set) var lastBackupURL: URL?
    private(set) var lastInventory: BackupInventory?
    /// Opens the password sheet for a backup action.
    func ask(_ kind: PasswordForm.Kind) { error = nil; message = nil; form = PasswordForm(kind: kind) }

    /// The page's first action when opened from the Security centre (taken once).
    var initial: Initial?
    #if DEBUG
    /// Screenshots: a fixed status instead of the real one.
    var previewStatus: RecoveryStatus?
    #endif

    init(backup: MacFullBackup?, passwords: (any MasterPasswordService)?, history: BackupHistory = BackupHistory(),
         hasPhrase: (() -> Bool)? = nil, schedule: @escaping () -> ScheduleSummary = { .off },
         now: @escaping () -> Date = Date.init, appVersion: String = SecurityModel.bundleVersion,
         scheduleModel: BackupScheduleModel? = nil, lastFolder: URL? = nil, rememberFolder: @escaping (URL) -> Void = { _ in }) {
        self.backup = backup; self.passwords = passwords; self.history = history
        self.hasPhrase = hasPhrase ?? { [weak passwords] in passwords?.hasRecoveryPhrase ?? false }
        self.schedule = schedule; self.now = now; self.appVersion = appVersion
        self.scheduleModel = scheduleModel; self.lastFolder = lastFolder; self.rememberFolder = rememberFolder
    }

    /// The model over scheduled backups: their status on the card, the folder bookmark for manual backups.
    convenience init(backup: MacFullBackup?, passwords: (any MasterPasswordService)?, scheduleModel: BackupScheduleModel) {
        self.init(backup: backup, passwords: passwords, schedule: { [weak scheduleModel] in scheduleModel?.status ?? .off },
                  scheduleModel: scheduleModel, lastFolder: scheduleModel.manualFolder(),
                  rememberFolder: { [weak scheduleModel] in scheduleModel?.rememberManualFolder($0) })
    }

    // MARK: status

    var status: RecoveryStatus {
        _ = revision
        #if DEBUG
        if let previewStatus { return previewStatus }
        #endif
        return Self.status(lastBackup: history.lastBackup, lastVerified: history.lastVerified, phrase: hasPhrase(),
                           schedule: schedule(), now: now())
    }

    nonisolated static func status(lastBackup: Date?, lastVerified: Date?, phrase: Bool, schedule: ScheduleSummary,
                                   now: Date) -> RecoveryStatus {
        let stale = lastBackup.map { now.timeIntervalSince($0) > staleSeconds } ?? true
        var warnings: [String] = []
        if lastBackup == nil { warnings.append(noBackupWarning) } else if stale { warnings.append(staleWarning) }
        if !phrase { warnings.append(noPhraseWarning) }
        if let w = schedule.warning { warnings.append(w) }
        return RecoveryStatus(lastBackup: lastBackup, lastVerified: lastVerified, phraseEnrolled: phrase,
                              schedule: schedule, warnings: warnings, stale: stale)
    }

    /// The overview card's pill (Windows `Overview.svelte` `ago`).
    nonisolated static func overviewText(_ status: RecoveryStatus, now: Date) -> String {
        guard let last = status.lastBackup else { return String(localized: "No backup yet") }
        let seconds = max(0, now.timeIntervalSince(last))
        if seconds < 3600 { return String(localized: "Last backup within the hour") }
        if seconds < 86_400 { return String(localized: "Last backup \(Int(seconds / 3600)) h ago") }
        return String(localized: "Last backup \(Int(seconds / 86_400)) d ago")
    }

    /// Windows `overview_model.age_text`.
    nonisolated static func ageText(_ seconds: TimeInterval) -> String {
        if seconds < 60 { return String(localized: "just now") }
        if seconds < 3600 {
            let n = Int(seconds / 60)
            return n == 1 ? String(localized: "1 minute ago") : String(localized: "\(n) minutes ago")
        }
        if seconds < 86_400 {
            let n = Int(seconds / 3600)
            return n == 1 ? String(localized: "1 hour ago") : String(localized: "\(n) hours ago")
        }
        let n = Int(seconds / 86_400)
        return n == 1 ? String(localized: "1 day ago") : String(localized: "\(n) days ago")
    }

    var phraseText: String { status.phraseEnrolled ? Self.phraseSetText : Self.phraseNotSetText }
    var phraseButtons: [String] { status.phraseEnrolled ? [String(localized: "Replace…"), String(localized: "Remove…")] : [String(localized: "Create…")] }

    func lastBackupLine() -> String {
        guard let last = status.lastBackup else { return Self.noBackupWarning }
        let age = Self.ageText(max(0, now().timeIntervalSince(last)))
        guard let checked = status.lastVerified else { return String(localized: "Last backup \(age)") }
        let checkedAge = Self.ageText(max(0, now().timeIntervalSince(checked)))
        return String(localized: "Last backup \(age) · last checked \(checkedAge)")
    }

    /// A phrase sheet closed (or anything else changed the status).
    func refresh() { revision += 1 }

    // MARK: full backup

    /// Checks the form like Windows before anything is written.
    nonisolated static func checkCreate(password: String, confirm: String, master: String) -> String? {
        if password.isEmpty || confirm.isEmpty || master.isEmpty { return enterCreate }
        if password != confirm { return mismatch }
        if password.count < minimumBackupPassword { return tooShort }
        return nil
    }

    /// Writes a full backup into `folder` (chosen with an `NSOpenPanel`, so the backup and its checksum file can both
    /// be written). True when it was saved and checked.
    @discardableResult
    func create(folder: URL, password: String, confirm: String, master: String, withoutKeptData: Bool = false) async -> Bool {
        if let problem = Self.checkCreate(password: password, confirm: confirm, master: master) { error = problem; return false }
        guard let backup else { return false }
        error = nil; message = nil; working = true
        defer { working = false }
        let scoped = folder.startAccessingSecurityScopedResource()
        defer { if scoped { folder.stopAccessingSecurityScopedResource() } }
        let url = folder.appendingPathComponent(MacFullBackup.defaultFileName(now: now()))
        do {
            let inventory = try await backup.create(to: url, backupPassword: password, masterPassword: master,
                                                    withoutKeptData: withoutKeptData)
            history.lastBackup = now()
            history.lastVerified = now()
            lastFolder = folder; lastBackupURL = url; lastInventory = inventory
            rememberFolder(folder)
            message = backup.message
            form = nil
            if !inventory.warnings.isEmpty { message = (message ?? "") + " " + inventory.warnings.joined(separator: " ") }
            refresh()
            return true
        } catch let e as RecoveryError where e == MacFullBackup.keptDataUnreadable {
            form = nil
            askWithoutKeptData = (folder, password, master)
        } catch is CancellationError {
        } catch {
            self.error = MacFullBackup.describe(error)
        }
        return false
    }

    func verify(url: URL, password: String, master: String) async {
        guard !password.isEmpty, !master.isEmpty else { error = Self.enterBoth; return }
        guard let backup else { return }
        error = nil; message = nil; working = true
        defer { working = false }
        do {
            let inventory = try await backup.verify(url: url, password: password, vaultPassword: master)
            history.lastVerified = now()
            lastBackupURL = url; lastInventory = inventory
            message = Self.verifiedText
            form = nil
            refresh()
        } catch {
            self.error = MacFullBackup.describe(error)
        }
    }

    /// Opens the backup and shows what restoring it would do; nothing is written.
    func previewRestore(url: URL, password: String, master: String) async {
        guard !password.isEmpty, !master.isEmpty else { error = Self.enterBoth; return }
        guard let backup else { return }
        error = nil; message = nil; working = true
        defer { working = false }
        do {
            let preview = try await backup.previewRestore(url: url, password: password, vaultPassword: master)
            readyPreview = PendingRestore(url: url, password: password, vaultPassword: master, preview: preview)
            form = nil
        } catch {
            self.error = MacFullBackup.describe(error)
        }
    }

    /// Runs when the password sheet is dismissed (sheets chain through `onDismiss`).
    func showReadyPreview() {
        pendingRestore = readyPreview
        readyPreview = nil
    }

    /// The preview was accepted: once its sheet is gone, the strict gate asks for the master password.
    func approveRestore(_ restore: PendingRestore) {
        approvedRestore = restore
        pendingRestore = nil
    }

    /// Runs after the preview sheet is dismissed (sheets chain through `onDismiss`).
    func startApprovedRestore() {
        guard let restore = approvedRestore, let backup else { return }
        approvedRestore = nil
        let asked = backup.requestRestore(url: restore.url, password: restore.password, vaultPassword: restore.vaultPassword,
                                          then: { [weak self] ok in self?.restoreFinished(ok) })
        if !asked { error = backup.message }
    }

    func putBack(_ copy: MacFullBackup.SafetyCopy) {
        guard let backup else { return }
        if !backup.requestRestore(safetyCopy: copy, then: { [weak self] ok in self?.restoreFinished(ok) }) {
            error = backup.message
        }
    }

    /// Each finished restore's result, in order (the page shows the last; tests count them).
    private(set) var finishedRestores: [Bool] = []

    private func restoreFinished(_ ok: Bool) {
        finishedRestores.append(ok)
        if ok { message = backup?.message; error = nil } else { error = backup?.message }
        refresh()
    }

    var safetyCopies: [MacFullBackup.SafetyCopy] { _ = revision; return backup?.safetyCopies() ?? [] }
    var setAside: [String] { _ = revision; return backup?.setAsideCopies() ?? [] }

    /// The recovery kit for the backup made or checked last.
    func writeKit(to destination: URL) {
        guard let backup, let url = lastBackupURL else { error = Self.kitNeedsBackup; return }
        do {
            try backup.writeRecoveryKit(to: destination, backup: url, inventory: lastInventory, appVersion: appVersion)
            message = Self.kitSavedText; error = nil
        } catch {
            self.error = MacFullBackup.describe(error)
        }
    }

    // MARK: old backups

    /// Windows `plan_backup_rotation` (non-mutating).
    nonisolated static func plan(folder: URL, keep: Int = rotationKeep) throws -> BackupCleanupPlan {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        let attrs = try? fm.attributesOfItem(atPath: folder.path)
        guard fm.fileExists(atPath: folder.path, isDirectory: &isDir), isDir.boolValue,
              attrs?[.type] as? FileAttributeType != .typeSymbolicLink else { throw RecoveryError(folderUnusable) }
        func regular(_ name: String) -> Date? {
            guard let a = try? fm.attributesOfItem(atPath: folder.appendingPathComponent(name).path),
                  a[.type] as? FileAttributeType == .typeRegular else { return nil }
            return a[.modificationDate] as? Date ?? .distantPast
        }
        let names = (try? fm.contentsOfDirectory(atPath: folder.path)) ?? []
        let backups = names.filter { $0.hasSuffix(".lgk") }.compactMap { n in regular(n).map { (n, $0) } }
            .sorted { ($0.1, $0.0) > ($1.1, $1.0) }.map(\.0)
        let suffix = ChecksumManifest.suffix
        let backupNames = Set(backups)
        let orphans = names.filter { $0.hasSuffix(suffix) && regular($0) != nil && !backupNames.contains(String($0.dropLast(suffix.count))) }
            .sorted()
        return BackupCleanupPlan(folder: folder, keep: keep, retained: Array(backups.prefix(keep)),
                                 remove: Array(backups.dropFirst(keep)), orphanManifests: orphans)
    }

    /// "1 older backup" / "3 older backups"; "1 checksum file" / "2 checksum files".
    nonisolated static func backupsText(_ n: Int) -> String {
        n == 1 ? String(localized: "1 older backup") : String(localized: "\(n) older backups")
    }
    nonisolated static func manifestsText(_ n: Int) -> String {
        n == 1 ? String(localized: "1 checksum file") : String(localized: "\(n) checksum files")
    }

    nonisolated static func cleanupQuestion(_ plan: BackupCleanupPlan) -> String {
        let keep = plan.keep
        let backups = backupsText(plan.remove.count)
        let orphans = plan.orphanManifests.count == 1 ? String(localized: "1 checksum file without its backup")
            : String(localized: "\(plan.orphanManifests.count) checksum files without its backup")
        switch (plan.remove.isEmpty, plan.orphanManifests.isEmpty) {
        case (false, false):
            return String(localized: "\(backups) and \(orphans) will be deleted from this folder. The newest \(keep) backups are kept.")
        case (false, true):
            return String(localized: "\(backups) will be deleted from this folder. The newest \(keep) backups are kept.")
        case (true, false):
            return String(localized: "\(orphans) will be deleted from this folder. The newest \(keep) backups are kept.")
        case (true, true):
            return String(localized: " will be deleted from this folder. The newest \(keep) backups are kept.")
        }
    }

    /// Plans a cleanup of `folder`; asks (`pendingCleanup`) only when something would be deleted.
    func planCleanup(folder: URL) {
        error = nil; message = nil
        let scoped = folder.startAccessingSecurityScopedResource()
        defer { if scoped { folder.stopAccessingSecurityScopedResource() } }
        do {
            let plan = try Self.plan(folder: folder)
            if plan.requiresConfirmation { pendingCleanup = plan } else {
                message = String(localized: "Nothing to clean up. The newest \(plan.keep) backups are kept.")
            }
        } catch {
            self.error = MacFullBackup.describe(error)
        }
    }

    func cancelCleanup() { pendingCleanup = nil }

    /// Deletes what the confirmed plan lists (re-checked: only regular files still there), with each removed backup's
    /// own checksum file.
    func confirmCleanup(_ plan: BackupCleanupPlan) {
        pendingCleanup = nil
        let fm = FileManager.default
        let scoped = plan.folder.startAccessingSecurityScopedResource()
        defer { if scoped { plan.folder.stopAccessingSecurityScopedResource() } }
        func removeRegular(_ name: String) -> Bool {
            let url = plan.folder.appendingPathComponent(name)
            guard !name.contains("/"), (try? fm.attributesOfItem(atPath: url.path))?[.type] as? FileAttributeType == .typeRegular
            else { return false }
            return (try? fm.removeItem(at: url)) != nil
        }
        var backups = 0, manifests = 0
        for name in plan.remove where removeRegular(name) {
            backups += 1
            _ = removeRegular(name + ChecksumManifest.suffix)
        }
        for name in plan.orphanManifests where removeRegular(name) { manifests += 1 }
        let keep = plan.keep
        let backupsText = Self.backupsText(backups), manifestsText = Self.manifestsText(manifests)
        switch (backups > 0, manifests > 0) {
        case (false, false): message = String(localized: "Nothing was deleted.")
        case (true, true): message = String(localized: "Deleted \(backupsText) and \(manifestsText). The newest \(keep) backups are kept.")
        case (true, false): message = String(localized: "Deleted \(backupsText). The newest \(keep) backups are kept.")
        case (false, true): message = String(localized: "Deleted \(manifestsText). The newest \(keep) backups are kept.")
        }
    }
}
