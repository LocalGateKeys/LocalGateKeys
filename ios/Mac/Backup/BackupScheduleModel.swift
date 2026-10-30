import Foundation
import Observation
import LGKCore
import AppSharedMac

/// Scheduled backups' settings and status (Windows `backup_schedule.py`, `app/settings.py` backup password and
/// `_schedule_status`, with "this Mac"): frequency, time, weekday, how many to keep, the folder and the mirror folder
/// (bookmarks), and the backup password. `MacBackupScheduler` runs them.
@MainActor @Observable
final class BackupScheduleModel {
    // Copy from Windows `app/settings.py`, `app/schedule.py`, `shell/settings_sections.py`.
    nonisolated static let offText = String(localized: "Scheduled backups are off.")
    nonisolated static let lockedText = String(localized: "Scheduled backups run only while the vault is unlocked.")
    nonisolated static let needsPasswordText = String(localized: "Scheduled backups are off: set a backup password first.")
    nonisolated static let noneYetText = String(localized: "No scheduled backup yet.")
    nonisolated static let skippedText = String(localized: "Scheduled backup skipped: set a backup password first.")
    nonisolated static let failedText = String(localized: "Scheduled backup failed; the previous backup was kept. See the error log.")
    nonisolated static let savedText = String(localized: "Scheduled backup saved.")
    nonisolated static let mirroredText = String(localized: "Scheduled backup saved and copied to the mirror folder.")
    nonisolated static let chooseAgainText = String(localized: "Choose the backup folder again")
    nonisolated static let chooseMirrorAgainText = String(localized: "The mirror folder is not available")
    nonisolated static let enterText = String(localized: "Enter the backup password twice and your master password.")
    nonisolated static let mismatchText = String(localized: "The backup passwords do not match.")
    nonisolated static let tooShortText = String(localized: "The backup password must contain at least 12 characters.")
    nonisolated static let sameText = String(localized: "Choose a backup password different from your master password")
    nonisolated static let passwordSavedText = String(localized: "Backup password saved on this Mac. Scheduled backups use it.")
    nonisolated static let passwordClearedText = String(localized: "Backup password cleared. Scheduled backups are off.")
    nonisolated static let clearQuestion = String(localized: "Scheduled backups stop until you set a backup password again. Existing backup files keep the password they were made with.")
    nonisolated static let unavailableText = String(localized: "Scheduled backups aren't available in this build.")
    nonisolated static let defaultFolderText = String(localized: "In the Backups folder on this Mac")
    nonisolated static let mirrorText = String(localized: "A copy of each scheduled backup also goes to this folder, for example one your cloud app syncs. Only encrypted backups are copied.")
    nonisolated static let phraseRemovedText = String(localized: "The recovery phrase was removed, so new scheduled backups open with the master password only.")
    nonisolated static let keepTitles = [String(localized: "Keep newest"), String(localized: "Keep newest two")]
    nonisolated static let frequencyTitles = [String(localized: "Off"), String(localized: "Daily"), String(localized: "Weekly")]

    nonisolated static var copy: [String] {
        [offText, lockedText, needsPasswordText, noneYetText, skippedText, failedText, savedText, mirroredText, chooseAgainText,
         chooseMirrorAgainText, enterText, mismatchText, tooShortText, sameText, passwordSavedText, passwordClearedText,
         clearQuestion, unavailableText, defaultFolderText, mirrorText, phraseRemovedText]
    }

    /// The Mac has one vault (profiles are Phase 6): its scheduled files carry the tag of profile id `mac`.
    nonisolated static let profileID = "mac"
    nonisolated static let profileTag = BackupSchedule.profileTag(profileID)

    nonisolated static let frequencyKey = "scheduledBackup.frequency"
    nonisolated static let timeKey = "scheduledBackup.time"
    nonisolated static let weekdayKey = "scheduledBackup.weekday"
    nonisolated static let keepKey = "scheduledBackup.keep"

    /// `off`, `daily` or `weekly`; the page offers only those (anything else counts as off).
    var frequency: String { didSet { defaults.set(frequency, forKey: Self.frequencyKey); changed() } }
    /// `HH:MM`, 24-hour; set through `setTime` from a text field.
    var time: String { didSet { defaults.set(time, forKey: Self.timeKey); changed() } }
    /// Monday is 0 (Windows).
    var weekday: Int { didSet { defaults.set(weekday, forKey: Self.weekdayKey); changed() } }
    /// 1 or 2.
    var keep: Int { didSet { defaults.set(keep, forKey: Self.keepKey); changed() } }

    /// A typed time: kept when it is a 24-hour time, else the error to show (Windows `parse_time`).
    @discardableResult
    func setTime(_ text: String) -> String? {
        guard let (h, m) = try? BackupSchedule.parseTime(text) else { return BackupSchedule.timeHint }
        time = String(format: "%02d:%02d", h, m)
        return nil
    }

    private(set) var folder: BackupFolderBookmark?
    private(set) var mirror: BackupFolderBookmark?
    /// Bumped when the secret is saved or cleared (`hasPassword` reads the sealed file).
    private var secretRevision = 0
    /// A backup password is set and opens under the vault's current local key.
    var hasPassword: Bool { _ = secretRevision; return secret() != nil }
    /// Shown on the Scheduled backups card after the recovery phrase was removed.
    var phraseNotice: String?
    /// The chosen folder no longer resolves: no run until it is chosen again.
    private(set) var folderNeedsChoosing = false
    /// The last run's problem (failed, or the mirror copy failed), cleared by the next success.
    var runWarning: String?
    /// The last run's notice (toast in Windows).
    var lastNotice: String?
    /// The skipped warning was shown once (Windows `_warned`), until the settings change.
    var skipWarned = false
    private(set) var lastSuccess: Date?
    var isUnlocked: () -> Bool = { true }

    @ObservationIgnored let keychain: (any KeychainVault)?
    @ObservationIgnored let bookmarks: any BookmarkResolving
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private weak var passwords: (any MasterPasswordService)?
    @ObservationIgnored private let kdf: FullBackupV2.KDF
    @ObservationIgnored private let random: any RandomSource
    @ObservationIgnored let calendar: Calendar
    /// The secret store under the unlocked vault's local key (nil while locked).
    @ObservationIgnored private let secrets: @MainActor () -> ScheduleSecretStore?

    /// `kdf` other than `.default` is for tests. `keychain` nil: this build can't keep the secret (no app-only group).
    init(keychain: (any KeychainVault)?, secrets: @escaping @MainActor () -> ScheduleSecretStore?, defaults: UserDefaults = AppSettings.shared.defaults,
         passwords: (any MasterPasswordService)?, bookmarks: any BookmarkResolving = SecurityScopedBookmarks(),
         kdf: FullBackupV2.KDF = .default, random: any RandomSource = SystemRandomSource(), calendar: Calendar = .current) {
        self.keychain = keychain; self.secrets = secrets; self.defaults = defaults; self.passwords = passwords; self.bookmarks = bookmarks
        self.kdf = kdf; self.random = random; self.calendar = calendar
        let f = defaults.string(forKey: Self.frequencyKey) ?? "off"
        frequency = BackupSchedule.frequencies.contains(f) ? f : "off"
        time = BackupSchedule.validatedTime(defaults.string(forKey: Self.timeKey))
        let w = defaults.object(forKey: Self.weekdayKey) as? Int ?? 0
        weekday = (0...6).contains(w) ? w : 0
        let k = defaults.object(forKey: Self.keepKey) as? Int ?? 1
        keep = BackupSchedule.keepChoices.contains(k) ? k : 1
        folder = BackupFolderBookmark.load(.scheduledBackupFolder, from: keychain)
        mirror = BackupFolderBookmark.load(.scheduledBackupMirror, from: keychain)
    }

    private func changed() { skipWarned = false }

    // MARK: status

    var status: ScheduleSummary {
        let warning = runWarning ?? (folderNeedsChoosing ? Self.chooseAgainText : nil)
        guard keychain != nil else { return ScheduleSummary(frequency: frequency, text: Self.unavailableText, warning: nil) }
        if frequency == "off" { return ScheduleSummary(frequency: frequency, text: Self.offText, warning: nil) }
        if !isUnlocked() { return ScheduleSummary(frequency: frequency, text: Self.lockedText, warning: warning) }
        if !hasPassword { return ScheduleSummary(frequency: frequency, text: Self.needsPasswordText, warning: Self.skippedText) }
        guard let lastSuccess else { return ScheduleSummary(frequency: frequency, text: Self.noneYetText, warning: warning) }
        return ScheduleSummary(frequency: frequency, text: String(localized: "Last scheduled backup: \(Self.stamp(lastSuccess, calendar))"), warning: warning)
    }

    nonisolated static func stamp(_ date: Date, _ calendar: Calendar) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = calendar.timeZone
        f.dateFormat = "yyyy-MM-dd HH:mm"
        return f.string(from: date)
    }

    /// When the next slot is (for the page), or nil when off.
    func nextText(now: Date = Date()) -> String? {
        guard let slot = BackupSchedule.latestSlot(now: now, frequency: frequency, time: time, weekday: weekday, calendar: calendar),
              let next = calendar.date(byAdding: .day, value: frequency == "weekly" ? 7 : 1, to: slot) else { return nil }
        return String(localized: "Next: \(Self.stamp(next, calendar))")
    }

    func noteLastSuccess(_ date: Date?) { lastSuccess = date }

    // MARK: password

    static func describe(_ error: Error) -> String {
        if let e = error as? RecoveryError { return e.message }
        if let e = error as? DesktopVaultError { return e.message }
        if error is CancellationError { return String(localized: "The vault was locked.") }
        return MacLockModel.describe(error, now: Date()) ?? String(localized: "Something went wrong.")
    }

    /// Saves the backup password for scheduled runs (Windows `backup_password`), after checking it like Windows (twice, at
    /// least 12 characters) and that it is not the master password, which is checked too (the unlock throttle applies).
    /// The master password's Argon2id key is kept with it so a run never needs the master password.
    func setPassword(_ password: String, confirm: String, master: String) async throws {
        guard keychain != nil else { throw RecoveryError(Self.unavailableText) }
        guard !password.isEmpty, !confirm.isEmpty, !master.isEmpty else { throw RecoveryError(Self.enterText) }
        guard password == confirm else { throw RecoveryError(Self.mismatchText) }
        guard password.count >= BackupSchedule.minBackupPasswordLength, password.utf8.count <= 4096 else {
            throw RecoveryError(Self.tooShortText)
        }
        guard !password.utf8.elementsEqual(master.utf8) else { throw RecoveryError(Self.sameText) }
        guard let passwords else { throw RecoveryError(Self.unavailableText) }
        // Checks the master password; with a phrase enrolled, the phrase's vault key comes with it (Ruling 9).
        var recovery = try await passwords.recoveryVaultKey(password: master)
        defer { recovery?.wipe() }
        var key = try await derive(master)
        defer { key.wipe() }
        var secret = ScheduledBackupSecret(backupPassword: password, passwordKey: key, recovery: recovery)
        defer { secret.wipe() }
        guard let store = secrets() else { throw CancellationError() }   // locked meanwhile
        try store.save(secret)
        secretRevision += 1
        phraseNotice = nil
        changed()
        lastNotice = Self.passwordSavedText
    }

    private func derive(_ master: String) async throws -> DesktopVaultFile.PasswordKey {
        let (kdf, random) = (self.kdf, self.random)
        return try await Task.detached(priority: .userInitiated) {
            try DesktopVaultFile.derivePasswordKey(password: master, kdf: kdf, random: random)
        }.value
    }

    func clearPassword() {
        secrets()?.delete()
        secretRevision += 1
        phraseNotice = nil
        changed()
        lastNotice = Self.passwordClearedText
    }

    /// The stored secret, or nil (none, locked, or not opening under the current local key).
    func secret() -> ScheduledBackupSecret? { (try? secrets()?.load()) ?? nil }

    /// The recovery phrase was replaced or removed. The rotation already re-sealed the secret (`MacVault`): a new
    /// phrase's key replaced the old one; after a removal backups open with the master password only, which the card says.
    func recoveryPhraseChanged(removed: Bool) {
        phraseNotice = removed && hasPassword ? Self.phraseRemovedText : nil
    }

    // MARK: folders

    /// The folder scheduled backups go to (`Scheduled` inside it), chosen in an `NSOpenPanel`.
    func chooseFolder(_ url: URL) throws {
        let mark = BackupFolderBookmark(bookmark: try bookmarks.bookmark(for: url), path: url.path)
        try mark.save(.scheduledBackupFolder, to: keychain)
        folder = mark
        folderNeedsChoosing = false
        runWarning = nil
        changed()
        lastSuccess = nil
    }

    /// Back to the Backups folder on this Mac.
    func clearFolder() {
        try? keychain?.delete(.scheduledBackupFolder)
        folder = nil
        folderNeedsChoosing = false
        runWarning = nil
        lastSuccess = nil
    }

    func chooseMirror(_ url: URL) throws {
        let mark = BackupFolderBookmark(bookmark: try bookmarks.bookmark(for: url), path: url.path)
        try mark.save(.scheduledBackupMirror, to: keychain)
        mirror = mark
        runWarning = nil
    }

    func clearMirror() {
        try? keychain?.delete(.scheduledBackupMirror)
        mirror = nil
        runWarning = nil
    }

    /// The chosen folder now, or nil for the default; throws `BackupFolderBookmark.unavailable` (and remembers it) when
    /// the chosen one is gone.
    func resolveFolder() throws -> URL? {
        guard let folder else { return nil }
        do {
            let url = try folder.resolve(with: bookmarks, slot: .scheduledBackupFolder, keychain: keychain)
            folderNeedsChoosing = false
            return url
        } catch {
            folderNeedsChoosing = true
            throw BackupFolderBookmark.unavailable
        }
    }

    func resolveMirror() -> URL? {
        guard let mirror else { return nil }
        return try? mirror.resolve(with: bookmarks, slot: .scheduledBackupMirror, keychain: keychain)
    }

    // MARK: manual backups (Recovery centre)

    /// Keeps the folder of a manual full backup as a bookmark, so the next launch starts there (and Clean up… can use it).
    func rememberManualFolder(_ url: URL) {
        guard let bytes = try? bookmarks.bookmark(for: url) else { return }
        try? BackupFolderBookmark(bookmark: bytes, path: url.path).save(.manualBackupFolder, to: keychain)
    }

    func manualFolder() -> URL? {
        guard let mark = BackupFolderBookmark.load(.manualBackupFolder, from: keychain) else { return nil }
        return try? mark.resolve(with: bookmarks, slot: .manualBackupFolder, keychain: keychain)
    }
}
