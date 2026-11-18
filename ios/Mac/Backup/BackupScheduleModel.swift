import Foundation
import Observation
import LGKCore
import AppSharedMac

/// Scheduled backups' settings and status (Windows `backup_schedule.py`, `app/settings.py` backup password and
/// `_schedule_status`, with "this Mac"): frequency, time, weekday, how many to keep, the folder and the mirror folder
/// (bookmarks), and the backup key. `MacBackupScheduler` runs them.
///
/// Scheduled backups lock with a **public backup key** (design `docs/design/backup-public-key-2026-10-31.md`): only
/// its record is stored (`ScheduleSecretStore` format v2), never the backup password. Setting needs the master
/// password; changing needs the current backup password (optionally re-locking the version 3 backups, never older
/// ones); a reset needs the vault's current recovery phrase bound in the record (owner decision Q2); removing needs
/// either. A v1 secret (the stored password of an older install) is migrated at the first unlock.
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
    nonisolated static let passwordSavedText = String(localized: "Backup password set. Scheduled backups lock with its public key; the password itself is not stored on this Mac.")
    nonisolated static let passwordClearedText = String(localized: "Backup password removed. Scheduled backups are off.")
    nonisolated static let clearQuestion = String(localized: "Scheduled backups stop until you set a backup password again. Existing backup files keep the password they were made with.")
    nonisolated static let unavailableText = String(localized: "Scheduled backups aren't available in this build.")
    nonisolated static let defaultFolderText = String(localized: "In the Backups folder on this Mac")
    nonisolated static let mirrorText = String(localized: "A copy of each scheduled backup also goes to this folder, for example one your cloud app syncs. Only encrypted backups are copied.")
    nonisolated static let phraseRemovedText = String(localized: "The recovery phrase was removed, so new scheduled backups open with the master password only.")
    nonisolated static let keepTitles = [String(localized: "Keep newest"), String(localized: "Keep newest two")]
    nonisolated static let frequencyTitles = [String(localized: "Off"), String(localized: "Daily"), String(localized: "Weekly")]

    // Public-key backups (design sections 5-9, 16).
    nonisolated static let upgradeNoticeText = String(localized: "Scheduled backups now lock with a public key. The app no longer stores your backup password.")
    nonisolated static let upgradeRecommendText = String(localized: "Change your backup password to finish the upgrade.")
    nonisolated static let upgradeReminderText = String(localized: "Reminder: change your backup password to finish the upgrade. Copies of the vault from before the upgrade still hold the old one.")
    nonisolated static let keyMigratedText = String(localized: "Backup password: from before the upgrade (changing it is recommended)")
    nonisolated static let notSetText = String(localized: "Not set · scheduled backups need one")
    nonisolated static let damagedText = String(localized: "The backup key on this Mac is damaged, so scheduled backups are skipped. Set a new backup password.")
    nonisolated static let damagedSkippedText = String(localized: "Scheduled backup skipped: the backup key on this Mac is damaged.")
    nonisolated static let pausedSkippedText = String(localized: "Scheduled backups are paused: confirm or change the backup password.")
    nonisolated static let migrationFailedText = String(localized: "Scheduled backups are skipped this session: the backup key could not be saved. The app tries again at the next unlock.")
    nonisolated static let alreadySetText = String(localized: "A backup password is already set. Use Change to replace it.")
    nonisolated static let enterChangeText = String(localized: "Enter the current backup password and the new one twice.")
    nonisolated static let enterNewText = String(localized: "Enter the new backup password twice.")
    nonisolated static let changedText = String(localized: "Backup password changed. New scheduled backups use it.")
    nonisolated static let resetUnavailableText = String(localized: "This backup password was set when no recovery phrase was active, so it cannot be reset. Scheduled backups keep using it. To start over with a new password, make a manual backup in Recovery centre.")
    nonisolated static let rebindNeededText = String(localized: "Your recovery phrase changed. Enter the backup password once so the new phrase can reset it. Until then the backup password can't be reset with the phrase.")
    nonisolated static let noPhraseResetText = String(localized: "No recovery phrase is set, so the backup password can't be reset. Scheduled backups keep using it.")
    nonisolated static let reboundText = String(localized: "The recovery phrase can now reset the backup password.")
    nonisolated static let removeRefusedText = String(localized: "That is neither the current backup password nor the recovery phrase that can reset it.")
    nonisolated static let confirmedText = String(localized: "Backup password confirmed. Scheduled backups run again.")
    nonisolated static let testOKText = String(localized: "Opened with your backup password.")
    nonisolated static let testNoBackupText = String(localized: "The backup password is right. There is no scheduled backup to open yet.")
    nonisolated static let busyText = String(localized: "A scheduled backup is running. Try again in a moment.")
    nonisolated static let relockNoteText = String(localized: "Only scheduled backups made with the public key are re-locked. Older backups keep the password they were made with.")
    // Review fixes M1, M2, L4 and design 16c.
    nonisolated static let unreadableText = String(localized: "The backup key on this Mac could not be read. Nothing was changed. Try again later.")
    nonisolated static let changedMeanwhileText = String(localized: "The vault's keys changed while this was running (for example the master password or the recovery phrase). Nothing was saved. Try again.")
    nonisolated static let pausedRefusedText = String(localized: "Scheduled backups are paused. Enter the backup password last set on this Mac, or reset it with the recovery phrase.")
    nonisolated static let masterNeededText = String(localized: "Enter your master password too: the backup key on this Mac has to be written again.")
    nonisolated static let testOlderKeyText = String(localized: "The backup password is right. The scheduled backups in the folder use an older backup password, so none was opened.")

    nonisolated static var copy: [String] {
        [offText, lockedText, needsPasswordText, noneYetText, skippedText, failedText, savedText, mirroredText, chooseAgainText,
         chooseMirrorAgainText, enterText, mismatchText, tooShortText, sameText, passwordSavedText, passwordClearedText,
         clearQuestion, unavailableText, defaultFolderText, mirrorText, phraseRemovedText, upgradeNoticeText, upgradeRecommendText,
         upgradeReminderText, keyMigratedText, notSetText, damagedText, damagedSkippedText, pausedSkippedText, migrationFailedText,
         alreadySetText, enterChangeText, enterNewText, changedText, resetUnavailableText, rebindNeededText, noPhraseResetText,
         reboundText, removeRefusedText, confirmedText, testOKText, testNoBackupText, busyText, relockNoteText,
         unreadableText, changedMeanwhileText, pausedRefusedText, masterNeededText, testOlderKeyText]
    }

    /// "Backup password set on <date>".
    nonisolated static func keySetText(_ date: String) -> String { String(localized: "Backup password set on \(date)") }
    /// Shown while `reset_at` is set (design section 6 step 4).
    nonisolated static func keyResetText(_ date: String) -> String { String(localized: "Backup password was reset on \(date)") }
    nonisolated static func resetDoneText(_ date: String) -> String {
        String(localized: "Backup password was reset on \(date). Backups made before \(date) still need the old backup password.")
    }
    nonisolated static func phraseRefusedText(_ date: String) -> String {
        String(localized: "This is not the recovery phrase that was active when the backup password was set on \(date).")
    }
    /// Design sections 2.3 and 16c: only the backup password last set here (or a reset with the bound phrase) unpauses.
    nonisolated static func pausedText(set: String, seen: String) -> String {
        String(localized: "The backup password on this Mac was set on \(set), but a newer one was set on \(seen). This can happen after restoring an older vault. Scheduled backups are paused until you enter the backup password set on \(seen), or reset it with the recovery phrase.")
    }
    /// 16c: a v1 file (stored password) came back after a record had been seen here, and was migrated.
    nonisolated static func olderCopyPausedText(seen: String) -> String {
        String(localized: "An older copy of the vault was brought back on this Mac. The newest backup password here was set on \(seen). Scheduled backups are paused until you enter that backup password, or reset it with the recovery phrase.")
    }
    /// 16c: no record any more, although one was seen here.
    nonisolated static func missingPausedText(seen: String) -> String {
        String(localized: "The backup key on this Mac is missing, but a backup password was set here on \(seen). Scheduled backups are paused until you enter that backup password, or reset it with the recovery phrase.")
    }
    /// 16c: the record does not open or fails validation, and one was seen here.
    nonisolated static func damagedPausedText(seen: String) -> String {
        String(localized: "The backup key on this Mac is damaged. The newest backup password here was set on \(seen). Scheduled backups are paused until you enter that backup password, or reset it with the recovery phrase.")
    }

    /// The Mac has one vault (profiles are Phase 6): its scheduled files carry the tag of profile id `mac`.
    nonisolated static let profileID = "mac"
    nonisolated static let profileTag = BackupSchedule.profileTag(profileID)

    nonisolated static let frequencyKey = "scheduledBackup.frequency"
    nonisolated static let timeKey = "scheduledBackup.time"
    nonisolated static let weekdayKey = "scheduledBackup.weekday"
    nonisolated static let keepKey = "scheduledBackup.keep"
    /// Design 16c `seen_record`: the whole public record (canonical JSON, public data only) last set, changed, reset,
    /// migrated, re-bound or confirmed through the app on this Mac. Never in the vault folder, so a restore or an
    /// older copy of the vault can't bring back an older one.
    nonisolated static let seenRecordKey = "scheduledBackup.seenRecord"
    /// 16c: a v1 file migrated after a newer record had been seen here (an older vault copy): paused like a rollback.
    nonisolated static let confirmKeyIDKey = "scheduledBackup.confirmKeyID"
    /// Owner decision Q3: names of old-format scheduled backups never pruned (added to `keep`).
    nonisolated static let protectOldKey = "scheduledBackup.protectOld"
    nonisolated static let protectOldPendingKey = "scheduledBackup.protectOldPending"
    /// Owner decision Q1: when the upgrade notice and its one 30-day reminder were dismissed (Unix seconds).
    nonisolated static let upgradeDismissedKey = "scheduledBackup.upgradeNoticeDismissedAt"
    nonisolated static let upgradeReminderDismissedKey = "scheduledBackup.upgradeReminderDismissedAt"
    nonisolated static let reminderSeconds: TimeInterval = 30 * 86_400

    /// `off`, `daily` or `weekly`; the page offers only those (anything else counts as off).
    var frequency: String { didSet { defaults.set(frequency, forKey: ProfileScope.key(Self.frequencyKey)); changed() } }
    /// `HH:MM`, 24-hour; set through `setTime` from a text field.
    var time: String { didSet { defaults.set(time, forKey: ProfileScope.key(Self.timeKey)); changed() } }
    /// Monday is 0 (Windows).
    var weekday: Int { didSet { defaults.set(weekday, forKey: ProfileScope.key(Self.weekdayKey)); changed() } }
    /// 1 or 2.
    var keep: Int { didSet { defaults.set(keep, forKey: ProfileScope.key(Self.keepKey)); changed() } }

    /// A typed time: kept when it is a 24-hour time, else the error to show (Windows `parse_time`).
    @discardableResult
    func setTime(_ text: String) -> String? {
        guard let (h, m) = try? BackupSchedule.parseTime(text) else { return BackupSchedule.timeHint }
        time = String(format: "%02d:%02d", h, m)
        return nil
    }

    private(set) var folder: BackupFolderBookmark?
    private(set) var mirror: BackupFolderBookmark?
    /// Bumped when the secret or the key settings change (`keyState` reads the sealed file).
    private var secretRevision = 0
    /// A backup key is set and opens under the vault's current local key.
    var hasPassword: Bool { record != nil }
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
    /// The vault's `Backups` folder, used when no folder was chosen (set by the scheduler).
    var defaultFolder: () -> URL? = { nil }
    /// A scheduled run is writing (set by the scheduler): key operations wait.
    var runInFlight = false
    /// A key operation (set, change and re-lock, reset, remove, migration) is running: scheduled runs wait.
    private(set) var operationInFlight = false
    /// The migration's save failed: scheduled backups skip until the next unlock (design section 5 step 2).
    var migrationFailed = false
    @ObservationIgnored private var migrationTask: Task<Bool, Never>?

    @ObservationIgnored let keychain: (any KeychainVault)?
    @ObservationIgnored let bookmarks: any BookmarkResolving
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private weak var passwords: (any MasterPasswordService)?
    @ObservationIgnored private let kdf: FullBackupV2.KDF
    @ObservationIgnored private let backupKDF: FullBackupV2.KDF
    @ObservationIgnored private let random: any RandomSource
    @ObservationIgnored private let clock: () -> Date
    @ObservationIgnored let calendar: Calendar
    /// The secret store under the unlocked vault's local key (nil while locked).
    @ObservationIgnored private let secrets: @MainActor () -> ScheduleSecretStore?

    /// `kdf` (the master password key) and `backupKDF` (the backup key) other than the defaults are for tests.
    /// `keychain` nil: this build can't keep the folders (no app-only group).
    init(keychain: (any KeychainVault)?, secrets: @escaping @MainActor () -> ScheduleSecretStore?, defaults: UserDefaults = AppSettings.shared.defaults,
         passwords: (any MasterPasswordService)?, bookmarks: any BookmarkResolving = SecurityScopedBookmarks(),
         kdf: FullBackupV2.KDF = .default, backupKDF: FullBackupV2.KDF = BackupKeyKDF.defaultParameters,
         random: any RandomSource = SystemRandomSource(), calendar: Calendar = .current, clock: @escaping () -> Date = Date.init) {
        self.keychain = keychain; self.secrets = secrets; self.defaults = defaults; self.passwords = passwords; self.bookmarks = bookmarks
        self.kdf = kdf; self.backupKDF = backupKDF; self.random = random; self.calendar = calendar; self.clock = clock
        let f = defaults.string(forKey: ProfileScope.key(Self.frequencyKey)) ?? "off"
        frequency = BackupSchedule.frequencies.contains(f) ? f : "off"
        time = BackupSchedule.validatedTime(defaults.string(forKey: ProfileScope.key(Self.timeKey)))
        let w = defaults.object(forKey: ProfileScope.key(Self.weekdayKey)) as? Int ?? 0
        weekday = (0...6).contains(w) ? w : 0
        let k = defaults.object(forKey: ProfileScope.key(Self.keepKey)) as? Int ?? 1
        keep = BackupSchedule.keepChoices.contains(k) ? k : 1
        folder = BackupFolderBookmark.load(.scheduledBackupFolder, from: keychain)
        mirror = BackupFolderBookmark.load(.scheduledBackupMirror, from: keychain)
    }

    private func changed() { skipWarned = false }
    private var unixNow: Int64 { Int64(clock().timeIntervalSince1970) }

    // MARK: key state

    enum KeyState: Equatable {
        /// No secret file (never set on this device, or removed: `pause` tells which).
        case none
        /// Format v1 (a stored password from before the update): the migration is due.
        case legacy
        /// The record failed validation (section 3.3), or the file is there but does not open under this local key
        /// (bad format, authentication failure).
        case damaged(String)
        /// The file is there but could not be read (an I/O error): every key operation is refused, try again later.
        case unreadable
        case ready(BackupKeyRecord)
        /// Locked.
        case locked
    }

    var keyState: KeyState {
        _ = secretRevision
        guard let store = secrets() else { return .locked }
        return Self.state(of: store)
    }

    nonisolated static func state(of store: ScheduleSecretStore) -> KeyState {
        do {
            guard var secret = try store.load() else { return .none }
            defer { secret.wipe() }
            if let record = secret.backupKey { return .ready(record) }
            return .legacy
        } catch ScheduleSecretStore.Failure.damagedRecord(let message) {
            return .damaged(message)
        } catch ScheduleSecretStore.Failure.io {
            return .unreadable
        } catch {
            return .damaged("")   // `Failure.format` or a GCM failure: the file does not open
        }
    }

    /// The current public backup key record (nil: none, legacy, damaged, unreadable or locked).
    var record: BackupKeyRecord? { if case .ready(let r) = keyState { return r }; return nil }

    /// The stored secret, or nil (none, locked, damaged, or not opening under the current local key).
    func secret() -> ScheduledBackupSecret? { (try? secrets()?.load()) ?? nil }

    /// Design 2.3 `backup_key_seen` (key id and time of `seenRecord`).
    struct KeySeen: Equatable, Sendable {
        let keyID: String
        let setAt: Int64
    }

    var keySeen: KeySeen? { seenRecord.map { KeySeen(keyID: $0.keyID, setAt: $0.setAt) } }

    /// Design 16c `seen_record`: the public record last set, changed, reset, migrated, re-bound or confirmed here.
    var seenRecord: BackupKeyRecord? {
        _ = secretRevision
        guard let text = defaults.string(forKey: ProfileScope.key(Self.seenRecordKey)) else { return nil }
        return try? BackupKeyRecord(encoded: Array(text.utf8))
    }

    private var confirmKeyID: String? { defaults.string(forKey: ProfileScope.key(Self.confirmKeyIDKey)) }

    private func noteSeen(_ record: BackupKeyRecord) {
        if let bytes = try? record.encoded() {
            defaults.set(String(decoding: bytes, as: UTF8.self), forKey: ProfileScope.key(Self.seenRecordKey))
        }
        defaults.removeObject(forKey: ProfileScope.key(Self.confirmKeyIDKey))
        secretRevision += 1
    }

    /// After a removal with proof: the device starts over (Set needs only the master password again).
    private func forgetSeen() {
        defaults.removeObject(forKey: ProfileScope.key(Self.seenRecordKey))
        defaults.removeObject(forKey: ProfileScope.key(Self.confirmKeyIDKey))
        secretRevision += 1
    }

    /// Why scheduled backups wait for proof of `seenRecord` (16c).
    enum Pause: Equatable {
        /// The record here is older than the one seen here (2.3), or a v1 file came back and was migrated.
        case rolledBack(BackupKeyRecord)
        /// No record, although one was seen here.
        case missing
        /// The record fails validation or the file does not open, and one was seen here.
        case damaged
    }

    /// Nil on a device that never saw a record (it behaves as before), and while locked or unreadable.
    var pause: Pause? {
        guard let seen = seenRecord else { return nil }
        switch keyState {
        case .ready(let r):
            if let c = confirmKeyID, c == r.keyID { return .rolledBack(r) }
            if r.setAt < seen.setAt || (r.setAt == seen.setAt && r.keyID != seen.keyID) { return .rolledBack(r) }
            return nil
        case .none: return .missing
        case .damaged: return .damaged
        case .legacy, .unreadable, .locked: return nil   // a v1 file migrates first (then paused, `confirmKeyID`)
        }
    }

    /// Scheduled backups are paused (2.3, 16c). The only ways forward: the backup password of `seenRecord`
    /// (`confirmKey`, which writes it back) or a reset with the current phrase bound in its authority (`resetPassword`).
    var paused: Bool { pause != nil }

    /// A missing or damaged file holds no master password key and phrase key: the master password rebuilds them.
    var proofNeedsMaster: Bool { pause == .missing || pause == .damaged }

    /// The pause explanation (nil when not paused).
    var pausedNotice: String? {
        guard let pause, let seen = seenRecord else { return nil }
        let seenDay = Self.day(seen.setAt, calendar)
        switch pause {
        case .rolledBack(let r):
            if r.keyID == confirmKeyID { return Self.olderCopyPausedText(seen: seenDay) }
            return Self.pausedText(set: Self.day(r.setAt, calendar), seen: seenDay)
        case .missing: return Self.missingPausedText(seen: seenDay)
        case .damaged: return Self.damagedPausedText(seen: seenDay)
        }
    }

    /// The line beside "Backup password" (owner decision Q1 for a migrated record).
    var keyLine: String {
        switch keyState {
        case .ready(let r):
            if r.setBy == "migrated" { return Self.keyMigratedText }
            if let resetAt = r.resetAt { return Self.keyResetText(Self.day(resetAt, calendar)) }
            return Self.keySetText(Self.day(r.setAt, calendar))
        case .legacy: return Self.keyMigratedText
        case .damaged: return Self.damagedText
        case .unreadable: return Self.unreadableText
        case .none, .locked: return Self.notSetText
        }
    }

    /// Owner decision Q1: after the migration, a dismissible notice; once dismissed, one reminder 30 days later.
    var upgradeNotice: String? {
        _ = secretRevision
        guard let r = record, r.setBy == "migrated" else { return nil }
        guard let dismissed = defaults.object(forKey: ProfileScope.key(Self.upgradeDismissedKey)) as? Double else {
            return Self.upgradeNoticeText + " " + Self.upgradeRecommendText
        }
        guard defaults.object(forKey: ProfileScope.key(Self.upgradeReminderDismissedKey)) == nil,
              clock().timeIntervalSince1970 >= dismissed + Self.reminderSeconds else { return nil }
        return Self.upgradeReminderText
    }

    /// Hides the notice (the migration stays done); the second dismissal ends the reminders.
    func dismissUpgradeNotice() {
        let now = clock().timeIntervalSince1970
        if defaults.object(forKey: ProfileScope.key(Self.upgradeDismissedKey)) == nil {
            defaults.set(now, forKey: ProfileScope.key(Self.upgradeDismissedKey))
        } else {
            defaults.set(now, forKey: ProfileScope.key(Self.upgradeReminderDismissedKey))
        }
        secretRevision += 1
    }

    private func clearUpgradeNotice() {
        defaults.removeObject(forKey: ProfileScope.key(Self.upgradeDismissedKey))
        defaults.removeObject(forKey: ProfileScope.key(Self.upgradeReminderDismissedKey))
    }

    /// The current phrase's reset authority for `record` (nil without a phrase). The stored phrase key follows every
    /// rotation (`MacVault.commitRotation`), so it is the vault's current phrase.
    private func currentAuthority(_ secret: ScheduledBackupSecret, _ record: BackupKeyRecord) -> JSONValue? {
        try? ResetAuthority.captureMac(secret.recovery, keyID: record.keyID)
    }

    /// Owner decision Q2: the phrase was replaced (or enrolled) since the key was set; the backup password re-binds it.
    var needsRebind: Bool {
        guard let s = self.secret(), let r = s.backupKey, let current = currentAuthority(s, r) else { return false }
        return !r.isBound(to: current)
    }

    /// Why "Forgot the backup password?" can't reset now, or nil when it can.
    var resetUnavailableReason: String? {
        if let pause, let seen = seenRecord {
            // 16c: the reset replaces the record last seen here, with the current phrase bound in its authority.
            if seen.resetAuthority == nil { return Self.resetUnavailableText }
            if case .rolledBack = pause, let s = self.secret(), currentAuthority(s, seen) == nil { return Self.noPhraseResetText }
            return nil   // missing or damaged: the master password gives the current phrase
        }
        guard let s = self.secret(), let r = s.backupKey else { return Self.notSetText }
        let current = currentAuthority(s, r)
        if current != nil, !r.isBound(to: current) { return Self.rebindNeededText }
        if r.resetAuthority == nil { return Self.resetUnavailableText }
        if current == nil { return Self.noPhraseResetText }
        return nil
    }

    /// Local short date of integer Unix seconds (design section 8: formatted only in the UI).
    nonisolated static func day(_ seconds: Int64, _ calendar: Calendar) -> String {
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .none
        f.timeZone = calendar.timeZone
        return f.string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
    }

    // MARK: status

    var status: ScheduleSummary {
        let warning = runWarning ?? (folderNeedsChoosing ? Self.chooseAgainText : nil)
        guard keychain != nil else { return ScheduleSummary(frequency: frequency, text: Self.unavailableText, warning: nil) }
        if frequency == "off" { return ScheduleSummary(frequency: frequency, text: Self.offText, warning: nil) }
        if !isUnlocked() { return ScheduleSummary(frequency: frequency, text: Self.lockedText, warning: warning) }
        if paused { return ScheduleSummary(frequency: frequency, text: Self.pausedSkippedText, warning: Self.pausedSkippedText) }
        switch keyState {
        case .none, .locked:
            return ScheduleSummary(frequency: frequency, text: Self.needsPasswordText, warning: Self.skippedText)
        case .damaged:
            return ScheduleSummary(frequency: frequency, text: Self.needsPasswordText, warning: Self.damagedSkippedText)
        case .unreadable:
            return ScheduleSummary(frequency: frequency, text: Self.unreadableText, warning: Self.unreadableText)
        case .legacy:
            if migrationFailed { return ScheduleSummary(frequency: frequency, text: Self.migrationFailedText, warning: Self.migrationFailedText) }
        case .ready:
            break
        }
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

    // MARK: key operations

    static func describe(_ error: Error) -> String {
        if let e = error as? RecoveryError { return e.message }
        if let e = error as? DesktopVaultError { return e.message }
        if let e = error as? BackupKeyError { return e.message }
        if let e = error as? FullBackupError { return e.message }
        if let e = error as? RecoveryPhraseError { return e.message }
        if error is CancellationError { return String(localized: "The vault was locked.") }
        return MacLockModel.describe(error, now: Date()) ?? String(localized: "Something went wrong.")
    }

    /// One key operation at a time, never while a scheduled run writes.
    private func begin() throws {
        guard !runInFlight, !operationInFlight else { throw RecoveryError(Self.busyText) }
        operationInFlight = true
    }

    /// What a key operation read when it started (review M1): the store instance (a new one at every unlock, so after
    /// every key rotation) and its sealed bytes (every save seals with a fresh nonce).
    private struct Generation {
        let store: ScheduleSecretStore
        let bytes: Data?
    }

    /// The generation now. Locked: `CancellationError`; a file that can't be read: refused (try again later).
    private func generation() throws -> Generation {
        guard let store = secrets() else { throw CancellationError() }
        do { return Generation(store: store, bytes: try store.sealedBytes()) } catch { throw RecoveryError(Self.unreadableText) }
    }

    /// The secret as `generation` saw it (nil: no file, or it does not open).
    private func load(_ generation: Generation) -> ScheduledBackupSecret? { (try? generation.store.load()) ?? nil }

    /// Review M1: saves `secret` (nil: removes the file) only when nothing changed since `generation` was taken: the
    /// same store (no lock, unlock or key rotation since) holding the same sealed bytes (no other save, rotation
    /// re-seal or removal), so its master password key, phrase key and record are the ones the operation read. The
    /// check and the write run on the main actor with no suspension point in between, and `MacVault.commitRotation`
    /// is synchronous on the main actor too: a rotation lands either before the check (which then fails, and nothing
    /// is saved) or after the write (and re-seals what was written with its own new keys).
    private func commit(_ secret: ScheduledBackupSecret?, over generation: Generation) throws {
        guard let store = secrets(), store === generation.store else { throw RecoveryError(Self.changedMeanwhileText) }
        let now: Data?
        do { now = try store.sealedBytes() } catch { throw RecoveryError(Self.unreadableText) }
        guard now == generation.bytes else { throw RecoveryError(Self.changedMeanwhileText) }
        if let secret { try store.save(secret) } else { try store.delete() }
        secretRevision += 1
    }

    /// Change, re-bind and remove act on the record in the vault: refused while it waits for proof (16c), while a v1
    /// file from an older vault copy waits to migrate, and while the file can't be read.
    private func requireUnpaused() throws {
        let state = keyState
        if case .unreadable = state { throw RecoveryError(Self.unreadableText) }
        if case .legacy = state, seenRecord != nil { throw RecoveryError(Self.pausedRefusedText) }
        if paused { throw RecoveryError(Self.pausedRefusedText) }
    }

    /// The new password typed twice: equal bytes (no Unicode normalisation: the key is derived from the bytes),
    /// 12-4096 characters, and not the master password (checked against the stored master password key).
    private func checkNew(_ password: String, _ confirm: String, passwordKey: DesktopVaultFile.PasswordKey?) async throws {
        guard !password.isEmpty, !confirm.isEmpty else { throw RecoveryError(Self.enterNewText) }
        guard password.utf8.elementsEqual(confirm.utf8) else { throw RecoveryError(Self.mismatchText) }
        guard BackupKey.validLength(password) else { throw RecoveryError(Self.tooShortText) }
        if let passwordKey {
            let same = await Task.detached(priority: .userInitiated) { passwordKey.matches(password) }.value
            if same { throw RecoveryError(Self.sameText) }
        }
    }

    /// A new key pair with a fresh salt (Argon2id off the main actor).
    private func newKeyPair(_ password: String) async throws -> BackupKeyPair {
        let kdf = try BackupKeyKDF.fresh(backupKDF, random: random)
        return try await Task.detached(priority: .userInitiated) { try BackupKey.derive(password: password, kdf: kdf) }.value
    }

    /// Proof (a), keeping the pair for a re-lock.
    private func proof(_ record: BackupKeyRecord, _ password: String) async -> BackupKeyPair? {
        await Task.detached(priority: .userInitiated) { record.matchingKeyPair(password) }.value
    }

    /// Proof (a) only.
    private func matches(_ record: BackupKeyRecord, _ password: String) async -> Bool {
        await Task.detached(priority: .userInitiated) { record.passwordMatches(password) }.value
    }

    private func derive(_ master: String) async throws -> DesktopVaultFile.PasswordKey {
        let (kdf, random) = (self.kdf, self.random)
        return try await Task.detached(priority: .userInitiated) {
            try DesktopVaultFile.derivePasswordKey(password: master, kdf: kdf, random: random)
        }.value
    }

    /// The secret a write-back of `seen` starts from (16c): the stored master password key and phrase key when the
    /// vault's file opens (a rolled-back record), else rebuilt from the master password, which is checked (a missing
    /// or damaged file holds neither). Its record is `seen`; a reset replaces it.
    private func writeBackBase(_ pause: Pause, _ generation: Generation, seen: BackupKeyRecord,
                               master: String) async throws -> ScheduledBackupSecret {
        switch pause {
        case .rolledBack:
            guard var secret = load(generation), secret.backupKey != nil else { throw RecoveryError(Self.changedMeanwhileText) }
            secret.backupKey = seen
            return secret
        case .missing, .damaged:
            guard !master.isEmpty else { throw RecoveryError(Self.masterNeededText) }
            guard let passwords else { throw RecoveryError(Self.unavailableText) }
            // Checks the master password (the unlock throttle applies); the phrase's vault key comes with it.
            let recovery = try await passwords.recoveryVaultKey(password: master)
            return try await ScheduledBackupSecret(backupKey: seen, passwordKey: derive(master), recovery: recovery)
        }
    }

    /// Set (no key yet on a device that never saw one, or a damaged one there): the backup password twice and the
    /// master password, which is checked (the unlock throttle applies) and must differ. Only the public record is
    /// stored, with the master password's Argon2id key (so a run never needs the master password) and the phrase's
    /// vault key; the authority binds the current phrase. Once a record was seen on this Mac, a missing or damaged
    /// one is replaced only with its proof (`confirmKey`, `resetPassword`; design 16c).
    func setPassword(_ password: String, confirm: String, master: String) async throws {
        guard keychain != nil else { throw RecoveryError(Self.unavailableText) }
        guard !password.isEmpty, !confirm.isEmpty, !master.isEmpty else { throw RecoveryError(Self.enterText) }
        guard password.utf8.elementsEqual(confirm.utf8) else { throw RecoveryError(Self.mismatchText) }
        guard BackupKey.validLength(password) else { throw RecoveryError(Self.tooShortText) }
        guard !password.utf8.elementsEqual(master.utf8) else { throw RecoveryError(Self.sameText) }
        guard let passwords else { throw RecoveryError(Self.unavailableText) }
        switch keyState {
        case .ready, .legacy: throw RecoveryError(Self.alreadySetText)   // "remove then set" never bypasses Change
        case .unreadable: throw RecoveryError(Self.unreadableText)
        case .locked: throw CancellationError()
        case .none, .damaged: if seenRecord != nil { throw RecoveryError(Self.pausedRefusedText) }
        }
        try begin()
        defer { operationInFlight = false }
        let generation = try self.generation()
        // Checks the master password; with a phrase enrolled, the phrase's vault key comes with it (Ruling 9).
        var recovery = try await passwords.recoveryVaultKey(password: master)
        defer { recovery?.wipe() }
        var pair = try await newKeyPair(password)
        defer { pair.wipe() }
        let record = try BackupKeyRecord.build(key: pair, now: unixNow, setBy: "set",
                                               resetAuthority: try ResetAuthority.captureMac(recovery, keyID: pair.keyID), previous: nil)
        var secret = try await ScheduledBackupSecret(backupKey: record, passwordKey: derive(master), recovery: recovery)
        defer { secret.wipe() }
        try commit(secret, over: generation)
        noteSeen(record)
        clearUpgradeNotice()
        phraseNotice = nil
        changed()
        lastNotice = Self.passwordSavedText
    }

    /// Change (section 7): proof with the current backup password, the new one twice. With `relock`, this Mac's
    /// scheduled **version 3** backups (Scheduled folder and mirror) are re-locked to the new key; older ones are
    /// never touched. Refused while paused (16c: the record here may be a rolled-back one). Returns the result text.
    @discardableResult
    func changePassword(old: String, new: String, confirm: String, relock: Bool) async throws -> String {
        guard !old.isEmpty, !new.isEmpty, !confirm.isEmpty else { throw RecoveryError(Self.enterChangeText) }
        try requireUnpaused()
        try begin()
        defer { operationInFlight = false }
        let generation = try self.generation()
        guard var secret = load(generation), let record = secret.backupKey else { throw RecoveryError(Self.notSetText) }
        defer { secret.wipe() }
        try await checkNew(new, confirm, passwordKey: secret.passwordKey)
        // Boxed, so the re-lock task and this function share one private key buffer, zeroed at the end (review L3).
        guard let oldKey = await proof(record, old).map(KeyPairBox.init) else { throw BackupKeyError.notCurrentPassword }
        defer { oldKey.wipe() }
        var pair = try await newKeyPair(new)
        defer { pair.wipe() }
        let newRecord = try BackupKeyRecord.build(key: pair, now: unixNow, setBy: "changed",
                                                  resetAuthority: try ResetAuthority.captureMac(secret.recovery, keyID: pair.keyID),
                                                  previous: record)
        secret.backupKey = newRecord   // in place: no second copy of the keys left unwiped (review L3)
        try commit(secret, over: generation)
        noteSeen(newRecord)
        clearUpgradeNotice()
        changed()
        var text = Self.changedText
        if relock {
            let targets = relockTargets()
            let (tag, rnd, now) = (Self.profileTag, random, unixNow)
            let result = await Task.detached(priority: .userInitiated) { () -> BackupKeyRelock.Result in
                let scoped = targets.map { $0.scope.startAccessingSecurityScopedResource() }
                defer { for (t, s) in zip(targets, scoped) where s { t.scope.stopAccessingSecurityScopedResource() } }
                return BackupKeyRelock.relock(folders: targets.map(\.folder), tag: tag, oldKey: oldKey.pair, newRecord: newRecord,
                                              random: rnd, now: now)
            }.value
            text += " " + BackupKeyRelock.text(result)
        }
        lastNotice = text
        return text
    }

    /// The Scheduled folder (chosen or this Mac's) and the mirror: the only folders a re-lock looks in (section 7.2).
    private func relockTargets() -> [(scope: URL, folder: URL)] {
        var out: [(scope: URL, folder: URL)] = []
        let base: URL? = folder == nil ? defaultFolder() : (try? resolveFolder()) ?? nil
        if let base { out.append((base, base.appendingPathComponent(BackupSchedule.scheduledDirName, isDirectory: true))) }
        if let m = resolveMirror() { out.append((m, m)) }
        return out
    }

    /// Reset (section 6, strict Q2): the vault's current recovery phrase, bound in the record, then the new password
    /// twice. Older backups keep needing the old password (a reset cannot re-lock). While paused (16c) the reset
    /// replaces the record last seen on this Mac, never the rolled-back, missing or damaged one, and the phrase must be
    /// bound in the seen record and be the vault's current one; a missing or damaged file also needs `master`.
    func resetPassword(phrase: String, new: String, confirm: String, master: String = "") async throws {
        if case .unreadable = keyState { throw RecoveryError(Self.unreadableText) }
        try begin()
        defer { operationInFlight = false }
        let generation = try self.generation()
        var entropy = [UInt8](try BIP39.entropy(from: phrase))
        defer { for i in entropy.indices { entropy[i] = 0 } }
        let replaced: BackupKeyRecord
        var secret: ScheduledBackupSecret
        if let pause = self.pause {
            guard let seen = seenRecord else { throw RecoveryError(Self.notSetText) }
            guard seen.resetAuthority != nil else { throw RecoveryError(Self.resetUnavailableText) }
            replaced = seen
            secret = try await writeBackBase(pause, generation, seen: seen, master: master)
        } else {
            guard let s = load(generation), let r = s.backupKey else { throw RecoveryError(Self.notSetText) }
            replaced = r
            secret = s
        }
        defer { secret.wipe() }
        guard replaced.resetAuthority != nil else { throw RecoveryError(Self.resetUnavailableText) }
        guard try ResetAuthority.verifyReset(record: replaced, entropy: entropy, current: currentAuthority(secret, replaced)) else {
            throw RecoveryError(Self.phraseRefusedText(Self.day(replaced.setAt, calendar)))
        }
        try await checkNew(new, confirm, passwordKey: secret.passwordKey)
        var pair = try await newKeyPair(new)
        defer { pair.wipe() }
        let now = unixNow
        let newRecord = try BackupKeyRecord.build(key: pair, now: now, setBy: "reset",
                                                  resetAuthority: try ResetAuthority.captureMac(secret.recovery, keyID: pair.keyID),
                                                  previous: replaced)
        secret.backupKey = newRecord
        try commit(secret, over: generation)
        noteSeen(newRecord)
        clearUpgradeNotice()
        changed()
        lastNotice = Self.resetDoneText(Self.day(now, calendar))
    }

    /// Re-bind (Q2): after the recovery phrase was replaced or enrolled, the backup password binds the authority to
    /// the current phrase. Only the authority changes (16b: `set_at` and history stay). The seen record follows it
    /// (same key id and time), so a reset after a later rollback checks the new phrase (16c (b)).
    func rebind(password: String) async throws {
        try requireUnpaused()
        try begin()
        defer { operationInFlight = false }
        let generation = try self.generation()
        guard var secret = load(generation), let record = secret.backupKey else { throw RecoveryError(Self.notSetText) }
        defer { secret.wipe() }
        let current = currentAuthority(secret, record)
        let rebound = try await Task.detached(priority: .userInitiated) {
            try record.rebound(password: password, resetAuthority: current)
        }.value
        secret.backupKey = rebound
        try commit(secret, over: generation)
        noteSeen(rebound)
        lastNotice = Self.reboundText
    }

    enum Proof: Sendable {
        case password(String)
        case phrase(String)
    }

    /// Remove (section 4): proof with the current backup password or the bound current phrase, so "remove then set"
    /// can't bypass Change. Refused while paused (16c). A damaged record on a device that never saw one can be removed
    /// without proof (nothing in it can be proven; Set then starts over). After a removal the device starts over:
    /// the seen record goes too.
    func removeKey(proof: Proof) async throws {
        try requireUnpaused()
        try begin()
        defer { operationInFlight = false }
        let generation = try self.generation()
        switch Self.state(of: generation.store) {
        case .ready(let record):
            let ok: Bool
            switch proof {
            case .password(let p): ok = await matches(record, p)
            case .phrase(let text):
                guard var secret = load(generation) else { throw RecoveryError(Self.changedMeanwhileText) }
                defer { secret.wipe() }
                var entropy = [UInt8](try BIP39.entropy(from: text))
                defer { for i in entropy.indices { entropy[i] = 0 } }
                ok = try ResetAuthority.verifyReset(record: record, entropy: entropy, current: currentAuthority(secret, record))
            }
            guard ok else { throw RecoveryError(Self.removeRefusedText) }
        case .legacy:
            guard var secret = load(generation) else { throw RecoveryError(Self.removeRefusedText) }
            defer { secret.wipe() }
            guard case .password(let p) = proof, let stored = secret.legacyPassword,
                  stored.utf8.elementsEqual(p.utf8) else { throw RecoveryError(Self.removeRefusedText) }
        case .damaged, .none:
            break   // only where no record was ever seen (`requireUnpaused`)
        case .unreadable:
            throw RecoveryError(Self.unreadableText)
        case .locked:
            throw CancellationError()
        }
        try commit(nil, over: generation)
        forgetSeen()
        phraseNotice = nil
        changed()
        lastNotice = Self.passwordClearedText
    }

    /// Pause (2.3, 16c): the backup password of the record last seen on this Mac (proof (a)) writes that record back
    /// into the vault and resumes scheduled backups. The password of the rolled-back record here never does. A
    /// missing or damaged file also needs the master password (`master`) to rebuild its keys.
    func confirmKey(password: String, master: String = "") async throws {
        if case .unreadable = keyState { throw RecoveryError(Self.unreadableText) }
        guard let pause, let seen = seenRecord else { throw RecoveryError(Self.notSetText) }
        try begin()
        defer { operationInFlight = false }
        let generation = try self.generation()
        guard await matches(seen, password) else { throw BackupKeyError.notCurrentPassword }
        var secret = try await writeBackBase(pause, generation, seen: seen, master: master)
        defer { secret.wipe() }
        // A key rotation drops the record when the new master password is its backup password (`MacVault`): proven,
        // but never written back. The device starts over and Set asks for a different backup password.
        let same = await Task.detached(priority: .userInitiated) { [passwordKey = secret.passwordKey] in
            passwordKey.matches(password)
        }.value
        if same {
            forgetSeen()
            changed()
            lastNotice = Self.sameText
            return
        }
        try commit(secret, over: generation)
        noteSeen(seen)
        changed()
        lastNotice = Self.confirmedText
    }

    /// Design 9.2 "Test a backup": the typed password against the record (refreshing the seen record when it matches
    /// and nothing is paused), then the newest scheduled **version 3** backup locked to this record, opened with it
    /// (outer layer; nothing is written). Files under another key or in an old format are not tried (review L4).
    @discardableResult
    func testBackup(password: String) async throws -> String {
        guard let record else { throw RecoveryError(Self.notSetText) }
        guard await matches(record, password) else { throw BackupKeyError.notCurrentPassword }
        if !paused { noteSeen(record) }
        let base: URL? = folder == nil ? defaultFolder() : (try? resolveFolder()) ?? nil
        guard let base else { lastNotice = Self.testNoBackupText; return Self.testNoBackupText }
        let directory = base.appendingPathComponent(BackupSchedule.scheduledDirName, isDirectory: true)
        let keyID = record.keyID
        let text = try await Task.detached(priority: .userInitiated) { () throws -> String in
            let scoped = base.startAccessingSecurityScopedResource()
            defer { if scoped { base.stopAccessingSecurityScopedResource() } }
            let files = BackupSchedule.ownedBackups(in: directory, tag: Self.profileTag)
            guard !files.isEmpty else { return Self.testNoBackupText }
            for url in files {   // newest first
                guard let data = try? Data(contentsOf: url, options: .alwaysMapped),
                      FullBackup.headerVersion(data) == FullBackupV3.version,
                      let info = try? FullBackupV3.inspect(data), info.recipient.keyID == keyID else { continue }
                _ = try FullBackup.open(data, password: password)
                return Self.testOKText
            }
            return Self.testOlderKeyText
        }.value
        lastNotice = text
        return text
    }

    // MARK: migration (design section 5, Q3)

    /// The first unlock after the update: a v1 secret (stored backup password) becomes a record derived from that
    /// password (`set_by = "migrated"`, authority from the current phrase) in one atomic save that drops the password.
    /// No backup file is written, renamed, moved or deleted; the newest old-format scheduled backup is protected from
    /// pruning (Q3, a read of the folder only). A failed save keeps the v1 file and skips this session. A v1 file on a
    /// Mac that already saw a record is an older copy of the vault (16c): it is migrated the same way (the stored
    /// password goes) but stays paused until the seen record's password or a reset.
    @discardableResult
    func migrateIfNeeded() async -> Bool {
        if let migrationTask { return await migrationTask.value }
        let task = Task { await self.migrate() }
        migrationTask = task
        defer { migrationTask = nil }
        return await task.value
    }

    /// Starts the migration without waiting (the scheduler's check).
    func startMigration() {
        guard migrationTask == nil else { return }
        Task { await self.migrateIfNeeded() }
    }

    private func migrate() async -> Bool {
        guard case .legacy = keyState, !migrationFailed, !operationInFlight, !runInFlight,
              let generation = try? self.generation(), var secret = load(generation),
              let password = secret.legacyPassword else { return false }
        operationInFlight = true
        defer { operationInFlight = false; secret.wipe() }
        guard BackupKey.validLength(password), var pair = try? await newKeyPair(password) else { migrationFailed = true; return false }
        defer { pair.wipe() }
        guard let record = try? BackupKeyRecord.build(key: pair, now: unixNow, setBy: "migrated",
                                                      resetAuthority: try? ResetAuthority.captureMac(secret.recovery, keyID: pair.keyID),
                                                      previous: nil) else { migrationFailed = true; return false }
        // Saved in place, only over the same v1 file (no rotation, lock or set since it was read; review M1).
        secret.backupKey = record
        secret.legacyPassword = nil
        do {
            try commit(secret, over: generation)
        } catch let e as RecoveryError where e.message == Self.changedMeanwhileText {
            return false
        } catch {
            migrationFailed = true
            return false
        }
        if seenRecord != nil {
            defaults.set(record.keyID, forKey: ProfileScope.key(Self.confirmKeyIDKey))   // 16c: an older vault copy, paused
            secretRevision += 1
        } else {
            noteSeen(record)
        }
        defaults.set(true, forKey: ProfileScope.key(Self.protectOldPendingKey))
        clearUpgradeNotice()
        if let base = folder == nil ? defaultFolder() : (try? resolveFolder()) ?? nil {
            let scoped = base.startAccessingSecurityScopedResource()
            defer { if scoped { base.stopAccessingSecurityScopedResource() } }
            resolveProtectOld(in: base.appendingPathComponent(BackupSchedule.scheduledDirName, isDirectory: true))
        }
        return true
    }

    /// Owner decision Q3: names kept out of pruning (`BackupSchedule.prune` `protectOld`).
    var protectedOld: Set<String> { Set(defaults.stringArray(forKey: ProfileScope.key(Self.protectOldKey)) ?? []) }

    /// Once after the migration: the newest scheduled backup of this profile in `directory` whose header parses as an
    /// old format (version 1 or 2; headers only, read-only) is protected until the person deletes it. A file whose
    /// header does not parse (corrupt, partial) is never pinned (review L5). Its mirror copy has the same name.
    func resolveProtectOld(in directory: URL) {
        guard defaults.bool(forKey: ProfileScope.key(Self.protectOldPendingKey)) else { return }
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDir), isDir.boolValue else { return }
        for url in BackupSchedule.ownedBackups(in: directory, tag: Self.profileTag) {
            let version = (try? Data(contentsOf: url, options: .alwaysMapped)).flatMap { FullBackup.headerVersion($0) }
            guard version == 1 || version == 2 else { continue }
            defaults.set((protectedOld.union([url.lastPathComponent])).sorted(), forKey: ProfileScope.key(Self.protectOldKey))
            break
        }
        defaults.set(false, forKey: ProfileScope.key(Self.protectOldPendingKey))
    }

    /// A new vault on this Mac (the first one, or one made after an erase): the record seen for the old vault no
    /// longer applies, so Set works as on a fresh install (16c).
    func freshVault() { forgetSeen() }

    /// The recovery phrase was replaced or removed. The rotation already re-sealed the secret (`MacVault`): a new
    /// phrase's key replaced the old one; after a removal backups open with the master password only, which the card
    /// says. A replaced phrase no longer resets the backup password until it is re-bound (Q2, `needsRebind`).
    func recoveryPhraseChanged(removed: Bool) {
        secretRevision += 1
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

    /// Where scheduled backups are kept now, as paths for the emergency kit: the Scheduled folder (the chosen one, or
    /// this Mac's) and the mirror folder. Read from the saved paths; nothing is opened or resolved.
    func kitFolders() -> [String] {
        var out: [String] = []
        if let base = folder?.path ?? defaultFolder()?.path {
            out.append(URL(fileURLWithPath: base, isDirectory: true)
                .appendingPathComponent(BackupSchedule.scheduledDirName, isDirectory: true).path)
        }
        if let mirror { out.append(mirror.path) }
        return out
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

/// A private key shared by a key operation and its re-lock task, zeroed in place once both are done (review L3:
/// copies of a value type would each keep their own buffer).
final class KeyPairBox: @unchecked Sendable {
    private(set) var pair: BackupKeyPair
    init(_ pair: BackupKeyPair) { self.pair = pair }
    func wipe() { pair.wipe() }
}
