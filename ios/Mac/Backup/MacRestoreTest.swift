import Foundation
import LGKCore
import AppSharedMac

/// The Mac's backup restore test (sub-plan 12): the newest scheduled backup of this profile, opened with the backup
/// password typed for this run (version 3 backups are locked to a key only that password opens), its `vault.json`
/// unlocked in a scratch folder with the stored password key (`scheduled-backup.bin`, sealed under the local key), so
/// no master password is typed and none is stored.
extension BackupScheduleModel {
    /// This profile's scheduled backup folder and the security-scoped URL to open around reading it (nil: no folder).
    func scheduledBackupFolder() -> (directory: URL, scope: URL)? {
        let base: URL? = folder == nil ? defaultFolder() : (try? resolveFolder()) ?? nil
        guard let base else { return nil }
        return (base.appendingPathComponent(BackupSchedule.scheduledDirName, isDirectory: true), base)
    }

    /// The newest scheduled backup of this profile, or nil.
    func newestScheduledBackup() -> (backup: URL, scope: URL)? {
        guard let found = scheduledBackupFolder() else { return nil }
        let directory = found.directory, scope = found.scope
        let scoped = scope.startAccessingSecurityScopedResource()
        defer { if scoped { scope.stopAccessingSecurityScopedResource() } }
        guard let newest = BackupSchedule.ownedBackups(in: directory, tag: Self.profileTag).first else { return nil }
        return (newest, scope)
    }

    /// The restorer for `password` and this vault's stored password key; nil without scheduled backups set up.
    func restoreTestRestorer(password: String) -> RestoreTest.Restorer? {
        guard var stored = secret() else { return nil }
        let key = stored.passwordKey
        stored.wipe()
        return RestoreTest.fullBackup(password: password, passwordKey: key)
    }
}
