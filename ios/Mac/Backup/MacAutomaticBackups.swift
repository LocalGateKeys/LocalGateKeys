import Foundation
import AppSharedMac

/// Settings › Backups › Automatic backups to keep (Windows `automatic_backup_count`, `vault.py` `_rolling_backup`): after
/// each save the vault as it is then is copied to `Backups/automatic-<ms>/`, laid out like a safety copy (the records
/// sealed under the vault's key in `records.bin`, `desktop-profile.bin`, `Attachments/` cloned), and only the newest
/// `count` are kept. With the count at 0 (Off) no copy is made and older ones stay, as on Windows. The Recovery centre
/// lists them with the safety copies, and puts one back through the same gated restore.
///
/// A master password change gives the vault a new key, which only the `before-restore-` copies follow (`MacVault`
/// re-seals them). `key-check.bin` in each copy tells whether it still opens under the vault's key; one that doesn't
/// can never be restored, so it is left out of the list and removed at the next prune.
@MainActor
enum MacAutomaticBackups {
    static let prefix = "automatic-"
    static let keyCheckName = "key-check.bin"

    /// The complete automatic copies of the vault in `directory`, newest first (readable or not).
    static func copies(in directory: URL) -> [MacFullBackup.SafetyCopy] {
        let folder = MacFullBackup.backupsFolder(directory)
        let names = (try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? []
        return names.compactMap { name -> MacFullBackup.SafetyCopy? in
            guard name.hasPrefix(prefix), let ms = Int64(name.dropFirst(prefix.count)),
                  FileManager.default.fileExists(atPath: folder.appendingPathComponent(name).appendingPathComponent("records.bin").path)
            else { return nil }
            return MacFullBackup.SafetyCopy(folder: folder.appendingPathComponent(name, isDirectory: true), createdAtMillis: ms)
        }.sorted { $0.createdAtMillis > $1.createdAtMillis }
    }

    /// True when `copy` was sealed under `profile`'s key (its key check opens).
    static func opens(_ copy: MacFullBackup.SafetyCopy, with profile: DesktopProfileStore) -> Bool {
        (try? profile.openRecords(copy.folder.appendingPathComponent(keyCheckName))) != nil
    }

    /// The copies the Recovery centre can put back.
    static func restorable(in profile: DesktopProfileStore) -> [MacFullBackup.SafetyCopy] {
        copies(in: profile.directory).filter { opens($0, with: profile) }
    }

    /// Writes one copy of `records` (and the profile's `desktop-profile.bin` and `Attachments/`) under a temporary name,
    /// renamed when complete.
    @discardableResult
    static func write(records: [String: JSONValue], revision: Int64, profile: DesktopProfileStore,
                      now: Date = Date()) throws -> MacFullBackup.SafetyCopy {
        let fm = FileManager.default
        let backups = MacFullBackup.backupsFolder(profile.directory)
        try fm.createDirectory(at: backups, withIntermediateDirectories: true)
        var ms = Int64(now.timeIntervalSince1970 * 1000)
        while fm.fileExists(atPath: backups.appendingPathComponent(prefix + "\(ms)").path) { ms += 1 }
        let target = backups.appendingPathComponent(prefix + "\(ms)", isDirectory: true)
        let tmp = backups.appendingPathComponent(".\(prefix)\(UUID().uuidString)", isDirectory: true)
        do {
            try fm.createDirectory(at: tmp, withIntermediateDirectories: false)
            try profile.sealRecords([:], revision: 0).write(to: tmp.appendingPathComponent(keyCheckName))
            try profile.sealRecords(records, revision: revision).write(to: tmp.appendingPathComponent("records.bin"))
            if fm.fileExists(atPath: profile.fileURL.path) {
                try fm.copyItem(at: profile.fileURL, to: tmp.appendingPathComponent(DesktopProfileStore.fileName))
            }
            // APFS clones the files, so unchanged documents take no extra space.
            if fm.fileExists(atPath: profile.attachmentsURL.path) {
                try fm.copyItem(at: profile.attachmentsURL, to: tmp.appendingPathComponent(DesktopProfileStore.attachmentsName))
            }
            try fm.moveItem(at: tmp, to: target)
        } catch {
            try? fm.removeItem(at: tmp)
            throw error
        }
        return MacFullBackup.SafetyCopy(folder: target, createdAtMillis: ms)
    }

    /// Keeps the newest `keep` copies that open under `profile`'s key; removes the rest, the copies sealed under an
    /// old key and unfinished temporary folders. Returns the copies kept.
    @discardableResult
    static func prune(profile: DesktopProfileStore, keep: Int) -> [MacFullBackup.SafetyCopy] {
        let fm = FileManager.default
        let backups = MacFullBackup.backupsFolder(profile.directory)
        for name in (try? fm.contentsOfDirectory(atPath: backups.path)) ?? [] where name.hasPrefix(".\(prefix)") {
            try? fm.removeItem(at: backups.appendingPathComponent(name))
        }
        var kept: [MacFullBackup.SafetyCopy] = []
        for copy in copies(in: profile.directory) {
            if kept.count < keep, opens(copy, with: profile) { kept.append(copy) } else { try? fm.removeItem(at: copy.folder) }
        }
        return kept
    }

    /// After each commit while unlocked: one copy, then the prune, when the count isn't Off and no restore is running.
    /// A failed copy changes nothing else (the vault is saved already).
    @MainActor static func wire(lock: MacLockModel, defaults: UserDefaults = AppSettings.shared.defaults) {
        lock.onCommit.append { [weak lock] _ in
            // The duress password's second vault leaves no automatic copies (sub-plan 08).
            guard let lock, !lock.isSecondSession else { return }
            let keep = MacExtraSettings.automaticBackupCount(defaults)
            guard keep > 0, !MacFullBackup.anyInFlight, let profile = lock.desktopProfile, let snap = try? lock.store?.load()
            else { return }
            do {
                try write(records: snap.records, revision: snap.revision, profile: profile)
                prune(profile: profile, keep: keep)
            } catch {}
        }
    }
}
