import Foundation
import Security
import LGKCore
import AppSharedMac

/// Erases this Mac's vault after another member of the cloud-folder group removed it (desktop
/// `device_erase.erase_profile`, the iPhone's `VaultEraser`): the vault directory (vault, master key file,
/// Mac-local data, restored desktop profile, scheduled-backup secret, the internal `Backups` folder and its safety
/// copies, the removal watch file last), every Keychain item of this install (shared, app-only and Safari groups),
/// the Touch ID key, the Safari save files, attachment files, open copies, received shares and site icons. The
/// caller locks first (`MacLockModel.beginErase`) and then removes the AutoFill identities and reminder notifications
/// (`MacLockModel.endErase`).
///
/// Kept (owner decision 2026-10-31): before the erase, `keepScheduledBackups` moves the vault's own scheduled backups
/// (`<vault>/Backups/Scheduled`, this vault's filename pattern, readable full-backup containers) and their
/// `.sha256.json` manifests to `<Application Support>/LocalGateKeys Kept backups/Vault <YYYY-MM-DD>/` (desktop
/// `<data dir>/Kept backups/`). They are locked with the separate backup password and hold the vault under the master
/// password, so the master password alone opens nothing in them. The safety copies and `scheduled-backup.bin` (the
/// stored backup password, sealed under the local key) are erased with the rest.
///
/// Never touched: what the person exported (scheduled backups in a folder they chose, the mirror folder, `.lgkfull`
/// and CSV files, phone backups), the sync folder, and the menu bar and Open at login preferences (they hold no
/// vault data; the menu bar shows nothing without a vault). Every step is attempted; the names of the steps that
/// failed are returned (empty: done). Missing items are not errors, so erasing again is safe.
struct MacVaultEraser: Sendable {
    let directory: URL
    let keychains: [any KeychainVault]
    let biometric: @Sendable () throws -> Void
    var extraDirectories: @Sendable () -> [URL] = { [] }
    /// The folder kept scheduled backups go to (nil: none are kept). Never inside a folder this eraser deletes.
    var keptBackupsRoot: @Sendable () -> URL? = { nil }

    /// Beside, not inside, `<Application Support>/LocalGateKeys` (which `localFolders` erases).
    static let keptFolderName = "LocalGateKeys Kept backups"

    static func defaultKeptRoot() -> URL? {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent(keptFolderName, isDirectory: true)
    }

    static func live(directory: URL) -> MacVaultEraser {
        var groups: [String?] = [AppGroup.keychainAccessGroup]
        for group in [AppGroup.appKeychainAccessGroup, AppGroup.safariKeychainAccessGroup] {
            if let g = group, !g.isEmpty, !g.hasPrefix("."), !g.contains("$(") { groups.append(g) }
        }
        groups.append(nil)   // the default group (Safari keys of a build without their own group)
        return MacVaultEraser(directory: directory, keychains: groups.map { SystemKeychainVault(accessGroup: $0, accountPrefix: ProfileScope.keychainPrefix) },
                              biometric: { [prefix = ProfileScope.keychainPrefix] in try SystemBiometricKeyStore(accessGroup: AppGroup.keychainAccessGroup, accountPrefix: prefix).remove() },
                              extraDirectories: { MacVaultEraser.localFolders() },
                              keptBackupsRoot: { MacVaultEraser.defaultKeptRoot() })
    }

    /// `<Application Support>/LocalGateKeys` (attachments, received shares), the open copies, the site icons and the
    /// Safari save files.
    static func localFolders() -> [URL] {
        var dirs = [AttachmentFiles.openCopiesDirectory]
        if let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            // Another profile erases only its own attachments; the default profile's folder holds the others'.
            if ProfileScope.isDefault {
                let root = support.appendingPathComponent("LocalGateKeys", isDirectory: true)
                let others = root.appendingPathComponent("Profiles", isDirectory: true)
                let items = (try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)) ?? []
                dirs += items.filter { $0.standardizedFileURL != others.standardizedFileURL }
            } else {
                dirs.append(AttachmentFiles.localRoot(support))
            }
        }
        // `SiteIconStore.defaultDirectory`, spelled out (the store is main-actor isolated).
        if let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first {
            dirs.append(caches.appendingPathComponent("SiteIcons", isDirectory: true))
        }
        if let safari = try? SafariSaveFiles.location() { dirs.append(safari) }
        // The pre-Safari-group folder (shared group), in case the launch migration could not move it.
        if let legacy = SafariSaveFiles.legacyLocation() { dirs.append(legacy) }
        return dirs
    }

    /// Moves this vault's scheduled backups out of the vault folder before `erase` (desktop `keep_scheduled_backups`):
    /// only files in `<vault>/Backups/Scheduled` that match this vault's scheduled-backup name and open as a full-backup
    /// container (header only, no password), each with its `.sha256.json`. They go to a new
    /// `<root>/Vault <YYYY-MM-DD>[ (n)]` folder, which is returned (nil: nothing moved). A file that cannot be moved
    /// stays and is erased with the rest. Never moves anything from outside the vault folder.
    func keepScheduledBackups(now: Date = Date(), calendar: Calendar = .current) -> URL? {
        let fm = FileManager.default
        let source = MacFullBackup.backupsFolder(directory)
            .appendingPathComponent(BackupSchedule.scheduledDirName, isDirectory: true)
        let files = BackupSchedule.ownedBackups(in: source, tag: BackupScheduleModel.profileTag).filter { url in
            guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { return false }
            return (try? FullBackup.inspect(data)) != nil   // v2, or v3 (scheduled to a public key)
        }
        guard !files.isEmpty, let root = keptBackupsRoot()?.standardizedFileURL else { return nil }
        // The kept folder must survive the erase: never inside the vault folder or another folder erased below.
        for erased in [directory] + extraDirectories() {
            let path = erased.standardizedFileURL.path
            if root.path == path || root.path.hasPrefix(path.hasSuffix("/") ? path : path + "/") { return nil }
        }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.calendar = Calendar(identifier: .gregorian)
        f.timeZone = calendar.timeZone
        f.dateFormat = "yyyy-MM-dd"
        let base = "Vault \(f.string(from: now))"
        guard let target = (1..<1000).lazy
            .map({ root.appendingPathComponent($0 == 1 ? base : "\(base) (\($0))", isDirectory: true) })
            .first(where: { !fm.fileExists(atPath: $0.path) }) else { return nil }
        do { try fm.createDirectory(at: target, withIntermediateDirectories: true) } catch { return nil }
        var moved = 0
        for url in files {
            do { try fm.moveItem(at: url, to: target.appendingPathComponent(url.lastPathComponent)) } catch { continue }
            moved += 1
            let manifest = url.appendingPathExtension("sha256.json")
            if fm.fileExists(atPath: manifest.path) {
                try? fm.moveItem(at: manifest, to: target.appendingPathComponent(manifest.lastPathComponent))
            }
        }
        if moved == 0 { try? fm.removeItem(at: target); return nil }
        return target
    }

    @discardableResult
    func erase() -> [String] {
        var failed: [String] = []
        let fm = FileManager.default
        let watch = SyncDependencies.watchFileURL(in: directory)
        var vaultStepDone = true
        if fm.fileExists(atPath: directory.path) {
            // Everything but the watch file first, so an erase that stops half way is checked (and retried) again.
            let names = (try? fm.contentsOfDirectory(atPath: directory.path)) ?? []
            for name in names where name != watch.lastPathComponent {
                do { try fm.removeItem(at: directory.appendingPathComponent(name)) } catch { failed.append("store files") }
            }
            if failed.isEmpty {
                do { try fm.removeItem(at: directory) } catch { failed.append("store files") }
            }
            vaultStepDone = failed.isEmpty
        }
        let vaultPath = directory.standardizedFileURL.path
        for dir in extraDirectories() where fm.fileExists(atPath: dir.path) {
            let path = dir.standardizedFileURL.path
            if path == vaultPath { continue }
            // A folder that holds the vault directory (`<Application Support>/LocalGateKeys/Vault` without an app
            // group) goes only once the vault step succeeded: it would take the watch file with it, and a failed
            // erase must stay checked and retried (desktop `erase_profile` erases the watch file last).
            if vaultPath.hasPrefix(path.hasSuffix("/") ? path : path + "/"), !vaultStepDone { continue }
            try? fm.removeItem(at: dir)   // sealed under keys deleted here: best effort, never a failure
        }
        do { try biometric() } catch { failed.append("touch-id") }
        for slot in VaultSlot.allCases {
            for keychain in keychains {
                do { try keychain.delete(slot) }
                catch KeychainVaultError.status(errSecMissingEntitlement) {}   // group unusable: nothing stored there
                catch { if !failed.contains(slot.rawValue) { failed.append(slot.rawValue) } }
            }
        }
        return Array(Set(failed)).sorted()
    }
}

/// The removal check (desktop `app/device_removal.py` `RemovalGuard`): at launch, every 5 minutes (locked or
/// unlocked) and after a sync run that verified a notice, with "Erase this device if it is removed from sync" on.
/// Locked, it reads the watch file next to the vault, the folder bookmark and the install id (app-only Keychain
/// group, no `.userPresence` on the Mac) and verifies the notice in the folder (`RemovalNotice.check`). Only a
/// verified notice erases; the "maybe removed" sync issues never do.
@MainActor
final class MacRemovalGuard {
    static let interval: TimeInterval = 300

    let lock: MacLockModel
    let settings: AppSettings
    /// The sync slots' vault (nil: sync unavailable in this build, so nothing to check).
    let keychain: (any KeychainVault)?
    let folders: any FolderOpening
    let eraser: MacVaultEraser
    /// The unlock session's sync coordinator, taken before locking so the erase waits for its run in flight.
    var currentCoordinator: @MainActor () -> SyncCoordinator? = { nil }
    private var timer: Timer?
    private var busy = false

    init(lock: MacLockModel, settings: AppSettings, keychain: (any KeychainVault)?, folders: any FolderOpening = SecurityScopedFolderOpener(),
         eraser: MacVaultEraser) {
        self.lock = lock; self.settings = settings; self.keychain = keychain; self.folders = folders; self.eraser = eraser
    }

    isolated deinit { timer?.invalidate() }

    /// Checks now and every `interval`.
    func start() {
        Task { await check() }
        let t = Timer(timeInterval: Self.interval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { guard let self else { return }; Task { await self.check() } }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    /// Erases when a notice for this Mac verifies and the setting is on; else nothing.
    func check() async {
        guard settings.eraseOnSyncRemoval, !busy, lock.state != .noVault, let keychain else { return }
        busy = true
        let watchURL = SyncDependencies.watchFileURL(in: lock.vaultDirectory), folders = folders
        // The folder read blocks (NSFileCoordinator): a GCD thread, never a cooperative one.
        let verified: Bool = await withCheckedContinuation { c in
            DispatchQueue.global(qos: .utility).async {
                c.resume(returning: MacRemovalGuard.verified(watchURL: watchURL, keychain: keychain, folders: folders))
            }
        }
        busy = false
        if verified { await erase() }
    }

    nonisolated static func verified(watchURL: URL, keychain: any KeychainVault, folders: any FolderOpening) -> Bool {
        guard let raw = FileRemovalWatchStore(url: watchURL, folder: "").load(), let watch = RemovalWatch.parse(raw),
              let bookmark = (try? keychain.read(.folderBookmark)) ?? nil,
              let idBytes = (try? keychain.read(.installID)) ?? nil,
              let installID = String(bytes: idBytes, encoding: .utf8), !installID.isEmpty,
              let opened = try? folders.open(bookmark: bookmark) else { return false }
        return RemovalNotice.check(watch, access: opened.folder, installID: installID) != nil
    }

    /// A sync run verified a notice (`SyncCoordinator.onRemovalNotice`): erase now, with the setting on.
    func removedBySync() { Task { await erase() } }

    func erase() async {   // internal: the tests call it directly
        guard settings.eraseOnSyncRemoval, !busy, lock.state != .noVault else { return }
        busy = true
        defer { busy = false }
        let coordinator = currentCoordinator()
        lock.beginErase()   // locks, and refuses password and Touch ID unlocks until `endErase`
        await coordinator?.shutdownAndWait()   // nothing commits or writes the watch file after this
        QuickAccessBridge.shared.pending = nil   // a copy the menu bar asked for goes too
        let eraser = eraser
        // Scheduled backups (backup password + master password) move out first; everything else is erased.
        let (failed, kept): ([String], URL?) = await withCheckedContinuation { c in
            DispatchQueue.global(qos: .userInitiated).async {
                let kept = eraser.keepScheduledBackups()
                c.resume(returning: (eraser.erase(), kept))
            }
        }
        // Remembered even when the erase must be retried: the retry finds nothing left to move.
        if let kept {
            settings.syncRemovalKeptBackups = [settings.syncRemovalKeptBackups, kept.path].compactMap { $0 }.joined(separator: "\n")
        }
        // A step that failed is retried by the next check (the watch file is deleted last, and only on success).
        let watchGone = !FileManager.default.fileExists(atPath: SyncDependencies.watchFileURL(in: lock.vaultDirectory).path)
        lock.endErase(erased: failed.isEmpty || watchGone)
        // The one-time notice only once the vault is really gone (desktop: written after `erase_tree` succeeded).
        if lock.state == .noVault { settings.syncRemovalErasedAt = Int64(Date().timeIntervalSince1970) }
    }
}
