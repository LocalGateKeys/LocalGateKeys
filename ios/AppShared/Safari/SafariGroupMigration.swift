import Foundation

/// Audit 2026-11-10: the Safari web extensions hold their own app group (`AppGroup.safariIdentifier`) instead of the
/// shared one with the vault, its keys and the duress files. At every launch the app (iPhone and Mac) brings that
/// group up to date before anything reads it: the `SafariSave` folders an earlier build kept in the shared group are
/// moved over (once: nothing is left behind to move again), and the flags the extension can no longer read from the
/// shared group are mirrored (duress state, erase pending, the Mac's active profile). Best effort and idempotent.
public enum SafariGroupMigration {
    /// A no-op without both containers (unsigned builds, the extensions).
    public static func runAtLaunch(settings: AppSettings = .shared) {
        guard let safariRoot = AppGroup.safariContainerURL, let sharedRoot = AppGroup.containerURL else { return }
        moveLegacyFolders(sharedRoot: sharedRoot, safariRoot: safariRoot)
        #if os(macOS)
        if let registry = ProfileRegistry.shared() {
            let id = registry.active().id
            SafariSaveFiles.recordActiveProfile(id, safariRoot: safariRoot)
            // The Mac's duress files sit in each profile's vault folder (`DuressFiles.under(vault)`): the active one's
            // state is what the Safari extension sees (the app syncs it again at every profile switch).
            PhoneDuress(files: .under(registry.vaultDirectory(for: id)),
                        mirror: SafariSaveFiles.duressMirror(safariRoot: safariRoot)).syncMirror()
        }
        #else
        PhoneDuress.shared()?.syncMirror()
        #endif
        SafariSaveFiles.setErasePending(settings.erasePending)
    }

    /// Every `SafariSave` folder of the shared group (the default one and, on the Mac, each other profile's) to the
    /// same place in the Safari group.
    static func moveLegacyFolders(sharedRoot: URL, safariRoot: URL) {
        var profiles: [String?] = [nil]
        #if os(macOS)
        let folder = sharedRoot.appendingPathComponent("Profiles", isDirectory: true)
        for name in ((try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? []).sorted()
        where name != ProfileScope.defaultID && ProfileRegistry.isValidID(name) {
            profiles.append(name)
        }
        #endif
        for id in profiles {
            moveFolder(from: SafariSaveFiles.folder(in: sharedRoot, profile: id),
                       to: SafariSaveFiles.folder(in: safariRoot, profile: id))
        }
    }

    /// Moves one `SafariSave` folder: whole when the new place has none; else each waiting inbox blob not already there
    /// (the index, site list, plan marker and probe counts of the old folder are dropped: the app publishes them again
    /// at the next unlock and commit). The old folder is removed once every blob has moved; a blob that could not move
    /// keeps it for the next launch. Blobs stay valid: they are sealed under the inbox key in the Keychain and bound to
    /// their file name, neither of which changes.
    static func moveFolder(from old: URL, to new: URL) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: old.path) else { return }
        try? fm.createDirectory(at: new.deletingLastPathComponent(), withIntermediateDirectories: true)
        if !fm.fileExists(atPath: new.path), (try? fm.moveItem(at: old, to: new)) != nil {
            LocalStore.excludeFromBackup(new)
            return
        }
        let oldInbox = old.appendingPathComponent(SafariInbox.directoryName, isDirectory: true)
        let newInbox = new.appendingPathComponent(SafariInbox.directoryName, isDirectory: true)
        var allMoved = true
        let blobs = ((try? fm.contentsOfDirectory(atPath: oldInbox.path)) ?? [])
            .filter { $0.hasSuffix("." + SafariInbox.fileExtension) }
        if !blobs.isEmpty {
            do { try fm.createDirectory(at: newInbox, withIntermediateDirectories: true) } catch { return }
            LocalStore.excludeFromBackup(new)
        }
        for name in blobs {
            let target = newInbox.appendingPathComponent(name)
            if fm.fileExists(atPath: target.path) { continue }   // already there (an earlier, interrupted run)
            if (try? fm.moveItem(at: oldInbox.appendingPathComponent(name), to: target)) == nil { allMoved = false }
        }
        if allMoved { try? fm.removeItem(at: old) }
    }
}
