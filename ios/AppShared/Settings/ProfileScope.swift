import Foundation

/// Mac profiles (docs/design/mac-profiles-2026-11-03.md): which profile's per-vault settings, Keychain items and
/// files are in use. The default profile (and every iPhone) uses an empty prefix, so its keys, accounts and paths
/// are the ones that existed before profiles.
public enum ProfileScope {
    /// The id the vault from before profiles keeps.
    public static let defaultID = "default"

    /// The active profile's id (set by the Mac app when a profile is chosen, and by the AutoFill extension from the
    /// registry). Read on any thread; written on the main thread before the profile's models are built.
    nonisolated(unsafe) public private(set) static var currentID = defaultID

    public static func select(_ id: String) { currentID = id }

    public static var isDefault: Bool { currentID == defaultID }

    /// `"profile.<id>."` for another profile, empty for the default one.
    public static var defaultsPrefix: String { isDefault ? "" : "profile.\(currentID)." }

    /// `"<id>/"` before a Keychain account for another profile, empty for the default one.
    public static var keychainPrefix: String { keychainPrefix(for: currentID) }

    public static func keychainPrefix(for id: String) -> String { id == defaultID ? "" : "\(id)/" }

    /// `key` for the active profile when it is a per-vault setting; app-wide settings pass through unchanged.
    public static func key(_ key: String) -> String {
        perVaultKeys.contains(key) ? defaultsPrefix + key : key
    }

    /// The defaults keys each profile keeps for itself. Everything else (appearance, auto-lock, clipboard, menu bar,
    /// quick access, breach check, strict offline) is shared by all profiles.
    public static let perVaultKeys: Set<String> = [
        AppSettings.Key.touchIDUnlock, AppSettings.Key.wifiSyncOn, AppSettings.Key.wifiSyncEndpoint,
        AppSettings.Key.erasePending, AppSettings.Key.identityRemovalPending, AppSettings.Key.planFullRevision,
        AppSettings.Key.importCardDismissed, AppSettings.Key.setupDone, AppSettings.Key.setupSeen,
        AppSettings.Key.setupCardHidden, AppSettings.Key.eraseOnSyncRemoval, AppSettings.Key.syncRemovalErasedAt,
        AppSettings.Key.syncRemovalKeptBackups, AppSettings.Key.syncRemovalErasePending, AppSettings.Key.autoSync,
        // Unlock throttle (`AppPasswordThrottle`), backup history and scheduled backups.
        "settings.unlockFailures", "settings.unlockFailureAt", "settings.unlockFailureBoot", "settings.unlockFailureUptime",
        "recoveryCentre.lastBackupAt", "recoveryCentre.lastVerifiedAt",
        "scheduledBackup.frequency", "scheduledBackup.time", "scheduledBackup.weekday", "scheduledBackup.keep",
        "scheduledBackup.seenRecord", "scheduledBackup.confirmKeyID", "scheduledBackup.protectOld",
        "scheduledBackup.protectOldPending", "scheduledBackup.upgradeNoticeDismissedAt",
        "scheduledBackup.upgradeReminderDismissedAt",
    ]

    /// Every per-vault key of profile `id` as stored (to delete a removed profile's settings).
    public static func storedKeys(for id: String) -> [String] {
        let prefix = id == defaultID ? "" : "profile.\(id)."
        return perVaultKeys.map { prefix + $0 }
    }
}
