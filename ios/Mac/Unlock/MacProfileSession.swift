import Foundation
import Observation
import AppSharedMac

/// The open profile and its lock model (docs/design/mac-profiles-2026-11-03.md). Choosing another profile, only
/// while locked, rebuilds the lock model and everything `makeLockModel` wires for it; the old ones are released.
@MainActor @Observable
final class MacProfileSession {
    nonisolated static let removeTitle = String(localized: "Remove this profile?")
    nonisolated static let removeText = String(localized: "Its vault, Touch ID and sync settings are deleted from this Mac. Scheduled backups are kept in LocalGateKeys Kept backups. Enter the profile's master password to confirm.")
    nonisolated static let nameError = String(localized: "Enter a name of up to 40 characters.")
    nonisolated static let lastProfileError = String(localized: "The last profile can't be removed.")
    nonisolated static let saveError = String(localized: "The profile list couldn't be saved.")

    private(set) var lock: MacLockModel
    private(set) var profiles: [ProfileRecord]
    private(set) var active: ProfileRecord
    /// The chooser sheet (lock and create screens).
    var choosing = false
    var message: String?
    @ObservationIgnored private let registry: ProfileRegistry?
    @ObservationIgnored private let makeLock: @MainActor () -> MacLockModel
    /// What removing a profile erases (its directory, Keychain items under its prefix, Touch ID item, local folders).
    @ObservationIgnored private let makeEraser: @MainActor (URL) -> MacVaultEraser
    /// Where per-vault settings live (removed with the profile).
    @ObservationIgnored private let defaults: UserDefaults

    init(registry: ProfileRegistry? = ProfileRegistry.shared(),
         makeLock: @escaping @MainActor () -> MacLockModel = { MacAppEnvironment.makeLockModel() },
         makeEraser: @escaping @MainActor (URL) -> MacVaultEraser = { MacVaultEraser.live(directory: $0) },
         defaults: UserDefaults = AppSettings.shared.defaults) {
        self.registry = registry; self.makeLock = makeLock; self.makeEraser = makeEraser; self.defaults = defaults
        let active = registry?.active() ?? ProfileRecord(id: ProfileScope.defaultID, name: String(localized: "Personal"),
                                                          color: ProfileRegistry.colors[0], createdAt: 0, lastUsedAt: 0)
        ProfileScope.select(active.id)
        self.active = active
        self.profiles = registry?.profiles() ?? [active]
        self.lock = makeLock()
    }

    /// Profiles need the app group container (signed builds).
    var canUseProfiles: Bool { registry != nil }
    var hasSeveral: Bool { profiles.count > 1 }

    private func reload() {
        guard let registry else { return }
        profiles = registry.profiles()
        active = registry.active()
    }

    /// Opens `id` (locked, or on its create screen). Refused while the vault is open.
    func open(_ id: String) {
        guard let registry, lock.state != .unlocked, !lock.isBusy else { return }
        guard id != active.id else { choosing = false; return }
        do { try registry.setActive(id) } catch { message = Self.saveError; return }
        lock.lock()
        forgetForExtensions()
        ProfileScope.select(id)
        reload()
        lock = makeLock()
        choosing = false
        message = nil
    }

    /// AutoFill's QuickType list belongs to the profile being left: it goes until the next profile's unlock
    /// publishes its own (the AutoFill extension opens the active profile, which may not hold those logins).
    private func forgetForExtensions() {
        let identities = lock.identities
        Task { await identities?.removeAll() }
    }

    /// A fresh lock model for the open profile (after its files changed underneath, e.g. a failed restore).
    func reopen() {
        guard lock.state != .unlocked else { return }
        lock = makeLock()
    }

    /// The open (locked) profile back to no vault, keeping it in the list (a failed restore on the create screen).
    func eraseOpenProfile() {
        guard lock.state != .unlocked else { return }
        _ = makeEraser(lock.vaultDirectory).erase()
        lock = makeLock()
    }

    /// A new empty profile, opened at once on its create screen.
    @discardableResult
    func create(name: String) -> Bool {
        guard let registry else { return false }
        do {
            let record = try registry.create(name: name)
            reload()
            open(record.id)
            return true
        } catch ProfileRegistryError.invalidName {
            message = Self.nameError
        } catch {
            message = Self.saveError
        }
        return false
    }

    func rename(_ id: String, to name: String) -> Bool {
        guard let registry else { return false }
        do { try registry.rename(id, to: name); reload(); return true } catch ProfileRegistryError.invalidName {
            message = Self.nameError
        } catch { message = Self.saveError }
        return false
    }

    /// Removes the open (locked) profile after its master password is checked, or at once when it has no vault yet.
    /// Its scheduled backups go to `LocalGateKeys Kept backups` first, as when sync removes a Mac.
    func removeActive(password: String) async -> Bool {
        guard let registry, lock.state != .unlocked else { return false }
        guard hasSeveral else { message = Self.lastProfileError; return false }
        if lock.state == .locked {
            do { try await lock.checkPasswordWhileLocked(password) } catch {
                message = lock.message ?? String(localized: "Wrong master password.")
                return false
            }
        }
        let id = active.id
        let eraser = makeEraser(lock.vaultDirectory)
        _ = eraser.keepScheduledBackups()
        _ = eraser.erase()
        for key in ProfileScope.storedKeys(for: id) { defaults.removeObject(forKey: key) }
        do { try registry.remove(id) } catch { message = Self.saveError; return false }
        forgetForExtensions()
        reload()
        ProfileScope.select(active.id)
        lock = makeLock()
        choosing = false
        message = nil
        return true
    }
}
