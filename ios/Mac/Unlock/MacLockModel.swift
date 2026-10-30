import Foundation
import Observation
import LocalAuthentication
import LGKCore
import AppSharedMac

/// Lock state of the Mac app: creates and opens the vault, and locks it on idle timeout, screen lock, sleep,
/// ⌘L or the maximum session length. Locking drops the store and runs every `onLock` hook.
@MainActor @Observable
final class MacLockModel {
    enum State: Equatable { case noVault, locked, unlocked }

    static let touchIDReason = String(localized: "unlock LocalGateKeys")

    private(set) var state: State
    private(set) var store: (any ItemStore)?
    /// Mac-local data (Recently deleted, activity, reminders, collections), open while unlocked.
    private(set) var localStore: MacLocalStore?
    private(set) var localData: LocalData?
    /// What a restored Windows full backup carries that the Mac keeps for the next backup; open while unlocked.
    private(set) var desktopProfile: DesktopProfileStore?
    /// Shown as a banner in the main window when the Mac-local data couldn't be read and was reset.
    var localDataNotice: String?
    /// The error line under the password field, or nil.
    var message: String?
    /// True while a password attempt (Argon2) runs; the screens disable their fields and buttons.
    private(set) var isBusy = false
    /// Seconds left before the idle lock, while unlocked with an idle limit.
    private(set) var autoLockRemaining: TimeInterval?
    /// Run on every lock (Task 6 clears the app's own pasteboard copy here).
    @ObservationIgnored var onLock: [() -> Void] = []
    /// Run after every unlock, once the store is open (the sync schedule starts here).
    @ObservationIgnored var onUnlock: [() -> Void] = []
    /// Run after every commit through `store`; `fromSync` is true for commits made by sync itself
    /// (`SyncSourceStore`), which never count as local edits.
    @ObservationIgnored var onCommit: [(_ fromSync: Bool) -> Void] = []
    /// Run once the recovery phrase was replaced (`false`) or removed (`true`), after the window reopened.
    @ObservationIgnored var onRecoveryPhraseChange: [(_ removed: Bool) -> Void] = []
    /// The scheduled-backup secret, sealed under the local key; open while unlocked.
    private(set) var scheduleSecrets: ScheduleSecretStore?
    /// Run before a new vault is created (an erased or replaced vault leaves nothing behind, e.g. reminder notifications).
    @ObservationIgnored var onFreshVault: [() -> Void] = []
    /// Publishes the AutoFill identities at unlock and after every successful commit (nil: none, e.g. tests).
    @ObservationIgnored var identities: MacIdentityPublisher?
    /// Republishes the Safari fingerprint index after every commit (so the Safari extension classifies against
    /// the vault as it is); nil: none (tests).
    @ObservationIgnored var safariIndex: (any SafariIndexPublishing)?
    /// "Copy password?" once per unlock; reset on lock.
    /// The one strength cache for vault health; emptied on lock.
    let strengthCache = StrengthCache()
    /// Content-free activity history (session, item and copy events) in the Mac-local data.
    @ObservationIgnored private(set) lazy var activity = ActivityRecorder(host: self, clock: clock)

    @ObservationIgnored private let vault: MacVault
    @ObservationIgnored private let settings: AppSettings
    @ObservationIgnored private let events: any SystemEvents
    @ObservationIgnored private let clock: () -> Date
    @ObservationIgnored private var lastActivity: Date
    @ObservationIgnored private var unlockedAt: Date?
    @ObservationIgnored private var listeners: [Task<Void, Never>] = []
    @ObservationIgnored private var ticker: Timer?
    /// Bumped by every `lock()`; an attempt that finishes under a newer generation is discarded.
    @ObservationIgnored private var lockGeneration = 0
    /// Touch ID is offered automatically once, at launch; after a lock only the button offers it.
    @ObservationIgnored private var launchTouchIDPending = true

    init(vault: MacVault, settings: AppSettings, events: any SystemEvents, clock: @escaping () -> Date = Date.init,
         startTimer: Bool = true) {
        self.vault = vault; self.settings = settings; self.events = events; self.clock = clock
        self.lastActivity = clock()
        self.state = vault.exists ? .locked : .noVault
        listeners.append(Task { [weak self, stream = events.screenLocked] in
            for await _ in stream { guard let self else { return }; if self.settings.lockOnScreenLock { self.lock() } }
        })
        listeners.append(Task { [weak self, stream = events.willSleep] in
            for await _ in stream { guard let self else { return }; if self.settings.lockOnSleep { self.lock() } }
        })
        if startTimer {
            let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated { self?.tick() }
            }
            RunLoop.main.add(timer, forMode: .common)   // keeps ticking during menus and live resize
            ticker = timer
        }
    }

    isolated deinit { listeners.forEach { $0.cancel() }; ticker?.invalidate() }

    var touchIDEnabled: Bool { settings.touchIDUnlock }

    /// True once, at launch, when Touch ID should be asked for without a click.
    func takeLaunchTouchIDPrompt() -> Bool {
        defer { launchTouchIDPending = false }
        return launchTouchIDPending && touchIDEnabled
    }

    // MARK: - Create and unlock

    func create(password: String, confirm: String, touchID: Bool) async {
        guard !isBusy else { return }
        guard password == confirm else { message = String(localized: "The passwords don't match."); return }
        for hook in onFreshVault { hook() }
        // A new vault has no backups yet: no date from an earlier vault carries over.
        BackupHistory(defaults: settings.defaults).reset()
        await attempt {
            let store = try await vault.create(password: password, enableTouchID: touchID)
            settings.touchIDUnlock = touchID && vault.touchIDStored
            return store
        }
    }

    func unlock(password: String) async {
        guard !isBusy else { return }
        await attempt { try await vault.unlock(password: password) }
    }

    func unlockWithTouchID() async {
        guard !isBusy else { return }
        await attempt { try await vault.unlockWithTouchID(reason: Self.touchIDReason) }
    }

    // MARK: - Recovery phrase

    /// Shown once after a recovery (Windows `RECOVERY_RESET_TEXT`, for the Mac).
    static let recoveredNotice = String(localized: "Your new master password is set. The same recovery phrase still opens the vault. Touch ID was turned off; turn it on again in Settings if you use it. Old backups keep their old contents under the old master password, so protect or replace them.")
    /// The notice after a recovery, until the user dismisses it.
    var recoveryNotice: String?
    /// After a phrase was replaced or removed (Windows `recovery_phrase_change_warnings`).
    static let oldPhraseNote = String(localized: "The previous recovery phrase no longer opens this vault. Backup files you exported or copied elsewhere earlier still open with the old phrase or the master password of that time: delete them if the old phrase may be known to someone else.")
    static let phraseRemovedText = String(localized: "The recovery phrase was removed.")
    /// Set when a key rotation relocked and reopened the window; the window goes back to where it was (taken once).
    private var reopenedAfterRotation = false
    @ObservationIgnored private var beforeRotationLock: (@MainActor () -> Void)?
    func setBeforeRotationLock(_ hook: (@MainActor () -> Void)?) { beforeRotationLock = hook }

    func takeRotationReturn() -> Bool {
        defer { reopenedAfterRotation = false }
        return reopenedAfterRotation
    }

    var hasRecoveryPhrase: Bool { vault.hasRecoveryPhrase }

    /// "Forgot your master password?": opens the vault with the recovery phrase and sets a new master password at
    /// once. Touch ID is turned off until the user turns it on again. True when the vault is now open.
    func recover(phrase: String, newPassword: String, confirm: String) async -> Bool {
        guard !isBusy else { return false }
        guard newPassword == confirm else { message = String(localized: "The new passwords did not match."); return false }
        await attempt {
            let store = try await vault.recover(phrase: phrase, newPassword: newPassword)
            settings.touchIDUnlock = false
            return store
        }
        guard state == .unlocked else { return false }
        recoveryNotice = Self.recoveredNotice
        noteSetAsideCopies()
        return true
    }

    private func attempt(_ body: () async throws -> LocalStore) async {
        isBusy = true
        message = nil
        launchTouchIDPending = false
        defer { isBusy = false }
        let generation = lockGeneration
        do {
            let opened = try await body()
            guard generation == lockGeneration else {
                // A lock arrived while the attempt ran: drop the store and its key, and stay locked.
                vault.discardOpenedLocalKey()
                if state == .noVault, vaultExists { state = .locked }
                return
            }
            opened.safariIndex = safariIndex
            // Every commit through the app goes through this wrapper, so AutoFill never shows stale logins.
            store = PublishingItemStore(base: opened) { [weak self] fromSync in
                if Thread.isMainThread { MainActor.assumeIsolated { self?.committed(fromSync: fromSync) } }
                else { Task { @MainActor in self?.committed(fromSync: fromSync) } }
            }
            openLocalData()
            state = .unlocked
            activity.record(.sessionUnlock)
            unlockedAt = clock()
            lastActivity = clock()
            updateRemaining()
            republishIdentities()
            for hook in onUnlock { hook() }
        } catch {
            vault.discardOpenedLocalKey()
            message = Self.describe(error, now: clock())
        }
    }

    static func describe(_ error: Error, now: Date) -> String? {
        func wait(_ until: Date) -> String {
            String(localized: "Too many attempts. Try again in \(max(1, Int((until.timeIntervalSince(now)).rounded(.up)))) s.")
        }
        switch error {
        case MacVaultError.wrongPassword(let retryAfter):
            return retryAfter.map { String(localized: "That password isn't right.") + " " + wait($0) } ?? String(localized: "That password isn't right.")
        case MacVaultError.throttled(let until): return wait(until)
        case MacVaultError.wrongRecoveryPhrase(let retryAfter):
            let text = String(localized: "This recovery phrase does not belong to this vault, or it was regenerated.")
            return retryAfter.map { text + " " + wait($0) } ?? text
        case let e as RecoveryPhraseError: return e.message.hasSuffix(".") ? e.message : e.message + "."
        case MacVaultError.passwordTooShort: return String(localized: "Use at least \(MacVault.minPasswordLength) characters.")
        case MacVaultError.passwordTooShortFor(let minimum): return String(localized: "Use at least \(minimum) characters.")
        case MacVaultError.biometricUnavailable: return String(localized: "Touch ID isn't available. Use your master password.")
        case MacVaultError.busy: return nil
        case MacVaultError.backupRunning: return String(localized: "A backup is running. Try again in a moment.")
        case MacVaultError.backupOrRestoreRunning: return String(localized: "A backup or restore is running. Try again in a moment.")
        case MacVaultError.alreadyExists: return String(localized: "A vault already exists on this Mac.")
        case MacVaultError.noVault: return String(localized: "No vault was found on this Mac.")
        case BiometricKeyError.cancelled: return nil
        case MasterKeyError.empty: return String(localized: "Enter a password.")
        case MasterKeyError.tooLong: return String(localized: "That password is too long.")
        default: return String(localized: "Something went wrong: \(error.localizedDescription)")
        }
    }

    /// Opens the Mac-local data with the key the vault just handed over. Never fails: an unreadable file is
    /// reset (with a notice), and an unwritable one only means the data isn't kept this session.
    private func openLocalData() {
        guard var key = vault.takeOpenedLocalKey() else { return }
        defer { for i in key.indices { key[i] = 0 } }
        let local = MacLocalStore(directory: vault.directory, localKey: key)
        // A full backup restore a crash interrupted is finished or put back (safety copies stay).
        MacFullBackup.finishInterruptedRestore(in: vault.directory)
        desktopProfile = DesktopProfileStore(directory: vault.directory, localKey: key)
        scheduleSecrets = ScheduleSecretStore(directory: vault.directory, localKey: key)
        var (data, notice) = local.load()
        localStore = local
        // Auto-purge (Windows purges expired entries on the next vault write): saved now, best effort.
        let before = data.trash.count
        data.purgeExpiredTrash(now: Int64(clock().timeIntervalSince1970))
        if data.trash.count != before { try? local.save(data) }
        localData = data
        localDataNotice = notice
    }

    private func committed(fromSync: Bool) {
        republishIdentities()
        guard state == .unlocked else { return }
        for hook in onCommit { hook(fromSync) }
    }

    /// Queues an AutoFill identity update from the store (unlock, a commit, an AutoFill setting). Locked: nothing.
    func republishIdentities() {
        guard state == .unlocked, let identities, let snap = try? store?.load() else { return }
        identities.enqueue(snapshot: snap)
    }

    /// An AutoFill setting changed: republish while unlocked; while locked, turning suggestions off still
    /// removes the published identities right away (the store can't be read, so nothing is republished).
    func autoFillSettingsChanged() {
        if state == .unlocked { return republishIdentities() }
        guard !settings.showInQuickType, let identities else { return }
        identities.enqueueRemoveAll()
    }

    // MARK: - Locking

    private var vaultExists: Bool { vault.exists }

    func lock() {
        lockGeneration += 1
        vault.discardOpenedLocalKey()
        guard state == .unlocked else { return }
        activity.record(.sessionLock)
        store = nil
        localStore = nil
        localData = nil
        desktopProfile = nil
        scheduleSecrets = nil
        localDataNotice = nil
        recoveryNotice = nil
        state = .locked
        unlockedAt = nil
        autoLockRemaining = nil
        message = nil
        strengthCache.removeAll()
        for hook in onLock { hook() }
    }

    /// The vault's folder (scheduled backups default to its `Backups`).
    var vaultDirectory: URL { vault.directory }

    /// Runs `body` while no password attempt or key rotation is in flight (they wait out, refused as busy); throws
    /// `MacVaultError.busy` when one is running.
    func withoutRotation<T>(_ body: @MainActor () async throws -> T) async throws -> T {
        var result: T?
        try await vault.exclusiveRun(scheduled: true) { result = try await body() }
        guard let result else { throw CancellationError() }
        return result
    }

    func noteActivity() {
        lastActivity = clock()
        updateRemaining()
    }

    /// Checks the idle and session limits; the app calls it every second, tests call it directly.
    func tick() {
        guard state == .unlocked else { return }
        if let max = settings.maxSessionSeconds, let since = unlockedAt, clock().timeIntervalSince(since) >= TimeInterval(max) {
            lock(); return
        }
        updateRemaining()
        if let left = autoLockRemaining, left <= 0 { lock() }
    }

    private func updateRemaining() {
        guard state == .unlocked, let limit = settings.idleLock.seconds else { autoLockRemaining = nil; return }
        let idle = min(clock().timeIntervalSince(lastActivity), events.idleSeconds())
        autoLockRemaining = TimeInterval(limit) - idle
    }
}

extension MacLockModel: LocalDataHosting {
    /// Saves the Mac-local data; on failure nothing changes (the caller undoes its store change).
    func commitLocalData(_ data: LocalData) throws {
        guard state == .unlocked, let localStore else { throw MacLocalStore.Failure.io("locked") }
        try localStore.save(data)
        localData = try data.validated()
    }
}

// MARK: - Settings › Unlocking

/// What Settings › Unlocking needs from the vault: change the master password, turn Touch ID on or off.
@MainActor
protocol MasterPasswordService: AnyObject {
    var hasVault: Bool { get }
    /// Locking and Unlocking settings change only while the vault is open.
    var isUnlocked: Bool { get }
    var touchIDAvailable: Bool { get }
    func changePassword(old: String, new: String) async throws
    /// Checks `password`, then stores or removes the Touch ID item and records the choice.
    func setTouchID(_ on: Bool, password: String) async throws
    /// Checks the master password (throttled) without unlocking anything new.
    func verifyPassword(_ password: String) async throws
    /// Routine re-authentication (non-strict logins) may use Touch ID: it is turned on and available.
    var routineTouchIDEnabled: Bool { get }
    /// Asks for Touch ID (biometrics only) without unlocking anything new; refuses across a lock.
    func verifyWithTouchID(reason: String) async throws
    /// Changes at every lock, so a routine grace never outlives its unlock session.
    var sessionGeneration: Int { get }
    /// True when a recovery phrase is enrolled.
    var hasRecoveryPhrase: Bool { get }
    /// Checks the master password and makes a new phrase (not saved until `confirmRecoveryPhrase`).
    func prepareRecoveryPhrase(password: String) async throws -> MacVault.PreparedRecovery
    func confirmRecoveryPhrase(_ prepared: MacVault.PreparedRecovery) async throws
    func removeRecoveryPhrase(password: String) async throws
    /// Checks the master password; the recovery key for a `vault.json` this Mac seals, or nil without a phrase.
    func recoveryVaultKey(password: String) async throws -> RecoveryWrapper.VaultKey?
    /// True once after a key rotation relocked and reopened the window (it returns to the page it was on).
    func takeRotationReturn() -> Bool
    /// Runs just before a key rotation relocks the window (the window remembers where it was).
    func setBeforeRotationLock(_ hook: (@MainActor () -> Void)?)
}

extension MasterPasswordService {
    var hasRecoveryPhrase: Bool { false }
    func prepareRecoveryPhrase(password: String) async throws -> MacVault.PreparedRecovery { throw MacVaultError.noVault }
    func confirmRecoveryPhrase(_ prepared: MacVault.PreparedRecovery) async throws { throw MacVaultError.noVault }
    func removeRecoveryPhrase(password: String) async throws { throw MacVaultError.noVault }
    func recoveryVaultKey(password: String) async throws -> RecoveryWrapper.VaultKey? {
        try await verifyPassword(password)
        return nil
    }
    var routineTouchIDEnabled: Bool { false }
    func verifyWithTouchID(reason: String) async throws { throw MacVaultError.biometricUnavailable }
    var sessionGeneration: Int { 0 }
    func takeRotationReturn() -> Bool { false }
    func setBeforeRotationLock(_ hook: (@MainActor () -> Void)?) {}
}

extension MacLockModel: MasterPasswordService {
    var hasVault: Bool { vault.exists }
    var isUnlocked: Bool { state == .unlocked }
    var touchIDAvailable: Bool { vault.touchIDAvailable }

    func changePassword(old: String, new: String) async throws {
        guard state == .unlocked else { throw CancellationError() }
        try await reopenAfterRotation { try await vault.changePassword(old: old, new: new) }
    }

    /// A key rotation (password change, phrase replaced or removed) left every open store on the old key: lock, then
    /// open again with the new key, as at an unlock (hooks, Mac-local data and the window all restart). Touch ID was
    /// removed by the rotation and stays off until the user turns it on again.
    private func reopenAfterRotation(_ rotate: () async throws -> LocalStore) async throws {
        let store = try await rotate()
        settings.touchIDUnlock = false
        let key = vault.takeOpenedLocalKey()
        beforeRotationLock?()
        lock()
        if let key { vault.handBack(key) }
        await attempt { store }
        if state == .unlocked { reopenedAfterRotation = true }
        noteSetAsideCopies()
    }

    /// Safety copies a rotation could not read were set aside (`<name>.unreadable` in Backups); the user is told.
    private func noteSetAsideCopies() {
        let names = vault.lastRotationSetAside
        guard !names.isEmpty, state == .unlocked else { return }
        let list = names.joined(separator: ", ")
        localDataNotice = String(localized: "A safety copy couldn't be read and was set aside in Backups: \(list).")
    }

    /// Refuses while locked, and refuses if the vault locked while the password was being checked, so a
    /// gated release never runs after a lock.
    func verifyPassword(_ password: String) async throws {
        guard state == .unlocked else { throw CancellationError() }
        let generation = lockGeneration
        try await vault.verifyPassword(password)
        guard state == .unlocked, generation == lockGeneration else { throw CancellationError() }
    }

    var routineTouchIDEnabled: Bool { touchIDEnabled && vault.touchIDAvailable }

    func prepareRecoveryPhrase(password: String) async throws -> MacVault.PreparedRecovery {
        guard state == .unlocked else { throw CancellationError() }
        let generation = lockGeneration
        let prepared = try await vault.prepareRecovery(password: password)
        guard state == .unlocked, generation == lockGeneration else { throw CancellationError() }
        return prepared
    }

    func confirmRecoveryPhrase(_ prepared: MacVault.PreparedRecovery) async throws {
        guard state == .unlocked else { throw CancellationError() }
        let replacing = vault.hasRecoveryPhrase
        try await reopenAfterRotation { try await vault.confirmRecovery(prepared) }
        for hook in onRecoveryPhraseChange { hook(false) }
        // The sheet that asked is gone with the old window: the reopened one says what happened.
        if state == .unlocked {
            recoveryNotice = RecoveryPhraseSheet.confirmed + (replacing ? " " + Self.oldPhraseNote : "")
        }
    }

    func removeRecoveryPhrase(password: String) async throws {
        guard state == .unlocked else { throw CancellationError() }
        try await reopenAfterRotation { try await vault.removeRecovery(password: password) }
        for hook in onRecoveryPhraseChange { hook(true) }
        if state == .unlocked { recoveryNotice = Self.phraseRemovedText + " " + Self.oldPhraseNote }
    }

    func recoveryVaultKey(password: String) async throws -> RecoveryWrapper.VaultKey? {
        guard state == .unlocked else { throw CancellationError() }
        let generation = lockGeneration
        var key = try await vault.recoveryVaultKey(password: password)
        guard state == .unlocked, generation == lockGeneration else { key?.wipe(); throw CancellationError() }
        return key
    }
    var sessionGeneration: Int { lockGeneration }

    func verifyWithTouchID(reason: String) async throws {
        guard state == .unlocked else { throw CancellationError() }
        let generation = lockGeneration
        let context = LAContext()
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch let error as LAError where error.code == .userCancel || error.code == .appCancel || error.code == .systemCancel {
            throw CancellationError()
        } catch {
            throw MacVaultError.biometricUnavailable
        }
        guard state == .unlocked, generation == lockGeneration else { throw CancellationError() }
    }

    func setTouchID(_ on: Bool, password: String) async throws {
        try await vault.setTouchID(on, password: password)
        settings.touchIDUnlock = on
    }
}
