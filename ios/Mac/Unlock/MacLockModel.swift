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
    /// True while a password attempt (Argon2) runs or the vault is being erased; the screens disable their fields
    /// and buttons, and no unlock, recovery or create starts.
    var isBusy: Bool { attemptRunning || isErasing }
    private var attemptRunning = false
    /// True while `MacRemovalGuard` erases the vault after a removal from sync (iPhone `AppLockModel.isErasing`,
    /// desktop `_erase_profile` under the controller lock): password and Touch ID unlocks are refused until it ends.
    private(set) var isErasing = false
    /// Seconds left before the idle lock, while unlocked with an idle limit.
    private(set) var autoLockRemaining: TimeInterval?
    /// Run on every lock (Task 6 clears the app's own pasteboard copy here).
    @ObservationIgnored var onLock: [() -> Void] = []
    /// Run after every unlock, once the store is open (the sync schedule starts here).
    @ObservationIgnored var onUnlock: [() -> Void] = []
    /// Run after every commit through `store`; `fromSync` is true for commits made by sync itself
    /// (`SyncSourceStore`), which never count as local edits.
    @ObservationIgnored var onCommit: [(_ fromSync: Bool) -> Void] = []
    /// Run after travel mode changed (feature pack §2): windows reload their lists.
    @ObservationIgnored var onTravelChange: [() -> Void] = []
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
    /// Whether this vault has Pro (item history keeps 90 days and 50 versions with Pro, 30 days and 10 without).
    @ObservationIgnored var historyIsPro: @MainActor () -> Bool = { false }
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

    /// "Touch your YubiKey" for every screen; every lock cancels a pending touch.
    @ObservationIgnored let yubiKeyPrompt: YubiKeyPrompt
    /// The key file picked on the lock screen for the next unlock (nil: the remembered one, if any).
    private(set) var pickedKeyFile: URL?
    /// Shown once in the main window after an unlock removed Touch ID ("Always ask for the key file / YubiKey").
    var factorNotice: String?
    /// Duress password (sub-plan 08): true while the open vault is the second one (from its unlock to the next lock).
    /// Every service that could show or send the real vault checks it (`MacAppEnvironment`, sync, backups, agents).
    private(set) var isSecondSession = false
    /// The real vault's duress hours, read at unlock (Settings › Duress password); nil: not set up, or a second session.
    private(set) var duressHours: Int?

    init(vault: MacVault, settings: AppSettings, events: any SystemEvents, clock: @escaping () -> Date = Date.init,
         startTimer: Bool = true, yubiKeyPrompt: YubiKeyPrompt? = nil) {
        self.vault = vault; self.settings = settings; self.events = events; self.clock = clock
        self.yubiKeyPrompt = yubiKeyPrompt ?? YubiKeyPrompt()
        self.lastActivity = clock()
        self.state = vault.exists ? .locked : .noVault
        // A password check that was given no factors (Settings, a strict login, a backup) asks here.
        vault.provideFactors = { [weak self] specs in
            guard let self else { throw CancellationError() }
            return try await self.provideFactors(specs)
        }
        rememberedName = readRememberedName()
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

    var touchIDEnabled: Bool { settings.touchIDUnlock && !touchIDBlockedByFactors }

    /// "Always ask for the key file / YubiKey" is on and a factor is set: Touch ID is deleted and refused.
    var touchIDBlockedByFactors: Bool { settings.factorsAlwaysAsk && !vault.factors.isEmpty }

    /// True once, at launch, when Touch ID should be asked for without a click.
    func takeLaunchTouchIDPrompt() -> Bool {
        defer { launchTouchIDPending = false }
        return launchTouchIDPending && touchIDEnabled && !vault.duressHeld
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
        guard !isBusy, !isErasing else { return }
        await attempt {
            let specs = vault.factors
            let picked = pickedKeyFile
            let store = try await vault.unlock(password: password, factors: try await unlockFactors(for: specs))
            if let spec = specs.first(where: { $0.kind == .keyFile }) { rememberAfterUnlock(picked, check: spec.check) }
            return store
        }
    }

    func unlockWithTouchID() async {
        guard !isBusy, !isErasing else { return }
        if touchIDBlockedByFactors {
            // Enforced here too, not only hidden: the item would open the vault without the factors.
            vault.removeTouchIDItem()
            settings.touchIDUnlock = false
            message = MacFactors.touchIDRemovedOnUnlock
            return
        }
        await attempt { try await vault.unlockWithTouchID(reason: Self.touchIDReason) }
    }

    // MARK: - Key file and YubiKey at unlock

    /// The factors `master-key.json` asks for (none: the lock screen shows only the password).
    var unlockFactorSpecs: [FactorSpec] { vault.factors }

    /// The lock screen's "Choose key file…".
    func chooseKeyFile() {
        guard let url = MacFactors.chooseKeyFile() else { return }
        pickedKeyFile = url
        message = nil
    }

    /// The key file the next unlock uses: the one picked now, else the remembered one (by name), else nil.
    var keyFileName: String? { pickedKeyFile?.lastPathComponent ?? rememberedName }

    /// The remembered key file's name, cached: read from the Keychain at launch and whenever it may have changed,
    /// never on a render.
    private(set) var rememberedName: String?
    private func readRememberedName() -> String? {
        guard settings.rememberKeyFile, let spec = vault.factors.first(where: { $0.kind == .keyFile }) else { return nil }
        return KeyFileBookmark.load(for: spec.check, from: vault.factorKeychain)?.name
    }
    /// After anything that may change the remembered key file (a bookmark saved or forgotten, a factor change).
    private func refreshRememberedName() { rememberedName = readRememberedName() }

    /// "Remember this key file on this Mac" (off: "Don't remember"; the remembered one is forgotten at once).
    var rememberKeyFile: Bool {
        get { settings.rememberKeyFile }
        set {
            settings.rememberKeyFile = newValue
            if !newValue { KeyFileBookmark.forget(in: vault.factorKeychain) }
            refreshRememberedName()
        }
    }

    private func rememberedKeyFile(check: String) -> URL? {
        guard settings.rememberKeyFile else { return nil }
        return KeyFileBookmark.load(for: check, from: vault.factorKeychain)?.resolve(keychain: vault.factorKeychain)
    }

    /// What the unlock screen supplies: the picked or remembered key file (read, bounded) and the YubiKey responder. A
    /// missing key file is left out, so the vault says "This vault also needs its key file" before the YubiKey is asked.
    private func unlockFactors(for specs: [FactorSpec]) async throws -> FactorSecrets {
        var input = FactorSecrets()
        if let spec = specs.first(where: { $0.kind == .keyFile }), let url = pickedKeyFile ?? rememberedKeyFile(check: spec.check) {
            input.keyFile = try await MacFactors.loadKeyFile(url)
        }
        if let spec = specs.first(where: { $0.kind == .yubiKeyHMAC }) {
            input.yubiKey = yubiKeyPrompt.responder(slot: spec.slot ?? MacFactors.defaultSlot)
        }
        return input
    }

    /// After an unlock with a picked key file: remembered unless "Don't remember".
    private func rememberAfterUnlock(_ picked: URL?, check: String) {
        pickedKeyFile = nil
        guard let picked else { return }
        if settings.rememberKeyFile { try? KeyFileBookmark.save(picked, check: check, to: vault.factorKeychain) }
        refreshRememberedName()
    }

    /// The factors for a password check that was given none (Settings, a strict login, a backup, the recovery phrase
    /// sheet): the remembered key file, else one picked now (Cancel: nothing happens), and the YubiKey.
    private func provideFactors(_ specs: [FactorSpec]) async throws -> FactorSecrets {
        var input = FactorSecrets()
        if let spec = specs.first(where: { $0.kind == .keyFile }) {
            guard let url = rememberedKeyFile(check: spec.check) ?? MacFactors.chooseKeyFile() else { throw CancellationError() }
            input.keyFile = try await MacFactors.loadKeyFile(url)
        }
        if let spec = specs.first(where: { $0.kind == .yubiKeyHMAC }) {
            input.yubiKey = yubiKeyPrompt.responder(slot: spec.slot ?? MacFactors.defaultSlot)
        }
        return input
    }

    /// After an unlock: a vault with factors keeps no Touch ID item while "Always ask" is on (Windows
    /// `_enforce_always_ask`); the window says so once.
    private func enforceAlwaysAskAfterUnlock() {
        guard touchIDBlockedByFactors else { return }
        let wasOn = settings.touchIDUnlock
        vault.removeTouchIDItem()
        settings.touchIDUnlock = false
        if wasOn { factorNotice = MacFactors.touchIDRemovedOnUnlock }
    }

    /// The YubiKey slot named in the messages.
    var yubiKeySlot: Int { vault.factors.first(where: { $0.kind == .yubiKeyHMAC })?.slot ?? MacFactors.defaultSlot }

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
        if vault.lastRecoveryDroppedFactors {
            // The phrase replaced the key file / YubiKey too (design §4.2): they are gone until added again.
            KeyFileBookmark.forget(in: vault.factorKeychain)
            refreshRememberedName()
            recoveryNotice = Self.recoveredNotice + " " + MacFactors.factorsRemovedByPhrase
        }
        noteSetAsideCopies()
        return true
    }

    private func attempt(_ body: () async throws -> LocalStore) async {
        attemptRunning = true
        message = nil
        launchTouchIDPending = false
        defer { attemptRunning = false }
        let generation = lockGeneration
        do {
            let opened = try await body()
            guard generation == lockGeneration, !isErasing else {
                // A lock arrived while the attempt ran: drop the store and its key, and stay locked.
                vault.discardOpenedLocalKey()
                vault.forgetHeldFactors()
                vault.closeSecondSession()
                if state == .noVault, vaultExists { state = .locked }
                return
            }
            isSecondSession = vault.openedSecond
            // The second vault publishes no Safari index (the extension sees the session marker and offers nothing).
            opened.safariIndex = isSecondSession ? nil : safariIndex
            // Item history (feature pack §1): each commit's replaced versions go to this vault's Mac-local data.
            HistoryCapture.install(on: opened) { [weak self] rows in Task { @MainActor in self?.recordHistory(rows) } }
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
            if isSecondSession {
                // The real vault's AutoFill suggestions are withdrawn until its next unlock; no setting is changed.
                identities?.enqueueRemoveAll()
            } else {
                republishIdentities()
                enforceAlwaysAskAfterUnlock()
            }
            for hook in onUnlock { hook() }
        } catch {
            vault.discardOpenedLocalKey()
            message = Self.describe(error, now: clock(), slot: yubiKeySlot)
        }
    }

    static func describe(_ error: Error, now: Date, slot: Int = MacFactors.defaultSlot) -> String? {
        // Key file and YubiKey problems: never a wrong password (the throttle did not count them).
        if let line = MacFactors.describe(error, slot: slot) { return line }
        if error is CancellationError { return nil }
        if let e = error as? DuressError { return MacDuressText.describe(e) }
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
        // The second vault keeps its Mac-local data (Recently deleted, activity, reminders, the kept profile, backup
        // copies) in its own folder, under its own key; nothing of the real vault's is opened.
        let dataDir = isSecondSession ? vault.duressFiles.vault : vault.directory
        duressHours = isSecondSession ? nil : vault.duressHours(realKey: key)
        let local = MacLocalStore(directory: dataDir, localKey: key)
        // A full backup restore a crash interrupted is finished or put back (safety copies stay).
        MacFullBackup.finishInterruptedRestore(in: dataDir)
        desktopProfile = DesktopProfileStore(directory: dataDir, localKey: key)
        scheduleSecrets = isSecondSession ? nil : ScheduleSecretStore(directory: dataDir, localKey: key)
        var (data, notice) = local.load()
        localStore = local
        // Auto-purge (Windows purges expired entries on the next vault write): saved now, best effort.
        let before = data.trash.count
        data.purgeExpiredTrash(now: Int64(clock().timeIntervalSince1970))
        // Item history of items deleted for good goes too (scan 2026-11-15 W-M5, A-M3).
        var forgot = false
        if let store, let snap = try? store.load() { forgot = data.forgetHistoryOfPurgedItems(snap) }
        if data.trash.count != before || forgot { try? local.save(data) }
        // Collections (sub-plan 07): an older Mac's local collections move into the item store once. `data` is the
        // cleared copy from then on, also when its save fails, and it is the copy every later local write starts from.
        if let store {
            MacCollectionsModel.unlock(store: store, local: &data) { try local.save($0) }
        }
        localData = data
        localDataNotice = notice
        // Travel mode (feature pack §2): read by the list, AutoFill and exports while this vault is open. A duress
        // session reads its own vault's setting, never the real vault's.
        TravelModeBox.shared.current = data.travel
    }

    private func committed(fromSync: Bool) {
        republishIdentities()
        guard state == .unlocked else { return }
        for hook in onCommit { hook(fromSync) }
    }

    /// Queues an AutoFill identity update from the store (unlock, a commit, an AutoFill setting). Locked: nothing.
    func republishIdentities() {
        guard state == .unlocked, !isSecondSession, let identities, let snap = try? store?.load() else { return }
        identities.enqueue(snapshot: snap)
    }

    /// Rewrites the Safari index (travel mode hides or shows items in it, `MacTravelSafariIndex`).
    func republishSafariIndex() {
        guard state == .unlocked, !isSecondSession, let safariIndex, let snap = try? store?.load() else { return }
        safariIndex.publish(snap)
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
        // A pending YubiKey touch is cancelled, and the session's key file is no longer held.
        yubiKeyPrompt.cancel()
        vault.forgetHeldFactors()
        pickedKeyFile = nil
        guard state == .unlocked else { vault.closeSecondSession(); return }
        factorNotice = nil
        activity.record(.sessionLock)
        // The second vault's session ends (its hold stays); recorded above in its own activity log.
        vault.closeSecondSession()
        isSecondSession = false
        duressHours = nil
        store = nil
        localStore = nil
        localData = nil
        TravelModeBox.shared.current = .off
        // The clean-up's one Undo lasts until the vault locks (feature pack §3.3).
        HygieneActions.clearUndo()
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

    /// An erase after a removal from sync starts (`MacRemovalGuard`): unlocks are refused from now on, and the vault
    /// locks (an attempt in flight is discarded by the lock generation).
    func beginErase() {
        isErasing = true
        lock()
    }

    /// The erase ended. `erased`: locked, then no vault, as at first launch (the fresh-vault hooks remove the AutoFill
    /// identities and the reminder notifications at once). Otherwise the vault stays locked and unlockable again; the
    /// next check erases again while the watch file is there.
    func endErase(erased: Bool) {
        isErasing = false
        if erased { vaultErased() }
    }

    /// Locked, then no vault, when the master key file is gone.
    func vaultErased() {
        lock()
        guard !vault.exists else { return }   // the key file is still there: the next check erases again
        state = .noVault
        for hook in onFreshVault { hook() }
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
        // Settings › Locking › Count activity from (Windows `idle_source`).
        let idle = MacExtraSettings.idleSource(settings.defaults)
            .idleSeconds(system: events.idleSeconds(), app: clock().timeIntervalSince(lastActivity))
        autoLockRemaining = TimeInterval(limit) - idle
    }
}

extension MacLockModel: LocalDataHosting {
    /// Appends item history rows (captured by the store hook) to the Mac-local data, pruned to the plan's limits.
    /// Dropped while locked; a failed save loses only these versions, never the item change.
    func recordHistory(_ rows: [ItemHistory.Row]) {
        guard state == .unlocked, let data = localData else { return }
        let next = HistoryCapture.appending(rows, to: data, now: Int64(clock().timeIntervalSince1970),
                                            limits: .plan(isPro: historyIsPro()))
        try? commitLocalData(next)
    }

    /// Saves the Mac-local data; on failure nothing changes (the caller undoes its store change).
    func commitLocalData(_ data: LocalData) throws {
        guard state == .unlocked, let localStore else { throw MacLocalStore.Failure.io("locked") }
        try localStore.save(data)
        let before = TravelModeBox.shared.current
        localData = try data.validated()
        let travel = localData?.travel ?? .off
        TravelModeBox.shared.current = travel
        // Travel mode changed: AutoFill suggestions and the windows follow at once (§2).
        if travel != before { travelChanged() }
    }

    /// Republishes the AutoFill identities and tells the windows to reload (travel mode turned on, off or changed).
    private func travelChanged() {
        republishIdentities()
        republishSafariIndex()
        for hook in onTravelChange { hook() }
        NotificationCenter.default.post(name: MacAccess.travelModeChanged, object: nil)
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
        if isSecondSession {
            // Only the second vault's password changes; nothing is tried against the real vault.
            try await vault.changeSecondPassword(current: old, new: new)
            return
        }
        try await reopenAfterRotation { try await vault.changePassword(old: old, new: new) }
    }

    /// Inside the second session a change to the real vault's unlocking (Touch ID, recovery phrase, key file, YubiKey)
    /// checks the open vault's password where one is given, then fails with the generic line and changes nothing.
    private func refuseInSecondSession(password: String?) async throws {
        guard isSecondSession else { return }
        if let password { try await vault.verifySecondPassword(password) }
        throw DuressError("generic")
    }

    /// A key rotation (password change, phrase replaced or removed) left every open store on the old key: lock, then
    /// open again with the new key, as at an unlock (hooks, Mac-local data and the window all restart). Touch ID was
    /// removed by the rotation and stays off until the user turns it on again.
    private func reopenAfterRotation(_ rotate: () async throws -> LocalStore) async throws {
        let store = try await rotate()
        settings.touchIDUnlock = false
        let key = vault.takeOpenedLocalKey()
        let heldKeyFile = vault.takeHeldKeyFile()
        // The open Mac-local store still seals under the old key, and the rotation already resealed the file under
        // the new one: nothing may write through it now (the lock below records an activity event), or the reopen
        // finds the file unreadable and resets Recently deleted, reminders and activity.
        localStore = nil
        beforeRotationLock?()
        lock()
        if let key { vault.handBack(key) }
        vault.holdKeyFile(heldKeyFile)
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

    /// Checks the master password without unlocking (removing this profile from the lock screen); the unlock
    /// throttle applies.
    func checkPasswordWhileLocked(_ password: String) async throws {
        guard state != .unlocked else { throw CancellationError() }
        try await vault.verifyPassword(password)
    }

    /// Refuses while locked, and refuses if the vault locked while the password was being checked, so a
    /// gated release never runs after a lock.
    func verifyPassword(_ password: String) async throws {
        guard state == .unlocked else { throw CancellationError() }
        let generation = lockGeneration
        if isSecondSession {
            try await vault.verifySecondPassword(password)
        } else {
            try await vault.verifyPassword(password)
        }
        guard state == .unlocked, generation == lockGeneration else { throw CancellationError() }
    }

    var routineTouchIDEnabled: Bool { touchIDEnabled && vault.touchIDAvailable }

    func prepareRecoveryPhrase(password: String) async throws -> MacVault.PreparedRecovery {
        guard state == .unlocked else { throw CancellationError() }
        try await refuseInSecondSession(password: password)
        let generation = lockGeneration
        let prepared = try await vault.prepareRecovery(password: password)
        guard state == .unlocked, generation == lockGeneration else { throw CancellationError() }
        return prepared
    }

    func confirmRecoveryPhrase(_ prepared: MacVault.PreparedRecovery) async throws {
        guard state == .unlocked else { throw CancellationError() }
        try await refuseInSecondSession(password: nil)
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
        try await refuseInSecondSession(password: password)
        try await reopenAfterRotation { try await vault.removeRecovery(password: password) }
        for hook in onRecoveryPhraseChange { hook(true) }
        if state == .unlocked { recoveryNotice = Self.phraseRemovedText + " " + Self.oldPhraseNote }
    }

    func recoveryVaultKey(password: String) async throws -> RecoveryWrapper.VaultKey? {
        guard state == .unlocked else { throw CancellationError() }
        let generation = lockGeneration
        if isSecondSession {
            // The second vault has no recovery phrase: its backups are sealed under its password alone.
            try await vault.verifySecondPassword(password)
            guard state == .unlocked, generation == lockGeneration else { throw CancellationError() }
            return nil
        }
        var key = try await vault.recoveryVaultKey(password: password)
        guard state == .unlocked, generation == lockGeneration else { key?.wipe(); throw CancellationError() }
        return key
    }
    var sessionGeneration: Int { lockGeneration }

    func verifyWithTouchID(reason: String) async throws {
        guard state == .unlocked else { throw CancellationError() }
        let generation = lockGeneration
        let box = TouchIDContextBox(LAContext())
        do {
            // A cancelled request (an SSH agent deadline) takes its Touch ID dialog down with it (appCancel).
            try await withTaskCancellationHandler {
                try await box.evaluate(reason: reason)
            } onCancel: {
                box.invalidate()
            }
        } catch let error as LAError where error.code == .userCancel || error.code == .appCancel || error.code == .systemCancel {
            throw CancellationError()
        } catch {
            throw MacVaultError.biometricUnavailable
        }
        guard state == .unlocked, generation == lockGeneration, !Task.isCancelled else { throw CancellationError() }
    }

    func setTouchID(_ on: Bool, password: String) async throws {
        if on && touchIDBlockedByFactors { throw MacFactors.alwaysAskOn }
        try await refuseInSecondSession(password: password)
        try await vault.setTouchID(on, password: password)
        settings.touchIDUnlock = on
    }
}

// MARK: - Settings › Unlocking › Key file and YubiKey

extension MacLockModel: FactorService {
    var factorSpecs: [FactorSpec] { vault.factors }
    var factorsAlwaysAsk: Bool { settings.factorsAlwaysAsk }

    /// Runs a factor change while unlocked; refuses if the vault locked meanwhile (the change itself is already
    /// written by then; only what follows is skipped).
    private func whileUnlocked(_ body: () async throws -> Void) async throws {
        guard state == .unlocked else { throw CancellationError() }
        // The second session never changes the real vault's factors (duress password, sub-plan 08).
        guard !isSecondSession else { throw DuressError("generic") }
        let generation = lockGeneration
        try await body()
        guard state == .unlocked, generation == lockGeneration else { throw CancellationError() }
    }

    /// "Always ask" with a factor set: the Touch ID item goes (the add or the switch said so first).
    private func removeTouchIDForAlwaysAsk() -> Bool {
        guard settings.factorsAlwaysAsk, !vault.factors.isEmpty else { return false }
        let wasOn = settings.touchIDUnlock
        vault.removeTouchIDItem()
        settings.touchIDUnlock = false
        return wasOn
    }

    private func added(_ text: String) -> String {
        removeTouchIDForAlwaysAsk() ? text + " " + FactorTexts.touchIDRemoved : text
    }

    func addKeyFile(url: URL, password: String) async throws -> String {
        let data = try await MacFactors.loadKeyFile(url)
        try await whileUnlocked { try await vault.addKeyFile(password: password, keyFile: data) }
        rememberKeyFileAfterChange(url)
        return added(FactorTexts.keyFileAdded(url.lastPathComponent))
    }

    func createKeyFile(at url: URL, password: String) async throws -> String {
        guard state == .unlocked else { throw CancellationError() }
        guard !isSecondSession else { throw DuressError("generic") }
        let content = try KeyFile.newKeepassXMLv2(random: SystemRandomSource())
        try MacKeyFileWriter.write(content, to: url, vaultDirectory: vault.directory)
        do {
            try await whileUnlocked { try await vault.addKeyFile(password: password, keyFile: content) }
        } catch {
            // Never leave a key file behind that the vault does not use.
            if !vault.factors.contains(where: { $0.kind == .keyFile }) { try? FileManager.default.removeItem(at: url) }
            throw error
        }
        rememberKeyFileAfterChange(url)
        return added(FactorTexts.keyFileCreated(url.lastPathComponent))
    }

    func addYubiKey(slot: Int, password: String) async throws -> String {
        let respond = yubiKeyPrompt.confirmingResponder(slot: slot)
        try await whileUnlocked { try await vault.addYubiKey(password: password, slot: slot, respond: respond) }
        return added(FactorTexts.yubiKeyAdded(slot: slot))
    }

    func removeFactor(_ kind: FactorKind, password: String) async throws -> String {
        try await whileUnlocked { try await vault.removeFactor(kind, password: password) }
        if kind == .keyFile { KeyFileBookmark.forget(in: vault.factorKeychain) }
        refreshRememberedName()
        return kind == .keyFile ? FactorTexts.keyFileRemoved : FactorTexts.yubiKeyRemoved
    }

    /// A second YubiKey works only if it gives the same answer (programmed with the same secret). Nothing is written;
    /// no password is needed (the answer reveals no secret).
    func checkBackupYubiKey() async throws -> String {
        guard state == .unlocked else { throw CancellationError() }
        guard let spec = vault.factors.first(where: { $0.kind == .yubiKeyHMAC }) else { throw MacFactors.notSet }
        let respond = yubiKeyPrompt.responder(slot: spec.slot ?? MacFactors.defaultSlot)
        let response = try await respond(Data(spec.paddedChallenge))
        guard let secret = try? CompositeKey.yubiKeySecret([UInt8](response)),
              MacFactors.sameBytes(Data(CompositeKey.check(secret).utf8), Data(spec.check.utf8)) else {
            throw FactorMessageError(FactorTexts.backupDiffers)
        }
        return FactorTexts.backupMatches
    }

    func setFactorsAlwaysAsk(_ on: Bool) throws -> String {
        guard !isSecondSession else { throw DuressError("generic") }   // a real-vault setting (sub-plan 08)
        guard on else {
            settings.factorsAlwaysAsk = false
            return FactorTexts.alwaysAskOff
        }
        guard state == .unlocked else { throw CancellationError() }
        guard !vault.factors.isEmpty else { throw FactorMessageError(FactorTexts.alwaysAskNeedsFactor) }
        settings.factorsAlwaysAsk = true
        return removeTouchIDForAlwaysAsk() ? FactorTexts.alwaysAskOn + " " + FactorTexts.touchIDRemoved : FactorTexts.alwaysAskOn
    }

    /// The remembered key file's name (nil: none, or "Don't remember").
    var rememberedKeyFileName: String? { rememberedName }

    var touchIDOffForFactors: Bool { touchIDBlockedByFactors }

    /// A key file just added or created is remembered unless "Don't remember".
    private func rememberKeyFileAfterChange(_ url: URL) {
        defer { refreshRememberedName() }
        guard settings.rememberKeyFile, let spec = vault.factors.first(where: { $0.kind == .keyFile }) else { return }
        try? KeyFileBookmark.save(url, check: spec.check, to: vault.factorKeychain)
    }
}

// MARK: - Settings › Duress password (sub-plan 08)

extension MacLockModel: DuressService {
    /// Shown as "Set up" with these hours; nil ("Not set up") when there is none and always inside the second session.
    var duressStatusHours: Int? { isSecondSession ? nil : duressHours }

    /// Pro, the two duress passwords match and are long enough, the master password is right (throttled), and the
    /// duress password is neither the master password nor one edit from it. Inside the second session every check runs
    /// against the open vault and then the generic line is shown; nothing is written.
    func setUpDuress(masterPassword: String, duressPassword: String, confirm: String, hours: Int, isPro: Bool) async throws {
        guard state == .unlocked, let store else { throw CancellationError() }
        guard isPro else { throw DuressError("pro") }
        guard !masterPassword.isEmpty else { throw DuressError("current") }
        guard duressPassword == confirm else { throw DuressError("mismatch") }
        let generation = lockGeneration
        if isSecondSession {
            try await vault.setUpDuressInSecondSession(masterPassword: masterPassword, duressPassword: duressPassword, hours: hours)
            throw DuressError("generic")
        }
        let real = try store.load()
        try await vault.setUpDuress(masterPassword: masterPassword, duressPassword: duressPassword, hours: hours, real: real)
        guard state == .unlocked, generation == lockGeneration else { throw CancellationError() }
        duressHours = hours
    }

    /// Removes the second vault, its hold and the real vault's record (no mark of it stays). The confirmation asked first.
    func removeDuress() throws {
        guard state == .unlocked else { throw CancellationError() }
        guard !isSecondSession else { throw DuressError("generic") }
        try vault.removeDuress()
        duressHours = nil
    }
}

/// Lets the cancellation handler (any thread) invalidate the context; `LAContext.invalidate` may be called from any
/// thread.
private final class TouchIDContextBox: @unchecked Sendable {
    private let context: LAContext
    init(_ context: LAContext) { self.context = context }

    func evaluate(reason: String) async throws {
        try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
    }

    func invalidate() { context.invalidate() }
}
