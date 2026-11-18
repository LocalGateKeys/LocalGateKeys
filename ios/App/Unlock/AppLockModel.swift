import Foundation
import Observation
import LocalAuthentication
import AppShared

/// Starts a one-shot timer. The app uses `DispatchLockScheduler`; tests advance a manual one.
@MainActor
protocol LockScheduler: AnyObject {
    func schedule(after seconds: Int64, _ action: @escaping @MainActor () -> Void) -> any LockTimer
}

@MainActor
protocol LockTimer: AnyObject { func cancel() }

/// Device-owner authentication (Face ID, passcode fallback) plus opening the store with the
/// authenticated context. The real one is `SystemUnlocker`; tests use a fake.
@MainActor
protocol Unlocking: AnyObject {
    func unlock(reason: String) async throws -> any ItemStore
    /// The Keychain opened with the same authentication (sync state: install id, peer, bookmark, counters).
    var keychain: (any KeychainVault)? { get }
    /// Drops the authenticated context so the next unlock asks again.
    func lock()

    /// Task 7: the app password is on (no passcode route), and the Face ID shortcut is set up.
    var passwordOn: Bool { get }
    var biometricShortcut: Bool { get }
    func unlock(password: String) async throws -> any ItemStore
    /// The 24 words and the new app password to set.
    func recover(phrase: String, newPassword: String) async throws -> any ItemStore

    /// Task 8: the app password's key-file / YubiKey factors (public specs), and the password unlock with them.
    var factorSpecs: [FactorSpec] { get }
    func unlock(password: String, factors: FactorSecrets) async throws -> any ItemStore

    /// Sub-plan 08: the last unlock opened the duress password's second vault.
    var secondSession: Bool { get }
}

extension Unlocking {
    var passwordOn: Bool { false }
    var biometricShortcut: Bool { false }
    var factorSpecs: [FactorSpec] { [] }
    var secondSession: Bool { false }
    func unlock(password: String, factors: FactorSecrets) async throws -> any ItemStore { try await unlock(password: password) }
    func unlock(password: String) async throws -> any ItemStore { throw AppPasswordError.required }
    func recover(phrase: String, newPassword: String) async throws -> any ItemStore { throw AppPasswordError.required }
}

/// Lock state for the whole app: unlock, lock on background after the chosen delay, lock after the
/// chosen idle time without activity (both from `AppSettings`).
@MainActor
@Observable
final class AppLockModel {
    enum State: Equatable { case locked, unlocking, unlocked }
    static let unlockReason = String(localized: "Unlock your vault")

    private(set) var state: State = .locked
    private(set) var store: (any ItemStore)?
    private(set) var keychain: (any KeychainVault)?
    private(set) var errorMessage: String?
    /// The pending erase failed: the unlock screen offers "Start fresh anyway" so no one is locked out for good.
    private(set) var eraseFailed = false
    /// The vault's files are here but their key is not (a restored backup): only Start fresh can help.
    private(set) var vaultUnreadable = false
    /// Task 7: the unlock screen shows the app password field (and "Forgot app password?").
    private(set) var needsPassword = false
    /// Sub-plan 08: the open vault is the duress password's second vault (no sync, no Safari or AutoFill data, no
    /// passkeys). Nothing on screen says so; it is kept after the lock until the next unlock.
    private(set) var secondSession = false
    var biometricShortcut: Bool { unlocker.biometricShortcut }

    // Task 8: key file and YubiKey (design §4.6/§4.7). The specs are read when the password field is shown.
    private(set) var factorSpecs: [FactorSpec] = []
    var keyFileSpec: FactorSpec? { factorSpecs.first { $0.kind == .keyFile } }
    var yubiKeySpec: FactorSpec? { factorSpecs.first { $0.kind == .yubiKeyHMAC } }
    /// The key file picked on the unlock screen this time (its scope is the picker's); nil uses the remembered one.
    private(set) var pickedKeyFile: URL?
    /// The key file this iPhone remembers for the current key-file factor (name for display).
    private(set) var rememberedKeyFile: RememberedKeyFile?
    /// "Don't remember this key file": after the unlock the bookmark is removed instead of saved.
    var dontRememberKeyFile = false
    /// Shown once after the unlock (a phrase reset dropped the factors), until read.
    private(set) var unlockNotice: String?
    func dismissUnlockNotice() { unlockNotice = nil }
    /// The unlock screen shows "Start fresh anyway".
    var offersStartFresh: Bool { eraseFailed || vaultUnreadable }

    @ObservationIgnored private let unlocker: any Unlocking
    @ObservationIgnored private let clock: any UnixClock
    @ObservationIgnored private let scheduler: any LockScheduler
    @ObservationIgnored private let settings: AppSettings
    @ObservationIgnored private var idleTimer: (any LockTimer)?
    @ObservationIgnored private var lastActivity: Int64 = 0
    @ObservationIgnored private var backgroundedAt: Int64?
    @ObservationIgnored private let clipboard: SecretClipboard?
    /// Runs "Erase this iPhone's vault", and its retry while `settings.erasePending` is set.
    @ObservationIgnored private let eraser: any VaultErasing
    /// Task 8: the key-file bookmark and the YubiKey over NFC; nil (tests without factors) supplies nothing.
    @ObservationIgnored let factors: (any PhoneFactorSourcing)?
    /// Bumped by every lock, so an unlock that was in flight when the lock happened is discarded.
    @ObservationIgnored private var generation = 0
    /// True while `eraseAndLock` runs: `unlock()` returns early so no second erase starts and no vault opens.
    @ObservationIgnored private var isErasing = false
    /// Prompt for Face ID the next time the scene becomes active: at launch and after a real trip to the
    /// background, never when the Face ID sheet itself makes the scene inactive and active again.
    @ObservationIgnored private var promptOnActive = true

    init(unlocker: any Unlocking, clock: any UnixClock, scheduler: any LockScheduler, settings: AppSettings,
         clipboard: SecretClipboard?, eraser: any VaultErasing, factors: (any PhoneFactorSourcing)? = nil) {
        self.unlocker = unlocker; self.clock = clock; self.scheduler = scheduler; self.settings = settings
        self.clipboard = clipboard; self.eraser = eraser; self.factors = factors
    }

    /// Reads the factors of the app password file and the key file remembered for them (the password field shows
    /// what else is needed).
    func refreshFactors() {
        factorSpecs = unlocker.passwordOn ? unlocker.factorSpecs : []
        rememberedKeyFile = keyFileSpec.flatMap { factors?.rememberedKeyFile(check: $0.check) }
        if keyFileSpec == nil { pickedKeyFile = nil }
    }

    /// The key file picked on the unlock screen (nothing is read or remembered yet).
    func chooseKeyFile(_ url: URL) { pickedKeyFile = url }

    /// The factor input for `factorSpecs`: the picked (else remembered) key file's bytes, read now within
    /// `KeyFile.maxBytes`, and the NFC responder. A missing key file stays nil, so `CompositeKey` reports it as
    /// required before any YubiKey tap.
    private func factorInput() async throws -> FactorSecrets {
        var input = FactorSecrets()
        if keyFileSpec != nil, let url = pickedKeyFile ?? rememberedKeyFile?.url, let factors {
            input.keyFile = try await factors.readKeyFile(url)
        }
        if let spec = yubiKeySpec, let factors {
            input.yubiKey = factors.yubiKey(slot: spec.slot ?? PhoneFactors.defaultSlot, confirming: false)
        }
        return input
    }

    func unlock() async {
        guard state == .locked, !isErasing else { return }
        // An erase that did not finish (failed, or the app was killed during it): finish it first, so a
        // half-wiped vault never opens. The flag lives in the app group, so it survives a relaunch.
        if settings.erasePending {
            state = .unlocking; errorMessage = nil
            await runErase()
            state = .locked
            guard !settings.erasePending else { return }
        }
        if unlocker.passwordOn {
            needsPassword = true
            refreshFactors()
            // No shortcut: no prompt at all; the password field is the only way in (never the passcode).
            guard unlocker.biometricShortcut else { return }
        } else {
            needsPassword = false
        }
        await attempt { try await $0.unlock(reason: Self.unlockReason) }
    }

    /// Task 7: unlock with the typed app password; Task 8: with its key file and YubiKey when the file has them.
    /// The key file picked here is remembered only after the unlock succeeded (or forgotten with "Don't remember").
    func unlock(password: String) async {
        guard state == .locked, !isErasing, !settings.erasePending else { return }
        refreshFactors()
        guard !factorSpecs.isEmpty else {
            await attempt { try await $0.unlock(password: password) }
            return
        }
        let picked = pickedKeyFile, forget = dontRememberKeyFile, keyCheck = keyFileSpec?.check
        let opened = await attempt { unlocker in
            let input = try await self.factorInput()
            return try await unlocker.unlock(password: password, factors: input)
        }
        guard opened, let keyCheck else { return }
        if forget {
            factors?.forgetKeyFile()
        } else if let picked {
            factors?.rememberKeyFile(picked, check: keyCheck)
        }
        pickedKeyFile = nil
    }

    /// Task 7: "Forgot app password?" (the screen has already checked the new password's strength). Task 8: the
    /// phrase needs no key file or YubiKey; the new password comes without them, so the bookmark goes and a notice
    /// says so.
    func recover(phrase: String, newPassword: String) async {
        guard state == .locked, !isErasing, !settings.erasePending else { return }
        refreshFactors()
        let hadFactors = !factorSpecs.isEmpty
        let opened = await attempt { try await $0.recover(phrase: phrase, newPassword: newPassword) }
        guard opened, hadFactors else { return }
        factors?.forgetKeyFile()
        factorSpecs = []; pickedKeyFile = nil; rememberedKeyFile = nil
        unlockNotice = PhoneFactors.factorsRemovedByPhrase
    }

    /// True when the vault opened.
    @discardableResult
    private func attempt(_ open: @MainActor (any Unlocking) async throws -> any ItemStore) async -> Bool {
        state = .unlocking; errorMessage = nil; vaultUnreadable = false
        let started = generation
        do {
            let opened = try await open(unlocker)
            guard generation == started, state == .unlocking else { unlocker.lock(); return false }   // a lock won
            store = opened
            keychain = unlocker.keychain
            secondSession = unlocker.secondSession
            state = .unlocked
            needsPassword = false
            noteActivity()
            return true
        } catch {
            guard generation == started else { return false }
            state = .locked; store = nil; keychain = nil
            errorMessage = Self.message(for: error)
            vaultUnreadable = (error as? LocalStoreError) == .vaultWithoutKey
            if unlocker.passwordOn || error is AppPasswordError { needsPassword = true }
            return false
        }
    }

    static let wrongPasswordMessage = String(localized: "That app password is not right.")
    static let wrongPhraseMessage = String(localized: "This recovery phrase does not belong to this vault.")
    static let biometricChangedMessage = String(localized: "Your Face ID changed, so the Face ID shortcut was turned off. Type your app password.")
    static let biometricKeyMissingMessage = String(localized: "Face ID unlock is no longer set up on this device. Type your app password, then turn Face ID on again in Settings.")

    static func waitMessage(_ seconds: Int64) -> String {
        seconds >= 120 ? String(localized: "Too many wrong tries. Try again in \((seconds + 59) / 60) minutes.")
            : String(localized: "Too many wrong tries. Try again in \(seconds) seconds.")
    }

    static let vaultWithoutKeyMessage = DeviceText.isPad ? String(localized: "ipad.appLockModel.hasVaultFilesBut", defaultValue: "This iPad has vault files but not their key (for example after restoring a backup), so they cannot be opened. Start fresh to erase them and set up an empty vault, then sync with your PC to get your items back.") : String(localized: "This iPhone has vault files but not their key (for example after restoring a backup), so they cannot be opened. Start fresh to erase them and set up an empty vault, then sync with your PC to get your items back.")

    static let biometryLockoutMessage = DeviceText.isPad ? String(localized: "ipad.appLockModel.faceIdLockedAfter", defaultValue: "Face ID is locked after too many attempts. Lock and unlock your iPad with its passcode, then try again.") : String(localized: "Face ID is locked after too many attempts. Lock and unlock your iPhone with its passcode, then try again.")

    /// What the unlock screen says after a failed unlock; nil when the person cancelled (the Unlock button stays).
    static func message(for error: any Error) -> String? {
        if let e = error as? AppPasswordError {
            switch e {
            case .required: return nil
            case .wrongPassword: return wrongPasswordMessage
            case .wrongPhrase: return wrongPhraseMessage
            case .wait(let s): return waitMessage(s)
            case .biometricChanged: return biometricChangedMessage
            case .biometricKeyMissing: return biometricKeyMissingMessage
            case .openAppFirst: return String(localized: "Open LocalGateKeys and unlock it with your app password first.")
            case .corrupt: return DeviceText.isPad ? String(localized: "ipad.appLockModel.appPasswordFileDamaged", defaultValue: "The app password file on this iPad is damaged, so neither the app password nor the recovery phrase can open it. Use Start fresh, then restore a backup if you have one.") : String(localized: "The app password file on this iPhone is damaged, so neither the app password nor the recovery phrase can open it. Use Start fresh, then restore a backup if you have one.")
            case .alreadyOn: return String(localized: "The app password is already on.")
            case .openAppForFactors: return PhoneFactors.openAppForFactors
            }
        }
        if let e = error as? DuressError { return DuressText.message(e) }
        // Task 8: a missing or wrong key file / YubiKey, an NFC problem (a cancelled tap says nothing).
        if let factor = PhoneFactors.describe(error) { return factor.text }
        if let e = error as? RecoveryPhraseError { return e.message }
        if let e = error as? LAError {
            switch e.code {
            case .userCancel, .systemCancel, .appCancel: return nil
            case .passcodeNotSet: return String(localized: "Set a device passcode in Settings to use LocalGateKeys.")
            case .biometryLockout: return biometryLockoutMessage
            default: return String(localized: "Could not unlock (authentication error \(e.code.rawValue)). Try again.")
            }
        }
        if let e = error as? KeychainVaultError {
            switch e {
            case .status(let code): return String(localized: "Could not read the vault key from the Keychain (error \(String(code))). Try again.")
            case .accessControl: return String(localized: "Could not protect the vault key in the Keychain. Try again.")
            case .malformed(let slot): return String(localized: "A Keychain item of the vault is damaged (\(slot.rawValue)).")
            }
        }
        if let e = error as? LocalStoreError {
            switch e {
            case .noContainer: return DeviceText.isPad ? String(localized: "ipad.appLockModel.vaultStorageUnavailable", defaultValue: "The vault's storage on this iPad is unavailable.") : String(localized: "The vault's storage on this iPhone is unavailable.")
            case .noLocalKey: return DeviceText.isPad ? String(localized: "ipad.appLockModel.vaultKeyMissingFrom", defaultValue: "The vault key is missing from this iPad's Keychain.") : String(localized: "The vault key is missing from this iPhone's Keychain.")
            case .badLocalKey: return DeviceText.isPad ? String(localized: "ipad.appLockModel.vaultKeyInKeychain", defaultValue: "The vault key in this iPad's Keychain is damaged.") : String(localized: "The vault key in this iPhone's Keychain is damaged.")
            case .vaultWithoutKey: return vaultWithoutKeyMessage
            case .corrupt: return DeviceText.isPad ? String(localized: "ipad.appLockModel.vaultCouldNotBe", defaultValue: "The vault on this iPad could not be read (damaged).") : String(localized: "The vault on this iPhone could not be read (damaged).")
            case .io: return DeviceText.isPad ? String(localized: "ipad.appLockModel.vaultFilesCouldNot", defaultValue: "The vault's files on this iPad could not be read or written. Try again.") : String(localized: "The vault's files on this iPhone could not be read or written. Try again.")
            case .stale: return String(localized: "Could not unlock. Try again.")
            }
        }
        return String(localized: "Could not unlock. Try again.")
    }

    /// The scene became active. Prompts only at launch and on return from the background; checks the lock
    /// deadlines first (`willEnterForeground`).
    func sceneBecameActive() async {
        willEnterForeground()
        guard promptOnActive else { return }
        promptOnActive = false
        if state == .locked { await unlock() }
    }

    /// Dropping `store` is what drops the decoded records: the list and detail models live in views
    /// that exist only while `state == .unlocked`, so they are released with it.
    ///
    /// `clearClipboard` false: a lock because the app left the screen keeps what was just copied, since the
    /// person left to paste it somewhere else. The copy is local-only and still expires on its own timer.
    func lock(clearClipboard: Bool = true) {
        idleTimer?.cancel(); idleTimer = nil; backgroundedAt = nil
        guard state != .locked else { return }
        generation += 1
        factors?.cancelYubiKey()
        pickedKeyFile = nil
        store = nil; keychain = nil; state = .locked
        if clearClipboard { clipboard?.clearIfOwned() }
        unlocker.lock()
    }

    /// "Erase this iPhone's vault": locks first (whatever happens next), waits for work that could still
    /// write (`afterLock`: sync and identity refreshes), then erases. A failure is shown on the unlock screen
    /// and the erase is retried before the next unlock.
    func eraseAndLock(afterLock: () async -> Void = {}) async {
        isErasing = true
        defer { isErasing = false }
        lock()
        settings.erasePending = true   // before anything is deleted: a crash mid-erase leaves it set
        await afterLock()
        await runErase()
    }

    private func runErase() async {
        SiteIconStore.shared.clear()   // which sites the vault held, best effort
        do {
            try await eraser.erase()
            settings.erasePending = false   // cleared only on success
            errorMessage = nil; eraseFailed = false
            // An erase after a removal from sync (also its retry before unlock) says so once it really happened.
            if settings.syncRemovalErasePending {
                settings.syncRemovalErasePending = false
                settings.syncRemovalErasedAt = clock.now
            }
        } catch {
            errorMessage = (error as? VaultEraseFailure)?.message
                ?? String(localized: "The vault was not fully erased. Tap Unlock to try erasing again, or Start fresh anyway.")
            eraseFailed = true
        }
    }

    /// Another member of the cloud-folder group removed this iPhone and its signed notice verified (`RemovalNotice`):
    /// with "Erase this device if it is removed from sync" on, the same erase as "Erase this iPhone's vault" (locks
    /// first, waits for `afterLock`, retried before the next unlock if it fails), then a one-time notice on the
    /// unlock screen. Files the person exported (backups, CSV) are outside the app and never touched.
    func eraseAfterRemoval(afterLock: () async -> Void = {}) async {
        guard !isErasing, settings.eraseOnSyncRemoval else { return }
        settings.syncRemovalErasePending = true   // the notice follows a successful erase (`runErase`), never a failed one
        await eraseAndLock(afterLock: afterLock)
    }

    /// The unlock screen shows that the vault was erased after a removal from sync, until it is read.
    var showsRemovalNotice: Bool { settings.syncRemovalErasedAt != nil }
    func dismissRemovalNotice() { settings.syncRemovalErasedAt = nil }

    static let startFreshConfirm1 = DeviceText.isPad ? String(localized: "ipad.appLockModel.startFreshConfirm1", defaultValue: "Start fresh anyway?\n\nLocalGateKeys deletes everything it can from this iPad and opens a new, empty vault. Anything it could not delete stays on this iPad but is no longer used. Your PC and the sync folder are not changed.") : String(localized: "Start fresh anyway?\n\nLocalGateKeys deletes everything it can from this iPhone and opens a new, empty vault. Anything it could not delete stays on this iPhone but is no longer used. Your PC and the sync folder are not changed.")
    static let startFreshConfirm2 = String(localized: "Are you sure? This cannot be undone. Start fresh now?")

    /// "Start fresh anyway" (after two confirmations): one more erase attempt, then the pending flag is
    /// cleared whatever it left behind, so the next unlock is a first run.
    ///
    /// For a vault whose key is missing (`vaultUnreadable`) it is a normal erase instead: pending until it
    /// succeeds, so a failure continues in the erase flow above (retry on Unlock, then Start fresh anyway).
    func startFreshAnyway() async {
        if vaultUnreadable, !settings.erasePending, state == .locked, !isErasing {
            isErasing = true
            defer { isErasing = false }
            state = .unlocking
            settings.erasePending = true
            await runErase()
            if !eraseFailed { vaultUnreadable = false }
            state = .locked
            return
        }
        guard state == .locked, !isErasing, settings.erasePending else { return }
        isErasing = true
        defer { isErasing = false }
        state = .unlocking
        try? await eraser.erase()
        settings.erasePending = false
        settings.syncRemovalErasePending = false   // whatever it left behind: no "was erased" notice
        errorMessage = nil; eraseFailed = false; vaultUnreadable = false
        state = .locked
    }

    /// Any touch or edit. Restarts the idle timer (none when the setting is Never).
    func noteActivity() {
        guard state == .unlocked else { return }
        lastActivity = clock.now
        idleTimer?.cancel(); idleTimer = nil
        guard let timeout = settings.idleLock.seconds else { return }
        idleTimer = scheduler.schedule(after: timeout) { [weak self] in self?.idleTimerFired() }
    }

    private var idleExpired: Bool {
        guard let timeout = settings.idleLock.seconds else { return false }
        return clock.now - lastActivity >= timeout
    }

    private func idleTimerFired() {
        if state == .unlocked, idleExpired { lock() }
    }

    /// Unlocked, and the lock checks of the last return to the foreground (auto-lock delay, idle limit) have run: the
    /// moment a link opened from outside (`TwoFactorLinkRoute`) may be handed to the vault screens.
    var settledUnlocked: Bool { state == .unlocked && !promptOnActive }

    func didEnterBackground() {
        promptOnActive = true
        guard state == .unlocked else { return }
        if settings.autoLockDelay == .immediately { lock(clearClipboard: false); return }
        backgroundedAt = clock.now
    }

    /// When the vault counts as locked if the app stays in the background (Unix seconds): the auto-lock delay
    /// or the idle limit, whichever comes first. Nil while locked (it is locked already).
    var backgroundLockDeadline: Int64? {
        guard state == .unlocked else { return nil }
        var deadline = (backgroundedAt ?? clock.now) + settings.autoLockDelay.rawValue
        if let idle = settings.idleLock.seconds { deadline = min(deadline, lastActivity + idle) }
        return deadline
    }

    /// The app is suspended in the background, so timers may not have fired: check both limits here.
    func willEnterForeground() {
        guard state == .unlocked else { return }
        let now = clock.now
        if let since = backgroundedAt, now - since >= settings.autoLockDelay.rawValue { lock(clearClipboard: false); return }
        if idleExpired { lock(); return }
        backgroundedAt = nil
        noteActivity()
    }
}
