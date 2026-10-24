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
}

/// Lock state for the whole app: unlock, lock on background after the chosen delay, lock after the
/// chosen idle time without activity (both from `AppSettings`).
@MainActor
@Observable
final class AppLockModel {
    enum State: Equatable { case locked, unlocking, unlocked }
    static let unlockReason = "Unlock your vault"

    private(set) var state: State = .locked
    private(set) var store: (any ItemStore)?
    private(set) var keychain: (any KeychainVault)?
    private(set) var errorMessage: String?
    /// The pending erase failed: the unlock screen offers "Start fresh anyway" so no one is locked out for good.
    private(set) var eraseFailed = false
    /// The vault's files are here but their key is not (a restored backup): only Start fresh can help.
    private(set) var vaultUnreadable = false
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
    /// Bumped by every lock, so an unlock that was in flight when the lock happened is discarded.
    @ObservationIgnored private var generation = 0
    /// True while `eraseAndLock` runs: `unlock()` returns early so no second erase starts and no vault opens.
    @ObservationIgnored private var isErasing = false
    /// Prompt for Face ID the next time the scene becomes active: at launch and after a real trip to the
    /// background, never when the Face ID sheet itself makes the scene inactive and active again.
    @ObservationIgnored private var promptOnActive = true

    init(unlocker: any Unlocking, clock: any UnixClock, scheduler: any LockScheduler, settings: AppSettings,
         clipboard: SecretClipboard?, eraser: any VaultErasing) {
        self.unlocker = unlocker; self.clock = clock; self.scheduler = scheduler; self.settings = settings
        self.clipboard = clipboard; self.eraser = eraser
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
        state = .unlocking; errorMessage = nil; vaultUnreadable = false
        let started = generation
        do {
            let opened = try await unlocker.unlock(reason: Self.unlockReason)
            guard generation == started, state == .unlocking else { unlocker.lock(); return }   // a lock won
            store = opened
            keychain = unlocker.keychain
            state = .unlocked
            noteActivity()
        } catch {
            guard generation == started else { return }
            state = .locked; store = nil; keychain = nil
            errorMessage = Self.message(for: error)
            vaultUnreadable = (error as? LocalStoreError) == .vaultWithoutKey
        }
    }

    static let vaultWithoutKeyMessage = "This iPhone has vault files but not their key (for example after restoring a backup), so they cannot be opened. Start fresh to erase them and set up an empty vault, then sync with your PC to get your items back."

    static let biometryLockoutMessage = "Face ID is locked after too many attempts. Lock and unlock your iPhone with its passcode, then try again."

    /// What the unlock screen says after a failed unlock; nil when the person cancelled (the Unlock button stays).
    static func message(for error: any Error) -> String? {
        if let e = error as? LAError {
            switch e.code {
            case .userCancel, .systemCancel, .appCancel: return nil
            case .passcodeNotSet: return "Set a device passcode in Settings to use LocalGateKeys."
            case .biometryLockout: return biometryLockoutMessage
            default: return "Could not unlock (authentication error \(e.code.rawValue)). Try again."
            }
        }
        if let e = error as? KeychainVaultError {
            switch e {
            case .status(let code): return "Could not read the vault key from the Keychain (error \(code)). Try again."
            case .accessControl: return "Could not protect the vault key in the Keychain. Try again."
            case .malformed(let slot): return "A Keychain item of the vault is damaged (\(slot.rawValue))."
            }
        }
        if let e = error as? LocalStoreError {
            switch e {
            case .noContainer: return "The vault's storage on this iPhone is unavailable."
            case .noLocalKey: return "The vault key is missing from this iPhone's Keychain."
            case .badLocalKey: return "The vault key in this iPhone's Keychain is damaged."
            case .vaultWithoutKey: return vaultWithoutKeyMessage
            case .corrupt: return "The vault on this iPhone could not be read (damaged)."
            case .io: return "The vault's files on this iPhone could not be read or written. Try again."
            case .stale: return "Could not unlock. Try again."
            }
        }
        return "Could not unlock. Try again."
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
        } catch {
            errorMessage = (error as? VaultEraseFailure)?.message
                ?? "The vault was not fully erased. Tap Unlock to try erasing again, or Start fresh anyway."
            eraseFailed = true
        }
    }

    static let startFreshConfirm1 = "Start fresh anyway?\n\nLocalGateKeys deletes everything it can from this iPhone and opens a new, empty vault. Anything it could not delete stays on this iPhone but is no longer used. Your PC and the sync folder are not changed."
    static let startFreshConfirm2 = "Are you sure? This cannot be undone. Start fresh now?"

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

    func didEnterBackground() {
        promptOnActive = true
        guard state == .unlocked else { return }
        if settings.autoLockDelay == .immediately { lock(clearClipboard: false); return }
        backgroundedAt = clock.now
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
