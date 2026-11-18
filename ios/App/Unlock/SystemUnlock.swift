import Foundation
import LocalAuthentication
import os
import AppShared

/// Face ID / Touch ID with the device passcode as fallback (`.deviceOwnerAuthentication`). The same
/// authenticated `LAContext` opens the Keychain items, so one prompt covers the unlock.
///
/// Task 7: with the app password on (`app-password.json`), never the passcode: the password, the recovery phrase, or
/// the Face ID shortcut (`.deviceOwnerAuthenticationWithBiometrics` + the `.biometryCurrentSet` item). The local key is
/// then held in memory only (`AppPasswordKeyVault`).
@MainActor
final class SystemUnlocker: Unlocking {
    private static let log = Logger(subsystem: "app.localgatekeys.app", category: "keychain")
    private var context = LAContext()
    private(set) var keychain: (any KeychainVault)?
    let appPassword: AppPasswordStore?
    /// Sub-plan 08: the duress password's second vault (nil without the app-group container).
    let duress: PhoneDuress?
    /// The open session is the second vault's (set at its unlock, cleared by the next unlock).
    private(set) var secondSession = false

    init(appPassword: AppPasswordStore? = AppPasswordStore.shared(), duress: PhoneDuress? = PhoneDuress.shared()) {
        self.appPassword = appPassword; self.duress = duress
    }

    var passwordOn: Bool { appPassword?.isOn ?? false }
    /// Hidden while the real vault is held: the shortcut would open it.
    var biometricShortcut: Bool {
        enforceAlwaysAsk()
        if duress?.held() == true { return false }
        return appPassword?.biometricOn ?? false
    }
    var factorSpecs: [FactorSpec] { appPassword?.factorSpecs ?? [] }

    /// "Always ask for the key file / YubiKey": while factors are set the Face ID shortcut item is deleted (it would
    /// open the vault without them), also when a restored setting or an interrupted change left it behind.
    private func enforceAlwaysAsk() {
        guard let appPassword, AppSettings.shared.factorsAlwaysAsk, appPassword.biometric.exists, appPassword.hasFactors else { return }
        try? appPassword.biometric.remove()
    }

    func unlock(reason: String) async throws -> any ItemStore {
        if let appPassword, appPassword.isOn {
            enforceAlwaysAsk()
            guard appPassword.biometricOn, duress?.held() != true else { throw AppPasswordError.required }
            let ctx = LAContext()
            ctx.touchIDAuthenticationAllowableReuseDuration = 0
            ctx.localizedFallbackTitle = String(localized: "Use App Password")
            do {
                try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
            } catch let e as LAError where e.code == .userFallback {
                throw AppPasswordError.required
            }
            let key: [UInt8]
            do { key = try appPassword.biometric.load(context: ctx) } catch let e as AppPasswordError
                where e == .biometricChanged || e == .biometricKeyMissing {
                try? appPassword.biometric.remove()
                throw e
            }
            return try openWithKey(key, context: ctx)
        }
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        return try openSystem(context: ctx)
    }

    func unlock(password: String) async throws -> any ItemStore {
        try await unlock(password: password, factors: FactorSecrets())
    }

    /// The password and, for a file with factors, the key file and YubiKey (checked before Argon2id; a missing or
    /// wrong one is never counted as a wrong try). The recovery phrase (`recover`) needs neither.
    func unlock(password: String, factors: FactorSecrets) async throws -> any ItemStore {
        guard let appPassword, appPassword.isOn else { throw AppPasswordError.required }
        let duress = duress
        // Sub-plan 08: the real vault first, then the second one (both derivations only when it exists).
        let opened = try await Task.detached(priority: .userInitiated) {
            try await DuressUnlock.open(password: password, factors: factors, store: appPassword, duress: duress)
        }.value
        switch opened {
        case .real(let key): return try openWithKey(key, context: LAContext())
        case .second(let key): return try openSecond(key)
        }
    }

    /// The second vault: its own store in its own folder, a Keychain that exists only in memory (no sync slots, no
    /// Safari keys), no Safari index, no widget refresh. The real vault's AutoFill suggestions and reminder
    /// notifications are withdrawn until its next unlock.
    private func openSecond(_ key: [UInt8]) throws -> any ItemStore {
        guard let duress else { throw AppPasswordError.wrongPassword }
        context = LAContext()
        let opened = AppPasswordKeyVault(localKey: key, base: InMemoryKeychainVault())
        let store = try LocalStore.open(directory: duress.files.vault, vault: opened, limitHints: nil)
        keychain = opened
        secondSession = true
        duress.openSession()
        DuressEffects.secondVaultOpened()
        return store
    }

    /// The phrase opens without the key file or YubiKey; the new wrapper has no factors (version 1), so they are
    /// removed (the lock model says "add them again").
    func recover(phrase: String, newPassword: String) async throws -> any ItemStore {
        guard let appPassword, appPassword.isOn else { throw AppPasswordError.required }
        let duress = duress
        let key = try await Task.detached(priority: .userInitiated) { () throws -> [UInt8] in
            // While the real vault is held the phrase is refused as wrong (sub-plan 08).
            var k = try DuressUnlock.openPhrase(phrase, store: appPassword, duress: duress)
            do { try duress?.checkNewPassword(realKey: k, newPassword: newPassword, decoySession: false) } catch {
                for i in k.indices { k[i] = 0 }
                throw error
            }
            try appPassword.write(try appPassword.withNewPassword(try appPassword.readFile(), localKey: k,
                                                                    password: newPassword, random: SystemRandomSource()))
            return k
        }.value
        return try openWithKey(key, context: LAContext())
    }

    /// Password mode: the other slots carry no `.userPresence`, so an unevaluated context reads them. A passcode
    /// item of the local key left by an interrupted turn-on is deleted.
    private func openWithKey(_ key: [UInt8], context ctx: LAContext) throws -> any ItemStore {
        try? SystemKeychainVault(context: ctx).delete(.localKey)
        return try openSystem(context: ctx, localKey: key)
    }

    private func openSystem(context ctx: LAContext, localKey: [UInt8]? = nil) throws -> any ItemStore {
        // The real vault: no second session; a finished hold is removed.
        secondSession = false
        duress?.closeSession()
        duress?.release()
        DuressEffects.realVaultOpened()
        context = ctx
        let shared = SystemKeychainVault(context: ctx)
        // Sync-only slots live in the app-only group. When that group is unusable (no team prefix in unsigned
        // builds, or no entitlement for it: errSecMissingEntitlement) they stay in the shared group.
        let group = AppKeychainVault.appOnlyGroup(configured: AppGroup.appKeychainAccessGroup) {
            _ = try SystemKeychainVault(accessGroup: $0, context: ctx).read(.installID)
        }
        let synced: any KeychainVault = group.map {
            AppKeychainVault(shared: shared, appOnly: SystemKeychainVault(accessGroup: $0, context: ctx))
        } ?? shared
        if let app = synced as? AppKeychainVault {
            do { try app.migrate() } catch {
                Self.log.error("Keychain migration to the app-only group failed: \(String(describing: error), privacy: .public)")  // status codes and slot names only
            }
        }
        // The two Safari keys live in the Safari extension's own group (audit 2026-10-24 L-8); an earlier
        // build's copies in the shared group are moved there now. Unusable group: they stay where they were.
        let safariGroup = SafariKeys.group()
        let vault = SafariKeys.appVault(base: synced, group: safariGroup)
        if let safari = vault as? SafariKeychainVault {
            do { try safari.migrate() } catch {
                Self.log.error("Keychain migration to the Safari group failed: \(String(describing: error), privacy: .public)")  // status codes and slot names only
            }
        }
        let opened: any KeychainVault = localKey.map { AppPasswordKeyVault(localKey: $0, base: vault) } ?? vault
        keychain = opened
        // Task 7: an app-password turn-on or turn-off a crash or an error interrupted is finished now, in both modes
        // (the sync slots get the access flags the password file says). Idempotent; retried at the next unlock.
        do { try AppPasswordKeychainMigration.repairAtUnlock(vault) } catch {
            Self.log.error("App password Keychain repair failed: \(String(describing: error), privacy: .public)")  // status codes only
        }
        let store = try LocalStore.bootstrap(directory: try AppGroup.vaultDirectory(), vault: opened)
        // Every commit republishes the Safari fingerprint index. Its key has no `.userPresence`, so a vault
        // without this unlock's context reads it (a commit still finishing after a lock invalidated it).
        store.safariIndex = SafariIndexPublisher(keychain: SafariKeys.appVault(base: SystemKeychainVault(), group: safariGroup))
        // Every commit (edit, delete, import, sync run) rewrites the widgets' pinned codes, so a deleted item or a
        // removed or changed 2FA code never stays on the lock screen. Ignored once the vault has locked.
        store.onCommit = { snapshot in Task { @MainActor in WatchCodes.shared.refresh(snapshot: snapshot) } }
        // Item history (feature pack §1): each commit's replaced versions go to this unlock's local data.
        HistoryCapture.install(on: store) { rows in Task { @MainActor in HistoryRecorder.shared.record(rows) } }
        return store
    }

    func lock() {
        duress?.closeSession()
        context.invalidate()
        (keychain as? AppPasswordKeyVault)?.clear()   // zero the in-memory local key
        keychain = nil
        context = LAContext()
    }
}

/// Main-queue one-shot timers. Wall-clock deadlines are re-checked by `AppLockModel` on foreground.
@MainActor
final class DispatchLockScheduler: LockScheduler {
    final class Timer: LockTimer {
        let item: DispatchWorkItem
        init(_ item: DispatchWorkItem) { self.item = item }
        func cancel() { item.cancel() }
    }

    func schedule(after seconds: Int64, _ action: @escaping @MainActor () -> Void) -> any LockTimer {
        let item = DispatchWorkItem { MainActor.assumeIsolated { action() } }
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(Int(seconds)), execute: item)
        return Timer(item)
    }
}
