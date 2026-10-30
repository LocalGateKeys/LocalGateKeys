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

    init(appPassword: AppPasswordStore? = AppPasswordStore.shared()) { self.appPassword = appPassword }

    var passwordOn: Bool { appPassword?.isOn ?? false }
    var biometricShortcut: Bool { appPassword?.biometricOn ?? false }

    func unlock(reason: String) async throws -> any ItemStore {
        if let appPassword, appPassword.isOn {
            guard appPassword.biometricOn else { throw AppPasswordError.required }
            let ctx = LAContext()
            ctx.touchIDAuthenticationAllowableReuseDuration = 0
            ctx.localizedFallbackTitle = String(localized: "Use App Password")
            do {
                try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
            } catch let e as LAError where e.code == .userFallback {
                throw AppPasswordError.required
            }
            let key: [UInt8]
            do { key = try appPassword.biometric.load(context: ctx) } catch AppPasswordError.biometricChanged {
                try? appPassword.biometric.remove()
                throw AppPasswordError.biometricChanged
            }
            return try openWithKey(key, context: ctx)
        }
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        return try openSystem(context: ctx)
    }

    func unlock(password: String) async throws -> any ItemStore {
        guard let appPassword, appPassword.isOn else { throw AppPasswordError.required }
        let key = try await Task.detached(priority: .userInitiated) { try appPassword.open(password: password) }.value
        return try openWithKey(key, context: LAContext())
    }

    func recover(phrase: String, newPassword: String) async throws -> any ItemStore {
        guard let appPassword, appPassword.isOn else { throw AppPasswordError.required }
        let key = try await Task.detached(priority: .userInitiated) { () throws -> [UInt8] in
            let k = try appPassword.open(phrase: phrase)
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
        return store
    }

    func lock() {
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
