import Foundation
import LocalAuthentication
import os
import AppShared

/// Face ID / Touch ID with the device passcode as fallback (`.deviceOwnerAuthentication`). The same
/// authenticated `LAContext` opens the Keychain items, so one prompt covers the unlock.
@MainActor
final class SystemUnlocker: Unlocking {
    private static let log = Logger(subsystem: "app.localgatekeys.app", category: "keychain")
    private var context = LAContext()
    private(set) var keychain: (any KeychainVault)?

    func unlock(reason: String) async throws -> any ItemStore {
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
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
        keychain = vault
        let store = try LocalStore.bootstrap(directory: try AppGroup.vaultDirectory(), vault: vault)
        // Every commit republishes the Safari fingerprint index. Its key has no `.userPresence`, so a vault
        // without this unlock's context reads it (a commit still finishing after a lock invalidated it).
        store.safariIndex = SafariIndexPublisher(keychain: SafariKeys.appVault(base: SystemKeychainVault(), group: safariGroup))
        return store
    }

    func lock() {
        context.invalidate()
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
