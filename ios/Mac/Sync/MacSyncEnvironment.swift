import Foundation
import os
import Security
import AppSharedMac

/// The Mac never refreshes AutoFill identities after a sync run: every commit already goes through
/// `PublishingItemStore`, which republishes them (`MacLockModel`).
struct NoAutoFillRefresh: AutoFillIdentityRefreshing {
    func syncDidFinish(store: any ItemStore) async {}
}

/// Builds the iPhone's sync client for the Mac: the app-only Keychain group for the sync slots, the lock
/// model's publishing store, the Mac's activity tasks and its host name as the device name.
@MainActor
enum MacSyncEnvironment {
    private static let log = Logger(subsystem: "app.localgatekeys.mac", category: "keychain")
    /// Longest name shown for this Mac, and the most UTF-8 bytes it may take in the keyring.
    static let nameLimit = SyncWording.nameLimit
    static let nameByteLimit = 64

    /// Where the sync slots go. Release builds never put them in the shared group, which AutoFillMac can
    /// read and where Mac sync slots have no `.userPresence`: without the app-only group, sync stays off.
    enum KeychainPlan: Equatable {
        case appOnly(String)
        /// DEBUG and unsigned builds only.
        case sharedFallback
        case unavailable
    }

    static let unavailableText = String(localized: "Sync isn't available in this build.")

    #if DEBUG
    static let isRelease = false
    #else
    static let isRelease = true
    #endif

    static func keychainPlan(appOnlyGroup: String?, release: Bool) -> KeychainPlan {
        if let appOnlyGroup { return .appOnly(appOnlyGroup) }
        return release ? .unavailable : .sharedFallback
    }

    /// The sync slots' vault for `plan`: the app-only group over `shared` (earlier copies migrated), `shared`
    /// itself in DEBUG fallback, nil when sync is unavailable.
    static func makeSyncKeychain(plan: KeychainPlan, shared: any KeychainVault = SystemKeychainVault(),
                                 appOnly: (String) -> any KeychainVault = { SystemKeychainVault(accessGroup: $0) }) -> (any KeychainVault)? {
        switch plan {
        case .unavailable: return nil
        case .sharedFallback: return shared
        case .appOnly(let group):
            let vault = AppKeychainVault(shared: shared, appOnly: appOnly(group))
            // No `.userPresence` on Mac sync slots, so moving them never prompts.
            do { try vault.migrate() } catch {
                log.error("Keychain migration to the app-only group failed: \(String(describing: error), privacy: .public)")
            }
            return vault
        }
    }

    static let plan = keychainPlan(
        appOnlyGroup: AppKeychainVault.appOnlyGroup(configured: AppGroup.appKeychainAccessGroup) {
            _ = try SystemKeychainVault(accessGroup: $0).read(.installID)
        },
        release: isRelease)

    /// The sync slots' vault for the active profile (`ProfileScope`), or nil when this build cannot keep them safely.
    static var syncKeychain: (any KeychainVault)? { vaults().sync }

    /// The vault `MacVault` uses: the sync vault when there is one, else the shared group (no sync slots are
    /// ever written then: the coordinator refuses every action).
    static var keychain: any KeychainVault { vaults().main }

    /// Built once per profile (the migration from the shared group runs then); Keychain accounts carry the
    /// profile's prefix (none for the default profile).
    private static var cached: (id: String, sync: (any KeychainVault)?, main: any KeychainVault)?

    private static func vaults() -> (sync: (any KeychainVault)?, main: any KeychainVault) {
        let id = ProfileScope.currentID
        if let cached, cached.id == id { return (cached.sync, cached.main) }
        let prefix = ProfileScope.keychainPrefix
        let sync = makeSyncKeychain(plan: plan, shared: SystemKeychainVault(accountPrefix: prefix),
                                    appOnly: { SystemKeychainVault(accessGroup: $0, accountPrefix: prefix) })
        let main = sync ?? SystemKeychainVault(accountPrefix: prefix)
        cached = (id, sync, main)
        return (sync, main)
    }

    /// This Mac's name for the keyring and paired devices: the host name, sanitised to at most 40 characters
    /// and 64 UTF-8 bytes; "Mac" when there is none.
    static func deviceName(hostName: String? = Host.current().localizedName) -> String {
        guard let raw = hostName, !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return "Mac" }
        var name = SyncWording.sanitize(raw, limit: nameLimit)
        if name == SyncWording.unnamedDevice { return "Mac" }
        while name.utf8.count > nameByteLimit { name.removeLast() }
        return name.trimmingCharacters(in: .whitespaces)
    }

    /// A coordinator over the unlocked vault's publishing store (`lock.store`), or nil while locked.
    /// With no sync keychain (`.unavailable`) the coordinator keeps sync off and shows `unavailableText`.
    static func makeCoordinator(lock: MacLockModel, keychain: (any KeychainVault)? = MacSyncEnvironment.syncKeychain,
                                hostName: String? = Host.current().localizedName) -> SyncCoordinator? {
        guard lock.state == .unlocked, let store = lock.store as? PublishingItemStore else { return nil }
        // Sub-plan 08: the duress password's second vault never syncs. Its coordinator is inert, over a Keychain that
        // exists only in memory (none of the real vault's sync keys, peers or folders are read), with no watch file,
        // no attachment blobs and no removal notice.
        let second = lock.isSecondSession
        var deps = SyncDependencies.live(keychain: second ? InMemoryKeychainVault() : (keychain ?? RefusingKeychainVault()))
        if keychain == nil, !second { deps.unavailableText = unavailableText }
        deps.autoFill = NoAutoFillRefresh()
        deps.deviceName = deviceName(hostName: hostName)
        deps.editDebounceNanos = MacSyncScheduler.editDelayNanos   // Windows: 10 s after the last edit
        deps.watchFile = second ? nil : SyncDependencies.watchFileURL(in: lock.vaultDirectory)   // next to this Mac's vault
        if second { deps.inert = true; deps.attachmentBlobs = nil }
        let coordinator = SyncCoordinator(store: SyncSourceStore(base: store, local: lock), deps: deps,
                                          background: PlatformBackgroundTasks.make())
        // A verified removal notice: the removal guard erases (setting on), after this run has finished.
        if !second { coordinator.onRemovalNotice = { MacAppEnvironment.removalGuard?.removedBySync() } }
        // Shared collections (sub-plan 07): Recently deleted is the lock model's, and `SyncSourceStore` already moves
        // every live item a commit takes out there. Pro comes from the scheduler (`MacSyncScheduler.unlocked`).
        coordinator.shareTrash = lock
        coordinator.storeMovesDeletesToTrash = true
        return coordinator
    }

    /// The hello counter source of the coordinator's Wi-Fi client; the host must use this same one, so the
    /// counters this Mac sends keep increasing whichever side dials (one source, never two).
    static func helloCounters(_ deps: SyncDependencies) -> HelloCounterSource? {
        (deps.lan as? LiveLanTransport)?.counters
    }
}

/// Stands in for the sync vault when sync is unavailable: every access is refused, nothing is stored.
final class RefusingKeychainVault: KeychainVault, @unchecked Sendable {
    func read(_ slot: VaultSlot) throws -> [UInt8]? { throw KeychainVaultError.status(errSecMissingEntitlement) }
    func write(_ slot: VaultSlot, _ bytes: [UInt8]) throws { throw KeychainVaultError.status(errSecMissingEntitlement) }
    func delete(_ slot: VaultSlot) throws { throw KeychainVaultError.status(errSecMissingEntitlement) }
}

/// The store sync commits through: the lock model's `PublishingItemStore` (so AutoFill identities
/// republish), with every commit passed as `fromSync: true` so it never counts as a local edit. Every Mac sync
/// path commits here (Wi-Fi client and cloud folder through the coordinator, the Wi-Fi host through `LanHost`),
/// so an item another device deleted is copied to Recently deleted (`local`) before it leaves the vault.
final class SyncSourceStore: ItemStore, @unchecked Sendable {
    let base: PublishingItemStore
    /// Recently deleted (the lock model); required, so no sync path can skip it.
    let local: any LocalDataHosting
    init(base: PublishingItemStore, local: any LocalDataHosting) { self.base = base; self.local = local }
    func load() throws -> StoreSnapshot { try base.load() }
    func commit(_ change: StoreChange) throws {
        let before = try base.load()
        try RemoteDeletes.commit(change, before: before, local: local, now: Int64(Date().timeIntervalSince1970)) {
            try base.commit($0, fromSync: true)
        }
    }
}
