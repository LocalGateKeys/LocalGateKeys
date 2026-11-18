import Foundation
import LGKCore
import AppSharedMac

// The Mac-only part of the shared Wi-Fi host (App/Sync/LanListener.swift): building it over the lock model.

extension LanHost {
    /// A host over the unlocked vault's publishing store, stopped by every lock; nil while locked.
    static func make(lock: MacLockModel, deps: SyncDependencies, counters: HelloCounterSource) -> LanHost? {
        guard lock.state == .unlocked, let store = lock.store as? PublishingItemStore else { return nil }
        let host = LanHost(store: SyncSourceStore(base: store, local: lock), deps: deps, counters: counters,
                           isUnlocked: { [weak lock] in lock?.state == .unlocked })
        lock.onLock.append { [weak host] in host?.shutdown() }
        return host
    }
}
