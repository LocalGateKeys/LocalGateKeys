import Foundation
import UIKit
import AppShared
@testable import LocalGateKeys

final class TestClock: UnixClock, @unchecked Sendable {
    var now: Int64
    init(_ now: Int64) { self.now = now }
}

/// Fires timers only when the test advances time: no real waiting.
@MainActor
final class ManualScheduler: LockScheduler {
    final class Timer: LockTimer {
        let due: Int64; let action: @MainActor () -> Void; var cancelled = false
        init(due: Int64, action: @escaping @MainActor () -> Void) { self.due = due; self.action = action }
        func cancel() { cancelled = true }
    }
    let clock: TestClock
    private(set) var timers: [Timer] = []
    init(clock: TestClock) { self.clock = clock }

    func schedule(after seconds: Int64, _ action: @escaping @MainActor () -> Void) -> any LockTimer {
        let t = Timer(due: clock.now + seconds, action: action); timers.append(t); return t
    }

    func advance(by seconds: Int64) {
        let target = clock.now + seconds
        while let next = timers.filter({ !$0.cancelled && $0.due <= target }).min(by: { $0.due < $1.due }) {
            clock.now = next.due; next.cancelled = true; next.action()
        }
        clock.now = target
    }

    var pending: Int { timers.filter { !$0.cancelled }.count }
}

final class MemoryStore: ItemStore, @unchecked Sendable {
    var snapshot: StoreSnapshot
    private(set) var commits = 0
    init(_ snapshot: StoreSnapshot = StoreSnapshot()) { self.snapshot = snapshot }
    func load() throws -> StoreSnapshot { snapshot }
    /// Applies the change like LocalStore (stale base refused), so editor tests see what was written.
    func commit(_ change: StoreChange) throws {
        guard change.baseRevision == snapshot.revision else {
            throw LocalStoreError.stale(expected: change.baseRevision, actual: snapshot.revision)
        }
        snapshot = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: snapshot.revision + 1)
        commits += 1
    }
}

/// Deterministic bytes: a counter stream, so generator output is reproducible in tests.
final class CountingRandom: RandomSource, @unchecked Sendable {
    private var next: UInt8
    private let lock = NSLock()
    init(start: UInt8 = 0) { next = start }
    func bytes(count: Int) -> [UInt8] {
        lock.withLock { (0..<count).map { _ in defer { next &+= 37 }; return next } }
    }
}

@MainActor
final class FakePurchases: ProPurchasing {
    var entitled = false
    var purchaseResult: PurchaseOutcome = .purchased
    var restoreFinds = false
    var offerResult: ProOffer = .available(price: "$4.99")
    var purchaseError: (any Error)?
    var restoreError: (any Error)?
    var purchaseCalls = 0, restoreCalls = 0, priceCalls = 0
    /// Runs while the entitlement read is "in flight" (a slow StoreKit answer).
    var duringIsEntitled: (@MainActor () -> Void)?
    func isEntitled() async -> Bool {
        if let duringIsEntitled { await Task.yield(); duringIsEntitled() }
        return entitled
    }
    func offer() async -> ProOffer { priceCalls += 1; return offerResult }
    func purchase() async throws -> PurchaseOutcome {
        purchaseCalls += 1
        if let purchaseError { throw purchaseError }
        if purchaseResult == .purchased { entitled = true }
        return purchaseResult
    }
    func restore() async throws -> Bool {
        restoreCalls += 1
        if let restoreError { throw restoreError }
        if restoreFinds { entitled = true }
        return entitled
    }
    func entitlementChanges() -> AsyncStream<Void> { AsyncStream { $0.finish() } }
}

@MainActor
final class FakeUnlocker: Unlocking {
    var succeed = true
    /// Thrown instead of `Denied` when `succeed` is false.
    var error: (any Error)?
    /// Runs while the unlock is "in flight" (after the Face ID prompt, before it returns).
    var duringUnlock: (@MainActor () -> Void)?
    var unlockCalls = 0, lockCalls = 0
    let store = MemoryStore()
    var keychain: (any KeychainVault)? = InMemoryKeychainVault()
    struct Denied: Error {}
    func unlock(reason: String) async throws -> any ItemStore {
        unlockCalls += 1
        await Task.yield()
        duringUnlock?()
        if !succeed { throw error ?? Denied() }
        return store
    }
    func lock() { lockCalls += 1 }
}

@MainActor
final class FakePasteboard: PasteboardWriting {
    var items: [[String: Any]] = []
    var options: [UIPasteboard.OptionsKey: Any] = [:]
    var changeCount = 0
    /// Every write, oldest first.
    var history: [[[String: Any]]] = []
    func setItems(_ items: [[String: Any]], options: [UIPasteboard.OptionsKey: Any]) {
        self.items = items; self.options = options; changeCount += 1; history.append(items)
    }
}

/// Records background-task `begin`/`end` so tests can check they are paired.
@MainActor
final class FakeBackgroundTasks: BackgroundTasking {
    private(set) var begun: [String] = []
    private(set) var ended: [Int] = []
    private(set) var open: Set<Int> = []
    private(set) var expirations: [Int: @MainActor () -> Void] = [:]
    private var next = 1
    func begin(_ name: String, expiration: @escaping @MainActor () -> Void) -> Int {
        let t = next; next += 1
        begun.append(name); open.insert(t); expirations[t] = expiration
        return t
    }
    func end(_ token: Int) { ended.append(token); open.remove(token) }
    /// Simulates iOS expiring every open task.
    func expireAll() { for t in open.sorted() { expirations[t]?() } }
}
