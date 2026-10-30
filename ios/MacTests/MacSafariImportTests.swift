import XCTest
import LGKCore
@testable import AppSharedMac

@MainActor
private final class FreeSafariPurchases: ProPurchasing {
    func isEntitled() async -> Bool { false }
    func offer() async -> ProOffer { .unavailable }
    func purchase() async throws -> PurchaseOutcome { .cancelled }
    func restore() async throws -> Bool { false }
    func entitlementChanges() -> AsyncStream<Void> { AsyncStream { $0.finish() } }
}

private struct FixedUnixClock: UnixClock { let now: Int64 }

/// Counts the commits that reach the unlocked store (the app's `PublishingItemStore`).
private final class CountingStore: ItemStore, @unchecked Sendable {
    let base: any ItemStore
    private(set) var commits = 0
    init(_ base: any ItemStore) { self.base = base }
    func load() throws -> StoreSnapshot { try base.load() }
    func commit(_ change: StoreChange) throws { try base.commit(change); commits += 1 }
}

/// Records the index publishes the unlocked vault's commits make.
private final class IndexLog: SafariIndexPublishing, @unchecked Sendable {
    private(set) var publishes = 0
    func publish(_ snapshot: StoreSnapshot) { publishes += 1 }
}

/// The Safari inbox on the Mac: reviewed after each unlock, imported in one commit after a yes, the free plan
/// respected, the review sheet in the iPhone's words.
@MainActor
final class MacSafariImportTests: XCTestCase {
    private var dir: URL!
    private var safariRoot: URL!
    private var suite: String!
    private var settings: AppSettings!
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
    private let now: Int64 = 1_800_000_000

    override func setUp() async throws {
        let tmp = FileManager.default.temporaryDirectory
        dir = tmp.appendingPathComponent("lgk-mac-safari-\(UUID().uuidString)", isDirectory: true)
        safariRoot = tmp.appendingPathComponent("lgk-mac-safari-inbox-\(UUID().uuidString)", isDirectory: true)
        suite = "lgk-mac-safari-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        try? FileManager.default.removeItem(at: safariRoot)
        UserDefaults().removePersistentDomain(forName: suite)
    }

    private func importer(_ keychain: any KeychainVault) -> MacSafariImport {
        MacSafariImport(keychain: keychain, clock: FixedUnixClock(now: now), directory: { [safariRoot] in safariRoot! })
    }

    /// What the Safari extension does on Save: seals the login into the inbox under the inbox key.
    private func saveInSafari(_ keychain: any KeychainVault, _ origin: String, _ username: String, _ password: String) throws {
        let key = try XCTUnwrap(try keychain.read(.safariInboxKey))
        let inbox = SafariInbox(directory: safariRoot.appendingPathComponent(SafariInbox.directoryName, isDirectory: true),
                                key: key, now: { [now] in now })
        try inbox.add(origin: origin, username: username, password: password)
    }

    private func waitingCount(_ keychain: any KeychainVault) throws -> Int {
        let key = try XCTUnwrap(try keychain.read(.safariInboxKey))
        return SafariInbox(directory: safariRoot.appendingPathComponent(SafariInbox.directoryName, isDirectory: true),
                           key: key, now: { [now] in now }).entries().entries.count
    }

    func testInboxImportedAtUnlock() async throws {
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(), kdfParams: cheap)
        let lock = MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), startTimer: false)
        let index = IndexLog()
        lock.safariIndex = index
        let safariKeys = InMemoryKeychainVault()
        let safari = importer(safariKeys)
        lock.onLock.append { safari.locked() }
        let pro = ProModel(purchases: FreeSafariPurchases())

        // First unlock: the keys the extension needs are created; nothing waits.
        await lock.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertEqual(lock.state, .unlocked)
        await safari.afterUnlock(store: try XCTUnwrap(lock.store), pro: pro, isUnlocked: { lock.state == .unlocked })
        XCTAssertEqual(try safariKeys.read(.safariIndexKey)?.count, SafariKeys.length)
        XCTAssertEqual(try safariKeys.read(.safariInboxKey)?.count, SafariKeys.length)
        XCTAssertEqual(safari.pending, [])

        // Saved in Safari while locked; the next unlock lists them for the sheet and imports nothing yet.
        lock.lock()
        try saveInSafari(safariKeys, "https://accounts.example.com", "ada@example.com", "Pass-1")
        try saveInSafari(safariKeys, "https://b.example.com", "bo", "Pass-2")
        await lock.unlock(password: "correct horse")
        XCTAssertEqual(lock.state, .unlocked)
        let store = CountingStore(try XCTUnwrap(lock.store))
        await safari.afterUnlock(store: store, pro: pro, isUnlocked: { lock.state == .unlocked })
        XCTAssertEqual(safari.pending.map(\.username).sorted(), ["ada@example.com", "bo"])
        XCTAssertEqual(store.commits, 0, "nothing is imported before the yes")

        let publishesBefore = index.publishes
        var needsPro: [ProReason] = []
        let result = safari.confirm(Set(safari.pending.map(\.id)), store: store, isPro: pro.isPro,
                                    activity: lock.activity, onNeedsPro: { needsPro.append($0) })
        XCTAssertEqual(result, SafariImportResult(saved: 2, waiting: 0, damaged: 0))
        XCTAssertEqual(store.commits, 1, "one commit: AutoFill identities republish once")
        XCTAssertEqual(index.publishes, publishesBefore + 1, "the Safari index follows the commit")
        XCTAssertEqual(needsPro, [])
        XCTAssertEqual(safari.notice, "2 logins saved from Safari")
        XCTAssertEqual(try waitingCount(safariKeys), 0)
        XCTAssertEqual(safari.pending, [])

        let logins = VaultItem.items(from: try store.load()).filter { $0.kind == "web" }
        XCTAssertEqual(Set(logins.compactMap { $0.record["username"]?.stringValue }), ["ada@example.com", "bo"])
        // Content-free activity: one item.create per login, with its id only.
        let creates = (lock.localData?.events ?? []).filter { $0.eventType == "item.create" }
        XCTAssertEqual(Set(creates.compactMap(\.itemID)), Set(logins.map { $0.id.lowercased() }))

        // Locking clears the review; nothing is asked again for imported logins.
        lock.lock()
        XCTAssertNil(safari.notice)
    }

    func testReviewSheetCopyMatchesIPhone() {
        XCTAssertEqual(SafariReviewCopy.title, "Save from Safari?")
        XCTAssertEqual(SafariReviewCopy.footer, "Saved from Safari since you last opened LocalGateKeys. Only the logins you keep selected are saved; the others are deleted.")
        XCTAssertEqual(SafariReviewCopy.later, "Decide later")
        XCTAssertEqual(SafariReviewCopy.save(0), "Delete all")
        XCTAssertEqual(SafariReviewCopy.save(3), "Save 3")
        let new = SafariPendingSave(id: "a", origin: "https://accounts.example.com", username: "ada", change: .new, capturedAt: now)
        let update = SafariPendingSave(id: "b", origin: "https://accounts.example.com", username: "ada", change: .update, capturedAt: now)
        XCTAssertEqual(SafariReviewCopy.detail(new), "New login \u{00B7} https://accounts.example.com")
        XCTAssertEqual(SafariReviewCopy.detail(update), "Updates the saved password \u{00B7} https://accounts.example.com")
        XCTAssertEqual(SafariImportResult(saved: 1, waiting: 2, damaged: 0).notice, "1 login saved from Safari · 2 waiting: upgrade to Pro to import")
    }

    func testFreeLimitRespected() async throws {
        let storeDir = dir.appendingPathComponent("vault", isDirectory: true)
        let base = try LocalStore.bootstrap(directory: storeDir, vault: InMemoryKeychainVault())
        base.limitHints = nil
        try DemoData.seed(into: base, now: now)
        XCTAssertGreaterThanOrEqual(try base.load().records.count, ItemLimit.freeItems)
        let store = CountingStore(base)
        let safariKeys = InMemoryKeychainVault()
        try SafariKeys.ensure(keychain: safariKeys)
        try saveInSafari(safariKeys, "https://new-one.example.com", "ada", "Pass-1")
        try saveInSafari(safariKeys, "https://new-two.example.com", "bo", "Pass-2")
        let safari = importer(safariKeys)
        await safari.afterUnlock(store: store, pro: ProModel(purchases: FreeSafariPurchases()), isUnlocked: { true })
        XCTAssertEqual(safari.pending.count, 2)
        let before = try store.load().records.count

        var needsPro: [ProReason] = []
        let result = safari.confirm(Set(safari.pending.map(\.id)), store: store, isPro: false, activity: nil,
                                    onNeedsPro: { needsPro.append($0) })

        XCTAssertEqual(result, SafariImportResult(saved: 0, waiting: 2, damaged: 0))
        XCTAssertEqual(needsPro, [.itemLimit], "the Pro sheet opens")
        XCTAssertEqual(store.commits, 0)
        XCTAssertEqual(try store.load().records.count, before)
        XCTAssertEqual(try waitingCount(safariKeys), 2, "they wait in the inbox for Pro")
        XCTAssertEqual(safari.notice, "2 waiting: upgrade to Pro to import")
    }
}
