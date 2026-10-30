import XCTest
import LGKCore
@testable import AppSharedMac

/// Phase 4 Task 1: the sync client compiled for the Mac, its Keychain slots and its store.
@MainActor
final class MacSyncWiringTests: XCTestCase {
    private var dir: URL!
    private var suite: String!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-syncwire-\(UUID().uuidString)", isDirectory: true)
        suite = "lgk-syncwire-\(UUID().uuidString)"
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        UserDefaults().removePersistentDomain(forName: suite)
    }

    func testSyncSlotsInAppOnlyGroup() throws {
        let sync: Set<VaultSlot> = [.pairedPeer, .installID, .folderBookmark, .helloCounter, .peerCounters]
        let backups: Set<VaultSlot> = [.scheduledBackupFolder, .scheduledBackupMirror, .manualBackupFolder]
        XCTAssertEqual(VaultSlot.appOnly, sync.union(backups))
        XCTAssertTrue(VaultSlot.appOnly.isDisjoint(with: VaultSlot.deviceUnlocked))
        XCTAssertFalse(VaultSlot.appOnly.contains(.localKey))

        let shared = InMemoryKeychainVault(), appOnly = InMemoryKeychainVault()
        // An earlier build's counter in the shared group moves to the app-only group.
        try shared.writeInt64(.helloCounter, 7)
        var probed: String?
        let vault = try XCTUnwrap(MacSyncEnvironment.makeSyncKeychain(plan: .appOnly("TEAM.app.localgatekeys.app-only"),
                                                                      shared: shared, appOnly: { probed = $0; return appOnly }))
        XCTAssertEqual(probed, "TEAM.app.localgatekeys.app-only")
        XCTAssertNil(try shared.read(.helloCounter))
        XCTAssertEqual(try appOnly.readInt64(.helloCounter), 7)
        for slot in sync {
            try vault.write(slot, [1, 2, 3])
            XCTAssertEqual(try appOnly.read(slot), [1, 2, 3], "\(slot)")
            XCTAssertNil(try shared.read(slot), "\(slot)")
        }
        try vault.write(.safariIndexKey, [9])
        XCTAssertEqual(try shared.read(.safariIndexKey), [9])
        XCTAssertNil(try appOnly.read(.safariIndexKey))
    }

    func testReleaseWithoutAppOnlyGroupKeepsSyncOff() async throws {
        XCTAssertEqual(MacSyncEnvironment.keychainPlan(appOnlyGroup: "TEAM.g", release: true), .appOnly("TEAM.g"))
        XCTAssertEqual(MacSyncEnvironment.keychainPlan(appOnlyGroup: "TEAM.g", release: false), .appOnly("TEAM.g"))
        XCTAssertEqual(MacSyncEnvironment.keychainPlan(appOnlyGroup: nil, release: true), .unavailable)
        XCTAssertEqual(MacSyncEnvironment.keychainPlan(appOnlyGroup: nil, release: false), .sharedFallback)
        let shared = InMemoryKeychainVault()
        XCTAssertNil(MacSyncEnvironment.makeSyncKeychain(plan: .unavailable, shared: shared, appOnly: { _ in XCTFail(); return shared }))
        XCTAssertTrue(MacSyncEnvironment.makeSyncKeychain(plan: .sharedFallback, shared: shared, appOnly: { _ in XCTFail(); return shared }) === shared)

        // The coordinator then refuses everything and shows the one issue.
        let lock = try await unlockedLock()
        let coordinator = try XCTUnwrap(MacSyncEnvironment.makeCoordinator(lock: lock, keychain: nil, hostName: "Mac"))
        XCTAssertEqual(coordinator.issues.map(\.text), ["Sync isn't available in this build."])
        let joined = await coordinator.joinByQR("lgk-pair:x")
        XCTAssertFalse(joined)
        XCTAssertEqual(coordinator.actionError, "Sync isn't available in this build.")
        await coordinator.sync()
        XCTAssertEqual(coordinator.completedRuns, 0)
        coordinator.shutdown()
    }

    func testCounterCopiesKeepLargerValues() throws {
        let shared = InMemoryKeychainVault(), appOnly = InMemoryKeychainVault()
        let vault = AppKeychainVault(shared: shared, appOnly: appOnly)
        try appOnly.writeInt64(.helloCounter, 5)
        try shared.writeInt64(.helloCounter, 9)
        XCTAssertEqual(try vault.readInt64(.helloCounter), 9)
        XCTAssertEqual(try appOnly.readInt64(.helloCounter), 9)
        XCTAssertNil(try shared.read(.helloCounter))
        try appOnly.writeInt64(.helloCounter, 12)
        try shared.writeInt64(.helloCounter, 3)
        XCTAssertEqual(try vault.readInt64(.helloCounter), 12)
        XCTAssertNil(try shared.read(.helloCounter))

        let enc = { (o: [String: Int64]) in try CanonicalJSON.encode(.object(o.mapValues { .int($0) }), dialect: .utf8) }
        try appOnly.write(.peerCounters, enc(["a": 4, "b": 10]))
        try shared.write(.peerCounters, enc(["a": 7, "b": 2, "c": 1]))
        XCTAssertEqual(try vault.read(.peerCounters), try enc(["a": 7, "b": 10, "c": 1]))
        XCTAssertEqual(try appOnly.read(.peerCounters), try enc(["a": 7, "b": 10, "c": 1]))
        XCTAssertNil(try shared.read(.peerCounters))
        let store = VaultCounterStore(vault: vault)
        XCTAssertEqual(try store.lastAcceptedCounter(peer: "a"), 7)
    }

    private func unlockedLock() async throws -> MacLockModel {
        let settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(),
                             kdfParams: MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1))
        let lock = MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), startTimer: false)
        await lock.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertEqual(lock.state, .unlocked)
        return lock
    }

    func testSlotsWrittenWithoutUserPresenceOnMac() {
        for slot in [VaultSlot.pairedPeer, .installID, .folderBookmark, .helloCounter, .peerCounters] {
            XCTAssertEqual(slot.accessFlags, [], "\(slot)")
        }
        XCTAssertEqual(VaultSlot.safariIndexKey.accessFlags, [])
        XCTAssertEqual(VaultSlot.safariInboxKey.accessFlags, [])
        XCTAssertEqual(VaultSlot.localKey.accessFlags, .userPresence)
    }

    func testBookmarkUsesSecurityScope() throws {
        XCTAssertTrue(SecurityScopedFolderOpener.createOptions.contains(.withSecurityScope))
        XCTAssertTrue(SecurityScopedFolderOpener.resolveOptions.contains(.withSecurityScope))
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let opener = SecurityScopedFolderOpener()
        let bookmark = try opener.bookmark(for: dir)
        let (folder, _) = try opener.open(bookmark: bookmark)
        XCTAssertEqual((folder as? CoordinatedFolder)?.root.resolvingSymlinksInPath().path, dir.resolvingSymlinksInPath().path)
    }

    func testCoordinatorUsesPublishingStore() async throws {
        let settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(),
                             kdfParams: MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1))
        let lock = MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), startTimer: false)
        XCTAssertNil(MacSyncEnvironment.makeCoordinator(lock: lock, keychain: InMemoryKeychainVault()))
        await lock.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertEqual(lock.state, .unlocked)

        let coordinator = try XCTUnwrap(MacSyncEnvironment.makeCoordinator(lock: lock, keychain: InMemoryKeychainVault(),
                                                                           hostName: "Ilias's MacBook Pro"))
        let gated = try XCTUnwrap(coordinator.store as? GatedStore)
        // Sync commits through the publishing store, marked as sync's own (never counted as local edits).
        let source = try XCTUnwrap(gated.base as? SyncSourceStore)
        XCTAssertTrue(source.base is PublishingItemStore)
        XCTAssertTrue((source.base as AnyObject) === (lock.store as AnyObject))
        // Remote deletes (Wi-Fi client and cloud folder) are copied to this lock model's Recently deleted.
        XCTAssertTrue((source.local as AnyObject?) === lock)
        XCTAssertEqual(coordinator.deps.editDebounceNanos, 10_000_000_000)
        XCTAssertTrue(coordinator.deps.autoFill is NoAutoFillRefresh)
        XCTAssertEqual(coordinator.deps.deviceName, "Ilias's MacBook Pro")
        coordinator.shutdown()
    }

    func testDeviceNameLimits() {
        XCTAssertEqual(MacSyncEnvironment.deviceName(hostName: nil), "Mac")
        XCTAssertEqual(MacSyncEnvironment.deviceName(hostName: "  \n"), "Mac")
        let long = MacSyncEnvironment.deviceName(hostName: String(repeating: "é", count: 60))
        XCTAssertLessThanOrEqual(long.unicodeScalars.count, 40)
        XCTAssertLessThanOrEqual(long.utf8.count, 64)
    }

    func testWordingSaysThisMac() {
        XCTAssertEqual(SyncWording.thisDevice, "Mac")
        XCTAssertEqual(SyncWording.onPhone("Sync is not set up on this PC."), "Sync is not set up on this Mac.")
        XCTAssertEqual(SyncWording.onPhone("This vault was set up for sync on another PC."), "This vault was set up for sync on another device.")
        let e = EnrollConnectError(failure: .unreachable, endpoint: try! LanEndpoint(validating: "192.168.1.20", port: 47821))
        XCTAssertTrue(SyncWording.enrollFailureText(e).contains("from this Mac"))
    }
}
