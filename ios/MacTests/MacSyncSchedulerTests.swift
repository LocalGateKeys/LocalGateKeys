import XCTest
import LGKCore
@testable import AppSharedMac

/// Records exchanges; while `gated`, an exchange waits for `release()` (a run held mid-flight).
private final class HeldLan: LanTransporting, @unchecked Sendable {
    private let lock = NSLock()
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var count = 0
    var gated = false
    var answer: @Sendable () throws -> [ItemState] = { [] }
    var exchanges: Int { lock.withLock { count } }
    var waiting: Int { lock.withLock { waiters.count } }

    func exchangeViews(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                       ownCounter: Int64) async throws -> [ItemState] {
        let hold = lock.withLock { count += 1; return gated }
        if hold { await withCheckedContinuation { c in lock.withLock { waiters.append(c) } } }
        return try answer()
    }

    func enroll(endpoint: LanEndpoint, request: [UInt8], onConnected: @escaping @Sendable () -> Void) async throws -> [UInt8] {
        throw LanSocketError("refused")
    }

    func release() { let w = lock.withLock { defer { waiters = []; gated = false }; return waiters }; w.forEach { $0.resume() } }
}

private final class FakeNow: @unchecked Sendable {
    var date = Date(timeIntervalSince1970: 1_800_000_000)
    func advance(_ s: TimeInterval) { date += s }
}

private func note(_ i: Int) -> (String, JSONValue) {
    let id = String(format: "00000000-0000-4000-8000-%012d", i)
    let r: JSONValue = .object(["id": .string(id), "kind": .string("note"), "title": .string("Note \(i)"),
                                "created_at": .int(1_700_000_000), "updated_at": .int(1_700_000_000 + Int64(i)),
                                "favorite": .bool(false), "tags": .array([]),
                                "payload": .object(["body": .string("body \(i)"), "fields": .array([]), "template_id": .null])])
    return (id, Wrapper.make(ns: .item, record: try! Normalise.normalForm(ns: .item, record: r)))
}

@MainActor
final class MacSyncSchedulerTests: XCTestCase {
    private var dir: URL!
    private var suite: String!
    private var settings: AppSettings!
    private var keychain: InMemoryKeychainVault!
    private var lan: HeldLan!
    private let clock = FakeNow()

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-sched-\(UUID().uuidString)", isDirectory: true)
        suite = "lgk-sched-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        keychain = InMemoryKeychainVault()
        lan = HeldLan()
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        UserDefaults().removePersistentDomain(forName: suite)
    }

    private func lockModel() -> MacLockModel {
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(),
                             kdfParams: MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1))
        return MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), startTimer: false)
    }

    /// A coordinator like `MacSyncEnvironment.makeCoordinator` (sync-marked publishing store) over fakes.
    private func coordinator(_ lock: MacLockModel) -> SyncCoordinator? {
        guard lock.state == .unlocked, let store = lock.store as? PublishingItemStore else { return nil }
        var deps = SyncDependencies(keychain: keychain, folders: SecurityScopedFolderOpener(), lan: lan,
                                    autoFill: NoAutoFillRefresh(), random: SystemRandomSource(), clock: SystemClock(),
                                    licenseKeys: [:])
        deps.editDebounceNanos = MacSyncScheduler.editDelayNanos
        return SyncCoordinator(store: SyncSourceStore(base: store, local: lock), deps: deps)
    }

    private func scheduler(_ lock: MacLockModel) -> MacSyncScheduler {
        MacSyncScheduler(lock: lock, settings: settings, now: { [clock] in clock.date },
                         makeCoordinator: { [unowned self] in self.coordinator($0) },
                         makeHost: { _, _ in nil }, addresses: { [] }, startTimer: false)
    }

    private func unlock(_ lock: MacLockModel) async {
        if lock.state == .noVault {
            await lock.create(password: "correct horse", confirm: "correct horse", touchID: false)
        } else {
            await lock.unlock(password: "correct horse")
        }
        XCTAssertEqual(lock.state, .unlocked)
    }

    /// Joins the open vault to a Wi-Fi group paired with a PC at 192.168.1.30 (so a run dials `lan`).
    private func joinPairedGroup(_ lock: MacLockModel) throws {
        let store = try XCTUnwrap(lock.store)
        let installID = try keychain.installID(random: SystemRandomSource())
        let group = try SyncGroup.createWiFi(installID: installID, random: SystemRandomSource())
        let peer = try DeviceIdentity.generate(random: SystemRandomSource())
        try keychain.setPairedPeer(PinnedPeer(deviceID: peer.deviceID, groupID: group.groupID,
                                              signingPublic: peer.signingPublicKey, exchangePublic: peer.exchangePublicKey,
                                              endpoint: try LanEndpoint(validating: "192.168.1.30", port: 47821)))
        let snap = try store.load()
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: group))
    }

    private func localEdit(_ lock: MacLockModel, _ i: Int) throws {
        let store = try XCTUnwrap(lock.store)
        let snap = try store.load()
        var records = snap.records
        let (id, w) = note(i)
        records[id] = w
        try store.commit(StoreChange(baseRevision: snap.revision, records: records, meta: snap.meta, sync: snap.sync))
    }

    // MARK: tests

    func testSyncOnUnlockEveryFiveMinutesAndAfterEdit() async throws {
        let lock = lockModel()
        let s = scheduler(lock)
        await unlock(lock)
        await s.settled()
        XCTAssertEqual(s.triggers, [.unlock])
        XCTAssertEqual(s.syncRevision, 1)
        try joinPairedGroup(lock)   // a local commit: counts as an edit
        clock.advance(9); s.tick(); await s.settled()
        XCTAssertEqual(s.triggers, [.unlock], "not before 10 s")
        clock.advance(1); s.tick(); await s.settled()
        XCTAssertEqual(s.triggers, [.unlock, .localEdit])
        XCTAssertEqual(lan.exchanges, 1)

        // Edits keep pushing the run back: 10 s after the last one.
        try localEdit(lock, 1)
        clock.advance(6); try localEdit(lock, 2)
        clock.advance(6); s.tick(); await s.settled()
        XCTAssertEqual(s.triggers.count, 2)
        clock.advance(4); s.tick(); await s.settled()
        XCTAssertEqual(s.triggers, [.unlock, .localEdit, .localEdit])

        // Commits made by sync are not edits: no run follows them.
        let source = SyncSourceStore(base: try XCTUnwrap(lock.store as? PublishingItemStore), local: lock)
        let snap = try source.load()
        var records = snap.records; let (id, w) = note(3); records[id] = w
        try source.commit(StoreChange(baseRevision: snap.revision, records: records, meta: snap.meta, sync: snap.sync))
        clock.advance(11); s.tick(); await s.settled()
        XCTAssertEqual(s.triggers.count, 3)

        // Every 5 minutes after the last run.
        clock.advance(300 - 11 - 1); s.tick(); await s.settled()
        XCTAssertEqual(s.triggers.count, 3)
        clock.advance(1); s.tick(); await s.settled()
        XCTAssertEqual(s.triggers.last, .interval)
        clock.advance(300); s.tick(); await s.settled()
        XCTAssertEqual(s.triggers, [.unlock, .localEdit, .localEdit, .interval, .interval])
        XCTAssertEqual(s.syncRevision, 5 + 1, "five runs and one sync commit outside a run")
        lock.lock()
    }

    func testNothingAfterLock() async throws {
        let lock = lockModel()
        let s = scheduler(lock)
        await unlock(lock)
        await s.settled()
        try joinPairedGroup(lock)
        let coordinator = try XCTUnwrap(s.coordinator)
        lock.lock()
        XCTAssertNil(s.coordinator)
        XCTAssertFalse(coordinator.gate.isOpen, "the coordinator is shut down")
        let runs = s.triggers.count, exchanges = lan.exchanges
        clock.advance(3600); s.tick(); s.syncNow(); await s.settled()
        await coordinator.sync()
        XCTAssertEqual(s.triggers.count, runs)
        XCTAssertEqual(lan.exchanges, exchanges)

        // The next unlock gets a new coordinator and syncs again.
        await unlock(lock)
        await s.settled()
        XCTAssertNotNil(s.coordinator)
        XCTAssertFalse(s.coordinator === coordinator)
        XCTAssertEqual(s.triggers.last, .unlock)
        XCTAssertEqual(lan.exchanges, exchanges + 1)
        lock.lock()
    }

    func testLockMidRunCommitsNothing() async throws {
        let lock = lockModel()
        let s = scheduler(lock)
        await unlock(lock)
        await s.settled()
        try joinPairedGroup(lock)
        // The peer answers with an item this Mac doesn't have: the run would commit it.
        let (id, w) = note(42)
        let peerDevice = try XCTUnwrap(try keychain.pairedPeer()).deviceID
        lan.answer = { try SyncMeta.localView(records: [id: w], meta: [:], device: peerDevice, now: 1_800_000_000)
            .states.values.sorted { $0.itemID < $1.itemID } }
        var commits = 0
        lock.onCommit.append { _ in commits += 1 }
        lan.gated = true
        let revision = s.syncRevision
        s.syncNow()
        while lan.waiting == 0 { await Task.yield() }
        lock.lock()   // the vault locks mid-run
        lan.release()
        await s.settled()
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(commits, 0)
        XCTAssertEqual(s.syncRevision, revision, "a run cut short by the lock reloads nothing")

        lan.answer = { [] }   // the peer has nothing new now
        await unlock(lock)
        await s.settled()
        XCTAssertNil(try XCTUnwrap(lock.store).load().records[id], "nothing from the held run was kept")
        lock.lock()
    }

    func testPruneAndProUpdateAfterRun() async throws {
        let lock = lockModel()
        let s = scheduler(lock)
        await unlock(lock)
        await s.settled()
        let store = try XCTUnwrap(lock.store)
        try localEdit(lock, 1); try localEdit(lock, 2)
        let (keep, _) = note(1), (gone, _) = note(2)
        var data = try XCTUnwrap(lock.localData)
        data.ensureStarterCollections(now: 1_800_000_000)
        let collection = try XCTUnwrap(data.collections.first).id
        data.reminders = [keep, gone].map { LocalData.Reminder(id: UUID().uuidString.lowercased(), itemID: $0, dueDate: "2030-01-01") }
        data.memberships = [keep: [collection], gone: [collection]]
        try lock.commitLocalData(data)

        // A peer's merge (a sync commit) deletes item 2.
        let source = SyncSourceStore(base: try XCTUnwrap(store as? PublishingItemStore), local: lock)
        let snap = try source.load()
        var records = snap.records; records.removeValue(forKey: gone)
        try source.commit(StoreChange(baseRevision: snap.revision, records: records, meta: snap.meta, sync: snap.sync))
        let before = s.syncRevision
        clock.advance(300); s.tick(); await s.settled()
        XCTAssertGreaterThan(s.syncRevision, before, "the run completed")

        let list = VaultListModel(store: store)
        let reminders = RemindersModel(local: lock, notifier: nil, activity: nil)
        let collections = CollectionsModel(local: lock, activity: nil)
        var proSnapshots: [StoreSnapshot] = []
        MainWindow.afterSync(store: store, list: list, reminders: reminders, collections: collections,
                             updatePro: { proSnapshots.append($0) })
        XCTAssertEqual(list.items.map(\.id), [keep])
        XCTAssertEqual(lock.localData?.reminders.map(\.itemID), [keep])
        // The synced delete moved item 2 to Recently deleted, so (as for a local delete) its collection
        // membership is kept for a restore; only items gone from both are pruned.
        XCTAssertEqual(lock.localData?.trash.count, 1)
        XCTAssertEqual(lock.localData?.memberships, [keep: [collection], gone: [collection]])
        XCTAssertEqual(proSnapshots.map(\.revision), [try store.load().revision], "Pro is re-read from the synced store")
        lock.lock()
    }

    func testSharesOneHelloCounterSourceAndStopsWhenTheAddressGoes() async throws {
        let lock = lockModel()
        await unlock(lock)
        let live = try XCTUnwrap(MacSyncEnvironment.makeCoordinator(lock: lock, keychain: InMemoryKeychainVault(), hostName: "Mac"))
        let host = try XCTUnwrap(MacSyncScheduler.liveHost(lock: lock, coordinator: live))
        XCTAssertTrue(host.counters === MacSyncEnvironment.helloCounters(live.deps), "one counter source, never two")
        XCTAssertTrue(host.store.base is SyncSourceStore)
        live.shutdown(); host.shutdown()

        // Listening address saved; when it leaves this Mac the host stops with the Task 5 message, and
        // starts again when it comes back.
        var current = [LanInterfaceAddress(interface: "en0", address: "127.0.0.1")]
        var made: LanHost?
        settings.wifiSyncOn = true
        let port = Int.random(in: 40_000...60_000)
        settings.wifiSyncEndpoint = "127.0.0.1:\(port)"
        let s = MacSyncScheduler(lock: lock, settings: settings, now: { [clock] in clock.date },
                                 makeCoordinator: { [unowned self] in self.coordinator($0) },
                                 makeHost: { lock, c in
                                     let h = LanHost.make(lock: lock, deps: c.deps, counters: HelloCounterSource(
                                         store: VaultCounterStore(vault: InMemoryKeychainVault()), clock: SystemClock()))
                                     h?.allowsLoopbackForTests = true
                                     made = h
                                     return h
                                 },
                                 addresses: { current }, startTimer: false)
        s.allowsLoopbackForTests = true
        lock.lock(); await unlock(lock)   // the unlock starts the host on the saved endpoint
        await s.hostSettled()
        await s.settled()
        let host2 = try XCTUnwrap(made)
        XCTAssertTrue(host2.isListening, host2.listenError ?? "")
        XCTAssertEqual(host2.endpoint?.port, port)
        current = []
        s.tick()
        XCTAssertFalse(host2.isListening)
        XCTAssertEqual(host2.listenError, LanHost.stoppedText)
        current = [LanInterfaceAddress(interface: "en0", address: "127.0.0.1")]
        s.tick(); await s.hostSettled()
        XCTAssertTrue(host2.isListening, host2.listenError ?? "")

        // A run while listening collects the host's issues (not joined here); turning Wi-Fi off clears them.
        s.syncNow(); await s.settled()
        XCTAssertEqual(s.hostIssues, [SyncIssue("not-joined")])
        s.setWiFi(false)
        XCTAssertEqual(s.hostIssues, [])
        XCTAssertFalse(host2.isListening)
        s.setWiFi(true); await s.hostSettled()
        XCTAssertTrue(host2.isListening, host2.listenError ?? "")

        let snap = try host2.store.load()
        lock.lock()
        XCTAssertFalse(host2.isListening, "locking stops the listener")
        XCTAssertNil(host2.server, "every connection was cancelled with the listener")
        XCTAssertNil(s.host)
        // A serve still finishing after the lock cannot commit: the host's gate refuses it.
        XCTAssertThrowsError(try host2.store.commit(StoreChange(baseRevision: snap.revision, records: snap.records,
                                                                 meta: snap.meta, sync: snap.sync)))
        XCTAssertThrowsError(try host2.store.load())
    }

    /// Owner 2026-10-29 (Windows licence-only mode, `LICENCE_ONLY_LISTEN_SECONDS`): a free Mac with Wi-Fi sync on
    /// listens only while a pairing code is shown (and 120 s after it closes) and for 120 s after Sync now.
    func testFreeMacListensOnlyInTheListenWindow() async throws {
        let lock = lockModel()
        await unlock(lock)
        lock.lock()
        var made: LanHost?
        settings.wifiSyncOn = true
        let port = Int.random(in: 40_000...60_000)
        settings.wifiSyncEndpoint = "127.0.0.1:\(port)"
        let s = MacSyncScheduler(lock: lock, settings: settings, now: { [clock] in clock.date },
                                 makeCoordinator: { [unowned self] in self.coordinator($0) },
                                 makeHost: { lock, c in
                                     let h = LanHost.make(lock: lock, deps: c.deps, counters: HelloCounterSource(
                                         store: VaultCounterStore(vault: InMemoryKeychainVault()), clock: SystemClock()))
                                     h?.allowsLoopbackForTests = true
                                     made = h
                                     return h
                                 },
                                 addresses: { [LanInterfaceAddress(interface: "en0", address: "127.0.0.1")] }, startTimer: false)
        s.allowsLoopbackForTests = true
        var pro = false
        s.hostingAllowed = { pro }
        XCTAssertEqual(MacSyncScheduler.licenceOnlyListenSeconds, 120)

        // Unlocked with Wi-Fi sync on, free: nothing listens.
        await unlock(lock)
        await s.hostSettled(); await s.settled()
        let host = try XCTUnwrap(made)
        XCTAssertTrue(s.licenceOnly)
        XCTAssertFalse(s.mayListen)
        XCTAssertFalse(host.isListening, "a free Mac does not listen just because Wi-Fi sync is on")
        s.setWiFi(true); await s.hostSettled()
        XCTAssertFalse(host.isListening)
        s.tick(); await s.hostSettled()
        XCTAssertFalse(host.isListening, "nor does the timer start it")

        // Sync now: listens for 120 s, then stops quietly with Wi-Fi sync still on.
        s.syncNow(); await s.hostSettled(); await s.settled()
        XCTAssertTrue(host.isListening, host.listenError ?? "")
        XCTAssertEqual(s.listenUntil, clock.date.addingTimeInterval(120))
        clock.advance(119); s.tick()
        XCTAssertTrue(host.isListening)
        clock.advance(2); s.tick()
        XCTAssertFalse(host.isListening, "the window closed")
        XCTAssertNil(host.listenError, "no error: it waits for pairing or Sync now")
        XCTAssertNil(s.listenUntil)
        XCTAssertTrue(settings.wifiSyncOn)

        // Show QR code: listens first, then stays on while the code is shown, and 120 s after it closes.
        let listening = await s.listenForPairing()
        XCTAssertTrue(listening, host.listenError ?? "")
        XCTAssertEqual(host.showQR(), .shown)
        clock.advance(600); s.tick()
        XCTAssertTrue(host.isListening, "a shown pairing code keeps the listener")
        host.pairing.close()
        clock.advance(119); s.tick()
        XCTAssertTrue(host.isListening)
        clock.advance(2); s.tick()
        XCTAssertFalse(host.isListening)

        // Pro: listens whenever Wi-Fi sync is on.
        pro = true
        s.proChanged(); await s.hostSettled()
        XCTAssertFalse(s.licenceOnly)
        XCTAssertTrue(host.isListening, host.listenError ?? "")
        clock.advance(10_000); s.tick()
        XCTAssertTrue(host.isListening)

        // Free again: stops at once (no window open).
        pro = false
        s.proChanged()
        XCTAssertFalse(host.isListening)
        lock.lock()
    }
}
