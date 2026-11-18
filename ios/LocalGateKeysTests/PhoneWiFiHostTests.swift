import XCTest
import AppShared
@testable import LocalGateKeys

/// What the tests change from outside: the lock, Pro, the clock and the phone's addresses (read from any thread).
private final class World: @unchecked Sendable {
    private let lock = NSLock()
    private var _unlocked = true, _pro = true, _served = 0, _commits = 0
    private var _date = Date(timeIntervalSince1970: 1_800_000_000)
    private var _addresses = [LanInterfaceAddress(interface: "en0", address: "127.0.0.1")]
    var unlocked: Bool { get { lock.withLock { _unlocked } } set { lock.withLock { _unlocked = newValue } } }
    var pro: Bool { get { lock.withLock { _pro } } set { lock.withLock { _pro = newValue } } }
    var served: Int { get { lock.withLock { _served } } set { lock.withLock { _served = newValue } } }
    var commits: Int { get { lock.withLock { _commits } } set { lock.withLock { _commits = newValue } } }
    var date: Date { get { lock.withLock { _date } } set { lock.withLock { _date = newValue } } }
    var addresses: [LanInterfaceAddress] { get { lock.withLock { _addresses } } set { lock.withLock { _addresses = newValue } } }
    func advance(_ s: TimeInterval) { lock.withLock { _date += s } }
}

@MainActor
private func waitUntil(_ timeout: TimeInterval = 10, _ condition: () -> Bool) async throws {
    let end = Date().addingTimeInterval(timeout)
    while !condition() {
        guard Date() < end else { throw LanListenError.cannotListen("condition not met in time") }
        try await Task.sleep(nanoseconds: 10_000_000)
    }
}

/// Spec 2026-11-13-phone-wifi-host-design: the iPhone hosts Wi-Fi sync only while the app is in the foreground, the
/// vault is unlocked and the setting is on; a free phone only inside its listen window. A real listener on loopback.
@MainActor
final class PhoneWiFiHostTests: XCTestCase {
    private var suite: String!
    private var settings: AppSettings!
    private var world: World!
    private var store: MemoryStore!
    private var background: FakeBackgroundTasks!
    private var made: [PhoneWiFiHost] = []

    override func setUp() async throws {
        suite = "lgk-phonehost-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        world = World()
        store = MemoryStore()
        background = FakeBackgroundTasks()
    }

    override func tearDown() async throws {
        made.forEach { $0.shutdown() }
        made = []
        UserDefaults().removePersistentDomain(forName: suite)
    }

    /// A controller like `PhoneWiFiHost.live`, over fakes, listening on 127.0.0.1 and a port the system picks.
    private func controller() -> PhoneWiFiHost {
        let keychain = InMemoryKeychainVault()
        let counters = HelloCounterSource(store: VaultCounterStore(vault: keychain), clock: SystemClock())
        let deps = SyncDependencies(keychain: keychain, folders: SecurityScopedFolderOpener(),
                                    lan: LiveLanTransport(dialer: NWLanDialer(browseForPrompt: false), counters: counters,
                                                          random: SystemRandomSource(), clock: SystemClock()),
                                    autoFill: CountingAutoFill(), random: SystemRandomSource(), clock: SystemClock(),
                                    licenseKeys: [:])
        let world = self.world!, store = self.store!
        let c = PhoneWiFiHost(settings: settings, isUnlocked: { world.unlocked }, hostingAllowed: { world.pro },
                              now: { world.date }, addresses: { world.addresses }, copy: { _ in },
                              background: background, startTimer: false,
                              makeHost: { onCommit in
            let host = LanHost(store: CommitSignallingStore(base: store, onCommit: onCommit), deps: deps, counters: counters,
                               isUnlocked: { world.unlocked })
            host.allowsLoopbackForTests = true
            host.allowsSystemPort = true
            return host
        })
        c.defaultPort = 0
        c.onServedChange = { world.served += 1 }
        made.append(c)
        return c
    }

    /// On and in the foreground, settled.
    private func listening(_ c: PhoneWiFiHost) async {
        c.setEnabled(true)
        c.setForeground(true)
        await c.hostSettled()
    }

    // MARK: the start / stop rules

    func test_off_by_default_never_listens() async {
        let c = controller()
        XCTAssertFalse(c.isEnabled, "Host Wi-Fi sync on this phone is off by default")
        c.setForeground(true)
        await c.hostSettled()
        c.tick()
        await c.hostSettled()
        XCTAssertFalse(c.isListening)
        XCTAssertFalse(c.shouldListen)
        XCTAssertEqual(c.statusText(joined: false, pairedCount: 0), PhoneWiFiHost.offText)
    }

    func test_listens_only_in_the_foreground() async {
        let c = controller()
        c.setEnabled(true)
        await c.hostSettled()
        XCTAssertFalse(c.isListening, "not in the foreground yet")

        c.setForeground(true)
        await c.hostSettled()
        XCTAssertTrue(c.isListening)
        XCTAssertEqual(c.host?.endpoint?.host, "127.0.0.1")
        XCTAssertNotNil(settings.wifiSyncEndpoint, "the address is kept for the next start")
        XCTAssertTrue(c.statusText(joined: false, pairedCount: 0).contains("127.0.0.1"))

        c.setForeground(false)   // the background: stopped at once
        XCTAssertFalse(c.isListening)
        XCTAssertNil(c.host?.endpoint)
        c.tick()
        await c.hostSettled()
        XCTAssertFalse(c.isListening, "nothing runs in the background")

        c.setForeground(true)
        await c.hostSettled()
        XCTAssertTrue(c.isListening, "back in the foreground: listening again")
    }

    func test_lock_stops_and_shutdown_is_final() async {
        let c = controller()
        await listening(c)
        XCTAssertTrue(c.isListening)

        world.unlocked = false
        c.update()
        XCTAssertFalse(c.isListening, "locked: stopped")
        world.unlocked = true
        c.update()
        await c.hostSettled()
        XCTAssertTrue(c.isListening)

        c.shutdown()
        XCTAssertFalse(c.isListening)
        c.setForeground(false)
        c.setForeground(true)
        c.tick()
        await c.hostSettled()
        XCTAssertFalse(c.isListening, "a shut-down host never starts again")
        XCTAssertFalse(c.shouldListen)
        await c.showQR()
        XCTAssertFalse(c.showingQR)
    }

    func test_setting_off_stops() async {
        let c = controller()
        await listening(c)
        XCTAssertTrue(c.isListening)
        c.setEnabled(false)
        XCTAssertFalse(c.isListening)
        XCTAssertFalse(settings.wifiSyncOn)
        XCTAssertEqual(c.statusText(joined: true, pairedCount: 1), PhoneWiFiHost.offText)
    }

    func test_inactive_scene_changes_nothing_and_no_host_means_no_toggle() async {
        let c = controller()
        await listening(c)
        c.setForeground(true)   // repeated: no restart
        XCTAssertTrue(c.isListening)

        let none = PhoneWiFiHost(settings: settings, isUnlocked: { true }, hostingAllowed: { true }, startTimer: false,
                                 makeHost: { _ in nil })
        made.append(none)
        none.setEnabled(true)
        none.setForeground(true)
        XCTAssertNil(none.host)
        XCTAssertFalse(none.isListening)
        await none.showQR()
        XCTAssertEqual(none.error, HostPairingModel.notListeningText)
    }

    // MARK: Pro gating

    func test_free_listens_only_inside_the_listen_window() async {
        world.pro = false
        let c = controller()
        await listening(c)
        XCTAssertTrue(c.licenceOnly)
        XCTAssertEqual(c.host?.licenceOnly, true)
        XCTAssertFalse(c.isListening, "free: closed until a code is shown or Sync now")
        XCTAssertEqual(c.statusText(joined: true, pairedCount: 1), PhoneWiFiHost.licenceOnlyIdleText)

        await c.afterManualSync()
        await c.hostSettled()
        XCTAssertTrue(c.isListening, "Sync now opens the window")
        XCTAssertEqual(c.listenUntil, world.date.addingTimeInterval(PhoneWiFiHost.licenceOnlyListenSeconds))

        world.advance(PhoneWiFiHost.licenceOnlyListenSeconds - 1)
        c.tick()
        XCTAssertTrue(c.isListening)
        world.advance(2)
        c.tick()
        XCTAssertFalse(c.isListening, "the window closed")
        XCTAssertNil(c.listenUntil)

        world.pro = true   // Pro gained: hosts fully
        c.proChanged()
        await c.hostSettled()
        XCTAssertTrue(c.isListening)
        XCTAssertEqual(c.host?.licenceOnly, false)
        XCTAssertNil(c.listenUntil)

        world.pro = false   // Pro lost: licence-only again, and closed
        c.proChanged()
        XCTAssertFalse(c.isListening)
        XCTAssertEqual(c.host?.licenceOnly, true)
    }

    func test_free_show_qr_listens_while_the_code_is_shown() async {
        world.pro = false
        let c = controller()
        await listening(c)
        XCTAssertFalse(c.isListening)

        await c.showQR()
        XCTAssertNil(c.error)
        XCTAssertTrue(c.showingQR)
        XCTAssertTrue(c.isListening)
        world.advance(PhoneWiFiHost.licenceOnlyListenSeconds * 2)
        c.tick()
        XCTAssertTrue(c.isListening, "the shown code keeps the window open")

        c.closeQR()
        XCTAssertFalse(c.showingQR)
        world.advance(PhoneWiFiHost.licenceOnlyListenSeconds - 1)
        c.tick()
        XCTAssertTrue(c.isListening, "open for 2 minutes after the code closed")
        world.advance(2)
        c.tick()
        XCTAssertFalse(c.isListening)
    }

    // MARK: the address

    func test_follows_the_wifi_address() async {
        let c = controller()
        await listening(c)
        XCTAssertTrue(c.isListening)

        world.addresses = []   // Wi-Fi left
        c.tick()
        await c.hostSettled()
        XCTAssertFalse(c.isListening)
        XCTAssertTrue(c.noWiFi)
        XCTAssertEqual(c.statusText(joined: true, pairedCount: 1), PhoneWiFiHost.noWiFiText)

        world.addresses = [LanInterfaceAddress(interface: "en0", address: "127.0.0.1")]   // back
        c.tick()
        await c.hostSettled()
        XCTAssertTrue(c.isListening)
        XCTAssertFalse(c.noWiFi)
    }

    func test_no_wifi_address_never_listens() async {
        world.addresses = []
        let c = controller()
        await listening(c)
        XCTAssertFalse(c.isListening)
        XCTAssertTrue(c.noWiFi)
        await c.showQR()
        XCTAssertFalse(c.showingQR)
        XCTAssertEqual(c.error, PhoneWiFiHost.noWiFiText)
    }

    func test_preferred_address_is_wifi_first() {
        func a(_ i: String, _ s: String) -> LanInterfaceAddress { LanInterfaceAddress(interface: i, address: s) }
        XCTAssertEqual(PhoneWiFiHost.preferred([a("en1", "10.0.0.5"), a("en0", "192.168.1.20")]), a("en0", "192.168.1.20"))
        XCTAssertEqual(PhoneWiFiHost.preferred([a("en0", "169.254.1.1"), a("en2", "10.0.0.5")]), a("en0", "169.254.1.1"),
                       "no private Wi-Fi address: the candidates' own order")
        XCTAssertEqual(PhoneWiFiHost.preferred([a("en2", "10.0.0.5")]), a("en2", "10.0.0.5"))
        XCTAssertNil(PhoneWiFiHost.preferred([]))
    }

    // MARK: pairing and commits

    func test_show_qr_creates_the_group_and_the_background_closes_it() async throws {
        let c = controller()
        await listening(c)
        XCTAssertNil(store.snapshot.sync)

        await c.showQR()
        XCTAssertNil(c.error)
        XCTAssertTrue(c.showingQR)
        XCTAssertEqual(c.host?.pairing.stage, .showing)
        XCTAssertNotNil(c.host?.pairing.qrText)
        XCTAssertNotNil(store.snapshot.sync, "the first code creates this phone's Wi-Fi group")
        try await waitUntil { self.world.served > 0 }   // the commit reached the coordinator (lists reload)

        c.setForeground(false)
        XCTAssertFalse(c.showingQR, "the background closes the code")
        XCTAssertFalse(c.isListening)
        XCTAssertEqual(c.host?.pairing.isOpen, false)
    }

    func test_commit_signalling_store_signals_successful_commits_only() throws {
        let base = MemoryStore()
        let world = self.world!
        let s = CommitSignallingStore(base: base, onCommit: { world.commits += 1 })
        try s.commit(StoreChange(baseRevision: 0, records: [:], meta: [:], sync: nil))
        XCTAssertEqual(world.commits, 1)
        XCTAssertEqual(base.commits, 1)
        XCTAssertThrowsError(try s.commit(StoreChange(baseRevision: 0, records: [:], meta: [:], sync: nil)), "stale")
        XCTAssertEqual(world.commits, 1, "a refused commit changes nothing")
        XCTAssertEqual(try s.load().revision, 1)
    }

    // MARK: remove a paired device

    /// The phone's Wi-Fi group (created by Show QR code) with `name` pinned as a device that connects here.
    private func groupWithPeer(_ c: PhoneWiFiHost, name: String = "Pixel") async throws -> String {
        await c.showQR()
        c.closeQR()
        var state = try XCTUnwrap(store.snapshot.sync, "Show QR code creates the group")
        let id = "a1b2c3d4-0000-4000-8000-000000000001"
        state = try LanPeers.adding(LanPeer(deviceID: id, groupID: state.groupID, name: name,
                                            signingPublic: [UInt8](repeating: 7, count: 32),
                                            exchangePublic: [UInt8](repeating: 8, count: 32), pairedAt: 1), to: state)
        store.snapshot.sync = state
        return id
    }

    func test_remove_revokes_the_device_and_keeps_it_listed() async throws {
        let c = controller()
        await listening(c)
        let id = try await groupWithPeer(c)
        let served = world.served
        let commits = store.commits

        XCTAssertTrue(c.removePeer(id, name: "Pixel"))
        XCTAssertNil(c.error)
        XCTAssertEqual(c.info, PhoneWiFiHost.removedText("Pixel"))
        let entry = try XCTUnwrap(store.snapshot.sync?.lanPeers.first { $0.deviceID == id }, "kept listed so it cannot come back")
        XCTAssertTrue(entry.revoked)
        XCTAssertEqual(store.commits, commits + 1, "one commit through the host's store")
        try await waitUntil { self.world.served > served }   // the lists reload
        XCTAssertEqual(PhoneWiFiHost.removeDeviceText("Pixel"),
                       "Remove Pixel from Wi-Fi sync? It stops syncing with this phone but keeps what it already has.")
    }

    func test_remove_works_on_the_free_plan_and_while_not_listening() async throws {
        world.pro = false
        let c = controller()
        await listening(c)
        let id = try await groupWithPeer(c)
        c.setEnabled(false)   // hosting off: the paired devices are still listed and removable
        XCTAssertFalse(c.isListening)

        XCTAssertTrue(c.removePeer(id, name: "Pixel"), "free: Remove needs no Pro")
        XCTAssertEqual(store.snapshot.sync?.lanPeers.first { $0.deviceID == id }?.revoked, true)
    }

    func test_remove_of_an_unknown_device_changes_nothing() async throws {
        let c = controller()
        await listening(c)
        _ = try await groupWithPeer(c)
        let commits = store.commits
        XCTAssertFalse(c.removePeer("ffffffff-0000-4000-8000-00000000000f", name: "Ghost"))
        XCTAssertEqual(store.commits, commits)
        XCTAssertNil(c.info)
    }

    func test_remove_after_lock_is_refused_by_the_gate() async throws {
        let c = controller()
        await listening(c)
        let id = try await groupWithPeer(c)
        c.shutdown()   // the vault locked: the host's store gate is closed

        XCTAssertFalse(c.removePeer(id, name: "Pixel"))
        XCTAssertEqual(c.error, SyncWording.stepFailedCopy)
        XCTAssertEqual(store.snapshot.sync?.lanPeers.first { $0.deviceID == id }?.revoked, false, "nothing written")
    }

    func test_stop_with_no_open_connection_holds_no_background_task() async {
        let c = controller()
        await listening(c)
        c.setForeground(false)
        XCTAssertTrue(background.begun.isEmpty, "nothing in flight: nothing to hold")
    }
}
