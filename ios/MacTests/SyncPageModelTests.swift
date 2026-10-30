import XCTest
import AppKit
import LGKCore
@testable import AppSharedMac

/// The desktop's TEST-ONLY licence vector (never verifies with production keys).
private enum MacLicenceVector {
    static let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../../tests/vectors/sync/license_state.json").standardized

    static func load() throws -> (keys: [String: [UInt8]], id: String, wrapper: JSONValue) {
        guard case .object(let o) = try CanonicalJSON.parse(Array(try Data(contentsOf: url))),
              case .string(let keyID)? = o["key_id"], case .string(let pub)? = o["public_key_b64"],
              case .string(let stateID)? = o["state_id"], let wrapper = o["wrapper"] else {
            throw XCTSkip("licence vector shape")
        }
        return ([keyID: try Base64.decodeStrict(pub)], stateID, wrapper)
    }
}

/// Never answers: a join attempt fails at once.
private struct RefusingLan: LanTransporting {
    func exchangeViews(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                       ownCounter: Int64) async throws -> [ItemState] { throw LanSocketError("refused") }
    func enroll(endpoint: LanEndpoint, request: [UInt8], onConnected: @escaping @Sendable () -> Void) async throws -> [UInt8] {
        throw LanSocketError("refused")
    }
}

@MainActor
final class SyncPageModelTests: XCTestCase {
    private var dir: URL!
    private var suite: String!
    private var settings: AppSettings!
    private var keychain: InMemoryKeychainVault!
    private var needsPro: [ProReason] = []

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-syncpage-\(UUID().uuidString)", isDirectory: true)
        suite = "lgk-syncpage-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        keychain = InMemoryKeychainVault()
        needsPro = []
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        UserDefaults().removePersistentDomain(forName: suite)
    }

    private func unlockedLock() async -> MacLockModel {
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(),
                             kdfParams: MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1))
        let lock = MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), startTimer: false)
        await lock.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertEqual(lock.state, .unlocked)
        return lock
    }

    private func deps() -> SyncDependencies {
        SyncDependencies(keychain: keychain, folders: SecurityScopedFolderOpener(), lan: RefusingLan(),
                         autoFill: NoAutoFillRefresh(), random: SystemRandomSource(), clock: SystemClock(), licenseKeys: [:])
    }

    /// A scheduler over fakes with a real host, gated on `pro` exactly as `MacAppEnvironment` wires it.
    private func page(_ lock: MacLockModel, pro: ProModel) -> (SyncPageModel, MacSyncScheduler) {
        let deps = deps(), keychain = keychain!
        let scheduler = MacSyncScheduler(
            lock: lock, settings: settings,
            makeCoordinator: { lock in
                guard let store = lock.store as? PublishingItemStore else { return nil }
                return SyncCoordinator(store: SyncSourceStore(base: store, local: lock), deps: deps)
            },
            makeHost: { lock, coordinator in
                guard let store = lock.store as? PublishingItemStore else { return nil }
                return LanHost(store: SyncSourceStore(base: store, local: lock), deps: coordinator.deps,
                               counters: HelloCounterSource(store: VaultCounterStore(vault: keychain), clock: SystemClock()))
            },
            addresses: { [] }, startTimer: false)
        scheduler.hostingAllowed = { pro.isPro }
        let clipboard = MacClipboard(pasteboard: NSPasteboard(name: .init("lgk-syncpage-\(UUID().uuidString)")),
                                     clock: SystemClock(), clearAfter: 60)
        let model = SyncPageModel(scheduler: scheduler, pro: pro, clipboard: clipboard, settings: settings,
                                  onNeedsPro: { [unowned self] in self.needsPro.append($0) })
        return (model, scheduler)
    }

    private func joinWiFiGroup(_ lock: MacLockModel) throws {
        let store = try XCTUnwrap(lock.store)
        let group = try SyncGroup.createWiFi(installID: try keychain.installID(random: SystemRandomSource()), random: SystemRandomSource())
        let snap = try store.load()
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: group))
    }

    // MARK: tests

    /// Review focus 4 (changed by plan 2026-10-29-appstore-licence Task 8): a free Mac joins someone else's group,
    /// and its Wi-Fi host runs licence-only (Wi-Fi on and Show QR code work, with no Pro sheet).
    func testFreeCanJoinAndHostsLicenceOnly() async throws {
        let lock = await unlockedLock()
        let pro = ProModel(purchases: NoPurchases(), licenseKeys: [:])
        let (model, scheduler) = page(lock, pro: pro)
        await scheduler.settled()
        XCTAssertFalse(model.hostingAllowed)
        XCTAssertTrue(model.licenceOnly)
        XCTAssertEqual(scheduler.host?.licenceOnly, true)

        model.setWiFi(true)
        XCTAssertEqual(needsPro, [])
        XCTAssertTrue(settings.wifiSyncOn, "free: Wi-Fi sync turns on, licence-only")
        // Free: on, but listening only while pairing or for 2 minutes after Sync now (Windows licence-only mode).
        XCTAssertFalse(scheduler.mayListen)
        XCTAssertEqual(model.wifiText, SyncPageModel.licenceOnlyIdleText)

        // Show QR code first opens the listen window and tries to listen. No private address in tests, so
        // nothing listens: the page says so instead of asking for Pro.
        model.showQR()
        XCTAssertNotNil(model.pendingShow, "a free Mac starts the listener before showing a code")
        await model.pendingShow?.value
        XCTAssertTrue(scheduler.mayListen, "the listen window is open")
        XCTAssertEqual(needsPro, [])
        XCTAssertFalse(model.showingQR)
        XCTAssertEqual(model.error, HostPairingModel.notListeningText)
        XCTAssertEqual(scheduler.host?.showQR(), .notListening)

        // Joining by pasted code text is free: it is attempted (and fails here on a bad code), with no Pro sheet.
        model.joinText = "lgk-pair:not-a-real-code"
        await model.join()
        XCTAssertEqual(needsPro, [])
        XCTAssertNotNil(scheduler.coordinator?.actionError)
        XCTAssertNotEqual(scheduler.coordinator?.actionError, UpgradePrompt.syncMessage)
        XCTAssertEqual(UpgradePrompt.message(.sync), "Device sync is part of LocalGateKeys Pro. Everything already on this Mac stays here and keeps working; with Pro, sync resumes where it left off.")
        XCTAssertEqual(MacUpgradeSheet.subtitle(.sync), UpgradePrompt.syncMessage)

        // Empty text asks for the code; nothing else happens.
        model.joinText = "  "
        await model.join()
        XCTAssertEqual(model.error, SyncPageModel.joinEmptyText)
    }

    /// A desktop licence received through sync (`ProModel.update(from:)` after a run) unlocks hosting at once.
    func testSyncedLicenceUnlocksHosting() async throws {
        let v = try MacLicenceVector.load()
        let lock = await unlockedLock()
        let pro = ProModel(purchases: NoPurchases(), licenseKeys: v.keys)
        let (model, scheduler) = page(lock, pro: pro)
        await scheduler.settled()

        XCTAssertEqual(scheduler.host?.licenceOnly, true)

        // The run brought the licence state; the window updates Pro from the store.
        pro.update(from: StoreSnapshot(records: [v.id: v.wrapper]))
        XCTAssertTrue(pro.isPro)
        scheduler.proChanged()
        XCTAssertTrue(model.hostingAllowed)
        XCTAssertEqual(scheduler.host?.licenceOnly, false, "full hosting now")

        model.setWiFi(true)
        XCTAssertTrue(settings.wifiSyncOn, "Pro: Wi-Fi sync turns on")
        model.showQR()
        XCTAssertEqual(needsPro, [])
        // No private address in tests, so nothing listens: the page says so instead of asking for Pro.
        XCTAssertEqual(model.error, HostPairingModel.notListeningText)
    }

    func testLeaveNeedsTwoConfirmations() async throws {
        let lock = await unlockedLock()
        try joinWiFiGroup(lock)
        let pro = ProModel(purchases: NoPurchases(), licenseKeys: [:])
        let (model, scheduler) = page(lock, pro: pro)
        await scheduler.settled()
        model.reload()
        XCTAssertTrue(model.canLeave)

        // Cancel at the first step: still in the group.
        model.requestLeave()
        XCTAssertEqual(model.confirmation, .leave(step: 1))
        XCTAssertEqual(model.confirmationText, SyncWording.onPhone(SyncWording.leaveWifiText))
        XCTAssertTrue(model.confirmationText.contains("this Mac"))
        XCTAssertFalse(model.confirmationText.contains("PC"))
        model.cancelConfirmation()
        XCTAssertNotNil(try lock.store?.load().sync)

        // The first agreement only asks again.
        model.requestLeave()
        await model.confirm()
        XCTAssertEqual(model.confirmation, .leave(step: 2))
        XCTAssertEqual(model.confirmationText, "Are you sure? Leave sync on this Mac now?")
        XCTAssertNotNil(try lock.store?.load().sync, "nothing happens after one confirmation")
        await model.confirm()
        XCTAssertNil(model.confirmation)
        XCTAssertNil(try lock.store?.load().sync)
        XCTAssertEqual(model.info, "This Mac left sync. Remove it on one of your other devices.")
        XCTAssertFalse(model.canLeave)

        // Reset: the same two steps.
        try joinWiFiGroup(lock)
        model.reload()
        model.requestReset()
        XCTAssertEqual(model.confirmationText, SyncWording.onPhone(SyncWording.resetText1))
        await model.confirm()
        XCTAssertEqual(model.confirmation, .reset(step: 2))
        XCTAssertNotNil(try lock.store?.load().sync)
        await model.confirm()
        XCTAssertNil(try lock.store?.load().sync)
        XCTAssertEqual(model.info, "Sync was reset on this Mac.")
    }

    func testLeaveSurvivesAlertDismissOrder() async throws {
        // The alert clears `confirmation` as it closes, before the button's Task runs.
        let lock = await unlockedLock()
        try joinWiFiGroup(lock)
        let pro = ProModel(purchases: NoPurchases(), licenseKeys: [:])
        let (model, scheduler) = page(lock, pro: pro)
        await scheduler.settled()
        model.reload()
        model.requestLeave()
        var shown = model.confirmation
        model.cancelConfirmation()
        await model.confirm(shown)
        XCTAssertEqual(model.confirmation, .leave(step: 2))
        shown = model.confirmation
        model.cancelConfirmation()
        await model.confirm(shown)
        XCTAssertNil(try lock.store?.load().sync)
    }

    func testIssuesCopy() {
        // Host issues read as on the desktop, "this Mac" for "this PC", deduplicated and sorted by importance.
        let host = [SyncIssue("lan-not-listening"), SyncIssue("lan-not-listening"), SyncIssue("state-corrupt")]
        let coordinatorViews = SyncWording.views([SyncIssue("stale-self")])
        let shown = SyncPageModel.messages(host: host, coordinator: coordinatorViews)
        // Errors first; equal severities keep their order (the coordinator's before the host's).
        XCTAssertEqual(shown.map(\.kind), ["state-corrupt", "stale-self", "lan-not-listening"])
        XCTAssertEqual(shown[0].text, "This vault's sync settings are damaged. Reset sync on this Mac, then join again."
                       + " If that does not help, use Reset sync on this Mac below.")
        XCTAssertTrue(shown[1].text.hasPrefix("This Mac had not synced for over a year."))
        XCTAssertEqual(shown[2].text, "Wi-Fi sync is not listening yet.")
        XCTAssertFalse(shown.contains { $0.text.contains("PC") })
        XCTAssertTrue(SyncPageModel.messages(host: [], coordinator: []).isEmpty)
    }

    /// Removing a folder device wraps the new key only to confirmed members (audit M10): unconfirmed ones are
    /// named as losing access, and the keep-list passed to `rotate` is explicit.
    func testRotationKeepsConfirmedMembersOnly() throws {
        let me = try DeviceIdentity.generate(random: SystemRandomSource())
        let a = "a1111111-0000-4000-8000-00000000000a", b = "b2222222-0000-4000-8000-00000000000b"
        let c = "c3333333-0000-4000-8000-00000000000c"
        let state = SyncGroupState(groupID: "9e3c7b1e-0000-4000-8000-000000000001", epoch: 2, key: [UInt8](repeating: 1, count: 32),
                                   identity: me, installID: "install", hasFolder: true, membersEpoch: 2,
                                   members: [me.deviceID, a, b, c], unackedMembers: [c])
        XCTAssertEqual(SyncPageModel.keepList(state, removing: [b]), [a])
        let text = SyncPageModel.keepText(state, removing: [b], names: [a: "Laptop", c: "Unknown phone"])
        XCTAssertEqual(text, "The new sync key goes only to: Laptop, this Mac. Not confirmed, so they lose access: Unknown phone. To keep one, cancel and choose These are my devices first.")
    }

    func testQRImageScannableSize() throws {
        let image = try XCTUnwrap(SyncPageModel.qrImage("lgk-pair:" + String(repeating: "A", count: 600)))
        XCTAssertGreaterThanOrEqual(image.size.width, 200, "large enough to scan from a phone")
        XCTAssertLessThanOrEqual(image.size.width, 260)
        XCTAssertEqual(image.size.width, image.size.height)
    }

    func testConnectionsWiFiRow() throws {
        XCTAssertEqual(ConnectionsModel.wifiState(on: false, endpoint: nil).text, "Off")
        XCTAssertEqual(ConnectionsModel.wifiState(on: true, endpoint: nil).text, "On")
        let e = try LanEndpoint(validating: "192.168.1.20", port: 47821)
        XCTAssertEqual(ConnectionsModel.wifiState(on: true, endpoint: e).text, "On · 192.168.1.20:47821")
        XCTAssertEqual(ConnectionsModel.wifiState(on: true, endpoint: e).ok, true)
    }

    func testPaletteOpensSync() {
        let rows = PaletteModel.results("sync", items: [], unlocked: true)
        XCTAssertEqual(rows.first?.target, .action(.sync))
    }
}
