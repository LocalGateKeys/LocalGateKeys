import XCTest
import AppKit
import LGKCore
@testable import AppSharedMac

/// A clock the test moves by hand (the wrong-password back-off).
private final class HandClock: UnixClock, @unchecked Sendable {
    var now: Int64 = 1_800_000_000
}

/// Never answers: no Wi-Fi peer is reachable in these tests.
private struct NoLan: LanTransporting {
    func exchangeViews(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                       ownCounter: Int64) async throws -> [ItemState] { throw LanSocketError("refused") }
    func enroll(endpoint: LanEndpoint, request: [UInt8], onConnected: @escaping @Sendable () -> Void) async throws -> [UInt8] {
        throw LanSocketError("refused")
    }
}

/// Cloud folder sync on the Mac's Sync page: the folder picker hands back a temp folder, the real
/// security-scoped bookmark opener and `CoordinatedFolder` do the rest.
@MainActor
final class MacFolderSyncTests: XCTestCase {
    private static let password = "violet-harbor-canyon-47-quilt"

    /// One Mac: its own vault, sync keychain, settings and Sync page.
    private struct Mac {
        let lock: MacLockModel
        let keychain: InMemoryKeychainVault
        let model: SyncPageModel
        let scheduler: MacSyncScheduler
    }

    private var root: URL!
    private var folder: URL!
    private var suites: [String] = []
    private var needsPro: [ProReason] = []

    override func setUp() async throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-macfolder-\(UUID().uuidString)", isDirectory: true)
        folder = root.appendingPathComponent("Cloud", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        needsPro = []
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: root)
        for s in suites { UserDefaults().removePersistentDomain(forName: s) }
    }

    private func settings() -> AppSettings {
        let suite = "lgk-macfolder-\(UUID().uuidString)"; suites.append(suite)
        return AppSettings(defaults: UserDefaults(suiteName: suite)!)
    }

    private func unlocked(_ name: String, settings: AppSettings) async -> MacLockModel {
        let vault = MacVault(directory: root.appendingPathComponent(name, isDirectory: true), keychain: InMemoryKeychainVault(),
                             biometric: FakeBiometricKeyStore(),
                             kdfParams: MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1))
        let lock = MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), startTimer: false)
        await lock.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertEqual(lock.state, .unlocked)
        return lock
    }

    private func page(_ lock: MacLockModel, keychain: InMemoryKeychainVault, settings: AppSettings, pro: Bool,
                      clock: any UnixClock = SystemClock()) async -> Mac {
        let deps = SyncDependencies(keychain: keychain, folders: SecurityScopedFolderOpener(), lan: NoLan(),
                                    autoFill: NoAutoFillRefresh(), random: SystemRandomSource(), clock: clock, licenseKeys: [:])
        let scheduler = MacSyncScheduler(
            lock: lock, settings: settings,
            makeCoordinator: { lock in
                guard let store = lock.store as? PublishingItemStore else { return nil }
                return SyncCoordinator(store: SyncSourceStore(base: store, local: lock), deps: deps)
            },
            makeHost: { _, _ in nil }, addresses: { [] }, startTimer: false)
        let proModel = ProModel(purchases: NoPurchases(), licenseKeys: [:], purchased: pro)
        scheduler.hostingAllowed = { proModel.isPro }
        let clipboard = MacClipboard(pasteboard: NSPasteboard(name: .init("lgk-macfolder-\(UUID().uuidString)")),
                                     clock: SystemClock(), clearAfter: 60)
        let model = SyncPageModel(scheduler: scheduler, pro: proModel, clipboard: clipboard, settings: settings,
                                  onNeedsPro: { [unowned self] in self.needsPro.append($0) })
        model.folderPicker = { [folder] in folder }
        await scheduler.settled()
        return Mac(lock: lock, keychain: keychain, model: model, scheduler: scheduler)
    }

    private func mac(_ name: String, pro: Bool, clock: any UnixClock = SystemClock()) async -> Mac {
        let s = settings()
        let lock = await unlocked(name, settings: s)
        return await page(lock, keychain: InMemoryKeychainVault(), settings: s, pro: pro, clock: clock)
    }

    @discardableResult
    private func addLogin(_ m: Mac, _ title: String) throws -> String {
        let store = try XCTUnwrap(m.lock.store)
        let snap = try store.load()
        var records = snap.records
        let id = UUID().uuidString.lowercased()
        let r: JSONValue = .object(["id": .string(id), "kind": .string("note"), "title": .string(title),
                                    "created_at": .int(1_700_000_000), "updated_at": .int(1_700_000_001),
                                    "favorite": .bool(false), "tags": .array([]),
                                    "payload": .object(["body": .string("body"), "fields": .array([]), "template_id": .null])])
        records[id] = Wrapper.make(ns: .item, record: try Normalise.normalForm(ns: .item, record: r))
        try store.commit(StoreChange(baseRevision: snap.revision, records: records, meta: snap.meta, sync: snap.sync))
        return id
    }

    private func expect(_ want: Bool, _ got: Bool, _ message: @autoclosure () -> String = "",
                        file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(got, want, message(), file: file, line: line)
    }

    // MARK: tests

    func testCreateJoinAttachRepick() async throws {
        // Create needs Pro: a free Mac sees the upgrade sheet and no picker or password form.
        let free = await mac("free", pro: false)
        var picked = false
        free.model.folderPicker = { picked = true; return nil }
        await free.model.pickFolder(.create)
        XCTAssertEqual(needsPro, [.sync])
        XCTAssertFalse(picked)
        XCTAssertNil(free.model.folderForm)

        // A Pro Mac creates the group in the folder (new password twice).
        let a = await mac("a", pro: true)
        await a.model.pickFolder(.create)
        XCTAssertEqual(a.model.folderForm?.kind, .create)
        expect(false, await a.model.submitFolder(password: Self.password, again: "different-password-0000"))
        XCTAssertEqual(a.model.error, SyncPageModel.mismatchText)
        expect(true, await a.model.submitFolder(password: Self.password, again: Self.password), a.model.error ?? "")
        XCTAssertNil(a.model.folderForm)
        XCTAssertTrue(a.model.state?.hasFolder ?? false)
        XCTAssertTrue(FileManager.default.fileExists(atPath: folder.appendingPathComponent(FolderLayout.keyringPath).path))
        XCTAssertNotNil(try a.keychain.readSlot(.folderBookmark))

        // A free Mac joins it (joining is free).
        let b = await mac("b", pro: false)
        needsPro = []
        await b.model.pickFolder(.join)
        XCTAssertEqual(b.model.folderForm?.kind, .join)
        expect(true, await b.model.submitFolder(password: Self.password), b.model.error ?? "")
        XCTAssertEqual(needsPro, [])
        XCTAssertEqual(b.model.state?.groupID, a.model.state?.groupID)
        XCTAssertEqual(Set(b.model.state?.members ?? []).count, 2)

        // Choose the folder again: the bookmark was lost; no password is asked.
        try b.keychain.deleteSlot(.folderBookmark)
        await b.model.pickFolder(nil)
        XCTAssertNil(b.model.folderForm)
        XCTAssertNil(b.model.error)
        XCTAssertNotNil(try b.keychain.readSlot(.folderBookmark))

        // Attach: a Wi-Fi-only member of another group uses that group's folder, added by a Pro Mac.
        let other = root.appendingPathComponent("Cloud2", isDirectory: true)
        try FileManager.default.createDirectory(at: other, withIntermediateDirectories: true)
        let c = await mac("c", pro: true), d = await mac("d", pro: false)
        c.model.folderPicker = { other }; d.model.folderPicker = { other }
        var group = try SyncGroup.createWiFi(installID: try c.keychain.installID(random: SystemRandomSource()), random: SystemRandomSource())
        try commit(group, to: c)
        group.installID = try d.keychain.installID(random: SystemRandomSource())
        group.identity = try DeviceIdentity.generate(random: SystemRandomSource())
        try commit(group, to: d)
        c.model.reload(); d.model.reload()

        await c.model.pickFolder(.add)
        XCTAssertEqual(c.model.folderForm?.kind, .add)
        expect(true, await c.model.submitFolder(password: Self.password, again: Self.password), c.model.error ?? "")
        await d.model.pickFolder(.use)
        XCTAssertEqual(d.model.folderForm?.kind, .use)
        expect(true, await d.model.submitFolder(password: Self.password), d.model.error ?? "")
        XCTAssertTrue(d.model.state?.hasFolder ?? false)
        XCTAssertEqual(d.model.state?.groupID, c.model.state?.groupID)
    }

    private func commit(_ group: SyncGroupState, to m: Mac) throws {
        let store = try XCTUnwrap(m.lock.store)
        let snap = try store.load()
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: group))
    }

    func testBookmarkSurvivesRelaunch() async throws {
        let a = await mac("a", pro: true)
        await a.model.pickFolder(.create)
        expect(true, await a.model.submitFolder(password: Self.password, again: Self.password), a.model.error ?? "")
        let b = await mac("b", pro: false)
        await b.model.pickFolder(.join)
        expect(true, await b.model.submitFolder(password: Self.password), b.model.error ?? "")

        // A's app quits: the scheduler and page go away; a new launch reads the stored bookmark only.
        let bookmark = try XCTUnwrap(try a.keychain.readSlot(.folderBookmark))
        let s2 = settings()
        let relaunched = await page(a.lock, keychain: a.keychain, settings: s2, pro: false)
        relaunched.model.folderPicker = { XCTFail("no picker after a relaunch"); return nil }
        let (opened, _) = try SecurityScopedFolderOpener().open(bookmark: bookmark)
        XCTAssertEqual((opened as? CoordinatedFolder)?.root.resolvingSymlinksInPath().path, folder.resolvingSymlinksInPath().path)

        // An item added on A reaches B through the folder, with Pro lapsed on A.
        let id = try addLogin(a, "From A after relaunch")
        relaunched.scheduler.syncNow()
        await relaunched.scheduler.settled()
        XCTAssertFalse(relaunched.model.messages.contains { $0.kind == "folder-missing" }, "\(relaunched.model.messages)")
        b.scheduler.syncNow()
        await b.scheduler.settled()
        let onB = try XCTUnwrap(b.lock.store).load().records
        XCTAssertNotNil(onB[id], "\(onB.keys) \(b.model.messages) \(relaunched.model.messages)")
    }

    func testPasswordBackoffAfterFiveWrong() async throws {
        let a = await mac("a", pro: true)
        await a.model.pickFolder(.create)
        expect(true, await a.model.submitFolder(password: Self.password, again: Self.password), a.model.error ?? "")

        let clock = HandClock()
        let b = await mac("b", pro: false, clock: clock)
        await b.model.pickFolder(.join)
        for i in 1...5 {
            expect(false, await b.model.submitFolder(password: "wrong-password-number-\(i)"))
            XCTAssertNotEqual(b.model.error, SyncWording.passwordBackoffText, "attempt \(i)")
        }
        // The sixth, even with the right password, waits 30 s.
        expect(false, await b.model.submitFolder(password: Self.password))
        XCTAssertEqual(b.model.error, SyncWording.passwordBackoffText)
        clock.now += 29
        expect(false, await b.model.submitFolder(password: Self.password))
        XCTAssertEqual(b.model.error, SyncWording.passwordBackoffText)
        clock.now += 1
        expect(true, await b.model.submitFolder(password: Self.password), b.model.error ?? "")
        XCTAssertEqual(b.model.state?.groupID, a.model.state?.groupID)
    }

    private func peer(_ groupID: String, name: String, revoked: Bool) throws -> LanPeer {
        let id = try DeviceIdentity.generate(random: SystemRandomSource())
        return LanPeer(deviceID: id.deviceID, groupID: groupID, name: name, signingPublic: id.signingPublicKey,
                       exchangePublic: id.exchangePublicKey, revoked: revoked)
    }

    /// Audit M9: a removed Wi-Fi peer still holds the key, so adding a folder asks for a new key first and
    /// then makes the folder with it (epoch + 1); cancelling leaves everything as it was.
    func testAddFolderAfterRemovedPeerAsksForNewKey() async throws {
        let c = await mac("c", pro: true)
        var group = try SyncGroup.createWiFi(installID: try c.keychain.installID(random: SystemRandomSource()), random: SystemRandomSource())
        group.lanPeers = [try peer(group.groupID, name: "Old iPhone", revoked: true),
                          try peer(group.groupID, name: "Windows PC", revoked: false)]
        try commit(group, to: c)
        c.model.reload()

        await c.model.pickFolder(.add)
        expect(false, await c.model.submitFolder(password: Self.password, again: Self.password))
        let text = try XCTUnwrap(c.model.freshKeyText)
        XCTAssertEqual(text, SyncPageModel.lanRemovedFolderText(peers: ["Windows PC"]))
        XCTAssertTrue(text.contains("Until then they don't sync with this Mac.\n\nContinue?"))
        XCTAssertFalse(text.contains("Old iPhone"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: folder.appendingPathComponent(FolderLayout.keyringPath).path),
                       "nothing is written before the confirmation")

        expect(true, await c.model.submitFolder(password: Self.password, again: Self.password, freshKeyConfirmed: true),
               c.model.error ?? "")
        XCTAssertNil(c.model.freshKeyText)
        XCTAssertTrue(c.model.state?.hasFolder ?? false)
        XCTAssertEqual(c.model.state?.groupID, group.groupID)
        XCTAssertEqual(c.model.state?.epoch, group.epoch + 1)
        XCTAssertNotEqual(c.model.state?.key, group.key)
    }

    /// Choose the folder again on a vault that is no longer in a folder group never joins with an empty
    /// password, and does not count toward the wrong-password back-off.
    func testRepickNeverJoins() async throws {
        let a = await mac("a", pro: true)
        await a.model.pickFolder(.create)
        expect(true, await a.model.submitFolder(password: Self.password, again: Self.password), a.model.error ?? "")

        let clock = HandClock()
        let b = await mac("b", pro: false, clock: clock)
        for _ in 1...6 {
            await b.model.pickFolder(nil)
            XCTAssertEqual(b.model.error, SyncWording.errorText(reason: "not-joined"))
            XCTAssertNil(b.model.state, "no join happened")
        }
        XCTAssertNil(try b.keychain.readSlot(.folderBookmark))
        await b.model.pickFolder(.join)
        expect(true, await b.model.submitFolder(password: Self.password), b.model.error ?? "no back-off from the re-picks")
    }
}
