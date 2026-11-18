import XCTest
import LGKCore
@testable import AppSharedMac

/// A clock the test moves by hand, shared by both Macs.
private final class ShareHandClock: UnixClock, @unchecked Sendable {
    var now: Int64 = 1_800_000_000
}

/// Never answers: these Macs have no Wi-Fi peer.
private struct ShareNoLan: LanTransporting {
    func exchangeViews(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: [ItemState],
                       ownCounter: Int64) async throws -> [ItemState] { throw LanSocketError("refused") }
    func enroll(endpoint: LanEndpoint, request: [UInt8], onConnected: @escaping @Sendable () -> Void) async throws -> [UInt8] {
        throw LanSocketError("refused")
    }
}

/// Shared collections on the Mac (sub-plan 07 task 5i): two Macs, each with its own vault, Keychain, Recently deleted and
/// coordinator built as `MacSyncEnvironment.makeCoordinator` builds it (`SyncSourceStore`, `storeMovesDeletesToTrash`),
/// sharing through one real folder.
@MainActor
final class MacCollectionShareTests: XCTestCase {
    private static let sharePassword = "violet-harbor-canyon-47-quilt"
    private static let newSharePassword = "another very long passphrase 42?"
    private static let master = "correct horse"

    /// One Mac.
    @MainActor
    private struct Mac {
        let lock: MacLockModel
        let coordinator: SyncCoordinator
        let gate: StrictItemGate
        var store: any ItemStore { lock.store! }
    }

    private var root: URL!
    private var folder: URL!
    private var suites: [String] = []
    private let clock = ShareHandClock()

    override func setUp() async throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-macshare-\(UUID().uuidString)", isDirectory: true)
        folder = root.appendingPathComponent("Shared", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: root)
        for s in suites { UserDefaults().removePersistentDomain(forName: s) }
    }

    private func mac(_ name: String) async throws -> Mac {
        let suite = "lgk-macshare-\(UUID().uuidString)"; suites.append(suite)
        let vault = MacVault(directory: root.appendingPathComponent(name, isDirectory: true), keychain: InMemoryKeychainVault(),
                             biometric: FakeBiometricKeyStore(),
                             kdfParams: MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1))
        let lock = MacLockModel(vault: vault, settings: AppSettings(defaults: UserDefaults(suiteName: suite)!),
                                events: FakeSystemEvents(), startTimer: false)
        await lock.create(password: Self.master, confirm: Self.master, touchID: false)
        XCTAssertEqual(lock.state, .unlocked)
        let store = try XCTUnwrap(lock.store as? PublishingItemStore)
        let deps = SyncDependencies(keychain: InMemoryKeychainVault(), folders: SecurityScopedFolderOpener(), lan: ShareNoLan(),
                                    autoFill: NoAutoFillRefresh(), random: SystemRandomSource(), clock: clock, licenseKeys: [:])
        let coordinator = SyncCoordinator(store: SyncSourceStore(base: store, local: lock), deps: deps)
        // As `MacSyncEnvironment.makeCoordinator`: Recently deleted is the lock model's, and the store already moves
        // every live item a commit takes out there.
        coordinator.shareTrash = lock
        coordinator.storeMovesDeletesToTrash = true
        coordinator.isPro = { true }
        return Mac(lock: lock, coordinator: coordinator, gate: StrictItemGate(passwords: lock))
    }

    /// A "Family" collection holding one note: (collection id, item id).
    private func familyNote(_ m: Mac) throws -> (cid: String, itemID: String) {
        let made = try CollectionCatalog.create(name: "Family", in: try m.store.load(), now: clock.now)
        try m.store.commit(made.change)
        let snap = try m.store.load()
        var records = snap.records
        let id = UUID().uuidString.lowercased()
        let r: JSONValue = .object(["id": .string(id), "kind": .string("note"), "title": .string("Wi-Fi"),
                                    "created_at": .int(clock.now), "updated_at": .int(clock.now),
                                    "favorite": .bool(false), "tags": .array([]),
                                    "payload": .object(["body": .string("x"), "fields": .array([]), "template_id": .null])])
        records[id] = Wrapper.make(ns: .item, record: try Normalise.normalForm(ns: .item, record: r))
        try m.store.commit(StoreChange(baseRevision: snap.revision, records: records, meta: snap.meta, sync: snap.sync))
        try m.store.commit(try XCTUnwrap(try CollectionCatalog.setMemberships(itemID: id, kind: "note", to: [made.id],
                                                                              in: try m.store.load())))
        return (made.id, id)
    }

    private var bookmark: [UInt8] { get throws { try SecurityScopedFolderOpener().bookmark(for: folder) } }

    private func trashIDs(_ m: Mac) -> [String] {
        (m.lock.localData?.trash ?? []).compactMap { row -> String? in
            guard case .object(let r)? = try? row.record(), case .string(let id)? = r["id"] else { return nil }
            return id
        }
    }

    /// Waits (main-actor turns, bounded) until the gate shows a prompt.
    private func waitForPrompt(_ gate: StrictItemGate) async {
        for _ in 0..<10_000 where gate.pending == nil { await Task.yield() }
    }

    /// Owner shares `cid` (through the coordinator), member joins, owner lets it in, member syncs: the group id.
    private func shareAndJoin(_ owner: Mac, _ member: Mac, _ cid: String, canEdit: Bool) async throws -> String {
        let created = await owner.coordinator.createShare(collectionID: cid, bookmark: try bookmark, password: Self.sharePassword,
                                                          deviceName: "Owner", membersCanEdit: canEdit)
        let gid = try XCTUnwrap(created?.groupID, owner.coordinator.shareActionReason ?? "")
        clock.now += 1
        let joined = await member.coordinator.joinShare(bookmark: try bookmark, password: Self.sharePassword, deviceName: "Member")
        XCTAssertEqual(joined?.groupID, gid, member.coordinator.shareActionReason ?? "")
        clock.now += 1
        await owner.coordinator.sync(.manual)   // adopts the join: the member waits for approval
        let waiting = try ShareGroups.pendingMembers(in: try owner.store.load(), groupID: gid).map(\.deviceID)
        XCTAssertEqual(waiting.count, 1)
        let approved = await owner.coordinator.approveShare(groupID: gid, deviceIDs: waiting)
        XCTAssertNotNil(approved, owner.coordinator.shareActionReason ?? "")
        clock.now += 1
        await member.coordinator.sync(.manual)
        return gid
    }

    // MARK: - Tests

    /// Sharing asks for the master password first (desktop `_confirm_handover`): a cancelled prompt shares nothing and
    /// empties the password fields; a wrong password keeps asking; the right one shares.
    func testSharingAsksForTheMasterPasswordFirst() async throws {
        let owner = try await mac("owner")
        let (cid, _) = try familyNote(owner)
        let model = MacCollectionSharePage.makeModel(collectionID: cid, sync: owner.coordinator, gate: owner.gate)
        model.reload()
        XCTAssertEqual(model.summary?.shared, false)
        model.pick(bookmark: try bookmark, name: "Shared")
        model.name = "Anna"

        // Cancelled: nothing shared, nothing in the folder.
        model.password = Self.sharePassword; model.passwordAgain = Self.sharePassword
        let first = Task { await model.share() }
        await waitForPrompt(owner.gate)
        XCTAssertEqual(owner.gate.pending?.title, MacCollectionSharePage.shareGateTitle)
        XCTAssertEqual(owner.gate.pending?.level, .strict, "the master password, never Touch ID")
        XCTAssertEqual(model.password, "", "the fields are emptied as soon as the action read them")
        owner.gate.cancel()
        let cancelled = await first.value
        XCTAssertFalse(cancelled)
        XCTAssertEqual(model.error, CollectionShareModel.ownerNotConfirmedText)
        XCTAssertEqual(model.error, "Sharing needs your master password. Nothing was shared.")
        XCTAssertEqual(try ShareGroups.records(in: try owner.store.load()).count, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: folder.appendingPathComponent(FolderLayout.keyringPath).path))

        // A weak password never asks.
        model.password = "short"; model.passwordAgain = "short"
        let weak = await model.share()
        XCTAssertFalse(weak)
        XCTAssertNil(owner.gate.pending)

        // Wrong, then right: shared.
        model.password = Self.sharePassword; model.passwordAgain = Self.sharePassword
        let second = Task { await model.share() }
        await waitForPrompt(owner.gate)
        await owner.gate.submit("not the master password")
        XCTAssertNotNil(owner.gate.pending, "a wrong password keeps asking")
        XCTAssertNotNil(owner.gate.message)
        await owner.gate.submit(Self.master)
        let shared = await second.value
        XCTAssertTrue(shared, model.error ?? "")
        XCTAssertEqual(model.summary?.shared, true)
        XCTAssertEqual(model.summary?.isOwner, true)
        XCTAssertEqual(try ShareGroups.records(in: try owner.store.load()).count, 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: folder.appendingPathComponent(FolderLayout.keyringPath).path))
        XCTAssertEqual(model.summary?.members.first?.name, "Anna")
    }

    /// The 5g review's Mac case: the Mac's coordinator store (`SyncSourceStore`) moves a share's deletes to Recently
    /// deleted (`storeMovesDeletesToTrash`), once, with the item's collection; the share reports no problem.
    func testStoreMovesDeletesToTrash() async throws {
        let owner = try await mac("owner"), member = try await mac("member")
        let (cid, itemID) = try familyNote(owner)
        let gid = try await shareAndJoin(owner, member, cid, canEdit: true)
        XCTAssertNotNil(try member.store.load().records[itemID], "the shared note arrived: \(member.coordinator.shareIssues)")
        XCTAssertEqual(CollectionCatalog.memberships(of: itemID, in: try member.store.load()), [cid])

        // The owner deletes the note; its share run publishes the delete, the member's run applies it.
        let trash = TrashModel(store: owner.store, local: owner.lock, isPro: { true }, onNeedsPro: { _ in }, activity: nil)
        try trash.moveToTrash(id: itemID)
        clock.now += 1
        await owner.coordinator.sync(.manual)
        clock.now += 1
        await member.coordinator.sync(.manual)

        XCTAssertNil(try member.store.load().records[itemID], "\(member.coordinator.shareIssues)")
        XCTAssertEqual(trashIDs(member), [itemID], "in Recently deleted once, never lost and never twice")
        let row = try XCTUnwrap(member.lock.localData?.trash.first)
        XCTAssertEqual(try row.record().objectValue?["collection_ids"], .array([.string(cid)]))
        let issues = member.coordinator.shareIssues[gid] ?? []
        XCTAssertFalse(issues.contains { ["trash-full", "item-error", "busy"].contains($0.kind) }, "\(issues)")
    }

    /// A view-only share on the member Mac: the collection and its items are never changed there. Removing the member
    /// asks for no master password (a confirmation only, as on the desktop), and the removal moves the member's copies
    /// to its Recently deleted.
    func testViewOnlyShareAndRemovalOnTheMac() async throws {
        let owner = try await mac("owner"), member = try await mac("member")
        let (cid, itemID) = try familyNote(owner)
        _ = try await shareAndJoin(owner, member, cid, canEdit: false)
        XCTAssertNotNil(try member.store.load().records[itemID], "\(member.coordinator.shareIssues)")

        let collections = MacCollectionsModel(store: member.store, local: member.lock, activity: nil)
        collections.reload()
        let row = try XCTUnwrap(collections.rows.first { $0.id == cid })
        XCTAssertTrue(row.isShared)
        XCTAssertTrue(row.isReadOnly)
        XCTAssertTrue(collections.isReadOnly(itemID: itemID))
        XCTAssertFalse(collections.rename(cid, to: "Ours"))
        XCTAssertFalse(collections.delete(cid))
        XCTAssertFalse(collections.setMemberships(of: itemID, kind: "note", to: []))
        let trash = TrashModel(store: member.store, local: member.lock, isPro: { true }, onNeedsPro: { _ in }, activity: nil)
        XCTAssertThrowsError(try trash.moveToTrash(id: itemID)) { XCTAssertEqual($0 as? TrashModel.Failure, .readOnly) }
        XCTAssertThrowsError(try ItemActions.setFavourite(id: itemID, true, store: member.store, clock: clock))
        let list = VaultListModel(store: member.store); list.reload()
        let editor = MacEditorSession(store: member.store, pro: ProModel(purchases: NoPurchases()), onNeedsPro: { _ in })
        editor.collections = collections
        editor.startEdit(try XCTUnwrap(list.items.first { $0.id == itemID }))
        XCTAssertTrue(editor.isReadOnly)
        editor.model?.set("title", "Changed")
        XCTAssertEqual(editor.save(), .invalid)

        // The owner removes the member from the Mac's share page: a confirmation, then the new password; no prompt.
        let page = MacCollectionSharePage.makeModel(collectionID: cid, sync: owner.coordinator, gate: owner.gate)
        page.reload()
        let target = try XCTUnwrap(page.summary?.members.first { $0.removable })
        page.newPassword = Self.newSharePassword; page.newPasswordAgain = Self.newSharePassword
        let removed = await page.remove(target.id)
        XCTAssertTrue(removed, page.error ?? "")
        XCTAssertNil(owner.gate.pending, "removing a person asks for no master password")
        clock.now += 1
        await member.coordinator.sync(.manual)
        XCTAssertNil(try member.store.load().records[itemID])
        XCTAssertEqual(trashIDs(member), [itemID], "the removed member's copy is in its Recently deleted")
        XCTAssertNotNil(member.coordinator.removedShares[cid])
        XCTAssertEqual(try ShareGroups.records(in: try member.store.load()).count, 0)
    }

    /// The share page's join path on the Mac: the folder and the share password; Pro is required (the upgrade sheet).
    func testJoiningFromTheSharePage() async throws {
        let owner = try await mac("owner"), member = try await mac("member")
        let (cid, _) = try familyNote(owner)
        let created = await owner.coordinator.createShare(collectionID: cid, bookmark: try bookmark, password: Self.sharePassword,
                                                          deviceName: "Owner", membersCanEdit: true)
        XCTAssertNotNil(created, owner.coordinator.shareActionReason ?? "")

        let join = MacCollectionSharePage.makeModel(collectionID: nil, sync: member.coordinator, gate: member.gate)
        member.coordinator.isPro = { false }
        join.pick(bookmark: try bookmark, name: "Shared")
        join.password = Self.sharePassword
        let free = await join.join()
        XCTAssertFalse(free)
        XCTAssertTrue(join.showUpgrade)
        XCTAssertEqual(join.password, "")

        member.coordinator.isPro = { true }
        join.showUpgrade = false
        join.password = "wrong share password 2026!"
        let wrong = await join.join()
        XCTAssertFalse(wrong)
        XCTAssertEqual(join.error, CollectionShareModel.reasonText("password"))
        join.password = Self.sharePassword
        clock.now += 1
        let joined = await join.join()
        XCTAssertTrue(joined, join.error ?? "")
        XCTAssertEqual(join.collectionID, cid)
        XCTAssertNil(member.gate.pending, "joining asks for no master password")
        XCTAssertEqual(CollectionShareModel.memberName(""), "Mac", "a Mac's default name for the others")
    }

    /// A share made on the Mac is share v2 (keyring format 3): the share page offers no upgrade, and the upgrade is
    /// refused with its words, asking for no master password (only the owner of a share v1 collection sees it).
    func testANewShareIsShareV2AndOffersNoUpgrade() async throws {
        let owner = try await mac("owner")
        let (cid, _) = try familyNote(owner)
        let created = await owner.coordinator.createShare(collectionID: cid, bookmark: try bookmark, password: Self.sharePassword,
                                                          deviceName: "Owner", membersCanEdit: true)
        let group = try XCTUnwrap(created, owner.coordinator.shareActionReason ?? "")
        XCTAssertEqual(group.version, 2)
        let page = MacCollectionSharePage.makeModel(collectionID: cid, sync: owner.coordinator, gate: owner.gate)
        page.reload()
        XCTAssertEqual(page.summary?.canUpgradeShare, false)
        page.password = Self.sharePassword; page.passwordAgain = Self.sharePassword
        let upgraded = await page.upgradeShare()
        XCTAssertFalse(upgraded)
        XCTAssertEqual(page.error, CollectionShareModel.reasonText("already-upgraded"))
        XCTAssertEqual(page.password, ""); XCTAssertEqual(page.passwordAgain, "")
        XCTAssertNil(owner.gate.pending, "the upgrade asks for no master password")
    }
}
