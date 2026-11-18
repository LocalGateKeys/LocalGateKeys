import XCTest
import AppShared
@testable import LocalGateKeys

/// Sub-plan 07 task 5h: the iPhone's Share and Join sheet model (`CollectionShareModel`), ports of the desktop
/// `CollectionShare.test.js`, over two `ShareDevice`s (SyncCoordinatorTests) sharing one memory folder.
@MainActor
final class CollectionShareModelTests: XCTestCase {
    static let password = SyncCoordinatorTests.sharePassword
    static let newPassword = SyncCoordinatorTests.newSharePassword
    var clock: TestClock!
    var folder: MemoryFolder!
    /// The stubbed device-owner check (Face ID / passcode): its answer and how often it was asked.
    var ownerConfirms = true
    var ownerAsks = 0

    override func setUp() async throws {
        clock = TestClock(try SyncVectors.lanNow())
        folder = MemoryFolder()
    }

    func device() -> ShareDevice { ShareDevice(folder: folder, clock: clock) }

    func model(_ d: ShareDevice, _ cid: String?) -> CollectionShareModel {
        let m = CollectionShareModel(collectionID: cid, sync: d.coordinator, folderName: { _ in "Family folder" },
                                     confirmOwner: { [unowned self] in
                                         self.ownerAsks += 1
                                         return self.ownerConfirms
                                     })
        m.reload()   // the sheet does this when it appears
        return m
    }

    /// A "Family" collection in `d`'s vault.
    func family(_ d: ShareDevice) throws -> String {
        let made = try CollectionCatalog.create(name: "Family", in: d.store.snapshot, now: clock.now)
        try d.store.commit(made.change)
        return made.id
    }

    /// The owner shares Family read-only as "Anna"; the member joins as "Ben" and the owner's run adopts the join.
    func sharedFamily() async throws -> (owner: ShareDevice, member: ShareDevice, cid: String, owned: CollectionShareModel) {
        let owner = device(), member = device()
        let cid = try family(owner)
        let owned = model(owner, cid)
        owned.pick(bookmark: [1], name: "Family folder")
        owned.name = "Anna"
        owned.password = Self.password
        owned.passwordAgain = Self.password
        let shared = await owned.share()
        XCTAssertTrue(shared, owned.error ?? "")
        clock.now += 1
        let joining = model(member, nil)
        joining.pick(bookmark: [2], name: "Family folder")
        joining.name = "Ben"
        joining.password = Self.password
        let joined = await joining.join()
        XCTAssertTrue(joined, joining.error ?? "")
        clock.now += 1
        await owner.coordinator.sync(.manual)
        owned.reload()
        return (owner, member, cid, owned)
    }

    // MARK: - Share a collection

    func test_shares_through_a_chosen_folder_with_the_password_typed_twice_and_the_edit_choice() async throws {
        let owner = device()
        let cid = try family(owner)
        let m = model(owner, cid)
        let before = try XCTUnwrap(m.summary)
        XCTAssertFalse(before.shared)
        XCTAssertNil(before.status)
        XCTAssertEqual(CollectionShareModel.modeFixedText, "This choice is fixed once the collection is shared. To change it, stop sharing and share the collection again.")
        XCTAssertTrue(CollectionShareModel.ownerLossText.contains("If that device is lost"))

        // No folder yet: refused, nothing shared, and the passwords are gone anyway.
        m.password = Self.password; m.passwordAgain = Self.password
        let noFolder = await m.share()
        XCTAssertFalse(noFolder)
        XCTAssertEqual(m.error, CollectionShareModel.chooseFolderFirstText)
        XCTAssertEqual(m.password, ""); XCTAssertEqual(m.passwordAgain, "")

        m.pick(bookmark: [1], name: "Family folder")
        m.name = "Anna"
        m.password = Self.password; m.passwordAgain = Self.password
        m.membersCanEdit = true
        let shared = await m.share()
        XCTAssertTrue(shared, m.error ?? "")
        XCTAssertEqual(m.password, ""); XCTAssertEqual(m.passwordAgain, "")
        XCTAssertNil(m.picked)
        let s = try XCTUnwrap(m.summary)
        XCTAssertTrue(s.shared); XCTAssertTrue(s.isOwner)
        XCTAssertEqual(s.mode, "edit")
        XCTAssertEqual(s.modeText, "Members can edit")
        XCTAssertEqual(s.folder, "Family folder")
        XCTAssertEqual(s.members.map(\.name), ["Anna"])
        XCTAssertEqual(s.members.first?.state, .owner)
        XCTAssertEqual(s.members.first?.stateText, "Shared it")
        XCTAssertEqual(s.members.first?.isSelf, true)
        XCTAssertEqual(s.members.first?.removable, false)
        XCTAssertEqual(m.message, "“Family” is shared. Tell the others the share password and where the folder is.")
        XCTAssertNotNil(folder.files[FolderLayout.keyringPath])
        // Neither the summary nor the model's description holds the password.
        XCTAssertFalse(String(describing: s).contains(Self.password))
    }

    func test_clears_the_password_after_a_refusal_too_and_the_free_plan_gets_the_upgrade_sheet() async throws {
        let owner = device()
        let cid = try family(owner)
        let m = model(owner, cid)
        m.pick(bookmark: [1], name: "Family folder")

        // A weak password or a mismatch is refused before anything runs.
        m.password = "short"; m.passwordAgain = "short"
        let weak = await m.share()
        XCTAssertFalse(weak)
        XCTAssertEqual(m.error, CollectionShareModel.passwordProblem("short", "short"))
        XCTAssertEqual(m.password, "")
        m.password = Self.password; m.passwordAgain = Self.newPassword
        let mismatch = await m.share()
        XCTAssertFalse(mismatch)
        XCTAssertEqual(m.error, String(localized: "The two passwords do not match."))
        XCTAssertEqual(m.passwordAgain, "")

        owner.pro.on = false
        m.password = Self.password; m.passwordAgain = Self.password
        let free = await m.share()
        XCTAssertFalse(free)
        XCTAssertTrue(m.showUpgrade)
        XCTAssertEqual(m.password, ""); XCTAssertEqual(m.passwordAgain, "")
        XCTAssertEqual(owner.shares.count, 0)
        XCTAssertNil(folder.files[FolderLayout.keyringPath])
        m.reload()
        XCTAssertEqual(m.summary?.isPro, false)
    }

    func test_sharing_asks_the_device_owner_first_and_a_refusal_shares_nothing() async throws {
        let owner = device()
        let cid = try family(owner)
        let m = model(owner, cid)
        m.pick(bookmark: [1], name: "Family folder")
        // Local refusals come before the owner check: a weak password never asks for Face ID.
        m.password = "short"; m.passwordAgain = "short"
        _ = await m.share()
        XCTAssertEqual(ownerAsks, 0)

        ownerConfirms = false
        let commits = owner.store.commits
        m.password = Self.password; m.passwordAgain = Self.password
        let refused = await m.share()
        XCTAssertFalse(refused)
        XCTAssertEqual(ownerAsks, 1)
        XCTAssertEqual(m.error, CollectionShareModel.ownerNotConfirmedText)
        XCTAssertEqual(m.password, ""); XCTAssertEqual(m.passwordAgain, "")
        XCTAssertEqual(owner.shares.count, 0)
        XCTAssertNil(owner.store.snapshot.shares)
        XCTAssertEqual(owner.store.commits, commits)
        XCTAssertNil(folder.files[FolderLayout.keyringPath])
        XCTAssertEqual(m.summary?.shared, false)
        XCTAssertNotNil(m.picked, "the folder stays picked for another try")

        ownerConfirms = true
        m.password = Self.password; m.passwordAgain = Self.password
        let shared = await m.share()
        XCTAssertTrue(shared, m.error ?? "")
        XCTAssertEqual(ownerAsks, 2)
        XCTAssertEqual(owner.shares.count, 1)
    }

    func test_join_approve_remove_and_leave_never_ask_the_device_owner() async throws {
        let (_, member, cid, owned) = try await sharedFamily()
        XCTAssertEqual(ownerAsks, 1, "only the share itself asked")
        owned.selectedPending = Set(owned.summary?.pending.map(\.id) ?? [])
        _ = await owned.approve()
        let mine = model(member, cid)
        _ = await mine.leave()
        XCTAssertEqual(ownerAsks, 1)
    }

    func test_a_folder_that_already_holds_a_share_is_refused_with_its_words() async throws {
        let (owner, _, _, _) = try await sharedFamily()
        let other = try CollectionCatalog.create(name: "Work", in: owner.store.snapshot, now: clock.now)
        try owner.store.commit(other.change)
        let m = model(owner, other.id)
        m.pick(bookmark: [1], name: "Family folder")
        m.password = Self.password; m.passwordAgain = Self.password
        let again = await m.share()
        XCTAssertFalse(again)
        XCTAssertEqual(m.error, CollectionShareModel.reasonText("folder-in-use"))
        XCTAssertEqual(m.error, "That folder already holds a sync group or another shared collection. Choose an empty folder.")
        XCTAssertEqual(m.password, "")
        XCTAssertFalse(m.summary?.shared ?? true)
    }

    // MARK: - Members

    func test_shows_who_shared_it_who_waits_and_who_was_removed_and_fixes_the_mode() async throws {
        let (owner, member, cid, owned) = try await sharedFamily()
        let s = try XCTUnwrap(owned.summary)
        XCTAssertEqual(s.mode, "read")
        XCTAssertEqual(s.modeText, "Members can only view")
        XCTAssertEqual(s.members.map(\.name), ["Anna", "Ben"])
        XCTAssertEqual(s.members.map(\.state), [.owner, .pending])
        XCTAssertEqual(s.members.map(\.stateText), ["Shared it", "Waiting for approval"])
        XCTAssertEqual(s.members.map(\.removable), [false, true])
        XCTAssertEqual(s.pending.map(\.name), ["Ben"])
        XCTAssertEqual(s.removed, [])

        // The member sees itself waiting, no Remove, nothing to approve and no removed names.
        let mine = model(member, cid)
        let ms = try XCTUnwrap(mine.summary)
        XCTAssertTrue(ms.shared); XCTAssertFalse(ms.isOwner)
        XCTAssertEqual(ms.members.first { $0.isSelf }?.name, "Ben")
        XCTAssertEqual(ms.members.first { $0.isSelf }?.state, .pending)
        XCTAssertTrue(ms.members.allSatisfy { !$0.removable })
        XCTAssertEqual(ms.pending, [])
        _ = owner
    }

    func test_lets_in_only_the_waiting_people_the_owner_ticks_by_name() async throws {
        let (owner, _, _, owned) = try await sharedFamily()
        let ben = try XCTUnwrap(owned.summary?.pending.first)
        // Nobody ticked: no confirmation, nothing approved.
        XCTAssertNil(owned.approvalNames)
        let none = await owned.approve()
        XCTAssertFalse(none)
        owned.selectedPending = [ben.id, "not-a-waiting-id"]
        XCTAssertEqual(owned.approvalNames, "Ben")
        XCTAssertEqual(CollectionShareModel.approveText(names: "Ben", collection: "Family"),
                       "Let these people into “Family”: Ben? Their devices then sync every item in this collection, and their edits count. Only approve names you recognise.")
        let approved = await owned.approve()
        XCTAssertTrue(approved, owned.error ?? "")
        XCTAssertEqual(owned.message, "Let in: Ben.")
        XCTAssertEqual(owned.summary?.pending, [])
        XCTAssertEqual(owned.summary?.members.map(\.state), [.owner, .member])
        XCTAssertEqual(owned.selectedPending, [])
        XCTAssertEqual(try ShareGroups.pendingMembers(in: owner.store.snapshot, groupID: try XCTUnwrap(owned.summary?.groupID)), [])
    }

    func test_removes_someone_with_a_new_share_password_and_the_removed_device_says_so() async throws {
        let (owner, member, cid, owned) = try await sharedFamily()
        owned.selectedPending = Set(owned.summary?.pending.map(\.id) ?? [])
        _ = await owned.approve()
        clock.now += 1
        await member.coordinator.sync(.manual)
        let ben = try XCTUnwrap(owned.summary?.members.first { $0.name == "Ben" })
        XCTAssertEqual(CollectionShareModel.removeHint("Ben"),
                       "Ben knows the current share password, so removing them needs a new one. The others keep syncing without typing it; give it only to people you invite later.")

        // The owner cannot remove itself; a mismatch is refused; both clear the fields.
        let anna = try XCTUnwrap(owned.summary?.members.first { $0.isSelf })
        owned.newPassword = Self.newPassword; owned.newPasswordAgain = Self.newPassword
        let selfRemoval = await owned.remove(anna.id)
        XCTAssertFalse(selfRemoval)
        XCTAssertEqual(owned.error, CollectionShareModel.notAMemberText)
        owned.newPassword = Self.newPassword; owned.newPasswordAgain = "a different long phrase 77!"
        let mismatch = await owned.remove(ben.id)
        XCTAssertFalse(mismatch)
        XCTAssertEqual(owned.newPassword, ""); XCTAssertEqual(owned.newPasswordAgain, "")

        clock.now += 1
        owned.newPassword = Self.newPassword; owned.newPasswordAgain = Self.newPassword
        let removed = await owned.remove(ben.id)
        XCTAssertTrue(removed, owned.error ?? "")
        XCTAssertEqual(owned.newPassword, ""); XCTAssertEqual(owned.newPasswordAgain, "")
        XCTAssertEqual(owned.message, "Ben was removed.")
        XCTAssertEqual(owned.summary?.members.map(\.name), ["Anna"])
        XCTAssertEqual(owned.summary?.removed.map(\.name), ["Ben"])

        // The removed member: the collection stays, no longer shared, and says where its items went.
        clock.now += 1
        await member.coordinator.sync(.manual)
        let gone = model(member, cid)
        let s = try XCTUnwrap(gone.summary)
        XCTAssertFalse(s.shared)
        XCTAssertEqual(s.status?.text, "You were removed from this shared collection. Its items on this iPhone were moved to the trash.")
        XCTAssertNotNil(member.coordinator.removedShares[cid])
        XCTAssertEqual(CollectionShareModel.removedBadgeText, "Removed, items moved to the trash")
        _ = owner
    }

    func test_shows_a_merged_keyring_as_information_and_a_lost_join_with_join_again() async throws {
        let owner = device()
        let cid = try family(owner)
        let m = model(owner, cid)
        m.pick(bookmark: [1], name: "Family folder")
        m.password = Self.password; m.passwordAgain = Self.password
        _ = await m.share()
        let gid = try XCTUnwrap(m.summary?.groupID)
        let snapshot = owner.store.snapshot

        let merged = try XCTUnwrap(try CollectionShareModel.makeSummary(
            collectionID: cid, snapshot: snapshot, issues: [gid: [SyncIssue("keyring-merged")]], removedShares: [:],
            isPro: true, folderName: { _ in nil }))
        XCTAssertEqual(merged.status?.severity, .notice)
        XCTAssertEqual(merged.status?.text, "Someone joined while you were letting others in. They are waiting for your approval below.")
        XCTAssertEqual(merged.status?.joinAgain, false)
        XCTAssertEqual(merged.folder, "")

        let lost = try XCTUnwrap(try CollectionShareModel.makeSummary(
            collectionID: cid, snapshot: snapshot,
            issues: [gid: [SyncIssue("keyring-merged"), SyncIssue("superseded")]], removedShares: [:],
            isPro: true, folderName: { _ in nil }))
        XCTAssertEqual(lost.status?.severity, .warning, "a warning outranks information")
        XCTAssertEqual(lost.status?.joinAgain, true)
        XCTAssertEqual(lost.status?.text, "Someone else joined at the same moment, so your join did not reach the others. Join again with the share password.")

        // Join again without the password is refused before anything runs.
        let empty = await m.rejoin()
        XCTAssertFalse(empty)
        XCTAssertEqual(m.error, CollectionShareModel.enterPasswordText)
        // With one: the coordinator's join again runs and the field is emptied whatever it answers.
        m.password = Self.password
        _ = await m.rejoin()
        XCTAssertEqual(m.password, "")
    }

    // MARK: - Join a shared collection

    func test_joins_through_a_folder_and_a_password_and_then_shows_that_collection() async throws {
        let owner = device()
        let cid = try family(owner)
        let owned = model(owner, cid)
        owned.pick(bookmark: [1], name: "Family folder")
        owned.password = Self.password; owned.passwordAgain = Self.password
        _ = await owned.share()

        let member = device()
        let m = model(member, nil)
        XCTAssertNil(m.summary)
        // A wrong password: refused with the share wording, nothing joined, the field emptied.
        m.pick(bookmark: [2], name: "Family folder")
        m.password = "not the share password at all 9"
        let wrong = await m.join()
        XCTAssertFalse(wrong)
        XCTAssertEqual(m.error, "That share password is not right for this folder.")
        XCTAssertEqual(m.password, "")
        XCTAssertNil(m.collectionID)
        XCTAssertEqual(member.shares.count, 0)

        clock.now += 1
        m.password = Self.password
        let joined = await m.join()
        XCTAssertTrue(joined, m.error ?? "")
        XCTAssertEqual(m.password, "")
        XCTAssertEqual(m.collectionID, cid)
        XCTAssertEqual(m.message, "You joined “Family”. Its items start to sync once the person who shared it lets you in.")
        let s = try XCTUnwrap(m.summary)
        XCTAssertTrue(s.shared); XCTAssertFalse(s.isOwner)
        XCTAssertEqual(s.members.first { $0.isSelf }?.name, CollectionShareModel.memberName(""))
        XCTAssertEqual(CollectionCatalog.collections(in: member.store.snapshot).map(\.id), [cid])
    }

    func test_the_free_plan_cannot_join_and_gets_the_upgrade_sheet() async throws {
        let member = device()
        member.pro.on = false
        let m = model(member, nil)
        m.pick(bookmark: [2], name: "Family folder")
        m.password = Self.password
        let joined = await m.join()
        XCTAssertFalse(joined)
        XCTAssertTrue(m.showUpgrade)
        XCTAssertEqual(m.password, "")
        XCTAssertNil(member.store.snapshot.shares)
    }

    func test_join_without_a_folder_or_password_is_refused() async throws {
        let m = model(device(), nil)
        m.password = Self.password
        let noFolder = await m.join()
        XCTAssertFalse(noFolder)
        XCTAssertEqual(m.error, CollectionShareModel.chooseFolderFirstText)
        m.pick(bookmark: [2], name: "Family folder")
        let noPassword = await m.join()
        XCTAssertFalse(noPassword)
        XCTAssertEqual(m.error, CollectionShareModel.enterPasswordText)
        // An empty folder holds no share.
        m.password = Self.password
        let empty = await m.join()
        XCTAssertFalse(empty)
        XCTAssertEqual(m.error, "That folder holds no shared collection. Choose the folder the person who shared it gave you.")
    }

    // MARK: - Leave and stop sharing

    func test_the_owner_stops_sharing_and_a_member_leaves_and_the_collections_stay() async throws {
        let (owner, member, cid, owned) = try await sharedFamily()
        let mine = model(member, cid)
        let left = await mine.leave()
        XCTAssertTrue(left, mine.error ?? "")
        XCTAssertEqual(mine.message, "You left “Family”.")
        XCTAssertEqual(mine.summary?.shared, false)
        XCTAssertEqual(CollectionCatalog.collections(in: member.store.snapshot).map(\.id), [cid])

        let stopped = await owned.leave()
        XCTAssertTrue(stopped, owned.error ?? "")
        XCTAssertEqual(owned.message, "“Family” is no longer shared from this iPhone.")
        XCTAssertEqual(owned.summary?.shared, false)
        XCTAssertEqual(owner.shares.count, 0)
        XCTAssertEqual(CollectionCatalog.collections(in: owner.store.snapshot).map(\.id), [cid])
        XCTAssertEqual(CollectionShareModel.stopText("Family"),
                       "Stop sharing “Family” on this iPhone? The collection and its items stay here. The others keep their copies, but nobody can let people in or remove them any more.")
    }

    func test_a_collection_shared_from_two_devices_says_so() async throws {
        // Re-review wave B, B1: another of this person's devices shares Family too (its link is stored here).
        let (owner, _, cid, owned) = try await sharedFamily()
        XCTAssertEqual(owned.summary?.sharedTwice, false)
        let s = owner.store.snapshot
        var records = s.records
        records[CollectionStates.linkPrefix + cid] =
            CollectionStates.wrapper(CollectionStates.link(collectionID: cid, mode: "edit", role: "owner"))
        try owner.store.commit(StoreChange(baseRevision: s.revision, records: records, meta: s.meta, sync: s.sync))
        owned.reload()
        XCTAssertEqual(owned.summary?.sharedTwice, true)
        XCTAssertEqual(CollectionShareModel.sharedTwiceText,
                       "This collection is shared from two of your devices; stop sharing or leave it on one.")
    }

    func test_a_received_share_link_offers_forget_instead_of_share() async throws {
        // Final review finding 4: another of this person's devices shared Family and was lost.
        let d = device()
        let cid = try family(d)
        let s = d.store.snapshot
        var records = s.records
        records[CollectionStates.linkPrefix + cid] =
            CollectionStates.wrapper(CollectionStates.link(collectionID: cid, mode: "read", role: "owner"))
        try d.store.commit(StoreChange(baseRevision: s.revision, records: records, meta: s.meta, sync: s.sync))
        let m = model(d, cid)
        XCTAssertEqual(m.summary?.shared, false)
        XCTAssertEqual(m.summary?.linked, CollectionShares.Link(mode: "read", role: "owner"))
        let forgot = await m.forgetLink()
        XCTAssertTrue(forgot, m.error ?? "")
        XCTAssertEqual(m.message, "The share link of “Family” was forgotten.")
        XCTAssertNil(m.summary?.linked)
        XCTAssertNil(d.store.snapshot.records[CollectionStates.linkPrefix + cid])
        // Nothing left to forget; the collection can be shared from here now.
        let again = await m.forgetLink()
        XCTAssertFalse(again)
        XCTAssertEqual(CollectionShareModel.forgetLinkText("Family"),
                       "Forget the share link of “Family”? Do this only if the device that shares it was lost or reset. The collection and its items stay. If that device still exists, it shares the link again at its next sync.")
    }

    // MARK: - Share v2 upgrade

    func test_a_new_share_is_share_v2_and_offers_no_upgrade_which_is_refused_with_its_words() async throws {
        // Every share made now is share v2 (keyring format 3); only the owner of a share v1 collection is offered the
        // upgrade, so neither the owner nor the member sees it here (no app path makes a share v1 keyring).
        let (owner, member, cid, owned) = try await sharedFamily()
        let s = try XCTUnwrap(owned.summary)
        let gid = try XCTUnwrap(s.groupID)
        XCTAssertFalse(s.canUpgradeShare)
        XCTAssertFalse(ShareGroups.needsUpgrade(in: owner.store.snapshot, groupID: gid))
        XCTAssertEqual(model(member, cid).summary?.canUpgradeShare, false)
        let keyringBefore = folder.files[FolderLayout.keyringPath]

        // The model refuses before any work, and the passwords are gone anyway.
        owned.password = Self.password; owned.passwordAgain = Self.password
        let upgraded = await owned.upgradeShare()
        XCTAssertFalse(upgraded)
        XCTAssertEqual(owned.error, "This shared collection is already upgraded.")
        XCTAssertEqual(owned.password, ""); XCTAssertEqual(owned.passwordAgain, "")

        // The coordinator: a mismatch first, then the share group's own refusal; nothing in the folder changes.
        let mismatch = await owner.coordinator.upgradeShare(groupID: gid, password: Self.password, again: Self.newPassword)
        XCTAssertFalse(mismatch)
        XCTAssertEqual(owner.coordinator.shareActionReason, "password-mismatch")
        let already = await owner.coordinator.upgradeShare(groupID: gid, password: Self.password, again: Self.password)
        XCTAssertFalse(already)
        XCTAssertEqual(owner.coordinator.shareActionReason, "already-upgraded")
        let notOwner = await member.coordinator.upgradeShare(groupID: gid, password: Self.password, again: Self.password)
        XCTAssertFalse(notOwner)
        XCTAssertEqual(member.coordinator.shareActionReason, "not-owner")
        XCTAssertEqual(folder.files[FolderLayout.keyringPath], keyringBefore)
    }

    func test_upgrade_and_update_required_words() {
        XCTAssertEqual(CollectionShareModel.reasonText("already-upgraded"), "This shared collection is already upgraded.")
        let update = "This shared collection needs a newer version of LocalGateKeys. Update the app to keep syncing it."
        XCTAssertEqual(CollectionShareModel.reasonText("newer-format"), update)
        XCTAssertEqual(CollectionShareModel.reasonText("update-required"), update)
        XCTAssertEqual(CollectionShareModel.upgradeTitle, "Make this share safer")
        XCTAssertTrue(CollectionShareModel.upgradeText.hasPrefix("Right now anyone who knows the share password"))
        XCTAssertEqual(CollectionShareModel.Words.upgradeButton, "Upgrade share")
        XCTAssertEqual(CollectionShareModel.upgradedDoneText, "Share upgraded. Only the people you let in can open its items.")
    }

    // MARK: - Rules

    func test_member_names_and_refusal_words() {
        XCTAssertEqual(CollectionShareModel.memberName("  "), SyncWording.deviceName)
        XCTAssertEqual(CollectionShareModel.memberName(" Anna\u{202E} "), "Anna")
        XCTAssertLessThanOrEqual(CollectionShareModel.memberName(String(repeating: "é", count: 60)).utf8.count, 64)
        XCTAssertEqual(CollectionShareModel.displayName(nil), "Unnamed device")
        XCTAssertEqual(CollectionShareModel.displayName("Ben\nB"), "Ben B")
        XCTAssertEqual(CollectionShareModel.reasonText("password"), "That share password is not right for this folder.")
        XCTAssertEqual(CollectionShareModel.reasonText("not-owner"), "Only the device that shared this collection can do that.")
        XCTAssertEqual(CollectionShareModel.reasonText("pro-required"), SyncWording.shareCopy(SyncIssue("pro-required")))
        XCTAssertEqual(CollectionShareModel.reasonText("busy"), SyncWording.errorText(reason: "busy"))
        XCTAssertNil(CollectionShareModel.passwordProblem(Self.password, Self.password))
        XCTAssertNotNil(CollectionShareModel.passwordProblem("passwordpassword", "passwordpassword"))
    }

    func test_a_missing_collection_says_so() throws {
        let m = model(device(), "00000000-0000-4000-8000-000000000000")
        XCTAssertNil(m.summary)
        XCTAssertEqual(m.error, "That collection no longer exists.")
    }
}
