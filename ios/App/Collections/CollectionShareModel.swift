import Foundation
import LocalAuthentication
import Observation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// The Share section of one collection and the Join sheet (sub-plan 07 task 5h; desktop `app/collection_share.py`
/// `CollectionShareService.view` and its actions). The summary is read from the store's share records and the
/// coordinator's last share runs: role, mode, the fixed-mode hint, folder, members with their state, waiting and
/// removed names, the status and the owner-loss help. It never holds a key, a keyring or a stored password: the
/// password fields below are what the person is typing, and every action empties them as soon as it has read them.
///
/// Actions go through the coordinator (`SyncCoordinator.createShare` and the other share actions), which runs them under
/// its action lock. Creating and joining need Pro: on the free plan `showUpgrade` is set instead. No UIKit, so the Mac
/// can share it (task 5i).
@MainActor @Observable
final class CollectionShareModel {
    enum MemberState: String, Equatable { case owner, member, pending }

    struct Member: Identifiable, Equatable {
        let id: String
        let name: String
        let state: MemberState
        let stateText: String
        let isSelf: Bool
        /// Only the owner removes, never itself.
        let removable: Bool
    }

    struct Removed: Identifiable, Equatable {
        let id: Int
        let name: String
        let at: Int64
    }

    /// What the Share section shows (desktop `view`).
    struct Summary: Equatable {
        let collectionID: String
        let collectionName: String
        let isPro: Bool
        let shared: Bool
        /// The share group (nil while not shared).
        let groupID: String?
        let isOwner: Bool
        /// "edit" or "read" (nil while not shared).
        let mode: String?
        let modeText: String?
        let folder: String
        let members: [Member]
        /// Waiting for the owner's approval (the owner only).
        let pending: [Member]
        /// People the owner removed (the owner only).
        let removed: [Removed]
        /// The last share run's most important issue, or this device's removal while not shared.
        let status: SyncWording.ShareStatus?
        /// Not shared here, but another of this person's devices shares it (a received share link): Forget share link
        /// is offered instead of Share (final review finding 4). Nil otherwise.
        var linked: CollectionShares.Link? = nil
        /// Shared here and from another of this person's devices too (re-review wave B, B1): the screens warn.
        var sharedTwice = false
        /// This device owns a share v1 collection (`ShareGroups.needsUpgrade`): the screens offer the upgrade to share
        /// v2, where only the people let in can open its items.
        var canUpgradeShare = false
    }

    /// A folder picked for Share or Join, before the action uses it.
    struct PickedFolder: Equatable {
        let bookmark: [UInt8]
        let name: String
    }

    /// The collection shown (nil: the Join sheet before a join worked).
    private(set) var collectionID: String?
    private(set) var summary: Summary?
    /// The last action's result.
    private(set) var message: String?
    /// The last refusal.
    private(set) var error: String?
    /// The free plan tried to share or join: the upgrade sheet.
    var showUpgrade = false
    private(set) var busy = false

    // What the person is typing; each action empties the password fields.
    var name = ""
    var password = ""
    var passwordAgain = ""
    var membersCanEdit = false
    var newPassword = ""
    var newPasswordAgain = ""
    private(set) var picked: PickedFolder?
    /// Waiting people ticked for Let them in.
    var selectedPending: Set<String> = []

    @ObservationIgnored let sync: SyncCoordinator
    @ObservationIgnored private let folderName: ([UInt8]) -> String?
    /// The device owner proves it is them before a collection's items go to a folder (desktop `_confirm_handover`,
    /// create only): on the iPhone Face ID, Touch ID or the passcode, never a reused unlock; on the Mac the master
    /// password through `StrictItemGate` (passed in by the share page). Tests inject a stub.
    @ObservationIgnored private let confirmOwner: @MainActor () async -> Bool

    /// Cheap: nothing is read until `reload()` (the sheet calls it when it appears), so a view that rebuilds this
    /// model on every redraw does no store work.
    init(collectionID: String?, sync: SyncCoordinator,
         folderName: @escaping ([UInt8]) -> String? = CollectionShareModel.bookmarkName,
         confirmOwner: @escaping @MainActor () async -> Bool = CollectionShareModel.deviceOwnerCheck) {
        self.collectionID = collectionID; self.sync = sync; self.folderName = folderName
        self.confirmOwner = confirmOwner
    }

    /// `LAContext` `.deviceOwnerAuthentication` (biometrics or the passcode) with no reuse window; on the iPhone with
    /// the app password on, `AppPasswordGate` instead (never the passcode).
    static func deviceOwnerCheck() async -> Bool {
        #if os(iOS)
        // Says why when the check cannot run: no passcode, Face ID locked (review L3).
        return await AppPasswordGate.confirmOwner(confirmToShareText)
        #else
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: confirmToShareText)) ?? false
        #endif
    }

    // MARK: - Reading

    func reload() {
        guard let collectionID else { summary = nil; return }
        do {
            summary = try Self.makeSummary(collectionID: collectionID, snapshot: try sync.store.load(),
                                       issues: sync.shareIssues, removedShares: sync.removedShares, isPro: sync.isPro(),
                                       folderName: folderName)
            if summary == nil { error = Self.reasonText("no-collection") }
        } catch {
            summary = nil
            self.error = Self.reasonText(ShareSync.reason(error))
        }
        let waiting = Set(summary?.pending.map(\.id) ?? [])
        selectedPending = selectedPending.intersection(waiting)
    }

    /// The summary of `collectionID` (nil: no such collection). Throws on a damaged share store.
    static func makeSummary(collectionID: String, snapshot: StoreSnapshot, issues: [String: [SyncIssue]],
                        removedShares: [String: SyncIssue], isPro: Bool,
                        folderName: ([UInt8]) -> String?) throws -> Summary? {
        guard let row = CollectionCatalog.collections(in: snapshot).first(where: { $0.id == collectionID }) else { return nil }
        let records = try ShareGroups.records(in: snapshot)
        guard let record = records.values.first(where: { $0.collectionID == collectionID }) else {
            return Summary(collectionID: collectionID, collectionName: row.name, isPro: isPro, shared: false, groupID: nil,
                           isOwner: false, mode: nil, modeText: nil, folder: "", members: [], pending: [], removed: [],
                           status: removedShares[collectionID].map { SyncWording.shareStatus($0) },
                           linked: ShareGroups.receivedLink(in: snapshot, collectionID: collectionID))
        }
        let group = try ShareGroups.group(of: record)
        let own = record.state.deviceID
        let isOwner = record.role == .owner
        let members = group.members.map { m -> Member in
            let state: MemberState = m.deviceID == group.owner ? .owner : (m.approved ? .member : .pending)
            return Member(id: m.deviceID, name: displayName(m.name), state: state, stateText: stateText(state),
                          isSelf: m.deviceID == own, removable: isOwner && m.deviceID != own)
        }
        var removed: [Removed] = []
        if isOwner {
            for (i, r) in record.removed.enumerated() { removed.append(Removed(id: i, name: displayName(r.name), at: r.at)) }
        }
        return Summary(collectionID: collectionID, collectionName: row.name, isPro: isPro, shared: true,
                       groupID: record.groupID, isOwner: isOwner, mode: group.sharedMode,
                       modeText: group.sharedMode == "edit" ? modeEditText : modeReadText,
                       folder: record.folder.flatMap(folderName) ?? "",
                       members: members, pending: isOwner ? members.filter { $0.state == .pending } : [],
                       removed: removed, status: SyncWording.shareStatus(issues[record.groupID] ?? []),
                       sharedTwice: ShareGroups.sharedTwice(in: snapshot, collectionID: collectionID),
                       canUpgradeShare: ShareGroups.needsUpgrade(in: snapshot, groupID: record.groupID))
    }

    /// The folder name of a stored bookmark, for display only (nothing is opened).
    nonisolated static func bookmarkName(_ bookmark: [UInt8]) -> String? {
        var stale = false
        let url = try? URL(resolvingBookmarkData: Data(bookmark), options: SecurityScopedFolderOpener.resolveOptions,
                           relativeTo: nil, bookmarkDataIsStale: &stale)
        return url?.lastPathComponent
    }

    // MARK: - Actions

    /// A folder picked in the document picker (its bookmark made while its scope was open).
    func pick(bookmark: [UInt8], name: String) {
        picked = PickedFolder(bookmark: bookmark, name: name)
        error = nil
    }

    /// The picked folder could not be turned into a bookmark.
    func pickFailed() {
        picked = nil
        error = SyncWording.errorText(reason: "folder-error")
    }

    /// The free plan: the upgrade sheet, and true.
    func needsUpgrade() -> Bool {
        guard !sync.isPro() else { return false }
        showUpgrade = true
        return true
    }

    /// Share the collection through the picked folder with the password typed twice and the edit choice.
    @discardableResult
    func share() async -> Bool {
        let pw = password, again = passwordAgain
        clearPasswords()
        guard let collectionID, !busy else { return false }
        start()
        defer { busy = false }
        if needsUpgrade() { return false }
        guard let picked else { error = Self.chooseFolderFirstText; return false }
        if let problem = Self.passwordProblem(pw, again) { error = problem; return false }
        // The owner check comes last, right before the items are handed over; refused: nothing is shared.
        guard await confirmOwner() else { error = Self.ownerNotConfirmedText; return false }
        let group = await sync.createShare(collectionID: collectionID, bookmark: picked.bookmark, password: pw,
                                           deviceName: Self.memberName(name), membersCanEdit: membersCanEdit)
        guard group != nil else { refused(); return false }
        self.picked = nil
        reload()
        message = Self.sharedDoneText(summary?.collectionName ?? "")
        return true
    }

    /// Join the shared collection in the picked folder; the sheet then shows that collection.
    @discardableResult
    func join() async -> Bool {
        let pw = password
        clearPasswords()
        guard !busy else { return false }
        start()
        defer { busy = false }
        if needsUpgrade() { return false }
        guard let picked else { error = Self.chooseFolderFirstText; return false }
        guard !pw.isEmpty else { error = Self.enterPasswordText; return false }
        guard let group = await sync.joinShare(bookmark: picked.bookmark, password: pw,
                                               deviceName: Self.memberName(name)) else { refused(); return false }
        self.picked = nil
        collectionID = group.collectionID
        reload()
        message = Self.joinedDoneText(SyncWording.sanitize(summary?.collectionName ?? group.name))
        return true
    }

    /// Join again after a lost join (`superseded`), from the same folder.
    @discardableResult
    func rejoin() async -> Bool {
        let pw = password
        clearPasswords()
        guard let groupID = summary?.groupID, !busy else { return false }
        start()
        defer { busy = false }
        if needsUpgrade() { return false }
        guard !pw.isEmpty else { error = Self.enterPasswordText; return false }
        guard await sync.rejoinShare(groupID: groupID, password: pw, deviceName: Self.memberName(name)) != nil else {
            refused(); return false
        }
        reload()
        message = Self.joinedDoneText(summary?.collectionName ?? "")
        return true
    }

    /// The names of the ticked waiting people, as the confirmation shows them (nil: nobody ticked).
    var approvalNames: String? {
        let chosen = (summary?.pending ?? []).filter { selectedPending.contains($0.id) }
        return chosen.isEmpty ? nil : chosen.map(\.name).joined(separator: ", ")
    }

    /// Let the ticked waiting people in (after the confirmation that names them).
    @discardableResult
    func approve() async -> Bool {
        guard let groupID = summary?.groupID, let names = approvalNames, !busy else { return false }
        let ids = (summary?.pending ?? []).map(\.id).filter { selectedPending.contains($0) }
        start()
        defer { busy = false }
        guard await sync.approveShare(groupID: groupID, deviceIDs: ids) != nil else { refused(); return false }
        selectedPending = []
        reload()
        message = Self.approvedDoneText(names)
        return true
    }

    /// Remove `memberID` with a new share password typed twice (the owner; works without Pro).
    @discardableResult
    func remove(_ memberID: String) async -> Bool {
        let pw = newPassword, again = newPasswordAgain
        clearPasswords()
        guard let summary, let groupID = summary.groupID, !busy else { return false }
        start()
        defer { busy = false }
        guard let member = summary.members.first(where: { $0.id == memberID }), member.removable else {
            error = Self.notAMemberText; return false
        }
        if let problem = Self.passwordProblem(pw, again) { error = problem; return false }
        guard await sync.removeShareMember(groupID: groupID, deviceID: memberID, newPassword: pw, again: again) else {
            refused(); return false
        }
        let written = sync.shareRemovalWritten
        reload()
        message = written ? Self.removedDoneText(member.name) : Self.removedDoneText(member.name) + " " + Self.removedNotWrittenText
        return true
    }

    /// Upgrade this device's share v1 collection to share v2 with the share password typed twice (`password`,
    /// `passwordAgain`: the current one or a new one; the owner; works without Pro).
    @discardableResult
    func upgradeShare() async -> Bool {
        let pw = password, again = passwordAgain
        clearPasswords()
        guard let summary, let groupID = summary.groupID, !busy else { return false }
        start()
        defer { busy = false }
        guard summary.canUpgradeShare else { error = Self.reasonText("already-upgraded"); return false }
        if let problem = Self.passwordProblem(pw, again) { error = problem; return false }
        guard await sync.upgradeShare(groupID: groupID, password: pw, again: again) else { refused(); return false }
        reload()
        message = Self.upgradedDoneText
        return true
    }

    /// Leave (a member) or stop sharing (the owner): the collection and its items stay here.
    @discardableResult
    func leave() async -> Bool {
        guard let summary, let groupID = summary.groupID, !busy else { return false }
        start()
        defer { busy = false }
        guard await sync.leaveShare(groupID: groupID) else { refused(); return false }
        reload()
        let name = SyncWording.sanitize(summary.collectionName)
        message = summary.isOwner ? Self.stoppedDoneText(name) : Self.leftDoneText(name)
        return true
    }

    /// Forget the share link another of this person's devices published (final review finding 4; the screen asks
    /// first): for a device that was lost or reset. The collection and its items stay; a device that still holds the
    /// share publishes its link again.
    @discardableResult
    func forgetLink() async -> Bool {
        guard let summary, !summary.shared, summary.linked != nil, !busy else { return false }
        start()
        defer { busy = false }
        guard await sync.forgetShareLink(collectionID: summary.collectionID) else { refused(); return false }
        reload()
        message = Self.forgetLinkDoneText(SyncWording.sanitize(summary.collectionName))
        return true
    }

    /// Forgets the last result and refusal (a new step starts, such as opening Remove).
    func dismissMessages() {
        error = nil; message = nil
    }

    /// Empties every password field (also when the sheet closes).
    func clearPasswords() {
        password = ""; passwordAgain = ""; newPassword = ""; newPasswordAgain = ""
    }

    private func start() {
        busy = true; error = nil; message = nil
    }

    private func refused() {
        let reason = sync.shareActionReason ?? "error"
        if reason == "pro-required" { showUpgrade = true }
        error = Self.reasonText(reason)
        reload()
    }

    // MARK: - Rules

    /// The desktop share password rule (`check_sync_password`: 12+ characters, a Strong rating, both entries equal);
    /// the same words as `AppPasswordRules.problem`.
    nonisolated static func passwordProblem(_ password: String, _ again: String) -> String? {
        let minLength = 12
        if password.unicodeScalars.count < minLength { return String(localized: "Use at least \(minLength) characters.") }
        if PasswordStrength.estimate(password).score < 3 { return String(localized: "Too easy to guess. Add more words or characters.") }
        if password != again { return String(localized: "The two passwords do not match.") }
        return nil
    }

    /// The name the others see for this device (desktop `_member_name`): what was typed, cleaned, at most 64 UTF-8
    /// bytes; else the device's generic name.
    nonisolated static func memberName(_ typed: String) -> String {
        let trimmed = typed.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return SyncWording.thisDevice }
        var name = SyncWording.sanitize(trimmed, limit: 40)
        while !name.isEmpty, name.utf8.count > 64 {
            name.removeLast()
            name = name.trimmingCharacters(in: .whitespaces)
        }
        return name.isEmpty ? SyncWording.thisDevice : name
    }

    /// A member's name as shown: cleaned, or "Unnamed device".
    nonisolated static func displayName(_ name: String?) -> String {
        guard let name, !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return unnamedText }
        return SyncWording.sanitize(name)
    }

    nonisolated static func stateText(_ state: MemberState) -> String {
        switch state {
        case .owner: String(localized: "collectionShare.state.owner", defaultValue: "Shared it")
        case .member: String(localized: "collectionShare.state.member", defaultValue: "Member")
        case .pending: String(localized: "collectionShare.state.pending", defaultValue: "Waiting for approval")
        }
    }

    /// A refused share action's reason code (`ShareSync.reason`, or this model's own) as shown (desktop `ERROR_COPY`).
    nonisolated static func reasonText(_ reason: String) -> String {
        switch reason {
        case "already-shared": String(localized: "collectionShare.alreadyShared", defaultValue: "This collection is already shared.")
        case "no-collection": String(localized: "collectionShare.noCollection", defaultValue: "That collection no longer exists.")
        case "not-share", "personal-group": String(localized: "collectionShare.notAShare", defaultValue: "That folder holds device sync, not a shared collection. Choose the folder of the shared collection.")
        case "already-joined": String(localized: "collectionShare.alreadyJoined", defaultValue: "This vault is already in that shared collection.")
        case "collection-exists": String(localized: "collectionShare.collectionExists", defaultValue: "This vault already has that collection. Shared collections cannot be joined into an existing one.")
        case "not-owner": String(localized: "collectionShare.notOwner.device", defaultValue: "Only the device that shared this collection can do that.")
        case "not-pending": String(localized: "collectionShare.notPending", defaultValue: "Choose people who are waiting for your approval.")
        case "not-joined": String(localized: "collectionShare.notShared", defaultValue: "This collection is not shared.")
        case "not-member": notAMemberText
        case "password": String(localized: "collectionShare.wrongPassword", defaultValue: "That share password is not right for this folder.")
        case "password-reused": String(localized: "collectionShare.passwordReused", defaultValue: "Choose a new share password; it must differ from the current one.")
        case "too-many-members": String(localized: "collectionShare.tooManyMembers", defaultValue: "This shared collection has as many people as it can hold.")
        case "no-link": String(localized: "collectionShare.notShared", defaultValue: "This collection is not shared.")
        case "shared-here": String(localized: "collectionShare.forgetLinkSharedHere.device", defaultValue: "This collection is shared on this device. Leave it or stop sharing it instead.")
        case "folder-in-use": String(localized: "collectionShare.folderInUse", defaultValue: "That folder already holds a sync group or another shared collection. Choose an empty folder.")
        case "folder-error": String(localized: "collectionShare.folderNotWritable", defaultValue: "LocalGateKeys could not write to that folder. Nothing was shared.")
        case "no-share": String(localized: "collectionShare.noShareInFolder", defaultValue: "That folder holds no shared collection. Choose the folder the person who shared it gave you.")
        case "keyring-unreadable": String(localized: "collectionShare.folderUnreadable", defaultValue: "LocalGateKeys could not read that folder.")
        case "share-undo-failed": String(localized: "collectionShare.undoFailed", defaultValue: "LocalGateKeys could not write to that folder, and the share could not be undone. Choose Stop sharing, then try again with another folder.")
        case "password-mismatch": String(localized: "The two passwords do not match.")
        case "collection-limit": String(localized: "collectionShare.failed", defaultValue: "The shared collection could not be changed.")
        case "already-upgraded": String(localized: "collectionShare.alreadyUpgraded", defaultValue: "This shared collection is already upgraded.")
        // The share's key file is from a later app version (keyring `newer-format`, folder run `update-required`).
        case "newer-format", "update-required": SyncWording.shareCopy(SyncIssue("update-required")) ?? SyncWording.errorText(reason: reason)
        case "pro-required", "folder-missing": SyncWording.shareCopy(SyncIssue(reason)) ?? SyncWording.errorText(reason: reason)
        default: SyncWording.errorText(reason: reason)
        }
    }

    // MARK: - Words

    nonisolated static var confirmToShareText: String { String(localized: "collectionShare.confirmToShare", defaultValue: "Confirm to share this collection") }
    nonisolated static var ownerNotConfirmedText: String {
        SyncWording.onDevice(phone: String(localized: "collectionShare.ownerNotConfirmed", defaultValue: "Sharing needs Face ID, Touch ID or the device passcode. Nothing was shared."),
                             mac: String(localized: "collectionShare.ownerNotConfirmed.mac", defaultValue: "Sharing needs your master password. Nothing was shared."))
    }
    nonisolated static var unnamedText: String { String(localized: "collectionShare.unnamed.device", defaultValue: "Unnamed device") }
    nonisolated static var modeEditText: String { String(localized: "collectionShare.modeEdit", defaultValue: "Members can edit") }
    nonisolated static var modeReadText: String { String(localized: "collectionShare.modeRead", defaultValue: "Members can only view") }
    nonisolated static var modeFixedText: String { String(localized: "collectionShare.modeFixed", defaultValue: "This choice is fixed once the collection is shared. To change it, stop sharing and share the collection again.") }
    nonisolated static var introText: String { String(localized: "collectionShare.intro", defaultValue: "Share this collection with family or a team through a folder you all can reach, such as a shared iCloud Drive folder. Each person joins with the share password. That password protects the items in the folder, so give it only to people you invite.") }
    nonisolated static var helpText: String { String(localized: "collectionShare.help", defaultValue: "Everyone who joins keeps their own vault and their own key. Only the items in this collection go through the shared folder; your other items stay private.") }
    nonisolated static var ownerLossText: String { String(localized: "collectionShare.ownerLoss.device", defaultValue: "Only the device that shared the collection can let people in or remove them. If that device is lost, the others keep their items and keep syncing, but nobody can change who is in. To start again, choose Forget share link for this collection on one of your other devices, then share it again into a new, empty folder.") }
    nonisolated static var sharedTwiceText: String { String(localized: "collectionShare.sharedTwice", defaultValue: "This collection is shared from two of your devices; stop sharing or leave it on one.") }
    nonisolated static var forgetLinkTitle: String { String(localized: "collectionShare.forgetLinkTitle", defaultValue: "Forget the share link?") }
    nonisolated static var forgetLinkHintText: String { String(localized: "collectionShare.forgetLinkHint", defaultValue: "If that device was lost or reset, forget the share link. Then you can delete this collection or share it again.") }
    /// Shared by another of this person's devices: as the owner (`role` "owner") or as a member.
    nonisolated static func linkedText(_ link: CollectionShares.Link) -> String {
        link.role == "owner"
            ? String(localized: "collectionShare.linkedOwner", defaultValue: "Another of your devices shared this collection. Manage the share on that device.")
            : String(localized: "collectionShare.linkedMember", defaultValue: "Another of your devices is in this shared collection. Manage the share on that device.")
    }
    nonisolated static var joinIntroText: String { String(localized: "collectionShare.joinIntro", defaultValue: "Choose the shared folder you were given access to (for example a shared iCloud Drive folder), then type the share password you were told.") }
    nonisolated static var chooseFolderFirstText: String { String(localized: "collectionShare.chooseFolderFirst", defaultValue: "Choose the shared folder first.") }
    nonisolated static var enterPasswordText: String { String(localized: "collectionShare.enterPassword", defaultValue: "Type the share password.") }
    nonisolated static var notAMemberText: String { String(localized: "collectionShare.notAMember", defaultValue: "That person is no longer in this shared collection.") }
    nonisolated static var removedNotWrittenText: String { String(localized: "collectionShare.removedNotWritten", defaultValue: "The shared folder could not be updated yet; LocalGateKeys finishes this at the next sync.") }
    nonisolated static var waitingHintText: String { String(localized: "collectionShare.waitingHint", defaultValue: "Let in only people you invited. Each name is what that person typed.") }
    nonisolated static var approveTitle: String { String(localized: "collectionShare.approveTitle", defaultValue: "Let them in?") }
    nonisolated static var stopTitle: String { String(localized: "collectionShare.stopTitle", defaultValue: "Stop sharing?") }
    nonisolated static var leaveTitle: String { String(localized: "collectionShare.leaveTitle", defaultValue: "Leave the shared collection?") }
    /// Under a collection this device was removed from (the Collections list).
    nonisolated static var removedBadgeText: String { String(localized: "collectionShare.removedBadge", defaultValue: "Removed, items moved to the trash") }
    nonisolated static var upgradeTitle: String { String(localized: "collectionShare.upgradeTitle", defaultValue: "Make this share safer") }
    nonisolated static var upgradeText: String { String(localized: "collectionShare.upgradeText", defaultValue: "Right now anyone who knows the share password can open the items in the shared folder. After the upgrade, only the people you let in can. Type the share password twice: the current one or a new one. Everyone in this collection needs this app version or later; older versions stop syncing it until they are updated.") }
    nonisolated static var upgradedDoneText: String { String(localized: "collectionShare.upgradedDone", defaultValue: "Share upgraded. Only the people you let in can open its items.") }

    nonisolated static func sharedDoneText(_ name: String) -> String {
        String(localized: "collectionShare.sharedDone", defaultValue: "“\(name)” is shared. Tell the others the share password and where the folder is.")
    }
    nonisolated static func joinedDoneText(_ name: String) -> String {
        String(localized: "collectionShare.joinedDone", defaultValue: "You joined “\(name)”. Its items start to sync once the person who shared it lets you in.")
    }
    nonisolated static func approvedDoneText(_ names: String) -> String {
        String(localized: "collectionShare.approvedDone", defaultValue: "Let in: \(names).")
    }
    nonisolated static func approveText(names: String, collection name: String) -> String {
        String(localized: "collectionShare.approveText", defaultValue: "Let these people into “\(name)”: \(names)? Their devices then sync every item in this collection, and their edits count. Only approve names you recognise.")
    }
    nonisolated static func removedDoneText(_ person: String) -> String {
        String(localized: "collectionShare.removedDone", defaultValue: "\(person) was removed.")
    }
    nonisolated static func removeTitle(_ person: String) -> String {
        String(localized: "collectionShare.removeTitle", defaultValue: "Remove \(person)?")
    }
    nonisolated static func removeHint(_ person: String) -> String {
        String(localized: "collectionShare.removeHint", defaultValue: "\(person) knows the current share password, so removing them needs a new one. The others keep syncing without typing it; give it only to people you invite later.")
    }
    /// `person` appears twice, so the catalog value reuses `%1$@` (`%1$@ … %2$@ … %1$@`); the third argument is
    /// ignored on purpose. Do not change it to `%3$@`.
    nonisolated static func removeText(person: String, collection name: String) -> String {
        String(localized: "collectionShare.removeText", defaultValue: "\(person) will stop receiving changes to “\(name)”, and their copies of its items will move to their trash. Because \(person) knows the current share password, the collection gets the new share password you typed. The others keep syncing without typing it.")
    }
    nonisolated static func removeButton(_ person: String) -> String {
        String(localized: "collectionShare.removeButton", defaultValue: "Remove \(person)")
    }
    nonisolated static func shareTitle(_ name: String) -> String {
        String(localized: "collectionShare.shareTitle", defaultValue: "Share “\(name)”")
    }
    nonisolated static func stopText(_ name: String) -> String {
        SyncWording.onDevice(phone: DeviceText.isPad ? String(localized: "ipad.collectionShare.stopText", defaultValue: "Stop sharing “\(name)” on this iPad? The collection and its items stay here. The others keep their copies, but nobody can let people in or remove them any more.") : String(localized: "collectionShare.stopText.phone", defaultValue: "Stop sharing “\(name)” on this iPhone? The collection and its items stay here. The others keep their copies, but nobody can let people in or remove them any more."),
                             mac: String(localized: "collectionShare.stopText.mac", defaultValue: "Stop sharing “\(name)” on this Mac? The collection and its items stay here. The others keep their copies, but nobody can let people in or remove them any more."))
    }
    nonisolated static func leaveText(_ name: String) -> String {
        SyncWording.onDevice(phone: DeviceText.isPad ? String(localized: "ipad.collectionShare.leaveText", defaultValue: "Leave “\(name)”? Its items stay on this iPad but no longer sync with the others.") : String(localized: "collectionShare.leaveText.phone", defaultValue: "Leave “\(name)”? Its items stay on this iPhone but no longer sync with the others."),
                             mac: String(localized: "collectionShare.leaveText.mac", defaultValue: "Leave “\(name)”? Its items stay on this Mac but no longer sync with the others."))
    }
    nonisolated static func stoppedDoneText(_ name: String) -> String {
        SyncWording.onDevice(phone: DeviceText.isPad ? String(localized: "ipad.collectionShare.stoppedDone", defaultValue: "“\(name)” is no longer shared from this iPad.") : String(localized: "collectionShare.stoppedDone.phone", defaultValue: "“\(name)” is no longer shared from this iPhone."),
                             mac: String(localized: "collectionShare.stoppedDone.mac", defaultValue: "“\(name)” is no longer shared from this Mac."))
    }
    nonisolated static func forgetLinkText(_ name: String) -> String {
        String(localized: "collectionShare.forgetLinkText", defaultValue: "Forget the share link of “\(name)”? Do this only if the device that shares it was lost or reset. The collection and its items stay. If that device still exists, it shares the link again at its next sync.")
    }
    nonisolated static func forgetLinkDoneText(_ name: String) -> String {
        String(localized: "collectionShare.forgetLinkDone", defaultValue: "The share link of “\(name)” was forgotten.")
    }
    nonisolated static func leftDoneText(_ name: String) -> String {
        String(localized: "collectionShare.leftDone", defaultValue: "You left “\(name)”.")
    }

    /// The share screens' labels (desktop `collectionShare.*`): the iPhone sheet and the Mac page.
    enum Words {
        static var joinTitle: String { String(localized: "collectionShare.joinTitle", defaultValue: "Join a shared collection") }
        static var join: String { String(localized: "collectionShare.joinButton", defaultValue: "Join") }
        static var chooseFolder: String { String(localized: "collectionShare.chooseFolderButton", defaultValue: "Choose folder") }
        static var noFolder: String { String(localized: "collectionShare.noFolder", defaultValue: "No folder chosen yet.") }
        static var folder: String { String(localized: "collectionShare.folder", defaultValue: "Folder") }
        static var yourName: String { String(localized: "collectionShare.yourName", defaultValue: "Your name for the others") }
        static var namePlaceholder: String { String(localized: "collectionShare.namePlaceholder", defaultValue: "For example Anna") }
        static var password: String { String(localized: "collectionShare.password", defaultValue: "Share password") }
        static var passwordAgain: String { String(localized: "collectionShare.confirmPassword", defaultValue: "Share password again") }
        static var newPassword: String { String(localized: "collectionShare.newPassword", defaultValue: "New share password") }
        static var newPasswordAgain: String { String(localized: "collectionShare.newPasswordAgain", defaultValue: "New share password again") }
        static var canEdit: String { String(localized: "collectionShare.canEdit", defaultValue: "Members can edit") }
        static var shareButton: String { String(localized: "collectionShare.shareButton", defaultValue: "Share collection") }
        static var share: String { String(localized: "collectionShare.share", defaultValue: "Share") }
        static var people: String { String(localized: "collectionShare.people", defaultValue: "People") }
        static var you: String { String(localized: "collectionShare.you", defaultValue: "you") }
        static var remove: String { String(localized: "collectionShare.remove", defaultValue: "Remove") }
        static var waiting: String { String(localized: "collectionShare.waiting", defaultValue: "Waiting for your approval") }
        static var letIn: String { String(localized: "collectionShare.letIn", defaultValue: "Let them in") }
        static var removedHeading: String { String(localized: "collectionShare.removedHeading", defaultValue: "Removed") }
        static var stopSharing: String { String(localized: "collectionShare.stopSharing", defaultValue: "Stop sharing") }
        static var leave: String { String(localized: "collectionShare.leave", defaultValue: "Leave this shared collection") }
        static var sharedBadge: String { String(localized: "collectionShare.sharedBadge", defaultValue: "Shared") }
        static var forgetLink: String { String(localized: "collectionShare.forgetLink", defaultValue: "Forget share link") }
        static var upgradeButton: String { String(localized: "collectionShare.upgradeButton", defaultValue: "Upgrade share") }
    }
}
