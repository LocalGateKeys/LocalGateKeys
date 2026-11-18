import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

// Shared collections on the iPhone and the Mac (sub-plan 07 Task 5g; desktop `SyncService._run_shares` and
// `app/collection_share.py`). A shared collection is its own share group (`ShareGroups`) syncing through its own cloud
// folder (`FolderSync(share:)`); the coordinator runs every share after the personal group, and its share actions call
// `ShareSync` under the coordinator's action lock. Share passwords are only ever arguments: never stored, logged or
// put in an error.

/// Recently deleted as share runs use it: the iPhone's `PhoneLocalData`, the Mac's lock model (same requirements).
#if os(macOS)
typealias ShareTrashHosting = LocalDataHosting
#else
typealias ShareTrashHosting = PhoneLocalHosting
#endif

/// Runs `body` on the main actor now, from any thread, and returns its result (also the Mac's `RemoteDeletes.onMain`).
/// Share runs and their store work on a GCD thread while Recently deleted lives on the main actor; the main actor only
/// ever awaits that work (it never blocks on it), so this cannot deadlock.
enum MainThreadHop {
    static func run<T: Sendable>(_ body: @MainActor () throws -> T) throws -> T {
        if Thread.isMainThread { return try MainActor.assumeIsolated(body) }
        nonisolated(unsafe) var result: Result<T, Error>!
        DispatchQueue.main.sync { result = Result { try MainActor.assumeIsolated(body) } }
        return try result.get()
    }
}

/// A share run's store change that Recently deleted cannot take: `trash-full`, or `item-error` while it is not open.
/// Its text starts with the kind, so the run's `busy` for it is reported as that kind (`ShareSync.runIssue`).
struct ShareTrashRefusal: Error, Equatable, CustomStringConvertible {
    let kind: String
    static let full = ShareTrashRefusal(kind: "trash-full")
    static let unavailable = ShareTrashRefusal(kind: "item-error")
    var description: String { kind + ": " + ShareSync.runDetail }
}

/// What share runs need from the host for one coordinator run: Pro (read once, on the main actor, when the run starts)
/// and Recently deleted (read and written on the main actor at each step).
final class ShareHost: @unchecked Sendable {
    let isPro: Bool
    /// The coordinator's store already copies every live item a commit takes out to Recently deleted (the Mac's
    /// `SyncSourceStore`); otherwise share commits do it (`ShareTrashingStore`).
    let storeTrashes: Bool
    /// Only touched on the main actor.
    private weak var trash: (any ShareTrashHosting)?

    init(isPro: Bool, trash: (any ShareTrashHosting)?, storeTrashes: Bool) {
        self.isPro = isPro; self.trash = trash; self.storeTrashes = storeTrashes
    }

    /// Recently deleted now; nil while it is not open.
    func rows() -> [LocalData.TrashRow]? {
        (try? MainThreadHop.run { ShareHost.rows(self.trash) }) ?? nil
    }

    /// Room for `count` more rows (`ShareTrashRefusal` otherwise).
    func checkRoom(_ count: Int) throws {
        guard let rows = rows() else { throw ShareTrashRefusal.unavailable }
        guard rows.count + count <= LocalData.maxTrash else { throw ShareTrashRefusal.full }
    }

    /// Appends `new` to Recently deleted (before the commit that takes their items out).
    func add(_ new: [LocalData.TrashRow]) throws {
        try MainThreadHop.run { try ShareHost.add(new, to: self.trash) }
    }

    /// Takes `rows` out again, one match each by value (the commit they were for failed).
    func remove(_ rows: [LocalData.TrashRow]) {
        _ = try? MainThreadHop.run { try ShareHost.remove(rows, from: self.trash) }
    }

    /// Every row of `itemIDs` leaves Recently deleted: a share run brought those items back live.
    func leave(itemIDs: Set<String>) {
        guard !itemIDs.isEmpty else { return }
        _ = try? MainThreadHop.run { try ShareHost.leave(itemIDs, from: self.trash) }
    }

    @MainActor private static func rows(_ local: (any ShareTrashHosting)?) -> [LocalData.TrashRow]? {
        local?.localData?.trash
    }

    @MainActor private static func add(_ new: [LocalData.TrashRow], to local: (any ShareTrashHosting)?) throws {
        guard let local, var data = local.localData else { throw ShareTrashRefusal.unavailable }
        guard data.trash.count + new.count <= LocalData.maxTrash else { throw ShareTrashRefusal.full }
        data.trash += new
        try local.commitLocalData(data)
    }

    @MainActor private static func remove(_ rows: [LocalData.TrashRow], from local: (any ShareTrashHosting)?) throws {
        guard let local, var data = local.localData else { return }
        for row in rows {
            if let i = data.trash.lastIndex(of: row) { data.trash.remove(at: i) }
        }
        try local.commitLocalData(data)
    }

    @MainActor private static func leave(_ ids: Set<String>, from local: (any ShareTrashHosting)?) throws {
        guard let local, var data = local.localData else { return }
        let kept = data.trash.filter { row in
            guard case .object(let r)? = try? row.record(), case .string(let id)? = r["id"] else { return true }
            return !ids.contains(id)
        }
        guard kept.count != data.trash.count else { return }
        data.trash = kept
        try local.commitLocalData(data)
    }
}

/// The store a share run commits through: every live item a commit takes out goes to Recently deleted first, as the
/// Mac's `RemoteDeletes.commit` does (desktop: share deletes and removals land in the trash). When the base store
/// already does that (`ShareHost.storeTrashes`), only the room is checked. A failed commit takes out exactly the rows
/// it added, so an item is never lost from both.
final class ShareTrashingStore: ItemStore, @unchecked Sendable {
    let base: any ItemStore
    let host: ShareHost
    let now: Int64

    init(base: any ItemStore, host: ShareHost, now: Int64) { self.base = base; self.host = host; self.now = now }

    func load() throws -> StoreSnapshot { try base.load() }

    func commit(_ change: StoreChange) throws {
        let before = try base.load()
        let rows = RemovedItems.trashRows(before: before, records: change.records, meta: change.meta, now: now)
        guard !rows.isEmpty else { try base.commit(change); return }
        if host.storeTrashes {
            try host.checkRoom(rows.count)
            do { try base.commit(change) } catch is LocalDataError {
                // The base store saves Recently deleted first (`RemoteDeletes.commit`, which words every failure there
                // as a `LocalDataError`): that is a Recently deleted problem, never `busy`. Any other error is the vault
                // store's own (locked, stale, a write error) and is reported as it is (5g review R3).
                try host.checkRoom(rows.count)
                throw ShareTrashRefusal.unavailable
            }
            return
        }
        do { try host.add(rows) } catch let e as ShareTrashRefusal { throw e } catch {
            throw ShareTrashRefusal.unavailable   // Recently deleted could not be saved
        }
        do { try base.commit(change) } catch {
            host.remove(rows)
            throw error
        }
    }
}

/// The trash rows of the items a store change takes out (one rule for every path that moves remote deletes to Recently
/// deleted: share runs here, the Mac's `RemoteDeletes`, the iPhone's backup restore).
enum RemovedItems {
    /// Live logins and typed items in `before` that `records`/`meta` no longer hold live, as trash rows with their
    /// collections (restored with the item, as on Windows).
    static func trashRows(before: StoreSnapshot, records: [String: JSONValue], meta: [String: SyncMeta],
                          now: Int64) -> [LocalData.TrashRow] {
        var rows: [LocalData.TrashRow] = []
        for (id, wrapper) in before.itemRecords.sorted(by: { $0.key < $1.key }) where before.meta[id]?.deleted != true {
            guard records[id] == nil || meta[id]?.deleted == true, case .object(let w) = wrapper,
                  w["ns"] == .string(Namespace.entry.rawValue) || w["ns"] == .string(Namespace.item.rawValue),
                  case .object? = w["record"], let record = AttachmentDocuments.trashRecord(.object(w)),
                  let row = try? LocalData.TrashRow(record: CollectionCatalog.trashRecord(record, itemID: id, in: before),
                                                    deletedAt: now) else { continue }
            rows.append(row)
        }
        return rows
    }
}

/// The share runs and share actions, off the main actor (desktop `SyncService._run_shares`,
/// `CollectionShareService`).
enum ShareSync {
    /// Detail of a share run's own Recently deleted refusal (a normal run, not a removal): `SyncWording.shareStatus`
    /// words it as the sync trash message.
    static let runDetail = "share-run"
    /// The most keyring bytes read from a share folder (desktop `MAX_KEYRING_BYTES`, plus one to see it is too large).
    static let keyringReadLimit = 256 * 1024 + 1

    /// What personal sync needs from this vault's share groups (`ShareGroups.collectionShares`, which fails closed on a
    /// damaged share store), on every personal folder run. Throws when the store cannot be read: no run goes ahead
    /// without its read-only protection (the Wi-Fi paths read it from the snapshot they merge).
    static func collectionShares(_ store: any ItemStore) throws -> CollectionShares {
        ShareGroups.collectionShares(in: try store.load())
    }

    /// The result of every share run of one coordinator run.
    struct Runs: Sendable, Equatable {
        /// Share group id -> that group's issues (none: it synced); "" for share groups that cannot be read.
        var issues: [String: [SyncIssue]] = [:]
        var conflicts = 0
        var changed = 0
    }

    /// Every share group with a folder, one after the other in group id order, after the personal group. On a free
    /// device each run does its keyring step only (a repair, an adoption, a removal: security actions, final review A2)
    /// and reports `pro-required`; no view is read or written. A failing share never stops the others; nothing runs
    /// once the vault locks.
    static func runAll(store: any ItemStore, deps: SyncDependencies, host: ShareHost) async -> Runs {
        var out = Runs()
        let records: [String: ShareRecord]
        do { records = try ShareGroups.records(in: try store.load()) } catch let e as ShareGroupError {
            out.issues[""] = [SyncIssue("state-corrupt", e.reason)]
            return out
        } catch {
            out.issues[""] = [SyncIssue("local-data", "\(error)")]
            return out
        }
        guard !records.isEmpty else { return out }
        let installID: String
        do { installID = try deps.keychain.installID(random: deps.random) } catch {
            for gid in records.keys { out.issues[gid] = [SyncIssue("state-corrupt", "install id")] }
            return out
        }
        for (gid, record) in records.sorted(by: { $0.key < $1.key }) {
            guard SyncCoordinator.stillOpen(store) else { break }
            guard let bookmark = record.folder else { out.issues[gid] = [SyncIssue("folder-missing", gid)]; continue }
            // The folder blocks (NSFileCoordinator, iCloud downloads): a GCD thread, never a cooperative one.
            let report: RunReport = await withCheckedContinuation { c in
                DispatchQueue.global(qos: .utility).async {
                    c.resume(returning: ShareSync.run(store: store, deps: deps, installID: installID, groupID: gid,
                                                      bookmark: bookmark, host: host))
                }
            }
            out.issues[gid] = report.issues
            out.conflicts += report.conflicts
            out.changed += report.applied + report.deleted + report.conflicts
        }
        return out
    }

    /// Share runs with no Recently deleted to put a share's deletes in (not open yet, or it could not be read): none
    /// runs, and each group says so (`item-error`, the run's own detail), so a share that never ran never looks synced.
    /// A free device says `pro-required` instead (5g review R4), as its runs would.
    static func notRun(_ snapshot: StoreSnapshot, isPro: Bool = true) -> Runs {
        var out = Runs()
        guard let records = try? ShareGroups.records(in: snapshot) else {
            out.issues[""] = [SyncIssue("state-corrupt", "share groups")]
            return out
        }
        for gid in records.keys {
            out.issues[gid] = [isPro ? SyncIssue(ShareTrashRefusal.unavailable.kind, runDetail) : SyncIssue("pro-required", gid)]
        }
        return out
    }

    /// One share group's run over its own folder (`record.folder`, a security-scoped bookmark the host resolves).
    static func run(store: any ItemStore, deps: SyncDependencies, installID: String, groupID: String,
                    bookmark: [UInt8], host: ShareHost) -> RunReport {
        let opened: (folder: any FolderAccess, refreshed: [UInt8]?)
        do { opened = try deps.folders.open(bookmark: bookmark) } catch {
            return stop("folder-missing", "\(error)")
        }
        if let refreshed = opened.refreshed { try? ShareGroups.setFolder(store: store, groupID: groupID, folder: refreshed) }
        guard SyncCoordinator.stillOpen(store) else { return RunReport() }
        let before = try? store.load()
        let rows = host.rows()
        let trash = rows.map { ShareTrash.of($0) } ?? ShareTrash(count: nil)
        let fs: FolderSync
        do {
            fs = try FolderSync(access: opened.folder, installID: installID,
                                share: FolderSync.Share(groupID: groupID, isPro: host.isPro, trash: trash))
        } catch {
            return stop("state-corrupt", groupID)
        }
        var report = fs.runOnce(store: ShareTrashingStore(base: store, host: host, now: deps.clock.now),
                                random: deps.random, clock: deps.clock)
        report.issues = report.issues.map(ShareSync.runIssue)
        // A share item brought back from Recently deleted (the run restored it into the store) leaves it.
        if let before, let after = try? store.load(), !trash.records.isEmpty {
            let back = liveIDs(after).subtracting(liveIDs(before)).intersection(trash.records.keys)
            host.leave(itemIDs: back)
        }
        return report
    }

    /// A share commit that Recently deleted refused is that refusal (`trash-full`, `item-error`), never `busy`.
    static func runIssue(_ issue: SyncIssue) -> SyncIssue {
        guard issue.kind == "busy" else { return issue }
        for refusal in [ShareTrashRefusal.full, ShareTrashRefusal.unavailable] where issue.detail.hasPrefix(refusal.kind + ":") {
            return SyncIssue(refusal.kind, runDetail)
        }
        return issue
    }

    static func stop(_ kind: String, _ detail: String = "") -> RunReport {
        var report = RunReport()
        report.issues = [SyncIssue(kind, detail)]
        return report
    }

    /// The items the store holds a record of. Presence only: a share run writes a brought-back record but leaves the
    /// personal meta alone, which the personal run has already made a tombstone for an item in Recently deleted.
    static func liveIDs(_ snapshot: StoreSnapshot) -> Set<String> {
        Set(snapshot.itemRecords.keys)
    }

    // MARK: actions (each under the coordinator's action lock, off the main actor)

    static func open(_ bookmark: [UInt8], _ deps: SyncDependencies) throws -> (folder: any FolderAccess, refreshed: [UInt8]?) {
        do { return try deps.folders.open(bookmark: bookmark) } catch { throw SyncActionError("folder-missing") }
    }

    /// The folder's keyring bytes: `no-share` when there is none, `keyring-unreadable` when it cannot be read.
    static func keyring(in folder: any FolderAccess) throws -> [UInt8] {
        do { return try folder.read(FolderLayout.keyringPath, limit: keyringReadLimit) }
        catch FolderAccessError.notFound { throw SyncActionError("no-share") }
        catch { throw SyncActionError("keyring-unreadable") }
    }

    static func record(_ store: any ItemStore, _ groupID: String) throws -> ShareRecord {
        guard let record = try ShareGroups.records(in: try store.load())[groupID] else {
            throw ShareGroupError("not-joined", "this vault is not in that share group")
        }
        return record
    }

    /// A `FolderSync` over `groupID`'s own folder for the keyring and notice writes (`folder-missing` without one).
    static func folderSync(_ store: any ItemStore, _ deps: SyncDependencies, _ groupID: String) throws -> FolderSync {
        guard let bookmark = try record(store, groupID).folder else { throw SyncActionError("folder-missing") }
        let opened = try open(bookmark, deps)
        if let refreshed = opened.refreshed { try? ShareGroups.setFolder(store: store, groupID: groupID, folder: refreshed) }
        return try FolderSync(access: opened.folder, installID: try deps.keychain.installID(random: deps.random))
    }

    /// Share `collectionID` through the folder of `bookmark` (desktop `CollectionShareService.share`). Pro first, then
    /// `folder-in-use` when the folder already holds a sync group's keyring; the keyring is written at once and a
    /// failed write undoes the share (`leave`, `folder-error`).
    static func create(store: any ItemStore, deps: SyncDependencies, isPro: Bool, collectionID: String,
                       bookmark: [UInt8], password: String, deviceName: String, mode: String) throws -> ShareGroups.Group {
        try ShareAccess.requirePro(.create, isPro: isPro)
        let opened = try open(bookmark, deps)
        let fs = try FolderSync(access: opened.folder, installID: try deps.keychain.installID(random: deps.random))
        guard !fs.holdsKeyring() else { throw SyncActionError("folder-in-use") }
        let group = try ShareGroups.create(store: store, collectionID: collectionID, password: password,
                                           deviceName: deviceName, sharedMode: mode, installID: fs.installID,
                                           isPro: isPro, folder: opened.refreshed ?? bookmark, random: deps.random,
                                           clock: deps.clock)
        guard fs.writeShareKeyring(store: store, groupID: group.groupID) else {
            // Undone, once more if the vault changed meanwhile; a share that cannot be undone is said so (the screen
            // offers Stop sharing), never left to start working at the next run behind a "failed".
            do { try ShareGroups.leave(store: store, groupID: group.groupID) } catch {
                do { try ShareGroups.leave(store: store, groupID: group.groupID) } catch {
                    throw SyncActionError("share-undo-failed")
                }
            }
            throw SyncActionError("folder-error")
        }
        return group
    }

    /// Join the shared collection in the folder of `bookmark` (desktop `CollectionShareService.join`). Pro first; a
    /// refused join (`password`, `not-share`, `collection-exists`...) stores nothing. The grown keyring is written
    /// now when the folder allows it; the share run writes it otherwise.
    static func join(store: any ItemStore, deps: SyncDependencies, isPro: Bool, bookmark: [UInt8], password: String,
                     deviceName: String) throws -> ShareGroups.Group {
        try ShareAccess.requirePro(.join, isPro: isPro)
        let opened = try open(bookmark, deps)
        let raw = try keyring(in: opened.folder)
        let fs = try FolderSync(access: opened.folder, installID: try deps.keychain.installID(random: deps.random))
        let group = try ShareGroups.join(store: store, keyring: raw, password: password, deviceName: deviceName,
                                         installID: fs.installID, isPro: isPro, folder: opened.refreshed ?? bookmark,
                                         random: deps.random, clock: deps.clock)
        _ = fs.writeShareKeyring(store: store, groupID: group.groupID)
        return group
    }

    /// Join `groupID` again after someone else's join at the same moment won (`superseded`), from its own folder.
    static func rejoin(store: any ItemStore, deps: SyncDependencies, isPro: Bool, groupID: String, password: String,
                       deviceName: String) throws -> ShareGroups.Group {
        try ShareAccess.requirePro(.join, isPro: isPro)
        let fs = try folderSync(store, deps, groupID)
        let raw = try keyring(in: fs.access)
        let group = try ShareGroups.rejoin(store: store, groupID: groupID, keyring: raw, password: password,
                                           deviceName: deviceName, installID: fs.installID, isPro: isPro,
                                           random: deps.random, clock: deps.clock)
        _ = fs.writeShareKeyring(store: store, groupID: groupID)
        return group
    }

    /// The owner lets `deviceIDs` in (works without Pro); the new keyring is written now when the folder allows it.
    static func approve(store: any ItemStore, deps: SyncDependencies, groupID: String,
                        deviceIDs: [String]) throws -> [ShareGroups.Member] {
        let members = try ShareGroups.approve(store: store, groupID: groupID, deviceIDs: deviceIDs)
        if let fs = try? folderSync(store, deps, groupID) { _ = fs.writeShareKeyring(store: store, groupID: groupID) }
        return members
    }

    /// The owner removes `deviceID` with a new share password (works without Pro). The folder is opened first, so a
    /// missing folder changes nothing; then the rotation, the owner's removal notice and the rotated keyring. Returns
    /// whether both files were written (false: the removal stands, the share run writes the keyring later, but the
    /// removed person sees "can no longer open" instead of the removal).
    static func removeMember(store: any ItemStore, deps: SyncDependencies, groupID: String, deviceID: String,
                             newPassword: String) throws -> Bool {
        let fs = try folderSync(store, deps, groupID)
        let notice = try ShareGroups.removeMember(store: store, groupID: groupID, deviceID: deviceID,
                                                  newPassword: newPassword, random: deps.random, clock: deps.clock)
        let published = fs.publishShareNotice(deviceID: deviceID, notice: notice)
        let written = fs.writeShareKeyring(store: store, groupID: groupID)
        return published && written
    }

    /// The owner upgrades share v1 `groupID` to share v2 with `password` as the share password of the new epoch (works
    /// without Pro: a security action; desktop `upgrade_share`). The folder is opened first, so a missing folder
    /// changes nothing; the upgraded keyring is written now when the folder allows it (the share run writes it
    /// otherwise). Returns whether it was written.
    static func upgrade(store: any ItemStore, deps: SyncDependencies, groupID: String, password: String) throws -> Bool {
        let fs = try folderSync(store, deps, groupID)
        try ShareGroups.upgrade(store: store, groupID: groupID, password: password, random: deps.random)
        return fs.writeShareKeyring(store: store, groupID: groupID)
    }

    /// Forget `groupID` here (works without Pro): the collection and its items stay, no longer shared.
    static func leave(store: any ItemStore, groupID: String) throws {
        try ShareGroups.leave(store: store, groupID: groupID)
    }

    /// Forget the share link of `collectionID` another of this person's devices published (`ShareGroups.forgetLink`).
    static func forgetLink(store: any ItemStore, collectionID: String) throws {
        try ShareGroups.forgetLink(store: store, collectionID: collectionID)
    }

    /// The stable reason code of a refused share action (the share screen words it).
    static func reason(_ error: Error) -> String {
        switch error {
        case let e as ShareGroupError: return e.reason
        case let e as KeyringError: return e.reason
        case is ShareProRequiredError: return "pro-required"
        case let e as SyncActionError: return e.reason
        case let e as FolderSyncError: return e.reason
        case let e as CollectionCatalog.Failure: return e == .limit ? "collection-limit" : "\(e)"
        case is LocalStoreError: return "busy"
        default: return "error"
        }
    }
}
