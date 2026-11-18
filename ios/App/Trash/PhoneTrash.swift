import Foundation
import Observation
import SwiftUI
import AppShared

/// The iPhone's Recently deleted (UX plan workstream 3), the Mac `TrashModel` rules on the shared `LocalData`:
/// deleting saves the record as a trash row first, then removes it from the store with a tombstone (so the
/// delete still syncs); restoring writes the same record back live (a tomb's vector is kept, so another
/// device's delete is undone by the next sync, like Mac `RemoteDeletes`). Trash rows never count toward the
/// free limit; restoring over the limit is refused. Rows past the retention (1–365 days, default 30, the
/// Mac's key) are purged on unlock and on every write.
@MainActor @Observable
final class PhoneTrash {
    struct Row: Identifiable, Equatable {
        let id: String
        let itemID: String
        let title: String
        let detail: String
        let deletedAt: Int64
        fileprivate let index: Int
    }

    enum RestoreOutcome: Equatable { case restored, limit, failed(String) }

    nonisolated static let title = String(localized: "Recently deleted")
    nonisolated static let emptyText = String(localized: "Recently deleted is empty.")
    nonisolated static let saveFailedText = DeviceText.isPad ? String(localized: "ipad.phoneTrash.recentlyDeletedCouldNot", defaultValue: "Recently deleted could not be saved on this iPad.") : String(localized: "Recently deleted could not be saved on this iPhone.")
    nonisolated static let undoSeconds: Double = 5

    /// The last deleted item, for the Undo toast.
    private(set) var lastDeleted: (itemID: String, deletedAt: Int64)?

    @ObservationIgnored let local: any PhoneLocalHosting
    @ObservationIgnored private let store: any ItemStore
    @ObservationIgnored private let clock: any UnixClock
    @ObservationIgnored private let background: any BackgroundTasking
    @ObservationIgnored private let isPro: () -> Bool
    /// Called after Undo restored an item (the list reloads and a sync is scheduled).
    @ObservationIgnored var onRestored: () -> Void = {}

    init(local: any PhoneLocalHosting, store: any ItemStore, isPro: @escaping () -> Bool, clock: any UnixClock = SystemClock(),
         background: (any BackgroundTasking)? = nil) {
        self.local = local; self.store = store; self.isPro = isPro; self.clock = clock
        self.background = background ?? PlatformBackgroundTasks.make()
    }

    /// `moveToTrash` as the editors' delete hook.
    var mover: (String) -> SaveResult { { [self] id in moveToTrash(id: id) } }

    /// Shows "Moved to Recently deleted" with Undo for 5 seconds (after a delete that saved).
    func offerUndo(toast: UndoToast = .shared) {
        guard lastDeleted != nil else { return }
        toast.show(String(localized: "Moved to Recently deleted")) { [weak self] in
            guard let self else { return }
            switch self.undoLastDelete(isPro: self.isPro()) {
            case .restored: self.onRestored(); CopyToast.shared.show(String(localized: "Item restored"))
            case .limit: CopyToast.shared.show(String(localized: "Upgrade to Pro to restore more items"), for: .seconds(3))
            case .failed(let why): CopyToast.shared.show(why, for: .seconds(3))
            }
        }
    }

    // MARK: listing

    /// Newest first. Rows of items travel mode hides are left out (feature pack §2), as the list leaves them out.
    var rows: [Row] {
        guard let data = local.localData else { return [] }
        let trash = data.trash
        let hidden = Self.travelHidden(data, store: store)
        var seen: [String: Int] = [:]
        let rows = trash.enumerated().compactMap { index, row -> Row? in
            let record = (try? row.record())?.objectValue ?? [:]
            let itemID = record["id"]?.stringValue ?? ""
            if hidden.contains(itemID) { return nil }
            let item = VaultItem(id: itemID, record: record)
            let kind = item?.kindLabel ?? String(localized: "Item")
            let title = item.map { $0.title.isEmpty ? $0.kindLabel : $0.title } ?? kind
            let detail = item.map { $0.isLogin && !$0.username.isEmpty ? String(localized: "\(kind) · \($0.username)") : kind } ?? kind
            var key = "\(itemID)@\(row.deletedAt)"
            let n = seen[key, default: 0]; seen[key] = n + 1
            if n > 0 { key += "#\(n)" }
            return Row(id: key, itemID: itemID, title: title, detail: detail, deletedAt: row.deletedAt, index: index)
        }
        return rows.sorted { ($0.deletedAt, $0.index) > ($1.deletedAt, $1.index) }
    }

    /// The item ids travel mode hides here (Windows `hidden_id_set`): rows hidden by their own record, and rows of a
    /// live item it hides.
    private static func travelHidden(_ data: LocalData, store: any ItemStore) -> Set<String> {
        let travel = data.travel
        guard travel.on else { return [] }
        var out = travel.hiddenIDs(trashRecords: data.trash.compactMap { try? $0.record() })
        if let snap = try? store.load() { out.formUnion(travel.hiddenIDs(in: snap)) }
        return out
    }

    var retentionDays: Int { local.localData?.preferences.trashRetentionDays ?? 30 }

    /// Whole days left before `row` is purged (0 = goes at the next write).
    func daysLeft(_ row: Row) -> Int {
        let expires = row.deletedAt + Int64(retentionDays) * 86_400
        return max(0, Int((expires - clock.now + 86_399) / 86_400))
    }

    func setRetentionDays(_ days: Int) throws {
        guard var data = local.localData else { return }
        data.preferences.trashRetentionDays = min(max(days, 1), 365)
        data.purgeExpiredTrash(now: clock.now)
        try local.commitLocalData(data)
    }

    // MARK: delete

    /// Moves a live item to Recently deleted: the row is saved first, then the store change (a failed store
    /// commit takes the row out again, so the item is never lost from both). `.unchanged` when it was gone.
    func moveToTrash(id: String) -> SaveResult {
        guard var data = local.localData, let snap = try? store.load() else { return .failed }
        guard !CollectionStates.isStateID(id), case .object(let wrapper)? = snap.records[id], case .object? = wrapper["record"],
              let record = AttachmentDocuments.trashRecord(.object(wrapper)) else {
            return .unchanged
        }
        let now = clock.now
        // The row keeps the item's collections; the store delete drops its membership.
        guard let row = try? LocalData.TrashRow(record: CollectionCatalog.trashRecord(record, itemID: id, in: snap),
                                                deletedAt: now) else { return .failed }
        let previous = data
        data.trash.append(row)
        data.purgeExpiredTrash(now: now)
        do { try local.commitLocalData(data) } catch { return .failed }
        let r = EditorModel.delete(id: id, store: store, clock: clock, background: background)
        if r != .saved {
            try? local.commitLocalData(previous)
            return r
        }
        lastDeleted = (id, now)
        return .saved
    }

    /// Moves several live items to Recently deleted with one save of each store (the clean-up sweep's bulk delete and
    /// the undo of an import, feature pack §3.3 and §6.1), by the rules of `moveToTrash(id:)`. Items that are gone,
    /// collection states and view-only shared items are left out. Returns the ids moved, in `ids` order.
    func moveToTrash(ids: [String]) -> [String] {
        guard var data = local.localData, var snap = try? store.load() else { return [] }
        let now = clock.now
        let previous = data
        var moved: [String] = []
        for id in ids where !moved.contains(id) {
            guard !CollectionStates.isStateID(id), case .object(let wrapper)? = snap.records[id], case .object? = wrapper["record"],
                  !EditorModel.itemIsReadOnly(id, in: snap),
                  let record = AttachmentDocuments.trashRecord(.object(wrapper)),
                  let row = try? LocalData.TrashRow(record: CollectionCatalog.trashRecord(record, itemID: id, in: snap),
                                                    deletedAt: now) else { continue }
            // The tombstone as `EditorModel.delete` writes it (one bump for this device).
            var tomb: SyncMeta?
            if let m = snap.meta[id], !m.deleted, let device = snap.sync?.deviceID {
                guard let vv = try? VersionVector.bump(m.vv, device: device) else { continue }
                tomb = SyncMeta.tomb(vv: vv, deletedAt: now)
            }
            data.trash.append(row)
            snap.records[id] = nil
            snap.records = CollectionCatalog.withoutMembership(id, records: snap.records)
            if let tomb { snap.meta[id] = tomb }
            moved.append(id)
        }
        guard !moved.isEmpty else { return [] }
        data.purgeExpiredTrash(now: now)
        do { try local.commitLocalData(data) } catch { return [] }
        let change = StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync)
        do { try background.run("LocalGateKeys save") { try store.commit(change) } } catch {
            try? local.commitLocalData(previous)
            return []
        }
        return moved
    }

    /// Puts items back from Recently deleted (the newest row of each), as Restore does. Returns how many came back.
    @discardableResult
    func restoreItems(_ itemIDs: [String], isPro: Bool) -> Int {
        var restored = 0
        for itemID in itemIDs {
            guard let row = rows.first(where: { $0.itemID == itemID }) else { continue }
            if restore(row, isPro: isPro) == .restored { restored += 1 }
        }
        return restored
    }

    // MARK: restore

    func restore(_ rowID: String, isPro: Bool) -> RestoreOutcome {
        guard let row = rows.first(where: { $0.id == rowID }) else { return .failed(String(localized: "It is no longer in Recently deleted.")) }
        return restore(row, isPro: isPro)
    }

    /// The Undo toast: restores the item deleted last (if it is still in the trash).
    func undoLastDelete(isPro: Bool) -> RestoreOutcome {
        guard let last = lastDeleted,
              let row = rows.first(where: { $0.itemID == last.itemID && $0.deletedAt == last.deletedAt }) else {
            return .failed(String(localized: "It is no longer in Recently deleted."))
        }
        lastDeleted = nil
        return restore(row, isPro: isPro)
    }

    private func restore(_ row: Row, isPro: Bool) -> RestoreOutcome {
        guard var data = local.localData, data.trash.indices.contains(row.index),
              data.trash[row.index].deletedAt == row.deletedAt else { return .failed(String(localized: "It is no longer in Recently deleted.")) }
        guard case .object(let stored)? = try? data.trash[row.index].record(), case .string(let id)? = stored["id"], !id.isEmpty,
              !CollectionStates.isStateID(id),
              case .string(let kind)? = stored["kind"] else { return .failed(String(localized: "This entry can't be restored.")) }
        guard let snap = try? store.load() else { return .failed(String(localized: "The vault could not be read.")) }
        guard ItemLimit.allows(.restore, snapshot: snap, isPro: isPro) else { return .limit }
        if snap.records[id] != nil, snap.meta[id]?.deleted != true { return .failed(String(localized: "An item with the same ID already exists.")) }
        let ns: LGKCore.Namespace = kind == "web" || kind == "desktop" ? .entry : .item
        var next = snap
        // The row's collections become its membership again; the stored record never carries them.
        let back = CollectionCatalog.restored(stored, itemID: id, records: snap.records)
        next.records = back.records
        next.records[id] = AttachmentDocuments.restoredWrapper(.object(back.record), ns: ns)   // a document keeps its file
        if let m = snap.meta[id], m.deleted {
            // Live again: the tomb's vector is kept and bumped once at the next view, so the restore wins.
            next.meta[id] = SyncMeta(digest: nil, body: nil, updatedAt: nil, vv: m.vv, deleted: false, deletedAt: nil)
        }
        let change = StoreChange(baseRevision: snap.revision, records: next.records, meta: next.meta, sync: next.sync)
        do { try background.run("LocalGateKeys save") { try store.commit(change) } }
        catch { return .failed(String(localized: "The item could not be saved on this device.")) }
        data.trash.remove(at: row.index)
        data.purgeExpiredTrash(now: clock.now)
        do {
            try local.commitLocalData(data)
        } catch {
            // Store first, then the row: undo the store change so the item is not in both places.
            if var s = try? store.load() {
                let membership = CollectionStates.membershipPrefix + id
                s.records[id] = snap.records[id]; s.meta[id] = snap.meta[id]; s.records[membership] = snap.records[membership]
                try? store.commit(StoreChange(baseRevision: s.revision, records: s.records, meta: s.meta, sync: s.sync))
            }
            return .failed(Self.saveFailedText)
        }
        return .restored
    }

    // MARK: permanent delete

    func purge(_ rowIDs: Set<String>) throws {
        let wanted = rows.filter { rowIDs.contains($0.id) }
        guard !wanted.isEmpty, var data = local.localData else { return }
        for index in wanted.map(\.index).sorted(by: >) { data.trash.remove(at: index) }
        // Deleted for good: its earlier versions go too (scan 2026-11-15 W-M5, A-M3).
        if let snap = try? store.load() { data.forgetHistoryOfPurgedItems(snap) }
        try local.commitLocalData(data)
        collectAttachmentGarbage(data)
    }

    /// Files of documents purged for good (task 12): removed once nothing live and no remaining row needs them.
    private func collectAttachmentGarbage(_ data: LocalData) {
        AttachmentDocuments.collectGarbage(store: store, trash: data.trash.compactMap { try? $0.record() },
                                           blobs: AttachmentFiles.localFolder())
    }

    func emptyAll() throws { try purge(Set(rows.map(\.id))) }

    /// On unlock: drops rows past the retention period, and the item history of every item deleted for good (purged
    /// here or earlier, deleted with no trash, or deleted on another device; scan 2026-11-15 W-M5, A-M3).
    func purgeExpired() {
        guard var data = local.localData else { return }
        let before = data.trash.count
        data.purgeExpiredTrash(now: clock.now)
        let forgot = (try? store.load()).map { data.forgetHistoryOfPurgedItems($0) } ?? false
        guard data.trash.count != before || forgot else { return }
        if (try? local.commitLocalData(data)) != nil { collectAttachmentGarbage(data) }
    }
}

private struct PhoneTrashKey: EnvironmentKey {
    static let defaultValue: PhoneTrash? = nil
}

extension EnvironmentValues {
    /// Recently deleted while unlocked (nil: deletes are immediate, as before).
    var phoneTrash: PhoneTrash? {
        get { self[PhoneTrashKey.self] }
        set { self[PhoneTrashKey.self] = newValue }
    }
}
