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
    nonisolated static let saveFailedText = String(localized: "Recently deleted could not be saved on this iPhone.")
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

    /// Newest first.
    var rows: [Row] {
        guard let trash = local.localData?.trash else { return [] }
        var seen: [String: Int] = [:]
        let rows = trash.enumerated().map { index, row -> Row in
            let record = (try? row.record())?.objectValue ?? [:]
            let itemID = record["id"]?.stringValue ?? ""
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
        guard case .object(let wrapper)? = snap.records[id], case .object? = wrapper["record"],
              let record = AttachmentDocuments.trashRecord(.object(wrapper)) else {
            return .unchanged
        }
        let now = clock.now
        guard let row = try? LocalData.TrashRow(record: record, deletedAt: now) else { return .failed }
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
        guard case .object(let record)? = try? data.trash[row.index].record(), case .string(let id)? = record["id"], !id.isEmpty,
              case .string(let kind)? = record["kind"] else { return .failed(String(localized: "This entry can't be restored.")) }
        guard let snap = try? store.load() else { return .failed(String(localized: "The vault could not be read.")) }
        guard ItemLimit.allows(.restore, snapshot: snap, isPro: isPro) else { return .limit }
        if snap.records[id] != nil, snap.meta[id]?.deleted != true { return .failed(String(localized: "An item with the same ID already exists.")) }
        let ns: LGKCore.Namespace = kind == "web" || kind == "desktop" ? .entry : .item
        var next = snap
        next.records[id] = AttachmentDocuments.restoredWrapper(.object(record), ns: ns)   // a document keeps its file
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
                s.records[id] = snap.records[id]; s.meta[id] = snap.meta[id]
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
        try local.commitLocalData(data)
        collectAttachmentGarbage(data)
    }

    /// Files of documents purged for good (task 12): removed once nothing live and no remaining row needs them.
    private func collectAttachmentGarbage(_ data: LocalData) {
        AttachmentDocuments.collectGarbage(store: store, trash: data.trash.compactMap { try? $0.record() },
                                           blobs: AttachmentFiles.localFolder())
    }

    func emptyAll() throws { try purge(Set(rows.map(\.id))) }

    /// On unlock: drops rows past the retention period.
    func purgeExpired() {
        guard var data = local.localData else { return }
        let before = data.trash.count
        data.purgeExpiredTrash(now: clock.now)
        guard data.trash.count != before else { return }
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
