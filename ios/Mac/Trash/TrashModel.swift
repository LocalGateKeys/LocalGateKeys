import Foundation
import Observation
import LGKCore
import AppSharedMac

/// Recently deleted (Windows `TrashService`): deleting an item moves its record here and removes it from the
/// store, which publishes a tombstone; restoring writes the same bytes back live. Every change writes the store
/// first and the Mac-local data second, undoing the store change when the local save fails, so an item is never
/// lost from both.
@MainActor @Observable
final class TrashModel {
    struct Row: Identifiable, Equatable {
        let id: String
        let itemID: String
        let title: String
        /// "{kind label}", or "{kind label} · {username}" for logins (as Windows).
        let detail: String
        let deletedAt: Int64
        /// Position in `LocalData.trash`.
        fileprivate let index: Int
    }

    enum Failure: Error, Equatable { case notFound, locked, store, localSave, compensation }

    static let title = String(localized: "Recently deleted")
    static let emptyText = String(localized: "Recently deleted is empty.")
    static let deleteFailedMessage = String(localized: "The item could not be deleted on this device.")

    /// Rows selected for Restore or Delete selected.
    var selected: Set<String> = []
    /// The last result line ("Restored 1 item(s).").
    var message: String?
    /// Failures of the last action.
    var failures: [String] = []

    @ObservationIgnored private let store: any ItemStore
    @ObservationIgnored private let local: any LocalDataHosting
    @ObservationIgnored private let isPro: () -> Bool
    @ObservationIgnored private let onNeedsPro: (ProReason) -> Void
    @ObservationIgnored private let activity: ActivityRecorder?
    @ObservationIgnored private let clock: () -> Date

    init(store: any ItemStore, local: any LocalDataHosting, isPro: @escaping () -> Bool,
         onNeedsPro: @escaping (ProReason) -> Void, activity: ActivityRecorder?, clock: @escaping () -> Date = Date.init) {
        self.store = store; self.local = local; self.isPro = isPro; self.onNeedsPro = onNeedsPro
        self.activity = activity; self.clock = clock
    }

    private var now: Int64 { Int64(clock().timeIntervalSince1970) }

    // MARK: - Listing

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

    var retentionText: String {
        let prefs = local.localData?.preferences ?? LocalData.LocalPreferences()
        if prefs.trashAutoPurge {
            if prefs.trashRetentionDays == 1 {
                return String(localized: "Entries stay encrypted for 1 day. Expired entries are purged on the next vault write. Older backups may retain copies.")
            }
            return String(localized: "Entries stay encrypted for \(prefs.trashRetentionDays) days. Expired entries are purged on the next vault write. Older backups may retain copies.")
        }
        return String(localized: "Automatic emptying is off, so entries stay encrypted here until you delete them. Older backups may retain copies.")
    }

    var countText: String {
        let total = rows.count
        let picked = selected.intersection(rows.map(\.id)).count
        return picked > 0 ? String(localized: "\(picked) of \(total) selected") : String(localized: "\(total) item(s)")
    }

    func toggle(_ id: String) { if selected.contains(id) { selected.remove(id) } else { selected.insert(id) } }

    // MARK: - Delete

    /// Moves a live item to Recently deleted.
    ///
    /// Deliberately the reverse of the plan's "store commit first": the trash row is saved first, then the
    /// record leaves the store (tombstoned like the iPhone's delete). If the app dies in between, the item is
    /// still live and the trash holds a harmless duplicate (its restore is refused while the item is live);
    /// it is never lost from both. A failed store commit removes the row again; if even that save fails, both
    /// copies are kept and `Failure.compensation` is thrown.
    func moveToTrash(id: String) throws {
        guard var data = local.localData else { throw Failure.locked }
        let snap: StoreSnapshot
        do { snap = try store.load() } catch { throw Failure.store }
        guard case .object(let wrapper)? = snap.records[id], case .object? = wrapper["record"],
              let record = AttachmentDocuments.trashRecord(.object(wrapper)) else { throw Failure.notFound }
        let row: LocalData.TrashRow
        do { row = try LocalData.TrashRow(record: record, deletedAt: now) } catch { throw Failure.store }
        var next = snap
        next.records[id] = nil
        if let m = snap.meta[id], !m.deleted, let device = snap.sync?.deviceID {
            do { next.meta[id] = SyncMeta.tomb(vv: try VersionVector.bump(m.vv, device: device), deletedAt: now) }
            catch { throw Failure.store }
        }
        let previous = data
        data.trash.append(row)
        data.purgeExpiredTrash(now: now)
        do { try local.commitLocalData(data) } catch { throw Failure.localSave }
        do {
            try store.commit(StoreChange(baseRevision: snap.revision, records: next.records, meta: next.meta, sync: next.sync))
        } catch {
            do { try local.commitLocalData(previous) } catch { compensationFailed(); throw Failure.compensation }
            throw Failure.store
        }
        activity?.record(.itemDelete, itemID: id, count: 1)
    }

    static let compensationMessage = String(localized: "Recently deleted couldn't be updated.")

    private func compensationFailed() {
        failures = [Self.compensationMessage]
        message = nil
    }

    /// Re-applies a store change on the current snapshot (used when the local save failed). False when it couldn't.
    private func undo(_ change: (inout StoreSnapshot) -> Void) -> Bool {
        guard var s = try? store.load() else { return false }
        change(&s)
        do { try store.commit(StoreChange(baseRevision: s.revision, records: s.records, meta: s.meta, sync: s.sync)) }
        catch { return false }
        return true
    }

    // MARK: - Restore

    /// Restores the rows newest first, stopping at the free item limit (the rest stay here and the Pro sheet
    /// shows). Each row: the record is written back live, then the row leaves the local data.
    func restore(_ ids: Set<String>) {
        failures = []
        var restored = 0
        for key in rows.map(\.id) where ids.contains(key) {
            // Looked up again each time: a restored row shifts the positions of the others.
            guard let row = rows.first(where: { $0.id == key }) else { continue }
            switch restoreOne(row) {
            case .restored: restored += 1
            case .limit:
                onNeedsPro(.itemLimit)
                finish(String(localized: "Restored \(restored) item(s)."), restored: restored)
                return
            case .failed(let why): failures.append(String(localized: "\(row.title): \(why)"))
            }
        }
        finish(String(localized: "Restored \(restored) item(s)."), restored: restored)
    }

    private func finish(_ text: String, restored: Int) {
        message = text
        selected = []
        if restored > 0 { activity?.record(.itemRestore, count: restored) }
    }

    private enum Outcome: Equatable { case restored, limit, failed(String) }

    private func restoreOne(_ row: Row) -> Outcome {
        guard var data = local.localData, let stored = data.trash.indices.contains(row.index) ? data.trash[row.index] : nil,
              stored.deletedAt == row.deletedAt else { return .failed(String(localized: "It is no longer in Recently deleted.")) }
        guard case .object(let record)? = try? stored.record(), case .string(let id)? = record["id"], !id.isEmpty,
              case .string(let kind)? = record["kind"] else { return .failed(String(localized: "This entry can't be restored.")) }
        guard let snap = try? store.load() else { return .failed(String(localized: "The vault could not be read.")) }
        guard ItemLimit.allows(.restore, snapshot: snap, isPro: isPro()) else { return .limit }
        if snap.records[id] != nil, snap.meta[id]?.deleted != true { return .failed(String(localized: "An item with the same ID already exists.")) }
        let ns: Namespace = kind == "web" || kind == "desktop" ? .entry : .item
        var next = snap
        next.records[id] = AttachmentDocuments.restoredWrapper(.object(record), ns: ns)   // a document keeps its file
        if let m = snap.meta[id], m.deleted {
            // Live again: the tomb's vector is kept and bumped once at the next view (no digest matches).
            next.meta[id] = SyncMeta(digest: nil, body: nil, updatedAt: nil, vv: m.vv, deleted: false, deletedAt: nil)
        }
        do { try store.commit(StoreChange(baseRevision: snap.revision, records: next.records, meta: next.meta, sync: next.sync)) }
        catch { return .failed(String(localized: "The item could not be saved on this device.")) }
        data.trash.remove(at: row.index)
        do {
            try local.commitLocalData(data)
        } catch {
            // Store first, then the row: if the undo fails too, the item is live and still in the trash (both copies).
            guard undo({ s in s.records[id] = snap.records[id]; s.meta[id] = snap.meta[id] }) else {
                return .failed(Self.compensationMessage)
            }
            return .failed(String(localized: "Recently deleted could not be saved on this Mac."))
        }
        return .restored
    }

    // MARK: - Permanent delete

    /// The confirmation text for permanently deleting `ids` (Windows `TrashService.purge`).
    func purgeConfirmText(_ ids: Set<String>) -> String {
        let wanted = rows.filter { ids.contains($0.id) }
        if wanted.count == 1 {
            return String(localized: "Permanently delete \u{2018}\(wanted[0].title)\u{2019}? This cannot be undone. Previous backups can still contain it.")
        }
        return String(localized: "Permanently delete \(wanted.count) items? This cannot be undone. Previous backups can still contain them.")
    }

    func purge(_ ids: Set<String>) {
        failures = []
        let wanted = rows.filter { ids.contains($0.id) }
        guard !wanted.isEmpty, var data = local.localData else { message = String(localized: "Permanently deleted 0 item(s)."); return }
        for index in wanted.map(\.index).sorted(by: >) { data.trash.remove(at: index) }
        do {
            try local.commitLocalData(data)
        } catch {
            failures = [String(localized: "Recently deleted could not be saved on this Mac.")]
            message = String(localized: "Permanently deleted 0 item(s).")
            return
        }
        selected = []
        collectAttachmentGarbage(data)
        message = String(localized: "Permanently deleted \(wanted.count) item(s).")
        activity?.record(.itemClear, result: .deleted, count: wanted.count)
    }

    func emptyAll() { purge(Set(rows.map(\.id))) }

    /// Files of documents purged for good (task 12): removed once nothing live and no remaining row needs them.
    private func collectAttachmentGarbage(_ data: LocalData) {
        AttachmentDocuments.collectGarbage(store: store, trash: data.trash.compactMap { try? $0.record() },
                                           blobs: AttachmentFiles.localFolder())
    }

    /// Auto-purge (on unlock and every write): drops rows past the retention period when it is on.
    func purgeExpired() {
        guard var data = local.localData else { return }
        let before = data.trash.count
        data.purgeExpiredTrash(now: now)
        guard data.trash.count != before else { return }
        do {
            try local.commitLocalData(data)
            collectAttachmentGarbage(data)
        } catch {
            failures = [String(localized: "Recently deleted could not be saved on this Mac.")]
            message = String(localized: "Expired items could not be removed.")
        }
    }
}
