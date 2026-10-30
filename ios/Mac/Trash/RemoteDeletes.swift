import Foundation
import LGKCore
import AppSharedMac

/// Deletes that arrive from elsewhere (sync from another device, a restored phone backup) move the record to
/// Recently deleted and never purge it (Windows `vault_bridge.py`). Recently deleted is saved first, then the
/// store; a failed store commit takes out exactly the rows it added (anything saved meanwhile stays), so an
/// item is never lost from both.
enum RemoteDeletes {
    /// Live logins and typed items in `before` that `records`/`meta` no longer hold live, as trash rows.
    static func trashRows(before: StoreSnapshot, records: [String: JSONValue], meta: [String: SyncMeta],
                          now: Int64) -> [LocalData.TrashRow] {
        var rows: [LocalData.TrashRow] = []
        for (id, wrapper) in before.records.sorted(by: { $0.key < $1.key }) where before.meta[id]?.deleted != true {
            guard records[id] == nil || meta[id]?.deleted == true, case .object(let w) = wrapper,
                  w["ns"] == .string(Namespace.entry.rawValue) || w["ns"] == .string(Namespace.item.rawValue),
                  case .object? = w["record"], let record = AttachmentDocuments.trashRecord(.object(w)),
                  let row = try? LocalData.TrashRow(record: record, deletedAt: now) else { continue }
            rows.append(row)
        }
        return rows
    }

    /// Appends `rows` to Recently deleted. Throws when it can't be saved.
    @MainActor
    static func save(_ rows: [LocalData.TrashRow], to local: any LocalDataHosting) throws {
        guard var data = local.localData else { throw LocalDataError.invalid("Recently deleted is not open") }
        data.trash += rows
        try local.commitLocalData(data)
    }

    /// Takes `rows` out of Recently deleted again, one match each by value, keeping everything else saved since.
    @MainActor
    static func remove(_ rows: [LocalData.TrashRow], from local: any LocalDataHosting) throws {
        guard var data = local.localData else { return }
        for row in rows {
            if let i = data.trash.lastIndex(of: row) { data.trash.remove(at: i) }
        }
        try local.commitLocalData(data)
    }

    /// Commits `change` through `commit`, first copying every live item it deletes to Recently deleted.
    /// May run off the main thread (sync); Recently deleted is always touched on the main actor.
    static func commit(_ change: StoreChange, before: StoreSnapshot, local: any LocalDataHosting, now: Int64,
                       _ commit: (StoreChange) throws -> Void) throws {
        let rows = trashRows(before: before, records: change.records, meta: change.meta, now: now)
        guard !rows.isEmpty else { try commit(change); return }
        nonisolated(unsafe) let local = local
        try onMain { try save(rows, to: local) }
        do { try commit(change) } catch {
            try? onMain { try remove(rows, from: local) }
            throw error
        }
    }

    private static func onMain<T: Sendable>(_ body: @MainActor () throws -> T) throws -> T {
        if Thread.isMainThread { return try MainActor.assumeIsolated(body) }
        nonisolated(unsafe) let body = body
        nonisolated(unsafe) var result: Result<T, Error>!
        DispatchQueue.main.sync { result = Result { try MainActor.assumeIsolated(body) } }
        return try result.get()
    }
}
