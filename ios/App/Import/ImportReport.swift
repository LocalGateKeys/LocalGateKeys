import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// The switch report after an import and its one-level undo (feature pack contract §6.1), shared by the iPhone and
/// the Mac. Counts come only from what was committed (read back from the store), never from the parsed file. The
/// journal (`LocalData.lastImport`) is kept until the next import or 7 days.
struct ImportReport: Identifiable, Equatable, Sendable {
    let id: String
    /// Committed items by `kind` (`web` for logins; `passkey` on its own), largest first.
    let counts: [KindCount]
    /// Rows not imported, by reason code.
    let skipped: [SkipCount]
    /// The journal holds something to undo.
    let canUndo: Bool

    struct KindCount: Equatable, Sendable { let kind: String; let count: Int }
    struct SkipCount: Equatable, Sendable { let reason: ImportJournal.SkipReason; let count: Int }

    static let title = String(localized: "What arrived")
    static let checkHint = String(localized: "Open a few items and check them before you delete the old app's data.")
    static let notInSource = String(localized: "The file didn't include these, so they couldn't be imported.")
    static let undoLabel = String(localized: "Undo this import")
    static let undoHelp = String(localized: "Items the last import added move to Recently deleted, and items it changed get their earlier version back. Anything changed since is kept.")

    init(id: String, counts: [String: Int], skipped: [ImportJournal.SkipReason: Int], canUndo: Bool) {
        self.id = id
        self.counts = counts.filter { $0.value > 0 }
            .sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }
            .map { KindCount(kind: $0.key, count: $0.value) }
        self.skipped = ImportJournal.SkipReason.allCases.compactMap { r in
            skipped[r].flatMap { $0 > 0 ? SkipCount(reason: r, count: $0) : nil }
        }
        self.canUndo = canUndo
    }

    /// "12 logins", "1 passkey" (`import.reportCount`).
    static func countLine(_ c: KindCount) -> String {
        let n = c.count
        switch c.kind {
        case "web", "desktop": return String(localized: "\(n) logins")
        case "passkey": return String(localized: "\(n) passkeys")
        case "note": return String(localized: "\(n) secure notes")
        case "card": return String(localized: "\(n) cards")
        case "identity": return String(localized: "\(n) identities")
        default: return String(localized: "\(n) items")
        }
    }

    static func skipLine(_ s: SkipCount) -> String {
        let n = s.count
        switch s.reason {
        case .duplicate: return String(localized: "Already saved: \(n)")
        case .unsupported: return String(localized: "Not supported: \(n)")
        case .overFreeLimit: return String(localized: "Over the free limit: \(n)")
        case .invalid: return String(localized: "Could not be read: \(n)")
        case .notInSourceFormat: return String(localized: "Not in the file: \(n)")
        }
    }

    static func skippedHeader(_ total: Int) -> String { String(localized: "Not imported (\(total))") }

    static func undoneText(_ trashed: Int) -> String { String(localized: "Import undone. \(trashed) items moved to Recently deleted.") }
    static func keptText(_ kept: Int) -> String { String(localized: "\(kept) items changed after the import were kept.") }
}

/// The journal, the report and the undo of one import, independent of the platform's Recently deleted.
enum ImportUndo {
    /// The live login and item records of `snapshot` (id → record).
    static func records(_ snapshot: StoreSnapshot) -> [String: [String: JSONValue]] {
        var out: [String: [String: JSONValue]] = [:]
        for (id, wrapper) in snapshot.itemRecords where snapshot.meta[id]?.deleted != true {
            guard case .object(let w) = wrapper, case .string(let ns)? = w["ns"],
                  ns == Namespace.entry.rawValue || ns == Namespace.item.rawValue,
                  case .object(let r)? = w["record"] else { continue }
            out[id] = r
        }
        return out
    }

    /// The ids an import wrote: in `planned` and new or different from `before`.
    static func changedIDs(before: StoreSnapshot, planned: StoreSnapshot) -> [String] {
        let old = records(before)
        return records(planned).compactMap { id, r in
            guard let o = old[id] else { return id }
            return RecordDigest.digest(.object(o)) == RecordDigest.digest(.object(r)) ? nil : id
        }.sorted()
    }

    /// The journal of the commit that took the vault from `before` to `committed` (read back after the commit), nil
    /// when nothing was written or it can't be encoded (an import is never refused for its journal).
    static func journal(before: StoreSnapshot, committed: StoreSnapshot, ids: [String], source: String,
                                    at: Int64, random: any RandomSource) -> ImportJournal? {
        let j = try? ImportJournal.make(importID: EditorModel.uuid4(random), at: at, source: source, ids: ids,
                                        before: records(before), after: records(committed))
        guard let j, !(j.created.isEmpty && j.replaced.isEmpty) else { return nil }
        return j
    }

    /// The report: counts read back from `committed` for the ids the journal lists.
    static func report(_ journal: ImportJournal?, committed: StoreSnapshot,
                                   skipped: [ImportJournal.SkipReason: Int], now: Int64) -> ImportReport {
        let ids = journal.map { Array($0.created.keys) + Array($0.replaced.keys) } ?? []
        return ImportReport(id: journal?.importID ?? UUID().uuidString,
                            counts: ImportJournal.counts(ids: ids, committed: records(committed)),
                            skipped: skipped, canUndo: journal?.isUndoable(now: now) ?? false)
    }

    /// What `undo` did.
    struct Outcome: Equatable, Sendable {
        var trashed = 0
        var restored = 0
        /// Changed since the import (or gone), so kept.
        var kept = 0
        var failed = false
    }

    /// Undoes `journal` on `store`: replaced records still as the import wrote them get their earlier version back
    /// (one commit, history `restore`); created items still as written go to Recently deleted through `moveToTrash`
    /// (returns the ids moved); anything changed since is kept and counted. The caller removes the journal.
    static func undo(_ journal: ImportJournal, store: any ItemStore, now: Int64,
                     moveToTrash: ([String]) -> [String]) -> Outcome {
        guard var snap = try? store.load() else { return Outcome(failed: true) }
        let plan = journal.undo(current: records(snap), now: now)
        var out = Outcome(kept: plan.kept.count)
        if !plan.restore.isEmpty {
            for id in plan.restore.keys.sorted() {
                guard let before = plan.restore[id] else { continue }
                let kind = before["kind"]?.stringValue ?? ""
                let ns: Namespace = kind == "web" || kind == "desktop" ? .entry : .item
                if ImportReviewModel.put(before, ns: ns, into: &snap) != nil { out.restored += 1 } else { out.kept += 1 }
            }
            if out.restored > 0 {
                do {
                    try HistoryContext.$changeType.withValue(.restore) {
                        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta,
                                                     sync: snap.sync))
                    }
                } catch { return Outcome(failed: true) }
            }
        }
        if !plan.trash.isEmpty {
            let moved = moveToTrash(plan.trash)
            out.trashed = moved.count
            out.kept += plan.trash.count - moved.count
        }
        return out
    }

    /// The message after an undo.
    static func message(_ o: Outcome) -> String {
        if o.failed { return String(localized: "The import could not be undone.") }
        var text = ImportReport.undoneText(o.trashed)
        if o.kept > 0 { text += " " + ImportReport.keptText(o.kept) }
        return text
    }
}

extension ImportReviewModel {
    /// The skipped-row reasons of this review (§6.1): rows the vault already had or the person skipped are
    /// `duplicate`, rows held back by the free plan `over_free_limit`, rows the file could not give `invalid`.
    var skipReasons: [ImportJournal.SkipReason: Int] {
        var out: [ImportJournal.SkipReason: Int] = [:]
        for row in rows {
            if row.limited { out[.overFreeLimit, default: 0] += 1; continue }
            guard row.decision == .skip else { continue }
            if row.isSkippedSource { out[.invalid, default: 0] += 1 } else { out[.duplicate, default: 0] += 1 }
        }
        return out
    }
}
