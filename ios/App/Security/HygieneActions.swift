import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// The clean-up sweep's changes (feature pack contract §3.2 and §3.3), shared by the iPhone and the Mac: merge one
/// pair (always reviewed first, never automatic), and the Pro bulk actions (delete many, merge every same login) with
/// one level of Undo. The platform brings its Recently deleted and its history recorder.
@MainActor
struct HygieneActions {
    enum Outcome: Equatable {
        case done
        case needsPro
        case refused(Hygiene.MergeRefusal)
        /// One of the items is in a collection shared with this vault as view only.
        case readOnly
        /// An item changed or went away after the review.
        case changed
        case failed
    }

    /// One reviewed merge: the keeper as it will be saved, and what changes in it.
    struct MergePreview: Identifiable, Equatable {
        var id: String { keeperID + "+" + otherID }
        let keeperID: String
        let otherID: String
        let kind: String
        /// The keeper before → after, secrets masked (`ItemHistory.diff`).
        let changes: [ItemHistory.FieldChange]
        let merged: [String: JSONValue]
        let keeperBefore: [String: JSONValue]
        let other: [String: JSONValue]
        /// Typed items: the merged collections, nil when the keeper's stay as they are.
        let collections: [String]?
    }

    let store: any ItemStore
    let now: () -> Int64
    let background: any BackgroundTasking
    /// Recently deleted: moves ids there, returns those moved.
    let moveToTrash: ([String]) -> [String]
    /// Puts items back from Recently deleted, returns how many came back.
    let restoreFromTrash: ([String]) -> Int
    /// The device's item history (the other copy of a merge is captured here; the keeper by the commit hook).
    let recordHistory: ([ItemHistory.Row]) -> Void
    var newID: () -> String = { UUID().uuidString.lowercased() }

    /// The last bulk action, kept in memory until the vault locks or the next bulk action (`clearUndo` at lock).
    private(set) static var lastBulk: Hygiene.UndoJournal?
    static func clearUndo() { lastBulk = nil }

    static let mergeReview = String(localized: "Check what will be kept before merging. The other copy goes to Recently deleted.")
    static let bulkNeedsPro = String(localized: "Cleaning up many items at once is part of Pro.")

    /// Findings whose items may be merged here, one reviewed pair at a time: same login, same account with another
    /// password, same username on related addresses, same item. A merge keeps the other login's website addresses
    /// (contract §3.2, 2026-11-15), so the kept login still fills on both.
    static func isMergeable(_ type: Hygiene.FindingType) -> Bool {
        type == .sameLogin || type == .sameAccountOtherPassword || type == .sameSite || type == .sameItem
    }

    static func refusalText(_ r: Hygiene.MergeRefusal) -> String {
        let reason: String = switch r {
        case .tooManyTags: String(localized: "together they have more than 20 tags.")
        case .tooManyValues: String(localized: "together they have too many addresses, fields, codes or collections.")
        case .notesTooLong: String(localized: "together their notes are too long.")
        case .notMergeable: String(localized: "they are not the same kind of item.")
        }
        return String(localized: "These items can't be merged: \(reason)")
    }

    static func text(_ o: Outcome) -> String? {
        switch o {
        case .done: nil
        case .needsPro: bulkNeedsPro
        case .refused(let r): refusalText(r)
        case .readOnly: EditorModel.readOnlyItemText
        case .changed: String(localized: "These items changed. Check them again.")
        case .failed: String(localized: "The change could not be saved on this device.")
        }
    }

    // MARK: - Merge one pair

    static func live(_ id: String, in snapshot: StoreSnapshot) -> (Namespace, [String: JSONValue])? {
        guard snapshot.meta[id]?.deleted != true, !CollectionStates.isStateID(id), case .object(let w)? = snapshot.records[id],
              case .string(let ns)? = w["ns"], let namespace = Namespace(rawValue: ns),
              namespace == .entry || namespace == .item, case .object(let r)? = w["record"] else { return nil }
        return (namespace, r)
    }

    /// What merging `otherID` into `keeperID` writes (§3.2), or why it can't.
    static func preview(keeper keeperID: String, other otherID: String, in snapshot: StoreSnapshot,
                        now: Int64) -> Result<MergePreview, Hygiene.MergeRefusal> {
        guard keeperID != otherID, case let (_, keeper)? = live(keeperID, in: snapshot),
              case let (_, other)? = live(otherID, in: snapshot) else {
            return .failure(.notMergeable)
        }
        let kind = keeper["kind"]?.stringValue ?? ""
        let merged: [String: JSONValue]
        do { merged = try Hygiene.merge(keeper: keeper, other: other, now: now) } catch { return .failure(error) }
        var collections: [String]?
        if kind != "web" {
            let mine = CollectionCatalog.memberships(of: keeperID, in: snapshot)
            let union: [String]
            do { union = try Hygiene.mergedCollections(mine, CollectionCatalog.memberships(of: otherID, in: snapshot)) } catch {
                return .failure(error)
            }
            if union.count != mine.count { collections = union }
        }
        return .success(MergePreview(keeperID: keeperID, otherID: otherID, kind: kind,
                                     changes: ItemHistory.diff(before: keeper, after: merged, kind: kind),
                                     merged: merged, keeperBefore: keeper, other: other, collections: collections))
    }

    /// Writes one reviewed merge: the keeper (captured in history as `merge` by the store hook), the other copy's
    /// version captured as `merge` too, then the other copy moves to Recently deleted (never purged by this).
    func merge(_ p: MergePreview) -> Outcome {
        guard var snap = try? store.load() else { return .failed }
        guard case let (ns, keeper)? = Self.live(p.keeperID, in: snap), case let (otherNS, other)? = Self.live(p.otherID, in: snap),
              RecordDigest.digest(.object(keeper)) == RecordDigest.digest(.object(p.keeperBefore)),
              RecordDigest.digest(.object(other)) == RecordDigest.digest(.object(p.other)) else { return .changed }
        if EditorModel.itemIsReadOnly(p.keeperID, in: snap) || EditorModel.itemIsReadOnly(p.otherID, in: snap) { return .readOnly }
        guard let normal = try? Normalise.normalForm(ns: ns, record: .object(p.merged)) else { return .failed }
        snap.records[p.keeperID] = Wrapper.make(ns: ns, record: normal)
        if let collections = p.collections {
            do {
                guard let change = try CollectionCatalog.setMemberships(itemID: p.keeperID, kind: p.kind, to: collections,
                                                                       in: snap) else { return .failed }
                snap.records = change.records
            } catch { return .refused(.tooManyValues) }
        }
        let change = StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync)
        do {
            try HistoryContext.$changeType.withValue(.merge) {
                try background.run("LocalGateKeys save") { try store.commit(change) }
            }
        } catch { return .failed }
        var stored = other
        stored["site_icon"] = nil
        if let row = try? ItemHistory.Row(snapshotID: newID(), itemID: p.otherID, ns: otherNS.rawValue, createdAt: now(),
                                          changeType: .merge, record: .object(stored)) {
            recordHistory([row])
        }
        return moveToTrash([p.otherID]).isEmpty ? .failed : .done
    }

    // MARK: - Bulk (Pro)

    /// Moves `ids` to Recently deleted; Undo puts them back.
    func deleteMany(_ ids: [String], isPro: Bool) -> Outcome {
        guard isPro else { return .needsPro }
        let moved = moveToTrash(ids)
        guard !moved.isEmpty else { return .failed }
        Self.lastBulk = Hygiene.UndoJournal(trashed: moved)
        return .done
    }

    /// Merges every `same_login` group into its newest copy (the group's first id). Groups a rule refuses are left as
    /// they are. Undo reverts each keeper still as the merge wrote it and puts the other copies back.
    func mergeAllSameLogins(_ findings: [Hygiene.Finding], isPro: Bool) -> Outcome {
        guard isPro else { return .needsPro }
        var journal = Hygiene.UndoJournal()
        var beforeOf: [String: [String: JSONValue]] = [:]
        var refused: Hygiene.MergeRefusal?
        for finding in findings where finding.type == .sameLogin {
            guard let keeperID = finding.ids.first else { continue }
            for otherID in finding.ids.dropFirst() {
                guard let snap = try? store.load() else { return .failed }
                switch Self.preview(keeper: keeperID, other: otherID, in: snap, now: now()) {
                case .failure(let r): refused = r
                case .success(let p):
                    if beforeOf[keeperID] == nil { beforeOf[keeperID] = p.keeperBefore }
                    if merge(p) == .done { journal.trashed.append(otherID) }
                }
            }
        }
        if let snap = try? store.load() {
            for (id, before) in beforeOf {
                guard case let (_, written)? = Self.live(id, in: snap) else { continue }
                journal.merged[id] = .init(before: before, writtenDigest: RecordDigest.digest(.object(written)))
            }
        }
        guard !journal.trashed.isEmpty || !journal.merged.isEmpty else { return refused.map { .refused($0) } ?? .done }
        Self.lastBulk = journal
        return .done
    }

    /// Undoes the last bulk action: keepers still as the merge wrote them get their earlier version back, and the
    /// items it moved to Recently deleted come back. Returns how many items changed.
    func undoLastBulk() -> Int {
        guard let journal = Self.lastBulk else { return 0 }
        Self.lastBulk = nil
        var changed = 0
        if var snap = try? store.load() {
            var current: [String: [String: JSONValue]] = [:]
            for id in journal.merged.keys { if case let (_, r)? = Self.live(id, in: snap) { current[id] = r } }
            let revert = journal.revertibleKeepers(current: current)
            for (id, before) in revert {
                guard case let (ns, _)? = Self.live(id, in: snap) else { continue }
                var record = before
                record["updated_at"] = .int(now())
                guard let normal = try? Normalise.normalForm(ns: ns, record: .object(record)) else { continue }
                snap.records[id] = Wrapper.make(ns: ns, record: normal)
                changed += 1
            }
            if changed > 0 {
                let change = StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync)
                do {
                    try HistoryContext.$changeType.withValue(.restore) {
                        try background.run("LocalGateKeys save") { try store.commit(change) }
                    }
                } catch { changed = 0 }
            }
        }
        return changed + restoreFromTrash(journal.trashed)
    }
}

/// The clean-up sweep's findings over the vault (feature pack §3), computed on this device with no network.
@MainActor
enum HygieneScan {
    static func findings(_ snapshot: StoreSnapshot, hidden: Set<String> = [], now: Int64, today: String,
                         matcher: URLMatcher) -> [Hygiene.Finding] {
        var records: [String: [String: JSONValue]] = [:]
        for (id, wrapper) in snapshot.itemRecords where snapshot.meta[id]?.deleted != true && !hidden.contains(id) {
            guard case .object(let w) = wrapper, case .string(let ns)? = w["ns"],
                  ns == Namespace.entry.rawValue || ns == Namespace.item.rawValue,
                  case .object(let r)? = w["record"] else { continue }
            records[id] = r
        }
        return Hygiene.findings(records, now: now, today: today, matcher: matcher)
    }

    static func label(_ type: Hygiene.FindingType) -> String {
        switch type {
        case .sameLogin: String(localized: "Same login saved more than once")
        case .sameAccountOtherPassword: String(localized: "Same account, different passwords")
        case .sameSite: String(localized: "Same username on related addresses")
        case .sameItem: String(localized: "Same item saved more than once")
        case .notChanged2y: String(localized: "Not changed in 2 years")
        case .expired: String(localized: "Expired cards and licences")
        }
    }
}
