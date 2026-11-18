import XCTest
import AppShared
@testable import LocalGateKeys

/// Feature pack part A on the iPhone (shared with the Mac): the import journal and its undo, the clean-up sweep's
/// merge and bulk actions with Undo, Recently deleted for many items, and the travel filters of Collections and the
/// Security check.
@MainActor
final class FeaturePackPartATests: XCTestCase {
    let clock = TestClock(1_800_000_000)
    let a = "aaaaaaaa-0000-4000-8000-00000000000a"
    let b = "bbbbbbbb-0000-4000-8000-00000000000b"
    let c = "cccccccc-0000-4000-8000-00000000000c"

    override func tearDown() { HygieneActions.clearUndo(); super.tearDown() }

    private func web(_ id: String, user: String = "sam", password: String = "pw-1", updated: Int64 = 1_790_000_000,
                     tags: [String] = [], origin: String = "https://example.com") -> JSONValue {
        rec(["id": .string(id), "kind": .string("web"), "label": .string("Example"), "username": .string(user),
             "password": .string(password), "scope": rec(["origin": .string(origin)]),
             "tags": strs(tags), "updated_at": .int(updated)])
    }

    private func noteItem(_ id: String, body: String = "x") -> JSONValue {
        rec(["id": .string(id), "kind": .string("note"), "title": .string("Cabin"),
             "payload": rec(["body": .string(body), "fields": .array([])]), "updated_at": .int(1_790_000_000)])
    }

    private func trash(_ store: MemoryStore) -> PhoneTrash {
        PhoneTrash(local: InMemoryPhoneLocal(), store: store, isPro: { true }, clock: clock, background: FakeBackgroundTasks())
    }

    private func record(_ store: MemoryStore, _ id: String) -> [String: JSONValue]? {
        ImportUndo.records(store.snapshot)[id]
    }

    // MARK: Recently deleted, many at once

    func testMoveManyToTrashSkipsGoneItemsAndRestoresThem() {
        let store = MemoryStore(snapshot([web(a), noteItem(b)]))
        let t = trash(store)
        XCTAssertEqual(t.moveToTrash(ids: [a, "missing", b, a]), [a, b])
        XCTAssertNil(store.snapshot.records[a]); XCTAssertNil(store.snapshot.records[b])
        XCTAssertEqual(Set(t.rows.map(\.itemID)), [a, b])
        XCTAssertEqual(store.commits, 1, "one store save for the batch")
        XCTAssertEqual(t.restoreItems([a, b], isPro: true), 2)
        XCTAssertNotNil(store.snapshot.records[a]); XCTAssertNotNil(store.snapshot.records[b])
    }

    func testMoveManyToTrashWithNothingToMoveSavesNothing() {
        let store = MemoryStore(snapshot([web(a)]))
        XCTAssertEqual(trash(store).moveToTrash(ids: ["missing"]), [])
        XCTAssertEqual(store.commits, 0)
    }

    // MARK: Import journal and undo (§6.1)

    /// The vault before: login a. The import replaces a (new password) and creates note b.
    private func imported() -> (MemoryStore, ImportJournal) {
        let before = snapshot([web(a)])
        let store = MemoryStore(before)
        var planned = before
        planned.records[a] = Wrapper.make(ns: .entry, record: web(a, password: "pw-2", updated: 1_800_000_000))
        planned.records[b] = Wrapper.make(ns: .item, record: noteItem(b))
        let ids = ImportUndo.changedIDs(before: before, planned: planned)
        XCTAssertEqual(ids, [a, b].sorted())
        try! store.commit(StoreChange(baseRevision: store.snapshot.revision, records: planned.records, meta: planned.meta,
                                      sync: planned.sync))
        let journal = ImportUndo.journal(before: before, committed: store.snapshot, ids: ids, source: "csv",
                                         at: clock.now, random: CountingRandom())
        return (store, journal!)
    }

    func testJournalListsCreatedAndReplacedAndTheReportCountsWhatWasCommitted() {
        let (store, journal) = imported()
        XCTAssertEqual(Array(journal.created.keys), [b])
        XCTAssertEqual(Array(journal.replaced.keys), [a])
        let report = ImportUndo.report(journal, committed: store.snapshot, skipped: [.duplicate: 2], now: clock.now)
        XCTAssertEqual(report.counts.map(\.kind).sorted(), ["note", "web"])
        XCTAssertEqual(report.skipped, [ImportReport.SkipCount(reason: .duplicate, count: 2)])
        XCTAssertTrue(report.canUndo)
        let late = ImportUndo.report(journal, committed: store.snapshot, skipped: [:], now: clock.now + ImportJournal.keepSeconds + 1)
        XCTAssertFalse(late.canUndo, "kept 7 days")
    }

    func testNothingWrittenMakesNoJournal() {
        let before = snapshot([web(a)])
        XCTAssertNil(ImportUndo.journal(before: before, committed: before, ids: [], source: "csv", at: 1, random: CountingRandom()))
    }

    func testUndoTrashesCreatedAndRestoresReplaced() {
        let (store, journal) = imported()
        let t = trash(store)
        let out = ImportUndo.undo(journal, store: store, now: clock.now, moveToTrash: { t.moveToTrash(ids: $0) })
        XCTAssertEqual(out, ImportUndo.Outcome(trashed: 1, restored: 1, kept: 0, failed: false))
        XCTAssertNil(store.snapshot.records[b])
        XCTAssertEqual(t.rows.map(\.itemID), [b], "created items go to Recently deleted, never purged")
        XCTAssertEqual(record(store, a)?["password"], .string("pw-1"))
    }

    func testUndoKeepsWhatChangedSinceTheImport() {
        let (store, journal) = imported()
        var snap = store.snapshot
        snap.records[b] = Wrapper.make(ns: .item, record: noteItem(b, body: "edited after"))
        snap.records[a] = Wrapper.make(ns: .entry, record: web(a, password: "pw-3"))
        try! store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        let t = trash(store)
        let out = ImportUndo.undo(journal, store: store, now: clock.now, moveToTrash: { t.moveToTrash(ids: $0) })
        XCTAssertEqual(out, ImportUndo.Outcome(trashed: 0, restored: 0, kept: 2, failed: false))
        XCTAssertNotNil(store.snapshot.records[b])
        XCTAssertEqual(record(store, a)?["password"], .string("pw-3"))
        XCTAssertTrue(ImportUndo.message(out).contains("2"))
    }

    // MARK: Clean-up sweep (§3.2, §3.3)

    private func actions(_ store: MemoryStore, _ t: PhoneTrash, history: @escaping ([ItemHistory.Row]) -> Void = { _ in })
        -> HygieneActions {
        var n = 0
        var x = HygieneActions(store: store, now: { 1_800_000_000 }, background: FakeBackgroundTasks(),
                               moveToTrash: { t.moveToTrash(ids: $0) }, restoreFromTrash: { t.restoreItems($0, isPro: true) },
                               recordHistory: history)
        x.newID = { n += 1; return "snap-\(n)" }
        return x
    }

    func testMergeKeepsOneCopyMovesTheOtherToTrashAndRecordsAMergeVersion() throws {
        let store = MemoryStore(snapshot([web(a, updated: 2, tags: ["Work"]), web(b, updated: 1, tags: ["Home"])]))
        let t = trash(store)
        var rows: [ItemHistory.Row] = []
        let preview = try HygieneActions.preview(keeper: a, other: b, in: store.snapshot, now: clock.now).get()
        XCTAssertFalse(preview.changes.isEmpty, "the review shows what changes")
        XCTAssertEqual(actions(store, t, history: { rows += $0 }).merge(preview), .done)
        XCTAssertNil(store.snapshot.records[b])
        XCTAssertEqual(t.rows.map(\.itemID), [b])
        XCTAssertEqual(record(store, a)?["tags"], strs(["Work", "Home"]))
        XCTAssertEqual(rows.map(\.itemID), [b])
        XCTAssertEqual(rows.map(\.changeType), [ItemHistory.ChangeType.merge.rawValue])
    }

    func testMergeRefusesWhenAnItemChangedAfterTheReview() throws {
        let store = MemoryStore(snapshot([web(a, updated: 2), web(b, updated: 1)]))
        let preview = try HygieneActions.preview(keeper: a, other: b, in: store.snapshot, now: clock.now).get()
        var snap = store.snapshot
        snap.records[b] = Wrapper.make(ns: .entry, record: web(b, password: "changed"))
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        XCTAssertEqual(actions(store, trash(store)).merge(preview), .changed)
        XCTAssertNotNil(store.snapshot.records[b])
    }

    func testDifferentKindsCannotBeMerged() {
        let store = MemoryStore(snapshot([web(a), noteItem(b)]))
        guard case .failure(.notMergeable) = HygieneActions.preview(keeper: a, other: b, in: store.snapshot, now: 1) else {
            return XCTFail("a login and a note are not merged")
        }
    }

    func testOnlyDuplicateFindingsOfferAMerge() {
        XCTAssertTrue(HygieneActions.isMergeable(.sameLogin))
        XCTAssertTrue(HygieneActions.isMergeable(.sameAccountOtherPassword))
        XCTAssertTrue(HygieneActions.isMergeable(.sameItem))
        XCTAssertTrue(HygieneActions.isMergeable(.sameSite), "the merge keeps the other login's address")
        XCTAssertFalse(HygieneActions.isMergeable(.expired))
    }

    func testSameSiteMergeKeepsTheOtherAddress() {
        let store = MemoryStore(snapshot([web(a), web(b, origin: "https://www.example.com")]))
        guard case .success(let p) = HygieneActions.preview(keeper: a, other: b, in: store.snapshot, now: 1) else {
            return XCTFail("a same-site pair merges")
        }
        let scope = p.merged["scope"]?.objectValue
        XCTAssertEqual(scope?["origin"], .string("https://example.com"))
        XCTAssertEqual(scope?["urls"], .array([
            .object(["url": .string("https://example.com"), "match": .string("exact_origin")]),
            .object(["url": .string("https://www.example.com"), "match": .string("exact_origin")]),
        ]))
    }

    func testBulkDeleteNeedsProAndUndoPutsItemsBack() {
        let store = MemoryStore(snapshot([web(a), noteItem(b), noteItem(c)]))
        let t = trash(store)
        let x = actions(store, t)
        XCTAssertEqual(x.deleteMany([a, b], isPro: false), .needsPro)
        XCTAssertNotNil(store.snapshot.records[a])
        XCTAssertEqual(x.deleteMany([a, b], isPro: true), .done)
        XCTAssertNil(store.snapshot.records[a]); XCTAssertNil(store.snapshot.records[b])
        XCTAssertNotNil(HygieneActions.lastBulk)
        XCTAssertEqual(x.undoLastBulk(), 2)
        XCTAssertNotNil(store.snapshot.records[a]); XCTAssertNotNil(store.snapshot.records[b])
        XCTAssertNil(HygieneActions.lastBulk, "one level of undo")
    }

    func testMergeAllSameLoginsAndUndo() {
        let store = MemoryStore(snapshot([web(a, updated: 3), web(b, updated: 2), web(c, updated: 1)]))
        let before = record(store, a)
        let t = trash(store)
        let x = actions(store, t)
        let finding = Hygiene.Finding(type: .sameLogin, ids: [a, b, c])
        XCTAssertEqual(x.mergeAllSameLogins([finding], isPro: false), .needsPro)
        XCTAssertEqual(x.mergeAllSameLogins([finding], isPro: true), .done)
        XCTAssertNotNil(store.snapshot.records[a])
        XCTAssertNil(store.snapshot.records[b]); XCTAssertNil(store.snapshot.records[c])
        XCTAssertEqual(x.undoLastBulk(), 3, "the keeper reverted and two copies back")
        XCTAssertNotNil(store.snapshot.records[b]); XCTAssertNotNil(store.snapshot.records[c])
        XCTAssertEqual(record(store, a)?["password"], before?["password"])
        XCTAssertEqual(record(store, a)?["tags"], before?["tags"])
    }

    func testClearUndoAtLockForgetsTheBulkAction() {
        let store = MemoryStore(snapshot([web(a)]))
        _ = actions(store, trash(store)).deleteMany([a], isPro: true)
        HygieneActions.clearUndo()
        XCTAssertEqual(actions(store, trash(store)).undoLastBulk(), 0)
    }

    // MARK: Travel filters (§2)

    func testSecurityCheckLeavesTravelHiddenItemsOut() {
        let snap = snapshot([web(a, tags: ["Trip"]), web(b)])
        let hidden = TravelMode(on: true, tags: ["trip"]).hiddenIDs(in: snap)
        XCTAssertEqual(hidden, [a])
        let findings = HygieneScan.findings(snap, hidden: hidden, now: clock.now, today: "2026-11-15",
                                            matcher: SafariSaveService.bundledMatcher())
        XCTAssertFalse(findings.contains { $0.ids.contains(a) }, "clean-up never lists a hidden item")
    }

    func testSecurityCheckModelUsesTheTravelFilter() {
        let settings = AppSettings(defaults: UserDefaults(suiteName: "fpa-\(UUID().uuidString)")!)
        let model = SecurityCheckModel(store: MemoryStore(snapshot([web(a, tags: ["Trip"]), web(b)])), settings: settings,
                                       clock: { Date(timeIntervalSince1970: 1_800_000_000) })
        model.hidden = { TravelMode(on: true, tags: ["trip"]).hiddenIDs(in: $0) }
        model.refresh()
        XCTAssertEqual(model.items.map(\.id), [b], "a travel-hidden login is not checked or listed")
    }
}
