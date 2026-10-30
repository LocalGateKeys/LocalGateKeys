import XCTest
import LGKCore
@testable import AppSharedMac

/// Applies changes like LocalStore (a stale base is refused) and counts the commits.
private final class ReviewMemoryStore: ItemStore, @unchecked Sendable {
    var snapshot = StoreSnapshot()
    private(set) var commits = 0
    func load() throws -> StoreSnapshot { snapshot }
    func commit(_ change: StoreChange) throws {
        guard change.baseRevision == snapshot.revision else {
            throw LocalStoreError.stale(expected: change.baseRevision, actual: snapshot.revision)
        }
        snapshot = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: snapshot.revision + 1)
        commits += 1
    }
}

private final class CommitLog: @unchecked Sendable {
    private let lock = NSLock()
    private var calls: [Bool] = []
    func add(_ fromSync: Bool) { lock.withLock { calls.append(fromSync) } }
    var all: [Bool] { lock.withLock { calls } }
}

/// The review model shared by the Mac and iPhone imports: Windows `import_workflow.py` duplicates, decisions,
/// free-plan slots ("Needs Pro"), two-factor keys on the free plan and the save-time caps.
@MainActor
final class ImportReviewModelTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let otp = "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP&issuer=Example"

    private func login(_ host: String, _ user: String = "ada", _ password: String = "pw", otp: String? = nil,
                       title: String? = nil) -> ImportCandidate {
        ImportCandidate(title: title ?? host, kind: .login(LoginFields(url: "https://\(host)/login", username: user,
                                                                      password: password, notes: "", otpauth: otp)))
    }

    private func model(_ candidates: [ImportCandidate], skipped: [ImportSkip] = [], store: ReviewMemoryStore,
                       freeSlots: Int? = nil) throws -> ImportReviewModel {
        ImportReviewModel(result: LGKCore.ImportResult(candidates: candidates, skipped: skipped), snapshot: try store.load(),
                          freeSlots: freeSlots, now: { [now] in now }, random: SystemRandomSource())
    }

    private func records(_ store: ReviewMemoryStore, ns: Namespace) -> [[String: JSONValue]] {
        store.snapshot.records.values.compactMap { w -> [String: JSONValue]? in
            guard case .object(let o) = w, o["ns"] == .string(ns.rawValue) else { return nil }
            return o["record"]?.objectValue
        }
    }

    private func seed(_ store: ReviewMemoryStore, _ candidates: [ImportCandidate]) async throws {
        _ = try await model(candidates, store: store).commit(to: store)
    }

    func testDuplicateDefaultsToSkip() async throws {
        let store = ReviewMemoryStore()
        try await seed(store, [login("a.com")])
        let m = try model([login("a.com"), login("b.com"), login("b.com")], store: store)
        XCTAssertEqual(m.rows.map(\.status), [.duplicate, .new, .duplicate])
        XCTAssertEqual(m.rows.map(\.decision), [.skip, .create, .skip])
        XCTAssertNotNil(m.rows[0].targetID)
        XCTAssertNil(m.rows[2].targetID, "a repeat inside the import has no vault target")
        // A repeat with a different password is kept as a secure-note copy, as on Windows.
        let differing = try model([login("c.com", "ada", "one"), login("c.com", "ada", "two")], store: store)
        XCTAssertEqual(differing.rows[1].status, .duplicate)
        XCTAssertEqual(differing.rows[1].decision, .keepBoth)
        differing.set(.create, for: differing.rows[1].id)
        XCTAssertEqual(differing.rows[1].decision, .keepBoth, "a repeat inside the import can only be skipped or copied")
    }

    func testConflictOffersReplaceOrMerge() async throws {
        let store = ReviewMemoryStore()
        try await seed(store, [login("a.com", "ada", "old", title: "Old title")])
        let m = try model([login("a.com", "ada", "new", title: "New title")], store: store)
        let row = m.rows[0]
        XCTAssertEqual(row.status, .conflict)
        XCTAssertEqual(row.decision, .skip)
        let target = try XCTUnwrap(row.targetID)
        m.set(.create, for: row.id)
        XCTAssertEqual(m.rows[0].decision, .skip, "an existing account cannot be added again")
        m.set(.merge(target), for: row.id)
        XCTAssertEqual(m.rows[0].decision, .merge(target))
        m.set(.replace(target), for: row.id)
        XCTAssertEqual(m.rows[0].decision, .replace(target))
        let outcome = try await m.commit(to: store)
        XCTAssertEqual(outcome, ImportOutcome(created: 0, updated: 1, skipped: 0, limited: 0))
        let rec = try XCTUnwrap(records(store, ns: .entry).first)
        XCTAssertEqual(rec["password"], .string("new"))
        XCTAssertEqual(rec["label"], .string("New title"))
        XCTAssertEqual(rec["password_history"]?.arrayValue?.first?.objectValue?["password"], .string("old"))

        // Merge keeps the existing title and takes the password.
        let again = try model([login("a.com", "ada", "newer", title: "Other title")], store: store)
        again.set(.merge(target), for: again.rows[0].id)
        _ = try await again.commit(to: store)
        let merged = try XCTUnwrap(records(store, ns: .entry).first)
        XCTAssertEqual(merged["label"], .string("New title"))
        XCTAssertEqual(merged["password"], .string("newer"))
    }

    func testFreePlanMarksRowsBeyondSlotsLimited() async throws {
        let store = ReviewMemoryStore()
        let m = try model((1...5).map { login("site\($0).com") }, store: store, freeSlots: 2)
        XCTAssertEqual(m.rows.map(\.status), [.new, .new, .limited, .limited, .limited])
        XCTAssertEqual(m.rows[2].stateLabel, "Needs Pro")
        XCTAssertEqual(m.limitNote, "2 will be imported on the free plan; 3 need Pro")
        XCTAssertTrue(m.summary.contains("2 will be imported on the free plan; 3 need Pro"))
        // Skipping a row frees its slot for the next one.
        m.set(.skip, for: m.rows[0].id)
        XCTAssertEqual(m.rows.map(\.status), [.new, .new, .new, .limited, .limited])
        m.set(.create, for: m.rows[0].id)
        let outcome = try await m.commit(to: store)
        XCTAssertEqual(outcome, ImportOutcome(created: 2, updated: 0, skipped: 0, limited: 3))
        XCTAssertEqual(records(store, ns: .entry).count, 2)

        XCTAssertEqual(try model([login("x.com")], store: ReviewMemoryStore(), freeSlots: 3).limitNote,
                       "3 free slots left on the free plan")
        XCTAssertEqual(try model([login("x.com")], store: ReviewMemoryStore(), freeSlots: 1).limitNote,
                       "1 free slot left on the free plan")
        XCTAssertEqual(try model([login("x.com")], store: ReviewMemoryStore(), freeSlots: nil).limitNote, "")
        XCTAssertNil(ImportReviewModel.freeSlots(snapshot: store.snapshot, isPro: true))
        XCTAssertEqual(ImportReviewModel.freeSlots(snapshot: store.snapshot, isPro: false), ItemLimit.freeItems - 2)
    }

    /// Review focus 3: a 2,000-row file with duplicates on the free plan creates only the free slots left and
    /// a second run creates nothing.
    func testLargeFreeImportWithDuplicates() async throws {
        let store = ReviewMemoryStore()
        let rows = (0..<2000).map { login("site\($0 % 1500).com") }
        let first = try model(rows, store: store, freeSlots: ImportReviewModel.freeSlots(snapshot: store.snapshot, isPro: false))
        XCTAssertEqual(first.rows.filter { $0.status == .limited }.count, 1496)
        XCTAssertEqual(first.rows.filter { $0.status == .duplicate }.count, 500)
        let outcome = try await first.commit(to: store)
        XCTAssertEqual(outcome.created, ItemLimit.freeItems)
        XCTAssertEqual(outcome.limited, 1496)
        let second = try model(rows, store: store, freeSlots: ImportReviewModel.freeSlots(snapshot: store.snapshot, isPro: false))
        let again = try await second.commit(to: store)
        XCTAssertEqual(again.created, 0)
        XCTAssertEqual(records(store, ns: .entry).count, ItemLimit.freeItems)
    }

    func testFreePlanTOTPBecomesHiddenField() async throws {
        let store = ReviewMemoryStore()
        var note = ImportCandidate(title: "Server", kind: .note(NoteFields(notes: "body")))
        note.totp = otp
        let m = try model([login("a.com", otp: otp), note], store: store, freeSlots: 4)
        XCTAssertTrue(m.issues.contains("Two-factor codes need LocalGateKeys Pro: 1 key kept as hidden custom fields."))
        _ = try await m.commit(to: store)
        let web = try XCTUnwrap(records(store, ns: .entry).first)
        XCTAssertTrue(web["totp"] == nil || web["totp"] == .null)
        XCTAssertEqual(web["custom_fields"], .array([.object(["name": .string("Two-factor key (needs Pro)"),
                                                              "value": .string(otp), "hidden": .bool(true)])]))
        let saved = try XCTUnwrap(records(store, ns: .item).first)
        XCTAssertEqual(saved["payload"]?.objectValue?["fields"],
                       .array([.object(["name": .string("One-time password (otpauth)"), "value": .string(otp),
                                        "hidden": .bool(true)])]))

        let pro = ReviewMemoryStore()
        _ = try await model([login("a.com", otp: otp)], store: pro, freeSlots: nil).commit(to: pro)
        let proWeb = try XCTUnwrap(records(pro, ns: .entry).first)
        XCTAssertEqual(proWeb["totp"]?.objectValue?["secret"], .string("JBSWY3DPEHPK3PXP"))
        XCTAssertTrue(proWeb["custom_fields"] == nil || proWeb["custom_fields"] == .array([]))
    }

    func testReimportCreatesNothing() async throws {
        let store = ReviewMemoryStore()
        let card = ImportCandidate(title: "Visa", kind: .card(CardFields(notes: "", values: [
            "cardholder": "Ada", "number": "4111111111111111", "expiry": "12/2030"])),
            customFields: [ImportCustomField(name: "Bank", value: "Example", hidden: false)])
        let identity = ImportCandidate(title: "Me", kind: .identity(IdentityFields(notes: "", values: [
            "name": "Ada Lovelace", "email": "ada@example.com"])))
        let batch: [ImportCandidate] = [
            login("a.com"), login("b.com", "bob", "one"), login("b.com", "bob", "two"),
            ImportCandidate(title: "Note", kind: .note(NoteFields(notes: "hello")), folder: "Work/Sub"),
            card, identity,
        ]
        let first = try await model(batch, store: store).commit(to: store)
        // 2 logins, the keep-both copy, the note, the card, its extra details note, the identity.
        XCTAssertEqual(first, ImportOutcome(created: 7, updated: 0, skipped: 0, limited: 0))
        let count = store.snapshot.records.count
        let second = try model(batch, store: store)
        XCTAssertTrue(second.rows.allSatisfy { $0.decision == .skip }, "\(second.rows.map(\.decision))")
        let outcome = try await second.commit(to: store)
        XCTAssertEqual(outcome.created + outcome.updated, 0)
        XCTAssertEqual(store.snapshot.records.count, count)
        XCTAssertEqual(store.commits, 1)
        let note = try XCTUnwrap(records(store, ns: .item).first { $0["title"] == .string("Note") })
        XCTAssertEqual(note["tags"], .array([.string("Work / Sub")]), "the folder becomes a tag, as on Windows")
    }

    func testCommitGoesThroughPublishingStore() async throws {
        let base = ReviewMemoryStore()
        let log = CommitLog()
        let store = PublishingItemStore(base: base, onCommit: { log.add($0) })
        let m = ImportReviewModel(result: LGKCore.ImportResult(candidates: [login("a.com")]), snapshot: try store.load(),
                                  freeSlots: nil, now: { [now] in now }, random: SystemRandomSource())
        _ = try await m.commit(to: store)
        XCTAssertEqual(log.all, [false])
        XCTAssertEqual(base.commits, 1)
        // Nothing to write: no commit, no republish.
        let again = ImportReviewModel(result: LGKCore.ImportResult(candidates: [login("a.com")]), snapshot: try store.load(),
                                      freeSlots: nil, now: { [now] in now }, random: SystemRandomSource())
        _ = try await again.commit(to: store)
        XCTAssertEqual(log.all, [false])
    }

    /// Windows `import_workflow.py`: 20 URLs (the rest kept as "Other website or app" fields), 20 tags,
    /// 512-character titles.
    func testSaveTimeCapsLikeWindows() async throws {
        let store = ReviewMemoryStore()
        let urls = (1...25).map { "https://host\($0).example.com/" }
        let candidate = ImportCandidate(title: String(repeating: "t", count: 600),
                                        kind: .login(LoginFields(url: urls[0], username: "ada", password: "pw", notes: "",
                                                                 otpauth: nil)),
                                        urls: urls, tags: (1...25).map { "tag\($0)" } + [String(repeating: "x", count: 50)])
        _ = try await model([candidate], store: store).commit(to: store)
        let rec = try XCTUnwrap(records(store, ns: .entry).first)
        XCTAssertEqual(rec["label"]?.stringValue?.count, 512)
        XCTAssertEqual(rec["tags"]?.arrayValue?.count, 20)
        XCTAssertEqual(rec["tags"]?.arrayValue?.last, .string("tag20"))
        let rows = try XCTUnwrap(rec["scope"]?.objectValue?["urls"]?.arrayValue)
        XCTAssertEqual(rows.count, 20)
        let others = rec["custom_fields"]?.arrayValue ?? []
        XCTAssertEqual(others.count, 5)
        XCTAssertEqual(others.first, .object(["name": .string("Other website or app"),
                                              "value": .string("https://host21.example.com"), "hidden": .bool(false)]))
    }

    func testSkippedSourceRowsAreShown() throws {
        let m = try model([login("a.com")], skipped: [ImportSkip(row: 3, message: "Row 3: no data; skipped.")],
                          store: ReviewMemoryStore())
        XCTAssertEqual(m.rows.last?.status, .skipped("Row 3: no data; skipped."))
        m.set(.create, for: m.rows[1].id)
        XCTAssertEqual(m.rows[1].decision, .skip)
    }

    func testPasswordMessagesNameTheFormat() {
        XCTAssertEqual(ImportReviewModel.passwordPrompt(for: .keePassKDBX),
                       "KeePass 2 database (.kdbx) is encrypted.\nEnter the password that opens it (it is used once and not stored):")
        XCTAssertEqual(ImportReviewModel.message(for: .needsPassword, format: .bitwardenEncrypted),
                       "Bitwarden password-protected JSON is encrypted.\nEnter the password that opens it (it is used once and not stored):")
        XCTAssertEqual(ImportReviewModel.message(for: .wrongPassword, format: .bitwardenEncrypted),
                       ImportError.wrongPassword.message)
        XCTAssertTrue(ImportReviewModel.asksPasswordAgain(.wrongPasswordOrKeyFile("Wrong.")))
        XCTAssertFalse(ImportReviewModel.asksPasswordAgain(.tooLarge))
        XCTAssertEqual(ImportReviewModel.formatLabel(.chrome), "Chrome / Edge / Brave passwords CSV")
    }
}
