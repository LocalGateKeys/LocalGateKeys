import XCTest
import LGKCore
@testable import AppSharedMac

/// Records what the Safari index publisher was given.
private final class SpySafariIndex: SafariIndexPublishing, @unchecked Sendable {
    var published: [StoreSnapshot] = []
    func publish(_ snapshot: StoreSnapshot) { published.append(snapshot) }
}

/// Feature pack on the Mac, wave 3: the clean-up page (findings without travel-hidden items, Pro bulk delete and
/// merge with one Undo), Recently deleted's restore by item id, the privacy proof file, the passkey check and the
/// passkey upgrade card, the Safari index under travel mode, and shares dropping access rules.
@MainActor
final class MacFeaturePackCleanUpTests: XCTestCase {
    private var dir: URL!
    private var store: LocalStore!
    private var local: InMemoryLocalData!
    private var needsPro: [ProReason] = []
    private var pro = false

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-cleanup-\(UUID().uuidString)", isDirectory: true)
        store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        store.limitHints = nil
        local = InMemoryLocalData()
        needsPro = []; pro = false
        HygieneActions.clearUndo()
    }

    override func tearDown() async throws {
        HygieneActions.clearUndo()
        try? FileManager.default.removeItem(at: dir)
    }

    // MARK: fixtures

    private func trash() -> TrashModel {
        TrashModel(store: store, local: local, isPro: { [unowned self] in pro },
                   onNeedsPro: { [unowned self] in needsPro.append($0) }, activity: nil)
    }

    private func model(hidden: @escaping @MainActor (StoreSnapshot) -> Set<String> = { _ in [] }) -> MacCleanUpModel {
        let m = MacCleanUpModel(store: store, trash: trash(), local: local, isPro: { [unowned self] in pro },
                                onNeedsPro: { [unowned self] in needsPro.append($0) }, hidden: hidden, now: { 1_800_000_000 })
        m.reload()
        return m
    }

    /// Adds a login (same site, username and password unless told otherwise) and returns its id.
    @discardableResult
    private func addLogin(_ title: String, origin: String = "https://bank.example", updated: Int64 = 1_700_000_000,
                          tags: [String] = []) throws -> String {
        var r = EditorModel.newRecord(kind: .web, now: updated, random: SystemRandomSource())
        let id = try XCTUnwrap(r["id"]?.stringValue)
        r["label"] = .string(title); r["username"] = .string("sam"); r["password"] = .string("pw-same")
        r["scope"] = .object(["origin": .string(origin)])
        if !tags.isEmpty { r["tags"] = .array(tags.map { .string($0) }) }
        let normal = try Normalise.normalForm(ns: .entry, record: .object(r))
        var snap = try store.load()
        snap.records[id] = Wrapper.make(ns: .entry, record: normal)
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        return id
    }

    private func liveIDs() throws -> Set<String> { Set(VaultItem.items(from: try store.load()).map(\.id)) }

    // MARK: clean-up

    func testSameLoginsAreFoundAndTravelHiddenItemsLeftOut() throws {
        let a = try addLogin("Bank"), b = try addLogin("Bank copy")
        try addLogin("Shop", origin: "https://shop.example")
        let all = model()
        let group = try XCTUnwrap(all.findings.first { $0.type == .sameLogin })
        XCTAssertEqual(Set(group.ids), [a, b])
        XCTAssertEqual(all.summary.duplicates, 2, "distinct items in duplicate groups, as Windows (final review S-L2)")
        let hiding = model(hidden: { _ in [b] })
        XCTAssertNil(hiding.findings.first { $0.type == .sameLogin }, "a travel-hidden copy is never offered")
    }

    func testDeleteOneIsFreeAndGoesToRecentlyDeleted() throws {
        let a = try addLogin("Bank"); try addLogin("Bank copy")
        let m = model()
        var changes = 0
        m.onChange = { changes += 1 }
        m.deleteOne(a)
        XCTAssertFalse(try liveIDs().contains(a))
        XCTAssertEqual(local.localData?.trash.count, 1)
        XCTAssertEqual(changes, 1)
        XCTAssertTrue(needsPro.isEmpty)
        // The copy left (updated 1.7e9, now 1.8e9) is still listed as not changed in 2 years, as on Windows.
        XCTAssertTrue(m.findings.filter(\.type.isDuplicate).isEmpty, "the group is gone with one copy left")
    }

    func testBulkSelectionNeedsPro() throws {
        try addLogin("Bank"); try addLogin("Bank copy")
        let m = model()
        m.toggleSelecting()
        XCTAssertFalse(m.selecting)
        XCTAssertEqual(needsPro, [.hygiene])
        XCTAssertEqual(m.message, HygieneActions.bulkNeedsPro)
    }

    func testBulkDeleteThenUndoPutsItemsBack() throws {
        pro = true
        let a = try addLogin("Bank"), b = try addLogin("Bank copy")
        let m = model()
        m.toggleSelecting()
        XCTAssertTrue(m.selecting)
        m.toggle(a); m.toggle(b)
        m.deleteSelected()
        XCTAssertFalse(m.selecting)
        XCTAssertTrue(try liveIDs().isDisjoint(with: [a, b]))
        XCTAssertTrue(m.canUndo)
        m.undoBulk()
        XCTAssertEqual(try liveIDs().intersection([a, b]), [a, b])
        XCTAssertFalse(m.canUndo)
        XCTAssertNil(HygieneActions.lastBulk)
    }

    func testMergeAllSameLoginsKeepsTheNewestAndUndoes() throws {
        pro = true
        let old = try addLogin("Bank", updated: 1_700_000_000), new = try addLogin("Bank copy", updated: 1_700_000_500)
        let m = model()
        m.mergeAllSameLogins()
        XCTAssertEqual(try liveIDs(), [new], "the newest copy is the keeper")
        XCTAssertEqual(local.localData?.trash.count, 1)
        XCTAssertTrue(m.canUndo)
        m.undoBulk()
        XCTAssertEqual(try liveIDs(), [old, new])
    }

    func testUndoIsClearedOnLock() throws {
        pro = true
        let a = try addLogin("Bank"); try addLogin("Bank copy")
        let m = model()
        m.toggleSelecting(); m.toggle(a); m.deleteSelected()
        XCTAssertNotNil(HygieneActions.lastBulk)
        HygieneActions.clearUndo()   // what MacLockModel.lock() calls
        m.reload()
        XCTAssertFalse(m.canUndo)
    }

    func testRestoreItemsByItemID() throws {
        let a = try addLogin("Bank"), b = try addLogin("Shop", origin: "https://shop.example")
        let t = trash()
        try t.moveToTrash(id: a); try t.moveToTrash(id: b)
        XCTAssertEqual(t.restoreItems([a, "missing"]), 1)
        XCTAssertTrue(try liveIDs().contains(a))
        XCTAssertFalse(try liveIDs().contains(b))
        XCTAssertEqual(local.localData?.trash.count, 1)
    }

    // MARK: Safari index and travel mode

    func testSafariIndexLeavesOutTravelHiddenItems() throws {
        let work = try addLogin("Work", tags: ["Work"]), home = try addLogin("Home", origin: "https://home.example")
        let snap = try store.load()
        let spy = SpySafariIndex()
        let travel = TravelMode(on: true, tags: ["work"])
        MacTravelSafariIndex(base: spy, travel: { travel }).publish(snap)
        XCTAssertNil(spy.published.last?.records[work])
        XCTAssertNotNil(spy.published.last?.records[home])
        MacTravelSafariIndex(base: spy, travel: { .off }).publish(snap)
        XCTAssertEqual(spy.published.last, snap, "off: the snapshot passes unchanged")
    }

    // MARK: shares

    func testSharesDropAccessRules() {
        let rec: [String: JSONValue] = ["kind": .string("web"), "scope": .object([
            "origin": .string("https://bank.example"),
            AccessRules.scopeKey: .object(["copy": .string("once")]),
        ])]
        let out = Share.withoutLocalRefs(rec)
        XCTAssertNil(out["scope"]?.objectValue?[AccessRules.scopeKey])
        XCTAssertEqual(out["scope"]?.objectValue?["origin"], .string("https://bank.example"))
    }

    // MARK: privacy proof

    func testPrivacyProofOnTheMacIsUnsignedWithoutSync() throws {
        let suite = "lgk-proof-\(UUID().uuidString)"
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        let settings = AppSettings(defaults: try XCTUnwrap(UserDefaults(suiteName: suite)))
        try addLogin("Bank")
        let snap = try store.load()
        let facts = MacPrivacyProof.facts(snap, settings: settings)
        XCTAssertEqual(facts.sync, .off)
        XCTAssertEqual(facts.items, 1)
        XCTAssertFalse(facts.updateCheck)
        let made = try MacPrivacyProof.make(snap, appVersion: "1.2.3", settings: settings,
                                            now: Date(timeIntervalSince1970: 1_800_000_000))
        XCTAssertEqual(made.document["app"]?.objectValue?["platform"], .string("mac"))
        XCTAssertEqual(made.document["claims"], .array(PrivacyProof.appleClaims.map(JSONValue.string)))
        XCTAssertEqual(made.document["signature"], .null)
        XCTAssertEqual(PrivacyProof.verify(made.bytes).verdict, .unsigned)
        XCTAssertNil(MacPrivacyProof.fingerprint(snap))
    }

    // MARK: passkeys

    func testPasskeyCheck() {
        XCTAssertEqual(MacPasskeyDoctor.status(enabled: true), .on)
        XCTAssertEqual(MacPasskeyDoctor.status(enabled: false), .off)
        XCTAssertEqual(MacPasskeyDoctor.status(enabled: nil), .unknown)
        XCTAssertNotEqual(MacPasskeyDoctor.text(.off), MacPasskeyDoctor.text(.unknown), "unknown is never shown as off")
        XCTAssertEqual(MacPasskeyDoctor.otherChecks(offerPasskeys: false, passkeyCount: 0).map(\.id), ["offerPasskeys", "saved"])
        XCTAssertTrue(MacPasskeyDoctor.otherChecks(offerPasskeys: true, passkeyCount: 2).isEmpty)
    }

    func testPasskeyUpgradeCardAndNotNow() throws {
        let features = SiteFeatures(sites: ["github.com": ["passkey"]], matcher: URLMatcher(rules: nil))
        let login: [String: JSONValue] = ["kind": .string("web"), "scope": .object(["origin": .string("https://github.com")])]
        XCTAssertEqual(MacPasskeyUpgrade.domain(for: login, rpIDs: [], features: features, dismissed: [:], now: 100), "github.com")
        XCTAssertNil(MacPasskeyUpgrade.domain(for: login, rpIDs: ["github.com"], features: features, dismissed: [:], now: 100),
                     "a passkey is already saved for the site")
        var note = login; note["kind"] = .string("note")
        XCTAssertNil(MacPasskeyUpgrade.domain(for: note, rpIDs: [], features: features, dismissed: [:], now: 100))
        XCTAssertTrue(MacPasskeyUpgrade.dismiss("github.com", local: local, now: 100))
        let dismissed = try XCTUnwrap(local.localData?.passkeyUpgradeDismissed)
        XCTAssertEqual(dismissed["github.com"], 100)
        XCTAssertNil(MacPasskeyUpgrade.domain(for: login, rpIDs: [], features: features, dismissed: dismissed, now: 200))
        XCTAssertEqual(MacPasskeyUpgrade.domain(for: login, rpIDs: [], features: features, dismissed: dismissed,
                                                now: 100 + PasskeyUpgrade.again), "github.com", "asked again after 90 days")
        let locked = InMemoryLocalData(nil)
        XCTAssertFalse(MacPasskeyUpgrade.dismiss("github.com", local: locked, now: 100))
    }
}
