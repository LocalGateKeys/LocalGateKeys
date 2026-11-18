import XCTest
import AppKit
import LGKCore
@testable import AppSharedMac

@MainActor
private final class PackFakeVault: MasterPasswordService {
    let right = "correct horse"
    private(set) var verifyCalls = 0
    var hasVault = true
    var isUnlocked = true
    var touchIDAvailable = false
    func verifyPassword(_ password: String) async throws {
        verifyCalls += 1
        guard password == right else { throw MacVaultError.wrongPassword(retryAfter: nil) }
    }
    func changePassword(old: String, new: String) async throws {}
    func setTouchID(_ on: Bool, password: String) async throws {}
}

/// Applies changes like LocalStore (a stale base is refused).
private final class PackMemoryStore: ItemStore, @unchecked Sendable {
    var snapshot = StoreSnapshot()
    private(set) var commits = 0
    private(set) var changeTypes: [ItemHistory.ChangeType] = []
    func load() throws -> StoreSnapshot { snapshot }
    func commit(_ change: StoreChange) throws {
        guard change.baseRevision == snapshot.revision else {
            throw LocalStoreError.stale(expected: change.baseRevision, actual: snapshot.revision)
        }
        snapshot = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: snapshot.revision + 1)
        commits += 1
        changeTypes.append(HistoryContext.changeType)
    }
}

private final class PackClock: UnixClock, @unchecked Sendable {
    var now: Int64 = 1_000
}

/// Feature pack on the Mac: access rules (enforcement, copy once, the editor's Pro rule), travel mode (AutoFill,
/// the extension's read of the Mac local data, the Settings save rules) and item history restore.
@MainActor
final class MacFeaturePackTests: XCTestCase {
    // MARK: fixtures

    private func record(access: JSONValue? = nil, policy: JSONValue? = nil, tags: [String] = []) -> [String: JSONValue] {
        var r = EditorModel.newRecord(kind: .web, now: 1_700_000_000, random: SystemRandomSource())
        r["label"] = .string("Bank"); r["username"] = .string("alex"); r["password"] = .string("pw-1")
        var scope: [String: JSONValue] = ["origin": .string("https://bank.example")]
        if let access { scope[AccessRules.scopeKey] = access }
        r["scope"] = .object(scope)
        if let policy { r["policy"] = policy }
        if !tags.isEmpty { r["tags"] = .array(tags.map { .string($0) }) }
        return r
    }

    private func item(_ r: [String: JSONValue]) throws -> VaultItem {
        try XCTUnwrap(VaultItem(id: try XCTUnwrap(r["id"]?.stringValue), record: r))
    }

    /// A store holding `r` in normal form; returns its id.
    private func seed(_ store: PackMemoryStore, _ r: [String: JSONValue]) throws -> String {
        let id = try XCTUnwrap(r["id"]?.stringValue)
        var snap = try store.load()
        snap.records[id] = Wrapper.make(ns: .entry, record: try Normalise.normalForm(ns: .entry, record: .object(r)))
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        return id
    }

    private func stored(_ store: PackMemoryStore, _ id: String) throws -> [String: JSONValue] {
        guard case .object(let w)? = try store.load().records[id], case .object(let r)? = w["record"] else {
            XCTFail("missing \(id)"); return [:]
        }
        return r
    }

    // MARK: access rules on the Mac

    func testRulesOnThisMac() {
        let today = "2026-11-15"
        // View only on phones changes nothing on a Mac.
        let phones = MacAccess.rules(record(access: .object(["phones": .string("view")])), today: today)
        XCTAssertTrue(phones.autofill); XCTAssertFalse(phones.reauth)
        // An expired rule: master password every time, never AutoFill, a banner.
        let expired = MacAccess.rules(record(access: .object(["expires": .string("2026-11-15")])), today: today)
        XCTAssertTrue(expired.reauth); XCTAssertFalse(expired.autofill); XCTAssertNotNil(MacAccess.banner(expired))
        let later = MacAccess.rules(record(access: .object(["expires": .string("2026-11-16")])), today: today)
        XCTAssertFalse(later.reauth); XCTAssertNil(MacAccess.banner(later))
        // A rule from a newer version: the strictest rules and its banner.
        let unknown = MacAccess.rules(record(access: .object(["future": .bool(true)])), today: today)
        XCTAssertTrue(unknown.reauth && unknown.copyOnce && unknown.unknownRule); XCTAssertNotNil(MacAccess.banner(unknown))
        // Typed items: no access rules, `require_master_password` still counts.
        XCTAssertTrue(MacAccess.requiresMasterPassword(["kind": .string("note"),
                                                        "policy": .object(["require_master_password": .bool(true)])]))
        XCTAssertFalse(MacAccess.requiresMasterPassword(["kind": .string("note")]))
    }

    func testExpiredRuleMakesTheLoginStrictEverywhere() throws {
        let expired = try item(record(access: .object(["expires": .string("2000-01-01")])))
        XCTAssertTrue(StrictItemGate.isStrict(expired))
        XCTAssertFalse(StrictItemGate.isStrict(try item(record())))
        let entries = OverviewModel.codeEntries([try item({ var r = record(access: .object(["expires": .string("2000-01-01")]))
            r["totp"] = .object(["secret": .string("JBSWY3DPEHPK3PXP")]); return r }())])
        XCTAssertEqual(entries.first?.setup, .hidden, "the codes strip hides an expired login's code")
    }

    func testCopyOnceAsksAgainAfterTheFirstCopy() async throws {
        let vault = PackFakeVault(), gate = StrictItemGate(passwords: vault)
        let login = try item(record(access: .object(["copy": .string("once")])))
        var limits: [TimeInterval?] = []
        gate.releaseCopy(login, action: "Copy password") { limits.append($0) }
        XCTAssertEqual(limits, [StrictItemGate.copyOnceClearSeconds], "the first copy passes, cleared after 10 s")
        XCTAssertNil(gate.pending)
        gate.releaseCopy(login, action: "Copy one-time code") { limits.append($0) }
        XCTAssertEqual(gate.pending?.level, .strict, "a further copy in the session asks for the master password")
        XCTAssertEqual(limits.count, 1)
        await gate.submit("correct horse")
        XCTAssertEqual(limits.count, 2)
        XCTAssertEqual(vault.verifyCalls, 1)
        // A lock starts a new session: the first copy passes again.
        gate.lockReset()
        gate.releaseCopy(login, action: "Copy password") { limits.append($0) }
        XCTAssertEqual(limits.count, 3)
        XCTAssertNil(gate.pending)
        // Without copy once nothing changes: no limit, no prompt.
        var plain: [TimeInterval?] = []
        let ordinary = try item(record())
        gate.releaseCopy(ordinary, action: "Copy username") { plain.append($0) }
        gate.releaseCopy(ordinary, action: "Copy username") { plain.append($0) }
        XCTAssertEqual(plain.count, 2); XCTAssertNil(plain[0]); XCTAssertNil(gate.pending)
    }

    func testClipboardLimitAppliesToOneCopyOnly() {
        let pasteboard = NSPasteboard(name: NSPasteboard.Name("app.localgatekeys.tests.\(UUID().uuidString)"))
        defer { pasteboard.releaseGlobally() }
        let clock = PackClock()
        let clip = MacClipboard(pasteboard: pasteboard, clock: clock, clearAfter: 60)
        clip.copy("secret-1", concealed: true, limit: 10)
        XCTAssertEqual(clip.expiresAt, 1_010)
        clip.copy("secret-2", concealed: true)
        XCTAssertEqual(clip.expiresAt, 1_060, "the next copy uses the user's setting again")
        clip.copy("secret-3", concealed: true, limit: 300)
        XCTAssertEqual(clip.expiresAt, 1_060, "the user's shorter setting wins")
    }

    func testAccessEditorNeedsProToTightenNeverToLoosen() throws {
        let store = PackMemoryStore()
        let id = try seed(store, record())
        let once = AccessRules.Settings(copyOnce: true)
        XCTAssertEqual(MacAccessRules.save(once, id: id, store: store, isPro: false), .needsPro)
        XCTAssertEqual(store.commits, 1, "nothing written without Pro")
        XCTAssertEqual(MacAccessRules.save(once, id: id, store: store, isPro: true, now: 1_800_000_000), .saved)
        let saved = try stored(store, id)
        XCTAssertEqual(saved["scope"]?.objectValue?[AccessRules.scopeKey], .object(["copy": .string("once")]))
        XCTAssertEqual(saved["updated_at"], .int(1_800_000_000))
        XCTAssertEqual(MacAccessRules.save(AccessRules.Settings(), id: id, store: store, isPro: false), .needsOwner,
                       "loosening asks for the master password first (scan 2026-11-15)")
        XCTAssertEqual(store.commits, 2, "nothing written without the owner")
        XCTAssertEqual(MacAccessRules.save(AccessRules.Settings(), id: id, store: store, isPro: false,
                                           ownerConfirmed: true), .saved, "loosening never needs Pro")
        XCTAssertNil(try stored(store, id)["scope"]?.objectValue?[AccessRules.scopeKey], "an empty access is removed")
        XCTAssertEqual(MacAccessRules.save(AccessRules.Settings(expires: "2026-02-30"), id: id, store: store, isPro: true), .invalid)
    }

    func testAgentsNeverSeeALoginWithARule() throws {
        var ruled = record(access: .object(["copy": .string("once")]))
        ruled["scope"] = .object((ruled["scope"]?.objectValue ?? [:]).merging([AgentText.scopeKey: .bool(true)]) { $1 })
        var open = record()
        open["scope"] = .object((open["scope"]?.objectValue ?? [:]).merging([AgentText.scopeKey: .bool(true)]) { $1 })
        let vault = MacAgentVault(items: [try item(ruled), try item(open)])
        XCTAssertEqual(vault.logins().map(\.id), [try XCTUnwrap(open["id"]?.stringValue)])
    }

    // MARK: travel mode and AutoFill

    func testAutoFillOnTheMacOmitsTravelHiddenAndFillNever() throws {
        let store = PackMemoryStore()
        let phones = try seed(store, record(access: .object(["phones": .string("view")])))
        let never = try seed(store, record(policy: .object(["fill": .string("never")])))
        let trip = try seed(store, record(tags: ["Work"]))
        let plain = try seed(store, record())
        let snap = try store.load()
        let travel = TravelMode(on: true, tags: ["work"])
        let omitted = AutoFillGate.omitted(snap, travel: travel, today: "2026-11-15", device: .computer)
        XCTAssertEqual(omitted, [never, trip])
        XCTAssertFalse(omitted.contains(phones)); XCTAssertFalse(omitted.contains(plain))
        XCTAssertTrue(AutoFillGate.omitted(snap, travel: travel, today: "2026-11-15").contains(phones),
                      "a phone leaves view-only logins out")
    }

    func testExtensionReadsTheMacLocalData() throws {
        XCTAssertEqual(MacLocalDataFile.fileName, MacLocalStore.fileName)
        XCTAssertEqual(MacLocalDataFile.info, MacLocalStore.info)
        XCTAssertEqual(MacLocalDataFile.aad, MacLocalStore.aad)
        XCTAssertEqual(MacLocalDataFile.formatVersion, MacLocalStore.formatVersion)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-travel-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let keychain = InMemoryKeychainVault()
        let store = try LocalStore.bootstrap(directory: dir, vault: keychain)
        XCTAssertNil(MacLocalDataFile.read(for: store), "no file: nothing extra hidden")
        let key = try XCTUnwrap(try keychain.read(.localKey))
        var data = LocalData()
        data.travelMode = TravelMode(on: true, tags: ["work"], since: 1_800_000_000)
        try MacLocalStore(directory: dir, localKey: key).save(data)
        XCTAssertEqual(MacLocalDataFile.read(for: store)?.travel, data.travel)
    }

    /// Scan 2026-11-15 S-L4: a Mac-local data file that is there but can't be read hides every item from AutoFill.
    func testUnreadableLocalDataHidesEverythingFromAutoFill() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-travel-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        XCTAssertEqual(MacLocalDataFile.travel(for: store), .off, "no file yet: nothing extra hidden")
        try Data([MacLocalDataFile.formatVersion] + Array(repeating: 7, count: 40))
            .write(to: dir.appendingPathComponent(MacLocalDataFile.fileName))
        let travel = MacLocalDataFile.travel(for: store)
        XCTAssertTrue(travel.on && travel.unreadable)
        let subjects = [TravelMode.Subject(id: "a", kind: "web", tags: [], collections: [])]
        XCTAssertEqual(travel.hiddenIDs(subjects), ["a"])
    }

    func testTravelModeSaveRules() throws {
        let local = InMemoryLocalData()
        let on = TravelMode(on: true, tags: ["work"])
        XCTAssertEqual(MacTravelMode.save(on, local: local, isPro: false, now: 5, duress: false), .needsPro)
        XCTAssertEqual(local.localData?.travel, .off)
        XCTAssertEqual(MacTravelMode.save(on, local: local, isPro: true, now: 5, duress: true), .unavailable,
                       "a duress session saves nothing")
        XCTAssertEqual(MacTravelMode.save(on, local: local, isPro: true, now: 5, duress: false), .saved)
        XCTAssertEqual(local.localData?.travel.on, true)
        XCTAssertEqual(local.localData?.travel.since, 5)
        // Swapping the hidden tag for another would show the work items again (scan 2026-11-15 S-M4).
        let swapped = TravelMode(on: true, tags: ["unused"])
        XCTAssertEqual(MacTravelMode.save(swapped, local: local, isPro: true, now: 7, duress: false), .needsOwner)
        XCTAssertEqual(local.localData?.travel.tags, ["work"], "nothing saved without the owner")
        var off = on; off.on = false
        XCTAssertEqual(MacTravelMode.save(off, local: local, isPro: false, now: 9, duress: false), .needsOwner,
                       "turning it off shows hidden items: the owner confirms first")
        XCTAssertEqual(MacTravelMode.save(off, local: local, isPro: false, now: 9, duress: false, ownerConfirmed: true), .saved,
                       "turning it off never needs Pro")
        XCTAssertEqual(local.localData?.travel.on, false)
        let tooMany = TravelMode(on: true, tags: (0...TravelMode.maxTags).map { "t\($0)" })
        XCTAssertEqual(MacTravelMode.save(tooMany, local: local, isPro: true, now: 10, duress: false), .invalid)
    }

    // MARK: item history

    func testRestoreOneFieldFromAnEarlierVersion() throws {
        let store = PackMemoryStore()
        var old = record()
        let id = try seed(store, old)
        old = try stored(store, id)
        var edited = old
        edited["label"] = .string("Bank (new)"); edited["password"] = .string("pw-2")
        var snap = try store.load()
        snap.records[id] = Wrapper.make(ns: .entry, record: try Normalise.normalForm(ns: .entry, record: .object(edited)))
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        let row = try ItemHistory.Row(snapshotID: UUID().uuidString.lowercased(), itemID: id, ns: Namespace.entry.rawValue,
                                      createdAt: 1_700_000_000, changeType: .update, record: .object(old))
        let model = MacItemHistoryModel(store: store, rows: { [row] }, isPro: { false }, now: { 1_800_000_000 })
        XCTAssertEqual(model.versions(of: id).map(\.id), [row.id])
        let current = try item(try stored(store, id))
        let masked = model.changes(row, item: current, reveal: false)
        XCTAssertEqual(masked.first { $0.field == "password" }?.before, .string(ItemHistory.protectedMarker),
                       "secrets stay masked until confirmed")
        XCTAssertEqual(model.changes(row, item: current, reveal: true).first { $0.field == "password" }?.before, .string("pw-1"))
        XCTAssertEqual(model.restore(row, path: "label", id: id), .saved)
        let now = try stored(store, id)
        XCTAssertEqual(now["label"], .string("Bank"))
        XCTAssertEqual(now["password"], .string("pw-2"), "only the chosen field changes")
        XCTAssertEqual(store.changeTypes.last, .restore, "recorded as a restore, so the replaced version stays in history")
        XCTAssertEqual(model.restore(row, path: "label", id: id), .unchanged)
        XCTAssertEqual(model.restore(row, path: "id", id: id), .invalid)
    }

    func testRestoringAnOlderAccessRuleNeedsTheMasterPassword() throws {
        // Scan 2026-11-15 S-M3: bringing back a version without copy once loosens the rule.
        let store = PackMemoryStore()
        let id = try seed(store, record())
        let old = try stored(store, id)
        var ruled = record(access: .object(["copy": .string("once")]))
        ruled["id"] = .string(id)
        var snap = try store.load()
        snap.records[id] = Wrapper.make(ns: .entry, record: try Normalise.normalForm(ns: .entry, record: .object(ruled)))
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        let row = try ItemHistory.Row(snapshotID: UUID().uuidString.lowercased(), itemID: id, ns: Namespace.entry.rawValue,
                                      createdAt: 1_700_000_000, changeType: .update, record: .object(old))
        let model = MacItemHistoryModel(store: store, rows: { [row] }, isPro: { false }, now: { 1_800_000_000 })
        XCTAssertEqual(model.restore(row, path: "scope.access.copy", id: id), .needsOwner)
        XCTAssertEqual(try stored(store, id)["scope"]?.objectValue?[AccessRules.scopeKey], .object(["copy": .string("once")]))
        XCTAssertEqual(model.restore(row, path: "scope.access.copy", id: id, ownerConfirmed: true), .saved)
        XCTAssertNil(try stored(store, id)["scope"]?.objectValue?[AccessRules.scopeKey]?.objectValue?["copy"])
    }
}
