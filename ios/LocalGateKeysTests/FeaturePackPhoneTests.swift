import XCTest
import AppShared
@testable import LocalGateKeys

/// Feature pack on the iPhone: travel mode gating and filters, access rule gates, history capture and restore,
/// the passkey check and the privacy proof facts.
@MainActor
final class FeaturePackPhoneTests: XCTestCase {
    let clock = TestClock(1_800_000_000)

    private func login(_ id: String, tags: [String] = [], access: JSONValue? = nil,
                       policy: [String: JSONValue]? = nil) -> JSONValue {
        guard case .object(var o) = webLogin else { return webLogin }
        o["id"] = .string(id)
        o["tags"] = strs(tags)
        if let access, case .object(var scope)? = o["scope"] { scope["access"] = access; o["scope"] = .object(scope) }
        if let policy { o["policy"] = .object(policy) }
        return .object(o)
    }

    // MARK: Travel mode

    func testTurningTravelModeOnNeedsProButOffNeverDoes() {
        let local = InMemoryPhoneLocal()
        let on = TravelMode(on: true, tags: ["Work"])
        XCTAssertEqual(TravelModeActions.save(on, local: local, isPro: false, now: 10), .needsPro)
        XCTAssertEqual(local.localData?.travel, .off)
        XCTAssertEqual(TravelModeActions.save(on, local: local, isPro: true, now: 10), .saved)
        XCTAssertEqual(local.localData?.travel.since, 10)
        XCTAssertTrue(local.localData?.travel.on == true)
        var off = on; off.on = false
        XCTAssertEqual(TravelModeActions.save(off, local: local, isPro: false, now: 20), .needsOwner,
                       "turning off shows hidden items: the owner confirms first")
        XCTAssertTrue(local.localData?.travel.on == true)
        XCTAssertEqual(TravelModeActions.save(off, local: local, isPro: false, now: 20, ownerConfirmed: true), .saved)
        XCTAssertEqual(local.localData?.travel.on, false)
        XCTAssertEqual(local.localData?.travel.since, 10, "turning off keeps when it was last turned on")
    }

    func testDroppingAHiddenTagOrCollectionNeedsTheOwnerButAddingOneDoesNot() {
        let local = InMemoryPhoneLocal()
        let collection = "0f0e0d0c-0b0a-4908-8706-050403020100"
        let on = TravelMode(on: true, collections: [collection], tags: ["Bank"])
        XCTAssertEqual(TravelModeActions.save(on, local: local, isPro: true, now: 10), .saved)
        // Swapping the hidden tag for an unused one would show every bank login again (scan 2026-11-15 S-M4).
        let swapped = TravelMode(on: true, collections: [collection], tags: ["Unused"])
        XCTAssertEqual(TravelModeActions.save(swapped, local: local, isPro: true, now: 11), .needsOwner)
        let noCollection = TravelMode(on: true, tags: ["Bank"])
        XCTAssertEqual(TravelModeActions.save(noCollection, local: local, isPro: true, now: 11), .needsOwner)
        XCTAssertEqual(local.localData?.travel.tags, ["Bank"], "nothing is saved without the owner")
        // Adding to the set, or the same tag in another case, hides at least as much: no owner check.
        let more = TravelMode(on: true, collections: [collection], tags: ["bank", "Trip"])
        XCTAssertEqual(TravelModeActions.save(more, local: local, isPro: true, now: 12), .saved)
        XCTAssertEqual(TravelModeActions.save(swapped, local: local, isPro: true, now: 13, ownerConfirmed: true), .saved)
        XCTAssertEqual(local.localData?.travel.tags, ["Unused"])
    }

    func testRevealsHiddenComparesTheSettingNotTheItems() {
        let on = TravelMode(on: true, collections: ["AA"], tags: ["Work"])
        XCTAssertFalse(TravelMode.off.revealsHidden(to: on), "turning on never reveals")
        XCTAssertTrue(on.revealsHidden(to: .off))
        XCTAssertFalse(on.revealsHidden(to: TravelMode(on: true, collections: ["aa"], tags: [" work "])))
        XCTAssertTrue(on.revealsHidden(to: TravelMode(on: true, collections: [], tags: ["Work"])))
        XCTAssertTrue(on.revealsHidden(to: TravelMode(on: true, collections: ["aa"], tags: [])))
    }

    func testTravelModeWithoutLocalDataIsUnavailable() {
        XCTAssertEqual(TravelModeActions.save(TravelMode(on: true, tags: ["x"]), local: nil, isPro: true, now: 1), .unavailable)
    }

    func testTravelTagsAreListedOncePerFoldedForm() {
        let snap = snapshot([login("a", tags: ["Work"]), login("b", tags: ["work", "Home"])])
        XCTAssertEqual(TravelModeActions.tags(in: snap).count, 2)
    }

    func testTravelHidesFromListSearchAndExports() throws {
        let snap = snapshot([login("a", tags: ["Work"]), login("b"), note])
        let model = VaultListModel(store: MemoryStore(snap), defaults: UserDefaults(suiteName: "fp-\(UUID())")!)
        let travel = TravelMode(on: true, tags: ["work"])
        model.hidden = { travel.hiddenIDs(in: $0) }
        model.reload()
        XCTAssertFalse(model.items.contains { $0.id == "a" })
        XCTAssertEqual(model.hiddenCount, 1)
        let local = InMemoryPhoneLocal(); _ = TravelModeActions.save(travel, local: local, isPro: true, now: 1)
        XCTAssertTrue(PhoneFeaturePack.exportLeftOut(snap, local: local).contains("a"))
        XCTAssertFalse(PhoneFeaturePack.exportLeftOut(snap, local: local).contains("b"))
    }

    // MARK: AutoFill gate (travel, policy.fill, phones view)

    func testAutoFillGateOmitsTravelHiddenFillNeverAndPhoneViewLogins() {
        let snap = snapshot([login("t", tags: ["Trip"]), login("n", policy: ["fill": .string("never")]),
                             login("v", access: .object(["phones": .string("view")])), login("ok"),
                             login("u", access: .object(["future_rule": .bool(true)]))])
        let omitted = AutoFillGate.omitted(snap, travel: TravelMode(on: true, tags: ["trip"]), today: "2026-11-15")
        XCTAssertEqual(omitted, ["t", "n", "v", "u"])
    }

    func testExpiredAccessIsOmittedFromAutoFill() {
        let snap = snapshot([login("e", access: .object(["expires": .string("2026-11-15")]))])
        XCTAssertEqual(AutoFillGate.omitted(snap, travel: .off, today: "2026-11-15"), ["e"])
        XCTAssertEqual(AutoFillGate.omitted(snap, travel: .off, today: "2026-11-14"), [])
    }

    func testWidgetsAndWatchLeaveOutCodesThatNeedAnOwnerCheck() {
        // Scan 2026-11-15 S-L2: fill never alone still shows a code; view only, strict, expired and unknown do not.
        let snap = snapshot([login("t", tags: ["Trip"]), login("n", policy: ["fill": .string("never")]),
                             login("v", access: .object(["phones": .string("view")])), login("ok"),
                             login("s", policy: ["require_master_password": .bool(true)]),
                             login("e", access: .object(["expires": .string("2026-11-15")])),
                             login("u", access: .object(["future_rule": .bool(true)]))])
        let omitted = AutoFillGate.codesOmitted(snap, travel: TravelMode(on: true, tags: ["trip"]), today: "2026-11-15")
        XCTAssertEqual(omitted, ["t", "v", "s", "e", "u"])
    }

    // MARK: Access gate

    func testViewOnlyRefusesCopyWithoutAsking() async {
        let gate = AccessGate()
        var asked = 0
        gate.confirmOwner = { _ in asked += 1; return true }
        let item = VaultItem.items(from: snapshot([login("v", access: .object(["phones": .string("view")]))]))[0]
        let copied = await gate.mayCopy(item)
        XCTAssertFalse(copied)
        XCTAssertEqual(asked, 0)
        XCTAssertFalse(gate.mayShare(item))
        let revealed = await gate.mayReveal(item)
        XCTAssertTrue(revealed)
        XCTAssertEqual(asked, 1, "a reveal of a view-only login asks the owner")
    }

    func testCopyOnceAsksAgainAfterTheFirstCopyUntilReset() async {
        let gate = AccessGate()
        var asked = 0
        gate.confirmOwner = { _ in asked += 1; return true }
        let item = VaultItem.items(from: snapshot([login("o", access: .object(["copy": .string("once")]))]))[0]
        _ = await gate.mayCopy(item)
        XCTAssertEqual(asked, 0)
        _ = await gate.mayCopy(item)
        XCTAssertEqual(asked, 1)
        gate.reset()
        _ = await gate.mayCopy(item)
        XCTAssertEqual(asked, 1)
    }

    func testRequireMasterPasswordAsksOnEveryCopyAndReveal() async {
        let gate = AccessGate()
        var asked = 0
        gate.confirmOwner = { _ in asked += 1; return false }
        let item = VaultItem.items(from: snapshot([login("r", policy: ["require_master_password": .bool(true)])]))[0]
        let c = await gate.mayCopy(item), r = await gate.mayReveal(item)
        XCTAssertFalse(c); XCTAssertFalse(r)
        XCTAssertEqual(asked, 2)
    }

    func testOpenLoginNeverAsks() async {
        let gate = AccessGate()
        gate.confirmOwner = { _ in XCTFail("no rule, no prompt"); return false }
        let item = VaultItem.items(from: snapshot([login("ok")]))[0]
        let c = await gate.mayCopy(item), r = await gate.mayReveal(item)
        XCTAssertTrue(c); XCTAssertTrue(r)
    }

    func testCopyingTheUsernameDoesNotUseUpCopyOnce() async {
        // Final review S-LM1: copy once counts the item's secrets only, as on the Mac.
        let gate = AccessGate()
        var asked = 0
        gate.confirmOwner = { _ in asked += 1; return true }
        let item = VaultItem.items(from: snapshot([login("o", access: .object(["copy": .string("once")]))]))[0]
        _ = await gate.mayCopy(item, secret: false)
        _ = await gate.mayCopy(item, secret: false)
        XCTAssertEqual(asked, 0)
        _ = await gate.mayCopy(item)
        XCTAssertEqual(asked, 0, "the first secret copy is still free")
        _ = await gate.mayCopy(item)
        XCTAssertEqual(asked, 1)
    }

    func testCopyOnceClearsTheClipboardAfterTenSeconds() {
        // Final review S-LM1: §4.1 clears a copy-once copy after 10 s, not the 60 s setting.
        let gate = AccessGate()
        let once = VaultItem.items(from: snapshot([login("o", access: .object(["copy": .string("once")]))]))[0]
        let open = VaultItem.items(from: snapshot([login("ok")]))[0]
        XCTAssertEqual(gate.copyLimit(once), 10)
        XCTAssertNil(gate.copyLimit(open))
        let settings = AppSettings(defaults: UserDefaults(suiteName: "fp-clip-\(UUID())")!)
        settings.clipboardExpiry = .sixtySeconds
        let pasteboard = FakePasteboard()
        let clipboard = SecretClipboard(pasteboard: pasteboard, clock: clock, settings: settings)
        clipboard.copy("s3cret", clearAfterAtMost: AccessGate.copyOnceClearSeconds)
        XCTAssertEqual(pasteboard.options[.expirationDate] as? Date, Date(timeIntervalSince1970: TimeInterval(clock.now + 10)))
        clipboard.copy("s3cret")
        XCTAssertEqual(pasteboard.options[.expirationDate] as? Date, Date(timeIntervalSince1970: TimeInterval(clock.now + 60)))
    }

    func testTheLiveCodeIsMaskedLikeThePasswordOnRestrictedLogins() {
        // Final review S-M2: re-authenticate, view only on phones and an unknown rule mask the 2FA code too.
        let gate = AccessGate()
        gate.today = { "2026-11-15" }
        let items = VaultItem.items(from: snapshot([
            login("s", policy: ["require_master_password": .bool(true)]),
            login("v", access: .object(["phones": .string("view")])),
            login("u", access: .object(["future_rule": .bool(true)])),
            login("e", access: .object(["expires": .string("2026-11-15")])),
            login("o", access: .object(["copy": .string("once")])), login("ok")]))
        let masked = Set(items.filter { gate.masksSecrets($0) }.map(\.id))
        XCTAssertEqual(masked, ["s", "v", "u", "e"])
    }

    // MARK: Access rules editor

    func testSettingARuleNeedsProAndLooseningDoesNot() throws {
        let store = MemoryStore(snapshot([login("w1")]))
        var choice = AccessRulesActions.choice(VaultItem.items(from: store.snapshot)[0].record)
        choice.settings.copyOnce = true
        XCTAssertEqual(AccessRulesActions.save(choice, id: "w1", store: store, isPro: false, clock: clock,
                                               background: FakeBackgroundTasks()), .needsPro)
        XCTAssertEqual(AccessRulesActions.save(choice, id: "w1", store: store, isPro: true, clock: clock,
                                               background: FakeBackgroundTasks()), .saved)
        let saved = VaultItem.items(from: store.snapshot)[0].record
        XCTAssertEqual(saved["scope"]?.objectValue?["access"], .object(["copy": .string("once")]))
        choice.settings.copyOnce = false
        XCTAssertEqual(AccessRulesActions.save(choice, id: "w1", store: store, isPro: false, clock: clock,
                                               background: FakeBackgroundTasks()), .needsOwner,
                       "loosening asks the owner first (scan 2026-11-15)")
        XCTAssertNotNil(VaultItem.items(from: store.snapshot)[0].record["scope"]?.objectValue?["access"])
        XCTAssertEqual(AccessRulesActions.save(choice, id: "w1", store: store, isPro: false, clock: clock,
                                               background: FakeBackgroundTasks(), ownerConfirmed: true), .saved)
        XCTAssertNil(VaultItem.items(from: store.snapshot)[0].record["scope"]?.objectValue?["access"])
    }

    func testReplacingARuleFromANewerVersionNeedsTheOwner() {
        // `access` that is not an object reads as all rules on; the editor replacing it loosens it.
        let store = MemoryStore(snapshot([login("w1", access: .string("x"))]))
        var choice = AccessRulesActions.choice(VaultItem.items(from: store.snapshot)[0].record)
        choice.settings.copyOnce = true
        XCTAssertEqual(AccessRulesActions.save(choice, id: "w1", store: store, isPro: true, clock: clock,
                                               background: FakeBackgroundTasks()), .needsOwner)
        XCTAssertEqual(VaultItem.items(from: store.snapshot)[0].record["scope"]?.objectValue?["access"], .string("x"))
    }

    func testRestoringAnOlderAccessRuleNeedsTheOwner() throws {
        // The older version had no rule; the login now is view only on phones (scan 2026-11-15 S-M3).
        let row = try ItemHistory.Row(snapshotID: "s", itemID: "w1", ns: "entry", createdAt: 1, changeType: .update,
                                      record: login("w1"))
        let store = MemoryStore(snapshot([login("w1", access: .object(["phones": .string("view")]),
                                                policy: ["require_master_password": .bool(true), "fill": .string("never")])]))
        for path in ["scope.access.phones", "policy.require_master_password", "policy.fill"] {
            XCTAssertEqual(ItemHistoryActions.restore(row, path: path, id: "w1", store: store, clock: clock,
                                                      background: FakeBackgroundTasks()), .needsOwner, path)
        }
        XCTAssertEqual(VaultItem.items(from: store.snapshot)[0].record["scope"]?.objectValue?["access"],
                       .object(["phones": .string("view")]), "nothing written without the owner")
        XCTAssertEqual(ItemHistoryActions.restore(row, path: "scope.access.phones", id: "w1", store: store, clock: clock,
                                                  background: FakeBackgroundTasks(), ownerConfirmed: true), .saved)
        XCTAssertNil(VaultItem.items(from: store.snapshot)[0].record["scope"]?.objectValue?["access"]?
            .objectValue?["phones"])
    }

    func testFillNeverIsWrittenToPolicy() {
        let store = MemoryStore(snapshot([login("w1")]))
        var choice = AccessRulesActions.choice(VaultItem.items(from: store.snapshot)[0].record)
        XCTAssertTrue(choice.autofill)
        choice.autofill = false
        XCTAssertEqual(AccessRulesActions.save(choice, id: "w1", store: store, isPro: true, clock: clock,
                                               background: FakeBackgroundTasks()), .saved)
        XCTAssertEqual(VaultItem.items(from: store.snapshot)[0].record["policy"]?.objectValue?["fill"], .string("never"))
    }

    // MARK: History

    func testCaptureAppendsAndPrunesToThePlan() throws {
        let rows = (0..<8).map { n in
            ItemHistory.Row(snapshotID: "s\(n)", itemID: "w1", ns: "entry", createdAt: 1_800_000_000 - Int64(n),
                            changeType: "update", recordJSON: "{}")
        }
        let free = HistoryCapture.appending(rows, to: .empty, now: 1_800_000_000, limits: .free)
        XCTAssertEqual(free.itemHistory.count, 5)
        let pro = HistoryCapture.appending(rows, to: .empty, now: 1_800_000_000, limits: .pro)
        XCTAssertEqual(pro.itemHistory.count, 8)
    }

    func testRecorderBuffersUntilLocalDataOpens() {
        let recorder = HistoryRecorder()
        recorder.clock = { 1_800_000_000 }
        let row = ItemHistory.Row(snapshotID: "s", itemID: "w1", ns: "entry", createdAt: 1_800_000_000,
                                  changeType: "update", recordJSON: "{}")
        recorder.record([row])
        let local = InMemoryPhoneLocal()
        recorder.attach(local, isPro: { false })
        XCTAssertEqual(local.localData?.itemHistory, [row])
        recorder.detach()
        recorder.record([row])
        XCTAssertEqual(local.localData?.itemHistory.count, 1, "nothing recorded while locked reaches the old data")
    }

    func testRestoreOneFieldFromAnEarlierVersion() throws {
        guard case .object(var old) = webLogin else { return XCTFail() }
        old["username"] = .string("old-name")
        let row = try ItemHistory.Row(snapshotID: "s", itemID: "w1", ns: "entry", createdAt: 1, changeType: .update,
                                      record: .object(old))
        let store = MemoryStore(snapshot([webLogin]))
        XCTAssertEqual(ItemHistoryActions.restore(row, path: "username", id: "w1", store: store, clock: clock,
                                                  background: FakeBackgroundTasks()), .saved)
        let now = VaultItem.items(from: store.snapshot)[0].record
        XCTAssertEqual(now["username"], .string("old-name"))
        XCTAssertEqual(now["password"], .string("Maple-Orbit-7731"), "only the one field changes")
        XCTAssertEqual(ItemHistoryActions.restore(row, path: "username", id: "w1", store: store, clock: clock,
                                                  background: FakeBackgroundTasks()), .unchanged)
        XCTAssertEqual(ItemHistoryActions.restore(row, path: "id", id: "w1", store: store, clock: clock,
                                                  background: FakeBackgroundTasks()), .invalid)
    }

    // MARK: Passkey check and privacy proof

    func testPasskeyDoctorListsOnlyFailingChecks() {
        XCTAssertEqual(PasskeyDoctor.failing(providerEnabled: true, offerPasskeys: true, passkeyCount: 2), [])
        XCTAssertEqual(PasskeyDoctor.failing(providerEnabled: false, offerPasskeys: false, passkeyCount: 0),
                       [.provider, .offerPasskeys, .saved])
        XCTAssertEqual(PasskeyDoctor.failing(providerEnabled: nil, offerPasskeys: true, passkeyCount: 1), [])
    }

    func testPrivacyProofIsUnsignedWithoutSyncAndClaimsOnlyThePrefix() throws {
        let snap = snapshot([webLogin, note])
        let made = try PrivacyProofActions.make(snap, appVersion: "1.0", now: Date(timeIntervalSince1970: 1_800_000_000))
        XCTAssertEqual(made.document["signature"], .null)
        XCTAssertEqual(made.document["claims"], .array([.string("breach_prefix_only")]))
        XCTAssertEqual(made.document["app"]?.objectValue?["platform"], .string("ios"))
        XCTAssertEqual(PrivacyProof.verify(made.bytes).verdict, .unsigned)
        XCTAssertEqual(PrivacyProofActions.facts(snap).sync, .off)
        XCTAssertEqual(PrivacyProofActions.facts(snap).items, 2)
        XCTAssertEqual(PrivacyProofActions.facts(snap, travel: TravelMode(on: true, tags: ["personal"])).items, 1,
                       "travel-hidden items are not counted (scan 2026-11-15 W-L7)")
    }

    // MARK: Detail screen after a rule change (simulator check 2026-11-16)

    func testDetailShowsARuleSetFromAPushedScreenAtOnce() {
        // Access rules saved while the detail screen stays open: the screen reloads the item, so its secrets are
        // masked again and the gate sees the new rule (before, Reveal showed the password without asking).
        let open = VaultItem.items(from: snapshot([login("d")]))[0]
        let model = ItemDetailModel(item: open, clipboard: SecretClipboard(pasteboard: FakePasteboard(), clock: TestClock(0)),
                                    clock: TestClock(0), concealSecrets: false)
        let password = model.fields.first { $0.id == "password" }!
        XCTAssertTrue(model.isRevealed(password))
        XCTAssertNil(model.reloaded(open, concealSecrets: true), "unchanged item: same model")
        let ruled = VaultItem.items(from: snapshot([login("d", policy: ["require_master_password": .bool(true)])]))[0]
        let gate = AccessGate()
        XCTAssertTrue(gate.masksSecrets(ruled))
        let next = model.reloaded(ruled, concealSecrets: gate.concealsOnOpen(ruled, setting: false))
        XCTAssertNotNil(next)
        XCTAssertEqual(next?.item, ruled, "the screen now holds the saved item")
        XCTAssertFalse(next?.isRevealed(password) ?? true, "masked again until the owner confirms")
        XCTAssertNil(model.reloaded(VaultItem.items(from: snapshot([login("other")]))[0], concealSecrets: true),
                     "another item never replaces the screen's")
    }

    func testProtectedLoginOpensMaskedEvenWithHidePasswordsOff() {
        let gate = AccessGate()
        let plain = VaultItem.items(from: snapshot([login("p")]))[0]
        let strict = VaultItem.items(from: snapshot([login("s", policy: ["require_master_password": .bool(true)])]))[0]
        let view = VaultItem.items(from: snapshot([login("v", access: .object(["phones": .string("view")]))]))[0]
        XCTAssertFalse(gate.concealsOnOpen(plain, setting: false))
        XCTAssertTrue(gate.concealsOnOpen(plain, setting: true))
        XCTAssertTrue(gate.concealsOnOpen(strict, setting: false))
        XCTAssertTrue(gate.concealsOnOpen(view, setting: false))
    }
}
