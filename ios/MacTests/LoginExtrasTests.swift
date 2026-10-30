import XCTest
import LGKCore
@testable import AppSharedMac

@MainActor
private final class OnePassword: MasterPasswordService {
    private(set) var calls = 0
    var hasVault = true
    var isUnlocked = true
    var touchIDAvailable = true
    func verifyPassword(_ password: String) async throws {
        calls += 1
        guard password == "correct horse" else { throw MacVaultError.wrongPassword(retryAfter: nil) }
    }
    func changePassword(old: String, new: String) async throws {}
    func setTouchID(_ on: Bool, password: String) async throws {}
    var routineTouchIDEnabled = false
    var touchIDSucceeds = true
    private(set) var touchIDCalls = 0
    var sessionGeneration = 0
    func verifyWithTouchID(reason: String) async throws {
        touchIDCalls += 1
        guard touchIDSucceeds else { throw CancellationError() }
    }
}

@MainActor
private final class Now {
    var date = Date(timeIntervalSince1970: 1_800_000_000)
}

private struct FixedClock: UnixClock { var now: Int64 }


@MainActor
final class LoginExtrasTests: XCTestCase {
    private var dir: URL!
    private var store: LocalStore!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-extras-\(UUID().uuidString)", isDirectory: true)
        store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        store.limitHints = nil
    }

    override func tearDown() async throws { try? FileManager.default.removeItem(at: dir) }

    private func seed(_ extra: [String: JSONValue] = [:], strict: Bool = false) throws -> VaultItem {
        var r = EditorModel.newRecord(kind: .web, now: 1_700_000_000, random: SystemRandomSource())
        let id = try XCTUnwrap(r["id"]?.stringValue)
        r["label"] = .string("Bank"); r["username"] = .string("sam"); r["password"] = .string("first-password")
        r["scope"] = .object(["origin": .string("https://bank.example")])
        if strict { r["policy"] = .object(["require_master_password": .bool(true)]) }
        for (k, v) in extra { r[k] = v }
        let record = try Normalise.normalForm(ns: .entry, record: .object(r))
        let snap = try store.load()
        var records = snap.records
        records[id] = Wrapper.make(ns: .entry, record: record)
        try store.commit(StoreChange(baseRevision: snap.revision, records: records, meta: snap.meta, sync: snap.sync))
        return try XCTUnwrap(item(id))
    }

    private func item(_ id: String) -> VaultItem? {
        let list = VaultListModel(store: store)
        list.reload()
        return list.items.first { $0.id == id }
    }

    /// A gate whose routine grace has just been granted (one master password confirmation).
    private func graceGate(_ item: VaultItem) async -> StrictItemGate {
        let gate = StrictItemGate(passwords: OnePassword())
        gate.releaseRoutine(item, action: "Warm up") {}
        await gate.submit("correct horse")
        return gate
    }

    // MARK: custom fields

    func testCustomFieldsLimitsAndHiddenDefault() async throws {
        // A row without `hidden` is hidden (Windows `f.get("hidden", True) is True`); a non-bool is not.
        let stored = try seed(["custom_fields": .array([
            .object(["name": .string("PIN"), "value": .string("1234")]),
            .object(["name": .string("Branch"), "value": .string("Leeds"), "hidden": .bool(false)]),
        ])])
        XCTAssertEqual(LoginExtrasModel.customFields(of: stored).map(\.hidden), [true, false])
        XCTAssertTrue(LoginExtrasModel.CustomField(name: "a", value: "b").hidden, "new fields are hidden by default")
        XCTAssertEqual(LoginExtrasModel.customFieldsHelp,
                       "Hidden fields are masked on screen and treated like passwords when exported.")

        typealias F = LoginExtrasModel.CustomField
        let fifty = (0..<50).map { F(name: "f\($0)", value: "v") }
        XCTAssertNil(LoginExtrasModel.validate(fields: fifty))
        XCTAssertEqual(LoginExtrasModel.validate(fields: fifty + [F(name: "x", value: "y")]), "At most 50 custom fields")
        XCTAssertNil(LoginExtrasModel.validate(fields: fifty + [F(name: " ", value: "")]), "empty rows are dropped")
        XCTAssertNil(LoginExtrasModel.validate(fields: [F(name: String(repeating: "n", count: 100), value: String(repeating: "v", count: 4096))]))
        XCTAssertEqual(LoginExtrasModel.validate(fields: [F(name: String(repeating: "n", count: 101), value: "")]),
                       "Name is longer than 100 characters")
        XCTAssertEqual(LoginExtrasModel.validate(fields: [F(name: "n", value: String(repeating: "v", count: 4097))]),
                       "Value is longer than 4,096 characters")
        XCTAssertEqual(LoginExtrasModel.validate(fields: [F(name: "", value: "orphan")]), "Give this field a name")

        // Add field → save writes the desktop's {name, value, hidden} rows, names trimmed, empty rows dropped.
        let model = LoginExtrasModel(), gate = await graceGate(stored)
        model.revealFields(stored, gate: gate, onRevealed: {})
        model.addField()
        XCTAssertEqual(model.fields?.last?.hidden, true)
        model.fields?[2].name = "  Memorable word "; model.fields?[2].value = "otter"
        model.addField()
        var saved = 0
        model.saveFields(stored, store: store, clock: FixedClock(now: 1_800_000_000), gate: gate) { saved += 1 }
        XCTAssertEqual(saved, 1)
        let after = try XCTUnwrap(item(stored.id))
        XCTAssertEqual(after.record["custom_fields"], .array([
            .object(["name": .string("PIN"), "value": .string("1234"), "hidden": .bool(true)]),
            .object(["name": .string("Branch"), "value": .string("Leeds"), "hidden": .bool(false)]),
            .object(["name": .string("Memorable word"), "value": .string("otter"), "hidden": .bool(true)]),
        ]))
        XCTAssertEqual(after.record["updated_at"], .int(1_800_000_000))

        // Too many fields: refused before anything is written.
        model.fields = fifty + [F(name: "x", value: "y")]
        model.saveFields(after, store: store, clock: FixedClock(now: 1_800_000_100), gate: gate) { saved += 1 }
        XCTAssertEqual(saved, 1)
        XCTAssertEqual(model.error, "At most 50 custom fields")
        model.fields = fifty
        model.addField()
        XCTAssertEqual(model.fields?.count, 50, "Add field stops at 50")
    }

    // MARK: recovery codes

    func testRecoveryCodesLimits() async throws {
        let stored = try seed()
        XCTAssertEqual(LoginExtrasModel.recoveryText(stored), "No saved codes. Reveal to add some.")
        XCTAssertNil(LoginExtrasModel.validate(codes: Array(repeating: "c", count: 100)))
        XCTAssertEqual(LoginExtrasModel.validate(codes: Array(repeating: "c", count: 101)), "At most 100 recovery codes")
        XCTAssertNil(LoginExtrasModel.validate(codes: Array(repeating: "c", count: 100) + ["  ", ""]), "blank lines don't count")
        XCTAssertNil(LoginExtrasModel.validate(codes: [String(repeating: "x", count: 512)]))
        XCTAssertEqual(LoginExtrasModel.validate(codes: [String(repeating: "x", count: 513)]),
                       "Recovery codes are at most 512 characters")

        let model = LoginExtrasModel(), gate = await graceGate(stored)
        model.revealCodes(stored, gate: gate, onRevealed: {})
        XCTAssertEqual(model.codes, [])
        model.codes = [" AAAA-1111 ", "", "BBBB-2222"]
        model.saveCodes(stored, store: store, clock: FixedClock(now: 1_800_000_000), gate: gate) {}
        let after = try XCTUnwrap(item(stored.id))
        XCTAssertEqual(after.record["recovery_codes"], .array([.string("AAAA-1111"), .string("BBBB-2222")]))
        XCTAssertEqual(LoginExtrasModel.recoveryText(after), "2 saved code(s) hidden. Reveal to view or edit.")

        model.codes = Array(repeating: "c", count: 101)
        model.saveCodes(after, store: store, clock: FixedClock(now: 1_800_000_100), gate: gate) {}
        XCTAssertEqual(model.error, "At most 100 recovery codes")
        XCTAssertEqual(item(stored.id)?.record["recovery_codes"], after.record["recovery_codes"], "nothing written")

        let strict = try seed(["recovery_codes": .array([.string("ZZZZ")])], strict: true)
        XCTAssertEqual(LoginExtrasModel.recoveryText(strict),
                       "Locked · this login always asks for the master password. Reveal to view or edit.")
    }

    // MARK: password history

    func testHistoryOnlyOnRealChange() throws {
        let stored = try seed(["password_history": .array([.object(["password": .string("ancient"), "replaced_at": .int(1_790_000_000)])])])
        XCTAssertEqual(LoginExtrasModel.history(of: stored),
                       [.init(password: "ancient", changedAt: 1_790_000_000)], "replaced_at reads as changed_at")
        func edit(_ password: String, at now: Int64, keeps: Bool = true) throws -> SaveResult {
            let m = EditorModel(store: store, pro: ProModel(purchases: NoPurchases()), editing: try XCTUnwrap(item(stored.id)),
                                kind: .web, clock: FixedClock(now: now), random: SystemRandomSource(), keepsPasswordHistory: keeps)
            m.set("password", password)
            return m.save()
        }
        XCTAssertEqual(try edit("first-password", at: 1_800_000_000), .unchanged, "same password: no history")
        XCTAssertEqual(LoginExtrasModel.history(of: try XCTUnwrap(item(stored.id))).count, 1)

        XCTAssertEqual(try edit("second-password", at: 1_800_000_001), .saved)
        var rows = LoginExtrasModel.history(of: try XCTUnwrap(item(stored.id)))
        XCTAssertEqual(rows.first, .init(password: "first-password", changedAt: 1_800_000_001), "newest first")
        XCTAssertEqual(item(stored.id)?.record["password_history"]?.arrayValue?.first,
                       .object(["password": .string("first-password"), "changed_at": .int(1_800_000_001)]))

        // Changing only the username adds nothing.
        let m = EditorModel(store: store, pro: ProModel(purchases: NoPurchases()), editing: try XCTUnwrap(item(stored.id)),
                            kind: .web, clock: FixedClock(now: 1_800_000_002), random: SystemRandomSource(), keepsPasswordHistory: true)
        m.set("username", "sam.t")
        XCTAssertEqual(m.save(), .saved)
        XCTAssertEqual(LoginExtrasModel.history(of: try XCTUnwrap(item(stored.id))).count, 2)

        for n in 3...8 { XCTAssertEqual(try edit("password-\(n)", at: 1_800_000_000 + Int64(n)), .saved) }
        rows = LoginExtrasModel.history(of: try XCTUnwrap(item(stored.id)))
        XCTAssertEqual(rows.count, 5, "capped at 5")
        XCTAssertEqual(rows.map(\.password), ["password-7", "password-6", "password-5", "password-4", "password-3"])

        // The iPhone's editor (default) leaves the stored history alone.
        XCTAssertEqual(try edit("password-9", at: 1_800_000_100, keeps: false), .saved)
        XCTAssertEqual(LoginExtrasModel.history(of: try XCTUnwrap(item(stored.id))).map(\.password).first, "password-7")

        // An empty previous password is not history.
        let blank = EditorModel.withPasswordHistory(["password": .string("new")], original: ["password": .string("")], now: 1)
        XCTAssertNil(blank["password_history"])
    }

    // MARK: hiding

    func testRevealedHiddenOnLock() async throws {
        let extras: [String: JSONValue] = [
            "recovery_codes": .array([.string("AAAA-1111")]),
            "custom_fields": .array([.object(["name": .string("PIN"), "value": .string("1234"), "hidden": .bool(true)])]),
            "password_history": .array([.object(["password": .string("old"), "changed_at": .int(1_600_000_000)])]),
        ]
        let plain = try seed(extras), strict = try seed(extras, strict: true)
        let model = LoginExtrasModel()
        var reveals = 0

        // Ordinary login: revealed at once within the routine grace.
        let gate = await graceGate(plain)
        model.select(plain.id)
        model.revealCodes(plain, gate: gate) { reveals += 1 }
        model.revealFields(plain, gate: gate) { reveals += 1 }
        model.showHistory(0, of: plain, gate: gate) { reveals += 1 }
        XCTAssertEqual(model.codes, ["AAAA-1111"])
        XCTAssertEqual(model.fields?.first?.value, "1234")
        XCTAssertTrue(model.historyShown(0))
        XCTAssertEqual(reveals, 3)

        // Selecting another item hides everything.
        model.select(strict.id)
        XCTAssertNil(model.codes); XCTAssertNil(model.fields); XCTAssertFalse(model.historyShown(0))

        // Strict login: nothing until the master password, every time.
        let vault = OnePassword(), strictGate = StrictItemGate(passwords: vault)
        model.revealCodes(strict, gate: strictGate) { reveals += 1 }
        XCTAssertNil(model.codes)
        XCTAssertEqual(strictGate.pending?.action, "Reveal recovery codes")
        await strictGate.submit("wrong")
        XCTAssertNil(model.codes)
        await strictGate.submit("correct horse")
        XCTAssertEqual(model.codes, ["AAAA-1111"])
        model.revealFields(strict, gate: strictGate) { reveals += 1 }
        XCTAssertNil(model.fields, "asks again")
        await strictGate.submit("correct horse")
        XCTAssertEqual(model.fields?.first?.value, "1234")
        XCTAssertEqual(vault.calls, 3)

        // Locking hides it all; a release confirmed after the selection moved reveals nothing.
        let dir2 = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-extras-lock-\(UUID().uuidString)", isDirectory: true)
        let suite = "lgk-extras-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(at: dir2); UserDefaults().removePersistentDomain(forName: suite) }
        let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
        let lock = MacLockModel(vault: MacVault(directory: dir2, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(),
                                                kdfParams: cheap),
                                settings: AppSettings(defaults: UserDefaults(suiteName: suite)!), events: FakeSystemEvents(), startTimer: false)
        await lock.create(password: "correct horse battery", confirm: "correct horse battery", touchID: false)
        model.clear(on: lock)
        model.showHistory(0, of: strict, gate: StrictItemGate(passwords: nil)) {}
        lock.lock()
        XCTAssertNil(model.codes); XCTAssertNil(model.fields); XCTAssertFalse(model.historyShown(0)); XCTAssertNil(model.itemID)

        model.select(strict.id)
        model.revealCodes(strict, gate: strictGate) {}
        model.select(plain.id)
        await strictGate.submit("correct horse")
        XCTAssertNil(model.codes, "a late confirmation for another item reveals nothing")
    }

    // MARK: routine re-authentication

    func testRoutinePromptThenGrace() async throws {
        let plain = try seed(["recovery_codes": .array([.string("AAAA")])]), strict = try seed(strict: true)
        let vault = OnePassword(), clock = Now()
        let gate = StrictItemGate(passwords: vault, now: { clock.date })
        var released = 0

        gate.releaseRoutine(plain, action: "Copy password") { released += 1 }
        XCTAssertEqual(gate.pending?.level, .routine)
        XCTAssertFalse(gate.offersTouchID, "Touch ID off: master password only")
        XCTAssertEqual(released, 0)
        await gate.submit("correct horse")
        XCTAssertEqual(released, 1)

        clock.date += 119
        gate.releaseRoutine(plain, action: "Show password") { released += 1 }
        XCTAssertNil(gate.pending, "within 120 s: no prompt")
        XCTAssertEqual(released, 2)

        clock.date += 2   // 121 s after the confirmation
        gate.releaseRoutine(plain, action: "Show password") { released += 1 }
        XCTAssertNotNil(gate.pending, "grace over: asks again")
        await gate.submit("correct horse")
        XCTAssertEqual(released, 3)

        vault.sessionGeneration += 1   // locked and unlocked again
        gate.releaseRoutine(plain, action: "Show password") { released += 1 }
        XCTAssertNotNil(gate.pending, "a lock ends the grace")
        gate.cancel()

        // The grace never covers a strict login, and non-password releases on ordinary logins don't ask.
        gate.releaseRoutine(strict, action: "Copy password") { released += 1 }
        XCTAssertEqual(gate.pending?.level, .strict)
        gate.cancel()
        gate.release(plain, action: "Copy username") { released += 1 }
        XCTAssertNil(gate.pending)
        XCTAssertEqual(released, 4)
        gate.lockReset()
        gate.releaseRoutine(plain, action: "Show password") {}
        XCTAssertNotNil(gate.pending, "lockReset ends the grace")
    }

    func testTouchIDOfferedForRoutineNeverStrict() async throws {
        let plain = try seed(), strict = try seed(strict: true)
        let vault = OnePassword(); vault.routineTouchIDEnabled = true
        let gate = StrictItemGate(passwords: vault)
        var released = 0
        gate.releaseRoutine(strict, action: "Reveal recovery codes") { released += 1 }
        XCTAssertFalse(gate.offersTouchID)
        await gate.submitTouchID()
        XCTAssertEqual(vault.touchIDCalls, 0, "strict: never Touch ID")
        XCTAssertNotNil(gate.pending)
        gate.cancel()

        gate.releaseRoutine(plain, action: "Reveal recovery codes") { released += 1 }
        XCTAssertTrue(gate.offersTouchID)
        vault.touchIDSucceeds = false
        await gate.submitTouchID()
        XCTAssertEqual(released, 0, "cancelled Touch ID releases nothing")
        XCTAssertNotNil(gate.pending, "the password stays available")
        vault.touchIDSucceeds = true
        await gate.submitTouchID()
        XCTAssertEqual(released, 1)
        XCTAssertEqual(vault.calls, 0)
        gate.releaseRoutine(plain, action: "Copy password") { released += 1 }
        XCTAssertEqual(released, 2, "Touch ID starts the grace too")
    }

    func testStaleSaveRefused() async throws {
        let stored = try seed(["recovery_codes": .array([.string("AAAA")])])
        let model = LoginExtrasModel(), gate = await graceGate(stored)
        model.revealCodes(stored, gate: gate, onRevealed: {})
        model.revealFields(stored, gate: gate, onRevealed: {})
        // Changed elsewhere (another window, a sync) after the reveal.
        let changed = try XCTUnwrap(LoginExtrasModel().write(stored, store: store, clock: FixedClock(now: 1_800_000_500),
                                                               expected: LoginExtrasModel.stamp(stored.record),
                                                               changes: ["recovery_codes": .array([.string("BBBB")])]))
        XCTAssertNotEqual(changed, LoginExtrasModel.stamp(stored.record))
        var saved = 0
        model.codes = ["CCCC"]
        model.saveCodes(stored, store: store, clock: FixedClock(now: 1_800_000_600), gate: gate) { saved += 1 }
        XCTAssertEqual(model.error, "This login changed since you opened it. Reveal it again to edit.")
        model.fields = [.init(name: "PIN", value: "1")]
        model.saveFields(stored, store: store, clock: FixedClock(now: 1_800_000_600), gate: gate) { saved += 1 }
        XCTAssertEqual(model.error, LoginExtrasModel.changedText)
        XCTAssertEqual(saved, 0)
        XCTAssertEqual(item(stored.id)?.record["recovery_codes"], .array([.string("BBBB")]), "the other change is kept")

        // Revealed again: the save goes through, and a second save after our own works too.
        let fresh = try XCTUnwrap(item(stored.id))
        model.revealCodes(fresh, gate: gate, onRevealed: {})
        model.codes = ["DDDD"]
        model.saveCodes(fresh, store: store, clock: FixedClock(now: 1_800_000_700), gate: gate) { saved += 1 }
        model.codes = ["EEEE"]
        model.saveCodes(fresh, store: store, clock: FixedClock(now: 1_800_000_800), gate: gate) { saved += 1 }
        XCTAssertEqual(saved, 2)
        XCTAssertEqual(item(stored.id)?.record["recovery_codes"], .array([.string("EEEE")]))
    }

    func testLoginPasswordStartsConcealed() throws {
        let login = try seed()
        XCTAssertTrue(DetailPanel.concealsSecrets(login, setting: false), "logins ignore the setting")
        XCTAssertTrue(DetailPanel.concealsSecrets(login, setting: true))
        let note = VaultItem(id: "n", record: ["kind": .string("note"), "title": .string("N"), "payload": .object([:])])!
        XCTAssertFalse(DetailPanel.concealsSecrets(note, setting: false))
        let model = ItemDetailModel(item: login, clipboard: MacClipboard(pasteboard: .withUniqueName(), clock: FixedClock(now: 0), clearAfter: 60),
                                    clock: FixedClock(now: 0), concealSecrets: DetailPanel.concealsSecrets(login, setting: false))
        let pw = try XCTUnwrap(model.fields.first { $0.id == "password" })
        XCTAssertFalse(model.isRevealed(pw))
    }

    func testSavingCodesThenFieldsBothSucceed() async throws {
        let stored = try seed()
        let model = LoginExtrasModel(), gate = await graceGate(stored)
        model.revealCodes(stored, gate: gate, onRevealed: {})
        model.revealFields(stored, gate: gate, onRevealed: {})
        var saved = 0
        model.codes = ["AAAA"]
        model.saveCodes(stored, store: store, clock: FixedClock(now: 1_800_000_000), gate: gate) { saved += 1 }
        model.fields = [.init(name: "PIN", value: "1")]
        model.saveFields(stored, store: store, clock: FixedClock(now: 1_800_000_001), gate: gate) { saved += 1 }
        model.codes = ["BBBB"]
        model.saveCodes(stored, store: store, clock: FixedClock(now: 1_800_000_002), gate: gate) { saved += 1 }
        XCTAssertNil(model.error)
        XCTAssertEqual(saved, 3)
        let after = try XCTUnwrap(item(stored.id))
        XCTAssertEqual(after.record["recovery_codes"], .array([.string("BBBB")]))
        XCTAssertEqual(LoginExtrasModel.customFields(of: after).map(\.name), ["PIN"])
    }
}
