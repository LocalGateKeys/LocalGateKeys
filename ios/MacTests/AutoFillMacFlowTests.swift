import XCTest
import AuthenticationServices
import LGKCore
@testable import AppSharedMac

/// Records the one outcome the extension context gets.
@MainActor
final class AutoFillOutcomeRecorder: MacAutoFillSink {
    enum Outcome: Equatable {
        case password(String, String), code(String), cancelled(ASExtensionError.Code)
        case passkey(PasskeyAssertion), registration(PasskeyRegistration), text(String)
    }
    var outcomes: [Outcome] = []
    func completeText(_ text: String) { outcomes.append(.text(text)) }
    func completePasskey(_ assertion: PasskeyAssertion) { outcomes.append(.passkey(assertion)) }
    func completeRegistration(_ registration: PasskeyRegistration) { outcomes.append(.registration(registration)) }
    func completePassword(user: String, password: String) { outcomes.append(.password(user, password)) }
    func completeOneTimeCode(_ code: String) { outcomes.append(.code(code)) }
    func cancelRequest(_ code: ASExtensionError.Code) { outcomes.append(.cancelled(code)) }
}

private struct FixedClock: UnixClock { let now: Int64 }

@MainActor
final class AutoFillMacFlowTests: XCTestCase {
    private var dir: URL!
    private var bio: FakeBiometricKeyStore!
    private var settings: AppSettings!
    private var suite: String!
    private let sink = AutoFillOutcomeRecorder()
    private let date = Date(timeIntervalSince1970: 1_800_000_000)
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
    private let totpSecret = "JBSWY3DPEHPK3PXP"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-autofillmac-\(UUID().uuidString)", isDirectory: true)
        bio = FakeBiometricKeyStore()
        suite = "lgk-autofillmac-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
    }

    override func tearDown() async throws {
        UserDefaults().removePersistentDomain(forName: suite)
        try? FileManager.default.removeItem(at: dir)
    }

    private func makeModel() -> MacAutoFillModel {
        let date = self.date
        let opener = ExtensionVaultOpener(directory: dir, biometric: bio, clock: { date }, keychain: InMemoryKeychainVault())
        let m = MacAutoFillModel(opener: opener, matcher: AutoFillMatcher(matcher: URLMatcher(rules: nil)),
                                 settings: settings, clock: FixedClock(now: Int64(date.timeIntervalSince1970)),
                                 now: { date })
        m.sink = sink
        return m
    }

    /// A vault with Touch ID turned on, as the app creates it, and the given logins.
    private func createVault(_ logins: [(host: String, user: String, strict: Bool, totp: Bool)]) async throws -> [String] {
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: bio,
                             clock: { [date] in date }, random: SystemRandomSource(), kdfParams: cheap)
        let store = try await vault.create(password: "correct horse", enableTouchID: true)
        store.limitHints = nil
        var snap = try store.load()
        var ids: [String] = []
        for l in logins {
            var r = EditorModel.newRecord(kind: .web, now: 1_700_000_000, random: SystemRandomSource())
            let id = try XCTUnwrap(r["id"]?.stringValue)
            r["label"] = .string(l.host); r["username"] = .string(l.user); r["password"] = .string("pw-\(l.host)")
            r["scope"] = .object(["origin": .string("https://\(l.host)"),
                                  "urls": .array([.object(["url": .string("https://\(l.host)"), "match": .string("host")])])])
            if l.totp { r["totp"] = .object(["secret": .string(totpSecret)]) }
            if l.strict { r["policy"] = .object(["require_master_password": .bool(true)]) }
            let wrapper = Wrapper.make(ns: .entry, record: try Normalise.normalForm(ns: .entry, record: .object(r)))
            snap.records[id] = wrapper
            snap.meta[id] = try SyncMeta.live(wrapper, vv: ["0b6f3c1e-8a5d-4c2b-9f7e-1d2c3b4a5e6f": 1])
            ids.append(id)
        }
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        return ids
    }

    func testMatchesForURL() async throws {
        _ = try await createVault([("github.com", "sam", false, false), ("example.org", "alex", false, false),
                                   ("gitlab.com", "kim", false, false)])
        let m = makeModel()
        m.begin(.list(urls: ["https://github.com/login"]))
        XCTAssertEqual(m.screen, .unlock)
        XCTAssertTrue(m.matches.isEmpty, "nothing listed before an unlock")
        await m.unlockWithTouchID()
        XCTAssertEqual(m.screen, .list)
        XCTAssertEqual(m.matches.map(\.login.username), ["sam"], "the page's logins first")
        XCTAssertEqual(m.all.count, 3)
        m.query = "git"
        XCTAssertEqual(Set(m.searchResults.map(\.login.username)), ["sam", "kim"], "search all")
        m.select(m.searchResults.first { $0.login.username == "kim" }!)
        XCTAssertEqual(sink.outcomes, [.password("kim", "pw-gitlab.com")])
        XCTAssertTrue(m.all.isEmpty && m.matches.isEmpty, "the decrypted vault is dropped after the fill")
        // Plain HTTP pages are never offered an HTTPS login.
        let m2 = makeModel()
        m2.begin(.list(urls: ["http://github.com/"]))
        await m2.unlock(password: "correct horse")
        XCTAssertTrue(m2.matches.isEmpty)
    }

    /// UX workstream 11: card and identity fields only after the unlock, the security code never first, one
    /// insertion, then the vault is dropped.
    func testTextInsertionListsCardFieldsAfterUnlock() async throws {
        _ = try await createVault([("github.com", "sam", false, false)])
        let m = makeModel()
        m.begin(.textToInsert)
        XCTAssertEqual(m.screen, .unlock)
        XCTAssertTrue(m.textFields.isEmpty, "nothing listed before an unlock")
        await m.unlockWithTouchID()
        XCTAssertEqual(m.screen, .list)
        XCTAssertTrue(m.isTextInsertion)
        XCTAssertTrue(m.textFields.isEmpty, "a vault with only logins offers no fields")
        m.cancel()
        XCTAssertEqual(sink.outcomes, [.cancelled(.userCanceled)])
    }

    func testTextInsertionCatalogOrder() {
        let card = TextInsertionCatalog.card(id: "c1", title: "Visa", payload: [
            "number": .string("4111 1111 1111 6411"), "cvv": .string("123"), "expiry": .string("08/27")])
        XCTAssertEqual(card.map(\.kind), [.cardNumber, .cardExpiry, .cardSecurityCode])
        XCTAssertEqual(card.last?.isPreselectable, false)
        XCTAssertEqual(card.first?.display, "•••• 6411")
    }

    /// Review Focus 3: a strict login asks for the master password even right after a Touch ID unlock.
    func testStrictLoginNeedsMasterPassword() async throws {
        let ids = try await createVault([("bank.example", "sam", true, false)])
        let m = makeModel()
        m.begin(.password(recordID: ids[0]))
        await m.unlockWithTouchID()
        guard case .strict(let row) = m.screen else { return XCTFail("expected the strict prompt, got \(m.screen)") }
        XCTAssertEqual(row.login.id, ids[0])
        XCTAssertTrue(sink.outcomes.isEmpty, "nothing filled on Touch ID alone")
        await m.confirmStrict(password: "wrong horse!")
        XCTAssertTrue(sink.outcomes.isEmpty)
        XCTAssertEqual(m.message, "Wrong master password.")
        await m.confirmStrict(password: "correct horse")
        XCTAssertEqual(sink.outcomes, [.password("sam", "pw-bank.example")])

        // From the list too, and the shared throttle shows its wait.
        let m2 = makeModel()
        m2.begin(.list(urls: ["https://bank.example/"]))
        await m2.unlockWithTouchID()
        let strictRow = try XCTUnwrap(m2.matches.first)
        XCTAssertTrue(strictRow.strict)
        m2.select(strictRow)
        XCTAssertEqual(m2.screen, .strict(strictRow))
        for _ in 1...6 { await m2.confirmStrict(password: "nope nope") }
        XCTAssertEqual(m2.message, "Too many attempts. Try again in 2 s.")
        XCTAssertEqual(sink.outcomes.count, 1)
    }

    func testOneTimeCodeRequestReturnsCurrentCode() async throws {
        let ids = try await createVault([("totp.example", "sam", false, true), ("plain.example", "alex", false, false)])
        let expected = try TOTP.code(secret: totpSecret, algorithm: "SHA1", digits: 6, period: 30,
                                     at: Int64(date.timeIntervalSince1970))
        let m = makeModel()
        m.begin(.oneTimeCode(recordID: ids[0]))
        await m.unlock(password: "correct horse")
        XCTAssertEqual(sink.outcomes, [.code(expected)])

        // The list offers only logins with a 2FA secret.
        let m2 = makeModel()
        m2.begin(.oneTimeCodeList(urls: ["https://totp.example/"]))
        await m2.unlockWithTouchID()
        XCTAssertEqual(m2.all.map(\.login.username), ["sam"])
        m2.select(try XCTUnwrap(m2.matches.first))
        XCTAssertEqual(sink.outcomes.last, .code(expected))

        // A login without a secret is not found.
        let m3 = makeModel()
        m3.begin(.oneTimeCode(recordID: ids[1]))
        await m3.unlockWithTouchID()
        XCTAssertEqual(sink.outcomes.last, .cancelled(.credentialIdentityNotFound))
    }

    func testCancelReturnsUserCanceled() async throws {
        _ = try await createVault([("github.com", "sam", false, false)])
        let m = makeModel()
        m.begin(.list(urls: ["https://github.com/"]))
        m.cancel()
        XCTAssertEqual(sink.outcomes, [.cancelled(.userCanceled)])
        await m.unlockWithTouchID()
        m.cancel()
        XCTAssertEqual(sink.outcomes.count, 1, "one outcome per request")
        XCTAssertEqual(m.screen, .finished)
        // No record identifier: answered at once, without unlocking.
        let m2 = makeModel()
        m2.begin(.identityNotFound)
        XCTAssertEqual(sink.outcomes.last, .cancelled(.credentialIdentityNotFound))
    }

    func testErasePendingRefuses() async throws {
        _ = try await createVault([("github.com", "sam", false, false)])
        settings.erasePending = true
        let m = makeModel()
        m.begin(.list(urls: ["https://github.com/"]))
        XCTAssertEqual(sink.outcomes, [.cancelled(.failed)])
        XCTAssertNotEqual(m.screen, .unlock, "no unlock offered over a partly wiped vault")
    }

    func testUnsupportedRegistrationFailsCleanly() async throws {
        _ = try await createVault([("github.com", "sam", false, false)])
        let m = makeModel()
        m.begin(.unsupportedRegistration)
        XCTAssertEqual(sink.outcomes, [.cancelled(.failed)])
        XCTAssertEqual(m.screen, .finished, "no blank sheet left waiting")
    }

    func testDismissClearsSnapshot() async throws {
        _ = try await createVault([("github.com", "sam", false, false)])
        let m = makeModel()
        m.begin(.list(urls: ["https://github.com/"]))
        await m.unlockWithTouchID()
        XCTAssertTrue(m.holdsSnapshot)
        m.dismissed()
        XCTAssertFalse(m.holdsSnapshot)
        XCTAssertTrue(m.matches.isEmpty && m.all.isEmpty)
        XCTAssertEqual(sink.outcomes, [.cancelled(.userCanceled)])
        m.dismissed()
        XCTAssertEqual(sink.outcomes.count, 1)
    }

    /// An unlock that finishes after a newer request began delivers nothing into it.
    func testStaleUnlockDoesNotDeliverIntoNewerRequest() async throws {
        let ids = try await createVault([("github.com", "sam", false, false), ("gitlab.com", "kim", false, false)])
        let m = makeModel()
        m.begin(.password(recordID: ids[0]))
        let stale = Task { await m.unlock(password: "correct horse") }
        await Task.yield()
        m.begin(.list(urls: ["https://gitlab.com/"]))
        await stale.value
        XCTAssertTrue(sink.outcomes.isEmpty, "the first request's unlock fills nothing")
        XCTAssertEqual(m.screen, .unlock, "the newer request still needs its own unlock")
        XCTAssertFalse(m.holdsSnapshot)
        await m.unlockWithTouchID()
        XCTAssertEqual(m.matches.map(\.login.username), ["kim"])
    }
}
