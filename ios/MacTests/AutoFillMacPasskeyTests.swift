import XCTest
import CryptoKit
import LGKCore
@testable import AppSharedMac

private struct PasskeyClock: UnixClock { let now: Int64 }

/// Counts every byte asked for: a refused registration generates nothing.
private final class CountingRandom: RandomSource, @unchecked Sendable {
    private(set) var calls = 0
    func bytes(count: Int) -> [UInt8] { calls += 1; return SystemRandomSource().bytes(count: count) }
}

private final class RecordingIdentities: PasskeyIdentityRefreshing, @unchecked Sendable {
    var snapshots: [StoreSnapshot] = []
    func refresh(_ snapshot: StoreSnapshot) async { snapshots.append(snapshot) }
}

private struct FixedEntitlement: ProEntitlementChecking {
    let value: Bool
    func isEntitled() async -> Bool { value }
}

/// StoreKit that answers only when released: a cancel can land while it is asked.
private final class GatedEntitlement: ProEntitlementChecking, @unchecked Sendable {
    private(set) var asked = false
    private var release: CheckedContinuation<Void, Never>?
    func isEntitled() async -> Bool {
        await withCheckedContinuation { c in release = c; asked = true }
        return true
    }
    func open() { release?.resume(); release = nil }
}

@MainActor
final class AutoFillMacPasskeyTests: XCTestCase {
    private var dir: URL!
    private var bio: FakeBiometricKeyStore!
    private var settings: AppSettings!
    private var suite: String!
    private var sink: AutoFillOutcomeRecorder!
    private let date = Date(timeIntervalSince1970: 1_800_000_000)
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
    private let cdh = Data(repeating: 7, count: 32)

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-autofillmac-pk-\(UUID().uuidString)", isDirectory: true)
        bio = FakeBiometricKeyStore()
        suite = "lgk-autofillmac-pk-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        sink = AutoFillOutcomeRecorder()
    }

    override func tearDown() async throws {
        UserDefaults().removePersistentDomain(forName: suite)
        try? FileManager.default.removeItem(at: dir)
    }

    private func makeModel(random: any RandomSource = SystemRandomSource(), pro: Bool = false,
                           identities: RecordingIdentities? = nil, entitlement: (any ProEntitlementChecking)? = nil) -> MacAutoFillModel {
        let date = self.date
        let opener = ExtensionVaultOpener(directory: dir, biometric: bio, clock: { date }, keychain: InMemoryKeychainVault())
        let m = MacAutoFillModel(opener: opener, matcher: AutoFillMatcher(matcher: URLMatcher(rules: nil)),
                                 settings: settings, clock: PasskeyClock(now: Int64(date.timeIntervalSince1970)),
                                 now: { date }, pro: entitlement ?? FixedEntitlement(value: pro), identities: identities,
                                 random: random, today: { "2026-10-28" })
        m.sink = sink
        return m
    }

    /// A Touch ID vault with `logins` plain web logins.
    @discardableResult
    private func createVault(logins: Int) async throws -> LocalStore {
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: bio,
                             clock: { [date] in date }, random: SystemRandomSource(), kdfParams: cheap)
        let store = try await vault.create(password: "correct horse", enableTouchID: true)
        store.limitHints = nil
        var snap = try store.load()
        for i in 0..<logins {
            var r = EditorModel.newRecord(kind: .web, now: 1_700_000_000, random: SystemRandomSource())
            let id = try XCTUnwrap(r["id"]?.stringValue)
            r["label"] = .string("site\(i).example"); r["username"] = .string("u\(i)"); r["password"] = .string("pw")
            r["scope"] = .object(["origin": .string("https://site\(i).example"),
                                  "urls": .array([.object(["url": .string("https://site\(i).example"), "match": .string("host")])])])
            snap.records[id] = Wrapper.make(ns: .entry, record: try Normalise.normalForm(ns: .entry, record: .object(r)))
        }
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        return store
    }

    private func request(algorithms: [Int] = [-7]) -> PasskeyRegistrationRequest {
        PasskeyRegistrationRequest(rpID: "Example.com", rpName: "", userName: "sam@example.com", userDisplayName: "",
                                   userHandle: Data([1, 2, 3, 4]), clientDataHash: cdh, algorithms: algorithms)
    }

    /// Registers through the model and returns the registration.
    private func register(_ m: MacAutoFillModel) async throws -> PasskeyRegistration {
        m.begin(.passkeyRegistration(request()))
        await m.unlockWithTouchID()
        XCTAssertEqual(m.screen, .createPasskey(rpID: "example.com", userName: "sam@example.com"))
        await m.createPasskey()
        guard case .registration(let r)? = sink.outcomes.last else { throw XCTSkip("no registration: \(sink.outcomes)") }
        return r
    }

    func testAssertionSignsWithStoredKey() async throws {
        let store = try await createVault(logins: 1)
        _ = try await register(makeModel())
        let snap = try store.load()
        let (id, record) = try XCTUnwrap(snap.records.compactMap { id, w in PasskeyRecord.from(w, id: id).map { (id, $0) } }.first)
        let pub = try XCTUnwrap(record.key?.publicKey)

        sink = AutoFillOutcomeRecorder()
        let m = makeModel()
        m.begin(.passkey(recordID: id, rpID: "EXAMPLE.com", clientDataHash: cdh))
        await m.unlockWithTouchID()
        guard case .passkey(let a)? = sink.outcomes.first, sink.outcomes.count == 1 else { return XCTFail("\(sink.outcomes)") }
        let sig = try P256.Signing.ECDSASignature(derRepresentation: a.signature)
        XCTAssertTrue(pub.isValidSignature(sig, for: a.authenticatorData + cdh))
        XCTAssertEqual(a.rpID, "example.com")
        XCTAssertEqual(a.userHandle, Data([1, 2, 3, 4]))
        XCTAssertEqual(a.credentialID, Data(record.credentialID))
        XCTAssertEqual(a.authenticatorData[32] & 0x05, 0x05, "user present and user verified")
        XCTAssertFalse(m.holdsSnapshot)

        // The allow-list path: the passkey is listed for its relying party, and picking it signs.
        sink = AutoFillOutcomeRecorder()
        let l = makeModel()
        l.begin(.passkeyList(urls: ["https://example.com/"], rpID: "example.com", allowed: [a.credentialID], clientDataHash: cdh))
        await l.unlockWithTouchID()
        XCTAssertEqual(l.passkeys.map(\.itemID), [id])
        l.selectPasskey(try XCTUnwrap(l.passkeys.first))
        guard case .passkey? = sink.outcomes.first else { return XCTFail("\(sink.outcomes)") }

        // Another credential id in the allow-list: not offered.
        let other = makeModel()
        other.begin(.passkeyList(urls: [], rpID: "example.com", allowed: [Data([9])], clientDataHash: cdh))
        await other.unlockWithTouchID()
        XCTAssertEqual(other.passkeys, [])
    }

    func testRegistrationRefusedOnFullFreeVault() async throws {
        let store = try await createVault(logins: ItemLimit.freeItems)
        let before = try store.load()
        let random = CountingRandom()
        let m = makeModel(random: random)
        m.begin(.passkeyRegistration(request()))
        await m.unlockWithTouchID()
        await m.createPasskey()
        XCTAssertEqual(sink.outcomes, [.cancelled(.failed)])
        XCTAssertEqual(random.calls, 0, "no key or credential id generated")
        let after = try store.load()
        XCTAssertEqual(after.revision, before.revision)
        XCTAssertEqual(after.records.count, before.records.count)

        // The app's plan-full hint at the current revision: refused before the unlock, without Pro.
        settings.planFullRevision = LocalStore.committedRevision(directory: dir)
        sink = AutoFillOutcomeRecorder()
        let hinted = makeModel(random: random)
        hinted.begin(.passkeyRegistration(request()))
        await hinted.preflight?.value
        XCTAssertEqual(sink.outcomes, [.cancelled(.failed)])
        XCTAssertNotEqual(hinted.screen, .unlock)

        // With the App Store entitlement the same vault accepts it.
        sink = AutoFillOutcomeRecorder()
        let pro = makeModel(pro: true)
        pro.begin(.passkeyRegistration(request()))
        await pro.preflight?.value
        XCTAssertEqual(pro.screen, .unlock)
        await pro.unlockWithTouchID()
        await pro.createPasskey()
        guard case .registration? = sink.outcomes.first else { return XCTFail("\(sink.outcomes)") }
        XCTAssertEqual(try store.load().records.count, before.records.count + 1)
    }

    func testRegistrationRepublishesIdentities() async throws {
        let store = try await createVault(logins: 1)
        let ids = RecordingIdentities()
        let r = try await register(makeModel(identities: ids))
        let committed = try store.load()
        XCTAssertEqual(ids.snapshots.count, 1)
        XCTAssertEqual(ids.snapshots.first?.revision, committed.revision)
        XCTAssertEqual(ids.snapshots.first?.records, committed.records)
        XCTAssertEqual(r.rpID, "example.com")
        XCTAssertEqual(r.clientDataHash, cdh)
        XCTAssertFalse(r.attestationObject.isEmpty)
    }

    func testNonES256Refused() async throws {
        let store = try await createVault(logins: 1)
        let before = try store.load().revision
        let random = CountingRandom()
        let m = makeModel(random: random)
        m.begin(.passkeyRegistration(request(algorithms: [-257])))
        XCTAssertEqual(sink.outcomes, [.cancelled(.failed)])
        XCTAssertNotEqual(m.screen, .unlock, "no unlock asked for a site this cannot serve")
        XCTAssertEqual(random.calls, 0)
        XCTAssertEqual(try store.load().revision, before)
    }

    func testPasskeysOffDeclined() async throws {
        try await createVault(logins: 1)
        settings.offerPasskeys = false
        let m = makeModel()
        m.begin(.passkeyRegistration(request()))
        XCTAssertEqual(sink.outcomes, [.cancelled(.failed)])
        sink = AutoFillOutcomeRecorder()
        let a = makeModel()
        a.begin(.passkey(recordID: "x", rpID: "example.com", clientDataHash: cdh))
        XCTAssertEqual(sink.outcomes, [.cancelled(.failed)])
        let l = makeModel()
        l.begin(.passkeyList(urls: ["https://example.com/"], rpID: "example.com", allowed: [], clientDataHash: cdh))
        XCTAssertEqual(l.request, .list(urls: ["https://example.com/"]), "the plain login list")
    }

    func testRegistrationCancelWritesNothing() async throws {
        let store = try await createVault(logins: 1)
        let before = try store.load().revision
        let m = makeModel()
        m.begin(.passkeyRegistration(request()))
        await m.unlockWithTouchID()
        m.cancel()
        XCTAssertEqual(sink.outcomes, [.cancelled(.userCanceled)])
        await m.createPasskey()
        XCTAssertEqual(try store.load().revision, before)
        XCTAssertEqual(sink.outcomes.count, 1)
    }

    func testCancelDuringStoreKitCheckCommitsNothing() async throws {
        let store = try await createVault(logins: ItemLimit.freeItems)
        let before = try store.load()
        let gate = GatedEntitlement()
        let m = makeModel(entitlement: gate)
        m.begin(.passkeyRegistration(request()))
        await m.unlockWithTouchID()
        let create = Task { await m.createPasskey() }
        while !gate.asked { await Task.yield() }
        m.cancel()
        gate.open()
        await create.value
        XCTAssertEqual(sink.outcomes, [.cancelled(.userCanceled)])
        let after = try store.load()
        XCTAssertEqual(after.revision, before.revision)
        XCTAssertEqual(after.records.count, before.records.count)
    }
}
