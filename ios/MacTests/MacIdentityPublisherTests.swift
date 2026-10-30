import XCTest
import LGKCore
@testable import AppSharedMac

/// Records the identity store calls; `replace` can be held open to check that updates never overlap.
final class RecordingIdentityStore: CredentialIdentityStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var _calls: [String] = []
    private var _published: [IdentityEntry] = []
    private var running = 0
    private(set) var maxRunning = 0
    var enabled = true
    var hold: Duration = .zero

    var calls: [String] { lock.withLock { _calls } }
    var published: [IdentityEntry] { lock.withLock { _published } }

    func isEnabled() async -> Bool { enabled }

    func replace(_ identities: [IdentityEntry]) async throws {
        lock.withLock { running += 1; maxRunning = max(maxRunning, running); _calls.append("replace:\(identities.count)") }
        if hold > .zero { try? await Task.sleep(for: hold) }
        lock.withLock { _published = identities; running -= 1 }
    }

    func removeAll() async throws { lock.withLock { _calls.append("removeAll"); _published = [] } }
}

@MainActor
final class MacIdentityPublisherTests: XCTestCase {
    private var dir: URL!
    private var store: LocalStore!
    private var settings: AppSettings!
    private var ids: RecordingIdentityStore!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-ids-\(UUID().uuidString)", isDirectory: true)
        store = try LocalStore.bootstrap(directory: dir, vault: InMemoryKeychainVault())
        store.limitHints = nil
        let defaults = UserDefaults(suiteName: "lgk-ids-\(UUID().uuidString)")!
        settings = AppSettings(defaults: defaults)
        ids = RecordingIdentityStore()
    }

    override func tearDown() async throws { try? FileManager.default.removeItem(at: dir) }

    private func publisher() -> MacIdentityPublisher { MacIdentityPublisher(store: ids, settings: settings) }

    @discardableResult
    private func addLogin(_ host: String, username: String = "sam", totp: Bool = false, into target: (any ItemStore)? = nil) throws -> String {
        var r = EditorModel.newRecord(kind: .web, now: 1_700_000_000, random: SystemRandomSource())
        let id = try XCTUnwrap(r["id"]?.stringValue)
        r["label"] = .string(host); r["username"] = .string(username); r["password"] = .string("pw")
        r["scope"] = .object(["origin": .string("https://\(host)"),
                              "urls": .array([.object(["url": .string("https://\(host)"), "match": .string("base_domain")])])])
        if totp { r["totp"] = .object(["secret": .string("JBSWY3DPEHPK3PXP")]) }
        let normal = try Normalise.normalForm(ns: .entry, record: .object(r))
        let s: any ItemStore = target ?? store
        var snap = try s.load()
        let wrapper = Wrapper.make(ns: .entry, record: normal)
        snap.records[id] = wrapper
        snap.meta[id] = try SyncMeta.live(wrapper, vv: ["0b6f3c1e-8a5d-4c2b-9f7e-1d2c3b4a5e6f": 1])
        try s.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        return id
    }

    private func addPasskey(rp: String) throws {
        let key = PasskeyKey.generate()
        func b64(_ b: [UInt8]) -> String {
            Data(b).base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        let payload: JSONValue = .object([
            "relying_party_id": .string(rp), "rp_name": .string(""), "user_name": .string("alice"),
            "user_handle": .string(b64([9, 9])), "credential_id": .string(b64([1, 2, 3])),
            "private_key": .string(key.pkcs8B64URL), "algorithm": .string("ES256"),
        ])
        var snap = try store.load()
        snap.records["pk1"] = Wrapper.make(ns: .item, record: .object(["id": .string("pk1"), "kind": .string("passkey"),
                                                                     "title": .string(rp), "payload": payload, "updated_at": .int(1)]))
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
    }

    private func domains(_ entries: [IdentityEntry]) -> [String] {
        entries.compactMap { if case .password(let d, _, _) = $0 { d } else { nil } }
    }

    func testPublishesPasswordsAndPasskeys() async throws {
        let id = try addLogin("login.example.com")
        try addPasskey(rp: "example.com")
        await publisher().publish(snapshot: try store.load())
        let published = ids.published
        XCTAssertTrue(published.contains(.password(domain: "login.example.com", username: "sam", recordID: id)))
        XCTAssertTrue(published.contains { if case .passkey(let rp, "alice", _, _, "pk1") = $0 { rp == "example.com" } else { false } })
        XCTAssertFalse(published.contains { if case .oneTimeCode = $0 { true } else { false } }, "no TOTP, no code identity")
    }

    func testRemovedWhenSettingOff() async throws {
        try addLogin("example.com")
        let p = publisher()
        await p.publish(snapshot: try store.load())
        XCTAssertFalse(ids.published.isEmpty)
        settings.showInQuickType = false
        await p.publish(snapshot: try store.load())
        XCTAssertTrue(ids.published.isEmpty)
        XCTAssertEqual(ids.calls.last, "removeAll")
        // Erase pending and AutoFill turned off for the app follow the iPhone rules too.
        settings.showInQuickType = true; settings.erasePending = true
        try addLogin("other.example")
        await p.publish(snapshot: try store.load())
        XCTAssertTrue(ids.published.isEmpty)
        settings.erasePending = false; ids.enabled = false
        let before = ids.calls.count
        await p.publish(snapshot: try store.load())
        XCTAssertEqual(ids.calls.count, before, "not enabled: nothing published")
    }

    func testIdentitiesRepublishedAfterDeleteAndRestore() async throws {
        let p = publisher()
        let wrapped = PublishingItemStore(base: store) { [store] _ in
            let snap = try? store!.load()
            MainActor.assumeIsolated { if let snap { p.enqueue(snapshot: snap) } }
        }
        let keep = try addLogin("keep.example", into: wrapped)
        let gone = try addLogin("gone.example", into: wrapped)
        await p.settled()
        XCTAssertEqual(Set(ids.published.map(\.recordID)), [keep, gone])

        let local = InMemoryLocalData()
        let trash = TrashModel(store: wrapped, local: local, isPro: { true }, onNeedsPro: { _ in }, activity: nil)
        try trash.moveToTrash(id: gone)
        await p.settled()
        XCTAssertEqual(Set(ids.published.map(\.recordID)), [keep], "a trashed login leaves AutoFill")

        trash.restore(Set(trash.rows.map(\.id)))
        await p.settled()
        XCTAssertEqual(Set(ids.published.map(\.recordID)), [keep, gone], "a restored login comes back")
    }

    func testOneTimeCodeIdentitiesForTOTPLogins() async throws {
        let withCode = try addLogin("totp.example", totp: true)
        _ = try addLogin("plain.example")
        await publisher().publish(snapshot: try store.load())
        let codes = ids.published.filter { if case .oneTimeCode = $0 { true } else { false } }
        if #available(macOS 15.0, *) {
            XCTAssertEqual(codes, [.oneTimeCode(domain: "totp.example", label: "totp.example", recordID: withCode)])
            XCTAssertNotNil(codes.first?.systemIdentity)
        } else {
            XCTAssertTrue(codes.isEmpty)
        }
    }

    func testSerialisedPublishes() async throws {
        try addLogin("one.example")
        let first = try store.load()
        try addLogin("two.example")
        let second = try store.load()
        ids.hold = .milliseconds(50)
        let p = publisher()
        p.enqueue(snapshot: first)
        p.enqueue(snapshot: second)
        await p.settled()
        XCTAssertEqual(ids.maxRunning, 1, "one update at a time")
        XCTAssertEqual(ids.calls, ["replace:1", "replace:2"], "in the order asked")
        XCTAssertEqual(domains(ids.published).sorted(), ["one.example", "two.example"])
    }
}

/// The real wiring: MacLockModel publishes at unlock and after commits through its store, never while locked.
@MainActor
final class MacLockIdentityWiringTests: XCTestCase {
    private var dir: URL!
    private var suite: String!
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-wire-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        suite = "lgk-wire-\(UUID().uuidString)"
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        UserDefaults().removePersistentDomain(forName: suite)
    }

    private func make() -> (MacLockModel, MacIdentityPublisher, RecordingIdentityStore, AppSettings) {
        let settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(), kdfParams: cheap)
        let lock = MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), startTimer: false)
        let ids = RecordingIdentityStore()
        let publisher = MacIdentityPublisher(store: ids, settings: settings)
        lock.identities = publisher
        return (lock, publisher, ids, settings)
    }

    private func addLogin(_ store: any ItemStore) throws {
        var r = EditorModel.newRecord(kind: .web, now: 1_700_000_000, random: SystemRandomSource())
        let id = try XCTUnwrap(r["id"]?.stringValue)
        r["label"] = .string("Site"); r["username"] = .string("sam"); r["password"] = .string("pw")
        r["scope"] = .object(["origin": .string("https://site.example"),
                              "urls": .array([.object(["url": .string("https://site.example"), "match": .string("base_domain")])])])
        let normal = try Normalise.normalForm(ns: .entry, record: .object(r))
        var snap = try store.load()
        snap.records[id] = Wrapper.make(ns: .entry, record: normal)
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
    }

    func testUnlockAndCommitsPublishNothingWhileLocked() async throws {
        let (lock, publisher, ids, _) = make()
        await lock.create(password: "correct horse battery", confirm: "correct horse battery", touchID: false)
        XCTAssertEqual(lock.state, .unlocked)
        await publisher.settled()
        XCTAssertEqual(ids.calls, ["replace:0"], "unlock publishes")

        try addLogin(try XCTUnwrap(lock.store))
        await publisher.settled()
        XCTAssertEqual(ids.calls, ["replace:0", "replace:1"], "a commit through the store republishes")

        lock.lock()
        lock.republishIdentities()
        lock.autoFillSettingsChanged()
        await publisher.settled()
        XCTAssertEqual(ids.calls.count, 2, "nothing while locked")

        await lock.unlock(password: "correct horse battery")
        await publisher.settled()
        XCTAssertEqual(ids.calls.last, "replace:1", "unlock publishes again")
    }

    func testSuggestionsOffWhileLockedRemovesIdentities() async throws {
        let (lock, publisher, ids, settings) = make()
        await lock.create(password: "correct horse battery", confirm: "correct horse battery", touchID: false)
        try addLogin(try XCTUnwrap(lock.store))
        await publisher.settled()
        XCTAssertFalse(ids.published.isEmpty)
        lock.lock()
        let model = MacSettingsModel(settings: settings, pro: ProModel(purchases: StoreKitPurchases(), licenseKeys: [:]), passwords: lock)
        model.onAutoFillChanged = { lock.autoFillSettingsChanged() }
        model.showInQuickType = false
        await publisher.settled()
        XCTAssertEqual(ids.calls.last, "removeAll")
        XCTAssertTrue(ids.published.isEmpty)
    }
}
