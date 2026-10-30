import XCTest
import AuthenticationServices
import UIKit
import LocalAuthentication
import Security
import AppShared

// MARK: fakes

@MainActor
final class FakeAuth: AutoFillAuthenticating {
    var vault: any KeychainVault
    var fail: Error?
    /// Runs while the Face ID prompt would be up (e.g. the app starting an erase).
    var onAuthenticate: (() -> Void)?
    private(set) var calls = 0
    private(set) var reasons: [String] = []
    init(vault: any KeychainVault, fail: Error? = nil) { self.vault = vault; self.fail = fail }
    func authenticate(reason: String) async throws -> any KeychainVault {
        calls += 1; reasons.append(reason)
        onAuthenticate?()
        if let fail { throw fail }
        return vault
    }
}

final class RecordingStore: ItemStore, @unchecked Sendable {
    private(set) var snapshot: StoreSnapshot
    private(set) var loads = 0, commits = 0
    /// Called before each commit (e.g. another writer racing): may replace the snapshot.
    var beforeCommit: ((inout StoreSnapshot) -> Void)?
    init(_ s: StoreSnapshot) { snapshot = s }
    func load() throws -> StoreSnapshot { loads += 1; return snapshot }
    func commit(_ change: StoreChange) throws {
        beforeCommit?(&snapshot)
        guard change.baseRevision == snapshot.revision else {
            throw LocalStoreError.stale(expected: change.baseRevision, actual: snapshot.revision)
        }
        commits += 1
        snapshot = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: snapshot.revision + 1)
    }
}

final class FakeOpener: AutoFillStoreOpening, @unchecked Sendable {
    let store: RecordingStore
    let revision: Int64?
    private(set) var opened = 0
    init(_ store: RecordingStore, revision: Int64? = nil) { self.store = store; self.revision = revision }
    func committedRevision() -> Int64? { revision }
    func open(vault: any KeychainVault) throws -> any ItemStore { opened += 1; return store }
}

@MainActor
final class FakeClipboard: CodeCopying {
    var copied: [String] = []
    func copy(_ text: String) { copied.append(text) }
}

final class FixedClock: UnixClock, @unchecked Sendable { let now: Int64; init(_ n: Int64) { now = n } }

final class FakeIdentityStore: CredentialIdentityStoring, @unchecked Sendable {
    var enabled: Bool
    var failReplace = false
    var onReplace: (() -> Void)?
    private(set) var replaced: [[IdentityEntry]] = []
    private(set) var removedAll = 0
    init(enabled: Bool) { self.enabled = enabled }
    func isEnabled() async -> Bool { enabled }
    func replace(_ identities: [IdentityEntry]) async throws {
        if failReplace { throw LAErrorStub.cancelled }
        replaced.append(identities)
        onReplace?()
    }
    func removeAll() async throws { removedAll += 1 }
}

final class FakePasteboard: PasteboardWriting {
    var items: [[String: Any]] = []; var options: [UIPasteboard.OptionsKey: Any] = [:]; var changeCount = 0
    func setItems(_ items: [[String: Any]], options: [UIPasteboard.OptionsKey: Any]) {
        self.items = items; self.options = options; changeCount += 1
    }
}

// MARK: fixtures

enum Fixture {
    static func web(_ id: String, user: String, password: String, origin: String, urls: [(String, String)] = [],
                    updated: Int64 = 1, totp: JSONValue? = nil) -> JSONValue {
        var scope: [String: JSONValue] = ["origin": .string(origin)]
        if !urls.isEmpty { scope["urls"] = .array(urls.map { .object(["url": .string($0.0), "match": .string($0.1)]) }) }
        var r: [String: JSONValue] = ["id": .string(id), "kind": .string("web"), "label": .string("L-\(id)"),
                                      "username": .string(user), "password": .string(password), "scope": .object(scope),
                                      "updated_at": .int(updated)]
        if let totp { r["totp"] = totp }
        return Wrapper.make(ns: .entry, record: .object(r))
    }

    static let rfcTOTP: JSONValue = .object(["secret": .string("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
                                             "algorithm": .string("SHA1"), "digits": .int(8), "period": .int(30)])

    static let loginW1 = AutoFillLogin(id: "w1", title: "L-w1", username: "alice", password: "pw-alice", totp: nil)

    static func passkey(_ id: String, rp: String, user: String, credID: [UInt8], handle: [UInt8],
                        key: String, algorithm: String = "ES256") -> JSONValue {
        func b64(_ b: [UInt8]) -> String {
            Data(b).base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        let payload: JSONValue = .object([
            "relying_party_id": .string(rp), "rp_name": .string(""), "user_name": .string(user),
            "user_handle": .string(b64(handle)), "credential_id": .string(b64(credID)),
            "private_key": .string(key), "algorithm": .string(algorithm),
        ])
        return Wrapper.make(ns: .item, record: .object(["id": .string(id), "kind": .string("passkey"),
                                                        "title": .string(rp), "payload": payload, "updated_at": .int(1)]))
    }

    /// The password snapshot plus a usable passkey p1, an RS256 one p2 and one with a garbage key p3.
    static func snapshotWithPasskeys(_ key: PasskeyKey) -> StoreSnapshot {
        var s = snapshot()
        s.records["p1"] = passkey("p1", rp: "example.com", user: "alice", credID: [1, 2, 3], handle: [9, 9], key: key.pkcs8B64URL)
        s.records["p2"] = passkey("p2", rp: "rs.example", user: "carol", credID: [4], handle: [8], key: key.pkcs8B64URL, algorithm: "RS256")
        s.records["p3"] = passkey("p3", rp: "bad.example", user: "dave", credID: [5], handle: [7], key: "bm90LWEta2V5")
        return s
    }

    static func snapshot() -> StoreSnapshot {
        let deleted = SyncMeta(digest: nil, body: nil, updatedAt: 1, vv: [:], deleted: true, deletedAt: 1)
        let note = Wrapper.make(ns: .item, record: .object(["id": .string("n1"), "kind": .string("note"), "updated_at": .int(1)]))
        return StoreSnapshot(records: [
            "w1": web("w1", user: "alice", password: "pw-alice", origin: "https://example.com", updated: 5, totp: rfcTOTP),
            "w2": web("w2", user: "bob", password: "pw-bob", origin: "https://unused.example",
                      urls: [("https://shop.example.co.uk/", "base_domain"), ("https://example.com/app", "starts_with")], updated: 9),
            "w3": web("w3", user: "gone", password: "pw-gone", origin: "https://example.com"),
            "n1": note,
        ], meta: ["w3": deleted], revision: 3)
    }
}

// MARK: tests

@MainActor
final class AutoFillTests: XCTestCase {
    let matcher = AutoFillMatcher.bundled(Bundle(for: AutoFillTests.self))

    func freshSettings() -> AppSettings { AppSettings(defaults: UserDefaults(suiteName: "af-\(UUID().uuidString)")!) }
    /// "Include exact-site logins" off (the default since audit M-5): only base_domain rows publish identities.
    func exactSitesOff() -> AppSettings { let s = freshSettings(); s.quickTypeExactSites = false; return s }

    func flow(_ store: RecordingStore, auth: FakeAuth, clip: FakeClipboard = FakeClipboard(),
              settings: AppSettings? = nil) -> (CredentialFlow, FakeOpener) {
        let opener = FakeOpener(store)
        return (CredentialFlow(auth: auth, opener: opener, matcher: matcher, clipboard: clip, clock: FixedClock(59),
                               settings: settings ?? freshSettings()), opener)
    }

    func test_bundled_public_suffix_list_loads() {
        XCTAssertNotNil(matcher.matcher.rules, "public_suffix_list.dat must be bundled")
        XCTAssertEqual(try matcher.matcher.baseDomain("a.b.example.co.uk"), "example.co.uk")
    }

    /// Review Focus #5 at the extension level: the extension's own opener reads only the Keychain local
    /// key, runs no KDF, creates nothing and never writes.
    func test_extension_store_opens_without_kdf() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-af-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let appVault = InMemoryKeychainVault()
        let app = try LocalStore.bootstrap(directory: dir, vault: appVault)
        let snap = Fixture.snapshot()
        try app.commit(StoreChange(baseRevision: 0, records: snap.records, meta: snap.meta, sync: nil))
        let before = try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted()
        let current = try Data(contentsOf: dir.appendingPathComponent("CURRENT"))

        let extVault = InMemoryKeychainVault()
        try extVault.write(.localKey, try XCTUnwrap(appVault.read(.localKey)))
        let auth = FakeAuth(vault: extVault)
        let f = CredentialFlow(auth: auth, opener: ExtensionStoreOpener(directory: { dir }), matcher: matcher,
                               clipboard: FakeClipboard(), clock: FixedClock(59))
        let start = Date()
        let found = try await f.candidates(urls: ["https://example.com/login"])
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.5, "Argon2id (128 MiB / 4 passes) would take far longer")
        XCTAssertEqual(found.map(\.id), ["w1"])
        XCTAssertEqual(extVault.reads, [.localKey])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted(), before, "extension wrote files")
        XCTAssertEqual(try Data(contentsOf: dir.appendingPathComponent("CURRENT")), current)

        // No local key (app never set up): open fails and creates none.
        let fresh = InMemoryKeychainVault()
        XCTAssertThrowsError(try ExtensionStoreOpener(directory: { dir }).open(vault: fresh))
        XCTAssertNil(try fresh.read(.localKey))
    }

    func test_no_credential_without_authentication() async {
        let store = RecordingStore(Fixture.snapshot())
        let clip = FakeClipboard()
        let (f, opener) = flow(store, auth: FakeAuth(vault: InMemoryKeychainVault(), fail: LAErrorStub.cancelled), clip: clip)
        do { _ = try await f.candidates(urls: ["https://example.com/"]); XCTFail("must throw") } catch {}
        do { _ = try await f.login(recordID: "w1"); XCTFail("must throw") } catch {}
        XCTAssertEqual(opener.opened, 0, "store opened before authentication")
        XCTAssertEqual(store.loads, 0)
        XCTAssertTrue(clip.copied.isEmpty)
    }

    func test_service_identifiers_rank_exact_origin_first() async throws {
        let store = RecordingStore(Fixture.snapshot())
        let auth = FakeAuth(vault: InMemoryKeychainVault())
        let (f, _) = flow(store, auth: auth)
        let urls = AutoFillMatcher.candidateURLs([ASCredentialServiceIdentifier(identifier: "https://example.com/app/login", type: .URL)])
        let first = try await f.candidates(urls: urls).map(\.id)
        XCTAssertEqual(first, ["w1", "w2"], "exact origin before starts_with, deleted excluded")
        let domain = AutoFillMatcher.candidateURLs([ASCredentialServiceIdentifier(identifier: "www.example.co.uk", type: .domain)])
        XCTAssertEqual(domain, ["https://www.example.co.uk/"])
        let byDomain = try await f.candidates(urls: domain).map(\.id)
        XCTAssertEqual(byDomain, ["w2"])
        let none = try await f.candidates(urls: ["https://example.org/"])
        XCTAssertEqual(none, [])
        let plainHTTP = try await f.candidates(urls: ["http://example.com/app/login", "http://www.example.co.uk/"])
        XCTAssertEqual(plainHTTP, [], "audit M-4: no HTTPS login on a plain-HTTP page")
        XCTAssertEqual(auth.calls, 1, "one Face ID prompt per extension session")
        XCTAssertEqual(store.commits, 0)
    }

    /// Audit 2026-10-24 M-4: page URLs whose origin `Origin.canonicalize` rejects are dropped before matching.
    func test_insecure_page_urls_are_dropped_before_matching() {
        XCTAssertEqual(AutoFillMatcher.secureURLs([
            "https://example.com/login", "http://example.com/login", "http://bank.example.com:8080/",
            "http://localhost:8080/", "http://127.0.0.1/", "ftp://example.com/", "not a url",
        ]), ["https://example.com/login", "http://localhost:8080/", "http://127.0.0.1/"])
        XCTAssertEqual(AutoFillMatcher.secureURLs([]), [])
    }

    func test_fill_returns_password_and_copies_totp() async throws {
        let store = RecordingStore(Fixture.snapshot())
        let clip = FakeClipboard()
        let (f, _) = flow(store, auth: FakeAuth(vault: InMemoryKeychainVault()), clip: clip)
        let login = try await f.login(recordID: "w1")
        let filled = f.fill(login)
        XCTAssertEqual(filled.user, "alice"); XCTAssertEqual(filled.password, "pw-alice")
        XCTAssertEqual(clip.copied, ["94287082"], "RFC 6238 SHA1 at T=59")
        _ = f.fill(try await f.login(recordID: "w2"))
        XCTAssertEqual(clip.copied.count, 1, "no TOTP, nothing copied")
        do { _ = try await f.login(recordID: "w3"); XCTFail("deleted item") } catch { XCTAssertEqual(error as? CredentialFlow.Failure, .notFound) }
        do { _ = try await f.login(recordID: "n1"); XCTFail("not a login") } catch { XCTAssertEqual(error as? CredentialFlow.Failure, .notFound) }
        XCTAssertEqual(store.commits, 0)
    }

    func test_totp_copy_is_local_only_with_60s_expiry() {
        let pb = FakePasteboard()
        let clip = SecretClipboard(pasteboard: pb, clock: FixedClock(1000))
        clip.copy("123456")
        XCTAssertEqual(pb.options[.localOnly] as? Bool, true)
        XCTAssertEqual(pb.options[.expirationDate] as? Date, Date(timeIntervalSince1970: 1060))
    }

    func test_identities_are_username_and_domain_only() async {
        let ids = FakeIdentityStore(enabled: true)
        let sync = IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: exactSitesOff())
        await sync.refresh(Fixture.snapshot())
        XCTAssertEqual(ids.replaced, [[
            IdentityEntry(domain: "shop.example.co.uk", username: "bob", recordID: "w2"),
            IdentityEntry(domain: "example.co.uk", username: "bob", recordID: "w2"),
        ]], "the exact_origin login and the starts_with row get no identity")
        let dump = "\(ids.replaced)"
        for secret in ["pw-alice", "pw-bob", "GEZDGNBV"] { XCTAssertFalse(dump.contains(secret)) }
    }

    func test_only_domain_shaped_rows_get_identities() {
        let sync = IdentityStoreSync(identityStore: FakeIdentityStore(enabled: true), matcher: matcher.matcher, settings: exactSitesOff())
        func d(_ url: String, _ mode: URLMatchMode) -> [String] { sync.domains(URLRow(url: url, mode: mode)) }
        // iOS matches a `.domain` identity loosely and QuickType never sees the page URL, so only
        // base_domain rows (already that loose) publish; the rest fill through the list path.
        XCTAssertEqual(d("https://example.com", .exactOrigin), [])
        XCTAssertEqual(d("https://example.com:443", .exactOrigin), [])
        XCTAssertEqual(d("https://example.com:8443", .exactOrigin), [])
        XCTAssertEqual(d("http://localhost:8080", .exactOrigin), [])
        XCTAssertEqual(d("http://localhost", .exactOrigin), [])
        XCTAssertEqual(d("https://example.com/app", .startsWith), [])
        XCTAssertEqual(d("https://login.example.com/", .host), [])
        XCTAssertEqual(d("http://login.example.com:9/", .host), [])
        XCTAssertEqual(d("https://a.example.co.uk/", .baseDomain), ["a.example.co.uk", "example.co.uk"])
        XCTAssertEqual(d("not a url", .baseDomain), [])
    }

    func test_quicktype_identities_only_for_base_domain_logins() {
        let sync = IdentityStoreSync(identityStore: FakeIdentityStore(enabled: true), matcher: matcher.matcher, settings: exactSitesOff())
        let snap = StoreSnapshot(records: [
            "e1": Fixture.web("e1", user: "exact", password: "pw-e", origin: "https://login.example.com",
                              urls: [("https://login.example.com", "exact_origin")]),
            "h1": Fixture.web("h1", user: "host", password: "pw-h", origin: "https://login.example.com",
                              urls: [("https://login.example.com/", "host")]),
            "o1": Fixture.web("o1", user: "origin-only", password: "pw-o", origin: "https://login.example.com"),
            "b1": Fixture.web("b1", user: "base", password: "pw-b", origin: "https://login.example.com",
                              urls: [("https://login.example.com/", "base_domain")]),
        ], meta: [:], revision: 1)
        XCTAssertEqual(sync.identities(snap), [
            IdentityEntry(domain: "login.example.com", username: "base", recordID: "b1"),
            IdentityEntry(domain: "example.com", username: "base", recordID: "b1"),
        ], "exact_origin and host logins publish no QuickType identity; base_domain does")
    }

    /// "Include exact-site logins" on: exact_origin and host rows publish their exact host (never the
    /// registrable domain), only for https on the default port; starts_with still publishes nothing.
    func test_exact_site_switch_publishes_exact_host_for_https_default_port_only() {
        let settings = freshSettings(); settings.quickTypeExactSites = true
        let sync = IdentityStoreSync(identityStore: FakeIdentityStore(enabled: true), matcher: matcher.matcher, settings: settings)
        func d(_ url: String, _ mode: URLMatchMode) -> [String] { sync.domains(URLRow(url: url, mode: mode)) }
        XCTAssertEqual(d("https://example.com", .exactOrigin), ["example.com"])
        XCTAssertEqual(d("https://example.com:443", .exactOrigin), ["example.com"])
        XCTAssertEqual(d("https://login.example.co.uk", .exactOrigin), ["login.example.co.uk"])
        XCTAssertEqual(d("https://example.com:8443", .exactOrigin), [])
        XCTAssertEqual(d("http://localhost:8080", .exactOrigin), [])
        XCTAssertEqual(d("http://localhost", .exactOrigin), [])
        XCTAssertEqual(d("https://login.example.com/", .host), ["login.example.com"])
        XCTAssertEqual(d("https://login.example.com/path?q=1", .host), ["login.example.com"])
        XCTAssertEqual(d("https://login.example.com:9/", .host), [])
        XCTAssertEqual(d("http://login.example.com/", .host), [])
        XCTAssertEqual(d("https://example.com/app", .startsWith), [])
        XCTAssertEqual(d("https://a.example.co.uk/", .baseDomain), ["a.example.co.uk", "example.co.uk"],
                       "base_domain rows are unchanged by the switch")
        XCTAssertEqual(d("not a url", .exactOrigin), [])
    }

    func test_exact_site_switch_widens_identities_to_exact_hosts() {
        let settings = freshSettings()
        XCTAssertFalse(settings.quickTypeExactSites, "off by default (audit 2026-10-24 M-5)")
        settings.quickTypeExactSites = true
        let sync = IdentityStoreSync(identityStore: FakeIdentityStore(enabled: true), matcher: matcher.matcher, settings: settings)
        let snap = StoreSnapshot(records: [
            "e1": Fixture.web("e1", user: "exact", password: "pw-e", origin: "https://login.example.com",
                              urls: [("https://login.example.com", "exact_origin")]),
            "e2": Fixture.web("e2", user: "port", password: "pw-p", origin: "https://login.example.com:8443",
                              urls: [("https://login.example.com:8443", "exact_origin")]),
            "h1": Fixture.web("h1", user: "host", password: "pw-h", origin: "https://login.example.com",
                              urls: [("https://login.example.com/", "host")]),
            "o1": Fixture.web("o1", user: "origin-only", password: "pw-o", origin: "https://login.example.com"),
            "s1": Fixture.web("s1", user: "prefix", password: "pw-s", origin: "https://login.example.com",
                              urls: [("https://login.example.com/app", "starts_with")]),
            "b1": Fixture.web("b1", user: "base", password: "pw-b", origin: "https://login.example.com",
                              urls: [("https://login.example.com/", "base_domain")]),
        ], meta: [:], revision: 1)
        XCTAssertEqual(sync.identities(snap), [
            IdentityEntry(domain: "login.example.com", username: "base", recordID: "b1"),
            IdentityEntry(domain: "example.com", username: "base", recordID: "b1"),
            IdentityEntry(domain: "login.example.com", username: "exact", recordID: "e1"),
            IdentityEntry(domain: "login.example.com", username: "host", recordID: "h1"),
            IdentityEntry(domain: "login.example.com", username: "origin-only", recordID: "o1"),
        ], "exact host only, never example.com; the :8443 and starts_with logins publish nothing")
    }

    func test_exact_site_switch_on_still_publishes_nothing_while_an_erase_is_pending() async {
        let ids = FakeIdentityStore(enabled: true); let settings = freshSettings()
        settings.quickTypeExactSites = true; settings.erasePending = true
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: settings).refresh(Fixture.snapshot())
        XCTAssertTrue(ids.replaced.isEmpty)
        XCTAssertEqual(ids.removedAll, 1)
    }

    func test_exact_site_switch_on_with_quicktype_off_publishes_nothing() async {
        let ids = FakeIdentityStore(enabled: true); let settings = freshSettings()
        settings.quickTypeExactSites = true; settings.showInQuickType = false
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: settings).refresh(Fixture.snapshot())
        XCTAssertTrue(ids.replaced.isEmpty)
        XCTAssertEqual(ids.removedAll, 1)
    }

    func test_failed_replace_removes_all_identities() async {
        let ids = FakeIdentityStore(enabled: true); ids.failReplace = true
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: freshSettings()).refresh(Fixture.snapshot())
        XCTAssertEqual(ids.removedAll, 1)
    }

    func test_error_mapping() {
        for c in [LAError.Code.userCancel, .systemCancel, .appCancel] {
            XCTAssertEqual(AutoFillErrorMapping.code(for: LAError(c)), .userCanceled)
        }
        XCTAssertEqual(AutoFillErrorMapping.code(for: KeychainVaultError.status(errSecUserCanceled)), .userCanceled)
        for e: Error in [LAError(.biometryLockout), LAError(.authenticationFailed), LAError(.passcodeNotSet),
                         KeychainVaultError.status(errSecAuthFailed), LocalStoreError.noLocalKey, LAErrorStub.cancelled] {
            XCTAssertEqual(AutoFillErrorMapping.code(for: e), .failed, "\(e)")
        }
    }

    func test_reset_forgets_snapshot_and_reauthenticates() async throws {
        let auth = FakeAuth(vault: InMemoryKeychainVault())
        let (f, _) = flow(RecordingStore(Fixture.snapshot()), auth: auth)
        _ = try await f.candidates(urls: ["https://example.com/"])
        f.reset()
        XCTAssertNil(f.snapshot)
        _ = try await f.candidates(urls: ["https://example.com/"])
        XCTAssertEqual(auth.calls, 2)
    }

    func test_identities_untouched_when_autofill_disabled() async {
        let ids = FakeIdentityStore(enabled: false)
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: freshSettings()).refresh(Fixture.snapshot())
        XCTAssertTrue(ids.replaced.isEmpty)
    }

    func test_empty_vault_clears_identities() async {
        let ids = FakeIdentityStore(enabled: true)
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: freshSettings()).refresh(StoreSnapshot())
        XCTAssertEqual(ids.replaced, [[]])
    }
    func test_fill_skips_the_code_copy_when_the_setting_is_off() async throws {
        let clip = FakeClipboard(); let settings = freshSettings()
        AppSettings(defaults: settings.defaults).copyCodeOnFill = false   // written by the app
        let (f, _) = flow(RecordingStore(Fixture.snapshot()), auth: FakeAuth(vault: InMemoryKeychainVault()), clip: clip,
                          settings: settings)
        let filled = f.fill(try await f.login(recordID: "w1"))
        XCTAssertEqual(filled.password, "pw-alice")
        XCTAssertTrue(clip.copied.isEmpty)
    }

    func test_refuses_to_fill_while_an_erase_is_pending() async {
        let settings = freshSettings(); settings.erasePending = true
        let auth = FakeAuth(vault: InMemoryKeychainVault())
        let (f, opener) = flow(RecordingStore(Fixture.snapshot()), auth: auth, settings: settings)
        do { _ = try await f.login(recordID: "w1"); XCTFail("must refuse") }
        catch { XCTAssertEqual(error as? CredentialFlow.Failure, .erasePending) }
        XCTAssertEqual(auth.calls, 0, "no Face ID prompt"); XCTAssertEqual(opener.opened, 0)
    }

    func test_quicktype_turned_off_during_a_replace_removes_them_again() async {
        let settings = freshSettings()
        let ids = FakeIdentityStore(enabled: true)
        ids.onReplace = { settings.showInQuickType = false }
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: settings).refresh(Fixture.snapshot())
        XCTAssertEqual(ids.replaced.count, 1)
        XCTAssertEqual(ids.removedAll, 1)
    }

    func test_quicktype_off_removes_all_identities_and_publishes_none() async {
        let ids = FakeIdentityStore(enabled: true); let settings = freshSettings()
        settings.showInQuickType = false
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: settings).refresh(Fixture.snapshot())
        XCTAssertTrue(ids.replaced.isEmpty)
        XCTAssertEqual(ids.removedAll, 1)
    }

    // MARK: passkey identities

    static let passwordEntries = [
        IdentityEntry(domain: "shop.example.co.uk", username: "bob", recordID: "w2"),
        IdentityEntry(domain: "example.co.uk", username: "bob", recordID: "w2"),
    ]

    func test_usable_passkeys_published_with_passwords() async {
        let ids = FakeIdentityStore(enabled: true); let key = PasskeyKey.generate()
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: exactSitesOff())
            .refresh(Fixture.snapshotWithPasskeys(key))
        XCTAssertEqual(ids.replaced, [Self.passwordEntries + [
            .passkey(rpID: "example.com", userName: "alice", credentialID: Data([1, 2, 3]), userHandle: Data([9, 9]), recordID: "p1"),
        ]], "one replace call holds passwords and passkeys")
        XCTAssertFalse("\(ids.replaced)".contains(key.pkcs8B64URL), "no private key in an identity")
    }

    func test_unusable_passkeys_not_published() async {
        let ids = FakeIdentityStore(enabled: true)
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: freshSettings())
            .refresh(Fixture.snapshotWithPasskeys(.generate()))
        let recordIDs = ids.replaced.flatMap { $0 }.map(\.recordID)
        XCTAssertFalse(recordIDs.contains("p2")); XCTAssertFalse(recordIDs.contains("p3"))
    }

    func test_passkeys_off_publishes_none() async {
        let ids = FakeIdentityStore(enabled: true); let settings = exactSitesOff()
        settings.offerPasskeys = false
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: settings)
            .refresh(Fixture.snapshotWithPasskeys(.generate()))
        XCTAssertEqual(ids.replaced, [Self.passwordEntries], "passwords still published")
    }

    func test_erase_pending_removes_all_identities_and_publishes_none() async {
        let ids = FakeIdentityStore(enabled: true); let settings = freshSettings()
        settings.erasePending = true
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: settings)
            .refresh(Fixture.snapshotWithPasskeys(.generate()))
        XCTAssertTrue(ids.replaced.isEmpty)
        XCTAssertEqual(ids.removedAll, 1)
    }

    func test_identity_removal_retry_after_erase_runs_and_clears() async {
        let ids = FakeIdentityStore(enabled: true); let settings = freshSettings()
        settings.identityRemovalPending = true
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: settings).refresh(StoreSnapshot())
        XCTAssertEqual(ids.removedAll, 1)
        XCTAssertFalse(settings.identityRemovalPending)
    }

    func test_identity_removal_retry_waits_while_autofill_is_off() async {
        let ids = FakeIdentityStore(enabled: false); let settings = freshSettings()
        settings.identityRemovalPending = true
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: settings).refresh(StoreSnapshot())
        XCTAssertEqual(ids.removedAll, 0)
        XCTAssertTrue(settings.identityRemovalPending)
    }

    func test_tombstoned_and_empty_rp_passkeys_not_published() async {
        let ids = FakeIdentityStore(enabled: true); let key = PasskeyKey.generate()
        var s = Fixture.snapshotWithPasskeys(key)
        s.records["p6"] = Fixture.passkey("p6", rp: "dead.example", user: "x", credID: [6], handle: [6], key: key.pkcs8B64URL)
        s.meta["p6"] = SyncMeta(digest: nil, body: nil, updatedAt: 1, vv: [:], deleted: true, deletedAt: 1)
        s.records["p7"] = Fixture.passkey("p7", rp: "", user: "y", credID: [7], handle: [7], key: key.pkcs8B64URL)
        s.records["p8"] = Fixture.passkey("p8", rp: "   ", user: "z", credID: [8], handle: [8], key: key.pkcs8B64URL)
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: freshSettings()).refresh(s)
        let recordIDs = ids.replaced.flatMap { $0 }.map(\.recordID)
        XCTAssertTrue(recordIDs.contains("p1"))
        for id in ["p6", "p7", "p8"] { XCTAssertFalse(recordIDs.contains(id), id) }
    }

    func test_quicktype_off_publishes_nothing() async {
        let ids = FakeIdentityStore(enabled: true); let settings = freshSettings()
        settings.showInQuickType = false
        await IdentityStoreSync(identityStore: ids, matcher: matcher.matcher, settings: settings)
            .refresh(Fixture.snapshotWithPasskeys(.generate()))
        XCTAssertTrue(ids.replaced.isEmpty)
        XCTAssertEqual(ids.removedAll, 1)
    }
}

enum LAErrorStub: Error { case cancelled }

/// Auth that waits until the test releases it.
@MainActor
final class GatedAuth: AutoFillAuthenticating {
    let vault = InMemoryKeychainVault()
    private var gate: CheckedContinuation<Void, Error>?
    private(set) var calls = 0
    func authenticate(reason: String) async throws -> any KeychainVault {
        calls += 1
        try await withCheckedThrowingContinuation { gate = $0 }
        return vault
    }
    func release(throwing error: Error? = nil) {
        if let error { gate?.resume(throwing: error) } else { gate?.resume() }
        gate = nil
    }
}

@MainActor
final class RecordingSink: CredentialRequestSink {
    var lists: [[AutoFillLogin]] = [], completed: [(String, String)] = [], cancels: [ASExtensionError.Code] = []
    func showList(_ logins: [AutoFillLogin]) { lists.append(logins) }
    func completeRequest(user: String, password: String) { completed.append((user, password)) }
    func cancelRequest(_ code: ASExtensionError.Code) { cancels.append(code) }
    var passkeyLists: [[PasskeyCandidate]] = [], assertions: [PasskeyAssertion] = []
    var registrations: [PasskeyRegistration] = []
    func showPasskeys(_ rows: [PasskeyCandidate]) { passkeyLists.append(rows) }
    func completePasskey(_ assertion: PasskeyAssertion) { assertions.append(assertion) }
    func completeRegistration(_ registration: PasskeyRegistration) { registrations.append(registration) }
    var textLists: [[TextInsertionField]] = [], texts: [String] = []
    func showTextFields(_ fields: [TextInsertionField]) { textLists.append(fields) }
    func completeText(_ text: String) { texts.append(text) }
}

@MainActor
final class RequestLifecycleTests: XCTestCase {
    func make() -> (CredentialRequestDriver, GatedAuth, FakeOpener, FakeClipboard, RecordingSink) {
        let auth = GatedAuth(), opener = FakeOpener(RecordingStore(Fixture.snapshot())), clip = FakeClipboard()
        let flow = CredentialFlow(auth: auth, opener: opener, matcher: .bundled(Bundle(for: RequestLifecycleTests.self)),
                                  clipboard: clip, clock: FixedClock(59))
        let d = CredentialRequestDriver(flow: flow), sink = RecordingSink()
        d.sink = sink
        return (d, auth, opener, clip, sink)
    }

    func waitForAuth(_ auth: GatedAuth) async {
        for _ in 0..<1000 where auth.calls == 0 { await Task.yield() }
        XCTAssertEqual(auth.calls, 1)
    }

    func test_cancel_during_auth_then_release_fills_nothing() async {
        for path in ["identity", "list"] {
            let (d, auth, opener, clip, sink) = make()
            if path == "identity" { d.beginIdentity(recordID: "w1") } else { d.beginList(urls: ["https://example.com/"]) }
            await waitForAuth(auth)
            d.cancel(.userCanceled)
            auth.release()
            await d.task?.value
            XCTAssertNil(d.flow.snapshot, path)
            XCTAssertEqual(opener.opened, 0, "\(path): store opened after cancel")
            XCTAssertTrue(sink.completed.isEmpty, path)
            XCTAssertTrue(sink.lists.isEmpty, path)
            XCTAssertTrue(clip.copied.isEmpty, path)
            XCTAssertEqual(sink.cancels, [.userCanceled], path)
            d.select(Fixture.loginW1)   // a late tap does nothing either
            XCTAssertTrue(sink.completed.isEmpty, path)
        }
    }

    func test_cancel_before_first_run_never_prompts() async {
        for path in ["identity", "list"] {
            let (d, auth, opener, _, sink) = make()
            if path == "identity" { d.beginIdentity(recordID: "w1") } else { d.beginList(urls: ["https://example.com/"]) }
            d.cancel(.userCanceled)          // before the task's first yield
            await d.task?.value
            XCTAssertEqual(auth.calls, 0, path)
            XCTAssertEqual(opener.opened, 0, path)
            XCTAssertEqual(sink.cancels, [.userCanceled], path)
        }
    }

    func test_missing_record_id_finishes_without_task_or_prompt() async {
        let (d, auth, _, _, sink) = make()
        d.finishImmediately(.credentialIdentityNotFound)
        XCTAssertNil(d.task)
        for _ in 0..<50 { await Task.yield() }
        XCTAssertEqual(auth.calls, 0)
        XCTAssertEqual(sink.cancels, [.credentialIdentityNotFound])
        d.cancel(.userCanceled)
        XCTAssertEqual(sink.cancels.count, 1)
    }

    func test_cancel_before_any_request_reports_once() {
        let (d, _, _, _, sink) = make()
        d.cancel(.userCanceled)
        d.cancel(.userCanceled)
        XCTAssertEqual(sink.cancels, [.userCanceled])
    }

    func test_error_after_cancel_cancels_once() async {
        let (d, auth, _, _, sink) = make()
        d.beginIdentity(recordID: "w1")
        await waitForAuth(auth)
        d.cancel(.userCanceled)
        auth.release(throwing: LAError(.authenticationFailed))
        await d.task?.value
        XCTAssertEqual(sink.cancels, [.userCanceled])
    }

    func test_identity_completes_once_and_forgets_snapshot() async {
        let (d, auth, _, clip, sink) = make()
        d.beginIdentity(recordID: "w1")
        await waitForAuth(auth)
        auth.release()
        await d.task?.value
        XCTAssertEqual(sink.completed.map(\.0), ["alice"])
        XCTAssertEqual(clip.copied, ["94287082"])
        XCTAssertNil(d.flow.snapshot)
        d.cancel(.userCanceled)
        XCTAssertTrue(sink.cancels.isEmpty, "no cancel after complete")
    }

}
