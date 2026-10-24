import XCTest
import LGKCore
@testable import AppShared

/// A StoreKit `pro_unlimited` check the test sets, counting its calls.
final class FakeSafariEntitlement: SafariProEntitlement, @unchecked Sendable {
    private var value: Bool
    private var count = 0
    private let lock = NSLock()
    init(_ entitled: Bool) { value = entitled }
    var entitled: Bool {
        get { lock.withLock { value } }
        set { lock.withLock { value = newValue } }
    }
    var calls: Int { lock.withLock { count } }
    func isEntitled() async -> Bool { lock.withLock { count += 1; return value } }
}

final class SafariSaveServiceTests: XCTestCase {
    var root: URL!
    var filesDir: URL!
    var vaultDir: URL!
    var keychain: InMemoryKeychainVault!
    var settings: AppSettings!
    var entitlement: FakeSafariEntitlement!
    let indexKey = Array(repeating: UInt8(7), count: 32)
    let inboxKey = Array(repeating: UInt8(8), count: 32)

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-safari-save-\(UUID().uuidString)", isDirectory: true)
        filesDir = root.appendingPathComponent("SafariSave", isDirectory: true)
        vaultDir = root.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: filesDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: vaultDir, withIntermediateDirectories: true)
        keychain = InMemoryKeychainVault()
        settings = AppSettings(defaults: UserDefaults(suiteName: "safari-save-\(UUID().uuidString)")!)
        entitlement = FakeSafariEntitlement(false)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    // MARK: helpers

    func makeService() -> SafariSaveService {
        let files: URL = filesDir, vault: URL = vaultDir
        return SafariSaveService(keychain: keychain, files: { files }, vaultDirectory: { vault }, settings: settings,
                                 entitlement: entitlement, now: { 1000 }, random: FixedRandom())
    }

    func storeKeys() throws {
        try keychain.write(.safariIndexKey, indexKey)
        try keychain.write(.safariInboxKey, inboxKey)
    }

    /// Publishes an index holding one `web` login per (origin, username, password).
    func publishIndex(_ logins: [(String, String, String)]) throws {
        var records: [String: JSONValue] = [:]
        for (n, (origin, username, password)) in logins.enumerated() {
            let id = "item-\(n)"
            records[id] = Wrapper.make(ns: .entry, record: .object([
                "id": .string(id), "kind": .string("web"), "label": .string(id), "username": .string(username),
                "password": .string(password), "scope": .object(["origin": .string(origin)]), "updated_at": .int(1),
            ]))
        }
        let bytes = try SafariIndex.fingerprints(records: records, key: indexKey).encoded()
        try SafariSaveFiles.writeAtomically(bytes, to: SafariSaveFiles.indexURL(in: filesDir))
    }

    /// The free vault is full at revision 7 (hint and committed `CURRENT` agree).
    func makeVaultFull() throws {
        settings.planFullRevision = 7
        try Data("7".utf8).write(to: vaultDir.appendingPathComponent("CURRENT"))
    }

    var inbox: SafariInbox {
        SafariInbox(directory: filesDir.appendingPathComponent("inbox", isDirectory: true), key: inboxKey, now: { 1000 })
    }

    func classify(_ s: SafariSaveService, _ origin: String, _ username: String = "alex", _ password: String = "pw1") async -> [String: Any] {
        await s.handle(["action": "classify", "origin": origin, "username": username, "password": password])
    }

    func save(_ s: SafariSaveService, _ origin: String, _ username: String = "alex", _ password: String = "pw1",
              status: String = "new") async -> [String: Any] {
        await s.handle(["action": "save", "origin": origin, "username": username, "password": password, "status": status])
    }

    func assertStatus(_ reply: [String: Any], _ status: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(Set(reply.keys), ["status"], file: file, line: line)
        XCTAssertEqual(reply["status"] as? String, status, file: file, line: line)
    }

    func assertStored(_ reply: [String: Any], file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(Set(reply.keys), ["stored"], file: file, line: line)
        XCTAssertEqual(reply["stored"] as? Bool, true, file: file, line: line)
    }

    func assertRefused(_ reply: [String: Any], _ error: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(Set(reply.keys), ["stored", "error"], file: file, line: line)
        XCTAssertEqual(reply["stored"] as? Bool, false, file: file, line: line)
        XCTAssertEqual(reply["error"] as? String, error, file: file, line: line)
    }

    // MARK: tests

    func test_classify_without_keys_is_unavailable() async throws {
        try publishIndex([("https://example.com", "alex", "pw1")])
        let s = makeService()

        assertStatus(await classify(s, "https://example.com", "sam"), "unavailable")
        assertRefused(await save(s, "https://example.com", "sam"), "unavailable")

        // One key alone is not enough, and a key of the wrong length is refused.
        try keychain.write(.safariIndexKey, indexKey)
        assertStatus(await classify(s, "https://example.com", "sam"), "unavailable")
        try keychain.write(.safariInboxKey, [1, 2, 3])
        assertStatus(await classify(s, "https://example.com", "sam"), "unavailable")
        assertRefused(await save(s, "https://example.com", "sam"), "unavailable")

        XCTAssertFalse(FileManager.default.fileExists(atPath: filesDir.appendingPathComponent("inbox").path), "nothing written")
        XCTAssertEqual(entitlement.calls, 0)

        // No container: the files folder cannot be resolved.
        try storeKeys()
        let noContainer = SafariSaveService(keychain: keychain, files: { throw LocalStoreError.noContainer },
                                            vaultDirectory: { throw LocalStoreError.noContainer }, settings: settings,
                                            entitlement: entitlement, now: { 1000 }, random: FixedRandom())
        assertStatus(await classify(noContainer, "https://example.com", "sam"), "unavailable")
        assertRefused(await save(noContainer, "https://example.com", "sam"), "unavailable")
    }

    /// Audit 2026-10-24 M-3 / L-7: the answer never depends on the password.
    func test_classify_new_or_exists() async throws {
        try storeKeys()
        try publishIndex([("https://example.com", "alex", "pw1")])
        let s = makeService()

        assertStatus(await classify(s, "https://example.com", "alex", "pw1"), "exists")
        assertStatus(await classify(s, "https://example.com", "alex", "pw2"), "exists")
        assertStatus(await classify(s, "https://example.com", "sam", "pw1"), "new")
        assertStatus(await classify(s, "https://example.com", "Alex", "pw1"), "new")
        assertStatus(await classify(s, "https://other.example", "alex", "pw1"), "new")
        // The origin is canonicalised the same way as the vault's.
        assertStatus(await classify(s, "HTTPS://Example.COM:443/", "alex", "pw1"), "exists")

        // A damaged index answers nothing rather than guessing.
        try SafariSaveFiles.writeAtomically(Array("{}".utf8), to: SafariSaveFiles.indexURL(in: filesDir))
        assertStatus(await classify(s, "https://example.com", "alex", "pw1"), "unavailable")

        // No index yet (the app has not published one): everything is new.
        try FileManager.default.removeItem(at: SafariSaveFiles.indexURL(in: filesDir))
        assertStatus(await classify(s, "https://example.com", "alex", "pw1"), "new")

        // classify never writes.
        XCTAssertEqual(inbox.entries().entries, [])
    }

    func test_full_vault_new_login_is_full_unless_entitled() async throws {
        try storeKeys()
        try publishIndex([("https://example.com", "alex", "pw1")])
        try makeVaultFull()
        let s = makeService()

        assertStatus(await classify(s, "https://example.com", "sam"), "full")
        assertRefused(await save(s, "https://example.com", "sam"), "full")
        XCTAssertEqual(inbox.entries().entries, [], "a refused save writes nothing")
        XCTAssertEqual(entitlement.calls, 2)

        // Pro on this phone: saving new logins is allowed.
        entitlement.entitled = true
        assertStatus(await classify(s, "https://example.com", "sam"), "new")
        assertStored(await save(s, "https://example.com", "sam"))
        XCTAssertEqual(inbox.entries().entries.map(\.username), ["sam"])
        XCTAssertEqual(entitlement.calls, 4)

        // A stale hint (the vault moved on) is not full, and StoreKit is not asked.
        entitlement.entitled = false
        try Data("8".utf8).write(to: vaultDir.appendingPathComponent("CURRENT"))
        assertStatus(await classify(s, "https://example.com", "kim"), "new")
        XCTAssertEqual(entitlement.calls, 4)

        // No hint: not full.
        settings.planFullRevision = nil
        assertStatus(await classify(s, "https://example.com", "kim"), "new")
        XCTAssertEqual(entitlement.calls, 4)

        // A hint but no committed revision: not full.
        settings.planFullRevision = 7
        try FileManager.default.removeItem(at: vaultDir.appendingPathComponent("CURRENT"))
        assertStatus(await classify(s, "https://example.com", "kim"), "new")
        XCTAssertEqual(entitlement.calls, 4)
    }

    func test_update_allowed_when_full() async throws {
        try storeKeys()
        try publishIndex([("https://example.com", "alex", "pw1")])
        try makeVaultFull()
        let s = makeService()

        assertStatus(await classify(s, "https://example.com", "alex", "pw2"), "exists")
        assertStored(await save(s, "https://example.com/", "alex", "pw2", status: "exists"))
        let waiting = inbox.entries().entries
        XCTAssertEqual(waiting.count, 1)
        XCTAssertEqual(waiting.first?.origin, "https://example.com", "stored canonical")
        XCTAssertEqual(waiting.first?.username, "alex")
        XCTAssertEqual(waiting.first?.password, "pw2")
        XCTAssertEqual(waiting.first?.capturedAt, 1000)

        assertStatus(await classify(s, "https://example.com", "alex", "pw1"), "exists")
        XCTAssertEqual(entitlement.calls, 0, "StoreKit is asked only for new logins")
    }

    func test_save_same_login_twice_writes_one_entry() async throws {
        try storeKeys()
        try publishIndex([("https://example.com", "alex", "pw1")])
        let s = makeService()

        assertStored(await save(s, "https://example.com", "sam", "pw9"))
        assertStored(await save(s, "HTTPS://example.com:443", "sam", "pw9"))
        XCTAssertEqual(inbox.entries().entries.count, 1)

        // A login already in the vault is stored too (the extension cannot tell whether its password is
        // new); the app drops it at import when the password is unchanged. Saved twice, still one entry.
        assertStored(await save(s, "https://example.com", "alex", "pw1", status: "exists"))
        assertStored(await save(s, "https://example.com", "alex", "pw1", status: "new"))
        XCTAssertEqual(inbox.entries().entries.count, 2)
    }

    /// Audit 2026-10-24 M-3: at most `SafariProbeLimit.perOrigin` classify requests per origin a minute;
    /// other origins and saves are not affected, and the origin is free again after the window.
    func test_classify_is_rate_limited_per_origin() async throws {
        try storeKeys()
        try publishIndex([("https://example.com", "alex", "pw1")])
        let clock = InboxClock(1000)
        let files: URL = filesDir, vault: URL = vaultDir
        let s = SafariSaveService(keychain: keychain, files: { files }, vaultDirectory: { vault }, settings: settings,
                                  entitlement: entitlement, now: { clock.now }, random: FixedRandom())

        for n in 0..<SafariProbeLimit.perOrigin {
            assertStatus(await classify(s, "https://example.com", "guess\(n)"), "new")
        }
        assertStatus(await classify(s, "https://example.com", "alex"), "unavailable")
        assertStatus(await classify(s, "HTTPS://EXAMPLE.com:443", "alex"), "unavailable")   // the canonical origin is counted
        assertStatus(await classify(s, "https://other.example", "alex"), "new")
        assertStored(await save(s, "https://example.com", "alex", "pw2"))

        // The probe file names no site.
        let probes = try String(contentsOf: filesDir.appendingPathComponent("probes.json"), encoding: .utf8)
        XCTAssertFalse(probes.contains("example"))

        clock.now = 1000 + SafariProbeLimit.window
        assertStatus(await classify(s, "https://example.com", "alex"), "exists")
    }

    func test_save_rejects_http_public_origin() async throws {
        try storeKeys()
        let s = makeService()

        assertRefused(await save(s, "http://example.com"), "invalid")
        assertStatus(await classify(s, "http://example.com"), "unavailable")
        for bad in ["ftp://example.com", "https://", "example.com", "", "https://example.com/login",
                    "http://localhost.example.com", "http://10.0.0.1", "https://user@example.com"] {
            assertRefused(await save(s, bad), "invalid")
            assertStatus(await classify(s, bad), "unavailable")
        }
        assertRefused(await s.handle(["action": "save", "origin": "https://example.com", "username": "alex"]), "invalid")
        assertRefused(await s.handle(["action": "save", "origin": "https://example.com", "password": "pw1"]), "invalid")
        assertRefused(await save(s, "https://example.com", "", "pw1"), "invalid")
        assertRefused(await save(s, "https://example.com", "alex", ""), "invalid")
        assertRefused(await s.handle(["action": "save", "origin": 42, "username": "alex", "password": "pw1"]), "invalid")
        XCTAssertEqual(inbox.entries().entries, [])

        // Loopback test pages are allowed over http.
        assertStored(await save(s, "http://localhost:8080"))
        assertStored(await save(s, "http://127.0.0.1"))
        XCTAssertEqual(Set(inbox.entries().entries.map(\.origin)), ["http://localhost:8080", "http://127.0.0.1"])
    }

    func test_erase_pending_is_unavailable() async throws {
        try storeKeys()
        try publishIndex([("https://example.com", "alex", "pw1")])
        settings.erasePending = true
        let s = makeService()

        assertStatus(await classify(s, "https://example.com", "sam"), "unavailable")
        assertStatus(await classify(s, "https://example.com", "alex", "pw1"), "unavailable")
        assertRefused(await save(s, "https://example.com", "sam"), "unavailable")
        XCTAssertFalse(FileManager.default.fileExists(atPath: filesDir.appendingPathComponent("inbox").path))
        XCTAssertEqual(keychain.reads, [], "no key is read while an erase is pending")
    }

    func test_inbox_full_maps_to_inbox_full() async throws {
        try storeKeys()
        for n in 0..<SafariInbox.capacity {
            try inbox.add(origin: "https://example.com", username: "user\(n)", password: "pw")
        }
        let s = makeService()

        assertStatus(await classify(s, "https://example.com", "one-more"), "new")
        assertRefused(await save(s, "https://example.com", "one-more"), "inbox_full")
        XCTAssertEqual(inbox.entries().entries.count, SafariInbox.capacity)
    }

    func test_unknown_action_is_unsupported() async throws {
        try storeKeys()
        let s = makeService()
        for request: [String: Any] in [["action": "fill", "origin": "https://example.com"], [:], ["action": 1]] {
            let reply = await s.handle(request)
            XCTAssertEqual(Set(reply.keys), ["error"])
            XCTAssertEqual(reply["error"] as? String, "unsupported")
        }
    }

    // MARK: same_site

    func sameSiteService(rules: PublicSuffixRules? = PublicSuffixRules.parse(lines: ["com", "uk", "co.uk", "github.io"])) -> SafariSaveService {
        let files: URL = filesDir, vault: URL = vaultDir
        return SafariSaveService(keychain: keychain, files: { files }, vaultDirectory: { vault }, settings: settings,
                                 entitlement: entitlement, now: { 1000 }, random: FixedRandom(),
                                 matcher: URLMatcher(rules: rules))
    }

    func test_same_site_accepts_another_subdomain_of_the_registrable_domain() async {
        let service = sameSiteService()
        XCTAssertTrue(service.sameSite("https://vendors.paddle.com", "https://login.paddle.com"))
        XCTAssertTrue(service.sameSite("https://paddle.com", "https://login.paddle.com"))
        XCTAssertTrue(service.sameSite("https://www.shop.co.uk", "https://login.shop.co.uk"))
        let reply = await service.handle(["action": "same_site", "origin": "https://vendors.paddle.com",
                                          "other": "https://login.paddle.com"])
        XCTAssertEqual(reply["same"] as? Bool, true)
    }

    func test_same_site_refuses_other_sites_suffixes_and_unsaveable_origins() async {
        let service = sameSiteService()
        XCTAssertFalse(service.sameSite("https://login.paddle.com", "https://login.paddle.com"), "same origin is not a handoff")
        XCTAssertFalse(service.sameSite("https://vendors.paddle.com", "https://login.paddle.net"))
        XCTAssertFalse(service.sameSite("https://evil.co.uk", "https://shop.co.uk"), "public suffix co.uk")
        XCTAssertFalse(service.sameSite("https://alice.github.io", "https://bob.github.io"), "shared hosting suffix")
        XCTAssertFalse(service.sameSite("https://vendors.paddle.com:8443", "https://login.paddle.com"), "port")
        XCTAssertFalse(service.sameSite("http://vendors.paddle.com", "https://login.paddle.com"), "plain http")
        XCTAssertFalse(service.sameSite("https://10.0.0.2", "https://10.0.0.1"))
        XCTAssertFalse(service.sameSite(nil, "https://login.paddle.com"))
        let reply = await service.handle(["action": "same_site", "origin": "https://a.example.org"])
        XCTAssertEqual(reply["same"] as? Bool, false)
    }

    func test_same_site_without_a_suffix_list_fails_closed() {
        XCTAssertFalse(sameSiteService(rules: nil).sameSite("https://vendors.paddle.com", "https://login.paddle.com"))
    }
}
