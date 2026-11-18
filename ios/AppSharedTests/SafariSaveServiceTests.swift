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
        entitlement = FakeSafariEntitlement(false)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    // MARK: helpers

    func makeService() -> SafariSaveService {
        let files: URL = filesDir
        return SafariSaveService(keychain: keychain, files: { files },
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

    /// The free vault is full: the app's `plan-full` marker (audit 2026-11-10: the extension never reads the vault).
    func makeVaultFull(_ full: Bool = true) throws {
        let marker = SafariSaveFiles.planFullURL(in: filesDir)
        if full { try Data().write(to: marker) } else { try? FileManager.default.removeItem(at: marker) }
    }

    /// The app's erase-pending marker beside the `SafariSave` folder.
    func setErasePending() throws {
        try Data().write(to: SafariSaveFiles.erasePendingURL(beside: filesDir))
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

    /// Sub-plan 08 review I2: during a duress session or hold the real index is never consulted.
    func test_classify_while_blocked_answers_as_an_empty_index() async throws {
        try storeKeys()
        try publishIndex([("https://example.com", "alex", "pw1")])
        let files: URL = filesDir
        let s = SafariSaveService(keychain: keychain, files: { files },
                                  entitlement: entitlement, now: { 1000 }, random: FixedRandom(), blocked: { true })
        let known = await classify(s, "https://example.com", "alex", "pw1")
        assertStatus(known, "new")
        let other = await classify(s, "https://other.example", "sam", "pw1")
        assertStatus(other, "new")
        let stored = await s.save(origin: "https://example.com", username: "alex", password: "pw1")
        XCTAssertNil(stored)
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

        // No marker (the app's last commit left room): not full, and StoreKit is not asked.
        entitlement.entitled = false
        try makeVaultFull(false)
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
        let files: URL = filesDir
        let s = SafariSaveService(keychain: keychain, files: { files },
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
        try setErasePending()
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

    // MARK: pending_count

    func pendingCount(_ s: SafariSaveService) async -> [String: Any] { await s.handle(["action": "pending_count"]) }

    func assertCount(_ reply: [String: Any], _ count: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(reply as? [String: String], ["count": count], file: file, line: line)
    }

    func test_pending_count_counts_waiting_logins_only() async throws {
        try storeKeys()
        try publishIndex([])
        let s = makeService()
        assertCount(await pendingCount(s), "0")
        assertStored(await save(s, "https://example.com", "alex", "pw1"))
        assertStored(await save(s, "https://other.example", "sam", "pw2"))
        // The same capture again writes nothing.
        assertStored(await save(s, "https://example.com", "alex", "pw1"))
        assertCount(await pendingCount(s), "2")
        // A damaged blob is not a login waiting.
        let dir = filesDir.appendingPathComponent("inbox", isDirectory: true)
        try Data([1, 2, 3]).write(to: dir.appendingPathComponent("\(UUID().uuidString.lowercased()).blob"))
        assertCount(await pendingCount(s), "2")
        // The count never writes or classifies: the probe limit and the inbox are untouched.
        XCTAssertEqual(inbox.entries().entries.count, 2)
    }

    func test_pending_count_skips_expired_entries() async throws {
        try storeKeys()
        let old = SafariInbox(directory: filesDir.appendingPathComponent("inbox", isDirectory: true), key: inboxKey, now: { 10 })
        try old.add(origin: "https://example.com", username: "alex", password: "pw1")
        let files: URL = filesDir
        let later = SafariSaveService(keychain: keychain, files: { files }, entitlement: entitlement,
                                      now: { 10 + SafariInbox.lifetime + 1 }, random: FixedRandom())
        assertCount(await pendingCount(later), "0")
        assertCount(await pendingCount(makeService()), "1")
        XCTAssertEqual(old.entries().entries.count, 1, "nothing is deleted by a count")
    }

    func test_pending_count_keeps_the_inbox_expiry_rule_without_reading_passwords() async throws {
        try storeKeys()
        let dir = filesDir.appendingPathComponent("inbox", isDirectory: true)
        // From the future (the clock moved back): kept, like `expire()`. Added first: `add` expires older entries.
        try SafariInbox(directory: dir, key: inboxKey, now: { 10 * SafariInbox.lifetime }).add(origin: "https://c.example", username: "c", password: "pw3")
        // Exactly `lifetime` old still waits (expired is strictly older), one second more does not.
        try SafariInbox(directory: dir, key: inboxKey, now: { 100 }).add(origin: "https://a.example", username: "a", password: "pw1")
        try SafariInbox(directory: dir, key: inboxKey, now: { 99 }).add(origin: "https://b.example", username: "b", password: "pw2")
        // Sealed with the inbox key but not an inbox entry: not counted.
        let id = UUID().uuidString.lowercased()
        let junk = try SealedBlob.seal(Array(#"{"origin":"x"}"#.utf8), key: inboxKey, aad: SafariInbox.aadPrefix + id, random: FixedRandom())
        try Data(junk).write(to: dir.appendingPathComponent("\(id).blob"))

        let t = 100 + SafariInbox.lifetime
        let files: URL = filesDir
        let service = SafariSaveService(keychain: keychain, files: { files }, entitlement: entitlement, now: { t }, random: FixedRandom())
        assertCount(await pendingCount(service), "2")
        let reader = SafariInbox(directory: dir, key: inboxKey, now: { t })
        XCTAssertEqual(reader.count(now: t),
                       reader.entries().entries.filter { !SafariInbox.isExpired(capturedAt: $0.capturedAt, now: t) }.count)
    }

    func test_inbox_captured_at_reads_only_the_leading_key() {
        func parse(_ s: String) -> Int64? { SafariInbox.capturedAt(Array(s.utf8)) }
        XCTAssertEqual(parse(#"{"captured_at":1234,"origin":"https://a","password":"p","username":"u"}"#), 1234)
        XCTAssertEqual(parse(#"{"captured_at":-5,"origin":"x"#), -5)
        XCTAssertNil(parse(#"{"captured_at":,"origin":""#))
        XCTAssertNil(parse(#"{"captured_at":12"#))
        XCTAssertNil(parse(#"{"captured_at":"12","origin":""#))
        XCTAssertNil(parse(#"{"captured_at":99999999999999999999,"origin":""#))
        XCTAssertNil(parse(#"{"origin":"x","captured_at":1}"#))
        XCTAssertNil(parse(""))
    }

    func test_pending_count_is_zero_without_keys_on_erase_pending_and_when_blocked() async throws {
        try storeKeys()
        try inbox.add(origin: "https://example.com", username: "alex", password: "pw1")
        assertCount(await pendingCount(makeService()), "1")

        let files: URL = filesDir
        let blocked = SafariSaveService(keychain: keychain, files: { files }, entitlement: entitlement,
                                        now: { 1000 }, random: FixedRandom(), blocked: { true })
        assertCount(await pendingCount(blocked), "0")

        let noKeys = InMemoryKeychainVault()
        let keyless = SafariSaveService(keychain: noKeys, files: { files }, entitlement: entitlement, now: { 1000 }, random: FixedRandom())
        assertCount(await pendingCount(keyless), "0")

        let wrongKey = InMemoryKeychainVault()
        try wrongKey.write(.safariInboxKey, Array(repeating: UInt8(9), count: 32))
        assertCount(await pendingCount(SafariSaveService(keychain: wrongKey, files: { files }, entitlement: entitlement,
                                                         now: { 1000 }, random: FixedRandom())), "0")

        let missing = SafariSaveService(keychain: keychain, files: { throw CocoaError(.fileNoSuchFile) },
                                        entitlement: entitlement, now: { 1000 }, random: FixedRandom())
        assertCount(await pendingCount(missing), "0")

        try setErasePending()
        let fresh = InMemoryKeychainVault()
        try fresh.write(.safariInboxKey, inboxKey)
        let erasing = SafariSaveService(keychain: fresh, files: { files }, entitlement: entitlement, now: { 1000 }, random: FixedRandom())
        assertCount(await pendingCount(erasing), "0")
        XCTAssertEqual(fresh.reads, [], "no key is read while an erase is pending")
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
        let files: URL = filesDir
        return SafariSaveService(keychain: keychain, files: { files },
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

    // MARK: site verdict (phishing shield, sub-plan 09)

    func publishSites(_ origins: [String], key: [UInt8]? = nil) throws {
        let blob = try SafariSites.seal(origins, indexKey: key ?? indexKey, random: FixedRandom())
        try SafariSaveFiles.writeAtomically(blob, to: SafariSites.url(in: filesDir))
    }

    func siteService() -> SafariSaveService { sameSiteService(rules: PublicSuffixRules.parse(lines: ["com", "net", "org"])) }

    /// PENDING iPhone "Safari": `amazon.de` with `amazon.com` saved is the softer "Is this the same account?"
    /// (other-suffix, with a pair the extension remembers); a login saved for `login.example.com` is "related" on
    /// its own host and unknown (no badge) on the parent domain (design decision 2026-11-12).
    func test_classify_country_site_and_saved_subdomain() async throws {
        try storeKeys()
        try publishSites(["amazon.com", "login.example.com"])
        let s = sameSiteService(rules: PublicSuffixRules.parse(lines: ["com", "de"]))
        let de = await s.handle(["action": "classify", "origin": "https://amazon.de"])
        XCTAssertEqual(de["site"] as? String, "lookalike")
        XCTAssertEqual(de["site_reason"] as? String, "other-suffix")
        XCTAssertEqual(de["site_matched"] as? String, "amazon.com")
        XCTAssertEqual(de["site_pair"] as? String,
                       SafariSites.pairID(indexKey: indexKey, origin: "https://amazon.de", saved: "amazon.com"))
        let www = await s.handle(["action": "classify", "origin": "https://www.amazon.de"])
        XCTAssertEqual(www["site_reason"] as? String, "other-suffix")
        let same = await s.handle(["action": "classify", "origin": "https://login.example.com"])
        XCTAssertEqual(same["site"] as? String, "exact")
        let wwwLogin = await s.handle(["action": "classify", "origin": "https://www.login.example.com"])
        XCTAssertEqual(wwwLogin["site"] as? String, "related")
        let parent = await s.handle(["action": "classify", "origin": "https://example.com"])
        XCTAssertEqual(parent["site"] as? String, "unknown")
        XCTAssertEqual(parent["site_reason"] as? String, "same-site")
    }

    /// Carry T5b: Safari asks the app for the site check; the app answers the verdict, never the saved list.
    func test_classify_with_only_an_origin_answers_the_site_verdict() async throws {
        try storeKeys()
        try publishSites(["paypal.com", "example.com"])
        let s = siteService()
        let exact = await s.handle(["action": "classify", "origin": "https://example.com"])
        XCTAssertEqual(exact["status"] as? String, "unavailable", "no login was asked about")
        XCTAssertEqual(exact["site"] as? String, "exact")
        XCTAssertEqual(exact["site_reason"] as? String, "same-origin")
        XCTAssertNil(exact["site_matched"])
        let related = await s.handle(["action": "classify", "origin": "https://www.example.com"])
        XCTAssertEqual(related["site"] as? String, "related")
        // Design decision 2026-11-12: another host on a saved domain gets no "Related site" badge.
        let sameSite = await s.handle(["action": "classify", "origin": "https://login.example.com"])
        XCTAssertEqual(sameSite["site"] as? String, "unknown")
        XCTAssertEqual(sameSite["site_reason"] as? String, "same-site")
        let fake = await s.handle(["action": "classify", "origin": "https://paypa1.com"])
        XCTAssertEqual(fake["site"] as? String, "lookalike")
        XCTAssertEqual(fake["site_reason"] as? String, "edit-distance")
        XCTAssertEqual(fake["site_matched"] as? String, "paypal.com")
        XCTAssertNil(fake["site_pair"])
        let other = await s.handle(["action": "classify", "origin": "https://paypal.net"])
        XCTAssertEqual(other["site_reason"] as? String, "other-suffix")
        XCTAssertEqual(other["site_pair"] as? String,
                       SafariSites.pairID(indexKey: indexKey, origin: "https://paypal.net", saved: "paypal.com"))
        let mixed = await s.handle(["action": "classify", "origin": "https://xn--pple-43d.org"])
        XCTAssertEqual(mixed["site"] as? String, "lookalike")
        XCTAssertEqual(mixed["site_reason"] as? String, "mixed-script")
        XCTAssertNil(mixed["site_matched"])
        let new = await s.handle(["action": "classify", "origin": "https://unrelated.org"])
        XCTAssertEqual(new["site"] as? String, "unknown")
        // Replies are plist-safe Strings and Bools only.
        for reply in [exact, related, fake, other, mixed, new] {
            XCTAssertTrue(reply.values.allSatisfy { $0 is String || $0 is Bool })
        }
        // A login check carries the verdict too.
        let login = await classify(s, "https://paypa1.com", "alex", "pw1")
        XCTAssertEqual(login["status"] as? String, "new")
        XCTAssertEqual(login["site"] as? String, "lookalike")
    }

    func test_no_verdict_without_the_list_or_its_key() async throws {
        let s = siteService()
        try publishSites(["paypal.com"])
        var reply = await s.handle(["action": "classify", "origin": "https://paypa1.com"])
        XCTAssertNil(reply["site"], "no index key yet")
        try storeKeys()
        try publishSites(["paypal.com"], key: inboxKey)
        reply = await s.handle(["action": "classify", "origin": "https://paypa1.com"])
        XCTAssertNil(reply["site"], "sealed under another key")
        try FileManager.default.removeItem(at: SafariSites.url(in: filesDir))
        reply = await s.handle(["action": "classify", "origin": "https://paypa1.com"])
        XCTAssertNil(reply["site"], "no list published")
        try publishSites(["paypal.com"])
        try setErasePending()
        reply = await s.handle(["action": "classify", "origin": "https://paypa1.com"])
        XCTAssertNil(reply["site"], "erase pending")
    }

    /// Desktop review R1: a save on a lookalike is refused with the verdict until the guard question was answered.
    func test_save_on_a_lookalike_is_refused_until_confirmed() async throws {
        try storeKeys()
        try publishSites(["paypal.com"])
        let s = siteService()
        let request: [String: Any] = ["action": "save", "origin": "https://paypa1.com", "username": "alex",
                                      "password": "pw1", "status": "new"]
        let refused = await s.handle(request)
        XCTAssertEqual(refused["stored"] as? Bool, false)
        XCTAssertEqual(refused["error"] as? String, "lookalike_site")
        XCTAssertEqual(refused["site"] as? String, "lookalike")
        XCTAssertEqual(refused["site_matched"] as? String, "paypal.com")
        XCTAssertEqual(inbox.entries().entries.count, 0)
        // Only the string "true" confirms (the native handler keeps String values only).
        var wrong = request
        wrong["lookalike_confirmed"] = "yes"
        let stillRefused = await s.handle(wrong)
        XCTAssertEqual(stillRefused["error"] as? String, "lookalike_site")
        var confirmed = request
        confirmed["lookalike_confirmed"] = "true"
        assertStored(await s.handle(confirmed))
        XCTAssertEqual(inbox.entries().entries.count, 1)
        // The saved site itself saves at once.
        assertStored(await save(s, "https://paypal.com", "sam"))
    }
}
