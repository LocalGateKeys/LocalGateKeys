import XCTest
import Security
import LGKCore
@testable import AppShared

/// The "just filled" marker (`SafariFillMarker`): the iPhone's AutoFill extension writes it when it hands a password to
/// a website, and `classify` answers `filled` instead of `exists` for the sign-in that follows, so the Safari extension
/// does not ask to save a login it just filled. `classify` still never compares a password with the vault's.
final class SafariFillMarkerTests: XCTestCase {
    var root: URL!
    var filesDir: URL!
    var keychain: InMemoryKeychainVault!
    var clock: InboxClock!
    let indexKey = Array(repeating: UInt8(7), count: 32)
    let inboxKey = Array(repeating: UInt8(8), count: 32)
    let fillKey = Array(repeating: UInt8(9), count: 32)

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-safari-fill-\(UUID().uuidString)", isDirectory: true)
        filesDir = root.appendingPathComponent("SafariSave", isDirectory: true)
        try FileManager.default.createDirectory(at: filesDir, withIntermediateDirectories: true)
        keychain = InMemoryKeychainVault()
        clock = InboxClock(10_000)
        try keychain.write(.safariIndexKey, indexKey)
        try keychain.write(.safariInboxKey, inboxKey)
        try keychain.write(.safariFillKey, fillKey)
        try publishIndex([("https://example.com", "alex", "vault-pw")])
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    // MARK: helpers

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

    func service(blocked: Bool = false, entitlement: FakeSafariEntitlement = FakeSafariEntitlement(false)) -> SafariSaveService {
        let files: URL = filesDir, clock = clock!
        return SafariSaveService(keychain: keychain, files: { files }, entitlement: entitlement,
                                 now: { clock.now }, random: FixedRandom(), blocked: { blocked })
    }

    /// What AutoFill does after handing over a password (the AutoFill side's own gates are tested in AutoFillTests).
    /// `page` is the login's saved origin or the page URL; `also` a second origin (the page's, when it differs).
    @discardableResult
    func fill(_ page: String = "https://example.com/login", _ username: String = "alex", also: String? = nil,
              keychain: (any KeychainVault)? = nil) -> Bool {
        let files: URL = filesDir
        return SafariFillMarker.recordFill(origins: [page] + [also].compactMap { $0 }, username: username,
                                           keychain: keychain ?? self.keychain, directory: { files }, now: clock.now)
    }

    func status(_ s: SafariSaveService, _ origin: String = "https://example.com", _ username: String = "alex",
                password: String = "typed-pw") async -> String? {
        let reply = await s.handle(["action": "classify", "origin": origin, "username": username, "password": password])
        return reply["status"] as? String
    }

    var markerURL: URL { filesDir.appendingPathComponent(SafariFillMarker.fileName) }

    /// The marker file's `logins` array.
    func loginHashes() throws -> [String] {
        guard case .object(let o) = try CanonicalJSON.parse(Array(try Data(contentsOf: markerURL))),
              case .array(let rows)? = o["logins"] else { XCTFail("no logins array"); return [] }
        return rows.compactMap { row -> String? in if case .string(let h) = row { return h }; return nil }
    }
    var markerExists: Bool { FileManager.default.fileExists(atPath: markerURL.path) }

    // MARK: classify

    func test_a_fresh_marker_turns_exists_into_filled() async {
        XCTAssertTrue(fill())
        let s = service()
        let first = await status(s)
        XCTAssertEqual(first, "filled")
        // Another username or another origin: the marker does not apply.
        let otherUser = await status(s, "https://example.com", "sam")
        XCTAssertEqual(otherUser, "new")
        try? publishIndex([("https://example.com", "alex", "vault-pw"), ("https://other.example", "alex", "x"),
                           ("https://example.com", "kim", "y")])
        let otherUserExisting = await status(s, "https://example.com", "kim")
        XCTAssertEqual(otherUserExisting, "exists")
        let otherOrigin = await status(s, "https://other.example", "alex")
        XCTAssertEqual(otherOrigin, "exists")
        let subdomain = await status(s, "https://login.example.com", "alex")
        XCTAssertEqual(subdomain, "new")
    }

    func test_the_origin_is_canonicalised_like_the_vault() async {
        XCTAssertTrue(fill("HTTPS://Example.COM:443/sign-in?next=%2F#top"))
        let s = service()
        let answer = await status(s, "https://example.com")
        XCTAssertEqual(answer, "filled")
    }

    func test_an_unused_marker_expires_after_120_seconds_and_is_deleted() async {
        XCTAssertTrue(fill())
        clock.now += SafariFillMarker.unboundLifetime + 1
        let s = service()
        let late = await status(s)
        XCTAssertEqual(late, "exists")
        XCTAssertFalse(markerExists, "an expired marker is deleted when seen")
    }

    func test_an_unused_marker_matches_up_to_120_seconds() async {
        XCTAssertTrue(fill())
        clock.now += SafariFillMarker.unboundLifetime
        let s = service()
        let edge = await status(s)
        XCTAssertEqual(edge, "filled")
    }

    func test_a_used_marker_matches_for_20_seconds_whatever_the_password() async {
        XCTAssertTrue(fill())
        clock.now += 60
        let s = service()
        let first = await status(s, password: "pw-A")
        XCTAssertEqual(first, "filled")
        // The same submit captured again: still quiet.
        clock.now += 10
        let again = await status(s, password: "pw-A")
        XCTAssertEqual(again, "filled")
        // The answer never depends on the password (M-3): another one reads the same.
        let other = await status(s, password: "pw-B")
        XCTAssertEqual(other, "filled")
        clock.now += SafariFillMarker.graceLifetime - 10
        let edge = await status(s, password: "pw-B")
        XCTAssertEqual(edge, "filled")
        // A later sign-in (the filled password was refused, the user typed another): the normal prompt.
        clock.now += 1
        let late = await status(s, password: "pw-B")
        XCTAssertEqual(late, "exists")
        XCTAssertFalse(markerExists)
    }

    func test_the_marker_file_is_the_same_whatever_password_used_it() async throws {
        XCTAssertTrue(fill())
        _ = await status(service(), password: "pw-A")
        let a = try Data(contentsOf: markerURL)
        XCTAssertTrue(fill())
        _ = await status(service(), password: "a-completely-different-password")
        XCTAssertEqual(try Data(contentsOf: markerURL), a, "nothing made from the password is stored")
    }

    func test_a_marker_never_turns_new_full_or_unavailable_into_filled() async throws {
        // new: the username is not in the vault. The marker is not used up by it.
        XCTAssertTrue(fill("https://example.com", "sam"))
        let s = service()
        let new = await status(s, "https://example.com", "sam")
        XCTAssertEqual(new, "new")
        // full: the free vault is full and the login is new.
        try Data().write(to: SafariSaveFiles.planFullURL(in: filesDir))
        let full = await status(s, "https://example.com", "sam")
        XCTAssertEqual(full, "full")
        // unavailable: an origin the extension does not save for.
        let bad = await status(s, "http://example.com", "sam")
        XCTAssertEqual(bad, "unavailable")
        // Added to the vault meanwhile: the unbound marker still applies (nothing above bound it).
        try FileManager.default.removeItem(at: SafariSaveFiles.planFullURL(in: filesDir))
        try publishIndex([("https://example.com", "alex", "vault-pw"), ("https://example.com", "sam", "z")])
        let exists = await status(s, "https://example.com", "sam")
        XCTAssertEqual(exists, "filled")
    }

    func test_a_marker_hit_still_counts_against_the_per_origin_limit() async {
        XCTAssertTrue(fill())
        let s = service()
        for _ in 0..<SafariProbeLimit.perOrigin {
            let answer = await status(s, password: "pw-A")
            XCTAssertEqual(answer, "filled")
        }
        let over = await status(s, password: "pw-A")
        XCTAssertEqual(over, "unavailable", "a filled login does not get past the limit")
    }

    func test_without_the_fill_key_nothing_changes() async throws {
        try keychain.delete(.safariFillKey)
        XCTAssertFalse(fill(), "AutoFill writes no marker without the key")
        XCTAssertFalse(markerExists)
        // A marker written under a key the Safari side does not have.
        try keychain.write(.safariFillKey, fillKey)
        XCTAssertTrue(fill())
        try keychain.delete(.safariFillKey)
        let s = service()
        let missing = await status(s)
        XCTAssertEqual(missing, "exists")
        try keychain.write(.safariFillKey, [1, 2, 3])
        let short = await status(s)
        XCTAssertEqual(short, "exists")
        // Another key on the Safari side (the app recreated it): no match either.
        try keychain.write(.safariFillKey, Array(repeating: UInt8(3), count: 32))
        let rotated = await status(s)
        XCTAssertEqual(rotated, "exists")
    }

    func test_duress_and_erase_pending_ignore_the_marker() async throws {
        XCTAssertTrue(fill())
        let held = service(blocked: true)
        let blocked = await status(held)
        XCTAssertEqual(blocked, "new", "as for an empty index (review I2)")
        try Data().write(to: SafariSaveFiles.erasePendingURL(beside: filesDir))
        let erasing = await status(service())
        XCTAssertEqual(erasing, "unavailable")
        try FileManager.default.removeItem(at: SafariSaveFiles.erasePendingURL(beside: filesDir))
        // Neither one used the marker up.
        let after = await status(service())
        XCTAssertEqual(after, "filled")
    }

    func test_save_ignores_the_marker() async throws {
        XCTAssertTrue(fill())
        let before = try Data(contentsOf: markerURL)
        let s = service()
        let error = await s.save(origin: "https://example.com", username: "alex", password: "pw-A")
        XCTAssertNil(error, "stored as always")
        XCTAssertEqual(try Data(contentsOf: markerURL), before, "save neither binds nor removes the marker")
        let reply = await s.handle(["action": "save", "origin": "https://example.com", "username": "alex",
                                    "password": "pw-A", "status": "filled"])
        XCTAssertEqual(reply["stored"] as? Bool, true)
        XCTAssertEqual(try Data(contentsOf: markerURL), before)
    }

    func test_the_reply_is_plist_compatible_and_filled_is_a_status() async {
        XCTAssertEqual(SafariSaveService.Status(rawValue: "filled"), .filled)
        XCTAssertTrue(fill())
        let reply = await service().handle(["action": "classify", "origin": "https://example.com",
                                            "username": "alex", "password": "pw-A"])
        XCTAssertEqual(reply["status"] as? String, "filled")
        for (key, value) in reply { XCTAssertTrue(value is String || value is Bool, key) }
    }

    // MARK: the file

    func test_the_file_never_holds_the_origin_username_or_password() async throws {
        XCTAssertTrue(fill("https://secret-site.example/login", "alex.secret@example.org"))
        try publishIndex([("https://secret-site.example", "alex.secret@example.org", "vault-pw")])
        let s = service()
        let answer = await status(s, "https://secret-site.example", "alex.secret@example.org", password: "hunter2-password")
        XCTAssertEqual(answer, "filled")
        let bytes = try Data(contentsOf: markerURL)
        let text = String(decoding: bytes, as: UTF8.self)
        for secret in ["secret-site", "example", "alex", "hunter2", "vault-pw"] {
            XCTAssertFalse(text.contains(secret), secret)
            XCTAssertNil(bytes.range(of: Data(secret.utf8)), secret)
        }
        XCTAssertLessThan(bytes.count, 256, "one small marker")
    }

    func test_only_the_latest_marker_is_kept() async {
        XCTAssertTrue(fill("https://example.com", "alex"))
        try? publishIndex([("https://example.com", "alex", "vault-pw"), ("https://example.com", "kim", "y")])
        clock.now += 5
        XCTAssertTrue(fill("https://example.com", "kim"))
        let s = service()
        let alex = await status(s, "https://example.com", "alex")
        XCTAssertEqual(alex, "exists")
        let kim = await status(s, "https://example.com", "kim")
        XCTAssertEqual(kim, "filled")
    }

    func test_a_damaged_marker_is_ignored_and_removed() async throws {
        try SafariSaveFiles.writeAtomically(Array("not json".utf8), to: markerURL)
        let s = service()
        let answer = await status(s)
        XCTAssertEqual(answer, "exists")
        XCTAssertFalse(markerExists)
    }

    func test_a_marker_from_the_future_is_ignored_and_removed() async {
        XCTAssertTrue(fill())
        clock.now -= 60   // the clock went back
        let s = service()
        let answer = await status(s)
        XCTAssertEqual(answer, "exists")
        XCTAssertFalse(markerExists)
    }

    // MARK: two origins (the login's saved origin and the page's)

    func test_a_marker_for_two_origins_matches_either() async throws {
        try publishIndex([("https://example.com", "alex", "vault-pw"), ("https://login.example.com", "alex", "x")])
        XCTAssertTrue(fill("https://example.com", "alex", also: "https://login.example.com/signin"))
        let s = service()
        let page = await status(s, "https://login.example.com")
        XCTAssertEqual(page, "filled")
        // A fresh marker, matched through the other origin.
        XCTAssertTrue(fill("https://example.com", "alex", also: "https://login.example.com/signin"))
        let saved = await status(s, "https://example.com")
        XCTAssertEqual(saved, "filled")
        // Another site still does not match.
        try publishIndex([("https://example.com", "alex", "vault-pw"), ("https://other.example", "alex", "x")])
        XCTAssertTrue(fill("https://example.com", "alex", also: "https://login.example.com/signin"))
        let other = await status(s, "https://other.example")
        XCTAssertEqual(other, "exists")
    }

    /// Use is per marker: once one origin has matched, only that origin and username match.
    func test_a_bound_marker_with_two_origins_keeps_only_the_bound_one() async throws {
        try publishIndex([("https://example.com", "alex", "vault-pw"), ("https://login.example.com", "alex", "x")])
        XCTAssertTrue(fill("https://example.com", "alex", also: "https://login.example.com"))
        let s = service()
        let first = await status(s, "https://login.example.com", password: "pw-A")
        XCTAssertEqual(first, "filled")
        let again = await status(s, "https://login.example.com", password: "pw-A")
        XCTAssertEqual(again, "filled")
        let otherOrigin = await status(s, "https://example.com", password: "pw-A")
        XCTAssertEqual(otherOrigin, "exists", "the other origin no longer matches once used")
        let otherPassword = await status(s, "https://login.example.com", password: "pw-B")
        XCTAssertEqual(otherPassword, "filled", "the password never matters")
        clock.now += SafariFillMarker.graceLifetime + 1
        let late = await status(s, "https://login.example.com", password: "pw-A")
        XCTAssertEqual(late, "exists")
        XCTAssertFalse(markerExists)
    }

    func test_two_origins_file_holds_two_sorted_hashes_and_no_clear_text() async throws {
        XCTAssertTrue(fill("https://secret-site.example", "alex.secret@example.org", also: "https://login.secret-site.example/x"))
        let hashes = try loginHashes()
        XCTAssertEqual(hashes.count, 2)
        XCTAssertEqual(hashes, hashes.sorted())
        // The same origin twice (saved origin equals the page's): one hash.
        XCTAssertTrue(fill("https://example.com", "alex", also: "HTTPS://EXAMPLE.com:443/login"))
        XCTAssertEqual(try loginHashes().count, 1)
        try publishIndex([("https://secret-site.example", "alex.secret@example.org", "vault-pw")])
        XCTAssertTrue(fill("https://secret-site.example", "alex.secret@example.org", also: "https://login.secret-site.example/x"))
        let answer = await status(service(), "https://secret-site.example", "alex.secret@example.org", password: "hunter2-password")
        XCTAssertEqual(answer, "filled")
        let bytes = try Data(contentsOf: markerURL)
        for secret in ["secret-site", "example", "alex", "hunter2", "vault-pw", "login."] {
            XCTAssertNil(bytes.range(of: Data(secret.utf8)), secret)
        }
    }

    func test_usable_origins_drop_unusable_and_duplicate_ones() {
        XCTAssertEqual(SafariFillMarker.usableOrigins(["http://example.com", "https://Example.com/a", "https://example.com:443",
                                                       "https://b.example", "https://c.example"]),
                       ["https://example.com", "https://b.example"])
        XCTAssertEqual(SafariFillMarker.usableOrigins([]), [])
        XCTAssertFalse(fill("http://example.com", "alex", also: "ftp://example.com"))
        XCTAssertFalse(markerExists)
    }

    func test_an_earlier_format_marker_is_deleted() async throws {
        let old: JSONValue = .object(["version": .int(1), "at": .int(clock.now), "login": .string("AAAA")])
        try SafariSaveFiles.writeAtomically(try CanonicalJSON.encode(old, dialect: .utf8), to: markerURL)
        let answer = await status(service())
        XCTAssertEqual(answer, "exists")
        XCTAssertFalse(markerExists)
    }

    /// The phishing-verdict call sends only an origin: it never matches or binds a marker.
    func test_classify_with_only_an_origin_never_uses_the_marker() async throws {
        XCTAssertTrue(fill())
        let before = try Data(contentsOf: markerURL)
        let s = service()
        let reply = await s.handle(["action": "classify", "origin": "https://example.com"])
        XCTAssertEqual(reply["status"] as? String, "unavailable")
        let partial = await s.handle(["action": "classify", "origin": "https://example.com", "username": "alex"])
        XCTAssertEqual(partial["status"] as? String, "unavailable")
        XCTAssertEqual(try Data(contentsOf: markerURL), before, "not used")
        let first = await status(s, password: "pw-A")
        XCTAssertEqual(first, "filled")
        XCTAssertNotEqual(try Data(contentsOf: markerURL), before, "used by the full request, not by the origin-only one")
    }

    // MARK: the AutoFill side's helper

    func test_record_fill_only_for_origins_the_extension_saves_for() {
        for bad in ["http://example.com/login", "ftp://example.com", "example.com", "", "https://",
                    "http://10.0.0.1/login", "javascript:alert(1)"] {
            XCTAssertFalse(fill(bad), bad)
        }
        XCTAssertFalse(markerExists)
        XCTAssertFalse(fill("https://example.com", ""), "no username: nothing to match")
        XCTAssertTrue(fill("http://localhost:8080/login"))
        XCTAssertTrue(fill("http://127.0.0.1/"))
        XCTAssertEqual(SafariFillMarker.pageOrigin("https://user:pw@Example.com:8443/a/b?c#d"), "https://example.com:8443")
        XCTAssertEqual(SafariFillMarker.pageOrigin("https://example.com:443/"), SafariSaveService.canonicalOrigin("https://example.com"))
        XCTAssertNil(SafariFillMarker.pageOrigin("http://example.com/"))
    }

    func test_record_fill_writes_nothing_while_an_erase_is_pending_or_without_the_folder() {
        try? Data().write(to: SafariSaveFiles.erasePendingURL(beside: filesDir))
        XCTAssertFalse(fill())
        XCTAssertFalse(markerExists)
        XCTAssertFalse(SafariFillMarker.recordFill(origins: ["https://example.com"], username: "alex", keychain: keychain,
                                                   directory: { throw LocalStoreError.noContainer }, now: 1))
    }

    func test_record_fill_swallows_keychain_errors() {
        final class Failing: KeychainVault, @unchecked Sendable {
            func read(_ slot: VaultSlot) throws -> [UInt8]? { throw KeychainVaultError.status(errSecInteractionNotAllowed) }
            func write(_ slot: VaultSlot, _ bytes: [UInt8]) throws {}
            func delete(_ slot: VaultSlot) throws {}
        }
        XCTAssertFalse(fill(keychain: Failing()))
        XCTAssertFalse(markerExists)
    }

    // MARK: the key

    func test_the_fill_key_needs_no_face_id_and_is_not_app_only() {
        XCTAssertEqual(VaultSlot.safariFillKey.rawValue, "safari-fill-key")
        XCTAssertEqual(VaultSlot.safariFillKey.accessFlags, [])
        XCTAssertFalse(VaultSlot.appOnly.contains(.safariFillKey))
        XCTAssertFalse(VaultSlot.deviceUnlocked.contains(.safariFillKey), "not moved out of the shared group")
        XCTAssertEqual(VaultSlot.fillMarker, [.safariFillKey])
        XCTAssertFalse(AppPasswordKeychainMigration.slots.contains(.safariFillKey))
    }

    /// The app keeps one key in two places: the shared group (AutoFill) and the Safari group (the Safari extension).
    func test_the_app_keeps_the_same_fill_key_in_both_groups() throws {
        let base = InMemoryKeychainVault(), safari = InMemoryKeychainVault(), legacy = InMemoryKeychainVault()
        let v = SafariKeychainVault(base: base, safari: safari, legacy: legacy)
        try SafariKeys.ensure(keychain: v)
        let key = try XCTUnwrap(try safari.read(.safariFillKey))
        XCTAssertEqual(key.count, SafariKeys.length)
        XCTAssertEqual(try base.read(.safariFillKey), key, "AutoFill reads the same key from the shared group")
        XCTAssertNil(try legacy.read(.safariFillKey))
        // Kept on the next unlock.
        try SafariKeys.ensure(keychain: v)
        XCTAssertEqual(try safari.read(.safariFillKey), key)
        XCTAssertEqual(try base.read(.safariFillKey), key)
        // One copy missing or different: both replaced by a new key.
        try base.delete(.safariFillKey)
        XCTAssertNil(try v.read(.safariFillKey))
        try SafariKeys.ensure(keychain: v)
        let renewed = try XCTUnwrap(try base.read(.safariFillKey))
        XCTAssertEqual(try safari.read(.safariFillKey), renewed)
        try safari.write(.safariFillKey, Array(repeating: 1, count: 32))
        try SafariKeys.ensure(keychain: v)
        XCTAssertEqual(try safari.read(.safariFillKey), try base.read(.safariFillKey))
        // Deleted from both (erase goes through each group too).
        try v.delete(.safariFillKey)
        XCTAssertNil(try base.read(.safariFillKey))
        XCTAssertNil(try safari.read(.safariFillKey))
        // The other two Safari keys are untouched by all this.
        XCTAssertEqual(try safari.read(.safariIndexKey)?.count, 32)
        XCTAssertNil(try base.read(.safariIndexKey))
    }
}
