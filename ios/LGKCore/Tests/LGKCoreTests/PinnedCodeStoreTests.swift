import XCTest
@testable import LGKCore

/// An in-memory Keychain; `failStores` makes every write fail.
final class MemoryKeychain: KeychainAccess, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]
    var failStores = false

    func store(_ data: Data, key: String) throws {
        try lock.withLock {
            if failStores { throw NSError(domain: "MemoryKeychain", code: 1) }
            items[key] = data
        }
    }
    func load(key: String) -> Data? { lock.withLock { items[key] } }
    func delete(key: String) { lock.withLock { _ = items.removeValue(forKey: key) } }
    var isEmpty: Bool { lock.withLock { items.isEmpty } }
}

/// Sub-plan 06: the pinned codes in storage the widgets can read.
final class PinnedCodeStoreTests: XCTestCase {
    /// RFC 6238 SHA1 seed "12345678901234567890" in Base32 (6 digits at t = 59: 287082).
    let rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    var suites: [String] = []

    override func tearDown() {
        for s in suites { UserDefaults().removePersistentDomain(forName: s) }
        suites = []
        super.tearDown()
    }

    func defaults() -> UserDefaults {
        let name = "pinned-\(UUID().uuidString)"
        suites.append(name)
        return UserDefaults(suiteName: name)!
    }

    func code(_ id: String) -> WatchCode { WatchCode(id: id, title: id.uppercased(), secret: rfcSecret) }

    func make() -> (PinnedCodeStore, MemoryKeychain) {
        let k = MemoryKeychain()
        return (PinnedCodeStore(defaults: defaults(), keychain: k), k)
    }

    func test_replace_then_codes_in_pin_order() {
        let (s, _) = make()
        s.pinnedIDs = ["b", "a"]
        s.replace([code("a"), code("b"), code("c")])
        let shown = s.codes(at: Date(timeIntervalSince1970: 59))
        XCTAssertEqual(shown.map { $0.0.id }, ["b", "a"], "pin order; the unpinned c is not stored")
        XCTAssertEqual(shown.map { $0.code }, ["287082", "287082"])
        XCTAssertEqual(shown.first?.secondsRemaining, 1)
    }

    func test_forget_secrets_keeps_pins_and_shows_nothing() {
        let (s, k) = make()
        s.pinnedIDs = ["a", "b"]
        s.replace([code("a"), code("b")])
        s.forgetSecrets()
        XCTAssertEqual(s.pinnedIDs, ["a", "b"])
        XCTAssertTrue(s.codes(at: Date(timeIntervalSince1970: 59)).isEmpty)
        XCTAssertTrue(k.isEmpty, "no secret is left in the Keychain")
    }

    func test_at_most_four_codes_are_stored_and_shown() throws {
        let (s, k) = make()
        let ids = ["a", "b", "c", "d", "e", "f"]
        s.pinnedIDs = ids
        s.replace(ids.map { code($0) })
        XCTAssertEqual(s.codes(at: Date(timeIntervalSince1970: 59)).map { $0.0.id }, ["a", "b", "c", "d"])
        let data = try XCTUnwrap(k.load(key: PinnedCodeStore.secretsKey))
        guard case .replace(let stored) = try WatchMessage.decode(data) else { return XCTFail() }
        XCTAssertEqual(stored.map(\.id), ["a", "b", "c", "d"], "only the shown codes' secrets are kept")
    }

    func test_unpinned_code_is_not_shown_and_last_unpin_leaves_no_secret() {
        let (s, k) = make()
        s.pinnedIDs = ["a", "b"]
        s.replace([code("a"), code("b")])
        s.pinnedIDs = ["b"]
        XCTAssertEqual(s.codes(at: Date(timeIntervalSince1970: 59)).map { $0.0.id }, ["b"], "never a stale code")
        s.pinnedIDs = []
        s.replace([])
        XCTAssertTrue(s.codes(at: Date(timeIntervalSince1970: 59)).isEmpty)
        XCTAssertTrue(k.isEmpty)
    }

    func test_keychain_failure_leaves_no_old_secret() {
        let (s, k) = make()
        s.pinnedIDs = ["a"]
        s.replace([code("a")])
        k.failStores = true
        s.replace([code("a")])
        XCTAssertTrue(k.isEmpty)
        XCTAssertTrue(s.codes(at: Date(timeIntervalSince1970: 59)).isEmpty)
    }

    func test_remove_all() {
        let (s, k) = make()
        s.pinnedIDs = ["a"]
        s.replace([code("a")])
        s.removeAll()
        XCTAssertEqual(s.pinnedIDs, [])
        XCTAssertTrue(k.isEmpty)
    }

    func test_pins_are_cleaned() {
        let (s, _) = make()
        s.pinnedIDs = ["a", "", "a", "b"] + (0..<20).map { "x\($0)" }
        XCTAssertEqual(Array(s.pinnedIDs.prefix(2)), ["a", "b"])
        XCTAssertEqual(s.pinnedIDs.count, WatchMessage.maxPins)
    }

    func test_invalid_dates_and_secrets_show_nothing() {
        let (s, _) = make()
        s.pinnedIDs = ["a", "bad"]
        s.replace([code("a"), WatchCode(id: "bad", title: "Bad", secret: "!!!")])
        XCTAssertEqual(s.codes(at: Date(timeIntervalSince1970: 59)).map { $0.0.id }, ["a"])
        XCTAssertTrue(s.codes(at: Date(timeIntervalSince1970: -1)).isEmpty)
        XCTAssertTrue(s.codes(at: Date(timeIntervalSince1970: 1e16)).isEmpty)
    }

    func test_expiry_hides_every_code_from_then_on() {
        let (s, _) = make()
        s.pinnedIDs = ["a"]
        s.replace([code("a")])
        s.expiresAt = Date(timeIntervalSince1970: 100)
        XCTAssertEqual(s.codes(at: Date(timeIntervalSince1970: 99)).count, 1)
        XCTAssertTrue(s.codes(at: Date(timeIntervalSince1970: 100)).isEmpty, "the vault counts as locked")
        XCTAssertTrue(s.codes(at: Date(timeIntervalSince1970: 5000)).isEmpty)
        s.expiresAt = nil
        XCTAssertEqual(s.codes(at: Date(timeIntervalSince1970: 5000)).count, 1)
        s.expiresAt = Date(timeIntervalSince1970: 0)
        s.removeAll()
        XCTAssertNil(s.expiresAt)
    }

    func test_no_keychain_stores_and_shows_nothing() {
        let s = PinnedCodeStore(defaults: defaults(), keychain: NoKeychainAccess())
        s.pinnedIDs = ["a"]
        s.replace([code("a")])
        XCTAssertEqual(s.pinnedIDs, ["a"])
        XCTAssertTrue(s.codes(at: Date(timeIntervalSince1970: 59)).isEmpty)
    }

    func test_migrate_legacy_moves_ids_once_and_removes_the_key() {
        let legacy = defaults()
        legacy.set(["a", "b"], forKey: PinnedCodeStore.legacyPinsKey)
        let (s, _) = make()
        s.migrateLegacy(from: legacy)
        XCTAssertEqual(s.pinnedIDs, ["a", "b"])
        XCTAssertNil(legacy.object(forKey: PinnedCodeStore.legacyPinsKey))
        s.pinnedIDs = ["c"]
        s.migrateLegacy(from: legacy)
        XCTAssertEqual(s.pinnedIDs, ["c"], "runs once: nothing left to move")
    }

    func test_migrate_legacy_keeps_existing_pins() {
        let legacy = defaults()
        legacy.set(["a"], forKey: PinnedCodeStore.legacyPinsKey)
        let (s, _) = make()
        s.pinnedIDs = ["z"]
        s.migrateLegacy(from: legacy)
        XCTAssertEqual(s.pinnedIDs, ["z"])
        XCTAssertNil(legacy.object(forKey: PinnedCodeStore.legacyPinsKey))
    }
}
