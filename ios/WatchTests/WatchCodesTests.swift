import XCTest
import LGKCore

/// In-memory stand-in for the watch Keychain.
final class MemoryWatchStore: WatchSecretStoring, @unchecked Sendable {
    var codes: [WatchCode] = []
    var removed = 0
    func load() -> [WatchCode] { codes }
    func save(_ codes: [WatchCode]) throws { self.codes = codes }
    func removeAll() { codes = []; removed += 1 }
}

/// Counts complication reloads (main actor, so the reload closure may capture it).
@MainActor final class ReloadCounter { var count = 0 }

/// UX workstream 12, run on watchOS: the TOTP vectors, and unpin / forget removing secrets.
@MainActor
final class WatchCodesTests: XCTestCase {
    let rfc: [String: String] = [
        "SHA1": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "SHA256": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
        "SHA512": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
    ]

    /// RFC 6238 Appendix B, 8 digits, period 30.
    func test_rfc6238_vectors_on_watch() {
        let table: [(Int64, String, String)] = [
            (59, "SHA1", "94287082"), (59, "SHA256", "46119246"), (59, "SHA512", "90693936"),
            (1111111109, "SHA1", "07081804"), (1234567890, "SHA256", "91819424"), (2000000000, "SHA512", "38618901"),
        ]
        for (t, alg, expected) in table {
            let c = WatchCode(id: alg, title: alg, secret: rfc[alg]!, algorithm: alg, digits: 8, period: 30)
            XCTAssertEqual(c.current(at: t)?.code, expected, "\(alg) at \(t)")
        }
    }

    var suites: [String] = []

    override func tearDown() async throws {
        for name in suites { UserDefaults().removePersistentDomain(forName: name) }
        suites = []
        try await super.tearDown()
    }

    /// A fresh defaults suite per list, so the last applied send order never leaks between tests.
    func defaults() -> UserDefaults {
        let name = "watch-tests-\(UUID().uuidString)"
        suites.append(name)
        return UserDefaults(suiteName: name)!
    }

    func message(_ m: WatchMessage, sequence: Int64? = nil) throws -> [String: Any] { try m.userInfo(sequence: sequence) }

    /// Review fix: a code update still in transit that lands after Forget on lock must not bring the codes back,
    /// and the order survives a relaunch (it is kept in defaults).
    func test_update_older_than_the_last_forget_is_ignored() throws {
        let store = MemoryWatchStore(), suite = defaults()
        let reloads = ReloadCounter()
        let list = WatchCodesList(store: store, defaults: suite, reloadComplications: { reloads.count += 1 })
        let a = WatchCode(id: "a", title: "GitHub", secret: rfc["SHA1"]!)
        list.received(try message(.replace([a]), sequence: 10))
        list.received(try message(.forget, sequence: 12))
        list.received(try message(.replace([a]), sequence: 11))   // sent before the forget, delivered after it
        XCTAssertTrue(store.codes.isEmpty)
        XCTAssertTrue(list.codes.isEmpty)
        XCTAssertEqual(reloads.count, 2, "the late update changes nothing")
        let relaunched = WatchCodesList(store: store, defaults: suite, reloadComplications: {})
        relaunched.received(try message(.replace([a]), sequence: 12))
        XCTAssertTrue(store.codes.isEmpty, "a repeat of the forget's order is ignored too")
        relaunched.received(try message(.replace([a]), sequence: 13))   // pinned again after the unlock
        XCTAssertEqual(store.codes.map(\.id), ["a"])
    }

    /// Fix round 2: after the iPhone's order went back (reinstall, new phone), its forget still clears the watch,
    /// and its next update is accepted; a corrupt stored order is repaired.
    func test_forget_with_a_lower_order_still_clears_and_recovers() throws {
        let store = MemoryWatchStore(), suite = defaults()
        let list = WatchCodesList(store: store, defaults: suite, reloadComplications: {})
        let a = WatchCode(id: "a", title: "GitHub", secret: rfc["SHA1"]!)
        list.received(try message(.replace([a]), sequence: 1_000))
        list.received(try message(.forget, sequence: 5))
        XCTAssertTrue(store.codes.isEmpty, "a forget with seq < last still clears")
        list.received(try message(.replace([a]), sequence: 6))
        XCTAssertEqual(store.codes.map(\.id), ["a"], "a replace after such a forget is accepted")
        suite.set(NSNumber(value: Int64.max), forKey: WatchCodesList.lastSequenceKey)
        list.received(try message(.replace([a]), sequence: 7))
        XCTAssertEqual(store.codes.map(\.id), ["a"])
        XCTAssertEqual((suite.object(forKey: WatchCodesList.lastSequenceKey) as? NSNumber)?.int64Value, 7)
    }

    func test_unpin_removes_the_secret_and_forget_clears_all() throws {
        let reloads = ReloadCounter()
        let store = MemoryWatchStore(), list = WatchCodesList(store: store, defaults: defaults(),
                                                         reloadComplications: { reloads.count += 1 })
        let a = WatchCode(id: "a", title: "GitHub", secret: rfc["SHA1"]!)
        let b = WatchCode(id: "b", title: "Mail", secret: rfc["SHA1"]!)
        list.received(try message(.replace([a, b])))
        XCTAssertEqual(list.codes.map(\.id), ["a", "b"])
        list.received(try message(.replace([b])))   // "a" unpinned on the iPhone
        XCTAssertEqual(store.codes.map(\.id), ["b"])
        XCTAssertFalse(store.codes.contains { $0.secret == a.secret && $0.id == "a" })
        list.received(try message(.forget))
        XCTAssertTrue(store.codes.isEmpty)
        XCTAssertTrue(list.codes.isEmpty)
        XCTAssertEqual(reloads.count, 3, "the complication is reloaded after each change, the forget included")
    }

    func test_malformed_message_changes_nothing_and_hide_drops_codes() throws {
        let reloads = ReloadCounter()
        let store = MemoryWatchStore(), list = WatchCodesList(store: store, defaults: defaults(),
                                                         reloadComplications: { reloads.count += 1 })
        list.received(try message(.replace([WatchCode(id: "a", title: "", secret: rfc["SHA1"]!)])))
        list.received(["lgk.watch.v1": Data("junk".utf8)])
        XCTAssertEqual(store.codes.count, 1)
        XCTAssertEqual(reloads.count, 1, "a malformed message reloads nothing")
        list.hide()
        XCTAssertTrue(list.codes.isEmpty, "nothing decoded stays in memory while hidden")
        list.reload()
        XCTAssertEqual(list.codes.count, 1)
    }

    /// The empty list names the iPhone's pin button as it reads since sub-plan 06.
    func testEmptyHintNamesTheIPhoneButton() {
        XCTAssertTrue(WatchText.emptyHint.contains("Show in widgets and on Apple Watch"))
        XCTAssertFalse(WatchText.emptyHint.contains("choose Show on Apple Watch"))
    }
}
