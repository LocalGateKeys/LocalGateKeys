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

    func message(_ m: WatchMessage) throws -> [String: Any] { try m.userInfo() }

    func test_unpin_removes_the_secret_and_forget_clears_all() throws {
        let store = MemoryWatchStore(), list = WatchCodesList(store: store)
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
    }

    func test_malformed_message_changes_nothing_and_hide_drops_codes() throws {
        let store = MemoryWatchStore(), list = WatchCodesList(store: store)
        list.received(try message(.replace([WatchCode(id: "a", title: "", secret: rfc["SHA1"]!)])))
        list.received(["lgk.watch.v1": Data("junk".utf8)])
        XCTAssertEqual(store.codes.count, 1)
        list.hide()
        XCTAssertTrue(list.codes.isEmpty, "nothing decoded stays in memory while hidden")
        list.reload()
        XCTAssertEqual(list.codes.count, 1)
    }
}
