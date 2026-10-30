import XCTest
import AppShared
@testable import LocalGateKeys

@MainActor
final class FakeWatchLink: WatchSending {
    var isAvailable = true
    var sent: [WatchMessage] = []
    func send(_ message: WatchMessage) { sent.append(message) }
}

/// UX workstream 12: pins, Pro, unpin and forget on the iPhone side.
@MainActor
final class WatchCodesModelTests: XCTestCase {
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    func snapshot() -> StoreSnapshot {
        func login(_ id: String) -> JSONValue {
            Wrapper.make(ns: .entry, record: .object(["id": .string(id), "kind": .string("web"), "title": .string(id),
                                                      "totp": .object(["secret": .string(secret)])]))
        }
        return StoreSnapshot(records: ["a": login("a"), "b": login("b")], meta: [:], revision: 1)
    }

    func make() -> (WatchCodesModel, FakeWatchLink, UserDefaults) {
        let d = UserDefaults(suiteName: "watch-\(UUID().uuidString)")!
        let link = FakeWatchLink()
        return (WatchCodesModel(link: link, defaults: d), link, d)
    }

    func test_pin_sends_codes_and_unpin_removes_the_secret() {
        let (m, link, d) = make()
        XCTAssertEqual(m.toggle("a", snapshot: snapshot(), isPro: true), .pinned)
        XCTAssertEqual(m.toggle("b", snapshot: snapshot(), isPro: true), .pinned)
        guard case .replace(let two)? = link.sent.last else { return XCTFail() }
        XCTAssertEqual(two.map(\.id), ["a", "b"])
        XCTAssertEqual(m.toggle("a", snapshot: snapshot(), isPro: true), .unpinned)
        guard case .replace(let one)? = link.sent.last else { return XCTFail() }
        XCTAssertEqual(one.map(\.id), ["b"])
        XCTAssertEqual(m.toggle("b", snapshot: snapshot(), isPro: true), .unpinned)
        XCTAssertEqual(link.sent.last, .forget, "the last unpin leaves nothing on the watch")
        XCTAssertEqual(d.stringArray(forKey: WatchCodesModel.pinsKey), [])
    }

    func test_free_plan_cannot_pin() {
        let (m, link, _) = make()
        XCTAssertEqual(m.toggle("a", snapshot: snapshot(), isPro: false), .needsPro)
        XCTAssertTrue(link.sent.isEmpty)
        XCTAssertTrue(m.pins.isEmpty)
    }

    func test_forget_on_lock_and_erase() {
        let (m, link, _) = make()
        m.toggle("a", snapshot: snapshot(), isPro: true)
        m.vaultLocked()
        XCTAssertEqual(link.sent.count, 1, "Forget on watch is off by default")
        m.forgetOnLock = true
        m.vaultLocked()
        XCTAssertEqual(link.sent.last, .forget)
        m.vaultErased()
        XCTAssertTrue(m.pins.isEmpty)
        XCTAssertEqual(link.sent.last, .forget)
    }
}
