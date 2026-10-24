#if DEBUG
import XCTest
import AppShared
@testable import LocalGateKeys

@MainActor
final class DemoDataTests: XCTestCase {
    func test_seed_writes_valid_live_items_of_each_kind() throws {
        let store = MemoryStore()
        try DemoData.seed(into: store, now: 1_800_000_000)
        let items = VaultItem.items(from: store.snapshot)
        let counts = Dictionary(grouping: items, by: \.kind).mapValues(\.count)
        XCTAssertEqual(counts, ["web": 8, "card": 2, "note": 2, "identity": 2, "bank_account": 1, "subscription": 1,
                                "wifi": 1, "license": 1, "api_key": 1, "bookmark": 1])
        XCTAssertEqual(items.filter(\.hasTOTP).count, 3)
        XCTAssertGreaterThan(ItemLimit.liveCount(store.snapshot), ItemLimit.freeItems, "seeding bypasses the free limit")
        XCTAssertTrue(store.snapshot.meta.isEmpty, "nothing marked as synced")
        for (id, wrapper) in store.snapshot.records {
            guard case .object(let w) = wrapper, case .string(let ns)? = w["ns"], let record = w["record"],
                  let namespace = Namespace(rawValue: ns) else { return XCTFail("bad wrapper \(id)") }
            XCTAssertEqual(try Normalise.normalForm(ns: namespace, record: record), record, id)
        }
        let titles = Set(items.map(\.title))
        for t in ["github.com", "proton.me", "bank.example", "Visa", "Mastercard", "Wi-Fi at home", "Door code", "Passport", "Driving licence"] {
            XCTAssertTrue(titles.contains(t), t)
        }
        for item in items where item.hasTOTP {
            let secret = item.record["totp"]?.objectValue?["secret"]?.stringValue ?? ""
            XCTAssertNotNil(try TOTP.parseField(secret, defaults: TOTPConfig(secret: "")), item.title)
        }
    }

    func test_seed_twice_does_not_duplicate() throws {
        let store = MemoryStore()
        try DemoData.seed(into: store, now: 1_800_000_000)
        try DemoData.seed(into: store, now: 1_800_000_100)
        XCTAssertEqual(VaultItem.items(from: store.snapshot).count, 20)
    }
}
#endif
