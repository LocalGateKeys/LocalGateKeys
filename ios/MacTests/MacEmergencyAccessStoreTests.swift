import XCTest
import LGKCore
@testable import AppSharedMac

/// Found by MacPendingChecksUITests 2026-11-16: the Recovery centre showed no Emergency access card on the Mac, so
/// "Grant now", "Show the recovery phrase" and "Create estate pack note" could not be reached. The unlocked Mac store is
/// a `PublishingItemStore` around the `LocalStore`, and `HeirLocalState.open` only accepted a bare `LocalStore`, so
/// `EmergencyAccess.live` was nil and the card was hidden.
final class MacEmergencyAccessStoreTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-heir-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    func testEmergencyAccessOpensThroughTheMacPublishingStore() throws {
        let local = try LocalStore(directory: dir, key: Array(repeating: 7, count: 32), random: SystemRandomSource())
        let published = PublishingItemStore(base: local) { _ in }
        XCTAssertTrue(LocalStore.underlying(published) === local)
        let state = try XCTUnwrap(HeirLocalState.open(for: published), "the heir state opens through the wrapper")
        XCTAssertEqual(state.url, try XCTUnwrap(HeirLocalState.open(for: local)).url, "same file as the bare store")
        XCTAssertNotNil(EmergencyAccess.live(store: published), "the Recovery centre gets its Emergency access card")
    }

    func testOtherStoresStillGetNone() {
        final class Memory: ItemStore, @unchecked Sendable {
            func load() throws -> StoreSnapshot { StoreSnapshot() }
            func commit(_ change: StoreChange) throws {}
        }
        XCTAssertNil(HeirLocalState.open(for: Memory()))
        XCTAssertNil(HeirLocalState.open(for: PublishingItemStore(base: Memory()) { _ in }))
    }
}
