import XCTest
import LGKCore
@testable import AppSharedMac

/// The shared store code compiles and runs on macOS.
final class SmokeTests: XCTestCase {
    func testStoreRoundTripOnMac() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-mac-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let vault = InMemoryKeychainVault()
        let store = try LocalStore.bootstrap(directory: dir, vault: vault)
        store.limitHints = nil
        let note: JSONValue = .object(["ns": .string("item"),
                                       "record": .object(["id": .string("n1"), "kind": .string("note")])])
        try store.commit(StoreChange(baseRevision: 0, records: ["n1": note], meta: [:], sync: nil))

        let reopened = try LocalStore.open(directory: dir, vault: vault, limitHints: nil)
        let snap = try reopened.load()
        XCTAssertEqual(snap.records["n1"], note)
        XCTAssertEqual(snap.revision, 1)
    }

    func testPaletteResolvesOnMac() {
        for token in Palette.Token.allCases { _ = Palette.nsColor(token) }
    }

    func testAppTargetSourcesCompileIntoTests() {
        XCTAssertEqual(MacAppInfo.displayName, "LocalGateKeys")
    }
}
