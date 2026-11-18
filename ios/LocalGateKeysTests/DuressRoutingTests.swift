#if os(iOS)
import XCTest
@testable import LocalGateKeys
import AppShared

/// Sub-plan 08, Task 5c (mirrors android DuressRoutingTest): inside a duress session Settings' change-password and
/// erase take the second vault's path; outside it the real one runs. And the owner's plan never leaves in an export.
@MainActor
final class DuressRoutingTests: XCTestCase {
    var dir: URL!

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("routing-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() { try? FileManager.default.removeItem(at: dir) }

    func test_change_outside_a_duress_session_runs_the_real_change() async throws {
        var realRan = false
        let routing = DuressRouting(inDuressSession: { false }, duress: nil, throttle: nil)
        try await routing.changePassword(localKey: { XCTFail("no session key outside a duress session"); return [] },
                                         current: "a", new: "b", real: { realRan = true })
        XCTAssertTrue(realRan)
    }

    func test_change_inside_a_duress_session_never_runs_the_real_change() async {
        var realRan = false
        let routing = DuressRouting(inDuressSession: { true }, duress: nil, throttle: nil)
        var refusal: Error?
        do {
            try await routing.changePassword(localKey: { [] }, current: "a", new: "b", real: { realRan = true })
        } catch { refusal = error }
        XCTAssertFalse(realRan)
        XCTAssertEqual((refusal as? DuressError)?.code, "generic")
    }

    func test_erase_outside_a_duress_session_runs_the_real_erase() async {
        var realRan = false, locked = false
        let routing = DuressRouting(inDuressSession: { false }, duress: nil, throttle: nil)
        let done = await routing.erase(lockAndWait: { locked = true }, real: { realRan = true })
        XCTAssertTrue(done)
        XCTAssertTrue(realRan)
        XCTAssertFalse(locked)
    }

    func test_erase_inside_a_duress_session_wipes_only_the_second_vault() async throws {
        let duress = PhoneDuress(files: .under(dir), params: MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1),
                                 session: DuressSession())
        try duress.setup(realKey: Array(repeating: 7, count: 32), appPassword: "river otter lantern 42",
                         duressPassword: "copper meadow 7", hours: 1, decoySession: false, seed: { _ in })
        // Something of the real vault beside the duress files.
        let realFile = dir.appendingPathComponent("vault-real.bin")
        try Data([1, 2, 3]).write(to: realFile)
        var realRan = false, locked = false
        let routing = DuressRouting(inDuressSession: { true }, duress: duress, throttle: nil)
        let done = await routing.erase(lockAndWait: { locked = true }, real: { realRan = true })
        XCTAssertTrue(done)
        XCTAssertTrue(locked)
        XCTAssertFalse(realRan)
        XCTAssertTrue(duress.configured)
        XCTAssertTrue(FileManager.default.fileExists(atPath: realFile.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: duress.files.vault.path))
    }

    func test_heir_states_are_kept_out_of_exports() {
        XCTAssertTrue(VaultExporter.isHeirState("heir:plan"))
        XCTAssertTrue(VaultExporter.isHeirState("heir:other"))
        XCTAssertFalse(VaultExporter.isHeirState("licence:pro"))
        XCTAssertFalse(VaultExporter.isHeirState("heirloom"))
    }
}
#endif
