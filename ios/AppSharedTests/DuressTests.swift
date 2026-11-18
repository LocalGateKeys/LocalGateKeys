#if os(iOS)
import XCTest
import LocalAuthentication
@testable import AppShared

/// Sub-plan 08, Task 5c (mirrors android DuressTest): the duress password's second vault, the hold and the unlock
/// routing; and this vault's sealed emergency access state.
final class DuressTests: XCTestCase {
    final class NoBiometric: AppPasswordBiometricStore, @unchecked Sendable {
        func store(_ key: [UInt8]) throws {}
        func load(context: LAContext) throws -> [UInt8] { throw AppPasswordError.biometricChanged }
        func remove() throws {}
        var exists: Bool { false }
    }

    /// The wall clock, and the monotonic clock with its boot (`PhoneDuress.BootTime`).
    /// Also the app password store's boot clock, so its delay never depends on how long Argon2id took.
    final class Clock: AppPasswordBootClock, @unchecked Sendable {
        var uptime: Int64 { mono }
        var bootID: String? { boot }
        var now: Int64 = 1_000_000
        var mono: Int64 = 50_000
        var boot: String? = "boot-a"
        /// Real time passing: both clocks move.
        func advance(_ seconds: Int64) { now += seconds; mono += seconds }
        var bootTime: PhoneDuress.BootTime { PhoneDuress.BootTime(boot: boot, seconds: mono) }
    }

    let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
    let realKey = (0..<32).map { UInt8($0) }
    let appPassword = "river otter lantern 42"
    let duressPassword = "copper meadow 7"
    var dir: URL!, clock: Clock!, store: AppPasswordStore!, duress: PhoneDuress!, phrase: String!

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("duress-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        clock = Clock()
        let c = clock!
        store = AppPasswordStore(url: dir.appendingPathComponent(AppPasswordStore.fileName), biometric: NoBiometric(),
                                 defaults: UserDefaults(suiteName: "duress-\(UUID().uuidString)")!, params: cheap,
                                 now: { c.now }, bootClock: c)
        let p = try! store.prepare(localKey: realKey, password: appPassword, random: SystemRandomSource())
        try! store.write(p.file)
        phrase = p.phrase
        duress = PhoneDuress(files: .under(dir), params: cheap, session: DuressSession(), now: { c.now },
                             bootTime: { c.bootTime })
    }

    override func tearDown() { try? FileManager.default.removeItem(at: dir) }

    private func setUpDuress(hours: Int = 2) throws {
        try duress.setup(realKey: realKey, appPassword: appPassword, duressPassword: duressPassword, hours: hours,
                         decoySession: false, seed: { _ in })
    }

    private func unlock(_ password: String) async throws -> DuressOpened {
        try await DuressUnlock.open(password: password, factors: FactorSecrets(), store: store, duress: duress)
    }

    func test_one_edit_rule() {
        XCTAssertTrue(PhoneDuress.withinOneEdit("abc", "abc"))
        XCTAssertTrue(PhoneDuress.withinOneEdit("abc", "abd"))
        XCTAssertTrue(PhoneDuress.withinOneEdit("abc", "abcd"))
        XCTAssertTrue(PhoneDuress.withinOneEdit("abc", "ac"))
        XCTAssertFalse(PhoneDuress.withinOneEdit("abc", "xyz"))
    }

    func test_setup_refuses_same_close_and_hours() {
        XCTAssertThrowsError(try duress.setup(realKey: realKey, appPassword: appPassword, duressPassword: appPassword,
                                              hours: 2, decoySession: false, seed: { _ in })) {
            XCTAssertEqual(($0 as? DuressError)?.code, "same")
        }
        XCTAssertThrowsError(try duress.setup(realKey: realKey, appPassword: appPassword, duressPassword: appPassword + "x",
                                              hours: 2, decoySession: false, seed: { _ in })) {
            XCTAssertEqual(($0 as? DuressError)?.code, "close")
        }
        XCTAssertThrowsError(try duress.setup(realKey: realKey, appPassword: appPassword, duressPassword: duressPassword,
                                              hours: 0, decoySession: false, seed: { _ in })) {
            XCTAssertEqual(($0 as? DuressError)?.code, "hours")
        }
        XCTAssertFalse(duress.configured)
    }

    func test_setup_inside_a_duress_session_writes_nothing() {
        XCTAssertThrowsError(try duress.setup(realKey: realKey, appPassword: appPassword, duressPassword: duressPassword,
                                              hours: 2, decoySession: true, seed: { _ in })) {
            XCTAssertEqual(($0 as? DuressError)?.code, "generic")
        }
        XCTAssertFalse(duress.configured)
    }

    func test_without_a_second_vault_only_the_real_password_opens() async throws {
        let opened = try await unlock(appPassword)
        guard case .real(let key) = opened else { return XCTFail("expected the real vault") }
        XCTAssertEqual(key, realKey)
        var refusal: Error?
        do { _ = try await unlock(duressPassword) } catch { refusal = error }
        XCTAssertEqual(refusal as? AppPasswordError, .wrongPassword)
    }

    func test_duress_password_opens_the_second_vault_and_holds_the_real_one() async throws {
        try setUpDuress(hours: 2)
        XCTAssertEqual(duress.realHours(realKey: realKey), 2)
        let opened = try await unlock(duressPassword)
        guard case .second(let key) = opened else { return XCTFail("expected the second vault") }
        XCTAssertNotEqual(key, realKey)
        XCTAssertTrue(duress.held())
        XCTAssertTrue(duress.servicesBlocked())

        // While held the real password is refused as wrong.
        var refusal: Error?
        do { _ = try await unlock(appPassword) } catch { refusal = error }
        XCTAssertEqual(refusal as? AppPasswordError, .wrongPassword)
        XCTAssertThrowsError(try DuressUnlock.openPhrase(phrase, store: store, duress: duress)) {
            XCTAssertEqual($0 as? AppPasswordError, .wrongPhrase)
        }

        // Once the hours pass the real password opens again and the hold is gone.
        clock.advance(2 * 3600 + 1)
        let after = try await unlock(appPassword)
        guard case .real(let real) = after else { return XCTFail("expected the real vault") }
        XCTAssertEqual(real, realKey)
        XCTAssertFalse(duress.held())
    }

    /// Review I1: while held, the real password counts exactly like a wrong guess (same count, same delay).
    func test_held_real_password_grows_the_delay_like_a_wrong_one() async throws {
        try setUpDuress(hours: 2)
        _ = try await unlock(duressPassword)
        var realWaits: [Int64] = []
        for _ in 0..<6 {
            do { _ = try await unlock(appPassword) } catch {}
            realWaits.append(store.waitSeconds())
        }
        let realCount = store.failureCount
        store.clearFailures()
        var wrongWaits: [Int64] = []
        for _ in 0..<6 {
            do { _ = try await unlock("not it at all 55") } catch {}
            wrongWaits.append(store.waitSeconds())
        }
        XCTAssertEqual(realWaits, wrongWaits)
        XCTAssertEqual(store.failureCount, realCount)
        XCTAssertGreaterThan(realWaits.last ?? 0, 0)
    }

    /// Review M5: the extensions stay blocked while a second-vault session is open, even after the hold ends.
    func test_session_marker_blocks_services_after_the_hold_ends() async throws {
        try setUpDuress(hours: 1)
        _ = try await unlock(duressPassword)
        duress.openSession()
        clock.advance(2 * 3600)
        XCTAssertFalse(duress.held())
        let c = clock!
        let extensionView = PhoneDuress(files: .under(dir), params: cheap, session: DuressSession(), now: { c.now },
                                        bootTime: { c.bootTime })
        XCTAssertTrue(extensionView.servicesBlocked())
        duress.closeSession()
        XCTAssertFalse(extensionView.servicesBlocked())
    }

    /// Audit 2026-11-10: setting the date forward (the wall clock alone) does not end the hold; the monotonic clock
    /// has to count the hours too.
    func test_moving_the_date_forward_does_not_end_the_hold() async throws {
        try setUpDuress(hours: 2)
        _ = try await unlock(duressPassword)
        clock.now += 30 * 24 * 3600
        XCTAssertTrue(duress.held())
        XCTAssertEqual(duress.heldUntil(), clock.now + 2 * 3600)
        var refusal: Error?
        do { _ = try await unlock(appPassword) } catch { refusal = error }
        XCTAssertEqual(refusal as? AppPasswordError, .wrongPassword)
        XCTAssertNil(duress.release())   // still held: nothing removed

        clock.mono += 2 * 3600
        XCTAssertFalse(duress.held())
        store.clearFailures()
        let after = try await unlock(appPassword)
        guard case .real = after else { return XCTFail("expected the real vault") }
    }

    /// Setting the date back keeps the hold (the wall clock still has to pass `until`), as before.
    func test_moving_the_date_back_does_not_end_the_hold() async throws {
        try setUpDuress(hours: 2)
        _ = try await unlock(duressPassword)
        clock.mono += 2 * 3600 + 1
        clock.now -= 3600
        XCTAssertTrue(duress.held())
    }

    /// A restart sets the monotonic clock back to zero: only the time since the restart counts (never more than really
    /// passed), with or without a boot identifier.
    func test_after_a_restart_only_the_time_since_it_counts() async throws {
        try setUpDuress(hours: 2)
        _ = try await unlock(duressPassword)
        clock.boot = "boot-b"
        clock.mono = 600
        clock.now += 3 * 3600
        XCTAssertTrue(duress.held())
        clock.mono = 2 * 3600
        XCTAssertFalse(duress.held())

        XCTAssertEqual(PhoneDuress.monotonicRemaining(length: 7200, mono: 100, boot: "a",
                                                      now: PhoneDuress.BootTime(boot: "a", seconds: 3700)), 3600)
        XCTAssertEqual(PhoneDuress.monotonicRemaining(length: 7200, mono: 5000, boot: "a",
                                                      now: PhoneDuress.BootTime(boot: "b", seconds: 9000)), -1800)
        // No boot identifier: a clock below the anchor is a restart; one above it counts only from the anchor.
        XCTAssertEqual(PhoneDuress.monotonicRemaining(length: 7200, mono: 5000, boot: nil,
                                                      now: PhoneDuress.BootTime(boot: nil, seconds: 50)), 7150)
        XCTAssertEqual(PhoneDuress.monotonicRemaining(length: 7200, mono: 5000, boot: "a",
                                                      now: PhoneDuress.BootTime(boot: nil, seconds: 6000)), 6200)
    }

    /// A hold an earlier build wrote (no monotonic anchor) keeps the wall-clock rule.
    func test_hold_without_an_anchor_uses_the_wall_clock() throws {
        let body: JSONValue = .object(["version": .int(1), "since": .int(clock.now), "until": .int(clock.now + 3600)])
        try Data(try CanonicalJSON.encode(body, dialect: .utf8)).write(to: duress.files.hold)
        XCTAssertEqual(duress.heldUntil(), clock.now + 3600)
        clock.now += 3601
        XCTAssertFalse(duress.held())
    }

    /// A second trip never shortens the hold: what is left of the first one is kept on both clocks.
    func test_second_trip_keeps_the_rest_of_the_first_hold() async throws {
        try setUpDuress(hours: 48)
        _ = try await unlock(duressPassword)
        clock.now += 10 * 24 * 3600   // the date moved forward; only 10 minutes really passed
        clock.mono += 600
        // A key without sealed settings holds for the default 24 hours, less than the 48 still left.
        let until = try duress.trip(decoyKey: Array(repeating: 9, count: 32))
        XCTAssertEqual(until, clock.now + 48 * 3600 - 600)
        clock.advance(48 * 3600 - 601)
        XCTAssertTrue(duress.held())
        clock.advance(1)
        XCTAssertFalse(duress.held())
    }

    func test_new_real_password_may_not_be_near_the_duress_password() throws {
        try setUpDuress()
        XCTAssertThrowsError(try duress.checkNewPassword(realKey: realKey, newPassword: duressPassword, decoySession: false)) {
            XCTAssertEqual(($0 as? DuressError)?.code, "near_duress")
        }
        XCTAssertThrowsError(try duress.checkNewPassword(realKey: realKey, newPassword: duressPassword + "!", decoySession: false))
        XCTAssertNoThrow(try duress.checkNewPassword(realKey: realKey, newPassword: "a wholly different one 99",
                                                     decoySession: false))
        // A duress session checks nothing (no oracle).
        XCTAssertNoThrow(try duress.checkNewPassword(realKey: realKey, newPassword: duressPassword, decoySession: true))
    }

    func test_erasing_the_second_vault_keeps_its_password_and_the_real_record() throws {
        try setUpDuress()
        XCTAssertTrue(duress.eraseSecondVault())
        XCTAssertTrue(duress.configured)
        XCTAssertTrue(FileManager.default.fileExists(atPath: duress.files.real.path))
        XCTAssertNotNil(duress.tryOpen(password: duressPassword))
        XCTAssertTrue(duress.eraseAll())
        XCTAssertFalse(duress.configured)
    }

    func test_heir_local_state_is_sealed_per_vault_key() throws {
        let a = HeirLocalState(directory: dir, key: Array(repeating: 1, count: 32))
        try a.update { $0["folder"] = .string("abc") }
        XCTAssertEqual(a.read()["folder"], .string("abc"))
        let raw = try Data(contentsOf: a.url)
        XCTAssertNil(raw.range(of: Data("abc".utf8)))
        // Another vault's key (the second vault) reads nothing of it.
        XCTAssertTrue(HeirLocalState(directory: dir, key: Array(repeating: 2, count: 32)).read().isEmpty)
    }
}
#endif
