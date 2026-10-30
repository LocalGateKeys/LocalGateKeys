#if os(iOS)
import XCTest
import LocalAuthentication
@testable import AppShared

/// Task 7 (mirrors android AppPasswordTest): the app-password file around the unchanged local key.
final class AppPasswordTests: XCTestCase {
    final class FakeBiometric: AppPasswordBiometricStore, @unchecked Sendable {
        var key: [UInt8]?
        var changed = false
        func store(_ key: [UInt8]) throws { self.key = key }
        func load(context: LAContext) throws -> [UInt8] {
            if changed { throw AppPasswordError.biometricChanged }
            guard let key else { throw AppPasswordError.biometricChanged }
            return key
        }
        func remove() throws { key = nil }
        var exists: Bool { key != nil }
    }

    final class Clock: @unchecked Sendable { var now: Int64 = 1_000_000 }

    final class FakeBoot: AppPasswordBootClock, @unchecked Sendable {
        var uptime: Int64 = 1_000
        var bootID: String? = "boot-1"
    }

    final class MemoryJournal: AppPasswordReprotectJournal, @unchecked Sendable {
        var items: [VaultSlot: [UInt8]] = [:]
        var pending = false
        func save(_ slot: VaultSlot, _ bytes: [UInt8]) throws { items[slot] = bytes }
        func load(_ slot: VaultSlot) throws -> [UInt8]? { items[slot] }
        func remove(_ slot: VaultSlot) throws { items[slot] = nil }
        func isPending() throws -> Bool { pending }
        func setPending(_ on: Bool) throws { pending = on }
    }

    struct Crash: Error {}

    /// Deletes normally; the first write of `crashOn` after its delete "crashes" (throws, nothing written).
    final class CrashingVault: KeychainVault, @unchecked Sendable {
        let inner = InMemoryKeychainVault()
        var crashOn: VaultSlot?
        func read(_ slot: VaultSlot) throws -> [UInt8]? { try inner.read(slot) }
        func write(_ slot: VaultSlot, _ bytes: [UInt8]) throws {
            if slot == crashOn { crashOn = nil; throw Crash() }
            try inner.write(slot, bytes)
        }
        func delete(_ slot: VaultSlot) throws { try inner.delete(slot) }
    }

    var dir: URL!, clock: Clock!, boot: FakeBoot!, bio: FakeBiometric!, store: AppPasswordStore!
    let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
    let localKey = (0..<32).map { UInt8($0) }

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("app-password-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        clock = Clock(); boot = FakeBoot(); bio = FakeBiometric()
        let c = clock!
        store = AppPasswordStore(url: dir.appendingPathComponent(AppPasswordStore.fileName), biometric: bio,
                                 defaults: UserDefaults(suiteName: "apw-\(UUID().uuidString)")!, params: cheap,
                                 now: { c.now }, bootClock: boot)
    }

    private func turnOn(_ password: String = "river otter lantern 42") throws -> String {
        let p = try store.prepare(localKey: localKey, password: password, random: SystemRandomSource())
        XCTAssertFalse(store.isOn, "prepare writes nothing")
        try store.write(p.file)
        return p.phrase
    }

    func test_off_by_default() {
        XCTAssertFalse(store.isOn)
        XCTAssertFalse(store.biometricOn)
    }

    func test_password_and_phrase_open_the_same_local_key() throws {
        let phrase = try turnOn()
        XCTAssertTrue(store.isOn)
        XCTAssertEqual(try store.open(password: "river otter lantern 42"), localKey)
        XCTAssertEqual(try store.open(phrase: phrase), localKey)
        XCTAssertEqual(phrase.split(separator: " ").count, 24)
    }

    func test_desktop_argon2_parameters_are_the_default() {
        XCTAssertEqual(MasterKeyFile.KDFParams.default, MasterKeyFile.KDFParams(timeCost: 3, memoryKiB: 65536, parallelism: 4))
    }

    func test_wrong_password_and_the_delay_from_the_fifth() throws {
        _ = try turnOn()
        for _ in 0..<4 { XCTAssertThrowsError(try store.open(password: "wrong")) { XCTAssertEqual($0 as? AppPasswordError, .wrongPassword) } }
        XCTAssertEqual(store.waitSeconds(), 0)
        XCTAssertThrowsError(try store.open(password: "wrong"))
        XCTAssertEqual(store.waitSeconds(), 30)
        XCTAssertThrowsError(try store.open(password: "river otter lantern 42")) { XCTAssertEqual($0 as? AppPasswordError, .wait(seconds: 30)) }
        clock.now += 30; boot.uptime += 30   // within one boot the uptime decides
        XCTAssertEqual(try store.open(password: "river otter lantern 42"), localKey)
        XCTAssertEqual(store.waitSeconds(), 0)
    }

    func test_wrong_phrase_counts() throws {
        _ = try turnOn()
        let other = try AppPasswordStore(url: dir.appendingPathComponent("other.json"), biometric: FakeBiometric(),
                                         defaults: UserDefaults(suiteName: "o-\(UUID().uuidString)")!, params: cheap)
            .prepare(localKey: localKey, password: "x", random: SystemRandomSource()).phrase
        XCTAssertThrowsError(try store.open(phrase: other)) { XCTAssertEqual($0 as? AppPasswordError, .wrongPhrase) }
    }

    func test_change_keeps_the_recovery_wrapper() throws {
        let phrase = try turnOn()
        let changed = try store.withNewPassword(try store.readFile(), localKey: localKey, password: "a brand new password", random: SystemRandomSource())
        try store.write(changed)
        XCTAssertEqual(try store.open(password: "a brand new password"), localKey)
        XCTAssertThrowsError(try store.open(password: "river otter lantern 42"))
        XCTAssertEqual(try store.open(phrase: phrase), localKey)
    }

    func test_turning_off_removes_the_file_and_the_shortcut() throws {
        _ = try turnOn()
        try bio.store(localKey)
        XCTAssertTrue(store.biometricOn)
        XCTAssertTrue(store.removeAll())
        XCTAssertFalse(store.isOn)
        XCTAssertFalse(bio.exists)
    }

    func test_changed_biometrics_are_reported() throws {
        _ = try turnOn()
        try bio.store(localKey)
        bio.changed = true
        XCTAssertThrowsError(try store.biometric.load(context: LAContext())) { XCTAssertEqual($0 as? AppPasswordError, .biometricChanged) }
    }

    func test_memory_vault_never_persists_the_local_key() throws {
        let base = InMemoryKeychainVault()
        let v = AppPasswordKeyVault(localKey: localKey, base: base)
        XCTAssertEqual(try v.read(.localKey), localKey)
        try v.write(.localKey, [1, 2, 3])
        XCTAssertNil(try base.read(.localKey))
        try v.write(.installID, [7])
        XCTAssertEqual(try base.read(.installID), [7])
    }

    func test_reprotect_rewrites_every_slot_but_the_local_key() throws {
        let base = InMemoryKeychainVault()
        try base.write(.localKey, localKey)
        try base.write(.pairedPeer, [1])
        try base.write(.safariIndexKey, [2])
        let journal = MemoryJournal()
        try AppPasswordKeychainMigration.reprotect(base, journal: journal)
        XCTAssertEqual(try base.read(.pairedPeer), [1])
        XCTAssertEqual(try base.read(.localKey), localKey)
        XCTAssertEqual(try base.read(.safariIndexKey), [2])
        XCTAssertTrue(journal.items.isEmpty)
        XCTAssertFalse(journal.pending)
    }

    // Finding 1: a crash between the delete and the add loses nothing.
    func test_a_crash_inside_reprotect_keeps_the_slot_in_the_journal_and_the_next_unlock_puts_it_back() throws {
        let v = CrashingVault()
        try v.write(.installID, [1, 2])
        try v.write(.pairedPeer, [3])
        try v.write(.folderBookmark, [4])
        try v.write(.peerCounters, [5])
        let journal = MemoryJournal()
        v.crashOn = .installID
        XCTAssertThrowsError(try AppPasswordKeychainMigration.reprotect(v, journal: journal))
        XCTAssertNil(try v.read(.installID), "the item was deleted when the crash came")
        XCTAssertEqual(journal.items[.installID], [1, 2])
        XCTAssertTrue(journal.pending)
        try AppPasswordKeychainMigration.repairAtUnlock(v, journal: journal)
        XCTAssertEqual(try v.read(.installID), [1, 2])
        XCTAssertEqual(try v.read(.pairedPeer), [3])
        XCTAssertEqual(try v.read(.folderBookmark), [4])
        XCTAssertEqual(try v.read(.peerCounters), [5])
        XCTAssertTrue(journal.items.isEmpty)
        XCTAssertFalse(journal.pending)
    }

    func test_recover_keeps_a_slot_that_was_already_added_back() throws {
        let v = InMemoryKeychainVault()
        try v.write(.pairedPeer, [9])
        let journal = MemoryJournal()
        journal.items[.pairedPeer] = [9]   // crash after the add, before the journal copy was removed
        try AppPasswordKeychainMigration.recover(v, journal: journal)
        XCTAssertEqual(try v.read(.pairedPeer), [9])
        XCTAssertTrue(journal.items.isEmpty)
    }

    // Findings 3 and 4: a mode change marked with `begin` and interrupted before `reprotect` is finished at unlock;
    // with nothing pending the unlock rewrites nothing.
    func test_an_interrupted_mode_change_is_finished_at_unlock() throws {
        let v = CrashingVault()
        try v.write(.installID, [1])
        let journal = MemoryJournal()
        try AppPasswordKeychainMigration.begin(journal: journal)
        // crash here (after the password file was written or removed)
        v.crashOn = .installID   // proves the item is rewritten by the repair
        XCTAssertThrowsError(try AppPasswordKeychainMigration.repairAtUnlock(v, journal: journal))
        XCTAssertTrue(journal.pending, "still pending: the next unlock tries again")
        try AppPasswordKeychainMigration.repairAtUnlock(v, journal: journal)
        XCTAssertEqual(try v.read(.installID), [1])
        XCTAssertFalse(journal.pending)
        v.crashOn = .installID   // nothing pending: no item is deleted or written
        try AppPasswordKeychainMigration.repairAtUnlock(v, journal: journal)
        XCTAssertEqual(try v.read(.installID), [1])
    }

    // Finding 7: the in-memory local key is overwritten at lock.
    func test_memory_vault_zeroes_the_local_key_on_clear() throws {
        let v = AppPasswordKeyVault(localKey: localKey, base: InMemoryKeychainVault())
        XCTAssertEqual(try v.read(.localKey), localKey)
        v.clear()
        XCTAssertTrue(v.isCleared)
        XCTAssertEqual(v.heldBytes, [UInt8](repeating: 0, count: localKey.count))
        XCTAssertNil(try v.read(.localKey))
    }

    // Finding 2: setting the date forward does not skip the wait.
    func test_moving_the_clock_forward_does_not_skip_the_delay() throws {
        _ = try turnOn()
        for _ in 0..<5 { XCTAssertThrowsError(try store.open(password: "wrong password 123")) }
        XCTAssertEqual(store.waitSeconds(), 30)
        clock.now += 86_400
        XCTAssertEqual(store.waitSeconds(), 30)
        XCTAssertThrowsError(try store.open(password: "river otter lantern 42")) {
            XCTAssertEqual($0 as? AppPasswordError, .wait(seconds: 30))
        }
        boot.uptime += 30
        XCTAssertEqual(store.waitSeconds(), 0)
        XCTAssertEqual(try store.open(password: "river otter lantern 42"), localKey)
    }

    func test_after_a_restart_the_wall_clock_decides_the_delay() throws {
        _ = try turnOn()
        for _ in 0..<5 { XCTAssertThrowsError(try store.open(password: "wrong password 123")) }
        boot.bootID = "boot-2"; boot.uptime = 5
        XCTAssertEqual(store.waitSeconds(), 30)
        clock.now += 10
        XCTAssertEqual(store.waitSeconds(), 20)
    }

    func test_delay_formula() {
        XCTAssertEqual(AppPasswordDelay.seconds(failures: 4), 0)
        XCTAssertEqual(AppPasswordDelay.seconds(failures: 5), 30)
        XCTAssertEqual(AppPasswordDelay.seconds(failures: 6), 60)
        XCTAssertEqual(AppPasswordDelay.seconds(failures: 50), 900)
        XCTAssertEqual(AppPasswordDelay.remaining(failures: 5, lastFailureAt: 100, now: 50), 30)
        XCTAssertEqual(AppPasswordDelay.remaining(failures: 5, lastFailureAt: 100, now: 86_500,
                                                  lastFailureUptime: 500, uptime: 520, sameBoot: true), 10)
        XCTAssertEqual(AppPasswordDelay.remaining(failures: 5, lastFailureAt: 100, now: 110,
                                                  lastFailureUptime: 500, uptime: 3, sameBoot: true), 20)
        XCTAssertEqual(AppPasswordDelay.remaining(failures: 5, lastFailureAt: 100, now: 110,
                                                  lastFailureUptime: -1, uptime: 600, sameBoot: true), 20)
        XCTAssertEqual(AppPasswordDelay.remaining(failures: 5, lastFailureAt: 100, now: 110,
                                                  lastFailureUptime: 500, uptime: 600, sameBoot: false), 20)
    }
}
#endif
