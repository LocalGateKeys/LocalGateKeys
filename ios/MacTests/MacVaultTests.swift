import XCTest
import LGKCore
@testable import AppSharedMac

/// Holds an attempt at a known point: the code under test awaits `pass()`, the test awaits `reached()`,
/// acts, then calls `open()`.
@MainActor
final class TestGate {
    private var isReached = false
    private var reachedWaiter: CheckedContinuation<Void, Never>?
    private var releaseWaiter: CheckedContinuation<Void, Never>?

    func pass() async {
        isReached = true
        reachedWaiter?.resume(); reachedWaiter = nil
        await withCheckedContinuation { releaseWaiter = $0 }
    }
    func reached() async {
        if isReached { return }
        await withCheckedContinuation { reachedWaiter = $0 }
    }
    func open() { releaseWaiter?.resume(); releaseWaiter = nil }
}

final class FakeBiometricKeyStore: BiometricKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var key: [UInt8]?
    var available = true
    /// Simulates an enrolment change: the Keychain item is gone (`errSecItemNotFound`).
    var invalidated = false
    var isAvailable: Bool { lock.withLock { available } }
    var stored: [UInt8]? { lock.withLock { key } }
    func store(_ key: [UInt8]) throws { lock.withLock { self.key = key } }
    func remove() throws { lock.withLock { key = nil } }
    func load(reason: String) async throws -> [UInt8] {
        try lock.withLock {
            if invalidated { throw BiometricKeyError.notFound }
            guard let key else { throw BiometricKeyError.notFound }
            return key
        }
    }
}

@MainActor
final class MacVaultTests: XCTestCase {
    private var dir: URL!
    private var now = Date(timeIntervalSince1970: 1_800_000_000)
    private var bio: FakeBiometricKeyStore!
    /// What the vault's `beforeKDF` init hook runs (nil: nothing).
    private var kdfHook: (@MainActor () async -> Void)?
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-macvault-\(UUID().uuidString)", isDirectory: true)
        bio = FakeBiometricKeyStore()
    }

    override func tearDown() async throws { try? FileManager.default.removeItem(at: dir) }

    private func makeVault(cheapKDF: Bool = true, biometric: (any BiometricKeyStore)? = nil) -> MacVault {
        MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: biometric ?? bio,
                 clock: { [unowned self] in self.now }, random: SystemRandomSource(),
                 kdfParams: cheapKDF ? cheap : .default,
                 beforeKDF: { [unowned self] in await self.kdfHook?() })
    }

    private func addItem(_ store: LocalStore) throws -> JSONValue {
        store.limitHints = nil
        let note: JSONValue = .object(["ns": .string("item"),
                                       "record": .object(["id": .string("n1"), "kind": .string("note")])])
        try store.commit(StoreChange(baseRevision: 0, records: ["n1": note], meta: [:], sync: nil))
        return note
    }

    private func assertThrows<E: Error & Equatable>(_ expected: E, file: StaticString = #filePath, line: UInt = #line,
                                                    _ op: () async throws -> Void) async {
        do { try await op(); XCTFail("expected \(expected)", file: file, line: line) }
        catch { XCTAssertEqual(error as? E, expected, file: file, line: line) }
    }

    private func assertWrong(_ v: MacVault, _ pw: String, retryAfter: Date?, file: StaticString = #filePath, line: UInt = #line) async {
        await assertThrows(MacVaultError.wrongPassword(retryAfter: retryAfter), file: file, line: line) {
            _ = try await v.unlock(password: pw)
        }
    }

    /// Real Argon2 cost (desktop DEFAULT_KDF).
    func testCreateThenUnlock() async throws {
        let v = makeVault(cheapKDF: false)
        XCTAssertFalse(v.exists)
        let note = try addItem(try await v.create(password: "correct horse", enableTouchID: false))
        XCTAssertTrue(v.exists)
        let data = try XCTUnwrap(FileManager.default.contents(atPath: dir.appendingPathComponent("master-key.json").path))
        let file = try JSONDecoder().decode(MasterKeyFile.self, from: data)
        XCTAssertEqual(file.kdf, .default)
        XCTAssertNil(bio.stored)
        let reopened = try await makeVault().unlock(password: "correct horse")
        XCTAssertEqual(try reopened.load().records["n1"], note)
    }

    func testWrongPasswordThrows() async throws {
        let v = makeVault()
        _ = try await v.create(password: "correct horse", enableTouchID: false)
        await assertWrong(v, "wrong horse!", retryAfter: nil)
    }

    func testThrottleSchedule() async throws {
        let v = makeVault()
        _ = try await v.create(password: "correct horse", enableTouchID: false)
        for _ in 1...5 { await assertWrong(v, "nope nope", retryAfter: nil); XCTAssertNil(v.retryAfter) }
        var expected: [TimeInterval] = [2, 4, 8, 16, 32, 60, 60]
        for wait in expected {
            await assertWrong(v, "nope nope", retryAfter: now.addingTimeInterval(wait))
            XCTAssertEqual(v.retryAfter, now.addingTimeInterval(wait))
            now = now.addingTimeInterval(wait)
            XCTAssertNil(v.retryAfter)
        }
        // Persisted: a fresh MacVault on the same directory sees the same throttle.
        await assertWrong(v, "nope nope", retryAfter: now.addingTimeInterval(60))
        XCTAssertEqual(makeVault().retryAfter, now.addingTimeInterval(60))
        now = now.addingTimeInterval(60)
        _ = try await v.unlock(password: "correct horse")
        XCTAssertNil(v.retryAfter)
        for _ in 1...5 { await assertWrong(v, "nope nope", retryAfter: nil) }   // success reset the count
        expected = [2]
        await assertWrong(v, "nope nope", retryAfter: now.addingTimeInterval(expected[0]))
    }

    func testThrottledAttemptRejectedEvenIfRight() async throws {
        let v = makeVault()
        _ = try await v.create(password: "correct horse", enableTouchID: false)
        for _ in 1...6 { _ = try? await v.unlock(password: "nope nope") }
        let until = now.addingTimeInterval(2)
        await assertThrows(MacVaultError.throttled(until: until)) { _ = try await v.unlock(password: "correct horse") }
        await assertThrows(MacVaultError.throttled(until: until)) { _ = try await v.changePassword(old: "correct horse", new: "battery staple") }
        now = until
        _ = try await v.unlock(password: "correct horse")
    }

    func testVerifyPasswordIsThrottled() async throws {
        let v = makeVault()
        _ = try await v.create(password: "correct horse", enableTouchID: false)
        v.discardOpenedLocalKey()
        try await v.verifyPassword("correct horse")
        XCTAssertNil(v.takeOpenedLocalKey(), "verifying opens nothing")
        for _ in 1...6 { _ = try? await v.verifyPassword("nope nope") }
        let until = now.addingTimeInterval(2)
        await assertThrows(MacVaultError.throttled(until: until)) { try await v.verifyPassword("correct horse") }
    }

    func testTouchIDUnlock() async throws {
        let v = makeVault()
        let note = try addItem(try await v.create(password: "correct horse", enableTouchID: true))
        XCTAssertNotNil(bio.stored)
        let store = try await makeVault().unlockWithTouchID(reason: "Unlock")
        XCTAssertEqual(try store.load().records["n1"], note)
    }

    func testBiometricItemInvalidatedFallsBack() async throws {
        let v = makeVault()
        let note = try addItem(try await v.create(password: "correct horse", enableTouchID: true))
        bio.invalidated = true
        do { _ = try await v.unlockWithTouchID(reason: "Unlock"); XCTFail("expected failure") }
        catch { XCTAssertEqual(error as? MacVaultError, .biometricUnavailable) }
        let byPassword = try await v.unlock(password: "correct horse")
        XCTAssertEqual(try byPassword.load().records["n1"], note)
        bio.available = false
        do { _ = try await v.unlockWithTouchID(reason: "Unlock"); XCTFail("expected failure") }
        catch { XCTAssertEqual(error as? MacVaultError, .biometricUnavailable) }
    }

    /// Fix round 1 ruling: a password change rotates the local key (Windows `_rotate_data_key`); the items are the
    /// same (one revision on, under the new key) and the Touch ID item, which held the old key, is removed.
    func testChangePasswordRotatesKeyAndRemovesTouchID() async throws {
        let v = makeVault()
        let store = try await v.create(password: "correct horse", enableTouchID: true)
        _ = try addItem(store)
        let before = try store.load()
        XCTAssertNotNil(bio.stored)
        try await v.changePassword(old: "correct horse", new: "battery staple")
        await assertWrong(v, "correct horse", retryAfter: nil)
        let byNew = try await v.unlock(password: "battery staple")
        XCTAssertEqual(try byNew.load().records, before.records)
        XCTAssertEqual(try byNew.load().revision, before.revision + 1)
        XCTAssertNil(bio.stored)
        await assertThrows(MacVaultError.biometricUnavailable) { _ = try await v.unlockWithTouchID(reason: "Unlock") }
    }

    func testNewPasswordTooShort() async throws {
        let v = makeVault()
        await assertThrows(MacVaultError.passwordTooShort) { _ = try await v.create(password: "short7!", enableTouchID: false) }
        XCTAssertFalse(v.exists)
        _ = try await v.create(password: "12345678", enableTouchID: false)
        await assertThrows(MacVaultError.passwordTooShort) { _ = try await v.changePassword(old: "12345678", new: "1234567") }
        _ = try await v.unlock(password: "12345678")
    }

    func testFailedCreateLeavesNoVault() async throws {
        final class Failing: BiometricKeyStore, @unchecked Sendable {
            struct Boom: Error {}
            var isAvailable: Bool { true }
            func store(_ key: [UInt8]) throws { throw Boom() }
            func load(reason: String) async throws -> [UInt8] { throw Boom() }
            func remove() throws {}
        }
        let v = makeVault(biometric: Failing())
        do { _ = try await v.create(password: "correct horse", enableTouchID: true); XCTFail("expected failure") } catch {}
        XCTAssertFalse(v.exists)
        XCTAssertFalse(LocalStore.hasStoreFiles(dir))
        let retry = makeVault()
        let note = try addItem(try await retry.create(password: "correct horse", enableTouchID: true))
        let reopened = try await makeVault().unlock(password: "correct horse")
        XCTAssertEqual(try reopened.load().records["n1"], note)
    }

    func testTouchIDStoreErrorsAreRethrown() async throws {
        let v = makeVault()
        _ = try await v.create(password: "correct horse", enableTouchID: true)
        try bio.store(Array(repeating: 7, count: 16))   // the store refuses a key of the wrong size
        do { _ = try await v.unlockWithTouchID(reason: "Unlock"); XCTFail("expected failure") }
        catch { XCTAssertNil(error as? MacVaultError); XCTAssertEqual(error as? LocalStoreError, .badLocalKey) }
    }

    func testThrottleFileMissingIsFreshCorruptFailsClosed() async throws {
        let v = makeVault()
        _ = try await v.create(password: "correct horse", enableTouchID: false)
        let url = dir.appendingPathComponent("throttle.json")
        try? FileManager.default.removeItem(at: url)
        XCTAssertNil(makeVault().retryAfter)
        try Data("{not json".utf8).write(to: url)
        let closed = makeVault()
        let expected = now.addingTimeInterval(32)   // 10 failures = 5 over the free ones → 32 s
        XCTAssertEqual(closed.retryAfter, expected)
        await assertThrows(MacVaultError.throttled(until: expected)) { _ = try await closed.unlock(password: "correct horse") }
        now = expected
        _ = try await closed.unlock(password: "correct horse")
        XCTAssertNil(makeVault().retryAfter)
    }

    /// A running verifyPassword blocks other attempts, and another verifyPassword is refused with .busy.
    func testVerifyPasswordBusyWhileAnotherAttemptRuns() async throws {
        let v = makeVault(cheapKDF: false)
        _ = try await v.create(password: "correct horse", enableTouchID: false)
        let gate = TestGate()
        kdfHook = { await gate.pass() }
        let first = Task { try await v.verifyPassword("correct horse") }
        await gate.reached()
        kdfHook = nil
        await assertThrows(MacVaultError.busy) { try await v.verifyPassword("correct horse") }
        await assertThrows(MacVaultError.busy) { _ = try await v.unlock(password: "correct horse") }
        gate.open()
        try await first.value
    }

    /// Real Argon2 cost, so the first attempt is still running when the second arrives.
    func testConcurrentAttemptIsBusy() async throws {
        let v = makeVault(cheapKDF: false)
        _ = try await v.create(password: "correct horse", enableTouchID: false)
        let gate = TestGate()
        kdfHook = { await gate.pass() }
        let first = Task { try await v.unlock(password: "correct horse") }
        await gate.reached()
        kdfHook = nil
        await assertThrows(MacVaultError.busy) { _ = try await v.unlock(password: "nope nope") }
        await assertThrows(MacVaultError.busy) { try await v.changePassword(old: "correct horse", new: "battery staple") }
        await assertThrows(MacVaultError.busy) { try await v.setTouchID(true, password: "correct horse") }
        await assertThrows(MacVaultError.busy) { try await v.verifyPassword("correct horse") }
        gate.open()
        _ = try await first.value
        XCTAssertNil(v.retryAfter)
        _ = try await v.unlock(password: "correct horse")   // free again
    }

    func testTouchIDRefusedWhileAttemptRuns() async throws {
        let v = makeVault()
        _ = try await v.create(password: "correct horse", enableTouchID: true)
        let gate = TestGate()
        kdfHook = { await gate.pass() }
        let first = Task { try await v.unlock(password: "correct horse") }
        await gate.reached()
        kdfHook = nil
        await assertThrows(MacVaultError.busy) { _ = try await v.unlockWithTouchID(reason: "Unlock") }
        gate.open()
        _ = try await first.value
        _ = try await v.unlockWithTouchID(reason: "Unlock")
    }

    /// The wait runs from when the failed attempt ended, not when it started (Argon2 can take seconds).
    func testFailureTimeRecordedAfterKDF() async throws {
        let v = makeVault()
        _ = try await v.create(password: "correct horse", enableTouchID: false)
        for _ in 1...5 { await assertWrong(v, "nope nope", retryAfter: nil) }
        kdfHook = { [unowned self] in self.now = self.now.addingTimeInterval(10) }
        let started = now
        await assertWrong(v, "nope nope", retryAfter: started.addingTimeInterval(12))
        XCTAssertEqual(v.retryAfter, started.addingTimeInterval(12))
    }
}
