import XCTest
import LGKCore
@testable import AppSharedMac

/// A settable clock both the app's MacVault and the extension's opener read.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date
    init(_ start: Date) { value = start }
    var now: Date {
        get { lock.withLock { value } }
        set { lock.withLock { value = newValue } }
    }
}

@MainActor
final class ExtensionVaultOpenerTests: XCTestCase {
    private var dir: URL!
    private var bio: FakeBiometricKeyStore!
    private let clock = TestClock(Date(timeIntervalSince1970: 1_800_000_000))
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-extopener-\(UUID().uuidString)", isDirectory: true)
        bio = FakeBiometricKeyStore()
    }

    override func tearDown() async throws {
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        try? FileManager.default.removeItem(at: dir)
    }

    private func makeVault() -> MacVault {
        let clock = self.clock
        return MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: bio,
                        clock: { clock.now }, random: SystemRandomSource(), kdfParams: cheap)
    }

    private func makeOpener() -> ExtensionVaultOpener {
        let clock = self.clock
        return ExtensionVaultOpener(directory: dir, biometric: bio, clock: { clock.now }, keychain: InMemoryKeychainVault())
    }

    /// Creates a vault with one note, as the app would.
    private func createVault(touchID: Bool = false) async throws {
        let store = try await makeVault().create(password: "correct horse", enableTouchID: touchID)
        store.limitHints = nil
        let note: JSONValue = .object(["ns": .string("item"),
                                       "record": .object(["id": .string("n1"), "kind": .string("note")])])
        try store.commit(StoreChange(baseRevision: 0, records: ["n1": note], meta: [:], sync: nil))
    }

    private func assertThrows<E: Error & Equatable>(_ expected: E, file: StaticString = #filePath, line: UInt = #line,
                                                    _ op: () async throws -> Void) async {
        do { try await op(); XCTFail("expected \(expected)", file: file, line: line) }
        catch { XCTAssertEqual(error as? E, expected, file: file, line: line) }
    }

    func testOpenWithPassword() async throws {
        try await createVault()
        let opener = makeOpener()
        let store = try await opener.open(password: "correct horse")
        XCTAssertNotNil(try store.load().records["n1"])
        try await opener.verifyMasterPassword("correct horse")
        await assertThrows(MacVaultError.wrongPassword(retryAfter: nil)) { _ = try await opener.open(password: "wrong horse!") }
        await assertThrows(MacVaultError.wrongPassword(retryAfter: nil)) { try await opener.verifyMasterPassword("wrong horse!") }
    }

    /// Failures in the app and in the extension add up in one throttle.json, both ways.
    func testThrottleSharedWithApp() async throws {
        try await createVault()
        let app = makeVault()
        let opener = makeOpener()
        for _ in 1...3 { _ = try? await app.unlock(password: "nope nope") }
        for _ in 1...2 { _ = try? await opener.open(password: "nope nope") }
        XCTAssertNil(opener.retryAfter, "5 failures are free")
        // The 6th failure, in the extension, starts the wait in the app too.
        await assertThrows(MacVaultError.wrongPassword(retryAfter: clock.now.addingTimeInterval(2))) {
            _ = try await opener.open(password: "nope nope")
        }
        XCTAssertEqual(app.retryAfter, clock.now.addingTimeInterval(2))
        await assertThrows(MacVaultError.throttled(until: clock.now.addingTimeInterval(2))) {
            _ = try await app.unlock(password: "correct horse")
        }
        clock.now = clock.now.addingTimeInterval(2)
        // The 7th, in the app, doubles the extension's wait.
        _ = try? await app.unlock(password: "nope nope")
        let until = clock.now.addingTimeInterval(4)
        XCTAssertEqual(opener.retryAfter, until)
        await assertThrows(MacVaultError.throttled(until: until)) { _ = try await opener.open(password: "correct horse") }
        await assertThrows(MacVaultError.throttled(until: until)) { try await opener.verifyMasterPassword("correct horse") }
        clock.now = until
        _ = try await opener.open(password: "correct horse")
        XCTAssertNil(app.retryAfter, "a success in the extension resets the app's throttle")
    }

    func testTouchIDInvalidatedFallsBackToPassword() async throws {
        try await createVault(touchID: true)
        let opener = makeOpener()
        XCTAssertTrue(opener.touchIDAvailable)
        let store = try await opener.openWithTouchID(reason: "Fill")
        XCTAssertNotNil(try store.load().records["n1"])
        bio.invalidated = true   // a finger was added or removed
        await assertThrows(MacVaultError.biometricUnavailable) { _ = try await opener.openWithTouchID(reason: "Fill") }
        XCTAssertNil(opener.retryAfter, "a Touch ID failure is not a password failure")
        let fallback = try await opener.open(password: "correct horse")
        XCTAssertNotNil(try fallback.load().records["n1"])
    }

    func testCorruptThrottleFailsClosed() async throws {
        try await createVault()
        try Data("{not json".utf8).write(to: dir.appendingPathComponent(UnlockThrottle.fileName))
        let opener = makeOpener()
        let expected = clock.now.addingTimeInterval(32)   // 10 failures = 5 over the free ones → 32 s
        XCTAssertEqual(opener.retryAfter, expected)
        clock.now = clock.now.addingTimeInterval(10)
        XCTAssertEqual(opener.retryAfter, expected, "the wait does not restart on each read")
        XCTAssertEqual(makeVault().retryAfter, expected, "the app sees the same fail-closed wait")
        await assertThrows(MacVaultError.throttled(until: expected)) { _ = try await opener.open(password: "correct horse") }
        clock.now = expected
        _ = try await opener.open(password: "correct horse")
        XCTAssertNil(opener.retryAfter)
    }

    func testNeverWritesMasterKeyFile() async throws {
        try await createVault(touchID: true)
        let url = dir.appendingPathComponent(MacVault.keyFileName)
        let before = try Data(contentsOf: url)
        let modified = try FileManager.default.attributesOfItem(atPath: url.path)[.modificationDate] as? Date
        let opener = makeOpener()
        _ = try await opener.open(password: "correct horse")
        try await opener.verifyMasterPassword("correct horse")
        _ = try await opener.openWithTouchID(reason: "Fill")
        _ = try? await opener.open(password: "wrong horse!")
        XCTAssertEqual(try Data(contentsOf: url), before)
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: url.path)[.modificationDate] as? Date, modified)

        // With no vault the opener creates nothing.
        try FileManager.default.removeItem(at: url)
        await assertThrows(MacVaultError.noVault) { _ = try await opener.open(password: "correct horse") }
        await assertThrows(MacVaultError.noVault) { _ = try await opener.openWithTouchID(reason: "Fill") }
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    }

    /// A directory where throttle.lock should be: the lock cannot be taken, so attempts fail closed (the
    /// fail-closed wait applies in the app and the extension) and nothing unlocks before it has passed.
    func testBlockedThrottleLockFailsClosed() async throws {
        try await createVault()
        let lockURL = dir.appendingPathComponent(UnlockThrottle.lockFileName)
        try? FileManager.default.removeItem(at: lockURL)
        try FileManager.default.createDirectory(at: lockURL, withIntermediateDirectories: false)
        let opener = makeOpener()
        let app = makeVault()
        let expected = clock.now.addingTimeInterval(32)
        XCTAssertEqual(opener.retryAfter, expected)
        clock.now = clock.now.addingTimeInterval(5)
        XCTAssertEqual(app.retryAfter, expected, "the wait does not restart on each read")
        await assertThrows(MacVaultError.throttled(until: expected)) { _ = try await opener.open(password: "correct horse") }
        await assertThrows(MacVaultError.throttled(until: expected)) { _ = try await app.unlock(password: "correct horse") }
        clock.now = expected
        // A failure that cannot be written still counts: 11 failures → 60 s.
        await assertThrows(MacVaultError.wrongPassword(retryAfter: expected.addingTimeInterval(60))) {
            _ = try await opener.open(password: "nope nope")
        }
        await assertThrows(MacVaultError.throttled(until: expected.addingTimeInterval(60))) {
            _ = try await app.unlock(password: "correct horse")
        }
    }

    /// throttle.json cannot be written (read-only vault directory): failures are still counted in-process.
    func testUnwritableThrottleCountsInProcess() async throws {
        try await createVault()
        let opener = makeOpener()
        _ = opener.retryAfter   // the lock file exists before the directory is made read-only
        try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: dir.path)
        for _ in 1...5 { _ = try? await opener.open(password: "nope nope") }
        await assertThrows(MacVaultError.wrongPassword(retryAfter: clock.now.addingTimeInterval(2))) {
            _ = try await opener.open(password: "nope nope")
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent(UnlockThrottle.fileName).path))
        await assertThrows(MacVaultError.throttled(until: clock.now.addingTimeInterval(2))) {
            _ = try await makeVault().unlock(password: "correct horse")
        }
    }

    func testThrottleFileIsPrivate() async throws {
        try await createVault()
        _ = try? await makeOpener().open(password: "nope nope")
        let attrs = try FileManager.default.attributesOfItem(atPath: dir.appendingPathComponent(UnlockThrottle.fileName).path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    /// Corrupt throttle.json that cannot be rewritten: the fail-closed wait runs once, then expires.
    func testCorruptUnwritableThrottleWaitExpires() async throws {
        try await createVault()
        let opener = makeOpener()
        _ = opener.retryAfter   // the lock file exists before the directory is made read-only
        try Data("{not json".utf8).write(to: dir.appendingPathComponent(UnlockThrottle.fileName))
        try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: dir.path)
        let expected = clock.now.addingTimeInterval(32)
        XCTAssertEqual(opener.retryAfter, expected)
        clock.now = clock.now.addingTimeInterval(20)
        XCTAssertEqual(makeVault().retryAfter, expected, "the wait does not slide forward")
        clock.now = expected
        XCTAssertNil(opener.retryAfter)
        _ = try await opener.open(password: "correct horse")
    }
}
