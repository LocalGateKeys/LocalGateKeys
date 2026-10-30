import XCTest
import LGKCore
@testable import AppSharedMac

@MainActor
final class MacLocalStoreTests: XCTestCase {
    private var dir: URL!
    private var suite: String!
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-local-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        suite = "lgk-local-tests-\(UUID().uuidString)"
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        UserDefaults().removePersistentDomain(forName: suite)
    }

    private func badFiles() -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []).filter { $0.hasPrefix(MacLocalStore.badFilePrefix) }
    }

    private func makeLockModel(hook: (@MainActor () async -> Void)? = nil) -> (MacLockModel, MacVault) {
        let settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(),
                             kdfParams: cheap, beforeKDF: hook)
        return (MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), startTimer: false), vault)
    }

    func testUnreadableFileIsSetAsideNotOverwritten() throws {
        let key = Array(repeating: UInt8(4), count: 32)
        let url = dir.appendingPathComponent(MacLocalStore.fileName)
        try MacLocalStore(directory: dir, localKey: key).save(sample())
        let original = try Data(contentsOf: url)
        try FileManager.default.setAttributes([.posixPermissions: 0], ofItemAtPath: url.path)
        let store = MacLocalStore(directory: dir, localKey: key)
        let (d, msg) = store.load()
        XCTAssertEqual(msg, MacLocalStore.resetMessage)
        XCTAssertTrue(d.trash.isEmpty)
        let bad = badFiles()
        XCTAssertEqual(bad.count, 1)
        let badURL = dir.appendingPathComponent(bad[0])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: badURL.path)
        XCTAssertEqual(try Data(contentsOf: badURL), original, "the unreadable file is kept intact")
        try store.save(d)
        XCTAssertEqual(try Data(contentsOf: badURL), original, "saving never overwrites it")
    }

    func testOlderBadFilesAreKept() throws {
        let url = dir.appendingPathComponent(MacLocalStore.fileName)
        let store = MacLocalStore(directory: dir, localKey: Array(repeating: 5, count: 32), clock: { Date(timeIntervalSince1970: 1_000) })
        try Data("one".utf8).write(to: url); _ = store.load()
        try Data("two".utf8).write(to: url); _ = store.load()
        XCTAssertEqual(badFiles().count, 2)
        XCTAssertTrue(badFiles().contains(MacLocalStore.badFilePrefix + "1000"))
    }

    func testLockDuringUnlockLeavesNoOpenedKey() async throws {
        var gate: CheckedContinuation<Void, Never>?
        var holding = false
        let (m, vault) = makeLockModel(hook: { if holding { await withCheckedContinuation { gate = $0 } } })
        await m.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertFalse(vault.hasOpenedLocalKey, "taken by the lock model")
        m.lock()
        holding = true
        let attempt = Task { await m.unlock(password: "correct horse") }
        while gate == nil { await Task.yield() }
        m.lock()
        holding = false
        gate?.resume()
        await attempt.value
        XCTAssertEqual(m.state, .locked)
        XCTAssertNil(m.localStore)
        XCTAssertFalse(vault.hasOpenedLocalKey, "no key copy left behind")
    }

    func testFailedUnlockLeavesNoOpenedKey() async throws {
        let (m, vault) = makeLockModel()
        await m.create(password: "correct horse", confirm: "correct horse", touchID: false)
        m.lock()
        // The item store opens lazily, so nothing in MacVault can throw after the key is set today. Leave a
        // key behind directly (an open the model never took), then a failed attempt must clear it.
        _ = try await vault.unlock(password: "correct horse")
        XCTAssertTrue(vault.hasOpenedLocalKey)
        await m.unlock(password: "wrong password")
        XCTAssertEqual(m.state, .locked)
        XCTAssertFalse(vault.hasOpenedLocalKey, "a failed attempt leaves no key copy")
        _ = try await vault.unlock(password: "correct horse")
        m.lock()
        XCTAssertFalse(vault.hasOpenedLocalKey, "lock clears it too")
    }

    private func sample() -> LocalData {
        var d = LocalData(trash: [try! .init(record: .object(["id": .string(UUID().uuidString.lowercased()), "n": .int(3)]), deletedAt: 7)],
                          events: [.init(id: UUID().uuidString.lowercased(), eventType: "item.delete", timestamp: 7)])
        d.ensureStarterCollections(now: 7)
        return d
    }

    func testRoundTripSealed() throws {
        let key = Array(repeating: UInt8(9), count: 32)
        let d = sample()
        try MacLocalStore(directory: dir, localKey: key).save(d)
        let raw = try Data(contentsOf: dir.appendingPathComponent(MacLocalStore.fileName))
        XCTAssertNil(raw.range(of: Data("item.delete".utf8)), "sealed, not plain JSON")
        let (back, message) = MacLocalStore(directory: dir, localKey: key).load()
        XCTAssertNil(message)
        XCTAssertEqual(back, d)
        // A fresh nonce every save.
        try MacLocalStore(directory: dir, localKey: key).save(d)
        XCTAssertNotEqual(try Data(contentsOf: dir.appendingPathComponent(MacLocalStore.fileName)), raw)
        // Another vault's key: reset, file kept aside.
        let (other, msg) = MacLocalStore(directory: dir, localKey: Array(repeating: 1, count: 32)).load()
        XCTAssertEqual(msg, MacLocalStore.resetMessage)
        XCTAssertTrue(other.trash.isEmpty)
        XCTAssertEqual(badFiles().count, 1)
    }

    func testFirstUseHasStarterCollections() {
        let (d, msg) = MacLocalStore(directory: dir, localKey: Array(repeating: 2, count: 32)).load()
        XCTAssertNil(msg)
        XCTAssertEqual(d.collections.map(\.name), LocalData.starterCollections)
    }

    func testCorruptLocalDataResetsWithoutBlockingUnlock() async throws {
        let settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(), kdfParams: cheap)
        let m = MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), startTimer: false)
        await m.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertNotNil(m.localStore)
        XCTAssertNil(m.localDataNotice)
        // Through the lock model (the lock event saves its current data); deleted now, so auto-purge keeps it.
        var data = sample()
        data.trash[0].deletedAt = Int64(Date().timeIntervalSince1970)
        try m.commitLocalData(data)
        m.lock()
        XCTAssertNil(m.localStore, "dropped on lock")
        XCTAssertNil(m.localData)

        await m.unlock(password: "correct horse")
        XCTAssertEqual(m.localData?.trash.count, 1, "reopened with the same key")
        m.lock()

        try Data("garbage".utf8).write(to: dir.appendingPathComponent(MacLocalStore.fileName))
        await m.unlock(password: "correct horse")
        XCTAssertEqual(m.state, .unlocked, "a bad local file never blocks unlock")
        XCTAssertNotNil(m.store)
        XCTAssertEqual(m.localDataNotice, MacLocalStore.resetMessage)
        XCTAssertEqual(m.localData?.trash.count, 0)
        XCTAssertEqual(badFiles().count, 1, "bad file kept as evidence")
    }
}
