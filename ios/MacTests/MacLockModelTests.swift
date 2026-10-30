import XCTest
import LGKCore
@testable import AppSharedMac

/// Test double: `fireScreenLock()`, `fireSleep()`, and a settable system idle time.
@MainActor
final class FakeSystemEvents: SystemEvents {
    let screenLocked: AsyncStream<Void>
    let willSleep: AsyncStream<Void>
    private let lockedCont: AsyncStream<Void>.Continuation
    private let sleepCont: AsyncStream<Void>.Continuation
    var idle: TimeInterval = .infinity

    init() {
        (screenLocked, lockedCont) = AsyncStream<Void>.makeStream()
        (willSleep, sleepCont) = AsyncStream<Void>.makeStream()
    }

    func fireScreenLock() { lockedCont.yield() }
    func fireSleep() { sleepCont.yield() }
    func idleSeconds() -> TimeInterval { idle }
}

@MainActor
final class MacLockModelTests: XCTestCase {
    private var dir: URL!
    private var now = Date(timeIntervalSince1970: 1_800_000_000)
    private var events: FakeSystemEvents!
    private var settings: AppSettings!
    private var suite: String!
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-lock-\(UUID().uuidString)", isDirectory: true)
        suite = "lgk-lock-tests-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        events = FakeSystemEvents()
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        UserDefaults().removePersistentDomain(forName: suite)
    }

    private var vault: MacVault!
    private var kdfHook: (@MainActor () async -> Void)?
    private var afterKdfHook: (@MainActor () async -> Void)?

    private func makeModel(biometric: FakeBiometricKeyStore = FakeBiometricKeyStore()) -> MacLockModel {
        vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: biometric,
                             clock: { [unowned self] in self.now }, kdfParams: cheap,
                             beforeKDF: { [unowned self] in await self.kdfHook?() },
                             afterKDF: { [unowned self] in await self.afterKdfHook?() })
        return MacLockModel(vault: vault, settings: settings, events: events, clock: { [unowned self] in self.now },
                            startTimer: false)
    }

    private func unlockedModel() async -> MacLockModel {
        let m = makeModel()
        await m.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertEqual(m.state, .unlocked)
        return m
    }

    /// A lock while a strict-login password check runs: the check refuses and the gated copy never runs.
    func testLockDuringGatedCheckReleasesNothing() async {
        let m = await unlockedModel()
        let gate = StrictItemGate(passwords: m)
        let item = VaultItem(id: "s", record: ["kind": .string("web"), "title": .string("Bank"),
                                               "policy": .object(["require_master_password": .bool(true)])])!
        var performed = false
        gate.release(item, action: "Copy password") { performed = true }
        kdfHook = { m.lock() }   // the vault locks while Argon2 is about to run
        await gate.submit("correct horse")
        kdfHook = nil
        XCTAssertEqual(m.state, .locked)
        XCTAssertFalse(performed, "nothing released after a lock")
        XCTAssertNil(gate.pending)
        do { try await m.verifyPassword("correct horse"); XCTFail("refuses while locked") } catch {}
    }

    /// A lock that lands after Argon2 returned but before the release: the check refuses, nothing is released.
    func testLockAfterKDFBeforeReleaseReleasesNothing() async {
        let m = await unlockedModel()
        let gate = StrictItemGate(passwords: m)
        let item = VaultItem(id: "s", record: ["kind": .string("web"), "title": .string("Bank"),
                                               "policy": .object(["require_master_password": .bool(true)])])!
        var performed = false
        gate.release(item, action: "Copy password") { performed = true }
        afterKdfHook = { m.lock() }   // Argon2 has accepted the password; the vault locks before the release
        await gate.submit("correct horse")
        afterKdfHook = nil
        XCTAssertEqual(m.state, .locked)
        XCTAssertFalse(performed, "nothing released after a lock")
        XCTAssertNil(gate.pending)
        do { try await m.verifyPassword("correct horse"); XCTFail("refuses while locked") } catch {}
    }

    func testVerifyPasswordRefusesWhenLockedAfterKDF() async {
        let m = await unlockedModel()
        afterKdfHook = { m.lock() }
        do { try await m.verifyPassword("correct horse"); XCTFail("refuses across a lock") } catch is CancellationError {} catch { XCTFail("\(error)") }
        afterKdfHook = nil
    }

    /// Reminder notifications of an old vault go before a new one is created, and at launch with no vault.
    func testFreshVaultHookRunsBeforeCreate() async {
        let m = makeModel()
        var cleared = 0
        var clearedAtKDF = -1
        MacAppEnvironment.wireReminderReset(model: m) { cleared += 1 }
        XCTAssertEqual(m.state, .noVault)
        await Task.yield(); await Task.yield()
        XCTAssertEqual(cleared, 1, "launch with no vault clears")
        kdfHook = { await Task.yield(); await Task.yield(); clearedAtKDF = cleared }
        await m.create(password: "correct horse", confirm: "correct horse", touchID: false)
        kdfHook = nil
        XCTAssertEqual(clearedAtKDF, 2, "cleared before the new vault is made")
        XCTAssertEqual(m.state, .unlocked)
    }

    func testNoClearAtLaunchWhenVaultExists() async {
        let first = await unlockedModel()
        first.lock()
        let m = makeModel()
        XCTAssertEqual(m.state, .locked)
        var cleared = 0
        MacAppEnvironment.wireReminderReset(model: m) { cleared += 1 }
        await Task.yield(); await Task.yield()
        XCTAssertEqual(cleared, 0)
    }

    /// Replaces the once-per-unlock "Copy password?" check: the routine re-authentication's grace covers
    /// further copies, and asks again after lock and unlock.
    func testPasswordCopyConfirmedOncePerUnlock() async {
        let m = await unlockedModel()
        let gate = StrictItemGate(passwords: m)
        let item = VaultItem(id: "p", record: ["kind": .string("web"), "title": .string("Mail"), "password": .string("pw")])!
        var copies = 0
        gate.releaseRoutine(item, action: "Copy password") { copies += 1 }
        XCTAssertNotNil(gate.pending, "first copy asks")
        await gate.submit("correct horse")
        gate.releaseRoutine(item, action: "Copy password") { copies += 1 }
        XCTAssertEqual(copies, 2, "second copy does not")
        m.lock()
        await m.unlock(password: "correct horse")
        XCTAssertEqual(m.state, .unlocked)
        gate.releaseRoutine(item, action: "Copy password") { copies += 1 }
        XCTAssertNotNil(gate.pending, "asks again after lock and unlock")
        XCTAssertEqual(copies, 2)
    }

    /// Lets the event-listening tasks run.
    private func settle() async { for _ in 0..<20 { await Task.yield() } }

    func testAutoLockAfterTimeout() async {
        let m = await unlockedModel()
        XCTAssertEqual(m.autoLockRemaining, 300)
        now += 299; m.tick()
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertEqual(m.autoLockRemaining, 1)
        now += 1; m.tick()
        XCTAssertEqual(m.state, .locked)
        XCTAssertNil(m.autoLockRemaining)
    }

    func testActivityResetsTimer() async {
        let m = await unlockedModel()
        now += 250; m.noteActivity()
        now += 250; m.tick()
        XCTAssertEqual(m.state, .unlocked)
        now += 50; m.tick()
        XCTAssertEqual(m.state, .locked)
    }

    func testSystemActivityResetsTimer() async {
        let m = await unlockedModel()
        events.idle = 10
        now += 1000; m.tick()
        XCTAssertEqual(m.state, .unlocked)
    }

    func testNeverIdleLockAndMaxSession() async {
        settings.idleLock = .never
        settings.maxSessionSeconds = 3600
        let m = await unlockedModel()
        now += 3599; m.tick()
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertNil(m.autoLockRemaining)
        now += 1; m.tick()
        XCTAssertEqual(m.state, .locked)
    }

    func testLocksOnScreenLock() async {
        let m = await unlockedModel()
        events.fireScreenLock(); await settle()
        XCTAssertEqual(m.state, .locked)
    }

    func testScreenLockIgnoredWhenSettingOff() async {
        settings.lockOnScreenLock = false
        let m = await unlockedModel()
        events.fireScreenLock(); await settle()
        XCTAssertEqual(m.state, .unlocked)
    }

    func testLocksOnSleep() async {
        let m = await unlockedModel()
        events.fireSleep(); await settle()
        XCTAssertEqual(m.state, .locked)
    }

    func testLockDropsStore() async {
        let m = await unlockedModel()
        var hooks = 0
        m.onLock.append { hooks += 1 }
        XCTAssertNotNil(m.store)
        m.lock()
        XCTAssertNil(m.store)
        XCTAssertEqual(m.state, .locked)
        XCTAssertEqual(hooks, 1)
        m.lock()
        XCTAssertEqual(hooks, 1, "locking while locked runs no hooks")
        await m.unlock(password: "correct horse")
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertNotNil(m.store)
    }

    func testCreateRequiresMatchingPasswords() async {
        let m = makeModel()
        XCTAssertEqual(m.state, .noVault)
        await m.create(password: "correct horse", confirm: "correct house", touchID: false)
        XCTAssertEqual(m.state, .noVault)
        XCTAssertEqual(m.message, "The passwords don't match.")
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent(MacVault.keyFileName).path))
        XCTAssertTrue(((try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []).isEmpty, "no vault files written")
        await m.create(password: "short", confirm: "short", touchID: false)
        XCTAssertEqual(m.state, .noVault)
        XCTAssertEqual(m.message, "Use at least 8 characters.")
    }

    func testWrongPasswordAndThrottleMessages() async {
        let m = await unlockedModel()
        m.lock()
        await m.unlock(password: "wrong one")
        XCTAssertEqual(m.message, "That password isn't right.")
        for _ in 0..<5 { await m.unlock(password: "wrong one") }
        XCTAssertEqual(m.message, "That password isn't right. Too many attempts. Try again in 2 s.")
        await m.unlock(password: "correct horse")
        XCTAssertEqual(m.message, "Too many attempts. Try again in 2 s.")
        XCTAssertEqual(m.state, .locked)
        now += 2
        await m.unlock(password: "correct horse")
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertNil(m.message)
    }

    /// Holds the attempt at the vault's pre-Argon2 gate, fires `trigger`, lets the listeners run, then
    /// releases the gate: the vault must stay locked with no store and no lock hooks.
    private func lockDuring(_ m: MacLockModel, _ trigger: () -> Void, _ op: @escaping @MainActor () async -> Void) async {
        var hooks = 0
        m.onLock.append { hooks += 1 }
        let gate = TestGate()
        kdfHook = { await gate.pass() }
        let t = Task { @MainActor in await op() }
        await gate.reached()
        kdfHook = nil
        trigger()
        await settle()
        XCTAssertTrue(m.isBusy, "the lock arrived while the attempt runs")
        gate.open()
        await t.value
        XCTAssertNil(m.store)
        XCTAssertEqual(m.state, .locked)
        XCTAssertEqual(hooks, 0, "the vault never opened, so no lock hooks ran")
    }

    func testScreenLockDuringUnlockStaysLocked() async {
        let m = await unlockedModel(); m.lock()
        await lockDuring(m, { events.fireScreenLock() }) { await m.unlock(password: "correct horse") }
    }

    func testSleepDuringUnlockStaysLocked() async {
        let m = await unlockedModel(); m.lock()
        await lockDuring(m, { events.fireSleep() }) { await m.unlock(password: "correct horse") }
    }

    func testManualLockDuringUnlockStaysLocked() async {
        let m = await unlockedModel(); m.lock()
        await lockDuring(m, { m.lock() }) { await m.unlock(password: "correct horse") }
    }

    func testLockDuringCreateStaysLocked() async {
        let m = makeModel()
        await lockDuring(m, { events.fireScreenLock() }) {
            await m.create(password: "correct horse", confirm: "correct horse", touchID: false)
        }
        await m.unlock(password: "correct horse")
        XCTAssertEqual(m.state, .unlocked)
    }

    func testCreateClearsLaunchTouchIDPrompt() async {
        settings.touchIDUnlock = true
        let m = makeModel()
        await m.create(password: "correct horse", confirm: "correct horse", touchID: true)
        XCTAssertEqual(m.state, .unlocked)
        m.lock()
        XCTAssertFalse(m.takeLaunchTouchIDPrompt())
    }

    func testTouchIDPromptOnlyAtLaunch() async {
        settings.touchIDUnlock = true
        let m = makeModel()
        XCTAssertTrue(m.takeLaunchTouchIDPrompt())
        XCTAssertFalse(m.takeLaunchTouchIDPrompt())
    }

    func testCancelledTouchIDShowsNothing() {
        XCTAssertNil(MacLockModel.describe(BiometricKeyError.cancelled, now: now))
    }

    func testTouchIDSettingOnlyWhenItemStored() async {
        let noTouchID = FakeBiometricKeyStore()
        noTouchID.available = false
        let m = makeModel(biometric: noTouchID)
        await m.create(password: "correct horse", confirm: "correct horse", touchID: true)
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertFalse(settings.touchIDUnlock, "no Touch ID item was stored")

        try? FileManager.default.removeItem(at: dir)
        let bio = FakeBiometricKeyStore()
        let m2 = makeModel(biometric: bio)
        await m2.create(password: "correct horse", confirm: "correct horse", touchID: true)
        XCTAssertNotNil(bio.stored)
        XCTAssertTrue(settings.touchIDUnlock)
    }
}
