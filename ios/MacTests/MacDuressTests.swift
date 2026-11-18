import XCTest
import LGKCore
@testable import AppSharedMac

/// Sub-plan 08 on the Mac: the duress password's second vault beside `master-key.json`, the unlock routing, the hold
/// (master password, Touch ID and recovery phrase refused and counted), the AutoFill extension's refusal, removal
/// without a trace, and the lock model's second session (Settings, password change, lock).
@MainActor
final class MacDuressTests: XCTestCase {
    /// The wall clock and the monotonic clock of the hold (`PhoneDuress.BootTime`).
    final class HoldClock: @unchecked Sendable {
        private let lock = NSLock()
        private var wall: Int64 = 1_800_000_000
        private var mono: Int64 = 50_000
        var now: Int64 { lock.withLock { wall } }
        var bootTime: PhoneDuress.BootTime { lock.withLock { PhoneDuress.BootTime(boot: "boot-a", seconds: mono) } }
        func advance(_ seconds: Int64) { lock.withLock { wall += seconds; mono += seconds } }
    }

    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
    private let master = "correct horse"
    private let duressPassword = "copper meadow 7"
    private var dir: URL!
    private var now = Date(timeIntervalSince1970: 1_800_000_000)
    private var hold: HoldClock!
    private var bio: FakeBiometricKeyStore!
    private var session: DuressSession!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-macduress-\(UUID().uuidString)", isDirectory: true)
        hold = HoldClock()
        bio = FakeBiometricKeyStore()
        session = DuressSession()
    }

    override func tearDown() async throws { try? FileManager.default.removeItem(at: dir) }

    private func makeVault() -> MacVault {
        let v = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: bio,
                         clock: { [unowned self] in self.now }, random: SystemRandomSource(), kdfParams: cheap)
        wire(v)
        return v
    }

    private func wire(_ v: MacVault) {
        let c = hold!
        v.duressSession = session
        v.duressNow = { c.now }
        v.duressBootTime = { c.bootTime }
    }

    /// Both clocks move: the throttle's and the hold's.
    private func advance(_ seconds: Int64) {
        now = now.addingTimeInterval(TimeInterval(seconds))
        hold.advance(seconds)
    }

    private func addNote(_ store: LocalStore) throws {
        store.limitHints = nil
        let note: JSONValue = .object(["ns": .string("item"),
                                       "record": .object(["id": .string("n1"), "kind": .string("note")])])
        try store.commit(StoreChange(baseRevision: 0, records: ["n1": note], meta: [:], sync: nil))
    }

    /// A real vault with one note and the duress password set up (`hours`).
    private func vaultWithDuress(hours: Int = 1, touchID: Bool = false) async throws -> MacVault {
        let v = makeVault()
        let store = try await v.create(password: master, enableTouchID: touchID)
        try addNote(store)
        try await v.setUpDuress(masterPassword: master, duressPassword: duressPassword, hours: hours, real: try store.load())
        XCTAssertTrue(v.duressConfigured)
        XCTAssertFalse(v.duressHeld)
        return v
    }

    private func assertThrows<E: Error & Equatable>(_ expected: E, file: StaticString = #filePath, line: UInt = #line,
                                                    _ op: () async throws -> Void) async {
        do { try await op(); XCTFail("expected \(expected)", file: file, line: line) }
        catch { XCTAssertEqual(error as? E, expected, file: file, line: line) }
    }

    private func assertDuress(_ code: String, file: StaticString = #filePath, line: UInt = #line,
                              _ op: () async throws -> Void) async {
        do { try await op(); XCTFail("expected DuressError(\(code))", file: file, line: line) }
        catch { XCTAssertEqual((error as? DuressError)?.code, code, "\(error)", file: file, line: line) }
    }

    private func exists(_ url: URL) -> Bool { FileManager.default.fileExists(atPath: url.path) }

    // MARK: - Unlock routing

    func testRealDuressAndWrongPasswordsRoute() async throws {
        let v = try await vaultWithDuress()
        let real = try await v.unlock(password: master)
        XCTAssertNotNil(try real.load().records["n1"])
        XCTAssertFalse(v.openedSecond)
        XCTAssertFalse(session.isOpen)

        await assertThrows(MacVaultError.wrongPassword(retryAfter: nil)) { _ = try await v.unlock(password: "wrong horse!") }
        XCTAssertFalse(v.duressHeld, "a wrong password holds nothing")

        let second = try await v.unlock(password: duressPassword)
        let records = try second.load().records
        XCTAssertNil(records["n1"], "the second vault holds none of the real items")
        XCTAssertFalse(records.isEmpty, "it holds the sample items")
        XCTAssertTrue(v.openedSecond)
        XCTAssertTrue(session.isOpen)
        XCTAssertEqual(session.secondDir?.standardizedFileURL, v.duressFiles.dir.standardizedFileURL)
        XCTAssertTrue(exists(v.duressFiles.session), "the extensions' marker")
        XCTAssertTrue(v.duressHeld)
        XCTAssertNil(v.retryAfter, "a duress unlock counts as a right one")
    }

    // MARK: - The hold

    func testHoldRefusesTheMasterPasswordAndCountsIt() async throws {
        let v = try await vaultWithDuress(hours: 1)
        _ = try await v.unlock(password: duressPassword)
        v.closeSecondSession()
        for _ in 1...5 { await assertThrows(MacVaultError.wrongPassword(retryAfter: nil)) { _ = try await v.unlock(password: self.master) } }
        await assertThrows(MacVaultError.wrongPassword(retryAfter: now.addingTimeInterval(2))) {
            _ = try await v.unlock(password: self.master)
        }
        advance(3600 + 60)
        XCTAssertFalse(v.duressHeld)
        let store = try await v.unlock(password: master)
        XCTAssertNotNil(try store.load().records["n1"])
        XCTAssertFalse(exists(v.duressFiles.hold), "the finished hold is removed on the real unlock")
        XCTAssertTrue(v.duressConfigured, "the duress password stays set up")
    }

    func testTouchIDIsRefusedWhileHeld() async throws {
        let v = try await vaultWithDuress(touchID: true)
        XCTAssertNotNil(bio.stored)
        _ = try await v.unlock(password: duressPassword)
        v.closeSecondSession()
        await assertThrows(MacVaultError.biometricUnavailable) { _ = try await v.unlockWithTouchID(reason: "test") }
        advance(3600 + 60)
        _ = try await v.unlockWithTouchID(reason: "test")
    }

    func testRecoveryPhraseIsRefusedWhileHeld() async throws {
        let v = makeVault()
        _ = try await v.create(password: master, enableTouchID: false)
        let prepared = try await v.prepareRecovery(password: master)
        let phrase = prepared.phrase
        let rotated = try await v.confirmRecovery(prepared)
        try await v.setUpDuress(masterPassword: master, duressPassword: duressPassword, hours: 1, real: try rotated.load())
        _ = try await v.unlock(password: duressPassword)
        v.closeSecondSession()
        await assertThrows(MacVaultError.wrongRecoveryPhrase(retryAfter: nil)) {
            _ = try await v.recover(phrase: phrase, newPassword: "violet harbour engine 2026")
        }
        advance(3600 + 60)
        _ = try await v.recover(phrase: phrase, newPassword: "violet harbour engine 2026")
        XCTAssertFalse(v.duressHeld)
    }

    // MARK: - The master password and the duress password

    func testNewMasterPasswordMayNotBeNearTheDuressPassword() async throws {
        let v = try await vaultWithDuress()
        await assertDuress("near_duress") { _ = try await v.changePassword(old: self.master, new: self.duressPassword) }
        await assertDuress("near_duress") { _ = try await v.changePassword(old: self.master, new: "copper meadow 8") }
        // A second setup while one exists is refused.
        let real = try await v.unlock(password: master)
        await assertDuress("exists") {
            try await v.setUpDuress(masterPassword: self.master, duressPassword: "silver canyon 31", hours: 1,
                                    real: try real.load())
        }
    }

    func testSetupRefusesSameAndClose() async throws {
        let v = makeVault()
        let store = try await v.create(password: "correct horse battery", enableTouchID: false)
        let real = try store.load()
        await assertDuress("same") {
            try await v.setUpDuress(masterPassword: "correct horse battery", duressPassword: "correct horse battery",
                                    hours: 1, real: real)
        }
        await assertDuress("close") {
            try await v.setUpDuress(masterPassword: "correct horse battery", duressPassword: "correct horse batterx",
                                    hours: 1, real: real)
        }
        XCTAssertFalse(v.duressConfigured)
        XCTAssertFalse(exists(v.duressFiles.dir))
    }

    /// A key rotation (password change) seals `duress.bin` under the new key: the one-edit check still works after it.
    func testRotationResealsTheRealRecord() async throws {
        let v = try await vaultWithDuress()
        _ = try await v.changePassword(old: master, new: "battery staple 99")
        await assertDuress("near_duress") { _ = try await v.changePassword(old: "battery staple 99", new: "copper meadow 8") }
        _ = try await v.unlock(password: duressPassword)
        XCTAssertTrue(v.openedSecond, "the duress password still opens the second vault")
    }

    // MARK: - The AutoFill extension

    func testExtensionOpenerIsBlockedBySessionAndHold() async throws {
        let v = try await vaultWithDuress(hours: 1)
        _ = try await v.unlock(password: duressPassword)
        let c = hold!
        let clock: @Sendable () -> Date = { Date(timeIntervalSince1970: TimeInterval(c.now)) }   // moves with `now`
        // The default check: the session marker the app wrote.
        let plain = ExtensionVaultOpener(directory: dir, biometric: bio, clock: clock, keychain: InMemoryKeychainVault())
        XCTAssertTrue(plain.duressBlocked)
        await assertThrows(MacVaultError.wrongPassword(retryAfter: nil)) { _ = try await plain.open(password: self.master) }

        v.closeSecondSession()
        let files = v.duressFiles
        let opener = ExtensionVaultOpener(directory: dir, biometric: bio, clock: clock,
                                          keychain: InMemoryKeychainVault(),
                                          blocked: { PhoneDuress(files: files, session: DuressSession(), now: { c.now },
                                                                 bootTime: { c.bootTime }).servicesBlocked() })
        XCTAssertTrue(opener.duressBlocked, "held after the session closed")
        await assertThrows(MacVaultError.biometricUnavailable) { _ = try await opener.openWithTouchID(reason: "test") }
        await assertThrows(MacVaultError.wrongPassword(retryAfter: nil)) { try await opener.verifyMasterPassword(self.master) }
        advance(3600 + 60)
        XCTAssertFalse(opener.duressBlocked)
        _ = try await opener.open(password: master)
    }

    // MARK: - The entry points the UI and the extensions call during a hold (docs/PENDING.md, no enrolled finger)

    /// The lock screen's Touch ID button (`MacLockModel.unlockWithTouchID`) during a hold: stays locked, nothing opens,
    /// and the master password is refused too; after the hold both work again.
    func testLockScreenTouchIDButtonIsRefusedWhileHeld() async throws {
        suite = "lgk-duress-tests-\(UUID().uuidString)"
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        let settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        let v = try await vaultWithDuress(touchID: true)
        let m = MacLockModel(vault: v, settings: settings, events: FakeSystemEvents(), clock: { [unowned self] in self.now },
                             startTimer: false)
        await m.unlock(password: duressPassword)
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertTrue(m.isSecondSession)
        m.lock()
        v.closeSecondSession()
        XCTAssertTrue(v.duressHeld)
        await m.unlockWithTouchID()
        XCTAssertNotEqual(m.state, .unlocked, "Touch ID opened nothing during the hold")
        XCTAssertNil(m.store)
        await m.unlock(password: master)
        XCTAssertNotEqual(m.state, .unlocked, "the master password opened nothing during the hold")
        advance(3600 + 60)
        await m.unlockWithTouchID()
        XCTAssertEqual(m.state, .unlocked, "Touch ID works again after the hold")
        XCTAssertFalse(m.isSecondSession)
        XCTAssertNotNil(try m.store?.load().records["n1"])
    }

    /// The AutoFill sheet (`MacAutoFillModel`, what CredentialProviderViewController drives): during the hold its
    /// Touch ID button and its master password field both open nothing, no snapshot is held and nothing is filled.
    func testAutoFillSheetRefusesTouchIDAndPasswordWhileHeld() async throws {
        suite = "lgk-duress-tests-\(UUID().uuidString)"
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        let settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        let v = try await vaultWithDuress(touchID: true)
        _ = try await v.unlock(password: duressPassword)
        v.closeSecondSession()
        let files = v.duressFiles
        let c = hold!
        let clock: @Sendable () -> Date = { Date(timeIntervalSince1970: TimeInterval(c.now)) }
        let opener = ExtensionVaultOpener(directory: dir, biometric: bio, clock: clock, keychain: InMemoryKeychainVault(),
                                          blocked: { PhoneDuress(files: files, session: DuressSession(), now: { c.now },
                                                                 bootTime: { c.bootTime }).servicesBlocked() })
        let sink = AutoFillOutcomeRecorder()
        let model = MacAutoFillModel(opener: opener, matcher: AutoFillMatcher(matcher: URLMatcher(rules: nil)),
                                     settings: settings, now: clock)
        model.sink = sink
        model.begin(.list(urls: ["https://example.com"]))
        await model.unlockWithTouchID()
        XCTAssertFalse(model.holdsSnapshot, "Touch ID opened nothing")
        await model.unlock(password: master)
        XCTAssertFalse(model.holdsSnapshot, "the master password opened nothing")
        XCTAssertFalse(sink.outcomes.contains { if case .password = $0 { true } else { false } }, "\(sink.outcomes)")
        advance(3600 + 60)
        model.begin(.list(urls: ["https://example.com"]))
        await model.unlockWithTouchID()
        XCTAssertTrue(model.holdsSnapshot, "after the hold Touch ID opens the vault in the sheet")
    }

    /// The Safari extension's view (`SafariSaveService.duressBlocked`, read from the mirror the app's vault writes
    /// into the Safari group): blocked while the second session is open and through the hold after it closes, so
    /// Safari's save/fill evaluation treats every login as new (`SafariSaveService` `blocked()`).
    func testSafariExtensionSeesTheHoldThroughTheAppsMirror() async throws {
        let safariRoot = dir.deletingLastPathComponent().appendingPathComponent("lgk-macduress-safari-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: safariRoot) }
        let mirror = try XCTUnwrap(SafariSaveFiles.duressMirror(safariRoot: safariRoot))
        let v = try await vaultWithDuress()
        v.duressMirror = mirror
        v.makeDuress().syncMirror()
        XCTAssertFalse(SafariSaveService.duressBlocked(mirror: mirror), "nothing held yet")
        _ = try await v.unlock(password: duressPassword)
        XCTAssertTrue(SafariSaveService.duressBlocked(mirror: mirror), "second session open")
        v.closeSecondSession()
        XCTAssertTrue(exists(mirror.hold), "the hold is mirrored for the Safari extension")
        XCTAssertTrue(SafariSaveService.duressBlocked(mirror: mirror), "held after the session closed")
        advance(3600 + 60)
        _ = try await v.unlock(password: master)
        XCTAssertFalse(SafariSaveService.duressBlocked(mirror: mirror), "the real unlock after the hold clears the mirror")
    }

    // MARK: - Removal

    func testRemovalLeavesNoTrace() async throws {
        let v = try await vaultWithDuress()
        _ = try await v.unlock(password: duressPassword)
        await assertDuress("generic") { _ = try v.removeDuress() }
        XCTAssertTrue(v.duressConfigured, "nothing removed from inside the second session")
        v.closeSecondSession()
        advance(3600 + 60)
        _ = try await v.unlock(password: master)
        XCTAssertTrue(try v.removeDuress())
        XCTAssertFalse(v.duressConfigured)
        for url in [v.duressFiles.dir, v.duressFiles.hold, v.duressFiles.real] { XCTAssertFalse(exists(url), url.path) }
        let names = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        XCTAssertFalse(names.contains { $0.contains("duress") || $0.contains("vault.hold") || $0 == DuressFiles.dirName },
                       "\(names)")
        await assertThrows(MacVaultError.wrongPassword(retryAfter: nil)) { _ = try await v.unlock(password: self.duressPassword) }
    }

    func testCloseSecondSessionEndsIt() async throws {
        let v = try await vaultWithDuress()
        _ = try await v.unlock(password: duressPassword)
        XCTAssertTrue(session.isOpen)
        v.closeSecondSession()
        XCTAssertFalse(session.isOpen)
        XCTAssertNil(session.secondDir)
        XCTAssertFalse(v.openedSecond)
        XCTAssertFalse(exists(v.duressFiles.session))
        XCTAssertTrue(v.duressHeld, "closing the session keeps the hold")
    }

    // MARK: - The lock model (Settings and the second session)

    private var suite: String!

    private func makeModel() -> (MacLockModel, MacVault) {
        suite = "lgk-duress-tests-\(UUID().uuidString)"
        let settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
        let v = makeVault()
        let m = MacLockModel(vault: v, settings: settings, events: FakeSystemEvents(), clock: { [unowned self] in self.now },
                             startTimer: false)
        return (m, v)
    }

    func testSettingsSetUpChecksProAndShowsHours() async throws {
        let (m, v) = makeModel()
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        await m.create(password: master, confirm: master, touchID: false)
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertNil(m.duressStatusHours)
        await assertDuress("pro") {
            try await m.setUpDuress(masterPassword: self.master, duressPassword: self.duressPassword,
                                    confirm: self.duressPassword, hours: 2, isPro: false)
        }
        await assertDuress("mismatch") {
            try await m.setUpDuress(masterPassword: self.master, duressPassword: self.duressPassword,
                                    confirm: "copper meadow 8", hours: 2, isPro: true)
        }
        XCTAssertFalse(v.duressConfigured)
        try await m.setUpDuress(masterPassword: master, duressPassword: duressPassword, confirm: duressPassword,
                                hours: 2, isPro: true)
        XCTAssertEqual(m.duressStatusHours, 2)
        m.lock()
        await m.unlock(password: master)
        XCTAssertEqual(m.duressStatusHours, 2, "read back from duress.bin with the real key")
        try m.removeDuress()
        XCTAssertNil(m.duressStatusHours)
        XCTAssertFalse(v.duressConfigured)
    }

    func testSecondSessionShowsNotSetUpAndChangesOnlyTheSecondVault() async throws {
        let (m, v) = makeModel()
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        await m.create(password: master, confirm: master, touchID: false)
        try await m.setUpDuress(masterPassword: master, duressPassword: duressPassword, confirm: duressPassword,
                                hours: 1, isPro: true)
        m.lock()
        let keyFile = dir.appendingPathComponent(MasterPasswordUnlock.keyFileName)
        let realBefore = try Data(contentsOf: keyFile)
        let recordBefore = try Data(contentsOf: v.duressFiles.real)

        await m.unlock(password: duressPassword)
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertTrue(m.isSecondSession)
        XCTAssertNil(m.duressStatusHours, "Settings shows Not set up")
        await assertDuress("generic") {
            try await m.setUpDuress(masterPassword: self.duressPassword, duressPassword: "silver canyon 31",
                                    confirm: "silver canyon 31", hours: 2, isPro: true)
        }
        await assertDuress("generic") { try m.removeDuress() }
        try await m.changePassword(old: duressPassword, new: "silver canyon 31")
        XCTAssertEqual(try Data(contentsOf: keyFile), realBefore, "the real key file is untouched")
        XCTAssertEqual(try Data(contentsOf: v.duressFiles.real), recordBefore, "the real duress record is untouched")

        m.lock()
        XCTAssertFalse(m.isSecondSession)
        XCTAssertFalse(session.isOpen, "a lock closes the second session")
        XCTAssertFalse(exists(v.duressFiles.session))

        await m.unlock(password: "silver canyon 31")
        XCTAssertTrue(m.isSecondSession, "the new password opens the second vault")
        m.lock()
        advance(3600 + 60)
        await m.unlock(password: master)
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertFalse(m.isSecondSession, "the master password is unchanged")
        XCTAssertEqual(m.duressStatusHours, 1)
    }
}
