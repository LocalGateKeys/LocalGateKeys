import XCTest
import LGKCore
@testable import AppSharedMac

/// The recovery phrase on the Mac (Ruling 9): a `bip39-english-24` wrapper of the local key beside the master-password
/// and Touch ID wrappers; recovering sets a new master password and turns Touch ID off.
@MainActor
final class RecoveryPhraseTests: XCTestCase {
    private var dir: URL!
    private var now = Date(timeIntervalSince1970: 1_800_000_000)
    private var bio: FakeBiometricKeyStore!
    private var settings: AppSettings!
    private var suite: String!
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
    private let master = "correct horse"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-recovery-\(UUID().uuidString)", isDirectory: true)
        bio = FakeBiometricKeyStore()
        suite = "lgk-recovery-tests-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        UserDefaults().removePersistentDomain(forName: suite)
    }

    private func makeVault() -> MacVault {
        MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: bio,
                 clock: { [unowned self] in self.now }, random: SystemRandomSource(), kdfParams: cheap)
    }

    private func keyFile() throws -> MasterKeyFile { try MasterPasswordUnlock.readKeyFile(directory: dir) }

    /// A vault with a confirmed phrase; returns the vault and the phrase.
    private func enrolled(touchID: Bool = false) async throws -> (MacVault, String) {
        let v = makeVault()
        _ = try await v.create(password: master, enableTouchID: touchID)
        let prepared = try await v.prepareRecovery(password: master)
        try await v.confirmRecovery(prepared)
        return (v, prepared.phrase)
    }

    private func otherPhrase() throws -> String { try BIP39.phrase(entropy: Data(repeating: 0x42, count: 32)) }

    func testRecoverSetsNewPasswordAndDisablesTouchID() async throws {
        let model = MacLockModel(vault: makeVault(), settings: settings, events: FakeSystemEvents(),
                                 clock: { [unowned self] in self.now }, startTimer: false)
        await model.create(password: master, confirm: master, touchID: true)
        XCTAssertTrue(settings.touchIDUnlock)
        XCTAssertNotNil(bio.stored)
        let prepared = try await model.prepareRecoveryPhrase(password: master)
        XCTAssertEqual(prepared.phrase.split(separator: " ").count, 24)
        try await model.confirmRecoveryPhrase(prepared)
        model.lock()
        XCTAssertTrue(model.hasRecoveryPhrase)

        // Typed with capitals and extra spaces, as a user might.
        let typed = "  " + prepared.phrase.uppercased().replacingOccurrences(of: " ", with: "   ") + "\n"
        let recovered = await model.recover(phrase: typed, newPassword: "battery staple", confirm: "battery staple")
        XCTAssertTrue(recovered)
        XCTAssertEqual(model.state, .unlocked)
        XCTAssertFalse(settings.touchIDUnlock)
        XCTAssertNil(bio.stored)
        XCTAssertEqual(model.recoveryNotice, MacLockModel.recoveredNotice)
        model.lock()

        let v = makeVault()
        _ = try await v.unlock(password: "battery staple")
        do { _ = try await v.unlock(password: master); XCTFail("old password still opens") }
        catch { XCTAssertEqual(error as? MacVaultError, .wrongPassword(retryAfter: nil)) }
        // The same phrase keeps working.
        XCTAssertNotNil(try keyFile().recovery)
        _ = try await v.recover(phrase: prepared.phrase, newPassword: "third password")
        _ = try await makeVault().unlock(password: "third password")
    }

    func testRecoverMismatchAndShortPasswordRefused() async throws {
        let (v, phrase) = try await enrolled()
        let model = MacLockModel(vault: v, settings: settings, events: FakeSystemEvents(),
                                 clock: { [unowned self] in self.now }, startTimer: false)
        let mismatch = await model.recover(phrase: phrase, newPassword: "battery staple", confirm: "battery stable")
        XCTAssertFalse(mismatch)
        XCTAssertEqual(model.message, "The new passwords did not match.")
        do { _ = try await v.recover(phrase: phrase, newPassword: "short"); XCTFail() }
        catch { XCTAssertEqual(error as? MacVaultError, .passwordTooShortFor(minimum: 12)) }
        _ = try await v.unlock(password: master)   // nothing changed
    }

    func testWrongPhraseIsThrottledAndPlain() async throws {
        let (v, _) = try await enrolled()
        let wrong = try otherPhrase()
        for _ in 1...5 {
            do { _ = try await v.recover(phrase: wrong, newPassword: "battery staple"); XCTFail() }
            catch { XCTAssertEqual(error as? MacVaultError, .wrongRecoveryPhrase(retryAfter: nil)) }
        }
        do { _ = try await v.recover(phrase: wrong, newPassword: "battery staple"); XCTFail() }
        catch { XCTAssertEqual(error as? MacVaultError, .wrongRecoveryPhrase(retryAfter: now.addingTimeInterval(2))) }
        // The shared throttle: passwords wait too, and so does a malformed phrase.
        do { _ = try await v.unlock(password: master); XCTFail() }
        catch { XCTAssertEqual(error as? MacVaultError, .throttled(until: now.addingTimeInterval(2))) }
        do { _ = try await v.recover(phrase: "abandon", newPassword: "battery staple"); XCTFail() }
        catch { XCTAssertEqual(error as? MacVaultError, .throttled(until: now.addingTimeInterval(2))) }
        now = now.addingTimeInterval(2)
        // A malformed phrase names the problem and is not counted (no secret was tried).
        let words = wrong.split(separator: " ")
        do { _ = try await v.recover(phrase: words.dropLast().joined(separator: " "), newPassword: "battery staple"); XCTFail() }
        catch { XCTAssertEqual(error as? RecoveryPhraseError, RecoveryPhraseError("A recovery phrase has exactly 24 words")) }
        XCTAssertNil(v.retryAfter)
        let message = MacLockModel.describe(MacVaultError.wrongRecoveryPhrase(retryAfter: nil), now: now)
        XCTAssertEqual(message, "This recovery phrase does not belong to this vault, or it was regenerated.")
        XCTAssertFalse(message!.contains(words[0]))
    }

    func testConfirmThreeWords() throws {
        let phrase = try BIP39.phrase(entropy: Data((0..<32).map { UInt8(truncatingIfNeeded: $0 * 37 + 5) }))
        let words = phrase.split(separator: " ").map(String.init)
        var seen = Set<[Int]>()
        for _ in 0..<20 {
            let challenge = try RecoveryPhraseChallenge(phrase: phrase)
            XCTAssertEqual(challenge.positions.count, 3)
            XCTAssertEqual(challenge.positions, challenge.positions.sorted())
            XCTAssertEqual(Set(challenge.positions).count, 3)
            XCTAssertTrue(challenge.positions.allSatisfy { (1...24).contains($0) })
            seen.insert(challenge.positions)
            let right = challenge.positions.map { words[$0 - 1] }
            XCTAssertTrue(challenge.verify(right))
            XCTAssertTrue(challenge.verify(right.map { " " + $0.uppercased() + " " }))
            if right != Array(right.reversed()) { XCTAssertFalse(challenge.verify(Array(right.reversed()))) }
            XCTAssertFalse(challenge.verify(Array(right.prefix(2))))
            XCTAssertFalse(challenge.verify([right[0], right[1], "zzz"]))
        }
        XCTAssertGreaterThan(seen.count, 1)
        XCTAssertThrowsError(try RecoveryPhraseChallenge(phrase: "only three words"))
    }

    func testNothingSavedUntilConfirmed() async throws {
        let v = makeVault()
        _ = try await v.create(password: master, enableTouchID: false)
        let prepared = try await v.prepareRecovery(password: master)
        XCTAssertNil(try keyFile().recovery)
        XCTAssertFalse(v.hasRecoveryPhrase)
        // A password change in between makes the prepared file stale; it is refused, not written over the new one.
        try await v.changePassword(old: master, new: "battery staple")
        do { try await v.confirmRecovery(prepared); XCTFail("stale prepared phrase written") } catch {}
        _ = try await v.unlock(password: "battery staple")
        let fresh = try await v.prepareRecovery(password: "battery staple")
        try await v.confirmRecovery(fresh)
        XCTAssertTrue(v.hasRecoveryPhrase)
        do { _ = try await v.recover(phrase: prepared.phrase, newPassword: "battery staple 2"); XCTFail() }
        catch { XCTAssertEqual(error as? MacVaultError, .wrongRecoveryPhrase(retryAfter: nil)) }
    }

    func testChangePasswordKeepsAndRemoveDropsThePhrase() async throws {
        let (v, phrase) = try await enrolled()
        try await v.changePassword(old: master, new: "battery staple")
        XCTAssertTrue(v.hasRecoveryPhrase)
        _ = try await v.recover(phrase: phrase, newPassword: "third password")
        try await v.removeRecovery(password: "third password")
        XCTAssertFalse(v.hasRecoveryPhrase)
        do { _ = try await v.recover(phrase: phrase, newPassword: "fourth password"); XCTFail() }
        catch { XCTAssertEqual(error as? RecoveryPhraseError, RecoveryPhraseError("This vault has no recovery phrase")) }
    }

    /// Ruling 9: the phrase that protects the Mac store also opens a `vault.json` the Mac writes (a full backup).
    func testBackupVaultOpensWithThePhrase() async throws {
        let (v, phrase) = try await enrolled()
        let fetched = try await v.recoveryVaultKey(password: master)
        var key = try XCTUnwrap(fetched)
        defer { key.wipe() }
        let vault = try DesktopVaultFile.seal(items: [], settings: .object([:]), password: "fixture master password 2026",
                                              random: SystemRandomSource(), kdf: .init(timeCost: 1, memoryKiB: 8192, parallelism: 1),
                                              recovery: key)
        XCTAssertTrue(try DesktopVaultFile.open(vault, recoveryEntropy: try BIP39.entropy(from: phrase)).recoveryEnrolled)
        try await v.removeRecovery(password: master)
        let none = try await v.recoveryVaultKey(password: master)
        XCTAssertNil(none)
    }

    /// A phrase made, replaced or removed from the main window's Recovery centre relocks and reopens the window:
    /// the reopened window goes back to the page it came from and says what happened (the sheet is gone by then).
    func testPhraseChangeReopensWithNoticeAndReturn() async throws {
        let model = MacLockModel(vault: makeVault(), settings: settings, events: FakeSystemEvents(),
                                 clock: { [unowned self] in self.now }, startTimer: false)
        await model.create(password: master, confirm: master, touchID: false)
        XCTAssertFalse(model.takeRotationReturn(), "an ordinary unlock does not return anywhere")

        try await model.confirmRecoveryPhrase(try await model.prepareRecoveryPhrase(password: master))
        XCTAssertEqual(model.state, .unlocked)
        XCTAssertEqual(model.recoveryNotice, RecoveryPhraseSheet.confirmed)
        XCTAssertTrue(model.takeRotationReturn())
        XCTAssertFalse(model.takeRotationReturn(), "taken once")

        try await model.confirmRecoveryPhrase(try await model.prepareRecoveryPhrase(password: master))
        XCTAssertEqual(model.recoveryNotice, RecoveryPhraseSheet.confirmed + " " + MacLockModel.oldPhraseNote)
        XCTAssertTrue(model.takeRotationReturn())

        try await model.removeRecoveryPhrase(password: master)
        XCTAssertEqual(model.recoveryNotice, MacLockModel.phraseRemovedText + " " + MacLockModel.oldPhraseNote)
        XCTAssertTrue(model.takeRotationReturn())
        XCTAssertFalse(MacLockModel.oldPhraseNote.contains("PC"))
    }

    func testNewVaultClearsBackupHistory() async throws {
        let history = BackupHistory(defaults: settings.defaults)
        history.lastBackup = now; history.lastVerified = now
        let model = MacLockModel(vault: makeVault(), settings: settings, events: FakeSystemEvents(),
                                 clock: { [unowned self] in self.now }, startTimer: false)
        await model.create(password: master, confirm: master, touchID: false)
        XCTAssertNil(history.lastBackup)
        XCTAssertNil(history.lastVerified)
    }

    /// The window remembers its page only when a rotation starts (just before the relock).
    func testBeforeRotationLockRunsOnlyForRotation() async throws {
        let model = MacLockModel(vault: makeVault(), settings: settings, events: FakeSystemEvents(),
                                 clock: { [unowned self] in self.now }, startTimer: false)
        await model.create(password: master, confirm: master, touchID: false)
        var calls: [MacLockModel.State] = []
        model.setBeforeRotationLock { calls.append(model.state) }
        model.lock()
        await model.unlock(password: master)
        XCTAssertEqual(calls, [], "an ordinary lock does not")
        try await model.confirmRecoveryPhrase(try await model.prepareRecoveryPhrase(password: master))
        XCTAssertEqual(calls, [.unlocked], "once, before the relock")
    }
}
