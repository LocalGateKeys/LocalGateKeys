import XCTest
import LGKCore
@testable import AppSharedMac

/// Local key rotation (Windows `_rotate_data_key`, vault.py:2798-2830, :2852, :2731): changing the master password,
/// replacing or removing the recovery phrase and recovering all move every sealed file to a new local key, so an
/// old copy of `master-key.json` with the old password or phrase opens nothing current. Crash-safe at every step.
@MainActor
final class KeyRotationTests: XCTestCase {
    private var dir: URL!
    private var bio: FakeBiometricKeyStore!
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
    private let master = "correct horse battery"
    private let safetyName = "before-restore-1800000000000"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-rotate-\(UUID().uuidString)", isDirectory: true)
        bio = FakeBiometricKeyStore()
    }

    override func tearDown() async throws { try? FileManager.default.removeItem(at: dir) }

    private func makeVault() -> MacVault {
        MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: bio, random: SystemRandomSource(), kdfParams: cheap)
    }

    private var keyFileURL: URL { dir.appendingPathComponent(MasterPasswordUnlock.keyFileName) }
    private var safetyFolder: URL { dir.appendingPathComponent("Backups/\(safetyName)", isDirectory: true) }

    private let note: JSONValue = .object(["ns": .string("item"), "record": .object(["id": .string("n1"), "kind": .string("note")])])
    private var localData: LocalData {
        var d = LocalData.empty
        d.ensureStarterCollections(now: 1_800_000_000)
        return d
    }
    private let profile = DesktopProfileStore.Contents(payload: ["license": .string("kept")], unsynced: [])

    /// A vault with an item, Mac-local data, a kept desktop profile and one safety copy, all under its key.
    private func populated(touchID: Bool = true) async throws -> MacVault {
        let v = makeVault()
        let store = try await v.create(password: master, enableTouchID: touchID)
        var key = try XCTUnwrap(v.takeOpenedLocalKey())
        defer { for i in key.indices { key[i] = 0 } }
        try store.commit(StoreChange(baseRevision: 0, records: ["n1": note], meta: [:], sync: nil))
        try MacLocalStore(directory: dir, localKey: key).save(localData)
        let p = DesktopProfileStore(directory: dir, localKey: key)
        try p.seal(profile).write(to: p.fileURL)
        try FileManager.default.createDirectory(at: safetyFolder, withIntermediateDirectories: true)
        try p.sealRecords(["n1": note], revision: 1).write(to: safetyFolder.appendingPathComponent("records.bin"))
        try p.seal(profile).write(to: safetyFolder.appendingPathComponent("desktop-profile.bin"))
        return v
    }

    /// Everything opens under `key` with the content `populated` wrote.
    private func assertAllOpen(with key: [UInt8], file: StaticString = #filePath, line: UInt = #line) throws {
        let store = try MasterPasswordUnlock.openStore(directory: dir, key: key, keychain: InMemoryKeychainVault(), random: SystemRandomSource())
        XCTAssertEqual(try store.load().records["n1"], note, file: file, line: line)
        let (data, message) = MacLocalStore(directory: dir, localKey: key).load()
        XCTAssertNil(message, file: file, line: line)
        XCTAssertEqual(data.collections.count, localData.collections.count, file: file, line: line)
        let p = DesktopProfileStore(directory: dir, localKey: key)
        XCTAssertEqual(try p.load().payload, profile.payload, file: file, line: line)
        XCTAssertEqual(try p.openRecords(safetyFolder.appendingPathComponent("records.bin")).records["n1"], note, file: file, line: line)
        XCTAssertEqual(try p.read(safetyFolder.appendingPathComponent("desktop-profile.bin")).payload, profile.payload, file: file, line: line)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent(KeyRotation.stagingName).path), file: file, line: line)
    }

    /// Nothing current opens under `key` (an old local key).
    private func assertNothingOpens(with key: [UInt8], file: StaticString = #filePath, line: UInt = #line) throws {
        let store = try MasterPasswordUnlock.openStore(directory: dir, key: key, keychain: InMemoryKeychainVault(), random: SystemRandomSource())
        XCTAssertThrowsError(try store.load(), file: file, line: line)
        // A copy, so the failed read does not move the live file aside.
        let copy = dir.appendingPathComponent("copy", isDirectory: true)
        try FileManager.default.createDirectory(at: copy, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: copy) }
        try FileManager.default.copyItem(at: dir.appendingPathComponent(MacLocalStore.fileName), to: copy.appendingPathComponent(MacLocalStore.fileName))
        XCTAssertNotNil(MacLocalStore(directory: copy, localKey: key).load().message, file: file, line: line)
        let p = DesktopProfileStore(directory: dir, localKey: key)
        XCTAssertThrowsError(try p.load(), file: file, line: line)
        XCTAssertThrowsError(try p.openRecords(safetyFolder.appendingPathComponent("records.bin")), file: file, line: line)
        XCTAssertThrowsError(try p.read(safetyFolder.appendingPathComponent("desktop-profile.bin")), file: file, line: line)
    }

    func testPasswordChangeRotatesEverythingAndOldKeyFileOpensNothing() async throws {
        let v = try await populated()
        let oldFile = try Data(contentsOf: keyFileURL)
        XCTAssertNotNil(bio.stored)
        try await v.changePassword(old: master, new: "new master password")
        XCTAssertNil(bio.stored, "Touch ID holds the old key: removed, turned on again by the user")
        XCTAssertFalse(v.touchIDStored)
        _ = try await makeVault().unlock(password: "new master password")
        let reopened = makeVault()
        _ = try await reopened.unlock(password: "new master password")
        try assertAllOpen(with: try XCTUnwrap(reopened.takeOpenedLocalKey()))

        // An old copy of master-key.json with the old password yields the old key, which opens nothing current.
        let old = try JSONDecoder().decode(MasterKeyFile.self, from: oldFile)
        try assertNothingOpens(with: try old.open(password: master))
    }

    func testReplacingThePhraseLeavesTheOldPhraseUseless() async throws {
        let v = try await populated(touchID: false)
        let first = try await v.prepareRecovery(password: master)
        _ = try await v.confirmRecovery(first)
        let oldFile = try JSONDecoder().decode(MasterKeyFile.self, from: Data(contentsOf: keyFileURL))
        let second = try await v.prepareRecovery(password: master)
        _ = try await v.confirmRecovery(second)
        // The old phrase with the old file opens the old key only.
        let oldKey = try RecoveryWrapper.open(try XCTUnwrap(oldFile.recovery), entropy: try BIP39.entropy(from: first.phrase))
        try assertNothingOpens(with: oldKey)
        do { _ = try await v.recover(phrase: first.phrase, newPassword: "new master password"); XCTFail() }
        catch { XCTAssertEqual(error as? MacVaultError, .wrongRecoveryPhrase(retryAfter: nil)) }
        _ = try await v.recover(phrase: second.phrase, newPassword: "new master password")
        let after = makeVault()
        _ = try await after.unlock(password: "new master password")
        try assertAllOpen(with: try XCTUnwrap(after.takeOpenedLocalKey()))
    }

    func testRemovingAndRecoveringRotate() async throws {
        let v = try await populated(touchID: false)
        let prepared = try await v.prepareRecovery(password: master)
        _ = try await v.confirmRecovery(prepared)
        let beforeRecover = try JSONDecoder().decode(MasterKeyFile.self, from: Data(contentsOf: keyFileURL))
        _ = try await v.recover(phrase: prepared.phrase, newPassword: "new master password")
        try assertNothingOpens(with: try beforeRecover.open(password: master))
        let beforeRemove = try JSONDecoder().decode(MasterKeyFile.self, from: Data(contentsOf: keyFileURL))
        _ = try await v.removeRecovery(password: "new master password")
        XCTAssertFalse(v.hasRecoveryPhrase)
        try assertNothingOpens(with: try RecoveryWrapper.open(try XCTUnwrap(beforeRemove.recovery),
                                                             entropy: try BIP39.entropy(from: prepared.phrase)))
        let after = makeVault()
        _ = try await after.unlock(password: "new master password")
        try assertAllOpen(with: try XCTUnwrap(after.takeOpenedLocalKey()))
    }

    /// A crash at each step: the next unlock opens with the old password (before the commit) or the new one (after),
    /// and every file opens under that one key; the other password is refused.
    func testCrashAtEachStepOpensWithOneKey() async throws {
        for step in KeyRotation.Step.allCases {
            try? FileManager.default.removeItem(at: dir)
            let v = try await populated(touchID: false)
            v.rotationCrash = step
            do { try await v.changePassword(old: master, new: "new master password"); XCTFail("\(step)") }
            catch { XCTAssertTrue(error is KeyRotation.SimulatedCrash, "\(step)") }
            let committed = step != .staged
            let reopened = makeVault()
            _ = try await reopened.unlock(password: committed ? "new master password" : master)
            try assertAllOpen(with: try XCTUnwrap(reopened.takeOpenedLocalKey()))
            do { _ = try await makeVault().unlock(password: committed ? master : "new master password"); XCTFail("\(step)") }
            catch { XCTAssertEqual(error as? MacVaultError, .wrongPassword(retryAfter: nil), "\(step)") }
        }
    }

    func testCorruptVaultKeyIsAnErrorNotASilentBackup() async throws {
        let v = makeVault()
        _ = try await v.create(password: master, enableTouchID: false)
        _ = try await v.confirmRecovery(try await v.prepareRecovery(password: master))
        var file = try JSONDecoder().decode(MasterKeyFile.self, from: Data(contentsOf: keyFileURL))
        file.recovery?.vaultKey = Base64.encode(Array(repeating: 1, count: 60))
        try JSONEncoder().encode(file).write(to: keyFileURL)
        do { _ = try await v.recoveryVaultKey(password: master); XCTFail("a damaged recovery key must not be skipped") }
        catch { XCTAssertNotNil(error as? RecoveryPhraseError) }
    }

    func testRecoveredPasswordNeedsTwelveCharacters() async throws {
        let v = makeVault()
        _ = try await v.create(password: master, enableTouchID: false)
        let prepared = try await v.prepareRecovery(password: master)
        _ = try await v.confirmRecovery(prepared)
        do { _ = try await v.recover(phrase: prepared.phrase, newPassword: "elevenchars"); XCTFail() }
        catch { XCTAssertEqual(error as? MacVaultError, .passwordTooShortFor(minimum: 12)) }
        _ = try await v.recover(phrase: prepared.phrase, newPassword: "twelve chars")
    }

    // MARK: - Fix round 2

    /// A refused rename or remove at each roll-forward step stops there, keeps `.rotate` (with READY), and the next
    /// unlock with the new password finishes it with nothing lost.
    func testRollForwardFailureAtEachStepIsRetriedOnNextUnlock() async throws {
        for op in KeyRotation.RollForwardOp.allCases {
            try? FileManager.default.removeItem(at: dir)
            let v = try await populated(touchID: false)
            KeyRotation.injectedFailure = op
            defer { KeyRotation.injectedFailure = nil }
            do { try await v.changePassword(old: master, new: "new master password"); XCTFail("\(op)") }
            catch { XCTAssertEqual(error as? KeyRotation.RollForwardError, KeyRotation.RollForwardError(step: op), "\(op)") }
            XCTAssertTrue(FileManager.default.fileExists(atPath: dir.appendingPathComponent(".rotate/READY").path), "\(op)")
            let reopened = makeVault()
            _ = try await reopened.unlock(password: "new master password")
            try assertAllOpen(with: try XCTUnwrap(reopened.takeOpenedLocalKey()))
            do { _ = try await makeVault().unlock(password: master); XCTFail("\(op)") }
            catch { XCTAssertEqual(error as? MacVaultError, .wrongPassword(retryAfter: nil), "\(op)") }
        }
    }

    private func damageSafetyCopy() throws {
        try Data(repeating: 7, count: 64).write(to: safetyFolder.appendingPathComponent("records.bin"))
    }

    private var setAsideFolder: URL { dir.appendingPathComponent("Backups/\(safetyName).unreadable", isDirectory: true) }

    func testDamagedSafetyCopyIsSetAsideOnPasswordChange() async throws {
        let v = try await populated(touchID: false)
        try damageSafetyCopy()
        try await v.changePassword(old: master, new: "new master password")
        XCTAssertEqual(v.lastRotationSetAside, ["\(safetyName).unreadable"])
        XCTAssertTrue(FileManager.default.fileExists(atPath: setAsideFolder.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: safetyFolder.path))
        XCTAssertTrue(MacFullBackup.safetyCopies(in: dir).isEmpty)
        _ = try await makeVault().unlock(password: "new master password")
    }

    func testDamagedSafetyCopyIsSetAsideOnRecovery() async throws {
        let v = try await populated(touchID: false)
        let prepared = try await v.prepareRecovery(password: master)
        try await v.confirmRecovery(prepared)
        try damageSafetyCopy()
        try await v.recover(phrase: prepared.phrase, newPassword: "new master password")
        XCTAssertEqual(v.lastRotationSetAside, ["\(safetyName).unreadable"])
        XCTAssertTrue(FileManager.default.fileExists(atPath: setAsideFolder.path))
        _ = try await makeVault().unlock(password: "new master password")
    }

    /// A half-written `.rotate/` (no READY) is discarded at the next open; the old key still opens everything.
    func testHalfWrittenStagingIsDiscarded() async throws {
        _ = try await populated(touchID: false)
        let staging = dir.appendingPathComponent(".rotate", isDirectory: true)
        try FileManager.default.createDirectory(at: staging.appendingPathComponent("g9"), withIntermediateDirectories: true)
        try Data("junk".utf8).write(to: staging.appendingPathComponent(MacLocalStore.fileName))
        try Data("9\n".utf8).write(to: staging.appendingPathComponent("CURRENT"))
        let reopened = makeVault()
        _ = try await reopened.unlock(password: master)
        try assertAllOpen(with: try XCTUnwrap(reopened.takeOpenedLocalKey()))
    }

    /// A safety copy deleted between the commit and the roll-forward is skipped, not recreated.
    func testDeletedSafetyCopyIsNotRecreated() async throws {
        let v = try await populated(touchID: false)
        v.rotationCrash = .committed
        do { try await v.changePassword(old: master, new: "new master password"); XCTFail() } catch {}
        try FileManager.default.removeItem(at: safetyFolder)
        let reopened = makeVault()
        _ = try await reopened.unlock(password: "new master password")
        XCTAssertFalse(FileManager.default.fileExists(atPath: safetyFolder.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent(".rotate").path))
        let key = try XCTUnwrap(reopened.takeOpenedLocalKey())
        let store = try MasterPasswordUnlock.openStore(directory: dir, key: key, keychain: InMemoryKeychainVault(), random: SystemRandomSource())
        XCTAssertEqual(try store.load().records["n1"], note)
    }

    /// A bad local-data.bin that cannot be moved aside stops the rotation; nothing is overwritten.
    func testUnmovableBadLocalDataStopsTheRotation() async throws {
        let v = try await populated(touchID: false)
        let url = dir.appendingPathComponent(MacLocalStore.fileName)
        let bad = Data(repeating: 9, count: 80)
        try bad.write(to: url)
        MacLocalStore.failMoveAside = true
        defer { MacLocalStore.failMoveAside = false }
        do { try await v.changePassword(old: master, new: "new master password"); XCTFail() }
        catch { XCTAssertNotNil(error as? MacLocalStore.Failure) }
        XCTAssertEqual(try Data(contentsOf: url), bad)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent(".rotate").path))
        _ = try await makeVault().unlock(password: master)
    }

    // MARK: scheduled-backup secret (Task 9 fix round 1)

    private static let scheduleKDF = FullBackupV2.KDF(timeCost: 1, memoryKiB: 8192, parallelism: 1)
    private static let scheduledPassword = "scheduled backup password"
    private let item: JSONValue = .object(["id": .string("a1"), "kind": .string("web"), "title": .string("Mail")])

    /// The schedule's secret, sealed under the vault's current local key (as `BackupScheduleModel.setPassword` does).
    private func writeSchedule(_ v: MacVault, password: String) async throws {
        _ = try await v.unlock(password: password)
        var key = try XCTUnwrap(v.takeOpenedLocalKey())
        defer { for i in key.indices { key[i] = 0 } }
        let pk = try DesktopVaultFile.derivePasswordKey(password: password, kdf: Self.scheduleKDF, random: SystemRandomSource())
        let recovery = v.hasRecoveryPhrase ? try await v.recoveryVaultKey(password: password) : nil
        try ScheduleSecretStore(directory: dir, localKey: key)
            .save(ScheduledBackupSecret(backupPassword: Self.scheduledPassword, passwordKey: pk, recovery: recovery))
    }

    private func schedule(_ password: String) async throws -> (secret: ScheduledBackupSecret?, key: [UInt8]) {
        let v = makeVault()
        _ = try await v.unlock(password: password)
        let key = try XCTUnwrap(v.takeOpenedLocalKey())
        return (try ScheduleSecretStore(directory: dir, localKey: key).load(), key)
    }

    /// A vault sealed with the stored keys opens with `password` (and the phrase, when given).
    private func assertOpens(_ secret: ScheduledBackupSecret, password: String, phrase: String? = nil,
                             file: StaticString = #filePath, line: UInt = #line) throws {
        let sealed = try DesktopVaultFile.seal(items: [item], settings: .object([:]), passwordKey: secret.passwordKey,
                                               random: SystemRandomSource(), recovery: secret.recovery)
        XCTAssertEqual(try DesktopVaultFile.open(sealed, password: password).items, [item], file: file, line: line)
        if let phrase {
            XCTAssertEqual(try DesktopVaultFile.open(sealed, recoveryEntropy: BIP39.entropy(from: phrase)).items, [item],
                           file: file, line: line)
        }
    }

    func testPasswordChangeResealsTheScheduleSecretForTheNewPassword() async throws {
        let v = try await populated(touchID: false)
        try await writeSchedule(v, password: master)
        let (_, oldKey) = try await schedule(master)
        try await v.changePassword(old: master, new: "new master password")
        let (secret, _) = try await schedule("new master password")
        let s = try XCTUnwrap(secret)
        XCTAssertEqual(s.backupPassword, Self.scheduledPassword)
        try assertOpens(s, password: "new master password")
        XCTAssertThrowsError(try ScheduleSecretStore(directory: dir, localKey: oldKey).load())
    }

    func testReplacingThePhraseRebuildsTheSchedulePhraseKey() async throws {
        let v = try await populated(touchID: false)
        let first = try await v.prepareRecovery(password: master)
        _ = try await v.confirmRecovery(first)
        try await writeSchedule(v, password: master)
        let second = try await v.prepareRecovery(password: master)
        _ = try await v.confirmRecovery(second)
        let loaded = try await schedule(master)
        let s = try XCTUnwrap(loaded.secret)
        try assertOpens(s, password: master, phrase: second.phrase)
        let sealed = try DesktopVaultFile.seal(items: [item], settings: .object([:]), passwordKey: s.passwordKey,
                                               random: SystemRandomSource(), recovery: s.recovery)
        XCTAssertThrowsError(try DesktopVaultFile.open(sealed, recoveryEntropy: BIP39.entropy(from: first.phrase)))
    }

    func testRemovingThePhraseDropsTheSchedulePhraseKey() async throws {
        let v = try await populated(touchID: false)
        let prepared = try await v.prepareRecovery(password: master)
        _ = try await v.confirmRecovery(prepared)
        try await writeSchedule(v, password: master)
        let loaded = try await schedule(master)
        XCTAssertNotNil(loaded.secret?.recovery)
        _ = try await v.removeRecovery(password: master)
        let reloaded = try await schedule(master)
        let s = try XCTUnwrap(reloaded.secret)
        XCTAssertNil(s.recovery)
        try assertOpens(s, password: master)
    }

    func testRecoveryResealsTheScheduleSecretForTheNewPassword() async throws {
        let v = try await populated(touchID: false)
        let prepared = try await v.prepareRecovery(password: master)
        _ = try await v.confirmRecovery(prepared)
        try await writeSchedule(v, password: master)
        _ = try await v.recover(phrase: prepared.phrase, newPassword: "new master password")
        let loaded = try await schedule("new master password")
        let s = try XCTUnwrap(loaded.secret)
        try assertOpens(s, password: "new master password", phrase: prepared.phrase)
    }

    func testBackupPasswordEqualToTheNewMasterPasswordIsDropped() async throws {
        let v = try await populated(touchID: false)
        try await writeSchedule(v, password: master)
        try await v.changePassword(old: master, new: Self.scheduledPassword)
        let loaded = try await schedule(Self.scheduledPassword)
        XCTAssertNil(loaded.secret)
    }

    func testCrashAtEachStepKeepsTheScheduleSecretUnderTheOneKey() async throws {
        for step in KeyRotation.Step.allCases {
            try? FileManager.default.removeItem(at: dir)
            let v = try await populated(touchID: false)
            try await writeSchedule(v, password: master)
            v.rotationCrash = step
            do { try await v.changePassword(old: master, new: "new master password"); XCTFail("\(step)") }
            catch { XCTAssertTrue(error is KeyRotation.SimulatedCrash, "\(step)") }
            let committed = step != .staged
            let password = committed ? "new master password" : master
            let loaded = try await schedule(password)
            let s = try XCTUnwrap(loaded.secret, "\(step)")
            try assertOpens(s, password: password)
        }
    }

    /// A dropped secret (the backup password became the master password) is staged as a deletion, so a crash after the
    /// commit never leaves the old-key file behind once the next open rolls forward.
    func testCrashAfterCommitStillDropsTheScheduleSecret() async throws {
        for step in KeyRotation.Step.allCases {
            try? FileManager.default.removeItem(at: dir)
            let v = try await populated(touchID: false)
            try await writeSchedule(v, password: master)
            v.rotationCrash = step
            do { try await v.changePassword(old: master, new: Self.scheduledPassword); XCTFail("\(step)") }
            catch { XCTAssertTrue(error is KeyRotation.SimulatedCrash, "\(step)") }
            let file = dir.appendingPathComponent(ScheduleSecretStore.fileName)
            if step == .staged {
                let old = try await schedule(master)
                XCTAssertNotNil(old.secret, "\(step)")   // nothing committed: the old secret stays
            } else {
                _ = try await schedule(Self.scheduledPassword)                  // the open rolls forward
                XCTAssertFalse(FileManager.default.fileExists(atPath: file.path), "\(step)")
            }
        }
    }

    // MARK: restore and rotation (final review)

    /// A rotation while a manual backup or restore runs is refused with its own message, and changes nothing; once the
    /// restore is over the same change goes through.
    func testRotationRefusedWhileABackupOrRestoreRuns() async throws {
        let v = try await populated(touchID: false)
        let store = try await v.unlock(password: master)
        let before = try store.load().records
        MacFullBackup.setInFlightForTesting(true)
        do {
            _ = try await v.changePassword(old: master, new: "new master password")
            XCTFail("rotated during a restore")
        } catch {
            XCTAssertEqual(error as? MacVaultError, .backupOrRestoreRunning)
            XCTAssertEqual(MacLockModel.describe(error, now: Date()), "A backup or restore is running. Try again in a moment.")
        }
        MacFullBackup.setInFlightForTesting(false)
        let reopened = try await makeVault().unlock(password: master)   // old password, same items
        XCTAssertEqual(try reopened.load().records, before)
        XCTAssertFalse(FileManager.default.fileExists(atPath: KeyRotation.stagingURL(dir).path))
        _ = try await v.changePassword(old: master, new: "new master password")
        let rotated = try await makeVault().unlock(password: "new master password")
        XCTAssertEqual(try rotated.load().records, before)
    }
}
