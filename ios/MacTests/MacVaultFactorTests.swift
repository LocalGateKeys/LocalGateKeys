import XCTest
import CryptoKit
import LGKCore
@testable import AppSharedMac

/// A YubiKey slot in variable-input mode (COMPOSITE_KEY_V1 §1.2): HMAC-SHA1 of the challenge minus its padding. Every
/// challenge it is handed is recorded (it must always be the full 64 bytes).
final class FakeYubiKeyResponder: @unchecked Sendable {
    private let lock = NSLock()
    private let secret: [UInt8]
    private var seen: [Data] = []
    var challenges: [Data] { lock.withLock { seen } }
    init(secret: [UInt8]) { self.secret = secret }

    var respond: @Sendable (Data) async throws -> Data {
        { [self] challenge in
            lock.withLock { seen.append(challenge) }
            var message = [UInt8](challenge)
            if let last = message.last { while message.last == last { message.removeLast() } }
            return Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: secret)))
        }
    }
}

/// Key file and YubiKey factors on the Mac vault (`master-key.json` v2): add, unlock, change password, recovery, remove.
@MainActor
final class MacVaultFactorTests: XCTestCase {
    private var dir: URL!
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
    private let master = "correct horse battery"

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-macfactors-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDown() async throws { try? FileManager.default.removeItem(at: dir) }

    private func makeVault(bio: FakeBiometricKeyStore = FakeBiometricKeyStore()) -> MacVault {
        let fixed = now
        return MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: bio, clock: { fixed },
                        random: SystemRandomSource(), kdfParams: cheap)
    }

    private func keyFile() throws -> Data { try KeyFile.newKeepassXMLv2(random: SystemRandomSource()) }

    private func stored() throws -> MasterKeyFile {
        try JSONDecoder().decode(MasterKeyFile.self, from: try Data(contentsOf: dir.appendingPathComponent("master-key.json")))
    }

    private func assertThrows<E: Error & Equatable>(_ expected: E, file: StaticString = #filePath, line: UInt = #line,
                                                    _ op: () async throws -> Void) async {
        do { try await op(); XCTFail("expected \(expected)", file: file, line: line) }
        catch { XCTAssertEqual(error as? E, expected, file: file, line: line) }
    }

    func testKeyFileIsNeededAndAWrongOneIsNeverCountedAsAWrongPassword() async throws {
        let v = makeVault()
        _ = try await v.create(password: master, enableTouchID: false)
        let file = try keyFile()
        try await v.addKeyFile(password: master, keyFile: file)
        XCTAssertEqual(try stored().version, 2)
        XCTAssertEqual(v.factors.map(\.kind), [.keyFile])

        let fresh = makeVault()
        await assertThrows(FactorError.required([.keyFile])) { _ = try await fresh.unlock(password: master) }
        for _ in 0..<8 {
            await assertThrows(FactorError.mismatch(.keyFile)) {
                _ = try await fresh.unlock(password: master, factors: FactorSecrets(keyFile: try keyFile()))
            }
        }
        XCTAssertNil(fresh.retryAfter)   // a factor problem is checked before Argon2 and never throttled
        _ = try await fresh.unlock(password: master, factors: FactorSecrets(keyFile: file))
        XCTAssertTrue(fresh.holdsKeyFile)
        // The held key file serves later password checks of the session (no dialog), until a lock forgets it.
        try await fresh.verifyPassword(master)
        fresh.forgetHeldFactors()
        await assertThrows(FactorError.required([.keyFile])) { try await fresh.verifyPassword(master) }
    }

    func testYubiKeyGetsThePaddedChallengeAndAPasswordChangeRenewsIt() async throws {
        let v = makeVault()
        _ = try await v.create(password: master, enableTouchID: false)
        let key = FakeYubiKeyResponder(secret: Array("vector-hmac-secret".utf8))
        try await v.addYubiKey(password: master, slot: 2, respond: key.respond)
        let first = try XCTUnwrap(v.factors.first)
        XCTAssertEqual(first.kind, .yubiKeyHMAC)
        XCTAssertEqual(first.slot, 2)
        XCTAssertTrue(key.challenges.allSatisfy { $0.count == 64 })
        XCTAssertEqual(key.challenges.last, Data(first.paddedChallenge))

        let fresh = makeVault()
        await assertThrows(FactorError.required([.yubiKeyHMAC])) { _ = try await fresh.unlock(password: master) }
        _ = try await fresh.unlock(password: master, factors: FactorSecrets(yubiKey: key.respond))

        // A password change keeps the YubiKey with a new challenge (asked through the provider: no factors given).
        fresh.provideFactors = { _ in FactorSecrets(yubiKey: key.respond) }
        try await fresh.changePassword(old: master, new: "battery staple horse")
        let renewed = try XCTUnwrap(fresh.factors.first)
        XCTAssertEqual(renewed.kind, .yubiKeyHMAC)
        XCTAssertNotEqual(renewed.challenge, first.challenge)
        _ = try await makeVault().unlock(password: "battery staple horse", factors: FactorSecrets(yubiKey: key.respond))

        let other = FakeYubiKeyResponder(secret: Array("another secret".utf8))
        await assertThrows(FactorError.mismatch(.yubiKeyHMAC)) {
            _ = try await self.makeVault().unlock(password: "battery staple horse", factors: FactorSecrets(yubiKey: other.respond))
        }
    }

    func testRemovingTheLastFactorWritesVersion1Again() async throws {
        let v = makeVault()
        _ = try await v.create(password: master, enableTouchID: false)
        let file = try keyFile()
        try await v.addKeyFile(password: master, keyFile: file)
        await assertThrows(MacFactors.alreadySet) { try await v.addKeyFile(password: self.master, keyFile: try self.keyFile()) }
        try await v.removeFactor(.keyFile, password: master)
        XCTAssertEqual(try stored().version, 1)
        XCTAssertNil(try stored().factors)
        XCTAssertFalse(v.holdsKeyFile)
        _ = try await makeVault().unlock(password: master)
    }

    func testAddingAFactorKeepsTheRecoveryPhraseAndTouchID() async throws {
        let bio = FakeBiometricKeyStore()
        let v = makeVault(bio: bio)
        _ = try await v.create(password: master, enableTouchID: true)
        let prepared = try await v.prepareRecovery(password: master)
        _ = try await v.confirmRecovery(prepared)
        try await v.setTouchID(true, password: master)
        let recovery = try stored().recovery
        try await v.addKeyFile(password: master, keyFile: try keyFile())
        XCTAssertEqual(try stored().recovery, recovery)   // the local key is not rotated by adding a factor
        XCTAssertNotNil(bio.stored)   // a device-bound shortcut keeps working (design §4.3)
        _ = try await makeVault(bio: bio).unlockWithTouchID(reason: "test")
        v.removeTouchIDItem()   // "Always ask for the key file / YubiKey" deletes it
        XCTAssertNil(bio.stored)
    }

    /// A freshly sealed key file is opened again before it is written: a broken seal changes nothing on disk.
    func testABrokenSealIsNeverWritten() async throws {
        let v = makeVault()
        _ = try await v.create(password: master, enableTouchID: false)
        let url = dir.appendingPathComponent("master-key.json")
        let before = try Data(contentsOf: url)
        v.damageSeal = { $0.salt = Base64.encode([UInt8](repeating: 9, count: 16)) }
        await assertThrows(MacVault.sealCheckFailed) { try await v.addKeyFile(password: self.master, keyFile: try self.keyFile()) }
        XCTAssertEqual(try Data(contentsOf: url), before)
        XCTAssertEqual(v.factors, [])
        await assertThrows(MacVault.sealCheckFailed) { _ = try await v.changePassword(old: self.master, new: "battery staple horse") }
        XCTAssertEqual(try Data(contentsOf: url), before)
        v.damageSeal = nil
        _ = try await makeVault().unlock(password: master)
    }

    func testRecoveryPhraseResetDropsTheFactors() async throws {
        let v = makeVault()
        _ = try await v.create(password: master, enableTouchID: false)
        let prepared = try await v.prepareRecovery(password: master)
        _ = try await v.confirmRecovery(prepared)
        try await v.addKeyFile(password: master, keyFile: try keyFile())

        let locked = makeVault()
        _ = try await locked.recover(phrase: prepared.phrase, newPassword: "a brand new master password")
        XCTAssertTrue(locked.lastRecoveryDroppedFactors)
        XCTAssertEqual(locked.factors, [])
        XCTAssertEqual(try stored().version, 1)
        _ = try await makeVault().unlock(password: "a brand new master password")
    }

    func testMessagesForFactorProblems() {
        XCTAssertEqual(MacLockModel.describe(FactorError.required([.keyFile]), now: now), "This vault also needs its key file.")
        XCTAssertEqual(MacLockModel.describe(FactorError.mismatch(.yubiKeyHMAC), now: now), "This isn't the YubiKey used for this vault.")
        XCTAssertEqual(MacLockModel.describe(YubiKeyError.removed, now: now), "Touch your YubiKey again.")
        XCTAssertNil(MacLockModel.describe(YubiKeyError.cancelled, now: now))
    }

    func testKeyFileReadIsBoundedAndRegularFilesOnly() throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let small = dir.appendingPathComponent("small.key")
        try Data(repeating: 7, count: 32).write(to: small)
        XCTAssertEqual(try MacFactors.readKeyFile(small).count, 32)
        XCTAssertThrowsError(try MacFactors.readKeyFile(dir)) { XCTAssertTrue($0 is FactorMessageError) }   // a folder
        let big = dir.appendingPathComponent("big.bin")
        FileManager.default.createFile(atPath: big.path, contents: nil)
        let handle = try FileHandle(forWritingTo: big)
        try handle.truncate(atOffset: UInt64(KeyFile.maxBytes + 1))   // sparse: no 64 MiB written
        try handle.close()
        XCTAssertThrowsError(try MacFactors.readKeyFile(big)) { XCTAssertEqual($0 as? FactorMessageError, MacFactors.keyFileTooLarge) }
    }

    func testCreatedKeyFileIsOwnerOnlyNeverOverwritesAndNeverInTheVaultFolder() throws {
        let outside = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-keyfile-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: outside) }
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let content = try keyFile()
        let target = outside.appendingPathComponent("LocalGateKeys.keyx")
        try MacKeyFileWriter.write(content, to: target, vaultDirectory: dir)
        XCTAssertEqual(try Data(contentsOf: target), content)
        let mode = try FileManager.default.attributesOfItem(atPath: target.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode?.intValue, 0o600)
        XCTAssertThrowsError(try MacKeyFileWriter.write(content, to: target, vaultDirectory: dir)) {
            XCTAssertEqual($0 as? FactorMessageError, MacKeyFileWriter.exists("LocalGateKeys.keyx"))
        }
        XCTAssertThrowsError(try MacKeyFileWriter.write(content, to: dir.appendingPathComponent("in-vault.keyx"), vaultDirectory: dir)) {
            XCTAssertEqual($0 as? FactorMessageError, MacKeyFileWriter.notInVaultFolder)
        }
    }

    func testKeyFileBookmarkRecordBelongsToOneCheck() throws {
        let mark = KeyFileBookmark(bookmark: [1, 2, 3], name: "vault.keyx", check: "10ed9c05250cf31b")
        let keychain = InMemoryKeychainVault()
        try keychain.write(.unlockKeyFile, try mark.encoded())
        XCTAssertEqual(KeyFileBookmark(encoded: try mark.encoded()), mark)
        XCTAssertEqual(KeyFileBookmark.load(for: "10ed9c05250cf31b", from: keychain), mark)
        XCTAssertNil(KeyFileBookmark.load(for: "d4cceb1d258554e0", from: keychain))   // another key file or vault
        KeyFileBookmark.forget(in: keychain)
        XCTAssertNil(KeyFileBookmark.load(for: "10ed9c05250cf31b", from: keychain))
    }
}
