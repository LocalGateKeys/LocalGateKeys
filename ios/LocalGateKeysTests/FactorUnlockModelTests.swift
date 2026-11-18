import XCTest
import CryptoKit
import CoreNFC
import LocalAuthentication
import AppShared
@testable import LocalGateKeys

/// Task 8 (mirrors android FactorUnlockModelTest, Mac MacVaultFactorTests): the iPhone app password with a key file
/// and a YubiKey. A real `app-password.json` (cheap Argon2id) in a temporary folder; a fake factor source (bookmark in
/// memory, a YubiKey modelled in variable-input mode); the NFC APDUs through a fake transport.
@MainActor
final class FactorUnlockModelTests: XCTestCase {
    final class FakeBiometric: AppPasswordBiometricStore, @unchecked Sendable {
        var key: [UInt8]?
        func store(_ key: [UInt8]) throws { self.key = key }
        func load(context: LAContext) throws -> [UInt8] {
            guard let key else { throw AppPasswordError.biometricChanged }
            return key
        }
        func remove() throws { key = nil }
        var exists: Bool { key != nil }
    }

    final class FakeBoot: AppPasswordBootClock, @unchecked Sendable {
        var uptime: Int64 = 1_000
        var bootID: String? = "boot-1"
    }

    /// A YubiKey slot in variable-input mode (the ykman default): HMAC-SHA1 over the challenge minus its trailing run
    /// of the last byte. Records every challenge it was given.
    final class FakeYubiKey: @unchecked Sendable {
        let secret: [UInt8]
        private let lock = NSLock()
        private var _challenges: [Data] = []
        var challenges: [Data] { lock.withLock { _challenges } }
        init(_ secret: String) { self.secret = Array(secret.utf8) }

        func respond(_ challenge: Data) -> Data {
            lock.withLock { _challenges.append(challenge) }
            var bytes = [UInt8](challenge)
            if let last = bytes.last { while bytes.last == last { bytes.removeLast() } }
            return Data(HMAC<Insecure.SHA1>.authenticationCode(for: bytes, using: SymmetricKey(data: secret)))
        }
    }

    final class FakeFactors: PhoneFactorSourcing {
        var remembered: (url: URL, check: String)?
        var rememberCalls: [String] = []
        var forgetCalls = 0
        var yubiKeyCalls = 0
        var cancels = 0
        var heldKey: FakeYubiKey?

        func rememberedKeyFile(check: String) -> RememberedKeyFile? {
            guard let remembered, remembered.check == check else { return nil }
            return RememberedKeyFile(name: remembered.url.lastPathComponent, url: remembered.url)
        }
        func readKeyFile(_ url: URL) async throws -> Data { try PhoneFactors.readKeyFile(url) }
        func rememberKeyFile(_ url: URL, check: String) { rememberCalls.append(check); remembered = (url, check) }
        func forgetKeyFile() { forgetCalls += 1; remembered = nil }
        func yubiKey(slot: Int, confirming: Bool) -> @Sendable (Data) async throws -> Data {
            yubiKeyCalls += 1
            let key = heldKey
            return { challenge in
                guard let key else { throw YubiKeyNFCError.timeout }
                return key.respond(challenge)
            }
        }
        func cancelYubiKey() { cancels += 1 }
    }

    /// The lock model's unlocker over the real store (the parts `SystemUnlocker` adds are the Keychain and the vault).
    final class StoreUnlocker: Unlocking {
        let appPassword: AppPasswordStore
        var keychain: (any KeychainVault)? = InMemoryKeychainVault()
        init(_ appPassword: AppPasswordStore) { self.appPassword = appPassword }
        var passwordOn: Bool { appPassword.isOn }
        var factorSpecs: [FactorSpec] { appPassword.factorSpecs }
        func unlock(reason: String) async throws -> any ItemStore { throw AppPasswordError.required }
        func unlock(password: String) async throws -> any ItemStore { try await unlock(password: password, factors: FactorSecrets()) }
        func unlock(password: String, factors: FactorSecrets) async throws -> any ItemStore {
            _ = try await appPassword.open(password: password, factors: factors)
            return MemoryStore()
        }
        func recover(phrase: String, newPassword: String) async throws -> any ItemStore {
            let key = try appPassword.open(phrase: phrase)
            try appPassword.write(try appPassword.withNewPassword(try appPassword.readFile(), localKey: key, password: newPassword,
                                                                  random: SystemRandomSource()))
            return MemoryStore()
        }
        func lock() {}
    }

    let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)
    let localKey = (0..<32).map { UInt8($0) }
    let password = "correct horse battery staple"
    var dir: URL!, defaults: UserDefaults!, bio: FakeBiometric!, store: AppPasswordStore!, phrase: String!
    var keyFile: URL!, otherKeyFile: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("factor-unlock-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defaults = UserDefaults(suiteName: "factors-\(UUID().uuidString)")!
        bio = FakeBiometric()
        store = AppPasswordStore(url: dir.appendingPathComponent(AppPasswordStore.fileName), biometric: bio, defaults: defaults,
                                 params: cheap, now: { 1_790_000_000 }, bootClock: FakeBoot())
        let prepared = try store.prepare(localKey: localKey, password: password, random: SystemRandomSource())
        try store.write(prepared.file)
        phrase = prepared.phrase
        keyFile = dir.appendingPathComponent("vault.keyx")
        otherKeyFile = dir.appendingPathComponent("other.keyx")
        try KeyFile.newKeepassXMLv2(random: SystemRandomSource()).write(to: keyFile)
        try KeyFile.newKeepassXMLv2(random: SystemRandomSource()).write(to: otherKeyFile)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
    }

    private func addKeyFile() async throws {
        var opened = try await store.openKeepingFactors(password: password, factors: FactorSecrets())
        defer { opened.clear() }
        let enrolled = try CompositeKey.enrolKeyFile(try Data(contentsOf: keyFile))
        try await store.rewrap(opened, password: password, added: ([enrolled.spec], [enrolled.secret]), random: SystemRandomSource())
    }

    private func addYubiKey(_ key: FakeYubiKey) async throws {
        // A key file added before must be supplied to reopen the vault.
        let held = store.factorSpecs.contains { $0.kind == .keyFile } ? try Data(contentsOf: keyFile) : nil
        var opened = try await store.openKeepingFactors(password: password, factors: FactorSecrets(keyFile: held))
        defer { opened.clear() }
        let enrolled = try await CompositeKey.enrolYubiKey(slot: 2, random: SystemRandomSource()) { key.respond($0) }
        try await store.rewrap(opened, password: password, added: ([enrolled.spec], [enrolled.secret]), random: SystemRandomSource())
    }

    private func model(_ factors: FakeFactors) -> AppLockModel {
        let clock = TestClock(1_790_000_000)
        return AppLockModel(unlocker: StoreUnlocker(store), clock: clock, scheduler: ManualScheduler(clock: clock),
                            settings: AppSettings(defaults: UserDefaults(suiteName: "fl-\(UUID().uuidString)")!),
                            clipboard: nil, eraser: FakeEraser(), factors: factors)
    }

    private var failures: Int { defaults.integer(forKey: "settings.unlockFailures") }

    func testMissingFactorRequired() async throws {
        try await addKeyFile()
        let key = FakeYubiKey("vector-hmac-secret")
        try await addYubiKey(key)
        XCTAssertEqual(store.factorSpecs.map(\.kind), [.keyFile, .yubiKeyHMAC])
        let factors = FakeFactors()
        factors.heldKey = key
        let m = model(factors)
        await m.unlock()
        XCTAssertTrue(m.needsPassword)
        XCTAssertNotNil(m.keyFileSpec)
        XCTAssertNotNil(m.yubiKeySpec)
        let tapsBefore = key.challenges.count
        await m.unlock(password: password)
        XCTAssertEqual(m.state, .locked)
        XCTAssertEqual(m.errorMessage, "This vault also needs its key file.")
        XCTAssertEqual(key.challenges.count, tapsBefore, "no YubiKey tap before every factor is supplied")
        XCTAssertEqual(failures, 0, "a missing factor is not a wrong try")
        XCTAssertEqual(factors.rememberCalls, [])
    }

    func testMismatchMessage() async throws {
        try await addKeyFile()
        let factors = FakeFactors()
        let m = model(factors)
        await m.unlock()
        m.chooseKeyFile(otherKeyFile)
        await m.unlock(password: password)
        XCTAssertEqual(m.state, .locked)
        XCTAssertEqual(m.errorMessage, "This isn't the key file used for this vault.")
        XCTAssertEqual(failures, 0, "a wrong key file is not a wrong try")
        XCTAssertEqual(factors.rememberCalls, [], "a key file that failed is never remembered")

        let key = FakeYubiKey("vector-hmac-secret")
        try FileManager.default.removeItem(at: store.url)
        try store.write(try store.prepare(localKey: localKey, password: password, random: SystemRandomSource()).file)
        try await addYubiKey(key)
        factors.heldKey = FakeYubiKey("another YubiKey")
        await m.unlock(password: password)
        XCTAssertEqual(m.errorMessage, "This isn't the YubiKey used for this vault.")
        factors.heldKey = nil   // the NFC sheet timed out
        await m.unlock(password: password)
        XCTAssertEqual(m.errorMessage, "No YubiKey found. Hold it to the top of your iPhone and try again.")
        XCTAssertEqual(failures, 0)
    }

    func testBookmarkOnlyAfterSuccess() async throws {
        try await addKeyFile()
        let check = try XCTUnwrap(store.factorSpecs.first?.check)
        let factors = FakeFactors()
        let m = model(factors)
        await m.unlock()
        m.chooseKeyFile(keyFile)
        await m.unlock(password: "not the password at all")
        XCTAssertEqual(m.errorMessage, AppLockModel.wrongPasswordMessage)
        XCTAssertEqual(factors.rememberCalls, [], "nothing remembered after a failed unlock")
        await m.unlock(password: password)
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertEqual(factors.rememberCalls, [check])
        XCTAssertNil(m.pickedKeyFile)

        // Next time the remembered file is used without a picker; "Don't remember" drops it after the unlock.
        m.lock()
        await m.unlock()
        XCTAssertEqual(m.rememberedKeyFile?.name, "vault.keyx")
        m.dontRememberKeyFile = true
        await m.unlock(password: password)
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertEqual(factors.forgetCalls, 1)
        XCTAssertGreaterThan(factors.cancels, 0, "a lock cancels a waiting YubiKey exchange")
    }

    func testRecoveryPhraseBypassesFactors() async throws {
        try await addKeyFile()
        try await addYubiKey(FakeYubiKey("vector-hmac-secret"))
        let factors = FakeFactors()
        let m = model(factors)
        await m.unlock()
        await m.recover(phrase: phrase, newPassword: "a brand new app password")
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertEqual(factors.yubiKeyCalls, 0, "the phrase needs no YubiKey")
        XCTAssertEqual(m.unlockNotice, "Key file / YubiKey removed; add them again.")
        XCTAssertEqual(factors.forgetCalls, 1)
        XCTAssertEqual(store.factorSpecs, [], "the phrase reset drops the factors (version 1)")
        XCTAssertEqual(try store.readFile().version, 1)
        XCTAssertEqual(try store.open(password: "a brand new app password"), localKey)
    }

    func testAutoFillDefersToAppWhenFactorsSet() async throws {
        XCTAssertThrowsError(try store.autoFillGate(alwaysAsk: false)) { XCTAssertEqual($0 as? AppPasswordError, .openAppFirst) }
        try await addKeyFile()
        XCTAssertThrowsError(try store.autoFillGate(alwaysAsk: false)) { XCTAssertEqual($0 as? AppPasswordError, .openAppForFactors) }
        bio.key = localKey
        XCTAssertNoThrow(try store.autoFillGate(alwaysAsk: false), "the Face ID shortcut still works without Always ask")
        XCTAssertThrowsError(try store.autoFillGate(alwaysAsk: true)) { XCTAssertEqual($0 as? AppPasswordError, .openAppForFactors) }
        XCTAssertNil(bio.key, "Always ask deletes the shortcut item")
        XCTAssertEqual(AppLockModel.message(for: AppPasswordError.openAppForFactors),
                       "Open LocalGateKeys to unlock this vault (it needs a key file or YubiKey).")
    }

    func testChangeKeepsFactorsAndRenewsTheChallenge() async throws {
        let key = FakeYubiKey("vector-hmac-secret")
        try await addYubiKey(key)
        let before = try XCTUnwrap(store.factorSpecs.first?.challenge)
        let factors = FakeFactors()
        factors.heldKey = key
        let controller = AppPasswordController(store: store, keychain: InMemoryKeychainVault(), factors: factors,
                                               settings: AppSettings(defaults: UserDefaults(suiteName: "fc-\(UUID().uuidString)")!))
        try await controller.change(current: password, new: "another long app password")
        let after = try XCTUnwrap(store.factorSpecs.first)
        XCTAssertNotEqual(after.challenge, before, "renewed with the rewritten wrapper")
        XCTAssertTrue(key.challenges.allSatisfy { $0.count == 64 }, "always the full padded challenge")
        let reopened = try await store.open(password: "another long app password",
                                            factors: FactorSecrets(yubiKey: { key.respond($0) }))
        XCTAssertEqual(reopened, localKey)

        // Remove: back to version 1, opened by the password alone.
        try await controller.removeFactor(.yubiKeyHMAC, current: "another long app password")
        XCTAssertEqual(store.factorSpecs, [])
        XCTAssertEqual(try store.open(password: "another long app password"), localKey)
    }

    func testAlwaysAskNeedsAFactorAndRemovesFaceID() async throws {
        let settings = AppSettings(defaults: UserDefaults(suiteName: "fa-\(UUID().uuidString)")!)
        let controller = AppPasswordController(store: store, keychain: InMemoryKeychainVault(), factors: FakeFactors(), settings: settings)
        XCTAssertThrowsError(try controller.setAlwaysAsk(true))
        try await addKeyFile()
        bio.key = localKey
        try controller.setAlwaysAsk(true)
        XCTAssertTrue(settings.factorsAlwaysAsk)
        XCTAssertNil(bio.key)
        XCTAssertThrowsError(try controller.setFaceID(true)) {
            XCTAssertEqual(($0 as? FactorMessageError)?.message, "Face ID is off while \u{201C}Always ask for the key file / YubiKey\u{201D} is on.")
        }
    }

    // MARK: NFC APDUs (docs/formats/COMPOSITE_KEY_V1.md §1.2)

    final class FakeTransport: YubiKeyAPDUTransport, @unchecked Sendable {
        private let lock = NSLock()
        private var _sent: [Data] = []
        var sent: [Data] { lock.withLock { _sent } }
        let answers: [Data]
        init(_ answers: [Data]) { self.answers = answers }
        func transmit(_ apdu: Data) async throws -> Data {
            lock.withLock {
                _sent.append(apdu)
                return answers[_sent.count - 1]
            }
        }
    }

    static func unhex(_ text: String) -> Data {
        var out = Data()
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            out.append(UInt8(text[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    /// tests/vectors/composite_key/cases.json "yubikey": the bytes on the wire are the 64-byte padded challenge.
    func testWireBytesAreThePaddedChallenge() async throws {
        let padded = Self.unhex("c05359d74919120739f641308863507d259ab55bd6401b04098c50989be6b5fb2020202020202020202020202020202020202020202020202020202020202020")
        let response = Self.unhex("32c1c73745d1873a0dc5dfc174e7822e3e5e40f9")
        let spec = try FactorSpec.yubiKey(check: "d4cceb1d258554e0", slot: 2,
                                          challenge: [UInt8](Self.unhex("c05359d74919120739f641308863507d259ab55bd6401b04098c50989be6b5fb")))
        XCTAssertEqual(Data(spec.paddedChallenge), padded)
        let ok = Data([0x90, 0x00])
        let transport = FakeTransport([ok, response + ok])
        let answer = try await YubiKeyNFC.respond(over: transport, slot: 2, challenge: Data(spec.paddedChallenge))
        XCTAssertEqual(answer, response)
        XCTAssertEqual(transport.sent.count, 2)
        XCTAssertEqual(transport.sent[0], Self.unhex("00a4040008a000000527200101"), "SELECT the OTP applet")
        XCTAssertEqual(transport.sent[1], Self.unhex("0001380040") + padded, "slot 2, Lc 64, then exactly padded_challenge_hex")
        XCTAssertEqual(FactorUnlockModelTests.FakeYubiKey("vector-hmac-secret").respond(padded), response, "variable-mode model")

        let slot1 = FakeTransport([ok, response + ok])
        _ = try await YubiKeyNFC.respond(over: slot1, slot: 1, challenge: padded)
        XCTAssertEqual(slot1.sent[1].prefix(5), Self.unhex("0001300040"))
    }

    func testNFCErrors() async throws {
        let padded = Data(repeating: 0x41, count: 64)
        let ok = Data([0x90, 0x00])
        // An empty answer: the slot is not set up for challenge-response.
        do {
            _ = try await YubiKeyNFC.respond(over: FakeTransport([ok, ok]), slot: 2, challenge: padded)
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual(error as? YubiKeyNFCError, .slotNotConfigured(slot: 2))
        }
        // The OTP applet missing (6A82).
        do {
            _ = try await YubiKeyNFC.respond(over: FakeTransport([Data([0x6A, 0x82])]), slot: 2, challenge: padded)
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual(error as? YubiKeyNFCError, .slotNotConfigured(slot: 2))
        }
        // Never padded here: a 32-byte challenge is refused before anything is sent.
        let none = FakeTransport([])
        do {
            _ = try await YubiKeyNFC.respond(over: none, slot: 2, challenge: Data(repeating: 1, count: 32))
            XCTFail("expected an error")
        } catch {
            XCTAssertEqual(none.sent.count, 0)
        }
        XCTAssertEqual(YubiKeyNFC.failure(NFCReaderError(.readerSessionInvalidationErrorUserCanceled)), .cancelled)
        XCTAssertEqual(YubiKeyNFC.failure(NFCReaderError(.readerSessionInvalidationErrorSessionTimeout)), .timeout)
        XCTAssertEqual(YubiKeyNFC.failure(NFCReaderError(.readerTransceiveErrorTagConnectionLost)), .tagLost)
        XCTAssertEqual(PhoneFactors.yubiKeyMessage(.tagLost), "Hold your YubiKey to the phone again.")
        XCTAssertNil(PhoneFactors.yubiKeyMessage(.cancelled), "a cancelled tap says nothing")
        XCTAssertNil(AppLockModel.message(for: YubiKeyNFCError.cancelled))
    }

    /// A session driver that connects a fake YubiKey on every start and reports each stop's end right away (as
    /// YubiKit does from `stopNFCConnection`), recording what it was asked.
    final class FakeDriver: NFCSessionDriving, @unchecked Sendable {
        private let lock = NSLock()
        private var _events: [String] = []
        var events: [String] { lock.withLock { _events } }
        let response: Data
        init(response: Data) { self.response = response }
        func start(delegate: YubiKeyNFCReader) {
            lock.withLock { _events.append("start") }
            let ok = Data([0x90, 0x00])
            let box = ConnectionBox(transport: FakeTransport([ok, response + ok]))
            DispatchQueue.main.async { delegate.connected(box) }
        }
        func stop(failed: Bool, message: String?) {
            lock.withLock { _events.append(failed ? "stop-error" : (message == nil ? "stop" : "stop-done")) }
        }
        /// The end callback of the stopped session, sent by the test.
        func end(_ reader: YubiKeyNFCReader) { DispatchQueue.main.async { reader.sessionEnded(nil) } }
    }

    func testBackToBackExchangesAndALateConnect() async throws {
        let response = Self.unhex("32c1c73745d1873a0dc5dfc174e7822e3e5e40f9")
        let driver = FakeDriver(response: response)
        let reader = YubiKeyNFCReader(driver: driver, closeTimeout: 0.2, available: { true })
        let padded = Data(repeating: 0x41, count: 64)
        // Two taps (enrolment): the first session's close times out (no end callback), the second one starts after
        // it; neither the first close's timer nor anything else ends the second exchange early.
        let answer = try await reader.confirmingResponder(slot: 2)(padded)
        XCTAssertEqual(answer, response)
        XCTAssertEqual(driver.events, ["start", "stop-done", "start", "stop-done"])

        // A session end that belongs to a close is used up by it, so the next connect still succeeds.
        let respond = reader.responder(slot: 2)
        let first = Task { try await respond(padded) }
        for _ in 0..<200 where driver.events.count < 6 { try await Task.sleep(nanoseconds: 5_000_000) }
        driver.end(reader)
        let got = try await first.value
        XCTAssertEqual(got, response)

        // A YubiKey that connects after a cancel: its session is closed again at once.
        reader.cancel()
        let before = driver.events.count
        reader.connected(ConnectionBox(transport: FakeTransport([])))
        XCTAssertEqual(driver.events.count, before + 1)
        XCTAssertEqual(driver.events.last, "stop")
    }
}
