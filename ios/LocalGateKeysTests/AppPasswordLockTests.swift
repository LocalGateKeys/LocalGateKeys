import XCTest
import AppShared
@testable import LocalGateKeys

/// Task 7 (mirrors android AppPasswordLockModelTest): the lock model in password mode.
@MainActor
final class AppPasswordLockTests: XCTestCase {
    final class PasswordUnlocker: Unlocking {
        let store = MemoryStore()
        var keychain: (any KeychainVault)? = InMemoryKeychainVault()
        var passwordOn = true
        var biometricShortcut = false
        var systemCalls = 0
        var calls: [String] = []
        var failWith: (any Error)?
        func unlock(reason: String) async throws -> any ItemStore {
            systemCalls += 1
            if let failWith { throw failWith }
            return store
        }
        func unlock(password: String) async throws -> any ItemStore {
            calls.append("password")
            if let failWith { throw failWith }
            return store
        }
        func recover(phrase: String, newPassword: String) async throws -> any ItemStore {
            calls.append("recovery")
            if let failWith { throw failWith }
            return store
        }
        func lock() {}
    }

    func model(_ u: PasswordUnlocker) -> AppLockModel {
        let clock = TestClock(1_790_000_000)
        return AppLockModel(unlocker: u, clock: clock, scheduler: ManualScheduler(clock: clock),
                            settings: AppSettings(defaults: UserDefaults(suiteName: "apl-\(UUID().uuidString)")!),
                            clipboard: nil, eraser: FakeEraser())
    }

    func test_password_on_without_shortcut_never_prompts() async {
        let u = PasswordUnlocker()
        let m = model(u)
        await m.unlock()
        XCTAssertEqual(u.systemCalls, 0, "no passcode or Face ID prompt")
        XCTAssertTrue(m.needsPassword)
        XCTAssertEqual(m.state, .locked)
        await m.unlock(password: "secret words")
        XCTAssertEqual(u.calls, ["password"])
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertFalse(m.needsPassword)
    }

    func test_face_id_shortcut_then_fallback_to_the_password_field() async {
        let u = PasswordUnlocker()
        u.biometricShortcut = true
        u.failWith = AppPasswordError.required   // "Use App Password" tapped
        let m = model(u)
        await m.unlock()
        XCTAssertEqual(u.systemCalls, 1)
        XCTAssertTrue(m.needsPassword)
        XCTAssertNil(m.errorMessage)
    }

    func test_messages_for_wrong_password_wait_and_changed_face_id() async {
        let u = PasswordUnlocker()
        let m = model(u)
        u.failWith = AppPasswordError.wrongPassword
        await m.unlock(password: "nope")
        XCTAssertEqual(m.errorMessage, AppLockModel.wrongPasswordMessage)
        u.failWith = AppPasswordError.wait(seconds: 30)
        await m.unlock(password: "nope")
        XCTAssertEqual(m.errorMessage, "Too many wrong tries. Try again in 30 seconds.")
        u.failWith = AppPasswordError.biometricChanged
        await m.unlock(password: "nope")
        XCTAssertEqual(m.errorMessage, AppLockModel.biometricChangedMessage)
        XCTAssertFalse(m.offersStartFresh)
        u.failWith = nil
        await m.recover(phrase: "words", newPassword: "new password here")
        XCTAssertEqual(m.state, .unlocked)
    }

    func test_password_off_keeps_today_s_unlock() async {
        let u = PasswordUnlocker()
        u.passwordOn = false
        let m = model(u)
        await m.unlock()
        XCTAssertEqual(u.systemCalls, 1)
        XCTAssertFalse(m.needsPassword)
        XCTAssertEqual(m.state, .unlocked)
    }

    // Finding 3: a turn-on over an existing file (a half-done one) is refused, so the phrase is never replaced.
    func test_turning_on_again_is_refused_while_the_file_exists() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("apl-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent(AppPasswordStore.fileName)
        try Data("{}".utf8).write(to: url)
        let store = AppPasswordStore(url: url, biometric: PhoneBiometricKeyStore(accessGroup: nil),
                                     defaults: UserDefaults(suiteName: "apl-\(UUID().uuidString)")!)
        let kc = InMemoryKeychainVault()
        try kc.write(.localKey, [UInt8](repeating: 1, count: 32))
        let controller = AppPasswordController(store: store, keychain: kc)
        let file = try MasterKeyFile.seal(localKey: [UInt8](repeating: 1, count: 32), password: "river otter lantern 42",
                                          params: MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1),
                                          random: SystemRandomSource())
        XCTAssertThrowsError(try controller.commit(file, faceID: false)) { XCTAssertEqual($0 as? AppPasswordError, .alreadyOn) }
        XCTAssertEqual(try Data(contentsOf: url), Data("{}".utf8), "the file is untouched")
        XCTAssertEqual(AppLockModel.message(for: AppPasswordError.alreadyOn), "The app password is already on.")
    }

    func test_damaged_file_message_does_not_send_the_user_to_the_phrase() {
        let m = AppLockModel.message(for: AppPasswordError.corrupt) ?? ""
        XCTAssertFalse(m.contains("Use your recovery phrase"))
        XCTAssertTrue(m.contains("Start fresh"))
    }

    func test_setup_rules() {
        XCTAssertNotNil(AppPasswordRules.problem("short", confirm: "short"))
        XCTAssertNotNil(AppPasswordRules.problem("passwordpassword", confirm: "passwordpassword"))
        XCTAssertNotNil(AppPasswordRules.problem("correct horse battery staple 9", confirm: "different"))
        XCTAssertNil(AppPasswordRules.problem("correct horse battery staple 9", confirm: "correct horse battery staple 9"))
        let positions = AppPasswordRules.confirmPositions(random: SystemRandomSource())
        XCTAssertEqual(positions.count, 3); XCTAssertEqual(Set(positions).count, 3)
        let phrase = (0..<24).map { "w\($0)" }.joined(separator: " ")
        XCTAssertTrue(AppPasswordRules.confirms(phrase: phrase, positions: [0, 5, 23], typed: ["w0", " W5 ", "w23"]))
        XCTAssertFalse(AppPasswordRules.confirms(phrase: phrase, positions: [0, 5, 23], typed: ["w0", "w6", "w23"]))
    }
}
