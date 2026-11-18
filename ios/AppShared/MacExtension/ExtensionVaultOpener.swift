#if os(macOS)
import Foundation
import LGKCore

/// Opens the Mac vault inside an extension (AutoFill): with the Touch ID item if it is present, otherwise
/// with the master password under the same Argon2 parameters (those in `master-key.json`) and the same
/// shared `throttle.json` as the app. It only reads `master-key.json`, never writes it, and keeps no key:
/// each call authenticates again, and the key is wiped as soon as the store is open.
public final class ExtensionVaultOpener: @unchecked Sendable {
    public let directory: URL
    private let biometric: any BiometricKeyStore
    private let keychain: any KeychainVault
    private let clock: @Sendable () -> Date
    private let random: any RandomSource
    private let lock = NSLock()
    /// True while an attempt runs, so a concurrent one cannot slip past the throttle.
    private var attemptInFlight = false
    /// The duress password (sub-plan 08): true while the app has the second vault open (its session marker) or this
    /// vault is held (`PhoneDuress.servicesBlocked` over the files beside it). Then Touch ID is unavailable and a right
    /// master password is refused as wrong after the same work, so AutoFill opens nothing, as on the iPhone.
    private let blocked: @Sendable () -> Bool

    public init(directory: URL, biometric: any BiometricKeyStore,
                clock: @escaping @Sendable () -> Date = { Date() },
                keychain: any KeychainVault = SystemKeychainVault(),
                random: any RandomSource = SystemRandomSource(),
                blocked: (@Sendable () -> Bool)? = nil) {
        self.directory = directory; self.biometric = biometric; self.clock = clock
        self.keychain = keychain; self.random = random
        let files = DuressFiles.under(directory)
        // A fresh session object: an extension never opens a duress session itself, it reads the app's marker.
        self.blocked = blocked ?? { PhoneDuress(files: files, session: DuressSession()).servicesBlocked() }
    }

    /// True while the duress password blocks this vault (tests and the extension's own wording).
    public var duressBlocked: Bool { blocked() }

    public var exists: Bool {
        FileManager.default.fileExists(atPath: directory.appendingPathComponent(MasterPasswordUnlock.keyFileName).path)
    }

    /// True when Touch ID can be offered (present and enrolled). The item may still be gone after an
    /// enrolment change; `openWithTouchID` then throws `.biometricUnavailable` and the caller asks for the
    /// master password.
    public var touchIDAvailable: Bool { biometric.isAvailable }

    /// True when `master-key.json` also asks for a key file or YubiKey (version 2): the extension can read neither,
    /// so here only Touch ID opens the vault, and a master password is asked for in the app. Only reads the file.
    public var needsFactors: Bool {
        let url = directory.appendingPathComponent(MasterPasswordUnlock.keyFileName)
        guard let data = FileManager.default.contents(atPath: url.path),
              let file = try? JSONDecoder().decode(MasterKeyFile.self, from: data) else { return false }
        return !file.factorKinds.isEmpty
    }

    /// When the next password attempt is allowed, or nil if it is allowed now.
    public var retryAfter: Date? { MasterPasswordUnlock.retryAfter(directory: directory, now: clock()) }

    public func openWithTouchID(reason: String) async throws -> LocalStore {
        guard exists else { throw MacVaultError.noVault }
        guard biometric.isAvailable, !blocked() else { throw MacVaultError.biometricUnavailable }
        return try await exclusive {
            var key: [UInt8]
            do { key = try await biometric.load(reason: reason) }
            catch BiometricKeyError.cancelled { throw BiometricKeyError.cancelled }
            catch { throw MacVaultError.biometricUnavailable }   // item gone (enrolment changed) or unreadable
            defer { wipe(&key) }
            let store = try MasterPasswordUnlock.openStore(directory: directory, key: key, keychain: keychain, random: random)
            MasterPasswordUnlock.recordSuccess(directory: directory, now: clock())
            return store
        }
    }

    public func open(password: String) async throws -> LocalStore {
        try await exclusive {
            var key = try await openKey(password)
            defer { wipe(&key) }
            return try MasterPasswordUnlock.openStore(directory: directory, key: key, keychain: keychain, random: random)
        }
    }

    /// Checks the master password without opening anything (strict logins); the throttle applies.
    public func verifyMasterPassword(_ password: String) async throws {
        try await exclusive {
            var key = try await openKey(password)
            wipe(&key)
        }
    }

    private func openKey(_ password: String) async throws -> [UInt8] {
        try MasterPasswordUnlock.checkThrottle(directory: directory, now: clock())
        let file = try MasterPasswordUnlock.readKeyFile(directory: directory)
        let held = blocked()
        do {
            var key = try await MasterPasswordUnlock.deriveKey(file, password: password)
            if held {
                // Blocked by the duress password: the same Argon2 ran; refused and counted as a wrong password.
                for i in key.indices { key[i] = 0 }
                throw MasterKeyError.wrongPassword
            }
            MasterPasswordUnlock.recordSuccess(directory: directory, now: clock())
            return key
        } catch MasterKeyError.wrongPassword {
            throw MasterPasswordUnlock.recordWrongPassword(directory: directory, now: clock())
        }
    }

    private func exclusive<T>(_ body: () async throws -> T) async throws -> T {
        let claimed = lock.withLock { () -> Bool in
            guard !attemptInFlight else { return false }
            attemptInFlight = true
            return true
        }
        guard claimed else { throw MacVaultError.busy }
        defer { lock.withLock { attemptInFlight = false } }
        return try await body()
    }
}

private func wipe(_ b: inout [UInt8]) { for i in b.indices { b[i] = 0 } }
#endif
