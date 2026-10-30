#if os(macOS)
import Foundation
import LGKCore

public enum MacVaultError: Error, Equatable {
    case wrongPassword(retryAfter: Date?)
    /// A well-formed recovery phrase that does not open this vault (counted by the shared throttle).
    case wrongRecoveryPhrase(retryAfter: Date?)
    case throttled(until: Date)
    case biometricUnavailable
    case passwordTooShort
    /// A new master password set through recovery is shorter than Windows allows (12).
    case passwordTooShortFor(minimum: Int)
    case alreadyExists
    case noVault
    /// Another password attempt is still running; this one was refused without running Argon2.
    case busy
    /// A scheduled backup held the vault longer than a prompt waits for it.
    case backupRunning
    /// A manual backup or restore is running: a key rotation (password or phrase change, recovery) waits for it.
    case backupOrRestoreRunning
}

/// Serves `.localKey` from memory and delegates every other slot, so the local key never sits in the
/// Keychain unprotected on the Mac (it is only ever sealed under the master password or the Touch ID item).
public final class MemoryKeyVault: KeychainVault, @unchecked Sendable {
    private let key: [UInt8]
    private let base: any KeychainVault
    public init(localKey: [UInt8], base: any KeychainVault) { self.key = localKey; self.base = base }

    public func read(_ slot: VaultSlot) throws -> [UInt8]? { slot == .localKey ? key : try base.read(slot) }
    public func write(_ slot: VaultSlot, _ bytes: [UInt8]) throws {
        guard slot != .localKey else { return }   // never persisted; the key is fixed for this vault
        try base.write(slot, bytes)
    }
    public func delete(_ slot: VaultSlot) throws { guard slot != .localKey else { return }; try base.delete(slot) }
}

/// The master-password steps the Mac app's `MacVault` and the AutoFill extension's `ExtensionVaultOpener`
/// share, so both apply the same key file, Argon2 parameters (those stored in the file) and `throttle.json`.
public enum MasterPasswordUnlock {
    public static let keyFileName = "master-key.json"

    /// When the next password attempt is allowed, or nil if it is allowed now.
    public static func retryAfter(directory: URL, now: Date) -> Date? {
        guard let until = UnlockThrottle.current(in: directory, now: now).waitUntil(), until > now else { return nil }
        return until
    }

    /// Throws `.throttled` while the shared throttle says wait; call before any Argon2.
    public static func checkThrottle(directory: URL, now: Date) throws {
        if let until = retryAfter(directory: directory, now: now) { throw MacVaultError.throttled(until: until) }
    }

    public static func readKeyFile(directory: URL) throws -> MasterKeyFile {
        KeyRotation.finish(directory: directory)   // an interrupted key rotation is settled before any key is used
        let url = directory.appendingPathComponent(keyFileName)
        guard let data = FileManager.default.contents(atPath: url.path) else { throw MacVaultError.noVault }
        do { return try JSONDecoder().decode(MasterKeyFile.self, from: data) } catch { throw MasterKeyError.corrupt }
    }

    /// Runs Argon2 off the calling actor; throws `MasterKeyError.wrongPassword` for a wrong password. Callers
    /// pass the outcome to `recordSuccess` or `recordWrongPassword` (both use the same shared throttle).
    public static func deriveKey(_ file: MasterKeyFile, password: String) async throws -> [UInt8] {
        try await Task.detached(priority: .userInitiated) { try file.open(password: password) }.value
    }

    /// Records a wrong password at `now` (taken after Argon2, so the wait runs from when the attempt ended)
    /// and returns the error to throw.
    public static func recordWrongPassword(directory: URL, now: Date) -> MacVaultError {
        UnlockThrottle.update(in: directory, now: now) { $0.recordFailure(at: now) }
        return .wrongPassword(retryAfter: retryAfter(directory: directory, now: now))
    }

    public static func recordSuccess(directory: URL, now: Date) {
        UnlockThrottle.update(in: directory, now: now) { t in
            if t != UnlockThrottle() { t.recordSuccess() }
        }
    }

    /// Resets the throttle to fresh (a new vault).
    public static func resetThrottle(directory: URL, now: Date) {
        UnlockThrottle.update(in: directory, now: now) { $0 = UnlockThrottle() }
    }

    // MARK: - Recovery phrase (Ruling 9)

    /// `file` with a new recovery wrapper of `localKey`, and the phrase (shown once by the caller, never stored).
    public static func enrolRecovery(_ file: MasterKeyFile, localKey: [UInt8],
                                     random: any RandomSource) throws -> (file: MasterKeyFile, phrase: String) {
        var entropy = Data(random.bytes(count: 32))
        defer { entropy.resetBytes(in: 0..<entropy.count) }
        var out = file
        out.recovery = try RecoveryWrapper.seal(localKey: localKey, entropy: entropy, random: random)
        return (out, try BIP39.phrase(entropy: entropy))
    }

    /// The local key from the recovery phrase, under the shared throttle (Windows `unlock_with_recovery_phrase`):
    /// the throttle is checked first; a malformed phrase throws its `RecoveryPhraseError` without counting (nothing
    /// secret was tried); a well-formed phrase that does not open the wrapper counts as a failed attempt.
    public static func openWithRecovery(directory: URL, phrase: String, now: () -> Date) throws -> (key: [UInt8], file: MasterKeyFile) {
        try checkThrottle(directory: directory, now: now())
        var entropy = try BIP39.entropy(from: phrase)
        defer { entropy.resetBytes(in: 0..<entropy.count) }
        let file = try readKeyFile(directory: directory)
        guard let wrapper = file.recovery else { throw RecoveryPhraseError("This vault has no recovery phrase") }
        do {
            let key = try RecoveryWrapper.open(wrapper, entropy: entropy)
            recordSuccess(directory: directory, now: now())
            return (key, file)
        } catch {
            UnlockThrottle.update(in: directory, now: now()) { $0.recordFailure(at: now()) }
            throw MacVaultError.wrongRecoveryPhrase(retryAfter: retryAfter(directory: directory, now: now()))
        }
    }

    /// Opens the store with the local key held in memory only.
    public static func openStore(directory: URL, key: [UInt8], keychain: any KeychainVault,
                                 random: any RandomSource) throws -> LocalStore {
        KeyRotation.finish(directory: directory)
        return try LocalStore.open(directory: directory, vault: MemoryKeyVault(localKey: key, base: keychain), random: random)
    }
}
#endif
