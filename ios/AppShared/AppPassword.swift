#if os(iOS)
import Foundation
import Security
import LocalAuthentication
import LGKCore

/// Task 7 (docs/superpowers/plans/2026-10-29-app-master-password.md): the optional iPhone app password.
///
/// The file is the Mac's `master-key.json` format (LGKCore `MasterKeyFile` with its `RecoveryWrapper`, desktop
/// Argon2id t=3, 64 MiB, p=4), named `app-password.json` in the app-group container. The local key stays the same;
/// while the file exists the `.userPresence` Keychain item of the local key is gone, so the passcode cannot open it.
public enum AppPasswordError: Error, Equatable {
    /// The password is on and no Face ID shortcut is set up (or it was cancelled): type the password.
    case required
    case wrongPassword
    case wrongPhrase
    case wait(seconds: Int64)
    /// Face ID enrolment changed: the shortcut was removed.
    case biometricChanged
    /// AutoFill without a Face ID shortcut: the app must be unlocked with the password first.
    case openAppFirst
    case corrupt
    /// Turning on while the file already exists (it would replace the recovery phrase).
    case alreadyOn
}

/// From the 5th consecutive wrong try: 30 s, doubling per further wrong try, at most 15 min (as Android).
public enum AppPasswordDelay {
    public static let freeTries = 4
    public static let firstDelay: Int64 = 30
    public static let maxDelay: Int64 = 15 * 60

    public static func seconds(failures: Int) -> Int64 {
        guard failures > freeTries else { return 0 }
        let steps = min(failures - freeTries - 1, 10)
        return min(firstDelay << Int64(steps), maxDelay)
    }

    public static func remaining(failures: Int, lastFailureAt: Int64, now: Int64) -> Int64 {
        let wait = seconds(failures: failures)
        guard wait > 0 else { return 0 }
        return max(wait - max(now - lastFailureAt, 0), 0)
    }

    /// As `remaining`, but a wall clock moved forward does not count as time passed: while the iPhone has not
    /// restarted (`sameBoot`, and the uptime did not go backwards) the elapsed time is the uptime's
    /// (`uptime - lastFailureUptime`). After a restart, or with no uptime stamp (`lastFailureUptime < 0`), the wall
    /// clock decides as before.
    public static func remaining(failures: Int, lastFailureAt: Int64, now: Int64,
                                 lastFailureUptime: Int64, uptime: Int64, sameBoot: Bool) -> Int64 {
        guard sameBoot, lastFailureUptime >= 0, uptime >= lastFailureUptime else {
            return remaining(failures: failures, lastFailureAt: lastFailureAt, now: now)
        }
        let wait = seconds(failures: failures)
        guard wait > 0 else { return 0 }
        return max(wait - (uptime - lastFailureUptime), 0)
    }
}

/// A clock a wall-clock change does not move: seconds since boot and which boot it is. The wrong-try delay uses it
/// so setting the date forward does not skip the wait.
public protocol AppPasswordBootClock: Sendable {
    /// Seconds since boot (`ProcessInfo.systemUptime`; time asleep does not count, which only makes the wait longer).
    var uptime: Int64 { get }
    /// This boot's identifier (`kern.bootsessionuuid`), nil when unknown.
    var bootID: String? { get }
}

public struct SystemBootClock: AppPasswordBootClock {
    public init() {}
    public var uptime: Int64 { Int64(ProcessInfo.processInfo.systemUptime) }
    public var bootID: String? {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &buf, &size, nil, 0) == 0 else { return nil }
        let id = String(cString: buf)
        return id.isEmpty ? nil : id
    }
}

/// Whether the app password is on, read from disk (no global state). Used by `VaultSlot.accessFlags`.
public enum AppPasswordMode {
    public static var isOn: Bool {
        guard let url = AppPasswordStore.defaultURL else { return false }
        return FileManager.default.fileExists(atPath: url.path)
    }
}

/// The Face ID shortcut: a Keychain item `WhenUnlockedThisDeviceOnly` + `.biometryCurrentSet` (no passcode), in the
/// group shared with AutoFill. A new face or finger makes it unreadable.
public protocol AppPasswordBiometricStore: AnyObject, Sendable {
    func store(_ key: [UInt8]) throws
    /// Reads with an already evaluated biometric context (no second prompt).
    func load(context: LAContext) throws -> [UInt8]
    func remove() throws
    var exists: Bool { get }
}

public final class PhoneBiometricKeyStore: AppPasswordBiometricStore, @unchecked Sendable {
    public static let service = "com.localgatekeys.app.biometric"
    public static let account = "local-key"
    let accessGroup: String?

    public init(accessGroup: String? = AppGroup.keychainAccessGroup) { self.accessGroup = accessGroup }

    private func base() -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: Self.service,
                                kSecAttrAccount as String: Self.account,
                                kSecAttrSynchronizable as String: false,
                                kSecUseDataProtectionKeychain as String: true]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    public func store(_ key: [UInt8]) throws {
        try remove()   // access control cannot be updated in place
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       .biometryCurrentSet, nil) else { throw KeychainVaultError.accessControl }
        var q = base()
        q[kSecValueData as String] = Data(key)
        q[kSecAttrAccessControl as String] = ac
        let st = SecItemAdd(q as CFDictionary, nil)
        guard st == errSecSuccess else { throw KeychainVaultError.status(st) }
    }

    public func load(context: LAContext) throws -> [UInt8] {
        var q = base()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecUseAuthenticationContext as String] = context
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        switch st {
        case errSecSuccess:
            guard let d = out as? Data else { throw KeychainVaultError.status(st) }
            return Array(d)
        // An item whose biometric set changed can no longer be read: the shortcut is gone.
        case errSecItemNotFound, errSecAuthFailed, errSecInvalidData: throw AppPasswordError.biometricChanged
        case errSecUserCanceled: throw LAError(.userCancel)
        default: throw KeychainVaultError.status(st)
        }
    }

    public func remove() throws {
        let st = SecItemDelete(base() as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw KeychainVaultError.status(st) }
    }

    /// Attributes only, with a context that forbids UI.
    public var exists: Bool {
        let noUI = LAContext()
        noUI.interactionNotAllowed = true
        var q = base()
        q[kSecUseAuthenticationContext as String] = noUI
        q[kSecReturnAttributes as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        return st == errSecSuccess || st == errSecInteractionNotAllowed
    }
}

/// Serves `.localKey` from memory and delegates every other slot (the iPhone twin of the Mac's `MemoryKeyVault`).
/// `clear()` (at lock) overwrites the held key with zeros; reads of `.localKey` return nil afterwards.
public final class AppPasswordKeyVault: KeychainVault, @unchecked Sendable {
    private var key: [UInt8]
    private var cleared = false
    private let guardLock = NSLock()
    public let base: any KeychainVault
    public init(localKey: [UInt8], base: any KeychainVault) { self.key = localKey; self.base = base }

    deinit { clear() }

    /// Zeroes the key in place (the buffer this vault owns; copies already handed out are the caller's).
    public func clear() {
        guardLock.lock(); defer { guardLock.unlock() }
        key.withUnsafeMutableBytes { raw in
            guard let p = raw.baseAddress else { return }
            _ = memset_s(p, raw.count, 0, raw.count)
        }
        cleared = true
    }

    public var isCleared: Bool { guardLock.lock(); defer { guardLock.unlock() }; return cleared }

    /// For tests: the bytes currently held (zeros after `clear()`).
    var heldBytes: [UInt8] { guardLock.lock(); defer { guardLock.unlock() }; return key }

    public func read(_ slot: VaultSlot) throws -> [UInt8]? {
        guard slot == .localKey else { return try base.read(slot) }
        guardLock.lock(); defer { guardLock.unlock() }
        return cleared ? nil : Array(key)
    }
    public func write(_ slot: VaultSlot, _ bytes: [UInt8]) throws {
        guard slot != .localKey else { return }   // never persisted in password mode
        try base.write(slot, bytes)
    }
    public func delete(_ slot: VaultSlot) throws { guard slot != .localKey else { return }; try base.delete(slot) }
}

/// `app-password.json`, the wrong-try count and the Face ID shortcut. Never logs or stores a password or phrase.
public final class AppPasswordStore: @unchecked Sendable {
    public static let fileName = "app-password.json"
    static let failuresKey = "settings.unlockFailures"
    static let failureAtKey = "settings.unlockFailureAt"
    static let failureUptimeKey = "settings.unlockFailureUptime"
    static let failureBootKey = "settings.unlockFailureBoot"

    public static var defaultURL: URL? { AppGroup.containerURL?.appendingPathComponent(fileName) }

    public let url: URL
    public let biometric: any AppPasswordBiometricStore
    private let defaults: UserDefaults
    private let now: @Sendable () -> Int64
    private let bootClock: any AppPasswordBootClock
    /// `.default` (desktop) in the app; tests pass a cheaper one.
    private let params: MasterKeyFile.KDFParams

    public init(url: URL, biometric: any AppPasswordBiometricStore, defaults: UserDefaults,
                params: MasterKeyFile.KDFParams = .default,
                now: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970) },
                bootClock: any AppPasswordBootClock = SystemBootClock()) {
        self.url = url; self.biometric = biometric; self.defaults = defaults; self.params = params; self.now = now
        self.bootClock = bootClock
    }

    /// The app's store, or nil without the app-group container (unsigned builds).
    public static func shared() -> AppPasswordStore? {
        guard let url = defaultURL else { return nil }
        return AppPasswordStore(url: url, biometric: PhoneBiometricKeyStore(),
                                defaults: UserDefaults(suiteName: AppGroup.identifier) ?? .standard)
    }

    public var isOn: Bool { FileManager.default.fileExists(atPath: url.path) }
    public var biometricOn: Bool { isOn && biometric.exists }

    public func readFile() throws -> MasterKeyFile {
        guard let data = FileManager.default.contents(atPath: url.path) else { throw AppPasswordError.required }
        do { return try JSONDecoder().decode(MasterKeyFile.self, from: data) } catch { throw AppPasswordError.corrupt }
    }

    public func write(_ file: MasterKeyFile) throws {
        let enc = JSONEncoder()
        enc.outputFormatting = .sortedKeys
        try enc.encode(file).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    public func waitSeconds() -> Int64 {
        let boot = bootClock.bootID
        let stampBoot = defaults.string(forKey: Self.failureBootKey)
        let stampUptime: Int64 = defaults.object(forKey: Self.failureUptimeKey) == nil
            ? -1 : Int64(defaults.integer(forKey: Self.failureUptimeKey))
        return AppPasswordDelay.remaining(failures: defaults.integer(forKey: Self.failuresKey),
                                          lastFailureAt: Int64(defaults.integer(forKey: Self.failureAtKey)), now: now(),
                                          lastFailureUptime: stampUptime, uptime: bootClock.uptime,
                                          sameBoot: boot != nil && boot == stampBoot)
    }

    private func counted(_ wrong: AppPasswordError, _ body: () throws -> [UInt8]) throws -> [UInt8] {
        let wait = waitSeconds()
        if wait > 0 { throw AppPasswordError.wait(seconds: wait) }
        do {
            let key = try body()
            if defaults.integer(forKey: Self.failuresKey) != 0 { defaults.set(0, forKey: Self.failuresKey) }
            return key
        } catch MasterKeyError.wrongPassword {
            noteFailure(); throw wrong
        } catch let e as RecoveryPhraseError {
            noteFailure()
            if e == .notThisVault { throw AppPasswordError.wrongPhrase }
            throw e
        }
    }

    private func noteFailure() {
        defaults.set(Int(now()), forKey: Self.failureAtKey)
        defaults.set(Int(bootClock.uptime), forKey: Self.failureUptimeKey)
        if let boot = bootClock.bootID {
            defaults.set(boot, forKey: Self.failureBootKey)
        } else {
            defaults.removeObject(forKey: Self.failureBootKey)
        }
        defaults.set(defaults.integer(forKey: Self.failuresKey) + 1, forKey: Self.failuresKey)
    }

    /// The local key; Argon2id runs on the calling thread (call it off the main actor).
    public func open(password: String) throws -> [UInt8] {
        let file = try readFile()
        return try counted(.wrongPassword) { try file.open(password: password) }
    }

    public func open(phrase: String) throws -> [UInt8] {
        let file = try readFile()
        guard let wrapper = file.recovery else { throw AppPasswordError.corrupt }
        return try counted(.wrongPhrase) {
            var entropy = try BIP39.entropy(from: phrase)
            defer { entropy.resetBytes(in: 0..<entropy.count) }
            return try RecoveryWrapper.open(wrapper, entropy: entropy)
        }
    }

    /// Turning on, step 1: the file and the phrase to show once. Nothing is written.
    public func prepare(localKey: [UInt8], password: String, random: any RandomSource) throws -> (file: MasterKeyFile, phrase: String) {
        var file = try MasterKeyFile.seal(localKey: localKey, password: password, params: params, random: random)
        var entropy = Data(random.bytes(count: 32))
        defer { entropy.resetBytes(in: 0..<entropy.count) }
        file.recovery = try RecoveryWrapper.seal(localKey: localKey, entropy: entropy, random: random)
        return (file, try BIP39.phrase(entropy: entropy))
    }

    /// A new password wrapper; the recovery wrapper is kept.
    public func withNewPassword(_ file: MasterKeyFile, localKey: [UInt8], password: String, random: any RandomSource) throws -> MasterKeyFile {
        var out = try MasterKeyFile.seal(localKey: localKey, password: password, params: params, random: random)
        out.recovery = file.recovery
        return out
    }

    /// Erase and turn-off: the shortcut, then the file. True when both are gone.
    @discardableResult
    public func removeAll() -> Bool {
        var ok = true
        do { try biometric.remove() } catch { ok = false }
        if isOn { do { try FileManager.default.removeItem(at: url) } catch { ok = false } }
        return ok
    }
}

/// Where a slot's bytes wait while `reprotect` replaces its item, so a crash between the delete and the add loses
/// nothing; `pending` stays set from the start of a mode change (`begin`) until `reprotect` finished.
public protocol AppPasswordReprotectJournal: AnyObject, Sendable {
    func save(_ slot: VaultSlot, _ bytes: [UInt8]) throws
    func load(_ slot: VaultSlot) throws -> [UInt8]?
    func remove(_ slot: VaultSlot) throws
    func isPending() throws -> Bool
    func setPending(_ on: Bool) throws
}

/// The journal in the Keychain: its own service, `WhenUnlockedThisDeviceOnly` without `.userPresence` (the slots it
/// holds are sync state, no vault secret), never synchronised.
public final class KeychainReprotectJournal: AppPasswordReprotectJournal, @unchecked Sendable {
    public static let service = "com.localgatekeys.reprotect"
    static let pendingAccount = "pending"
    let accessGroup: String?

    public init(accessGroup: String? = AppGroup.keychainAccessGroup) { self.accessGroup = accessGroup }

    private func base(_ account: String) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: Self.service,
                                kSecAttrAccount as String: account,
                                kSecAttrSynchronizable as String: false,
                                kSecUseDataProtectionKeychain as String: true]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    private func put(_ account: String, _ bytes: [UInt8]) throws {
        let st = SecItemUpdate(base(account) as CFDictionary, [kSecValueData as String: Data(bytes)] as CFDictionary)
        if st == errSecSuccess { return }
        guard st == errSecItemNotFound else { throw KeychainVaultError.status(st) }
        var q = base(account)
        q[kSecValueData as String] = Data(bytes)
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let added = SecItemAdd(q as CFDictionary, nil)
        guard added == errSecSuccess else { throw KeychainVaultError.status(added) }
    }

    private func get(_ account: String) throws -> [UInt8]? {
        var q = base(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecItemNotFound { return nil }
        guard st == errSecSuccess, let d = out as? Data else { throw KeychainVaultError.status(st) }
        return Array(d)
    }

    private func drop(_ account: String) throws {
        let st = SecItemDelete(base(account) as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw KeychainVaultError.status(st) }
    }

    public func save(_ slot: VaultSlot, _ bytes: [UInt8]) throws { try put("slot." + slot.rawValue, bytes) }
    public func load(_ slot: VaultSlot) throws -> [UInt8]? { try get("slot." + slot.rawValue) }
    public func remove(_ slot: VaultSlot) throws { try drop("slot." + slot.rawValue) }
    public func isPending() throws -> Bool { try get(Self.pendingAccount) != nil }
    public func setPending(_ on: Bool) throws {
        if on { try put(Self.pendingAccount, [1]) } else { try drop(Self.pendingAccount) }
    }
}

/// Re-adds every passcode-protected slot except the local key with the access flags of the current mode
/// (`VaultSlot.accessFlags`): `[]` while the app password is on, so sync reads never show a passcode prompt;
/// `.userPresence` again after it is turned off. `keychain` must be readable now (the unlocked app's).
///
/// Crash-safe: a slot's bytes go into the journal before its item is deleted and re-added, and leave it after;
/// `recover` adds back an item a crash left deleted. A mode change calls `begin` before it touches anything, and
/// `repairAtUnlock` (every unlock, both modes) re-runs `reprotect` while that mark is still set.
public enum AppPasswordKeychainMigration {
    static var slots: [VaultSlot] {
        VaultSlot.allCases.filter { $0 != .localKey && !VaultSlot.deviceUnlocked.contains($0) }
    }

    /// Marks a mode change as started (before the password file is written or removed).
    public static func begin(journal: any AppPasswordReprotectJournal = KeychainReprotectJournal()) throws {
        try journal.setPending(true)
    }

    public static func reprotect(_ keychain: any KeychainVault,
                                 journal: any AppPasswordReprotectJournal = KeychainReprotectJournal()) throws {
        try journal.setPending(true)
        try recover(keychain, journal: journal)
        for slot in slots {
            guard let bytes = try keychain.read(slot) else { continue }
            try journal.save(slot, bytes)
            try keychain.delete(slot)
            try keychain.write(slot, bytes)
            try journal.remove(slot)
        }
        try journal.setPending(false)
    }

    /// A slot left in the journal: its item is added back if a crash left it deleted; then the journal copy goes.
    public static func recover(_ keychain: any KeychainVault, journal: any AppPasswordReprotectJournal) throws {
        for slot in slots {
            guard let bytes = try journal.load(slot) else { continue }
            if try keychain.read(slot) == nil { try keychain.write(slot, bytes) }
            try journal.remove(slot)
        }
    }

    /// At every unlock, before the store opens: finishes a mode change a crash or an error interrupted, for the mode
    /// the password file says (idempotent). With nothing pending no item is rewritten, so AutoFill never finds a
    /// counter item missing during an ordinary unlock.
    public static func repairAtUnlock(_ keychain: any KeychainVault,
                                      journal: any AppPasswordReprotectJournal = KeychainReprotectJournal()) throws {
        if try journal.isPending() {
            try reprotect(keychain, journal: journal)
        } else {
            try recover(keychain, journal: journal)
        }
    }
}
#endif
