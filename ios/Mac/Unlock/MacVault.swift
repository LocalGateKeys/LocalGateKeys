import Foundation
import LGKCore
import AppSharedMac

// MacVaultError, MemoryKeyVault, UnlockThrottle and the Touch ID key store live in AppShared/MacVault, shared
// with the AutoFill extension (ExtensionVaultOpener).

/// The Mac vault: the local key sealed under the master password (`master-key.json`), optionally also in a
/// Touch ID Keychain item, with the desktop unlock throttle (`throttle.json`).
@MainActor
final class MacVault {
    static let keyFileName = MasterPasswordUnlock.keyFileName
    static let minPasswordLength = 8

    let directory: URL
    private let keychain: any KeychainVault
    private let biometric: any BiometricKeyStore
    private let clock: () -> Date
    private let random: any RandomSource
    private var kdfParams = MasterKeyFile.KDFParams.default
    /// True while a password attempt runs, so a concurrent one cannot slip past the throttle.
    private var attemptInFlight = false
    private var beforeKDF: (@MainActor () async -> Void)?
    private var afterKDF: (@MainActor () async -> Void)?

    init(directory: URL, keychain: any KeychainVault, biometric: any BiometricKeyStore,
         clock: @escaping () -> Date = Date.init, random: any RandomSource = SystemRandomSource()) {
        self.directory = directory; self.keychain = keychain; self.biometric = biometric
        self.clock = clock; self.random = random
    }

    #if DEBUG
    /// Test hooks (Debug builds only): cheaper Argon2 `kdfParams`; `beforeKDF` is awaited just before Argon2 runs
    /// (create and every password attempt), so a test can hold an attempt open; `afterKDF` once it has returned.
    convenience init(directory: URL, keychain: any KeychainVault, biometric: any BiometricKeyStore,
                     clock: @escaping () -> Date = Date.init, random: any RandomSource = SystemRandomSource(),
                     kdfParams: MasterKeyFile.KDFParams, beforeKDF: (@MainActor () async -> Void)? = nil,
                     afterKDF: (@MainActor () async -> Void)? = nil) {
        self.init(directory: directory, keychain: keychain, biometric: biometric, clock: clock, random: random)
        self.kdfParams = kdfParams; self.beforeKDF = beforeKDF; self.afterKDF = afterKDF
    }
    #endif

    private var keyFileURL: URL { directory.appendingPathComponent(Self.keyFileName) }

    var exists: Bool { FileManager.default.fileExists(atPath: keyFileURL.path) }

    /// When the next password attempt is allowed, or nil if it is allowed now.
    var retryAfter: Date? {
        MasterPasswordUnlock.retryAfter(directory: directory, now: clock())
    }

    /// Writes `master-key.json` last; if any step fails, everything this call created is removed again,
    /// so no half-created vault is left behind.
    func create(password: String, enableTouchID: Bool) async throws -> LocalStore {
        guard !exists else { throw MacVaultError.alreadyExists }
        try Self.checkNew(password)
        let fm = FileManager.default
        try fm.createDirectory(at: directory, withIntermediateDirectories: true)
        let before = Set((try? fm.contentsOfDirectory(atPath: directory.path)) ?? [])
        var key = random.bytes(count: 32)
        defer { wipe(&key) }
        var storedBiometric = false
        do {
            await beforeKDF?()
            let file = try await Self.seal(key, password: password, params: kdfParams, random: random)
            let store = try LocalStore.bootstrap(directory: directory, vault: MemoryKeyVault(localKey: key, base: keychain), random: random)
            if enableTouchID, biometric.isAvailable { try biometric.store(key); storedBiometric = true }
            touchIDStored = storedBiometric
            try writeKeyFile(file)
            hasRecoveryPhrase = false
            setOpenedLocalKey(key)
            MasterPasswordUnlock.resetThrottle(directory: directory, now: clock())
            return store
        } catch {
            discardOpenedLocalKey()
            if storedBiometric { try? biometric.remove(); touchIDStored = false }
            for name in Set((try? fm.contentsOfDirectory(atPath: directory.path)) ?? []).subtracting(before) {
                try? fm.removeItem(at: directory.appendingPathComponent(name))
            }
            throw error
        }
    }

    func unlock(password: String) async throws -> LocalStore {
        try await exclusive {
            var key = try await openKey(password)
            defer { wipe(&key) }
            do { return try openStore(key) } catch { discardOpenedLocalKey(); throw error }
        }
    }

    func unlockWithTouchID(reason: String) async throws -> LocalStore {
        guard exists else { throw MacVaultError.noVault }
        guard biometric.isAvailable else { throw MacVaultError.biometricUnavailable }
        return try await exclusive {
            var key: [UInt8]
            do { key = try await biometric.load(reason: reason) }
            catch BiometricKeyError.cancelled { throw BiometricKeyError.cancelled }
            catch { throw MacVaultError.biometricUnavailable }   // item gone (enrolment changed) or unreadable
            defer { wipe(&key) }
            do {
                let store = try openStore(key)   // store errors are real errors, not a Touch ID problem
                recordSuccess()
                return store
            } catch { discardOpenedLocalKey(); throw error }
        }
    }

    /// True when the Touch ID item was stored by this vault and not removed (create / setTouchID).
    private(set) var touchIDStored = false

    /// Seals the local key under `new` after rotating it (Windows `change_master_password` rotates the data key): an
    /// old `master-key.json` with the old password then opens nothing current. The recovery phrase keeps working;
    /// the Touch ID item is removed (it holds the old key) until the user turns it on again.
    @discardableResult
    func changePassword(old: String, new: String) async throws -> LocalStore {
        try Self.checkNew(new)
        return try await exclusive {
            var key = try await openKey(old)
            defer { wipe(&key) }
            return try await rotate(oldKey: key, password: new, recovery: .keep, passwordChanged: true)
        }
    }

    // MARK: - Recovery phrase (Ruling 9)

    /// Windows' minimum for a master password set through recovery (`vault.py` MIN_MASTER_PASSWORD_LENGTH).
    static let recoveredPasswordMinimum = 12
    static let damagedRecovery = RecoveryPhraseError(String(localized: "The recovery phrase on this Mac is damaged. Remove it and create a new one."))

    /// A new phrase, a new local key and the key file sealing it under the current password and the phrase. Nothing
    /// is written until `confirmRecovery`, after the user has typed three words back. Holds both keys until then
    /// (zeroed when released): confirming rotates the vault to the new key, as Windows does for a new phrase.
    final class PreparedRecovery {
        let phrase: String
        fileprivate let file: MasterKeyFile
        fileprivate let basis: MasterKeyFile
        fileprivate var oldKey: [UInt8]
        fileprivate var newKey: [UInt8]
        fileprivate init(phrase: String, file: MasterKeyFile, basis: MasterKeyFile, oldKey: [UInt8], newKey: [UInt8]) {
            self.phrase = phrase; self.file = file; self.basis = basis; self.oldKey = oldKey; self.newKey = newKey
        }
        deinit { wipe(&oldKey); wipe(&newKey) }
    }

    /// True when `master-key.json` carries a recovery wrapper; cached, refreshed whenever this vault changes it.
    private(set) lazy var hasRecoveryPhrase: Bool = readHasRecovery()

    private func readHasRecovery() -> Bool { (try? MasterPasswordUnlock.readKeyFile(directory: directory))?.recovery != nil }

    /// Checks the master password (throttled) and prepares a new phrase; replaces any earlier phrase once confirmed.
    func prepareRecovery(password: String) async throws -> PreparedRecovery {
        try await exclusive {
            let basis = try MasterPasswordUnlock.readKeyFile(directory: directory)
            var key = try await openKey(password)
            defer { wipe(&key) }
            var newKey = random.bytes(count: 32)
            defer { wipe(&newKey) }
            let sealed = try await Self.seal(newKey, password: password, params: kdfParams, random: random)
            let (file, phrase) = try MasterPasswordUnlock.enrolRecovery(sealed, localKey: newKey, random: random)
            return PreparedRecovery(phrase: phrase, file: file, basis: basis, oldKey: key, newKey: newKey)
        }
    }

    /// Rotates to the prepared key and phrase, unless the key file changed meanwhile (then nothing is written).
    @discardableResult
    func confirmRecovery(_ prepared: PreparedRecovery) async throws -> LocalStore {
        try await exclusive {
            let current = try MasterPasswordUnlock.readKeyFile(directory: directory)
            guard current.samePasswordWrapper(as: prepared.basis), current.recovery == prepared.basis.recovery else {
                throw RecoveryPhraseError(String(localized: "The master password changed while the phrase was shown. Create a new phrase."))
            }
            return try commitRotation(oldKey: prepared.oldKey, newKey: prepared.newKey, file: prepared.file, schedule: ScheduleUpdate())
        }
    }

    /// Removes the recovery phrase after checking the master password, rotating the key (Windows
    /// `remove_recovery_phrase`), so an old copy of the key file with the phrase opens nothing current.
    @discardableResult
    func removeRecovery(password: String) async throws -> LocalStore {
        try await exclusive {
            var key = try await openKey(password)
            defer { wipe(&key) }
            return try await rotate(oldKey: key, password: password, recovery: .remove, passwordChanged: false)
        }
    }

    /// Opens the local key with the recovery phrase and sets `newPassword` (12 to 4096 characters, as Windows),
    /// rotating the key (Windows `set_master_password_after_recovery`); the phrase stays valid; the Touch ID item is
    /// removed. Wrong phrases share the password throttle.
    @discardableResult
    func recover(phrase: String, newPassword: String) async throws -> LocalStore {
        guard newPassword.unicodeScalars.count >= Self.recoveredPasswordMinimum else {
            throw MacVaultError.passwordTooShortFor(minimum: Self.recoveredPasswordMinimum)
        }
        guard newPassword.unicodeScalars.count <= 4096 else { throw MasterKeyError.tooLong }
        return try await exclusive {
            var opened = try MasterPasswordUnlock.openWithRecovery(directory: directory, phrase: phrase, now: clock)
            defer { wipe(&opened.key) }
            await beforeKDF?()
            return try await rotate(oldKey: opened.key, password: newPassword, recovery: .keep, passwordChanged: true)
        }
    }

    /// The recovery key for a `vault.json` this Mac seals (full backups), after checking the master password; nil
    /// when no phrase is enrolled. A damaged one is an error, never a backup silently without the phrase.
    func recoveryVaultKey(password: String) async throws -> RecoveryWrapper.VaultKey? {
        try await exclusive {
            var key = try await openKey(password)
            defer { wipe(&key) }
            guard let wrapper = try MasterPasswordUnlock.readKeyFile(directory: directory).recovery else { return nil }
            do { return try RecoveryWrapper.vaultKey(for: wrapper, localKey: key) } catch { throw Self.damagedRecovery }
        }
    }

    // MARK: - Key rotation

    private enum RecoveryChange { case keep, remove }

    #if DEBUG
    /// Test seam: the rotation stops at this step as if the app died there (nothing is cleaned up).
    var rotationCrash: KeyRotation.Step?
    #endif

    /// A new local key sealed under `password`, the phrase kept (re-wrapped) or removed, then `commitRotation`.
    private func rotate(oldKey: [UInt8], password: String, recovery: RecoveryChange, passwordChanged: Bool) async throws -> LocalStore {
        let old = try MasterPasswordUnlock.readKeyFile(directory: directory)
        var newKey = random.bytes(count: 32)
        defer { wipe(&newKey) }
        var file = try await Self.seal(newKey, password: password, params: kdfParams, random: random)
        if case .keep = recovery, let wrapper = old.recovery {
            do { file.recovery = try RecoveryWrapper.reseal(wrapper, oldLocalKey: oldKey, newLocalKey: newKey, random: random) }
            catch { throw Self.damagedRecovery }
        }
        // Scheduled backups' vault.json key follows the new master password (Argon2 here, before the vault lock).
        var schedule = ScheduleUpdate(newPassword: passwordChanged ? password : nil)
        if passwordChanged, let old = try? ScheduleSecretStore(directory: directory, localKey: oldKey).load(),
           !old.backupPassword.utf8.elementsEqual(password.utf8) {
            let kdf = old.passwordKey.kdf
            let rnd = random
            schedule.passwordKey = try await Task.detached(priority: .userInitiated) {
                try DesktopVaultFile.derivePasswordKey(password: password, kdf: kdf, random: rnd)
            }.value
        }
        defer { schedule.passwordKey?.wipe() }
        return try commitRotation(oldKey: oldKey, newKey: newKey, file: file, schedule: schedule)
    }

    /// Stages every file sealed under `oldKey` re-sealed under `newKey`, removes the Touch ID item, commits
    /// `master-key.json` and rolls the rest forward (`KeyRotation`), all under the vault lock with no suspension
    /// point, so no commit or Mac-local save lands in between. Opens the store under the new key.
    /// How the scheduled-backup secret follows a rotation: a new master password (its key derived beforehand). The
    /// phrase key always follows the new key file (rebuilt for a new phrase, gone with a removed one).
    struct ScheduleUpdate {
        var newPassword: String?
        var passwordKey: DesktopVaultFile.PasswordKey?
    }

    private func commitRotation(oldKey: [UInt8], newKey: [UInt8], file: MasterKeyFile, schedule update: ScheduleUpdate) throws -> LocalStore {
        // A manual backup or restore reads and swaps the store under the old key outside this vault's lock: the rotation
        // is refused while one runs (it never waits, so it can't deadlock with it). The check and the whole commit are
        // synchronous on the main actor, so no restore can start in between. A scheduled run holds `exclusive`, so the
        // rotation has already waited it out.
        guard !MacFullBackup.anyInFlight else { throw MacVaultError.backupOrRestoreRunning }
        let staging = KeyRotation.stagingURL(directory)
        let fm = FileManager.default
        var committed = false
        do {
            try KeyRotation.withLock(directory) {
                try KeyRotation.settleLocked(directory: directory) { _ in }   // an earlier interrupted rotation first
                // Everything is read under the old key before anything is staged.
                let oldStore = try MasterPasswordUnlock.openStore(directory: directory, key: oldKey, keychain: keychain, random: random)
                let snapshot = try oldStore.load()
                var localData: LocalData?
                if fm.fileExists(atPath: directory.appendingPathComponent(MacLocalStore.fileName).path) {
                    let old = MacLocalStore(directory: directory, localKey: oldKey)
                    let (data, _) = old.load()
                    // An unreadable file that could not be moved aside must never be overwritten.
                    guard !old.isBlocked else { throw MacLocalStore.Failure.unreadableFileInPlace }
                    localData = data
                }
                let oldProfile = DesktopProfileStore(directory: directory, localKey: oldKey)
                let profile = fm.fileExists(atPath: oldProfile.fileURL.path) ? try oldProfile.load() : nil
                var copies: [(rel: String, records: (records: [String: JSONValue], revision: Int64), kept: DesktopProfileStore.Contents?)] = []
                var setAside: [String] = []
                for copy in MacFullBackup.safetyCopies(in: directory) {
                    let keptURL = copy.folder.appendingPathComponent(DesktopProfileStore.fileName)
                    do {
                        let records = try oldProfile.openRecords(copy.folder.appendingPathComponent("records.bin"))
                        let kept = fm.fileExists(atPath: keptURL.path) ? try oldProfile.read(keptURL) : nil
                        copies.append(("\(MacFullBackup.backupsName)/\(copy.folder.lastPathComponent)", records, kept))
                    } catch {
                        // Unreadable under the old key: set aside (outside the `before-restore-` names), not lost.
                        let name = copy.folder.lastPathComponent + ".unreadable"
                        try fm.moveItem(at: copy.folder, to: copy.folder.deletingLastPathComponent().appendingPathComponent(name))
                        setAside.append(name)
                    }
                }
                lastRotationSetAside = setAside
                // The scheduled-backup secret (unreadable under the old key: not carried over, removed by the roll-forward).
                let scheduleFile = directory.appendingPathComponent(ScheduleSecretStore.fileName)
                var schedule: ScheduledBackupSecret?
                if fm.fileExists(atPath: scheduleFile.path),
                   var s = (try? ScheduleSecretStore(directory: directory, localKey: oldKey).load()) ?? nil {
                    if let pw = update.newPassword, s.backupPassword.utf8.elementsEqual(pw.utf8) {
                        s.wipe()   // the backup password may not be the master password: cleared
                    } else {
                        if let k = update.passwordKey { s.passwordKey = k }
                        s.recovery = file.recovery.flatMap { try? RecoveryWrapper.vaultKey(for: $0, localKey: newKey) }
                        schedule = s
                    }
                }
                let dropSchedule = schedule == nil && fm.fileExists(atPath: scheduleFile.path)

                try fm.createDirectory(at: staging, withIntermediateDirectories: true)
                // The store, as a generation under a name no file uses yet, under the new key.
                let existing = ((try? fm.contentsOfDirectory(atPath: directory.path)) ?? [])
                    .filter(KeyRotation.isGeneration).compactMap { Int64($0.dropFirst()) }
                let revision = max(LocalStore.committedRevision(directory: directory) ?? 0, existing.max() ?? 0) + 1
                try LocalStore.stageGeneration(snapshot, revision: revision, key: newKey, random: random, into: staging)
                try KeyRotation.writeSynced(Data("\(revision)\n".utf8), to: staging.appendingPathComponent("CURRENT"))
                // It must decrypt under the new key, with every record, before anything moves.
                let staged = try LocalStore.open(directory: staging, vault: MemoryKeyVault(localKey: newKey, base: keychain),
                                                 random: random, limitHints: nil).load()
                guard staged.records == snapshot.records, staged.meta == snapshot.meta else {
                    throw LocalStoreError.corrupt("staged generation")
                }
                // Mac-local data, the kept Windows profile and every readable safety copy (re-sealed: they are the undo).
                if let localData { try MacLocalStore(directory: staging, localKey: newKey, random: random).save(localData) }
                let newProfile = DesktopProfileStore(directory: staging, localKey: newKey, random: random)
                if let profile { try KeyRotation.writeSynced(try newProfile.seal(profile), to: newProfile.fileURL) }
                for copy in copies {
                    try KeyRotation.writeSynced(try newProfile.sealRecords(copy.records.records, revision: copy.records.revision),
                                                to: staging.appendingPathComponent("\(copy.rel)/records.bin"))
                    if let kept = copy.kept {
                        try KeyRotation.writeSynced(try newProfile.seal(kept),
                                                    to: staging.appendingPathComponent("\(copy.rel)/\(DesktopProfileStore.fileName)"))
                    }
                }
                if dropSchedule {
                    // Staged as a deletion, so the roll-forward (now or after a crash) removes the old-key file.
                    try KeyRotation.writeSynced(Data(), to: staging.appendingPathComponent(ScheduleSecretStore.fileName + KeyRotation.dropSuffix))
                }
                if var schedule {
                    defer { schedule.wipe() }
                    try KeyRotation.writeSynced(try ScheduleSecretStore(directory: staging, localKey: newKey, random: random).seal(schedule),
                                                to: staging.appendingPathComponent(ScheduleSecretStore.fileName))
                }
                let enc = JSONEncoder()
                enc.outputFormatting = .sortedKeys
                try KeyRotation.writeSynced(try enc.encode(file), to: staging.appendingPathComponent(Self.keyFileName))
                try KeyRotation.writeSynced(Data(), to: staging.appendingPathComponent("READY"))
                try crashPoint(.staged)
                // The Touch ID item holds the old key; it goes before the commit so it can never outlive it.
                try? biometric.remove()
                touchIDStored = false
                try KeyRotation.commit(directory: directory)
                committed = true
                try crashPoint(.committed)
                try KeyRotation.settleLocked(directory: directory) { try crashPoint($0) }
            }
        } catch {
            #if DEBUG
            if error is KeyRotation.SimulatedCrash { throw error }
            #endif
            if !committed { try? fm.removeItem(at: staging) }   // after the commit, the next open rolls forward
            throw error
        }
        hasRecoveryPhrase = file.recovery != nil
        return try openStore(newKey)
    }

    /// Safety copies the last rotation could not read under the old key and set aside as `<name>.unreadable`.
    private(set) var lastRotationSetAside: [String] = []

    private func crashPoint(_ step: KeyRotation.Step) throws {
        #if DEBUG
        if rotationCrash == step { throw KeyRotation.SimulatedCrash() }
        #endif
    }

    /// Checks the master password without opening anything (the unlock throttle applies), e.g. before showing
    /// a code that needs the master password.
    func verifyPassword(_ password: String) async throws {
        try await exclusive {
            var key = try await openKey(password)
            wipe(&key)
        }
    }

    /// True when this Mac can hold the Touch ID item (Touch ID present and enrolled).
    var touchIDAvailable: Bool { biometric.isAvailable }

    func setTouchID(_ on: Bool, password: String) async throws {
        try await exclusive {
            var key = try await openKey(password)
            defer { wipe(&key) }
            if on {
                guard biometric.isAvailable else { throw MacVaultError.biometricUnavailable }
                try biometric.store(key)
                touchIDStored = true
            } else {
                try biometric.remove()
                touchIDStored = false
            }
        }
    }

    // MARK: - Private

    /// Checks the throttle before running Argon2, then opens the key file and records the outcome.
    private func openKey(_ password: String) async throws -> [UInt8] {
        try MasterPasswordUnlock.checkThrottle(directory: directory, now: clock())
        let file = try MasterPasswordUnlock.readKeyFile(directory: directory)
        await beforeKDF?()
        do {
            let key = try await MasterPasswordUnlock.deriveKey(file, password: password)
            MasterPasswordUnlock.recordSuccess(directory: directory, now: clock())
            await afterKDF?()   // test seam: runs once Argon2 has returned
            return key
        } catch MasterKeyError.wrongPassword {
            throw MasterPasswordUnlock.recordWrongPassword(directory: directory, now: clock())
        }
    }

    /// Runs `body` while no password attempt, key rotation or recovery is in flight, and keeps them out until it
    /// returns; throws `.busy` when one is running. `scheduled` (a scheduled backup): a prompt or rotation that comes
    /// meanwhile waits for it (up to `backupWaitSeconds`) instead of being refused.
    func exclusiveRun<T>(scheduled: Bool = false, _ body: () async throws -> T) async throws -> T {
        guard !attemptInFlight else { throw MacVaultError.busy }
        attemptInFlight = true
        scheduledRunInFlight = scheduled
        defer { attemptInFlight = false; scheduledRunInFlight = false }
        return try await body()
    }

    /// How long a password prompt or rotation waits for a scheduled backup to finish.
    var backupWaitSeconds: TimeInterval {
        get { _backupWaitSeconds }
        set {
            #if DEBUG
            _backupWaitSeconds = newValue   // tests only
            #endif
        }
    }
    private var _backupWaitSeconds: TimeInterval = 120
    private var scheduledRunInFlight = false

    /// Runs one password attempt at a time; a concurrent attempt throws `.busy` before any Argon2.
    private func exclusive<T>(_ body: () async throws -> T) async throws -> T {
        if attemptInFlight, scheduledRunInFlight {
            // A scheduled backup holds the vault: wait for it rather than refuse.
            let started = Date()
            while attemptInFlight, scheduledRunInFlight {
                guard Date().timeIntervalSince(started) < backupWaitSeconds else { throw MacVaultError.backupRunning }
                try await Task.sleep(nanoseconds: 20_000_000)
            }
        }
        guard !attemptInFlight else { throw MacVaultError.busy }
        attemptInFlight = true
        defer { attemptInFlight = false }
        return try await body()
    }

    /// Argon2 off the main actor.
    private nonisolated static func seal(_ key: [UInt8], password: String, params: MasterKeyFile.KDFParams,
                                         random: any RandomSource) async throws -> MasterKeyFile {
        try await Task.detached(priority: .userInitiated) {
            try MasterKeyFile.seal(localKey: key, password: password, params: params, random: random)
        }.value
    }

    private func recordSuccess() {
        MasterPasswordUnlock.recordSuccess(directory: directory, now: clock())
    }

    private func openStore(_ key: [UInt8]) throws -> LocalStore {
        let store = try MasterPasswordUnlock.openStore(directory: directory, key: key, keychain: keychain, random: random)
        setOpenedLocalKey(key)
        return store
    }

    /// The local key of the last successful create or unlock, for the Mac-local data file; handed over once.
    private var openedLocalKey: [UInt8]?

    /// True while a key is waiting to be taken (tests).
    var hasOpenedLocalKey: Bool { openedLocalKey != nil }

    func takeOpenedLocalKey() -> [UInt8]? {
        defer { openedLocalKey = nil }
        return openedLocalKey
    }

    /// Zeroes and drops a key that was never taken (lock during unlock, failure after open, lock).
    func discardOpenedLocalKey() {
        if openedLocalKey != nil { for i in openedLocalKey!.indices { openedLocalKey![i] = 0 } }
        openedLocalKey = nil
    }

    /// Hands a taken key back (a rotation's caller relocks, then reopens with the new key).
    func handBack(_ key: [UInt8]) { setOpenedLocalKey(key) }

    private func setOpenedLocalKey(_ key: [UInt8]) {
        discardOpenedLocalKey()
        openedLocalKey = key
    }

    private func writeKeyFile(_ file: MasterKeyFile) throws {
        let enc = JSONEncoder()
        enc.outputFormatting = .sortedKeys
        try enc.encode(file).write(to: keyFileURL, options: .atomic)
    }

    private static func checkNew(_ password: String) throws {
        if password.unicodeScalars.count < minPasswordLength { throw MacVaultError.passwordTooShort }
    }
}

private func wipe(_ b: inout [UInt8]) { for i in b.indices { b[i] = 0 } }
