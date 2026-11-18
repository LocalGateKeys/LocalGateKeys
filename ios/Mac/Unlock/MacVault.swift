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

    // MARK: Duress password (sub-plan 08), the iPhone's `PhoneDuress` over files beside `master-key.json`

    /// The copies of the hold and session marker in the Safari group (`SafariSaveFiles.duressMirror`), set by the app;
    /// nil in tests, so a test never touches the real group.
    var duressMirror: DuressFiles?
    /// The second-vault session flag (the process-wide one; a test gives each vault its own).
    var duressSession: DuressSession = .shared
    #if DEBUG
    /// Test seams: the hold's wall clock and monotonic clock.
    var duressNow: (@Sendable () -> Int64)?
    var duressBootTime: (@Sendable () -> PhoneDuress.BootTime)?
    #endif

    /// `<vault>/.lgk-d` (the second vault), `<vault>/vault.hold.json` and `<vault>/duress.bin`.
    var duressFiles: DuressFiles { .under(directory) }

    /// The duress files of this vault; `params` seals the second vault's record (the real file's, so both cost the same).
    func makeDuress(params: MasterKeyFile.KDFParams = .default) -> PhoneDuress {
        #if DEBUG
        return PhoneDuress(files: duressFiles, mirror: duressMirror, random: random, params: params, session: duressSession,
                           now: duressNow ?? { Int64(Date().timeIntervalSince1970) },
                           bootTime: duressBootTime ?? { PhoneDuress.systemBootTime() })
        #else
        return PhoneDuress(files: duressFiles, mirror: duressMirror, random: random, params: params, session: duressSession)
        #endif
    }

    var duressConfigured: Bool { makeDuress().configured }

    /// True while a duress unlock holds this vault: its master password, Touch ID and recovery phrase are refused.
    var duressHeld: Bool {
        let duress = makeDuress()
        return duress.configured && duress.held()
    }

    /// True while the open store is the second vault (from the last unlock until the next lock).
    private(set) var openedSecond = false

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
        _ = makeDuress().eraseAll()   // a new vault never inherits an earlier one's duress files or hold
        openedSecond = false
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
            factors = []
            heldKeyFile = nil
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

    /// `factors`: the key file and YubiKey the unlock screen supplies (nothing is asked through `provideFactors` here).
    /// A missing or wrong factor throws `FactorError` before Argon2, and a YubiKey problem `YubiKeyError`: neither is
    /// counted by the throttle.
    ///
    /// Duress password (sub-plan 08, as the iPhone's `DuressUnlock.open`): without a second vault only the real
    /// derivation runs. With one, the real vault is tried first and then the second one on every try (a held or wrong
    /// real password still costs its derivation), so the time does not tell which opened. While held, a right real
    /// password is refused and counted as a wrong one (`openKeyWithFactors`). A duress password opens the second vault
    /// (its own folder, a Keychain in memory only), trips the hold and undoes the wrong try the real side counted.
    func unlock(password: String, factors given: FactorSecrets = FactorSecrets()) async throws -> LocalStore {
        try await exclusive {
            let holdAt = holdGeneration
            openedSecond = false   // a new unlock: whatever session was open has ended
            let duress = makeDuress()
            guard duress.configured else {
                var opened = try await openKeyWithFactors(password, factors: given)
                defer { opened.clear() }
                let store = try openReal(opened, given: given, holdAt: holdAt)
                endSecondSession(duress)
                return store
            }
            try MasterPasswordUnlock.checkThrottle(directory: directory, now: clock())
            var opened: OpenedKey?
            var realError: (any Error)?
            do { opened = try await openKeyWithFactors(password, factors: given) } catch { realError = error }
            defer { opened?.clear() }
            var second = await Task.detached(priority: .userInitiated, operation: { duress.tryOpen(password: password) }).value
            defer { if second != nil { wipe(&second!) } }
            if opened != nil {
                let store = try openReal(opened!, given: given, holdAt: holdAt)
                endSecondSession(duress)
                return store
            }
            guard let key = second else {
                // Neither: a missing key file or YubiKey of the real vault says so (never counted), else a wrong password.
                throw realError ?? MacVaultError.wrongPassword(retryAfter: retryAfter)
            }
            do { try duress.trip(decoyKey: key) } catch { throw realError ?? MacVaultError.wrongPassword(retryAfter: retryAfter) }
            recordSuccess()   // the real side counted a wrong try; this unlock is a right one
            let store: LocalStore
            do {
                try FileManager.default.createDirectory(at: duress.files.vault, withIntermediateDirectories: true)
                store = try LocalStore.open(directory: duress.files.vault,
                                            vault: MemoryKeyVault(localKey: key, base: InMemoryKeychainVault()),
                                            random: random, limitHints: nil)
            } catch {
                throw realError ?? MacVaultError.wrongPassword(retryAfter: retryAfter)
            }
            setOpenedLocalKey(key)
            heldKeyFile = nil
            openedSecond = true
            duress.openSession()
            return store
        }
    }

    /// Opens the real store with a checked key and keeps the key file the unlock used.
    private func openReal(_ opened: OpenedKey, given: FactorSecrets, holdAt: Int) throws -> LocalStore {
        do {
            let store = try openStore(opened.key)
            // Not held again if a lock came meanwhile (it forgot the held key file).
            if holdAt == holdGeneration {
                heldKeyFile = opened.factors.specs.contains(where: { $0.kind == .keyFile }) ? given.keyFile : nil
            }
            openedSecond = false
            return store
        } catch { discardOpenedLocalKey(); throw error }
    }

    /// A real unlock: no second-vault session any more, and a finished hold is removed.
    private func endSecondSession(_ duress: PhoneDuress) {
        duress.release()
        duress.closeSession()
        openedSecond = false
    }

    /// The lock: the second vault's session (if one was open) ends; the hold stays.
    func closeSecondSession() {
        if openedSecond || duressSession.isOpen { makeDuress().closeSession() }
        openedSecond = false
    }

    func unlockWithTouchID(reason: String) async throws -> LocalStore {
        guard exists else { throw MacVaultError.noVault }
        // While a duress unlock holds the vault, Touch ID is unavailable (as on the iPhone).
        guard biometric.isAvailable, !duressHeld else { throw MacVaultError.biometricUnavailable }
        return try await exclusive {
            openedSecond = false
            var key: [UInt8]
            do { key = try await biometric.load(reason: reason) }
            catch BiometricKeyError.cancelled { throw BiometricKeyError.cancelled }
            catch { throw MacVaultError.biometricUnavailable }   // item gone (enrolment changed) or unreadable
            defer { wipe(&key) }
            // Held meanwhile (a duress unlock elsewhere cannot run in parallel, but be strict).
            guard !duressHeld else { throw MacVaultError.biometricUnavailable }
            do {
                let store = try openStore(key)   // store errors are real errors, not a Touch ID problem
                recordSuccess()
                endSecondSession(makeDuress())
                return store
            } catch { discardOpenedLocalKey(); throw error }
        }
    }

    /// True when the Touch ID item was stored by this vault and not removed (create / setTouchID).
    private(set) var touchIDStored = false

    /// Seals the local key under `new` after rotating it (Windows `change_master_password` rotates the data key): an
    /// old `master-key.json` with the old password then opens nothing current. The recovery phrase keeps working;
    /// the Touch ID item is removed (it holds the old key) until the user turns it on again.
    /// The key file and YubiKey stay (the YubiKey answers a new challenge).
    @discardableResult
    func changePassword(old: String, new: String) async throws -> LocalStore {
        try Self.checkNew(new)
        return try await exclusive {
            var opened = try await openKeyWithFactors(old)
            defer { opened.clear() }
            try await checkNotDuress(realKey: opened.key, newPassword: new)
            var kept = try await renewedFactors(opened)
            defer { kept.clear() }
            return try await rotate(oldKey: opened.key, password: new, recovery: .keep, passwordChanged: true, factors: kept)
        }
    }

    /// A new master password may not be the duress password or one edit from it (`DuressError("near_duress")`).
    private func checkNotDuress(realKey: [UInt8], newPassword: String) async throws {
        let duress = makeDuress()
        guard duress.configured else { return }
        try await Task.detached(priority: .userInitiated) {
            try duress.checkNewPassword(realKey: realKey, newPassword: newPassword, decoySession: false)
        }.value
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
            var opened = try await openKeyWithFactors(password)
            defer { opened.clear() }
            var newKey = random.bytes(count: 32)
            defer { wipe(&newKey) }
            var kept = try await renewedFactors(opened)
            defer { kept.clear() }
            let sealed = try await Self.seal(newKey, password: password, params: kdfParams, random: random, factors: kept)
            let (file, phrase) = try MasterPasswordUnlock.enrolRecovery(sealed, localKey: newKey, random: random)
            return PreparedRecovery(phrase: phrase, file: file, basis: basis, oldKey: opened.key, newKey: newKey)
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
            var opened = try await openKeyWithFactors(password)
            defer { opened.clear() }
            var kept = try await renewedFactors(opened)
            defer { kept.clear() }
            return try await rotate(oldKey: opened.key, password: password, recovery: .remove, passwordChanged: false, factors: kept)
        }
    }

    /// Opens the local key with the recovery phrase and sets `newPassword` (12 to 4096 characters, as Windows),
    /// rotating the key (Windows `set_master_password_after_recovery`); the phrase stays valid; the Touch ID item is
    /// removed. Wrong phrases share the password throttle. The key file and YubiKey are dropped (the phrase stands in
    /// for them too): `lastRecoveryDroppedFactors` tells the caller to say "add them again".
    @discardableResult
    func recover(phrase: String, newPassword: String) async throws -> LocalStore {
        guard newPassword.unicodeScalars.count >= Self.recoveredPasswordMinimum else {
            throw MacVaultError.passwordTooShortFor(minimum: Self.recoveredPasswordMinimum)
        }
        guard newPassword.unicodeScalars.count <= 4096 else { throw MasterKeyError.tooLong }
        return try await exclusive {
            // While a duress unlock holds the vault a right phrase is refused as a wrong one (and counted like one).
            openedSecond = false
            var opened = try MasterPasswordUnlock.openWithRecovery(directory: directory, phrase: phrase, now: clock,
                                                                   held: duressHeld)
            defer { wipe(&opened.key) }
            try await checkNotDuress(realKey: opened.key, newPassword: newPassword)
            await beforeKDF?()
            let hadFactors = !opened.file.factorKinds.isEmpty
            let store = try await rotate(oldKey: opened.key, password: newPassword, recovery: .keep, passwordChanged: true,
                                         factors: FactorSet())
            lastRecoveryDroppedFactors = hadFactors
            heldKeyFile = nil
            endSecondSession(makeDuress())
            return store
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

    /// A new local key sealed under `password` and `factors` (none: the format without factors), the phrase kept
    /// (re-wrapped) or removed, then `commitRotation`.
    private func rotate(oldKey: [UInt8], password: String, recovery: RecoveryChange, passwordChanged: Bool,
                        factors next: FactorSet) async throws -> LocalStore {
        let old = try MasterPasswordUnlock.readKeyFile(directory: directory)
        var newKey = random.bytes(count: 32)
        defer { wipe(&newKey) }
        var file = try await Self.seal(newKey, password: password, params: kdfParams, random: random, factors: next)
        if case .keep = recovery, let wrapper = old.recovery {
            do { file.recovery = try RecoveryWrapper.reseal(wrapper, oldLocalKey: oldKey, newLocalKey: newKey, random: random) }
            catch { throw Self.damagedRecovery }
        }
        #if DEBUG
        damageSeal?(&file)
        #endif
        try await checkSealed(file, password: password, secrets: next.secrets, key: newKey)
        // Scheduled backups' vault.json key follows the new master password (Argon2 here, before the vault lock).
        var schedule = ScheduleUpdate(newPassword: passwordChanged ? password : nil)
        if passwordChanged, let old = (try? ScheduleSecretStore(directory: directory, localKey: oldKey).load()) ?? nil {
            // The backup password may not be the master password. A public key record (format v2) holds no password:
            // the new master password is checked against it by deriving its public key (Argon2, before the vault lock).
            var sameAsMaster = false
            if let record = old.backupKey {
                sameAsMaster = await Task.detached(priority: .userInitiated) { record.passwordMatches(password) }.value
                if sameAsMaster { schedule.sameAsMasterKeyID = record.keyID }
            } else if let legacy = old.legacyPassword {
                sameAsMaster = legacy.utf8.elementsEqual(password.utf8)
            }
            if !sameAsMaster {
                let kdf = old.passwordKey.kdf
                let rnd = random
                schedule.passwordKey = try await Task.detached(priority: .userInitiated) {
                    try DesktopVaultFile.derivePasswordKey(password: password, kdf: kdf, random: rnd)
                }.value
            }
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
        /// The record whose backup password is the new master password (checked beforehand): the secret is dropped.
        var sameAsMasterKeyID: String?
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
                    let sameAsMaster: Bool
                    if let record = s.backupKey {
                        sameAsMaster = update.sameAsMasterKeyID == record.keyID
                    } else if let pw = update.newPassword, let legacy = s.legacyPassword {
                        sameAsMaster = legacy.utf8.elementsEqual(pw.utf8)
                    } else {
                        sameAsMaster = false
                    }
                    if sameAsMaster {
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
                // The real vault's duress record (`duress.bin`: hours and the one-edit fingerprint) follows the new key.
                if let sealed = makeDuress().resealedReal(oldKey: oldKey, newKey: newKey) {
                    try KeyRotation.writeSynced(sealed, to: staging.appendingPathComponent(duressFiles.real.lastPathComponent))
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
        factors = file.factors ?? []
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

    /// Where the remembered key file's bookmark lives (the app-only Keychain group, `VaultSlot.unlockKeyFile`).
    var factorKeychain: any KeychainVault { keychain }

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

    // MARK: - Key file and YubiKey factors

    /// The key-file / YubiKey factors of `master-key.json` (none in a version-1 file); cached, refreshed whenever this
    /// vault reads or changes the file.
    private(set) lazy var factors: [FactorSpec] = (try? MasterPasswordUnlock.readKeyFile(directory: directory))?.factors ?? []

    /// Supplies the factors for a password check that was given none (Settings, a strict login, a backup, the recovery
    /// phrase sheet): the key file remembered or picked now and the YubiKey responder; only the specs still needed are
    /// passed. Set by the lock model; nil in tests (the check then throws `FactorError.required`).
    var provideFactors: (@MainActor (_ specs: [FactorSpec]) async throws -> FactorSecrets)?

    /// The key file's bytes from this session's password unlock, so later password checks need no file dialog (Windows
    /// keeps the factors in its session); dropped at every lock.
    private var heldKeyFile: Data?
    var holdsKeyFile: Bool { heldKeyFile != nil }
    /// Bumped by every `forgetHeldFactors` (a lock): an unlock or add that finishes later holds nothing.
    private var holdGeneration = 0
    func forgetHeldFactors() { heldKeyFile = nil; holdGeneration += 1 }
    /// A rotation relocks the window: the held key file survives it (`MacLockModel.reopenAfterRotation`).
    func takeHeldKeyFile() -> Data? { defer { heldKeyFile = nil }; return heldKeyFile }
    func holdKeyFile(_ data: Data?) { heldKeyFile = data }

    /// True after `recover` dropped a key file or YubiKey (the caller says "add them again").
    private(set) var lastRecoveryDroppedFactors = false

    /// Specs and their 32-byte secrets in list order (key file first); `clear()` zeroes the secrets.
    struct FactorSet {
        var specs: [FactorSpec] = []
        var secrets: [[UInt8]] = []
        mutating func clear() { for i in secrets.indices { wipe(&secrets[i]) } }
    }

    /// A password check that kept its factors: the local key, the file it opened, the factors and what supplied them
    /// (its YubiKey responder answers a renewed challenge). `clear()` zeroes the key and the secrets.
    struct OpenedKey {
        var key: [UInt8]
        let file: MasterKeyFile
        var factors: FactorSet
        let input: FactorSecrets
        mutating func clear() { wipe(&key); factors.clear() }
    }

    private func factorInput(for specs: [FactorSpec], given: FactorSecrets?) async throws -> FactorSecrets {
        if let given { return given }
        var input = FactorSecrets(keyFile: heldKeyFile)
        let needsKeyFile = specs.contains { $0.kind == .keyFile } && input.keyFile == nil
        let needsYubiKey = specs.contains { $0.kind == .yubiKeyHMAC }
        guard needsKeyFile || needsYubiKey, let provideFactors else { return input }
        let provided = try await provideFactors(specs.filter { $0.kind != .keyFile || needsKeyFile })
        if needsKeyFile { input.keyFile = provided.keyFile }
        input.yubiKey = provided.yubiKey
        return input
    }

    /// The factors for a rewritten password wrapper (Android `renewed`): a kept key file as it is, a kept YubiKey with
    /// a new challenge (one more touch, COMPOSITE_KEY_V1 §1.2), minus `dropping`, plus `added` (just enrolled), key
    /// file first. The caller clears the result.
    private func renewedFactors(_ opened: OpenedKey, dropping: FactorKind? = nil, added: FactorSet = FactorSet()) async throws -> FactorSet {
        var out = FactorSet()
        do {
            for (spec, secret) in zip(opened.factors.specs, opened.factors.secrets)
            where spec.kind != dropping && !added.specs.contains(where: { $0.kind == spec.kind }) {
                if spec.kind == .yubiKeyHMAC {
                    guard let respond = opened.input.yubiKey, let slot = spec.slot else { throw FactorError.required([.yubiKeyHMAC]) }
                    let rnd = random
                    let fresh = try await Task.detached(priority: .userInitiated) {
                        try await CompositeKey.enrolYubiKey(slot: slot, random: rnd, respond: respond)
                    }.value
                    out.specs.append(fresh.spec); out.secrets.append(fresh.secret)
                } else {
                    out.specs.append(spec); out.secrets.append(secret)
                }
            }
            out.specs += added.specs; out.secrets += added.secrets
            let rank: (FactorSpec) -> Int = { $0.kind == .keyFile ? 0 : 1 }
            let order = out.specs.indices.sorted { rank(out.specs[$0]) < rank(out.specs[$1]) }
            out = FactorSet(specs: order.map { out.specs[$0] }, secrets: order.map { out.secrets[$0] })
        } catch {
            out.clear()
            throw error
        }
        return out
    }

    /// Adds a key file (the bytes of the chosen file) to the password wrapper (Android `changeFactors`). The master
    /// password and today's factors must open the file first. The local key is not rotated: the recovery phrase, the
    /// Touch ID item and copies of the vault made before keep opening it (the add confirmation says so). A YubiKey that
    /// stays answers a new challenge. A file that is not a usable key file throws `KeyFileError`.
    func addKeyFile(password: String, keyFile data: Data) async throws {
        guard !factors.contains(where: { $0.kind == .keyFile }) else { throw MacFactors.alreadySet }
        let holdAt = holdGeneration
        try await changeFactors(password: password, dropping: nil) { current in
            guard !current.contains(where: { $0.kind == .keyFile }) else { throw MacFactors.alreadySet }
            let enrolled = try await Task.detached(priority: .userInitiated) { try CompositeKey.enrolKeyFile(data) }.value
            return FactorSet(specs: [enrolled.spec], secrets: [enrolled.secret])
        }
        if holdAt == holdGeneration { heldKeyFile = data }
    }

    /// Adds the YubiKey answering `respond` from `slot` (a new challenge; the caller's responder asks twice and
    /// compares, Windows `_TwoTouches`). Otherwise as `addKeyFile`.
    func addYubiKey(password: String, slot: Int, respond: @escaping @Sendable (Data) async throws -> Data) async throws {
        guard !factors.contains(where: { $0.kind == .yubiKeyHMAC }) else { throw MacFactors.alreadySet }
        let rnd = random
        try await changeFactors(password: password, dropping: nil) { current in
            guard !current.contains(where: { $0.kind == .yubiKeyHMAC }) else { throw MacFactors.alreadySet }
            let enrolled = try await Task.detached(priority: .userInitiated) {
                try await CompositeKey.enrolYubiKey(slot: slot, random: rnd, respond: respond)
            }.value
            return FactorSet(specs: [enrolled.spec], secrets: [enrolled.secret])
        }
    }

    /// Removes the key file or the YubiKey; with none left the file is version 1 again.
    func removeFactor(_ kind: FactorKind, password: String) async throws {
        guard factors.contains(where: { $0.kind == kind }) else { throw MacFactors.notSet }
        try await changeFactors(password: password, dropping: kind) { current in
            guard current.contains(where: { $0.kind == kind }) else { throw MacFactors.notSet }
            return FactorSet()
        }
        if kind == .keyFile { heldKeyFile = nil }
    }

    /// Checks the password with today's factors, then rewrites only the password wrapper (same local key, same password,
    /// the recovery wrapper carried over) with today's factors minus `dropping` plus what `adding` enrols.
    private func changeFactors(password: String, dropping: FactorKind?,
                               adding: ([FactorSpec]) async throws -> FactorSet) async throws {
        try await exclusive {
            var opened = try await openKeyWithFactors(password)
            defer { opened.clear() }
            var added = try await adding(opened.factors.specs)
            defer { added.clear() }
            var next = try await renewedFactors(opened, dropping: dropping, added: added)
            defer { next.clear() }
            var file = try await Self.seal(opened.key, password: password, params: kdfParams, random: random, factors: next)
            file.recovery = opened.file.recovery
            #if DEBUG
            damageSeal?(&file)
            #endif
            try await checkSealed(file, password: password, secrets: next.secrets, key: opened.key)
            try writeKeyFile(file)
            factors = next.specs
        }
    }

    #if DEBUG
    /// Test seam: changes a freshly sealed key file before it is checked (a broken seal must never be written).
    var damageSeal: ((inout MasterKeyFile) -> Void)?
    #endif

    static let sealCheckFailed = LocalStoreError.corrupt("sealed key file")

    /// Opens a freshly sealed `master-key.json` again (Argon2, with the password and secrets still in memory) and
    /// checks that it gives `key`, before anything is written: a seal that went wrong would lock the vault for good.
    private func checkSealed(_ file: MasterKeyFile, password: String, secrets: [[UInt8]], key: [UInt8]) async throws {
        var reopened: [UInt8]
        do { reopened = try await Self.open(file, password: password, secrets: secrets) } catch { throw Self.sealCheckFailed }
        defer { wipe(&reopened) }
        var diff: UInt8 = reopened.count == key.count ? 0 : 1
        for (a, b) in zip(reopened, key) { diff |= a ^ b }
        guard diff == 0 else { throw Self.sealCheckFailed }
    }

    /// Deletes the Touch ID item without a password ("Always ask for the key file / YubiKey": less access, never more).
    func removeTouchIDItem() {
        try? biometric.remove()
        touchIDStored = false
    }

    // MARK: - Duress password (sub-plan 08)

    /// Sets up the duress password for the real vault: the master password is checked (throttled), then a second vault
    /// with sample items (`DuressSamples`, the plan carried over from `real`) is created beside this one, its record
    /// sealed with this vault's Argon2 parameters. A duress password equal to the master password or one edit from it
    /// throws `DuressError("same"/"close")`; one already set up `DuressError("exists")`.
    func setUpDuress(masterPassword: String, duressPassword: String, hours: Int, real: StoreSnapshot) async throws {
        try Self.checkNew(duressPassword)
        try await exclusive {
            var key = try await openKey(masterPassword)
            defer { wipe(&key) }
            let params = try MasterPasswordUnlock.readKeyFile(directory: directory).kdf
            let duress = makeDuress(params: params)
            let realKey = key, rnd = random, now = Int64(clock().timeIntervalSince1970)
            try await Task.detached(priority: .userInitiated) {
                try duress.setup(realKey: realKey, appPassword: masterPassword, duressPassword: duressPassword,
                                 hours: hours, decoySession: false) { store in
                    try DuressSamples.seed(store, real: real, random: rnd, now: now)
                }
            }.value
        }
    }

    /// "Set up" inside the second vault's session: every check runs against the open (second) vault's password, then it
    /// fails with `DuressError("generic")` and nothing is written (desktop review R2: no oracle against the real vault).
    func setUpDuressInSecondSession(masterPassword: String, duressPassword: String, hours: Int) async throws {
        try Self.checkNew(duressPassword)
        try await exclusive {
            var key = try await openSecondKey(masterPassword)
            wipe(&key)
            try makeDuress().setup(realKey: [], appPassword: masterPassword, duressPassword: duressPassword,
                                   hours: hours, decoySession: true) { _ in }
        }
    }

    /// Removes the second vault, its hold and `duress.bin`; inside the second session `DuressError("generic")`.
    @discardableResult
    func removeDuress() throws -> Bool {
        try makeDuress().remove(decoySession: openedSecond)
    }

    /// The real vault's duress hours (Settings), read with the real local key; nil when not set up.
    func duressHours(realKey: [UInt8]) -> Int? { makeDuress().realHours(realKey: realKey) }

    /// The second vault's password checked against its record (the session's "master password"), under the shared
    /// throttle: one Argon2 run, as a real check.
    func verifySecondPassword(_ password: String) async throws {
        try await exclusive {
            var key = try await openSecondKey(password)
            wipe(&key)
        }
    }

    /// "Change master password" inside the second session: only the second vault's record is sealed again (same key,
    /// this vault's Argon2 parameters). Nothing is tried against the real vault.
    func changeSecondPassword(current: String, new: String) async throws {
        try Self.checkNew(new)
        try await exclusive {
            var key = try await openSecondKey(current)
            defer { wipe(&key) }
            let params = (try? MasterPasswordUnlock.readKeyFile(directory: directory))?.kdf ?? kdfParams
            let duress = makeDuress(params: params)
            let k = key
            try await Task.detached(priority: .userInitiated) { try duress.resealSecond(key: k, password: new) }.value
        }
    }

    /// The second vault's key for `password` (the caller wipes it), under the shared throttle; a wrong one is counted.
    private func openSecondKey(_ password: String) async throws -> [UInt8] {
        try MasterPasswordUnlock.checkThrottle(directory: directory, now: clock())
        let duress = makeDuress()
        await beforeKDF?()
        let key = await Task.detached(priority: .userInitiated, operation: { duress.tryOpen(password: password) }).value
        guard let key else { throw MasterPasswordUnlock.recordWrongPassword(directory: directory, now: clock()) }
        recordSuccess()
        return key
    }

    // MARK: - Private

    /// Checks the throttle before running Argon2, then opens the key file and records the outcome.
    private func openKey(_ password: String) async throws -> [UInt8] {
        var opened = try await openKeyWithFactors(password)
        let key = opened.key
        opened.clear()
        return key
    }

    /// `openKey` keeping the factors: the throttle first, then everything in the file that can be checked without a
    /// factor, then the factors (`given`, else the held key file and `provideFactors`; a missing or wrong one throws
    /// `FactorError` and a YubiKey problem `YubiKeyError`, never counted), then Argon2.
    private func openKeyWithFactors(_ password: String, factors given: FactorSecrets? = nil) async throws -> OpenedKey {
        try MasterPasswordUnlock.checkThrottle(directory: directory, now: clock())
        let file = try MasterPasswordUnlock.readKeyFile(directory: directory)
        let specs = try file.factorsForUnlock(password: password)   // a malformed file never asks for a factor
        factors = specs
        var input = FactorSecrets()
        var secrets: [[UInt8]] = []
        if !specs.isEmpty {
            input = try await factorInput(for: specs, given: given)
            secrets = try await Self.secrets(for: specs, from: input)
        }
        // Duress password (sub-plan 08): while held, or while the second vault is open, a right master password is
        // refused after the same Argon2 and counted as a wrong one, on every path that opens the real key.
        let held = openedSecond || duressHeld
        await beforeKDF?()
        do {
            var key = try await Self.open(file, password: password, secrets: secrets)
            if held {
                wipe(&key)
                throw MasterKeyError.wrongPassword
            }
            MasterPasswordUnlock.recordSuccess(directory: directory, now: clock())
            await afterKDF?()   // test seam: runs once Argon2 has returned
            return OpenedKey(key: key, file: file, factors: FactorSet(specs: specs, secrets: secrets), input: input)
        } catch MasterKeyError.wrongPassword {
            for i in secrets.indices { wipe(&secrets[i]) }
            throw MasterPasswordUnlock.recordWrongPassword(directory: directory, now: clock())
        } catch {
            for i in secrets.indices { wipe(&secrets[i]) }
            throw error
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

    /// Argon2 off the main actor; with `factors`, a version-2 file (none: version 1, as before).
    private nonisolated static func seal(_ key: [UInt8], password: String, params: MasterKeyFile.KDFParams,
                                         random: any RandomSource, factors: FactorSet = FactorSet()) async throws -> MasterKeyFile {
        let specs = factors.specs, secrets = factors.secrets
        return try await Task.detached(priority: .userInitiated) {
            try MasterKeyFile.seal(localKey: key, password: password, params: params, random: random, factors: specs, secrets: secrets)
        }.value
    }

    /// The factor secrets (key-file parsing and the YubiKey exchange) off the main actor.
    private nonisolated static func secrets(for specs: [FactorSpec], from input: FactorSecrets) async throws -> [[UInt8]] {
        try await Task.detached(priority: .userInitiated) { try await CompositeKey.secrets(for: specs, from: input) }.value
    }

    /// Argon2 and the unwrap off the main actor; the secrets were checked already.
    private nonisolated static func open(_ file: MasterKeyFile, password: String, secrets: [[UInt8]]) async throws -> [UInt8] {
        try await Task.detached(priority: .userInitiated) { try file.open(password: password, secrets: secrets) }.value
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
