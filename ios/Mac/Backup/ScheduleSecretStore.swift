import Foundation
import LGKCore
import AppSharedMac

/// What a scheduled run needs: the **public** backup key record (design `docs/design/backup-public-key-2026-10-31.md`
/// 3.3; the backup password itself is not stored), the Argon2id key of the master password the backup's `vault.json`
/// is sealed with (so no master password is needed at run time) and, with a recovery phrase enrolled, the phrase's
/// vault key (also the *current* phrase for the reset authority, owner decision Q2). Kept only in
/// `scheduled-backup.bin`, sealed under the local key (`ScheduleSecretStore`). Never logged.
///
/// Format v2 (`{"v":2,"backup_key":<record>,"password_key":..,"recovery":..}`) is the only one written for a record.
/// Format v1 (`backup_password` instead of the record) is read for the migration at the first unlock after the update
/// (`BackupScheduleModel.migrateIfNeeded`), which replaces it in one atomic save; a key rotation that meets a v1 file
/// before that re-seals it as it is. A password is never kept next to a record.
struct ScheduledBackupSecret: Sendable {
    /// The public backup key record (format v2).
    var backupKey: BackupKeyRecord?
    /// Format v1 only: the backup password of an install from before public-key backups, until the migration.
    var legacyPassword: String?
    var passwordKey: DesktopVaultFile.PasswordKey
    var recovery: RecoveryWrapper.VaultKey?

    /// The v1 password (nil once migrated).
    var backupPassword: String? { legacyPassword }

    mutating func wipe() { passwordKey.wipe(); recovery?.wipe(); legacyPassword = nil }

    func encoded() throws -> [UInt8] {
        var o: [String: JSONValue] = ["password_key": .string(Base64.encode(try passwordKey.encoded()))]
        if let backupKey {
            o["v"] = .int(2)
            o["backup_key"] = backupKey.json
        } else if let legacyPassword {
            o["v"] = .int(1)
            o["backup_password"] = .string(legacyPassword)
        } else {
            throw ScheduleSecretStore.Failure.format
        }
        if let recovery {
            o["recovery"] = .object(["salt": .string(Base64.encode(recovery.salt)), "key": .string(Base64.encode(recovery.key))])
        }
        return try CanonicalJSON.encode(.object(o), dialect: .utf8)
    }

    init(backupKey: BackupKeyRecord, passwordKey: DesktopVaultFile.PasswordKey, recovery: RecoveryWrapper.VaultKey?) {
        self.backupKey = backupKey; self.legacyPassword = nil; self.passwordKey = passwordKey; self.recovery = recovery
    }

    /// Format v1 (tests, and a file not yet migrated).
    init(backupPassword: String, passwordKey: DesktopVaultFile.PasswordKey, recovery: RecoveryWrapper.VaultKey?) {
        self.backupKey = nil; self.legacyPassword = backupPassword; self.passwordKey = passwordKey; self.recovery = recovery
    }

    /// Throws `Failure.format` when the plaintext is not a secret this app wrote, `Failure.damagedRecord` when a v2
    /// record fails section 3.3 validation (scheduled backups skip; the page offers a new password).
    init(encoded: [UInt8]) throws {
        guard case .object(let o)? = try? CanonicalJSON.parse(encoded),
              case .string(let k)? = o["password_key"], let kb = try? Base64.decodeStrict(k),
              let key = try? DesktopVaultFile.PasswordKey(encoded: kb) else { throw ScheduleSecretStore.Failure.format }
        var recovery: RecoveryWrapper.VaultKey?
        if case .object(let r)? = o["recovery"] {
            guard case .string(let s)? = r["salt"], case .string(let rk)? = r["key"],
                  let salt = try? Base64.decodeStrict(s), let rkey = try? Base64.decodeStrict(rk),
                  salt.count == 16, rkey.count == 32 else { throw ScheduleSecretStore.Failure.format }
            recovery = RecoveryWrapper.VaultKey(salt: salt, key: rkey)
        }
        switch o["v"] {
        case .int(2)?:
            guard o["backup_password"] == nil, let raw = o["backup_key"] else { throw ScheduleSecretStore.Failure.format }
            let record: BackupKeyRecord
            do { record = try BackupKeyRecord(validating: raw) } catch {
                throw ScheduleSecretStore.Failure.damagedRecord((error as? BackupKeyError)?.message ?? "")
            }
            self.init(backupKey: record, passwordKey: key, recovery: recovery)
        case .int(1)?:
            guard case .string(let pw)? = o["backup_password"], pw.count >= BackupSchedule.minBackupPasswordLength else {
                throw ScheduleSecretStore.Failure.format
            }
            self.init(backupPassword: pw, passwordKey: key, recovery: recovery)
        default:
            throw ScheduleSecretStore.Failure.format
        }
    }
}

/// `scheduled-backup.bin` in the vault folder: the schedule's secret sealed (AES-256-GCM) under a key derived from the
/// local key, like `desktop-profile.bin`. So it opens only while the vault is unlocked, and nothing in the Keychain
/// opens a scheduled backup on its own (fix round 1 ruling). A key rotation re-seals it with the other files
/// (`MacVault.commitRotation`, same journal); after a master password change or recovery its password key is derived
/// again from the new password, and a new recovery phrase replaces the phrase key.
///
/// Since format v2 the backup password is not stored at all: the file holds only the public backup key record, which
/// encrypts new backups but opens none (design section 1). The Keychain holds nothing that opens a backup either.
final class ScheduleSecretStore: @unchecked Sendable {
    nonisolated static let fileName = "scheduled-backup.bin"
    nonisolated static let info = Array("localgatekeys|mac-scheduled-backup|v1".utf8)
    nonisolated static let aad = Array("localgatekeys|mac-scheduled-backup|v1".utf8)
    nonisolated static let formatVersion: UInt8 = 1

    enum Failure: Error, Equatable { case format, io, damagedRecord(String) }

    let directory: URL
    private let keyBox: DesktopProfileStore.KeyBox
    private let random: any RandomSource

    init(directory: URL, localKey: [UInt8], random: any RandomSource = SystemRandomSource()) {
        self.directory = directory
        self.keyBox = DesktopProfileStore.KeyBox(CryptoBox.hkdf(ikm: localKey, salt: [], info: Self.info, length: 32))
        self.random = random
    }

    var fileURL: URL { directory.appendingPathComponent(Self.fileName) }

    func seal(_ secret: ScheduledBackupSecret) throws -> Data {
        var plain = try secret.encoded()
        defer { for i in plain.indices { plain[i] = 0 } }
        let nonce = random.bytes(count: 12)
        return Data([Self.formatVersion] + nonce + (try CryptoBox.sealGCM(key: keyBox.bytes, nonce: nonce, plaintext: plain, aad: Self.aad)))
    }

    /// The sealed file as it is now (nil: no file); `Failure.io` when it is there but can't be read. Every save
    /// seals with a fresh nonce, so the same bytes from the same store instance mean nothing was saved, rotated or
    /// removed in between (the generation check of `BackupScheduleModel`'s key operations).
    func sealedBytes() throws -> Data? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
        do { return try Data(contentsOf: fileURL) } catch { throw Failure.io }
    }

    /// The secret, or nil when none is set; throws when the file is there but does not open under this key
    /// (`Failure.io`: not readable now; `format` or a GCM error: it does not open; `damagedRecord`: it fails 3.3).
    func load() throws -> ScheduledBackupSecret? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
        guard let bytes = try? Array(Data(contentsOf: fileURL)) else { throw Failure.io }
        guard bytes.count > 1 + 12 + 16, bytes[0] == Self.formatVersion else { throw Failure.format }
        var plain = try CryptoBox.openGCM(key: keyBox.bytes, nonce: Array(bytes[1..<13]), ciphertext: Array(bytes[13...]), aad: Self.aad)
        defer { for i in plain.indices { plain[i] = 0 } }
        return try ScheduledBackupSecret(encoded: plain)
    }

    func save(_ secret: ScheduledBackupSecret) throws {
        let data = try seal(secret)
        try data.write(to: fileURL, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }

    func delete() throws {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return }
        try FileManager.default.removeItem(at: fileURL)
    }
}
