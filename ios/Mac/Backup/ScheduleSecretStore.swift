import Foundation
import LGKCore
import AppSharedMac

/// What a scheduled run needs: the backup password, the Argon2id key of the master password the backup's `vault.json`
/// is sealed with (so no master password is needed at run time) and, with a recovery phrase enrolled, the phrase's
/// vault key. Kept only in `scheduled-backup.bin`, sealed under the local key (`ScheduleSecretStore`). Never logged.
struct ScheduledBackupSecret: Sendable {
    var backupPassword: String
    var passwordKey: DesktopVaultFile.PasswordKey
    var recovery: RecoveryWrapper.VaultKey?

    mutating func wipe() { passwordKey.wipe(); recovery?.wipe(); backupPassword = "" }

    func encoded() throws -> [UInt8] {
        var o: [String: JSONValue] = [
            "v": .int(1), "backup_password": .string(backupPassword),
            "password_key": .string(Base64.encode(try passwordKey.encoded())),
        ]
        if let recovery {
            o["recovery"] = .object(["salt": .string(Base64.encode(recovery.salt)), "key": .string(Base64.encode(recovery.key))])
        }
        return try CanonicalJSON.encode(.object(o), dialect: .utf8)
    }

    init(backupPassword: String, passwordKey: DesktopVaultFile.PasswordKey, recovery: RecoveryWrapper.VaultKey?) {
        self.backupPassword = backupPassword; self.passwordKey = passwordKey; self.recovery = recovery
    }

    init?(encoded: [UInt8]) {
        guard case .object(let o)? = try? CanonicalJSON.parse(encoded), o["v"] == .int(1),
              case .string(let pw)? = o["backup_password"], pw.count >= BackupSchedule.minBackupPasswordLength,
              case .string(let k)? = o["password_key"], let kb = try? Base64.decodeStrict(k),
              let key = try? DesktopVaultFile.PasswordKey(encoded: kb) else { return nil }
        var recovery: RecoveryWrapper.VaultKey?
        if case .object(let r)? = o["recovery"] {
            guard case .string(let s)? = r["salt"], case .string(let rk)? = r["key"],
                  let salt = try? Base64.decodeStrict(s), let rkey = try? Base64.decodeStrict(rk),
                  salt.count == 16, rkey.count == 32 else { return nil }
            recovery = RecoveryWrapper.VaultKey(salt: salt, key: rkey)
        }
        self.init(backupPassword: pw, passwordKey: key, recovery: recovery)
    }
}

/// `scheduled-backup.bin` in the vault folder: the schedule's secret sealed (AES-256-GCM) under a key derived from the
/// local key, like `desktop-profile.bin`. So it opens only while the vault is unlocked, and nothing in the Keychain
/// opens a scheduled backup on its own (fix round 1 ruling). A key rotation re-seals it with the other files
/// (`MacVault.commitRotation`, same journal); after a master password change or recovery its password key is derived
/// again from the new password, and a new recovery phrase replaces the phrase key.
///
/// The backup password is sealed here too, not kept in the Keychain: only the unlocked app ever reads it (scheduled runs
/// need the vault open anyway), so a Keychain item would add a copy readable without the local key and nothing else.
final class ScheduleSecretStore: @unchecked Sendable {
    nonisolated static let fileName = "scheduled-backup.bin"
    nonisolated static let info = Array("localgatekeys|mac-scheduled-backup|v1".utf8)
    nonisolated static let aad = Array("localgatekeys|mac-scheduled-backup|v1".utf8)
    nonisolated static let formatVersion: UInt8 = 1

    enum Failure: Error, Equatable { case format, io }

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

    /// The secret, or nil when none is set; throws when the file is there but does not open under this key.
    func load() throws -> ScheduledBackupSecret? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
        guard let bytes = try? Array(Data(contentsOf: fileURL)) else { throw Failure.io }
        guard bytes.count > 1 + 12 + 16, bytes[0] == Self.formatVersion else { throw Failure.format }
        var plain = try CryptoBox.openGCM(key: keyBox.bytes, nonce: Array(bytes[1..<13]), ciphertext: Array(bytes[13...]), aad: Self.aad)
        defer { for i in plain.indices { plain[i] = 0 } }
        guard let secret = ScheduledBackupSecret(encoded: plain) else { throw Failure.format }
        return secret
    }

    func save(_ secret: ScheduledBackupSecret) throws {
        let data = try seal(secret)
        try data.write(to: fileURL, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }

    func delete() { try? FileManager.default.removeItem(at: fileURL) }
}
