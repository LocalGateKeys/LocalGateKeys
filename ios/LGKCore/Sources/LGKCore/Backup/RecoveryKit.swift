import Foundation

/// The Windows recovery kit (`recovery.write_recovery_kit`): a non-secret JSON file describing a full backup (its
/// name, size and SHA-256, the checksum manifest beside it, the backup's inventory) with the restore guide text.
/// It never holds a password, the recovery phrase or vault data.
public enum RecoveryKit {
    public static let format = "localgatekeys-recovery-kit"
    public static let version: Int64 = 1

    /// Windows `_default_restore_guide`.
    public static let defaultRestoreGuide = "Keep the encrypted backup and its checksum manifest on separate protected media. "
        + "Install the matching LocalGateKeys package offline, verify the SHA-256 checksum, "
        + "then use Verify recovery backup with both the independent backup password and the "
        + "vault master password from backup time. Restore as a new profile first. "
        + "Store both passwords separately from the backup media; losing the vault master "
        + "password from backup time makes the encrypted backup unrecoverable. "
        + "If the vault had a 24-word recovery phrase, that phrase can replace a forgotten master "
        + "password for the restored vault only when the phrase is still in its sealed, "
        + "separately stored record; the phrase is never written into a backup or this kit."

    public struct FileDescriptor: Equatable, Sendable {
        public let name: String
        public let size: Int
        public let sha256: String
        public let role: String
        public init(name: String, size: Int, sha256: String, role: String) {
            self.name = name; self.size = size; self.sha256 = sha256; self.role = role
        }
        var json: JSONValue {
            .object(["name": .string(name), "size": .int(Int64(size)), "sha256": .string(sha256), "role": .string(role)])
        }
    }

    /// The kit bytes. `inventory` nil writes the minimal inventory Windows does (unverified).
    public static func make(backup: FileDescriptor, manifest: FileDescriptor?, inventory: BackupInventory?,
                            appVersion: String, generatedAt: Int64, restoreGuide: String? = nil) throws -> Data {
        guard !appVersion.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, appVersion.count <= 80 else {
            throw RecoveryError("Application version is malformed")
        }
        if let restoreGuide, restoreGuide.count > 20_000 { throw RecoveryError("Recovery guide is malformed") }
        let kitInventory: JSONValue = inventory?.json ?? .object([
            "version": .int(FullBackupV2.version), "path": .string(backup.name), "backup_bytes": .int(Int64(backup.size)),
            "backup_sha256": .string(backup.sha256), "verified": .bool(false),
        ])
        var files = [backup.json]
        if let manifest { files.append(manifest.json) }
        let payload: JSONValue = .object([
            "format": .string(format), "version": .int(version), "generated_at": .int(generatedAt),
            "app_version": .string(appVersion), "restore_guide": .string(restoreGuide ?? defaultRestoreGuide),
            "inventory": kitInventory, "files": .array(files),
            "safety": .object([
                "contains_passwords": .bool(false), "contains_recovery_phrase": .bool(false),
                "contains_vault_data": .bool(false), "restore_mode": .string("new-profile-only-by-default"),
            ]),
        ])
        return Data(try CanonicalJSON.encode(payload, dialect: .utf8))
    }

    /// Writes the kit for the backup at `backup` to `to`, listing `<backup>.sha256.json` when it is there.
    public static func write(to destination: URL, backup: URL, inventory: BackupInventory?, appVersion: String,
                             now: Int64, restoreGuide: String? = nil) throws {
        let backupFile = FileDescriptor(name: backup.lastPathComponent, size: try ChecksumManifest.fileSize(backup),
                                        sha256: try ChecksumManifest.sha256(of: backup), role: "encrypted-full-backup-v2")
        let manifestURL = ChecksumManifest.url(for: backup)
        var manifest: FileDescriptor?
        if FileManager.default.fileExists(atPath: manifestURL.path) {
            manifest = FileDescriptor(name: manifestURL.lastPathComponent, size: try ChecksumManifest.fileSize(manifestURL),
                                      sha256: try ChecksumManifest.sha256(of: manifestURL), role: "sha256-manifest")
        }
        let data = try make(backup: backupFile, manifest: manifest, inventory: inventory, appVersion: appVersion,
                            generatedAt: now, restoreGuide: restoreGuide)
        do { try data.write(to: destination, options: .atomic) } catch { throw RecoveryError("Could not write the recovery kit") }
    }
}
