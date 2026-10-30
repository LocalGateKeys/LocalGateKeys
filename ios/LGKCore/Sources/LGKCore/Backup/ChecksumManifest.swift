import Crypto
import Foundation

/// A refused or failed recovery step, with the message Windows (`recovery.py` `RecoveryError`) gives. Never carries
/// a password, a key or vault contents.
public struct RecoveryError: Error, Equatable, Sendable, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
    /// `_independent_passwords`.
    public static let samePassword = RecoveryError("Use an independent backup password, not the vault master password")
}

/// Windows `recovery.BackupInventory`: safe metadata about a full backup for the Recovery centre, the checksum
/// manifest and the recovery kit. Never holds a password, the recovery phrase or vault contents.
public struct BackupInventory: Equatable, Sendable {
    public var version: Int64
    public var path: String
    public var profileName: String?
    /// Members of the backup (vault, settings, generation and one per attachment).
    public var entries: Int
    public var attachmentCount: Int
    public var attachmentBytes: Int
    public var backupBytes: Int
    /// Lowercase hex.
    public var backupSHA256: String
    public var createdAt: Int64
    public var verified: Bool
    public var verifiedAt: Int64?
    public var sameDisk: Bool
    public var warnings: [String]
    public var manifestPath: String?
    /// Whether the backed-up vault had a recovery phrase enrolled (the phrase itself is never in a backup).
    public var recoveryPhraseEnrolled: Bool?

    public init(version: Int64 = FullBackupV2.version, path: String, profileName: String?, entries: Int,
                attachmentCount: Int, attachmentBytes: Int, backupBytes: Int, backupSHA256: String, createdAt: Int64,
                verified: Bool = false, verifiedAt: Int64? = nil, sameDisk: Bool = false, warnings: [String] = [],
                manifestPath: String? = nil, recoveryPhraseEnrolled: Bool? = nil) {
        self.version = version; self.path = path; self.profileName = profileName; self.entries = entries
        self.attachmentCount = attachmentCount; self.attachmentBytes = attachmentBytes; self.backupBytes = backupBytes
        self.backupSHA256 = backupSHA256; self.createdAt = createdAt; self.verified = verified; self.verifiedAt = verifiedAt
        self.sameDisk = sameDisk; self.warnings = warnings; self.manifestPath = manifestPath
        self.recoveryPhraseEnrolled = recoveryPhraseEnrolled
    }

    /// `BackupInventory.as_dict()` (every field, absent values as null).
    public var json: JSONValue {
        func opt<T>(_ v: T?, _ f: (T) -> JSONValue) -> JSONValue { v.map(f) ?? .null }
        return .object([
            "version": .int(version), "path": .string(path), "profile_name": opt(profileName) { .string($0) },
            "entries": .int(Int64(entries)), "attachment_count": .int(Int64(attachmentCount)),
            "attachment_bytes": .int(Int64(attachmentBytes)), "backup_bytes": .int(Int64(backupBytes)),
            "backup_sha256": .string(backupSHA256.lowercased()), "created_at": .int(createdAt), "verified": .bool(verified),
            "verified_at": opt(verifiedAt) { .int($0) }, "same_disk": .bool(sameDisk),
            "warnings": .array(warnings.map { .string($0) }), "manifest_path": opt(manifestPath) { .string($0) },
            "recovery_phrase_enrolled": opt(recoveryPhraseEnrolled) { .bool($0) },
        ])
    }
}

/// The `.sha256.json` sidecar Windows writes next to every full backup (`recovery._manifest_payload` /
/// `verify_sha256_manifest`): compact JSON with sorted keys, checked without decrypting anything.
public enum ChecksumManifest {
    public static let format = "localgatekeys-sha256-manifest"
    public static let version: Int64 = 1
    public static let suffix = ".sha256.json"
    static let chunk = 1024 * 1024

    /// `<backup>.sha256.json` beside the backup.
    public static func url(for backup: URL) -> URL {
        backup.deletingLastPathComponent().appendingPathComponent(backup.lastPathComponent + suffix)
    }

    /// `sha256_file`: lowercase hex, read in 1 MiB chunks.
    public static func sha256(of url: URL) throws -> String {
        guard let handle = try? FileHandle(forReadingFrom: url) else { throw RecoveryError("Could not calculate the recovery checksum") }
        defer { try? handle.close() }
        var hasher = SHA256()
        do {
            while let data = try handle.read(upToCount: chunk), !data.isEmpty { hasher.update(data: data) }
        } catch { throw RecoveryError("Could not calculate the recovery checksum") }
        return lowerHex(Array(hasher.finalize()))
    }

    /// The manifest bytes for a backup called `backupName` (`_manifest_payload`). The inventory goes in without
    /// `backup_sha256` and `backup_bytes`, as Windows writes it.
    public static func make(backupName: String, size: Int, sha256: String, inventory: BackupInventory? = nil,
                            generatedAt: Int64) throws -> Data {
        var payload: [String: JSONValue] = [
            "format": .string(format), "version": .int(version), "algorithm": .string("sha256"),
            "generated_at": .int(generatedAt),
            "backup": .object(["name": .string(backupName), "size": .int(Int64(size)), "sha256": .string(try digest(.string(sha256)))]),
        ]
        if let inventory, case .object(var safe) = inventory.json {
            safe["backup_sha256"] = nil
            safe["backup_bytes"] = nil
            payload["inventory"] = .object(safe)
        }
        return Data(try CanonicalJSON.encode(.object(payload), dialect: .utf8))
    }

    /// Writes `<backup>.sha256.json` for the file at `backup`; returns where it went.
    @discardableResult
    public static func write(for backup: URL, inventory: BackupInventory? = nil, now: Int64) throws -> URL {
        let target = url(for: backup)
        let size = try fileSize(backup)
        let data = try make(backupName: backup.lastPathComponent, size: size, sha256: try sha256(of: backup),
                            inventory: inventory, generatedAt: now)
        do { try data.write(to: target, options: .atomic) } catch { throw RecoveryError("Could not write the recovery checksum manifest") }
        return target
    }

    /// `verify_sha256_manifest`: the manifest describes this file (name, size, SHA-256). Returns the size and digest.
    @discardableResult
    public static func verify(backup: URL, manifest: Data) throws -> (size: Int, sha256: String) {
        guard let parsed = try? CanonicalJSON.parse(Array(manifest)) else {
            throw RecoveryError("The recovery checksum manifest is unreadable")
        }
        guard case .object(let raw) = parsed, raw["format"] == .string(format), raw["version"] == .int(version) else {
            throw RecoveryError("Unsupported recovery checksum manifest")
        }
        guard case .object(let record)? = raw["backup"], record["name"] == .string(backup.lastPathComponent) else {
            throw RecoveryError("Recovery checksum manifest does not describe this backup")
        }
        let expectedSize: Int
        switch record["size"] {
        case .int(let n)?: expectedSize = Int(n)
        case .string(let s)? where Int(s.trimmingCharacters(in: .whitespaces)) != nil: expectedSize = Int(s.trimmingCharacters(in: .whitespaces))!
        default: throw RecoveryError("Recovery checksum manifest is malformed")
        }
        guard expectedSize == (try fileSize(backup)) else {
            throw RecoveryError("The recovery backup checksum manifest does not match its file size")
        }
        let expected = try digest(record["sha256"] ?? .null)
        let actual = try sha256(of: backup)
        guard actual == expected else { throw RecoveryError("The recovery backup checksum does not match its manifest") }
        return (expectedSize, actual)
    }

    /// `_validate_digest`.
    static func digest(_ value: JSONValue) throws -> String {
        guard case .string(let s) = value, s.utf8.count == 64,
              s.utf8.allSatisfy({ (0x30...0x39).contains($0) || (0x41...0x46).contains($0) || (0x61...0x66).contains($0) }) else {
            throw RecoveryError("Recovery checksum is malformed")
        }
        return s.lowercased()
    }

    public static func fileSize(_ url: URL) throws -> Int {
        // Not `resourceValues`: those are cached on the URL and miss a file that changed since.
        guard let size = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.size] as? NSNumber else {
            throw RecoveryError("Backup is not readable")
        }
        return size.intValue
    }
}
