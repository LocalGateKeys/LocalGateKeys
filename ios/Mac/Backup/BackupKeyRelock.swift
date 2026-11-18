import Foundation
import Darwin
import LGKCore

/// Design `backup-public-key-2026-10-31.md` section 7.2 on the Mac: after a backup password change, this profile's
/// scheduled **version 3** backups in the Scheduled folder and the mirror folder are re-locked to the new key.
///
/// Per file: only `header.json` is read first. An old-format file (v2 full backup, anything not version 3) or a v3
/// file under another key is skipped and never opened further, rewritten, renamed or touched (hard rule 1.1). A
/// matching file: the data key is unwrapped with the old private key (outer layer only; `vault.json` is never
/// decrypted), a new header wraps the same key to the new record, every other member is copied verbatim into a
/// temporary file beside it, that file is checked without a password (section 9.1), renamed over the same name and
/// given the original's modification date (retention orders by the name, so nothing changes there). Its
/// `.sha256.json` is moved out of the way before the rename (a missing checksum file is tolerated, a stale one would
/// refuse the restore) and written again for the new bytes after it. A failure keeps the original; a crash leaves the
/// old or the new file, each restorable. A file that can't be read is left as it is and counted apart.
enum BackupKeyRelock {
    struct Result: Equatable, Sendable {
        var relocked = 0
        /// Old-format files plus files under other keys.
        var leftAsTheyAre = 0
        /// Files that could not be read at all (left as they are; nothing is known about their key).
        var unreadable = 0
        var failed = 0
    }

    nonisolated static let temporarySuffix = ".relock"

    nonisolated static func relock(folders: [URL], tag: String, oldKey: BackupKeyPair, newRecord: BackupKeyRecord,
                                   random: any RandomSource, now: Int64) -> Result {
        var result = Result()
        var seen = Set<String>()
        for folder in folders {
            let resolved = folder.resolvingSymlinksInPath().standardizedFileURL.path
            guard seen.insert(resolved).inserted else { continue }
            for url in BackupSchedule.ownedBackups(in: folder, tag: tag) {
                switch relockOne(url, oldKey: oldKey, newRecord: newRecord, random: random, now: now) {
                case .relocked: result.relocked += 1
                case .skipped: result.leftAsTheyAre += 1
                case .unreadable: result.unreadable += 1
                case .failed: result.failed += 1
                }
            }
        }
        return result
    }

    enum Outcome: Equatable { case relocked, skipped, unreadable, failed }

    nonisolated static func relockOne(_ url: URL, oldKey: BackupKeyPair, newRecord: BackupKeyRecord,
                                      random: any RandomSource, now: Int64) -> Outcome {
        let fm = FileManager.default
        // Step 1: the header only. Anything that is not a v3 file under the old key stays exactly as it is.
        guard let data = try? Data(contentsOf: url, options: .alwaysMapped) else { return .unreadable }
        guard FullBackup.headerVersion(data) == FullBackupV3.version else { return .skipped }
        guard let info = try? FullBackupV3.inspect(data), info.recipient.keyID == oldKey.keyID else { return .skipped }
        guard let attributes = try? fm.attributesOfItem(atPath: url.path),
              let modified = attributes[.modificationDate] as? Date else { return .failed }
        // Steps 2-3: unwrap with the old key, check the manifest, a new header to the new key.
        guard var written = try? FullBackupV3.relock(data, oldKey: oldKey, newRecord: newRecord, random: random) else { return .failed }
        defer { written.wipe() }
        // Step 4: a temporary file beside it, checked, renamed onto the same name, the original date kept.
        let temporary = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)\(temporarySuffix)")
        defer { try? fm.removeItem(at: temporary) }
        do {
            try written.data.write(to: temporary, options: .withoutOverwriting)
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporary.path)
            _ = try MacFullBackup.openWritten(temporary, written: written, record: newRecord, vault: nil)
        } catch {
            return .failed
        }
        // The checksum file goes first (review L1): from here on the old or the new bytes sit without one, which
        // restore and verify accept, never beside a checksum that no longer matches.
        let manifest = ChecksumManifest.url(for: url)
        let oldManifest = try? Data(contentsOf: manifest)
        if fm.fileExists(atPath: manifest.path) {
            do { try fm.removeItem(at: manifest) } catch { return .failed }
        }
        guard rename(temporary.path, url.path) == 0 else {
            if let oldManifest { try? oldManifest.write(to: manifest, options: .atomic) }   // the original is still there
            return .failed
        }
        try? fm.setAttributes([.modificationDate: modified], ofItemAtPath: url.path)
        if let oldManifest { rewriteManifest(oldManifest, for: url, now: now) }
        return .relocked
    }

    /// `<backup>.sha256.json` for the re-locked bytes, from the old one's content: name, size and SHA-256 updated,
    /// the inventory kept. Best effort: without it the backup still restores (no checksum to compare).
    nonisolated static func rewriteManifest(_ old: Data, for url: URL, now: Int64) {
        let manifest = ChecksumManifest.url(for: url)
        guard case .object(var o)? = try? CanonicalJSON.parse(Array(old)),
              let size = try? ChecksumManifest.fileSize(url), let sha = try? ChecksumManifest.sha256(of: url) else { return }
        o["backup"] = .object(["name": .string(url.lastPathComponent), "size": .int(Int64(size)), "sha256": .string(sha)])
        o["generated_at"] = .int(now)
        guard let bytes = try? CanonicalJSON.encode(.object(o), dialect: .utf8) else { return }
        try? Data(bytes).write(to: manifest, options: .atomic)
    }

    /// "Re-locked N backups to the new backup password. M older backups were left as they are and still need the
    /// password they were made with." (section 7.2), plus failures.
    nonisolated static func text(_ result: Result) -> String {
        var parts = [String(localized: "Re-locked \(result.relocked) backups to the new backup password.")]
        if result.leftAsTheyAre > 0 {
            parts.append(String(localized: "\(result.leftAsTheyAre) older backups were left as they are and still need the password they were made with."))
        }
        if result.unreadable > 0 {
            parts.append(String(localized: "\(result.unreadable) backups could not be read and were left as they are."))
        }
        if result.failed > 0 {
            parts.append(String(localized: "\(result.failed) backups could not be re-locked and still open with the old backup password."))
        }
        return parts.joined(separator: " ")
    }
}
