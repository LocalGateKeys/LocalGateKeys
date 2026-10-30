import Foundation
import XCTest
@testable import LGKCore

/// The `.sha256.json` checksum manifest and the recovery kit (`recovery.py`), pinned to `tests/vectors/recovery/kit`
/// (written by `scripts/gen_mac_backup_vectors.py kit` over `backup/v2/full.lgkfull`).
final class RecoveryKitTests: XCTestCase {
    private static let repo: URL = Vectors.root.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    private static let dir = repo.appendingPathComponent("tests/vectors/recovery/kit", isDirectory: true)
    private static let backup = repo.appendingPathComponent("tests/vectors/backup/v2/full.lgkfull")

    private static func expected() throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Data(contentsOf: dir.appendingPathComponent("expected.json"))) as! [String: Any]
    }
    private static func vector(_ name: String) throws -> Data { try Data(contentsOf: dir.appendingPathComponent(name)) }

    private static func inventory() throws -> BackupInventory {
        let i = try expected()["inventory"] as! [String: Any]
        return BackupInventory(version: Int64(i["version"] as! Int), path: i["path"] as! String,
                               profileName: i["profile_name"] as? String, entries: i["entries"] as! Int,
                               attachmentCount: i["attachment_count"] as! Int, attachmentBytes: i["attachment_bytes"] as! Int,
                               backupBytes: i["backup_bytes"] as! Int, backupSHA256: i["backup_sha256"] as! String,
                               createdAt: Int64(i["created_at"] as! Int), verified: i["verified"] as! Bool,
                               verifiedAt: (i["verified_at"] as? Int).map(Int64.init), sameDisk: i["same_disk"] as! Bool,
                               warnings: i["warnings"] as! [String], manifestPath: i["manifest_path"] as? String,
                               recoveryPhraseEnrolled: i["recovery_phrase_enrolled"] as? Bool)
    }

    /// A scratch copy of `full.lgkfull` under its own name (the manifest names the file).
    private func scratchBackup() throws -> URL {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-kit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: d) }
        let url = d.appendingPathComponent("full.lgkfull")
        try FileManager.default.copyItem(at: Self.backup, to: url)
        return url
    }

    func testManifestMatchesPython() throws {
        let now = Int64(try Self.expected()["generated_at"] as! Int)
        let url = try scratchBackup()
        let size = try ChecksumManifest.fileSize(url)
        let sha = try ChecksumManifest.sha256(of: url)
        XCTAssertEqual(try ChecksumManifest.make(backupName: "full.lgkfull", size: size, sha256: sha,
                                                 inventory: try Self.inventory(), generatedAt: now),
                       try Self.vector("full.lgkfull.sha256.json"))
        XCTAssertEqual(try ChecksumManifest.make(backupName: "full.lgkfull", size: size, sha256: sha, generatedAt: now),
                       try Self.vector("plain.sha256.json"))
        let written = try ChecksumManifest.write(for: url, inventory: try Self.inventory(), now: now)
        XCTAssertEqual(written.lastPathComponent, "full.lgkfull.sha256.json")
        XCTAssertEqual(try Data(contentsOf: written), try Self.vector("full.lgkfull.sha256.json"))
        let ok = try ChecksumManifest.verify(backup: url, manifest: try Self.vector("full.lgkfull.sha256.json"))
        XCTAssertEqual(ok.sha256, sha)
    }

    func testRecoveryKitMatchesPython() throws {
        let e = try Self.expected()
        let now = Int64(e["generated_at"] as! Int)
        let url = try scratchBackup()
        try Self.vector("full.lgkfull.sha256.json").write(to: ChecksumManifest.url(for: url))
        let kit = url.deletingLastPathComponent().appendingPathComponent("recovery-kit.json")
        try RecoveryKit.write(to: kit, backup: url, inventory: try Self.inventory(), appVersion: e["app_version"] as! String, now: now)
        XCTAssertEqual(try Data(contentsOf: kit), try Self.vector("recovery-kit.json"))
        XCTAssertEqual(RecoveryKit.defaultRestoreGuide, e["restore_guide"] as! String)
        XCTAssertEqual(RecoveryError.samePassword.message, e["same_password_message"] as! String)
        XCTAssertThrowsError(try RecoveryKit.write(to: kit, backup: url, inventory: nil, appVersion: " ", now: now))
    }

    func testEachRejectedManifestRefusedWithItsMessage() throws {
        let rejected = try Self.expected()["rejected"] as! [String: String]
        XCTAssertFalse(rejected.isEmpty)
        let url = try scratchBackup()
        for (name, message) in rejected {
            XCTAssertThrowsError(try ChecksumManifest.verify(backup: url, manifest: try Self.vector("rejected/\(name)")), name) {
                XCTAssertEqual(($0 as? RecoveryError)?.message, message, name)
            }
        }
    }
}
