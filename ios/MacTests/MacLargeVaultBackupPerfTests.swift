import XCTest
import LGKCore
@testable import AppSharedMac

/// docs/PENDING.md "save time on a vault with large documents, automatic backups on": a real vault holding 10 × 20 MB
/// documents (sealed blobs, as `DocumentFiles.add` stores them) and 10 × 20 MB Windows attachment sidecars in
/// `Attachments/` (the folder each automatic copy clones), then the work one save does with the count on: the commit,
/// `MacAutomaticBackups.write` and the prune. Fails above 3 s per save.
@MainActor
final class MacLargeVaultBackupPerfTests: XCTestCase {
    private var dir: URL!
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-largebackup-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() async throws { try? FileManager.default.removeItem(at: dir) }

    func testSaveWithAutomaticBackupsOnTenTwentyMBDocuments() async throws {
        let mb20 = 20 * 1024 * 1024
        let vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(),
                             random: SystemRandomSource(), kdfParams: cheap)
        let store = try await vault.create(password: "correct horse", enableTouchID: false)
        store.limitHints = nil
        let blobs = BlobFolder(root: dir.appendingPathComponent("blobs", isDirectory: true))
        try FileManager.default.createDirectory(at: blobs.dir, withIntermediateDirectories: true)
        let profile = DesktopProfileStore(directory: dir, localKey: [UInt8](repeating: 9, count: 32))
        try FileManager.default.createDirectory(at: profile.attachmentsURL, withIntermediateDirectories: true)

        var snap = try store.load()
        var payload = Data(count: mb20)
        let addStart = Date()
        for i in 0..<10 {
            payload.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 4096, $0.baseAddress!) }
            let made = try AttachmentDocuments.make(data: Array(payload), fileName: "doc\(i).pdf", mimeType: "application/pdf",
                                                    title: "Doc \(i)", now: 1_800_000_000, random: SystemRandomSource(),
                                                    blobs: blobs)
            snap.records[made.id] = made.wrapper
            try payload.write(to: profile.attachmentsURL.appendingPathComponent("a\(i).blob"))
        }
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        let addSeconds = Date().timeIntervalSince(addStart)

        // Six saves with the count at 5 (the default): the sixth also prunes the oldest copy.
        var times: [Double] = []
        for i in 0..<6 {
            let t0 = Date()
            var s = try store.load()
            let id = try XCTUnwrap(s.records.keys.sorted().first)
            if case .object(var w) = s.records[id]!, case .object(var r) = w["record"] ?? .null {
                r["title"] = .string("Doc edited \(i)"); w["record"] = .object(r); s.records[id] = .object(w)
            }
            try store.commit(StoreChange(baseRevision: s.revision, records: s.records, meta: s.meta, sync: s.sync))
            let after = try store.load()
            try MacAutomaticBackups.write(records: after.records, revision: after.revision, profile: profile,
                                          now: Date(timeIntervalSince1970: 1_800_000_000 + Double(i)))
            MacAutomaticBackups.prune(profile: profile, keep: 5)
            times.append(Date().timeIntervalSince(t0))
        }
        XCTAssertEqual(MacAutomaticBackups.copies(in: dir).count, 5)
        let worst = times.max() ?? 0
        print(String(format: "MAC-PERF add 10x20MB documents: %.2f s; save+backup per save: %@ s; worst %.3f s",
                     addSeconds, times.map { String(format: "%.3f", $0) }.joined(separator: ", "), worst))
        XCTAssertLessThan(worst, 3.0, "one save with automatic backups on stays under 3 s")
    }
}
