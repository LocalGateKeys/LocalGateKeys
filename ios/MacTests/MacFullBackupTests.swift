import XCTest
import LGKCore
@testable import AppSharedMac

@MainActor
private final class BackupFakeVault: MasterPasswordService {
    let right: String
    init(_ right: String) { self.right = right }
    var hasVault = true
    var isUnlocked = true
    var touchIDAvailable = false
    var routineTouchIDEnabled = false
    var sessionGeneration = 0
    func verifyPassword(_ password: String) async throws {
        guard password == right else { throw MacVaultError.wrongPassword(retryAfter: nil) }
    }
    func changePassword(old: String, new: String) async throws {}
    func setTouchID(_ on: Bool, password: String) async throws {}
    func verifyWithTouchID(reason: String) async throws {}
}

/// A real store whose commits can be made to fail.
private final class FlakyStore: ItemStore, @unchecked Sendable {
    let base: LocalStore
    var failCommits = false
    init(_ base: LocalStore) { self.base = base }
    func load() throws -> StoreSnapshot { try base.load() }
    func commit(_ change: StoreChange) throws {
        if failCommits { throw LocalStoreError.io("disk full") }
        try base.commit(change)
    }
}

/// A fixed byte stream, so a backup made in a test is the same file every run.
private final class SeededRandom: RandomSource, @unchecked Sendable {
    private var counter: UInt64 = 0
    private let lock = NSLock()
    func bytes(count: Int) -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        var out: [UInt8] = []
        while out.count < count {
            counter += 1
            out += CryptoBox.hkdf(ikm: withUnsafeBytes(of: counter.bigEndian) { Array($0) }, salt: [],
                                  info: Array("mac-full-backup-tests".utf8), length: 32)
        }
        return Array(out.prefix(count))
    }
}

/// Full backup on the Mac: create (with `.sha256.json`), verify, restore preview, restore by replacing (staged,
/// verified, swapped; old vault kept until next unlock) and the recovery kit, against Windows' own vectors.
@MainActor
final class MacFullBackupTests: XCTestCase {
    private static let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../..").standardized
    private static let v2 = repo.appendingPathComponent("tests/vectors/backup/v2")
    private static let cheap = FullBackupV2.KDF(timeCost: 1, memoryKiB: 8192, parallelism: 1)
    private static let master = "fixture master password 2026"
    private static let backupPassword = "fixture backup password 2026"

    private var dir: URL!
    private var vaultDir: URL!
    private let key = (0..<32).map { UInt8($0 &* 7 &+ 1) }

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-full-\(UUID().uuidString)")
        vaultDir = dir.appendingPathComponent("vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    private func liveStore() throws -> FlakyStore {
        FlakyStore(try LocalStore.open(directory: vaultDir, vault: MemoryKeyVault(localKey: key, base: InMemoryKeychainVault()),
                                       limitHints: nil))
    }

    private func model(_ store: any ItemStore, local: InMemoryLocalData? = InMemoryLocalData(),
                       random: any RandomSource = SystemRandomSource()) -> (MacFullBackup, StrictItemGate) {
        let vault = BackupFakeVault(Self.master)
        let gate = StrictItemGate(passwords: vault)
        let m = MacFullBackup(store: store, profile: DesktopProfileStore(directory: vaultDir, localKey: key),
                              passwords: vault, gate: gate, local: local, deviceName: "Test Mac", licenseKeys: [:],
                              now: { Date(timeIntervalSince1970: 1_793_100_000) }, random: random, kdf: Self.cheap,
                              vaultKDF: Self.cheap, attachmentFolder: attachments)
        return (m, gate)
    }

    /// This test's attachment folder (never the real Application Support).
    private var attachments: BlobFolder { BlobFolder(root: dir.appendingPathComponent("files", isDirectory: true)) }

    /// Task 12: a document goes into the backup as a Windows sidecar and catalog row; a restore preview writes no
    /// file; the confirmed restore seals the file again and brings the document back as a document.
    func testDocumentsRoundTripAndPreviewWritesNothing() async throws {
        let store = try liveStore()
        let doc = try AttachmentDocuments.make(data: Array("synthetic scan".utf8), fileName: "scan.pdf",
                                               mimeType: "application/pdf", title: "Scan", now: 1_700_000_000,
                                               random: SystemRandomSource(), blobs: attachments)
        try seed(store, [Self.a: Self.login(Self.a, "mail"), doc.id: doc.wrapper])
        let (m, gate) = model(store)
        let url = dir.appendingPathComponent("docs.lgk")
        _ = try await m.create(to: url, backupPassword: Self.backupPassword, masterPassword: Self.master)
        let contents = try FullBackupV2.open(Data(contentsOf: url), password: Self.backupPassword)
        XCTAssertEqual(contents.attachments.map(\.id), [doc.ref.attachmentID])
        let (payload, _) = try DesktopVaultFile.openPayload(contents.vault, password: Self.master)
        guard case .array(let rows)? = payload["attachments"], case .string(let storeID)? = payload["attachment_store_id"] else {
            return XCTFail("catalog")
        }
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(try DesktopAttachmentSidecar.open(Array(contents.attachments[0].data), id: doc.ref.attachmentID,
                                                         storeID: storeID, key: doc.ref.key), Array("synthetic scan".utf8))

        // A new Mac: the preview counts the document and writes nothing; the restore seals the file.
        try FileManager.default.removeItem(at: attachments.dir)
        try seed(store, [:])
        let preview = try await m.previewRestore(url: url, password: Self.backupPassword, vaultPassword: Self.master)
        XCTAssertEqual(preview.keptOnly, 0)
        XCTAssertEqual(preview.otherItems, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: attachments.dir.path))
        let ok = try await restore(m, gate, url)
        XCTAssertTrue(ok, m.message ?? "")
        XCTAssertEqual(try store.load().records[doc.id], doc.wrapper)
        XCTAssertTrue(attachments.has(doc.ref.blob))
    }

    private static func login(_ id: String, _ title: String, updated: Int64 = 1_700_000_000) -> JSONValue {
        Wrapper.make(ns: .entry, record: .object([
            "id": .string(id), "kind": .string("web"), "label": .string(title), "username": .string("ada"),
            "password": .string("pw-\(title)"), "urls": .array([.object(["url": .string("https://\(title).example"),
                                                                          "match": .string("exact_origin")])]),
            "created_at": .int(updated), "updated_at": .int(updated),
        ]))
    }

    private static func note(_ id: String) -> JSONValue {
        Wrapper.make(ns: .item, record: .object([
            "id": .string(id), "kind": .string("note"), "title": .string("Router"), "fields": .object(["body": .string("x")]),
            "created_at": .int(1_700_000_000), "updated_at": .int(1_700_000_000),
        ]))
    }

    private func seed(_ store: any ItemStore, _ records: [String: JSONValue]) throws {
        let snap = try store.load()
        try store.commit(StoreChange(baseRevision: snap.revision, records: records, meta: snap.meta, sync: snap.sync))
    }

    private static let a = "11111111-1111-4111-8111-111111111111"
    private static let b = "22222222-2222-4222-8222-222222222222"
    private static let c = "33333333-3333-4333-8333-333333333333"
    private static let d = "44444444-4444-4444-8444-444444444444"

    /// Canonical JSON of each record, sorted, for comparing record sets.
    private static func canon(_ v: [JSONValue]) -> [String] {
        v.map { String(decoding: (try? CanonicalJSON.encode($0, dialect: .utf8)) ?? [], as: UTF8.self) }.sorted()
    }

    private func restore(_ m: MacFullBackup, _ gate: StrictItemGate, _ url: URL, password: String = backupPassword) async throws -> Bool {
        XCTAssertTrue(m.requestRestore(url: url, password: password, vaultPassword: Self.master))
        await gate.submit(Self.master)
        return await m.restoreTask?.value ?? false
    }

    func testCreateVerifyRestoreRoundTrip() async throws {
        let store = try liveStore()
        let original = [Self.a: Self.login(Self.a, "mail"), Self.b: Self.login(Self.b, "bank"), Self.c: Self.note(Self.c)]
        try seed(store, original)
        let local = InMemoryLocalData()
        let (m, gate) = model(store, local: local)
        let url = dir.appendingPathComponent(MacFullBackup.defaultFileName(now: Date(timeIntervalSince1970: 1_793_100_000)))
        XCTAssertTrue(url.lastPathComponent.hasPrefix("LocalGateKeys-backup-2026-"))
        XCTAssertEqual(url.pathExtension, "lgk")

        let made = try await m.create(to: url, backupPassword: Self.backupPassword, masterPassword: Self.master)
        XCTAssertEqual(made.entries, 2)   // vault + settings, no attachments
        XCTAssertTrue(made.verified)
        XCTAssertEqual(made.profileName, "Test Mac")
        XCTAssertEqual(made.backupSHA256, try ChecksumManifest.sha256(of: url))
        let manifest = ChecksumManifest.url(for: url)
        XCTAssertNoThrow(try ChecksumManifest.verify(backup: url, manifest: Data(contentsOf: manifest)))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".staging") }, [])

        let checked = try await m.verify(url: url, password: Self.backupPassword, vaultPassword: Self.master)
        XCTAssertEqual(checked.backupSHA256, made.backupSHA256)
        XCTAssertEqual(checked.recoveryPhraseEnrolled, false)

        // Change the vault: edit one, delete one, add one.
        var changed = original
        changed[Self.a] = Self.login(Self.a, "mail-edited", updated: 1_800_000_000)
        changed[Self.b] = nil
        changed[Self.d] = Self.login(Self.d, "new")
        try seed(store, changed)

        let preview = try await m.previewRestore(url: url, password: Self.backupPassword, vaultPassword: Self.master)
        XCTAssertEqual(preview.logins, 2)
        XCTAssertEqual(preview.otherItems, 1)
        XCTAssertEqual(preview.currentItems, 3)
        XCTAssertEqual(preview.added, 1)       // b
        XCTAssertEqual(preview.replaced, 1)    // a
        XCTAssertEqual(preview.unchanged, 1)   // c
        XCTAssertEqual(preview.removed, 1)     // d
        XCTAssertEqual(preview.backupIsNewer, false)
        XCTAssertTrue(preview.lines.contains("1 items not in the backup move to Recently deleted"))

        // Not without the strict gate.
        do { try await m.restoreReplacing(url: url, password: Self.backupPassword, vaultPassword: Self.master); XCTFail() }
        catch { XCTAssertEqual(error as? RecoveryError, MacFullBackup.notAuthorised) }

        let ok = try await restore(m, gate, url)
        XCTAssertTrue(ok, m.message ?? "")
        XCTAssertEqual(try store.load().records, original)
        XCTAssertEqual(local.localData?.trash.count, 1, "the item the backup lacks went to Recently deleted")
        // A safety copy of the vault as it was is kept; unlock never deletes it, and it can be put back.
        MacFullBackup.finishInterruptedRestore(in: vaultDir)
        let copies = m.safetyCopies()
        XCTAssertEqual(copies.count, 1)
        XCTAssertTrue(m.requestRestore(safetyCopy: copies[0]))
        await gate.submit(Self.master)
        let back = await m.restoreTask?.value
        XCTAssertEqual(back, true, m.message ?? "")
        XCTAssertEqual(try store.load().records, changed)
        XCTAssertEqual(m.safetyCopies().count, 2, "putting a copy back keeps one of the vault it replaced")
        XCTAssertFalse(FileManager.default.fileExists(atPath: vaultDir.appendingPathComponent(MacFullBackup.markerName).path))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: vaultDir.path).filter { $0.hasPrefix("restore-staging-") }, [])
    }

    func testSafetyCopiesKeepNewestFive() async throws {
        let store = try liveStore()
        try seed(store, [Self.a: Self.login(Self.a, "mail")])
        var clock: TimeInterval = 1_793_100_000
        let vault = BackupFakeVault(Self.master)
        let gate = StrictItemGate(passwords: vault)
        let m = MacFullBackup(store: store, profile: DesktopProfileStore(directory: vaultDir, localKey: key), passwords: vault,
                              gate: gate, local: InMemoryLocalData(), deviceName: "Test Mac", licenseKeys: [:],
                              now: { Date(timeIntervalSince1970: clock) },
                              kdf: Self.cheap, vaultKDF: Self.cheap)
        let url = dir.appendingPathComponent("five.lgk")
        _ = try await m.create(to: url, backupPassword: Self.backupPassword, masterPassword: Self.master)
        for _ in 0..<7 {
            clock += 60
            let ok = try await restore(m, gate, url)
            XCTAssertTrue(ok, m.message ?? "")
        }
        let copies = m.safetyCopies()
        XCTAssertEqual(copies.count, MacFullBackup.safetyKeep)
        XCTAssertEqual(copies.first?.createdAtMillis, Int64(clock * 1000))
        XCTAssertEqual(copies.map(\.createdAtMillis), copies.map(\.createdAtMillis).sorted(by: >))
    }

    func testRestoreWindowsBackupKeepsAllItemsAndAttachments() async throws {
        let expected = try CanonicalJSON.parse(Array(Data(contentsOf: Self.v2.appendingPathComponent("expected.json"))))
        guard case .object(let e) = expected, case .array(let records)? = e["records"],
              case .array(let attachmentIDs)? = e["attachment_ids"] else { return XCTFail("vector") }
        let store = try liveStore()
        let (m, gate) = model(store)
        let windows = Self.v2.appendingPathComponent("full.lgkfull")
        let preview = try await m.previewRestore(url: windows, password: Self.backupPassword, vaultPassword: Self.master)
        XCTAssertEqual(preview.profileName, "Fixture profile")
        XCTAssertEqual(preview.items, records.count)
        XCTAssertEqual(preview.attachments, attachmentIDs.count)
        let ok = try await restore(m, gate, windows)
        XCTAssertTrue(ok, m.message ?? "")
        let snap = try store.load()
        XCTAssertEqual(Self.canon(snap.records.values.map(MacFullBackup.record)), Self.canon(records))
        for case .string(let id) in attachmentIDs {
            XCTAssertEqual(try Data(contentsOf: vaultDir.appendingPathComponent("Attachments/\(id).blob")),
                           try Data(contentsOf: Self.v2.appendingPathComponent("inputs/\(id).blob")))
        }
        let windowsPayload = try DesktopVaultFile.openPayload(Data(contentsOf: Self.v2.appendingPathComponent("inputs/vault.json")),
                                                              password: Self.master).payload

        // Backed up again on the Mac: every record, every sidecar, the settings and the catalog's other fields.
        let again = dir.appendingPathComponent("again.lgk")
        _ = try await m.create(to: again, backupPassword: Self.backupPassword, masterPassword: Self.master)
        let contents = try FullBackupV2.open(Data(contentsOf: again), password: Self.backupPassword)
        XCTAssertEqual(contents.profileName, "Fixture profile")
        XCTAssertEqual(contents.settings, try Data(contentsOf: Self.v2.appendingPathComponent("inputs/settings.json")))
        XCTAssertEqual(contents.attachments.map(\.id), attachmentIDs.compactMap { if case .string(let s) = $0 { return s }; return nil }.sorted())
        let (payload, _) = try DesktopVaultFile.openPayload(contents.vault, password: Self.master)
        let ids: (JSONValue?) -> [JSONValue] = { if case .array(let a)? = $0 { return a }; return [] }
        XCTAssertEqual(Self.canon(ids(payload["entries"]) + ids(payload["items"])), Self.canon(records))
        for (k, v) in windowsPayload where !["version", "catalog", "generation", "entries", "items", "created_at", "updated_at"].contains(k) {
            XCTAssertEqual(payload[k], v, k)
        }

        // Python opens a backup made through this create path (tests/test_mac_backup_vectors.py). Seeded randomness and
        // a fixed clock make it the same file every run; the tracked copy is rewritten only when the bytes change.
        let (fixed, _) = model(store, random: SeededRandom())
        let made = dir.appendingPathComponent("mac-created.lgk")
        let inventory = try await fixed.create(to: made, backupPassword: Self.backupPassword, masterPassword: Self.master)
        let made2 = dir.appendingPathComponent("again/mac-created.lgk")
        try FileManager.default.createDirectory(at: made2.deletingLastPathComponent(), withIntermediateDirectories: true)
        let (fixed2, _) = model(store, random: SeededRandom())
        _ = try await fixed2.create(to: made2, backupPassword: Self.backupPassword, masterPassword: Self.master)
        XCTAssertEqual(try Data(contentsOf: made), try Data(contentsOf: made2), "the Mac create path is deterministic here")
        let out = Self.repo.appendingPathComponent("tests/vectors/recovery/kit/from_mac", isDirectory: true)
        let target = out.appendingPathComponent("mac-created.lgk")
        if (try? Data(contentsOf: target)) != (try Data(contentsOf: made)) {
            try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
            try fixed.writeRecoveryKit(to: dir.appendingPathComponent("recovery-kit.json"), backup: made, inventory: inventory,
                                       appVersion: "1.0.0")
            for name in ["mac-created.lgk", "mac-created.lgk.sha256.json", "recovery-kit.json"] {
                try? FileManager.default.removeItem(at: out.appendingPathComponent(name))
                try FileManager.default.copyItem(at: dir.appendingPathComponent(name), to: out.appendingPathComponent(name))
            }
        }
    }

    func testInterruptedRestoreRolledBackAtUnlock() async throws {
        let (store, m, gate, mine, before) = try await interruptedSetup()
        m.crashPoint = .afterPiecesSwapped
        let crashed = try await restore(m, gate, mine)
        XCTAssertFalse(crashed)
        XCTAssertTrue(FileManager.default.fileExists(atPath: vaultDir.appendingPathComponent(MacFullBackup.markerName).path))
        XCTAssertNotEqual(try snapshotState(store), before, "the pieces were swapped when it stopped")
        MacFullBackup.finishInterruptedRestore(in: vaultDir)
        XCTAssertEqual(try snapshotState(store), before)
        XCTAssertFalse(FileManager.default.fileExists(atPath: vaultDir.appendingPathComponent(MacFullBackup.markerName).path))
    }

    func testInterruptedRestoreKeptWhenCommitLanded() async throws {
        let (store, m, gate, mine, before) = try await interruptedSetup()
        m.crashPoint = .afterCommit
        let crashed = try await restore(m, gate, mine)
        XCTAssertFalse(crashed)
        let after = try snapshotState(store)
        XCTAssertNotEqual(after, before)
        MacFullBackup.finishInterruptedRestore(in: vaultDir)
        XCTAssertEqual(try snapshotState(store), after, "the commit landed: the restore stands")
        XCTAssertEqual(Set(try store.load().records.keys), [Self.a])
        XCTAssertFalse(FileManager.default.fileExists(atPath: vaultDir.appendingPathComponent(MacFullBackup.markerName).path))
    }

    func testInterruptedRestoreWithMissingSafetyCopyLeavesFilesAndMarker() async throws {
        let (store, m, gate, mine, _) = try await interruptedSetup()
        m.crashPoint = .afterPiecesSwapped
        let crashed = try await restore(m, gate, mine)
        XCTAssertFalse(crashed)
        let swapped = try snapshotState(store)
        let marker = vaultDir.appendingPathComponent(MacFullBackup.markerName)
        // The copy the marker names lost its records.bin (incomplete): nothing is touched, the marker stays.
        let copy = try XCTUnwrap(m.safetyCopies().first)
        try FileManager.default.removeItem(at: copy.folder.appendingPathComponent("records.bin"))
        MacFullBackup.finishInterruptedRestore(in: vaultDir)
        XCTAssertEqual(try snapshotState(store), swapped)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
        // Gone altogether: the same.
        try FileManager.default.removeItem(at: copy.folder)
        MacFullBackup.finishInterruptedRestore(in: vaultDir)
        XCTAssertEqual(try snapshotState(store), swapped)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
    }

    func testFailedPutBackKeepsMarkerAndRetries() async throws {
        let (store, m, gate, mine, before) = try await interruptedSetup()
        m.crashPoint = .afterPiecesSwapped
        let crashed = try await restore(m, gate, mine)
        XCTAssertFalse(crashed)
        let marker = vaultDir.appendingPathComponent(MacFullBackup.markerName)
        // Leftover temp files from an earlier put-back and safety copy are swept at unlock.
        let strayFile = vaultDir.appendingPathComponent(".desktop-profile.bin.\(UUID().uuidString).putback")
        try Data("x".utf8).write(to: strayFile)
        let strayCopy = vaultDir.appendingPathComponent("Backups/.before-restore-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: strayCopy, withIntermediateDirectories: true)
        MacFullBackup.failPutBackForTests = true
        defer { MacFullBackup.failPutBackForTests = false }
        MacFullBackup.finishInterruptedRestore(in: vaultDir)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path), "a failed put-back keeps the marker")
        XCTAssertFalse(FileManager.default.fileExists(atPath: strayFile.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: strayCopy.path))
        MacFullBackup.failPutBackForTests = false
        MacFullBackup.finishInterruptedRestore(in: vaultDir)
        XCTAssertEqual(try snapshotState(store), before)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    struct VaultState: Equatable { let blobs: [String: Data]; let records: [String: JSONValue]; let profile: Data? }

    private func snapshotState(_ store: any ItemStore) throws -> VaultState {
        let fm = FileManager.default
        let att = vaultDir.appendingPathComponent("Attachments")
        var blobs: [String: Data] = [:]
        for name in (try? fm.contentsOfDirectory(atPath: att.path)) ?? [] { blobs[name] = try Data(contentsOf: att.appendingPathComponent(name)) }
        return VaultState(blobs: blobs, records: try store.load().records,
                          profile: try? Data(contentsOf: vaultDir.appendingPathComponent("desktop-profile.bin")))
    }

    /// A vault restored from the Windows vector (attachments, kept data), and a Mac backup with no attachments.
    private func interruptedSetup() async throws -> (FlakyStore, MacFullBackup, StrictItemGate, URL, VaultState) {
        let store = try liveStore()
        let (m, gate) = model(store)
        let ok = try await restore(m, gate, Self.v2.appendingPathComponent("full.lgkfull"))
        XCTAssertTrue(ok)
        let other = dir.appendingPathComponent("other-vault", isDirectory: true)
        try FileManager.default.createDirectory(at: other, withIntermediateDirectories: true)
        let otherStore = FlakyStore(try LocalStore.open(directory: other, vault: MemoryKeyVault(localKey: key, base: InMemoryKeychainVault()),
                                                        limitHints: nil))
        try seed(otherStore, [Self.a: Self.login(Self.a, "only")])
        let vault = BackupFakeVault(Self.master)
        let otherModel = MacFullBackup(store: otherStore, profile: DesktopProfileStore(directory: other, localKey: key),
                                       passwords: vault, gate: StrictItemGate(passwords: vault), local: nil,
                                       deviceName: "Other Mac", licenseKeys: [:], kdf: Self.cheap, vaultKDF: Self.cheap)
        let mine = dir.appendingPathComponent("mine.lgk")
        _ = try await otherModel.create(to: mine, backupPassword: Self.backupPassword, masterPassword: Self.master)
        return (store, m, gate, mine, try snapshotState(store))
    }

    func testDamagedKeptDataAsksBeforeBackingUp() async throws {
        let store = try liveStore()
        let (m, gate) = model(store)
        let ok = try await restore(m, gate, Self.v2.appendingPathComponent("full.lgkfull"))
        XCTAssertTrue(ok)
        try Data("damaged".utf8).write(to: vaultDir.appendingPathComponent("desktop-profile.bin"))
        let url = dir.appendingPathComponent("damaged.lgk")
        do { _ = try await m.create(to: url, backupPassword: Self.backupPassword, masterPassword: Self.master); XCTFail() }
        catch {
            XCTAssertEqual(error as? RecoveryError, MacFullBackup.keptDataUnreadable)
            XCTAssertNotEqual(MacFullBackup.describe(error), "Full backup restore failed")
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        _ = try await m.create(to: url, backupPassword: Self.backupPassword, masterPassword: Self.master, withoutKeptData: true)
        let contents = try FullBackupV2.open(Data(contentsOf: url), password: Self.backupPassword)
        XCTAssertEqual(contents.attachments.count, 0)
        XCTAssertEqual(try DesktopVaultFile.open(contents.vault, password: Self.master).items.count, try store.load().records.count)
    }

    func testLicenceGoesIntoBackup() async throws {
        let store = try liveStore()
        let bundle: JSONValue = .object(["payload": .string("signed licence"), "sig": .string("abc")])
        let licenceID = License.idPrefix + "fixture"
        try seed(store, [Self.a: Self.login(Self.a, "mail"), licenceID: Wrapper.make(ns: .license, record: bundle)])
        let (m, gate) = model(store)
        let url = dir.appendingPathComponent("licensed.lgk")
        _ = try await m.create(to: url, backupPassword: Self.backupPassword, masterPassword: Self.master)
        let contents = try FullBackupV2.open(Data(contentsOf: url), password: Self.backupPassword)
        let (payload, _) = try DesktopVaultFile.openPayload(contents.vault, password: Self.master)
        XCTAssertEqual(payload["license"], bundle)
        XCTAssertEqual(try DesktopVaultFile.open(contents.vault, password: Self.master).items.count, 1, "not an item")
        XCTAssertTrue(m.message?.contains(MacFullBackup.otherDeviceNote) ?? false)
        let ok = try await restore(m, gate, url)
        XCTAssertTrue(ok)
        XCTAssertEqual(try store.load().records[licenceID], Wrapper.make(ns: .license, record: bundle), "this Mac's licence stays")
    }

    func testFailedRestoreLeavesVaultUntouched() async throws {
        let store = try liveStore()
        let (m, gate) = model(store)
        // A vault holding Windows data (attachments, desktop-profile.bin) first.
        let windows = Self.v2.appendingPathComponent("full.lgkfull")
        let restored = try await restore(m, gate, windows)
        XCTAssertTrue(restored)
        let mine = dir.appendingPathComponent("mine.lgk")
        try seed(store, [Self.a: Self.login(Self.a, "only")])
        _ = try await m.create(to: mine, backupPassword: Self.backupPassword, masterPassword: Self.master)
        try seed(store, [Self.b: Self.login(Self.b, "current")])
        struct State: Equatable { let blobs: [String: Data]; let records: [String: JSONValue]; let profile: Data }
        func state() throws -> State {
            let fm = FileManager.default
            let att = vaultDir.appendingPathComponent("Attachments")
            var blobs: [String: Data] = [:]
            for name in try fm.contentsOfDirectory(atPath: att.path) { blobs[name] = try Data(contentsOf: att.appendingPathComponent(name)) }
            return State(blobs: blobs, records: try store.load().records,
                         profile: try Data(contentsOf: vaultDir.appendingPathComponent("desktop-profile.bin")))
        }
        let before = try state()

        // A wrong vault password, a wrong backup password, a tampered file.
        let wrongVault = m.requestRestore(url: mine, password: Self.backupPassword, vaultPassword: "not the master password")
        XCTAssertTrue(wrongVault)
        await gate.submit(Self.master)
        let r1 = await m.restoreTask?.value
        XCTAssertEqual(r1, false)
        XCTAssertEqual(try state(), before)
        let r2 = try await restore(m, gate, mine, password: "not the backup password!")
        XCTAssertFalse(r2)
        let tampered = dir.appendingPathComponent("tampered.lgk")
        var bytes = try Data(contentsOf: mine)
        bytes[bytes.count / 2] ^= 0x40
        try bytes.write(to: tampered)
        let r3 = try await restore(m, gate, tampered)
        XCTAssertFalse(r3)
        XCTAssertEqual(try state(), before)

        // A failure just before the swap, and a failed store commit after the files were swapped in.
        m.beforeSwap = { throw RecoveryError("injected") }
        let r4 = try await restore(m, gate, mine)
        XCTAssertFalse(r4)
        XCTAssertEqual(try state(), before)
        m.beforeSwap = {}
        store.failCommits = true
        let r5 = try await restore(m, gate, mine)
        XCTAssertFalse(r5)
        store.failCommits = false
        XCTAssertEqual(try state(), before)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: vaultDir.path).filter { $0.hasPrefix("restore-staging-") }, [])
        // And the same restore then works.
        let r6 = try await restore(m, gate, mine)
        XCTAssertTrue(r6)
        XCTAssertEqual(Set(try store.load().records.keys), [Self.a])
    }

    func testSamePasswordRefused() async throws {
        let store = try liveStore()
        try seed(store, [Self.a: Self.login(Self.a, "mail")])
        let (m, _) = model(store)
        let url = dir.appendingPathComponent("same.lgk")
        do { _ = try await m.create(to: url, backupPassword: Self.master, masterPassword: Self.master); XCTFail() }
        catch { XCTAssertEqual(error as? RecoveryError, .samePassword) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        do { _ = try await m.create(to: url, backupPassword: Self.backupPassword, masterPassword: "wrong master password"); XCTFail() }
        catch { XCTAssertEqual(MacFullBackup.describe(error), "The master password is wrong.") }
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        let windows = Self.v2.appendingPathComponent("full.lgkfull")
        do { _ = try await m.verify(url: windows, password: Self.master, vaultPassword: Self.master); XCTFail() }
        catch { XCTAssertEqual(error as? RecoveryError, .samePassword) }
    }

    func testManifestMismatchReported() async throws {
        let store = try liveStore()
        try seed(store, [Self.a: Self.login(Self.a, "mail")])
        let (m, gate) = model(store)
        let url = dir.appendingPathComponent("checked.lgk")
        _ = try await m.create(to: url, backupPassword: Self.backupPassword, masterPassword: Self.master)
        // The backup grows by a byte: the manifest no longer matches its size.
        let handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd(); try handle.write(contentsOf: Data([0])); try handle.close()
        do { _ = try await m.verify(url: url, password: Self.backupPassword, vaultPassword: Self.master); XCTFail() }
        catch { XCTAssertEqual((error as? RecoveryError)?.message, "The recovery backup checksum manifest does not match its file size") }
        // Same size, different bytes.
        var bytes = try Data(contentsOf: url)
        bytes.removeLast()
        bytes[10] ^= 1
        try bytes.write(to: url)
        do { _ = try await m.previewRestore(url: url, password: Self.backupPassword, vaultPassword: Self.master); XCTFail() }
        catch { XCTAssertEqual((error as? RecoveryError)?.message, "The recovery backup checksum does not match its manifest") }
        let r = try await restore(m, gate, url)
        XCTAssertFalse(r)
        XCTAssertEqual(m.message, "The recovery backup checksum does not match its manifest")
    }

    func testRecoveryKitMatchesPython() async throws {
        let store = try liveStore()
        try seed(store, [Self.a: Self.login(Self.a, "mail")])
        let (m, _) = model(store)
        let url = dir.appendingPathComponent("kit.lgk")
        let inventory = try await m.create(to: url, backupPassword: Self.backupPassword, masterPassword: Self.master)
        let kitURL = dir.appendingPathComponent("recovery-kit.json")
        try m.writeRecoveryKit(to: kitURL, backup: url, inventory: inventory, appVersion: "1.0.0")
        let kit = try JSONSerialization.jsonObject(with: Data(contentsOf: kitURL)) as! [String: Any]
        let python = try JSONSerialization.jsonObject(with: Data(contentsOf: Self.repo.appendingPathComponent(
            "tests/vectors/recovery/kit/recovery-kit.json"))) as! [String: Any]
        XCTAssertEqual(Set(kit.keys), Set(python.keys))
        XCTAssertEqual(Set((kit["inventory"] as! [String: Any]).keys), Set((python["inventory"] as! [String: Any]).keys))
        XCTAssertEqual(kit["restore_guide"] as? String, (python["restore_guide"] as! String) + " " + MacFullBackup.otherDeviceNote)
        let files = kit["files"] as! [[String: Any]]
        XCTAssertEqual(files.map { $0["role"] as! String }, ["encrypted-full-backup-v2", "sha256-manifest"])
        XCTAssertEqual(files.map { $0["name"] as! String }, ["kit.lgk", "kit.lgk.sha256.json"])
        XCTAssertEqual(files[0]["sha256"] as? String, inventory.backupSHA256)
        let text = String(decoding: try Data(contentsOf: kitURL), as: UTF8.self)
        XCTAssertFalse(text.contains(Self.master))
        XCTAssertFalse(text.contains(Self.backupPassword))
    }
}
