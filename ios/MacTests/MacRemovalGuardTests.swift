import XCTest
import LGKCore
@testable import AppSharedMac

/// A folder that never opens (the locked check then has nothing to read).
private struct NoFolders: FolderOpening {
    func bookmark(for url: URL) throws -> [UInt8] { [] }
    func open(bookmark: [UInt8]) throws -> (folder: any FolderAccess, refreshed: [UInt8]?) { throw CocoaError(.fileNoSuchFile) }
}

/// The Mac's erase after a removal from sync: unlocks refused while it runs (`MacLockModel.beginErase`), a failed vault
/// step keeps the watch file and the folder that holds the vault (retried by the next check), and the one-time notice
/// only after a real erase (`MacRemovalGuard`, `MacVaultEraser`).
@MainActor
final class MacRemovalGuardTests: XCTestCase {
    private var root: URL!
    private var dir: URL!
    private var settings: AppSettings!
    private var suite: String!
    private var vault: MacVault!
    private var kdfHook: (@MainActor () async -> Void)?
    private let cheap = MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1)

    override func setUp() async throws {
        // `<root>/Vault`, as `<Application Support>/LocalGateKeys/Vault` in a build without an app group.
        root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-removal-\(UUID().uuidString)", isDirectory: true)
        dir = root.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        suite = "lgk-removal-tests-\(UUID().uuidString)"
        settings = AppSettings(defaults: UserDefaults(suiteName: suite)!)
    }

    override func tearDown() async throws {
        try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.appendingPathComponent("stuck").path)
        try? FileManager.default.removeItem(at: root)
        UserDefaults().removePersistentDomain(forName: suite)
    }

    private func unlockedModel() async -> MacLockModel {
        vault = MacVault(directory: dir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(), kdfParams: cheap,
                         beforeKDF: { [unowned self] in await self.kdfHook?() })
        let m = MacLockModel(vault: vault, settings: settings, events: FakeSystemEvents(), startTimer: false)
        await m.create(password: "correct horse", confirm: "correct horse", touchID: false)
        XCTAssertEqual(m.state, .unlocked)
        return m
    }

    private var watchURL: URL { SyncDependencies.watchFileURL(in: dir) }

    private func eraser(extra: [URL], keychain: InMemoryKeychainVault) -> MacVaultEraser {
        MacVaultEraser(directory: dir, keychains: [keychain], biometric: {}, extraDirectories: { extra })
    }

    func testEraseOnSyncRemovalDefaultsToOn() {
        XCTAssertTrue(settings.eraseOnSyncRemoval)
        XCTAssertNil(settings.syncRemovalErasedAt)
    }

    func testRemovalNoticeWordingNamesTheMac() {
        XCTAssertEqual(SyncWording.removalNoticeCopy(here: true), "Another of your devices removed this Mac from sync. “Erase this device if it is removed from sync” is off, so the vault stays on this Mac. Leave sync, or join the folder again.")
        let views = SyncWording.views([SyncIssue("busy"), SyncIssue(RemovalNotice.issueKind, "phone")])
        XCTAssertEqual(views.map(\.kind), [RemovalNotice.issueKind, "busy"])
        XCTAssertEqual(views.first?.resetOffered, false)
    }

    func testUnlockIsRefusedWhileTheEraseRuns() async {
        let m = await unlockedModel()
        m.beginErase()
        XCTAssertEqual(m.state, .locked)
        XCTAssertTrue(m.isErasing); XCTAssertTrue(m.isBusy)
        await m.unlock(password: "correct horse")
        XCTAssertEqual(m.state, .locked, "no password unlock during the erase")
        await m.unlockWithTouchID()
        XCTAssertEqual(m.state, .locked, "no Touch ID unlock during the erase")
        m.endErase(erased: false)   // nothing was erased: the vault opens again
        XCTAssertFalse(m.isErasing); XCTAssertEqual(m.state, .locked)
        await m.unlock(password: "correct horse")
        XCTAssertEqual(m.state, .unlocked)
    }

    func testAnUnlockInFlightWhenTheEraseStartsIsDiscarded() async {
        let m = await unlockedModel()
        m.lock()
        kdfHook = { m.beginErase() }   // the erase starts while Argon2 is about to run
        await m.unlock(password: "correct horse")
        kdfHook = nil
        XCTAssertEqual(m.state, .locked)
        XCTAssertTrue(m.isErasing)
        m.endErase(erased: false)
    }

    /// Without an app group the extra folders include the one that holds the vault: it waits for the vault step, so
    /// a failed erase keeps the watch file (and the next check erases again); the retry then removes everything.
    func testFailedVaultStepKeepsTheWatchAndTheParentFolderUntilTheRetry() async throws {
        let m = await unlockedModel()
        let fm = FileManager.default
        try Data("{}".utf8).write(to: watchURL)
        let attachments = root.appendingPathComponent("Attachments", isDirectory: true)
        try fm.createDirectory(at: attachments, withIntermediateDirectories: true)
        try Data([1]).write(to: attachments.appendingPathComponent("a.blob"))
        let stuck = dir.appendingPathComponent("stuck", isDirectory: true)
        try fm.createDirectory(at: stuck, withIntermediateDirectories: true)
        try Data([1]).write(to: stuck.appendingPathComponent("x"))
        try fm.setAttributes([.posixPermissions: 0o555], ofItemAtPath: stuck.path)   // its file cannot be deleted
        let keychain = InMemoryKeychainVault()
        try keychain.write(.installID, Array("install".utf8))
        let removal = MacRemovalGuard(lock: m, settings: settings, keychain: nil, folders: NoFolders(),
                                      eraser: eraser(extra: [root], keychain: keychain))

        await removal.erase()
        XCTAssertEqual(m.state, .locked); XCTAssertFalse(m.isErasing)
        XCTAssertTrue(fm.fileExists(atPath: watchURL.path), "kept, so the next check erases again")
        XCTAssertTrue(fm.fileExists(atPath: attachments.path), "the folder holding the vault waits for the vault step")
        XCTAssertNil(settings.syncRemovalErasedAt, "no notice for an erase that failed")
        XCTAssertNil(try keychain.read(.installID))

        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: stuck.path)
        await removal.erase()
        XCTAssertEqual(m.state, .noVault)
        XCTAssertFalse(m.isErasing)
        XCTAssertFalse(fm.fileExists(atPath: root.path))
        XCTAssertNotNil(settings.syncRemovalErasedAt)
    }

    func testSettingOffErasesNothing() async throws {
        settings.eraseOnSyncRemoval = false
        let m = await unlockedModel()
        try Data("{}".utf8).write(to: watchURL)
        let removal = MacRemovalGuard(lock: m, settings: settings, keychain: InMemoryKeychainVault(), folders: NoFolders(),
                                      eraser: eraser(extra: [], keychain: InMemoryKeychainVault()))
        await removal.erase()
        await removal.check()
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertTrue(FileManager.default.fileExists(atPath: watchURL.path))
        XCTAssertNil(settings.syncRemovalErasedAt)
    }

    func testLockedCheckWithoutAVerifiedNoticeErasesNothing() async throws {
        let m = await unlockedModel()
        m.lock()
        let keychain = InMemoryKeychainVault()
        try keychain.write(.folderBookmark, [1, 2, 3])
        try keychain.write(.installID, Array("install".utf8))
        let removal = MacRemovalGuard(lock: m, settings: settings, keychain: keychain, folders: NoFolders(),
                                      eraser: eraser(extra: [], keychain: keychain))
        await removal.check()   // no watch file
        try Data("{}".utf8).write(to: watchURL)
        await removal.check()   // a watch file that does not parse, and a folder that does not open
        XCTAssertEqual(m.state, .locked)
        XCTAssertTrue(vault.exists)
        XCTAssertNil(settings.syncRemovalErasedAt)
    }

    // MARK: kept scheduled backups (owner decision 2026-10-31; desktop `tests/test_device_removal.py`)

    private static let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../..").standardized
    /// A real full backup (`tests/vectors/backup/v2`): backup password below, the vault inside under the fixture
    /// master password.
    private static let fullBackup = repo.appendingPathComponent("tests/vectors/backup/v2/full.lgkfull")
    private static let backupPassword = "fixture backup password 2026"
    private let when = Date(timeIntervalSince1970: 1_793_448_000)   // 2026-10-31 12:00 UTC
    private var utc: Calendar { var c = Calendar(identifier: .gregorian); c.timeZone = TimeZone(identifier: "UTC")!; return c }
    private var scheduled: URL { MacFullBackup.backupsFolder(dir).appendingPathComponent(BackupSchedule.scheduledDirName, isDirectory: true) }
    private var keptRoot: URL { root.appendingPathComponent("Kept", isDirectory: true) }

    /// One real scheduled backup with its manifest, plus look-alikes and master-password-only copies that are erased.
    @discardableResult
    private func scheduledFiles() throws -> String {
        let fm = FileManager.default
        try fm.createDirectory(at: scheduled, withIntermediateDirectories: true)
        let tag = BackupScheduleModel.profileTag
        let name = try BackupSchedule.scheduledFilename(tag: tag, when: when.addingTimeInterval(-86_400), calendar: utc)
        try fm.copyItem(at: Self.fullBackup, to: scheduled.appendingPathComponent(name))
        try Data("{}".utf8).write(to: scheduled.appendingPathComponent(name + ".sha256.json"))
        // Named like this vault's scheduled backup but not a container, and another vault's tag: erased.
        try Data("plain".utf8).write(to: scheduled.appendingPathComponent(
            try BackupSchedule.scheduledFilename(tag: tag, when: when.addingTimeInterval(-2 * 86_400), calendar: utc)))
        try fm.copyItem(at: Self.fullBackup, to: scheduled.appendingPathComponent(
            try BackupSchedule.scheduledFilename(tag: BackupSchedule.profileTag("someone-else"), when: when, calendar: utc)))
        // A safety copy and the stored backup password (master password / local key only): erased.
        let safety = MacFullBackup.backupsFolder(dir).appendingPathComponent("before-restore-1", isDirectory: true)
        try fm.createDirectory(at: safety, withIntermediateDirectories: true)
        try Data([1]).write(to: safety.appendingPathComponent("records.bin"))
        try Data([2]).write(to: dir.appendingPathComponent(ScheduleSecretStore.fileName))
        return name
    }

    private func keepingEraser(keychain: InMemoryKeychainVault, kept: URL? = nil) -> MacVaultEraser {
        let target = kept ?? keptRoot
        return MacVaultEraser(directory: dir, keychains: [keychain], biometric: {}, extraDirectories: { [] },
                              keptBackupsRoot: { target })
    }

    func testEraseKeepsScheduledBackupsAndErasesTheRest() async throws {
        let m = await unlockedModel()
        let fm = FileManager.default
        let name = try scheduledFiles()
        // A mirror folder outside the vault folder: never touched.
        let mirror = root.appendingPathComponent("Mirror", isDirectory: true)
        try fm.createDirectory(at: mirror, withIntermediateDirectories: true)
        try fm.copyItem(at: Self.fullBackup, to: mirror.appendingPathComponent(name))
        let removal = MacRemovalGuard(lock: m, settings: settings, keychain: nil, folders: NoFolders(),
                                      eraser: keepingEraser(keychain: InMemoryKeychainVault()))

        await removal.erase()
        XCTAssertEqual(m.state, .noVault)
        XCTAssertFalse(fm.fileExists(atPath: dir.path), "safety copies, scheduled-backup.bin and look-alikes are erased")
        let folders = try fm.contentsOfDirectory(atPath: keptRoot.path)
        XCTAssertEqual(folders.count, 1)
        XCTAssertTrue(folders[0].hasPrefix("Vault 20"))
        let kept = keptRoot.appendingPathComponent(folders[0], isDirectory: true)
        XCTAssertEqual(Set(try fm.contentsOfDirectory(atPath: kept.path)), [name, name + ".sha256.json"])
        XCTAssertEqual(try fm.contentsOfDirectory(atPath: mirror.path), [name])
        XCTAssertEqual(settings.syncRemovalKeptBackups, kept.path)
        XCTAssertNotNil(settings.syncRemovalErasedAt)
        // Still a backup: the backup password opens it (the vault inside needs the master password), nothing else does.
        let data = try Data(contentsOf: kept.appendingPathComponent(name))
        XCTAssertNoThrow(try FullBackupV2.open(data, password: Self.backupPassword))
        XCTAssertThrowsError(try FullBackupV2.open(data, password: "fixture master password 2026"))
        let message = DeviceRemoval.erasedMessage(keptFolders: settings.syncRemovalKeptBackups)
        XCTAssertTrue(message.contains(kept.path))
        XCTAssertTrue(message.contains("backup password") && message.contains("master password"))
    }

    /// A scheduled backup to the public backup key (full backup v3) is a container too: kept, not erased.
    func testErasureKeepsVersion3ScheduledBackups() throws {
        let name = try scheduledFiles()
        let kdf = FullBackupV2.KDF(timeCost: 1, memoryKiB: 8192, parallelism: 1)
        var pair = try BackupKey.derive(password: Self.backupPassword, kdf: BackupKeyKDF.fresh(kdf, random: SystemRandomSource()))
        defer { pair.wipe() }
        let record = try BackupKeyRecord.build(key: pair, now: 1_793_000_000, setBy: "set", resetAuthority: nil, previous: nil)
        let v3 = try FullBackupV3.write(vault: Data("{}".utf8), settings: Data("{}".utf8), attachments: [], record: record,
                                        random: SystemRandomSource(), progress: { _, _, _ in }, cancel: { false },
                                        profileName: "Test", createdAt: 1_793_000_000).data
        let v3Name = try BackupSchedule.scheduledFilename(tag: BackupScheduleModel.profileTag, when: when, calendar: utc)
        try v3.write(to: scheduled.appendingPathComponent(v3Name))
        let kept = try XCTUnwrap(keepingEraser(keychain: InMemoryKeychainVault()).keepScheduledBackups(now: when, calendar: utc))
        let names = Set(try FileManager.default.contentsOfDirectory(atPath: kept.path))
        XCTAssertTrue(names.isSuperset(of: [name, v3Name]), "\(names)")
        XCTAssertNoThrow(try FullBackupV3.open(Data(contentsOf: kept.appendingPathComponent(v3Name)), password: Self.backupPassword))
    }

    func testKeptFolderNamesAreUnique() throws {
        try scheduledFiles()
        try FileManager.default.createDirectory(at: keptRoot.appendingPathComponent("Vault 2026-10-31"), withIntermediateDirectories: true)
        let kept = keepingEraser(keychain: InMemoryKeychainVault()).keepScheduledBackups(now: when, calendar: utc)
        XCTAssertEqual(kept?.lastPathComponent, "Vault 2026-10-31 (2)")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: keptRoot.appendingPathComponent("Vault 2026-10-31").path), [])
        XCTAssertNil(keepingEraser(keychain: InMemoryKeychainVault()).keepScheduledBackups(now: when, calendar: utc),
                     "nothing left to move: no new folder")
    }

    func testAKeptRootInsideAnErasedFolderKeepsNothing() throws {
        let name = try scheduledFiles()
        let inside = dir.appendingPathComponent("Kept", isDirectory: true)
        XCTAssertNil(keepingEraser(keychain: InMemoryKeychainVault(), kept: inside).keepScheduledBackups(now: when, calendar: utc))
        XCTAssertTrue(FileManager.default.fileExists(atPath: scheduled.appendingPathComponent(name).path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: inside.path))
    }

    func testNoScheduledBackupsKeepsNothingAndShowsThePlainNotice() async throws {
        let m = await unlockedModel()
        let removal = MacRemovalGuard(lock: m, settings: settings, keychain: nil, folders: NoFolders(),
                                      eraser: keepingEraser(keychain: InMemoryKeychainVault()))
        await removal.erase()
        XCTAssertEqual(m.state, .noVault)
        XCTAssertNil(settings.syncRemovalKeptBackups)
        XCTAssertFalse(FileManager.default.fileExists(atPath: keptRoot.path))
        XCTAssertEqual(DeviceRemoval.erasedMessage(keptFolders: nil), DeviceRemoval.erasedMessage)
    }
}
