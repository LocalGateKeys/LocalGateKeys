import XCTest
import LGKCore
@testable import AppSharedMac

@MainActor
private final class ScheduleFakeVault: MasterPasswordService {
    var right: String
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

/// Bookmarks as plain paths: a folder that is gone no longer resolves (a stale bookmark).
private struct PathBookmarks: BookmarkResolving {
    func bookmark(for url: URL) throws -> [UInt8] { Array(url.path.utf8) }
    func resolve(_ bytes: [UInt8]) throws -> (url: URL, refreshed: [UInt8]?) {
        let url = URL(fileURLWithPath: String(decoding: bytes, as: UTF8.self), isDirectory: true)
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue else {
            throw BackupFolderBookmark.unavailable
        }
        return (url, nil)
    }
}

/// A writer that leaves a partial file and fails (a full disk), counting its calls.
@MainActor
private final class FailingWriter: ScheduledBackupWriting {
    var calls = 0
    func createScheduled(to url: URL, backupPassword: String, passwordKey: DesktopVaultFile.PasswordKey,
                         recovery: RecoveryWrapper.VaultKey?) async throws -> BackupInventory {
        calls += 1
        try? Data("partial".utf8).write(to: url.deletingLastPathComponent().appendingPathComponent(".partial.staging"))
        throw RecoveryError("Could not create the recovery backup")
    }
}

/// Scheduled backups (Windows `backup_schedule.py`, `app/schedule.py`): due slots, catch-up on wake, nothing while
/// locked, write → verify → mirror → prune, retry after 30 minutes, folders as bookmarks.
@MainActor
final class MacBackupSchedulerTests: XCTestCase {
    private static let cheap = FullBackupV2.KDF(timeCost: 1, memoryKiB: 8192, parallelism: 1)
    private static let master = "fixture master password 2026"
    private static let backupPassword = "fixture backup password 2026"

    private var dir: URL!
    private var vaultDir: URL!
    private var suite: String!
    private var defaults: UserDefaults!
    private var unlocked = true
    private var calendar: Calendar = {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        return c
    }()
    private let key = (0..<32).map { UInt8($0 &* 5 &+ 3) }
    private var vault: ScheduleFakeVault!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-sched-\(UUID().uuidString)")
        vaultDir = dir.appendingPathComponent("vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDir, withIntermediateDirectories: true)
        suite = "lgk-sched-\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)
        vault = ScheduleFakeVault(Self.master)
        unlocked = true
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        UserDefaults().removePersistentDomain(forName: suite)
    }

    /// 2026-10-26 (a Monday) at `hour`:`minute` UTC, plus `days`.
    private func at(_ days: Int, _ hour: Int, _ minute: Int = 0) -> Date {
        calendar.date(from: DateComponents(year: 2026, month: 10, day: 26 + days, hour: hour, minute: minute))!
    }

    private func store() throws -> LocalStore {
        let s = try LocalStore.open(directory: vaultDir, vault: MemoryKeyVault(localKey: key, base: InMemoryKeychainVault()),
                                    limitHints: nil)
        let snap = try s.load()
        let login = Wrapper.make(ns: .entry, record: .object([
            "id": .string("11111111-1111-4111-8111-111111111111"), "kind": .string("web"), "label": .string("Mail"),
            "username": .string("ada"), "password": .string("pw"), "created_at": .int(1_700_000_000),
            "updated_at": .int(1_700_000_000),
        ]))
        try s.commit(StoreChange(baseRevision: snap.revision, records: ["11111111-1111-4111-8111-111111111111": login], meta: snap.meta,
                                 sync: snap.sync))
        return s
    }

    private func fullBackup(_ store: any ItemStore, now: @escaping () -> Date) -> MacFullBackup {
        MacFullBackup(store: store, profile: DesktopProfileStore(directory: vaultDir, localKey: key), passwords: vault,
                      gate: StrictItemGate(passwords: vault), local: InMemoryLocalData(), deviceName: "Test Mac",
                      licenseKeys: [:], now: now, kdf: Self.cheap, vaultKDF: Self.cheap)
    }

    /// The secret store under the unlocked vault's local key (nil: locked).
    private var secrets: ScheduleSecretStore?

    private func makeModel(keychain: any KeychainVault = InMemoryKeychainVault()) -> BackupScheduleModel {
        if secrets == nil { secrets = ScheduleSecretStore(directory: vaultDir, localKey: key) }
        return BackupScheduleModel(keychain: keychain, secrets: { [unowned self] in self.secrets }, defaults: defaults,
                                   passwords: vault, bookmarks: PathBookmarks(), kdf: Self.cheap, calendar: calendar)
    }

    private var defaultFolder: URL { vaultDir.appendingPathComponent("Backups/Scheduled", isDirectory: true) }

    private func scheduler(_ model: BackupScheduleModel, clock: @escaping () -> Date,
                           writer: @escaping @MainActor () -> (any ScheduledBackupWriting)?,
                           exclusive: @escaping MacBackupScheduler.Exclusive = { try await $0() }) -> MacBackupScheduler {
        MacBackupScheduler(model: model, history: BackupHistory(defaults: defaults), isUnlocked: { [unowned self] in self.unlocked },
                           makeWriter: writer, exclusive: exclusive, defaultFolder: { [vaultDir] in
                               vaultDir!.appendingPathComponent("Backups", isDirectory: true) },
                           now: clock, calendar: calendar, startTimer: false, observeWake: false)
    }

    private func owned(_ folder: URL) -> [String] {
        BackupSchedule.ownedBackups(in: folder, tag: BackupScheduleModel.profileTag).map(\.lastPathComponent)
    }

    // MARK: password

    func testShortOrSameBackupPasswordRefused() async throws {
        let model = makeModel()
        func refused(_ pw: String, _ confirm: String, _ master: String, _ message: String) async {
            do {
                try await model.setPassword(pw, confirm: confirm, master: master)
                XCTFail("accepted \(pw.count) characters")
            } catch {
                XCTAssertEqual(BackupScheduleModel.describe(error), message)
            }
            XCTAssertFalse(model.hasPassword)
        }
        await refused("long enough pass 1", "long enough pass 2", Self.master,
                      BackupScheduleModel.mismatchText)
        await refused("elevenchars", "elevenchars", Self.master, BackupScheduleModel.tooShortText)
        await refused(Self.master, Self.master, Self.master, BackupScheduleModel.sameText)
        await refused("", "", Self.master, BackupScheduleModel.enterText)
        await refused(Self.backupPassword, Self.backupPassword, "not the master password", "That password isn't right.")

        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        XCTAssertTrue(model.hasPassword)
        model.clearPassword()
        XCTAssertFalse(model.hasPassword)
        XCTAssertEqual(BackupScheduleModel.tooShortText, "The backup password must contain at least 12 characters.")
    }

    func testNoKeychainItemOpensABackup() async throws {
        let keychain = InMemoryKeychainVault()
        let model = makeModel(keychain: keychain)
        model.frequency = "daily"
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        // Nothing in any Keychain slot: the password, its key and the phrase key are sealed under the local key.
        for slot in VaultSlot.allCases { XCTAssertNil(try keychain.read(slot), "\(slot)") }
        let file = vaultDir.appendingPathComponent(ScheduleSecretStore.fileName)
        let bytes = try Data(contentsOf: file)
        XCTAssertNil(bytes.range(of: Data(Self.backupPassword.utf8)))
        // Another local key (an old one, or none) opens nothing.
        XCTAssertThrowsError(try ScheduleSecretStore(directory: vaultDir, localKey: [UInt8](repeating: 9, count: 32)).load())
        XCTAssertEqual(try ScheduleSecretStore(directory: vaultDir, localKey: key).load()?.backupPassword, Self.backupPassword)
        // A second model over the same vault (the next launch) has it.
        XCTAssertTrue(makeModel(keychain: keychain).hasPassword)
    }

    // MARK: schedule

    func testTimerAndWakeStopAtLockAndRearmOnceAtUnlock() async throws {
        let model = makeModel()
        let s = MacBackupScheduler(model: model, history: BackupHistory(defaults: defaults), isUnlocked: { [unowned self] in self.unlocked },
                                   makeWriter: { nil }, exclusive: { try await $0() }, defaultFolder: { nil },
                                   now: Date.init, calendar: calendar, startTimer: true, observeWake: true)
        XCTAssertTrue(s.timerArmed); XCTAssertTrue(s.wakeArmed)   // built while unlocked
        unlocked = false
        s.locked()
        XCTAssertFalse(s.timerArmed); XCTAssertFalse(s.wakeArmed)
        unlocked = true
        s.arm(); s.unlocked(now: Date()); s.arm()   // the unlock hook and its delayed check: still one of each
        XCTAssertTrue(s.timerArmed); XCTAssertTrue(s.wakeArmed)
        s.locked()
        XCTAssertFalse(s.timerArmed); XCTAssertFalse(s.wakeArmed)
    }

    func testRunsOnWakeAfterMissedSlot() async throws {
        let model = makeModel()
        model.frequency = "daily"; model.time = "12:00"; model.keep = 2
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        var now = at(0, 12, 30)
        let live = try store()
        let backup = fullBackup(live) { now }
        let s = scheduler(model, clock: { now }, writer: { backup })
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        XCTAssertEqual(owned(defaultFolder).count, 1)
        XCTAssertFalse(s.tick(now: now.addingTimeInterval(60)))   // not due again before the next slot

        // The Mac slept through the next day's 12:00; on wake the missed slot runs once.
        now = at(2, 9)
        XCTAssertTrue(s.woke(now: now))
        await s.settled()
        let names = owned(defaultFolder)
        XCTAssertEqual(names.count, 2)
        XCTAssertEqual(names.first, try BackupSchedule.scheduledFilename(tag: BackupScheduleModel.profileTag, when: now,
                                                                         calendar: calendar))
        XCTAssertEqual(BackupHistory(defaults: defaults).lastBackup, now)   // the 7-day warning sees it
        XCTAssertEqual(BackupSchedule.readLastSuccess(defaultFolder), now)
        XCTAssertEqual(model.status.text, "Last scheduled backup: 2026-10-28 09:00")
        XCTAssertNil(model.status.warning)
        XCTAssertFalse(s.tick(now: now.addingTimeInterval(15 * 60)))

        // The file is a normal full backup: it opens with the master password (Windows reads the same format).
        let url = defaultFolder.appendingPathComponent(names[0])
        XCTAssertTrue(FileManager.default.fileExists(atPath: ChecksumManifest.url(for: url).path))
        let inventory = try await backup.verify(url: url, password: Self.backupPassword, vaultPassword: Self.master)
        XCTAssertTrue(inventory.verified)
        XCTAssertEqual(inventory.profileName, "Test Mac")
    }

    func testNothingWhileLocked() async throws {
        let model = makeModel()
        model.frequency = "daily"
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let now = at(0, 13)
        let live = try store()
        var made = 0
        let backup = fullBackup(live) { now }
        let s = scheduler(model, clock: { now }, writer: { made += 1; return backup })
        unlocked = false
        XCTAssertFalse(s.tick(now: now))
        XCTAssertFalse(s.woke(now: now))
        await s.settled()
        XCTAssertEqual(made, 0)
        XCTAssertTrue(owned(defaultFolder).isEmpty)
        unlocked = true
        XCTAssertTrue(s.unlocked(now: now))
        await s.settled()
        XCTAssertEqual(owned(defaultFolder).count, 1)
    }

    func testOffOrNoPasswordDoesNothing() async throws {
        let model = makeModel()
        let now = at(0, 13)
        var made = 0
        let s = scheduler(model, clock: { now }, writer: { made += 1; return nil })
        XCTAssertFalse(s.tick(now: now))   // off by default
        XCTAssertEqual(model.status.text, "Scheduled backups are off.")
        model.frequency = "weekly"; model.weekday = 0
        XCTAssertFalse(s.tick(now: now))
        XCTAssertEqual(model.status.text, "Scheduled backups are off: set a backup password first.")
        XCTAssertEqual(model.status.warning, BackupScheduleModel.skippedText)
        XCTAssertEqual(made, 0)
    }

    func testStaleBookmarkAsksAgain() async throws {
        let model = makeModel()
        model.frequency = "daily"
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let chosen = dir.appendingPathComponent("External", isDirectory: true)
        try FileManager.default.createDirectory(at: chosen, withIntermediateDirectories: true)
        try model.chooseFolder(chosen)
        XCTAssertEqual(model.folder?.path, chosen.path)
        try FileManager.default.removeItem(at: chosen)   // the drive was unplugged, the folder moved
        let now = at(0, 13)
        var made = 0
        let live = try store()
        let backup = fullBackup(live) { now }
        let s = scheduler(model, clock: { now }, writer: { made += 1; return backup })
        XCTAssertFalse(s.tick(now: now))
        XCTAssertEqual(made, 0)
        XCTAssertEqual(model.status.warning, "Choose the backup folder again")
        XCTAssertTrue(owned(defaultFolder).isEmpty)   // never silently redirected to another folder

        // Chosen again: the backup goes to Scheduled inside it.
        try FileManager.default.createDirectory(at: chosen, withIntermediateDirectories: true)
        try model.chooseFolder(chosen)
        XCTAssertNil(model.status.warning)
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        XCTAssertEqual(owned(chosen.appendingPathComponent("Scheduled")).count, 1)
    }

    func testFailureRetriesAfterThirtyMinutesWithoutPruning() async throws {
        let model = makeModel()
        model.frequency = "daily"; model.keep = 1
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        try FileManager.default.createDirectory(at: defaultFolder, withIntermediateDirectories: true)
        let old = defaultFolder.appendingPathComponent(try BackupSchedule.scheduledFilename(
            tag: BackupScheduleModel.profileTag, when: at(-3, 12), calendar: calendar))
        try Data("older backup".utf8).write(to: old)
        try Data("{}".utf8).write(to: ChecksumManifest.url(for: old))

        var now = at(0, 13)
        let failing = FailingWriter()
        let live = try store()
        let good = fullBackup(live) { now }
        var writer: any ScheduledBackupWriting = failing
        let s = scheduler(model, clock: { now }, writer: { writer })
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        XCTAssertEqual(failing.calls, 1)
        XCTAssertEqual(model.status.warning, "Scheduled backup failed; the previous backup was kept. See the error log.")
        XCTAssertTrue(FileManager.default.fileExists(atPath: old.path))   // nothing older pruned
        XCTAssertTrue(FileManager.default.fileExists(atPath: ChecksumManifest.url(for: old).path))
        XCTAssertNil(BackupHistory(defaults: defaults).lastBackup)

        now = now.addingTimeInterval(29 * 60)
        XCTAssertFalse(s.tick(now: now))
        XCTAssertEqual(failing.calls, 1)
        now = at(0, 13).addingTimeInterval(30 * 60)
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        XCTAssertEqual(failing.calls, 2)
        XCTAssertTrue(FileManager.default.fileExists(atPath: old.path))

        // Fixed: the next retry writes, verifies, then prunes the older one (keep 1).
        writer = good
        now = now.addingTimeInterval(30 * 60)
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        XCTAssertFalse(FileManager.default.fileExists(atPath: old.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: ChecksumManifest.url(for: old).path))
        XCTAssertEqual(owned(defaultFolder).count, 1)
        XCTAssertNil(model.status.warning)
        XCTAssertEqual(BackupHistory(defaults: defaults).lastBackup, now)
    }

    func testNeverDuringRotationOrRestore() async throws {
        let model = makeModel()
        model.frequency = "daily"
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let now = at(0, 13)
        let live = try store()
        let backup = fullBackup(live) { now }
        var busy = true
        let s = scheduler(model, clock: { now }, writer: { backup }, exclusive: { body in
            if busy { throw MacVaultError.busy }   // a password change holds the vault's lock
            return try await body()
        })
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        XCTAssertTrue(owned(defaultFolder).isEmpty)
        XCTAssertNil(model.status.warning)   // not a failure: tried again at the next check
        busy = false
        XCTAssertTrue(s.tick(now: now.addingTimeInterval(60)))
        await s.settled()
        XCTAssertEqual(owned(defaultFolder).count, 1)
    }

    func testMirrorCopiesAndPrunesWithoutTouchingOtherFiles() async throws {
        let model = makeModel()
        model.frequency = "daily"; model.keep = 1
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let mirror = dir.appendingPathComponent("Cloud", isDirectory: true)
        try FileManager.default.createDirectory(at: mirror, withIntermediateDirectories: true)
        try Data("mine".utf8).write(to: mirror.appendingPathComponent("notes.txt"))
        try model.chooseMirror(mirror)
        var now = at(0, 13)
        let live = try store()
        let backup = fullBackup(live) { now }
        let s = scheduler(model, clock: { now }, writer: { backup })
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        now = at(1, 13)
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        let local = owned(defaultFolder), mirrored = owned(mirror)
        XCTAssertEqual(local.count, 1)
        XCTAssertEqual(mirrored, local)
        XCTAssertEqual(try ChecksumManifest.sha256(of: mirror.appendingPathComponent(mirrored[0])),
                       try ChecksumManifest.sha256(of: defaultFolder.appendingPathComponent(local[0])))
        XCTAssertTrue(FileManager.default.fileExists(atPath: mirror.appendingPathComponent("notes.txt").path))
        XCTAssertEqual(model.lastNotice, "Scheduled backup saved and copied to the mirror folder.")

        // A mirror that has gone never fails the local backup.
        try FileManager.default.removeItem(at: mirror)
        now = at(2, 13)
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        XCTAssertEqual(owned(defaultFolder).count, 1)
        XCTAssertEqual(BackupHistory(defaults: defaults).lastBackup, now)
        XCTAssertEqual(model.status.warning, "Scheduled backup saved. Mirror copy failed: The mirror folder is not available")
    }

    func testSecretOnlyOpensUnderTheCurrentLocalKey() async throws {
        let model = makeModel()
        model.frequency = "daily"
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let now = at(0, 13)
        let live = try store()
        let backup = fullBackup(live) { now }
        let s = scheduler(model, clock: { now }, writer: { backup })
        // Locked (no store) or another key: no secret, no run.
        let held = secrets
        secrets = nil
        XCTAssertFalse(model.hasPassword)
        XCTAssertFalse(s.tick(now: now))
        secrets = ScheduleSecretStore(directory: vaultDir, localKey: [UInt8](repeating: 4, count: 32))
        XCTAssertFalse(model.hasPassword)
        XCTAssertFalse(s.tick(now: now))
        secrets = held
        XCTAssertTrue(model.hasPassword)
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        let url = defaultFolder.appendingPathComponent(owned(defaultFolder)[0])
        _ = try await backup.verify(url: url, password: Self.backupPassword, vaultPassword: Self.master)
    }

    func testRemovedPhraseShowsANoticeOnTheCard() async throws {
        let model = makeModel()
        model.frequency = "daily"
        model.recoveryPhraseChanged(removed: true)
        XCTAssertNil(model.phraseNotice)   // no scheduled backups: nothing to say
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        model.recoveryPhraseChanged(removed: true)
        XCTAssertEqual(model.phraseNotice, BackupScheduleModel.phraseRemovedText)
        model.recoveryPhraseChanged(removed: false)   // a new phrase: its key was rebuilt with the rotation
        XCTAssertNil(model.phraseNotice)
        XCTAssertFalse(BackupScheduleModel.phraseRemovedText.contains("PC"))
    }

    func testPasswordPromptWaitsForAScheduledRun() async throws {
        let vdir = dir.appendingPathComponent("real", isDirectory: true)
        let real = MacVault(directory: vdir, keychain: InMemoryKeychainVault(), biometric: FakeBiometricKeyStore(),
                            random: SystemRandomSource(), kdfParams: MasterKeyFile.KDFParams(timeCost: 1, memoryKiB: 8192, parallelism: 1))
        _ = try await real.create(password: Self.master, enableTouchID: false)
        var release: CheckedContinuation<Void, Never>?
        var order: [String] = []
        let run = Task { @MainActor in
            try await real.exclusiveRun(scheduled: true) {
                await withCheckedContinuation { release = $0 }
                order.append("backup")
            }
        }
        while release == nil { await Task.yield() }
        let prompt = Task { @MainActor in try await real.verifyPassword(Self.master); order.append("prompt") }
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(order, [])   // waiting, not refused
        release?.resume()
        try await run.value
        try await prompt.value
        XCTAssertEqual(order, ["backup", "prompt"])

        // A run that outlasts the wait: the prompt says so.
        real.backupWaitSeconds = 0.05
        var release2: CheckedContinuation<Void, Never>?
        let run2 = Task { @MainActor in try await real.exclusiveRun(scheduled: true) { await withCheckedContinuation { release2 = $0 } } }
        while release2 == nil { await Task.yield() }
        do { try await real.verifyPassword(Self.master); XCTFail("not refused") }
        catch { XCTAssertEqual(MacLockModel.describe(error, now: Date()), "A backup is running. Try again in a moment.") }
        release2?.resume()
        try await run2.value
    }

    func testRecoveryCentreShowsTheSchedule() async throws {
        let model = makeModel()
        model.frequency = "weekly"
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let recovery = RecoveryCentreModel(backup: nil, passwords: vault, history: BackupHistory(defaults: defaults),
                                           schedule: { model.status })
        XCTAssertEqual(recovery.status.schedule.frequency, "weekly")
        XCTAssertEqual(recovery.status.schedule.text, "No scheduled backup yet.")
        XCTAssertEqual(BackupScheduleModel.frequencyTitles, ["Off", "Daily", "Weekly"])
        for line in BackupScheduleModel.copy {
            XCTAssertFalse(line.contains("PC"), line)
        }
    }

    func testManualBackupFolderIsBookmarked() async throws {
        let keychain = InMemoryKeychainVault()
        let model = makeModel(keychain: keychain)
        let chosen = dir.appendingPathComponent("Manual", isDirectory: true)
        try FileManager.default.createDirectory(at: chosen, withIntermediateDirectories: true)
        model.rememberManualFolder(chosen)
        XCTAssertEqual(makeModel(keychain: keychain).manualFolder()?.path, chosen.path)
        // The next launch's Recovery centre starts there.
        let recovery = RecoveryCentreModel(backup: nil, passwords: vault, scheduleModel: makeModel(keychain: keychain))
        XCTAssertEqual(recovery.lastFolder?.path, chosen.path)
        try FileManager.default.removeItem(at: chosen)
        XCTAssertNil(makeModel(keychain: keychain).manualFolder())
    }
}
