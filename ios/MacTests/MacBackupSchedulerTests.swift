import XCTest
import LGKCore
@testable import AppSharedMac

@MainActor
private final class ScheduleFakeVault: MasterPasswordService {
    var right: String
    /// The phrase's vault key handed out with the master password (nil: no recovery phrase).
    var recovery: RecoveryWrapper.VaultKey?
    init(_ right: String) { self.right = right }
    var hasRecoveryPhrase: Bool { recovery != nil }
    func recoveryVaultKey(password: String) async throws -> RecoveryWrapper.VaultKey? {
        try await verifyPassword(password)
        return recovery
    }
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
    func createScheduled(to url: URL, record: BackupKeyRecord, passwordKey: DesktopVaultFile.PasswordKey,
                         recovery: RecoveryWrapper.VaultKey?) async throws -> BackupInventory {
        calls += 1
        try? Data("partial".utf8).write(to: url.deletingLastPathComponent().appendingPathComponent(".partial.staging"))
        throw RecoveryError("Could not create the recovery backup")
    }
}

/// A system random source that runs a hook once, at its next use (a key operation's new salt, after its proof).
private final class HookRandom: RandomSource, @unchecked Sendable {
    private var hook: (@MainActor () -> Void)?
    func arm(_ hook: @escaping @MainActor () -> Void) { self.hook = hook }
    /// The model asks on the main actor (synchronously, before its Argon2 task).
    func bytes(count: Int) -> [UInt8] {
        if let h = hook { hook = nil; MainActor.assumeIsolated { h() } }
        return SystemRandomSource().bytes(count: count)
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
    /// The model's clock (Unix seconds of record times, the Q1 reminder).
    private var clockNow = Date(timeIntervalSince1970: 1_793_000_000)

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

    private func makeModel(keychain: any KeychainVault = InMemoryKeychainVault(),
                           random: any RandomSource = SystemRandomSource()) -> BackupScheduleModel {
        if secrets == nil { secrets = ScheduleSecretStore(directory: vaultDir, localKey: key) }
        return BackupScheduleModel(keychain: keychain, secrets: { [unowned self] in self.secrets }, defaults: defaults,
                                   passwords: vault, bookmarks: PathBookmarks(), kdf: Self.cheap, backupKDF: Self.cheap,
                                   random: random, calendar: calendar, clock: { [unowned self] in self.clockNow })
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
        try await model.removeKey(proof: .password(Self.backupPassword))
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
        // Only the public record is stored (format v2): no backup password at all.
        let stored = try XCTUnwrap(try ScheduleSecretStore(directory: vaultDir, localKey: key).load())
        XCTAssertNil(stored.backupPassword)
        XCTAssertEqual(stored.backupKey?.setBy, "set")
        XCTAssertTrue(try XCTUnwrap(stored.backupKey).passwordMatches(Self.backupPassword))
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

    // MARK: public-key backups (design backup-public-key-2026-10-31)

    private var mirrorDir: URL { dir.appendingPathComponent("Cloud", isDirectory: true) }

    /// A v1 secret, as an install from before public-key backups stored it (the backup password itself).
    private func writeLegacySecret(recovery: RecoveryWrapper.VaultKey? = nil) throws {
        let pk = try DesktopVaultFile.derivePasswordKey(password: Self.master, kdf: Self.cheap, random: SystemRandomSource())
        try ScheduleSecretStore(directory: vaultDir, localKey: key)
            .save(ScheduledBackupSecret(backupPassword: Self.backupPassword, passwordKey: pk, recovery: recovery))
    }

    /// An old-format (v2, password) backup under a scheduled name, as the schedule wrote them before the update.
    private func oldFormatBackup(_ backup: MacFullBackup, at when: Date, in folder: URL) async throws -> URL {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let url = folder.appendingPathComponent(try BackupSchedule.scheduledFilename(tag: BackupScheduleModel.profileTag,
                                                                                     when: when, calendar: calendar))
        _ = try await backup.create(to: url, backupPassword: Self.backupPassword, masterPassword: Self.master)
        XCTAssertEqual(FullBackup.headerVersion(try Data(contentsOf: url)), 2)
        return url
    }

    /// Every file of a folder: name → SHA-256 and modification time.
    private func snapshot(_ folder: URL) throws -> [String: String] {
        var out: [String: String] = [:]
        for name in (try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? [] {
            let url = folder.appendingPathComponent(name)
            let date = try XCTUnwrap(try FileManager.default.attributesOfItem(atPath: url.path)[.modificationDate] as? Date)
            out[name] = "\(try ChecksumManifest.sha256(of: url))|\(date.timeIntervalSince1970)"
        }
        return out
    }

    private func version(_ url: URL) throws -> Int64? { FullBackup.headerVersion(try Data(contentsOf: url)) }

    func testScheduledBackupIsVersion3ToThePublicKey() async throws {
        let model = makeModel()
        model.frequency = "daily"
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let record = try XCTUnwrap(model.record)
        XCTAssertEqual(model.keyLine, BackupScheduleModel.keySetText(BackupScheduleModel.day(record.setAt, calendar)))
        XCTAssertEqual(model.keySeen, BackupScheduleModel.KeySeen(keyID: record.keyID, setAt: record.setAt))
        XCTAssertNil(model.upgradeNotice)
        let now = at(0, 13)
        let live = try store()
        let backup = fullBackup(live) { now }
        let s = scheduler(model, clock: { now }, writer: { backup })
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        let url = defaultFolder.appendingPathComponent(try XCTUnwrap(owned(defaultFolder).first))
        let data = try Data(contentsOf: url)
        guard case .v3(let info) = try FullBackup.inspect(data) else { return XCTFail("not v3") }
        XCTAssertEqual(info.recipient.keyID, record.keyID)
        XCTAssertNoThrow(try FullBackupV3.open(data, password: Self.backupPassword))
        XCTAssertThrowsError(try FullBackupV3.open(data, password: "not the backup password"))
        // The state file has the published file's SHA-256 (design 9.1 step 4).
        let state = try String(contentsOf: BackupSchedule.stateURL(defaultFolder), encoding: .utf8)
        XCTAssertTrue(state.contains(try ChecksumManifest.sha256(of: url)))
        XCTAssertEqual(BackupSchedule.readLastSuccess(defaultFolder), now)
        let inventory = try await backup.verify(url: url, password: Self.backupPassword, vaultPassword: Self.master)
        XCTAssertEqual(inventory.version, 3)
        // Manual backups stay password-encrypted v2 (hard rule 1.1, item 4).
        let manual = dir.appendingPathComponent("manual.lgk")
        _ = try await backup.create(to: manual, backupPassword: Self.backupPassword, masterPassword: Self.master)
        XCTAssertEqual(try version(manual), 2)
    }

    func testMigrationTouchesNoBackupAndKeepsTheNewestOldOne() async throws {
        let live = try store()
        var now = at(-3, 12)
        let backup = fullBackup(live) { now }
        let old1 = try await oldFormatBackup(backup, at: at(-3, 12), in: defaultFolder)
        let old2 = try await oldFormatBackup(backup, at: at(-2, 12), in: defaultFolder)
        try FileManager.default.createDirectory(at: mirrorDir, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: old2, to: mirrorDir.appendingPathComponent(old2.lastPathComponent))
        try writeLegacySecret()
        let model = makeModel()
        model.frequency = "daily"; model.keep = 1
        try model.chooseMirror(mirrorDir)
        XCTAssertEqual(model.keyState, .legacy)
        let s = scheduler(model, clock: { now }, writer: { backup })   // the app builds it at launch, before any unlock
        let before = try snapshot(defaultFolder), beforeMirror = try snapshot(mirrorDir)

        let migrated = await model.migrateIfNeeded()
        XCTAssertTrue(migrated)
        let record = try XCTUnwrap(model.record)
        XCTAssertEqual(record.setBy, "migrated")
        XCTAssertNil(record.resetAuthority)   // no phrase enrolled
        XCTAssertTrue(record.passwordMatches(Self.backupPassword))
        XCTAssertNil(try XCTUnwrap(model.secret()).backupPassword)   // the password went in the same save
        XCTAssertEqual(model.keySeen?.keyID, record.keyID)
        // Hard rule 1.1: same files, same bytes, same dates.
        XCTAssertEqual(try snapshot(defaultFolder), before)
        XCTAssertEqual(try snapshot(mirrorDir), beforeMirror)
        XCTAssertEqual(model.protectedOld, [old2.lastPathComponent])
        XCTAssertEqual(model.keyLine, BackupScheduleModel.keyMigratedText)
        XCTAssertEqual(model.upgradeNotice, BackupScheduleModel.upgradeNoticeText + " " + BackupScheduleModel.upgradeRecommendText)
        let again = await model.migrateIfNeeded()
        XCTAssertFalse(again)   // idempotent

        // Retention (keep 1): the first v3 run prunes old1 by the usual rule; old2 stays (Q3), locally and mirrored.
        now = at(0, 13)
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        XCTAssertFalse(FileManager.default.fileExists(atPath: old1.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: old2.path))
        now = at(1, 13)
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        let names = owned(defaultFolder)
        XCTAssertEqual(names.count, 2)
        XCTAssertTrue(names.contains(old2.lastPathComponent))
        XCTAssertTrue(owned(mirrorDir).contains(old2.lastPathComponent))
        XCTAssertEqual(owned(mirrorDir).count, 2)
        // The old backup still restores with the old password and the master password, exactly as before.
        let inventory = try await backup.verify(url: old2, password: Self.backupPassword, vaultPassword: Self.master)
        XCTAssertEqual(inventory.version, 2)
        XCTAssertNoThrow(try ChecksumManifest.verify(backup: old2, manifest: Data(contentsOf: ChecksumManifest.url(for: old2))))
    }

    func testMigrationThatCannotSaveKeepsTheStoredPassword() async throws {
        try writeLegacySecret()
        let model = makeModel()
        model.frequency = "daily"
        try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: vaultDir.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: vaultDir.path) }
        let migrated = await model.migrateIfNeeded()
        XCTAssertFalse(migrated)
        XCTAssertTrue(model.migrationFailed)
        XCTAssertEqual(model.keyState, .legacy)
        XCTAssertEqual(try XCTUnwrap(model.secret()).backupPassword, Self.backupPassword)
        let s = scheduler(model, clock: { [unowned self] in self.at(0, 13) }, writer: { nil })
        XCTAssertFalse(s.tick(now: at(0, 13)))   // skipped this session
        XCTAssertEqual(model.lastNotice, BackupScheduleModel.migrationFailedText)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: vaultDir.path)
        s.locked()   // the next unlock tries again
        let retried = await model.migrateIfNeeded()
        XCTAssertTrue(retried)
    }

    func testUpgradeNoticeThenOneReminder() async throws {
        try writeLegacySecret()
        let model = makeModel()
        _ = await model.migrateIfNeeded()
        XCTAssertNotNil(model.upgradeNotice)
        model.dismissUpgradeNotice()
        XCTAssertNil(model.upgradeNotice)
        XCTAssertEqual(model.record?.setBy, "migrated")   // dismissing undoes nothing
        clockNow = clockNow.addingTimeInterval(29 * 86_400)
        XCTAssertNil(model.upgradeNotice)
        clockNow = clockNow.addingTimeInterval(86_400)
        XCTAssertEqual(model.upgradeNotice, BackupScheduleModel.upgradeReminderText)
        model.dismissUpgradeNotice()
        clockNow = clockNow.addingTimeInterval(90 * 86_400)
        XCTAssertNil(model.upgradeNotice)
        // After a change the line gives the date and no notice is shown.
        try await model.changePassword(old: Self.backupPassword, new: "a brand new backup password", confirm: "a brand new backup password",
                                       relock: false)
        XCTAssertNil(model.upgradeNotice)
        XCTAssertEqual(model.keyLine, BackupScheduleModel.keySetText(BackupScheduleModel.day(Int64(clockNow.timeIntervalSince1970), calendar)))
    }

    func testChangeNeedsTheOldPasswordAndRelocksOnlyVersion3() async throws {
        let model = makeModel()
        model.frequency = "daily"; model.keep = 2
        try FileManager.default.createDirectory(at: mirrorDir, withIntermediateDirectories: true)
        try model.chooseMirror(mirrorDir)
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let live = try store()
        var now = at(-1, 12)
        let backup = fullBackup(live) { now }
        let old = try await oldFormatBackup(backup, at: at(-2, 12), in: defaultFolder)
        let oldMirror = mirrorDir.appendingPathComponent(old.lastPathComponent)
        try FileManager.default.copyItem(at: old, to: oldMirror)
        now = at(0, 13)
        let s = scheduler(model, clock: { now }, writer: { backup })
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        let v3 = try XCTUnwrap(owned(defaultFolder).first)
        let v3URL = defaultFolder.appendingPathComponent(v3), v3Mirror = mirrorDir.appendingPathComponent(v3)
        XCTAssertEqual(try version(v3URL), 3)
        XCTAssertEqual(try version(v3Mirror), 3)
        let oldBefore = try snapshot(defaultFolder).filter { $0.key.hasPrefix(old.lastPathComponent) }
        func modified(_ url: URL) throws -> TimeInterval {
            try XCTUnwrap(try FileManager.default.attributesOfItem(atPath: url.path)[.modificationDate] as? Date).timeIntervalSince1970
        }
        let v3Dates = [try modified(v3URL), try modified(v3Mirror)]
        let firstRecord = try XCTUnwrap(model.record)

        let new = "the new backup password 2026"
        do { try await model.changePassword(old: "not the backup password", new: new, confirm: new, relock: true); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), "That is not the current backup password.") }
        do { try await model.changePassword(old: Self.backupPassword, new: Self.master, confirm: Self.master, relock: true); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), BackupScheduleModel.sameText) }
        XCTAssertEqual(model.record, firstRecord)

        clockNow = clockNow.addingTimeInterval(3600)
        let text = try await model.changePassword(old: Self.backupPassword, new: new, confirm: new, relock: true)
        XCTAssertTrue(text.contains("Re-locked 2 backups"), text)
        XCTAssertTrue(text.contains("2 older backups were left as they are"), text)
        let record = try XCTUnwrap(model.record)
        XCTAssertEqual(record.setBy, "changed")
        XCTAssertEqual(record.history.first?.keyID, firstRecord.keyID)
        XCTAssertEqual(model.keySeen?.keyID, record.keyID)
        // The v3 files: same names and dates, open with the new password only, checksum files rewritten.
        for (url, date) in zip([v3URL, v3Mirror], v3Dates) {
            let data = try Data(contentsOf: url)
            XCTAssertNoThrow(try FullBackupV3.open(data, password: new))
            XCTAssertThrowsError(try FullBackupV3.open(data, password: Self.backupPassword))
            XCTAssertEqual(try modified(url), date, accuracy: 0.001)
        }
        XCTAssertNoThrow(try ChecksumManifest.verify(backup: v3URL, manifest: Data(contentsOf: ChecksumManifest.url(for: v3URL))))
        // The old-format files: every byte and date kept; the old password still opens them, the new one does not.
        XCTAssertEqual(try snapshot(defaultFolder).filter { $0.key.hasPrefix(old.lastPathComponent) }, oldBefore)
        for url in [old, oldMirror] {
            let data = try Data(contentsOf: url)
            XCTAssertNoThrow(try FullBackupV2.open(data, password: Self.backupPassword))
            XCTAssertThrowsError(try FullBackup.open(data, password: new))
        }
        _ = try await backup.verify(url: old, password: Self.backupPassword, vaultPassword: Self.master)
        for folder in [defaultFolder, mirrorDir] {
            let names = try FileManager.default.contentsOfDirectory(atPath: folder.path)
            XCTAssertEqual(names.filter { $0.hasSuffix(BackupKeyRelock.temporarySuffix) }, [])
        }
    }

    func testResetNeedsTheCurrentBoundPhrase() async throws {
        let model = makeModel()
        // No phrase when the password was set: no reset.
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        XCTAssertEqual(model.resetUnavailableReason, BackupScheduleModel.resetUnavailableText)
        let first = Data((0..<32).map { UInt8($0) })
        let firstPhrase = try BIP39.phrase(entropy: first)
        do { try await model.resetPassword(phrase: firstPhrase, new: "a reset backup password", confirm: "a reset backup password"); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), BackupScheduleModel.resetUnavailableText) }
        try await model.removeKey(proof: .password(Self.backupPassword))

        // Set with a phrase enrolled: the authority binds it.
        let salt = [UInt8](repeating: 3, count: 16)
        vault.recovery = RecoveryWrapper.VaultKey(salt: salt, key: try ResetAuthority.phraseKey(entropy: [UInt8](first), salt: salt))
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        XCTAssertNil(model.resetUnavailableReason)
        XCTAssertFalse(model.needsRebind)
        let other = Data((1...32).map { UInt8($0) })
        do { try await model.resetPassword(phrase: try BIP39.phrase(entropy: other), new: "a reset backup password", confirm: "a reset backup password"); XCTFail() }
        catch { XCTAssertTrue(BackupScheduleModel.describe(error).hasPrefix("This is not the recovery phrase that was active")) }
        clockNow = clockNow.addingTimeInterval(86_400)
        try await model.resetPassword(phrase: firstPhrase, new: "a reset backup password", confirm: "a reset backup password")
        let reset = try XCTUnwrap(model.record)
        XCTAssertEqual(reset.setBy, "reset")
        XCTAssertEqual(reset.resetAt, Int64(clockNow.timeIntervalSince1970))
        XCTAssertEqual(model.keyLine, BackupScheduleModel.keyResetText(BackupScheduleModel.day(reset.setAt, calendar)))
        XCTAssertTrue(reset.passwordMatches("a reset backup password"))

        // The phrase is replaced (the rotation re-seals the secret with the new phrase key): Q2 strict.
        var secret = try XCTUnwrap(model.secret())
        let newSalt = [UInt8](repeating: 5, count: 16)
        secret.recovery = RecoveryWrapper.VaultKey(salt: newSalt, key: try ResetAuthority.phraseKey(entropy: [UInt8](other), salt: newSalt))
        try XCTUnwrap(secrets).save(secret)
        model.recoveryPhraseChanged(removed: false)
        XCTAssertTrue(model.needsRebind)
        XCTAssertEqual(model.resetUnavailableReason, BackupScheduleModel.rebindNeededText)
        for phrase in [firstPhrase, try BIP39.phrase(entropy: other)] {   // replaced, and not bound yet
            do { try await model.resetPassword(phrase: phrase, new: "another reset password", confirm: "another reset password"); XCTFail() }
            catch { XCTAssertTrue(BackupScheduleModel.describe(error).hasPrefix("This is not the recovery phrase")) }
        }
        do { try await model.rebind(password: Self.backupPassword); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), "That is not the current backup password.") }
        try await model.rebind(password: "a reset backup password")
        XCTAssertFalse(model.needsRebind)
        XCTAssertEqual(model.record?.setAt, reset.setAt)   // a re-bind keeps the key and its date
        do { try await model.resetPassword(phrase: firstPhrase, new: "another reset password", confirm: "another reset password"); XCTFail() }
        catch { XCTAssertTrue(BackupScheduleModel.describe(error).hasPrefix("This is not the recovery phrase")) }
        try await model.resetPassword(phrase: try BIP39.phrase(entropy: other), new: "another reset password", confirm: "another reset password")
        XCTAssertEqual(model.record?.history.count, 2)
    }

    func testRemoveNeedsProofAndSetNeverReplacesAKey() async throws {
        let model = makeModel()
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        do { try await model.setPassword("another backup password", confirm: "another backup password", master: Self.master); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), BackupScheduleModel.alreadySetText) }
        do { try await model.removeKey(proof: .password("not the backup password")); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), BackupScheduleModel.removeRefusedText) }
        XCTAssertTrue(model.hasPassword)
        try await model.removeKey(proof: .password(Self.backupPassword))
        XCTAssertFalse(model.hasPassword)
        XCTAssertFalse(FileManager.default.fileExists(atPath: vaultDir.appendingPathComponent(ScheduleSecretStore.fileName).path))
    }

    func testTestABackup() async throws {
        let model = makeModel()
        model.frequency = "daily"
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let empty = try await model.testBackup(password: Self.backupPassword)
        XCTAssertEqual(empty, BackupScheduleModel.testNoBackupText)
        let now = at(0, 13)
        let live = try store()
        let backup = fullBackup(live) { now }
        let s = scheduler(model, clock: { now }, writer: { backup })
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        let opened = try await model.testBackup(password: Self.backupPassword)
        XCTAssertEqual(opened, BackupScheduleModel.testOKText)
        do { _ = try await model.testBackup(password: "not the backup password"); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), "That is not the current backup password.") }

        // L4: a correct password whose newest scheduled file is under an older key says so (no "wrong password").
        let newer = "the newer backup password 2026"
        clockNow = clockNow.addingTimeInterval(3600)
        try await model.changePassword(old: Self.backupPassword, new: newer, confirm: newer, relock: false)
        let older = try await model.testBackup(password: newer)
        XCTAssertEqual(older, BackupScheduleModel.testOlderKeyText)
    }

    // MARK: review fixes (M1, M2, 16c, L1, L5)

    private var secretFile: URL { vaultDir.appendingPathComponent(ScheduleSecretStore.fileName) }

    /// M1: a key rotation (or any other save) while an operation waits on Argon2 makes it save nothing.
    func testRotationDuringAKeyOperationSavesNothing() async throws {
        let random = HookRandom()
        let model = makeModel(random: random)
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let record = try XCTUnwrap(model.record)
        let newMaster = "a new master password 2026"
        let newKey = [UInt8](repeating: 7, count: 32)
        // Change: right after the proof (the new key pair's salt), the master password changes. The rotation re-seals
        // the file under a new local key with a new master password key, and the window reopens on a new store.
        random.arm { [unowned self] in
            var s = try! XCTUnwrap(try! self.secrets!.load())
            s.passwordKey = try! DesktopVaultFile.derivePasswordKey(password: newMaster, kdf: Self.cheap, random: SystemRandomSource())
            let rotated = ScheduleSecretStore(directory: self.vaultDir, localKey: newKey)
            try! rotated.save(s)
            self.secrets = rotated
        }
        do {
            try await model.changePassword(old: Self.backupPassword, new: "the new backup password 2026",
                                           confirm: "the new backup password 2026", relock: false)
            XCTFail("saved across a rotation")
        } catch {
            XCTAssertEqual(BackupScheduleModel.describe(error), BackupScheduleModel.changedMeanwhileText)
        }
        let after = try XCTUnwrap(try XCTUnwrap(secrets).load())
        XCTAssertEqual(after.backupKey, record)                    // the old record is still the one in the vault
        XCTAssertTrue(after.passwordKey.matches(newMaster))         // and the rotation's master password key stayed
        XCTAssertEqual(model.keySeen?.keyID, record.keyID)

        // Re-bind on the same store: the phrase is replaced meanwhile (the re-seal changes the bytes): nothing saved.
        let salt = [UInt8](repeating: 3, count: 16)
        let phraseKey = try ResetAuthority.phraseKey(entropy: [UInt8]((0..<32).map { UInt8($0) }), salt: salt)
        random.arm { [unowned self] in
            var s = try! XCTUnwrap(try! self.secrets!.load())
            s.recovery = RecoveryWrapper.VaultKey(salt: salt, key: phraseKey)
            try! self.secrets!.save(s)
        }
        do {
            try await model.changePassword(old: Self.backupPassword, new: "the new backup password 2026",
                                           confirm: "the new backup password 2026", relock: false)
            XCTFail("saved over a re-sealed file")
        } catch {
            XCTAssertEqual(BackupScheduleModel.describe(error), BackupScheduleModel.changedMeanwhileText)
        }
        let replaced = try XCTUnwrap(try XCTUnwrap(secrets).load())
        XCTAssertEqual(replaced.recovery?.key, phraseKey)            // the replaced phrase was not overwritten
        XCTAssertEqual(replaced.backupKey, record)
        // Nothing moved meanwhile: the same operation goes through.
        try await model.changePassword(old: Self.backupPassword, new: "the new backup password 2026",
                                       confirm: "the new backup password 2026", relock: false)
        XCTAssertEqual(model.record?.history.first?.keyID, record.keyID)
    }

    /// 16c, the attacker case: an older copy of the file comes back with its record and its (leaked) password. That
    /// password confirms, changes, removes, re-binds and sets nothing; the newest password seen here writes it back.
    func testRolledBackRecordAndItsPasswordCannotUnpause() async throws {
        let model = makeModel()
        model.frequency = "daily"
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let olderCopy = try Data(contentsOf: secretFile)
        let oldRecord = try XCTUnwrap(model.record)
        clockNow = clockNow.addingTimeInterval(86_400)
        let newest = "the new backup password 2026"
        try await model.changePassword(old: Self.backupPassword, new: newest, confirm: newest, relock: false)
        let newRecord = try XCTUnwrap(model.record)
        XCTAssertFalse(model.paused)
        try olderCopy.write(to: secretFile)
        model.recoveryPhraseChanged(removed: false)   // any refresh
        XCTAssertEqual(model.pause, .rolledBack(oldRecord))
        XCTAssertNotNil(model.pausedNotice)
        let now = at(0, 13)
        let backup = fullBackup(try store()) { now }
        let s = scheduler(model, clock: { now }, writer: { backup })
        XCTAssertFalse(s.tick(now: now))
        XCTAssertEqual(model.lastNotice, BackupScheduleModel.pausedSkippedText)

        func refused(_ body: () async throws -> Void, _ message: String) async {
            do { try await body(); XCTFail("accepted while paused") }
            catch { XCTAssertEqual(BackupScheduleModel.describe(error), message) }
        }
        await refused({ try await model.confirmKey(password: Self.backupPassword) }, "That is not the current backup password.")
        await refused({ _ = try await model.changePassword(old: Self.backupPassword, new: "an attacker password 1", confirm: "an attacker password 1",
                                                       relock: true) }, BackupScheduleModel.pausedRefusedText)
        await refused({ try await model.removeKey(proof: .password(Self.backupPassword)) }, BackupScheduleModel.pausedRefusedText)
        await refused({ try await model.rebind(password: Self.backupPassword) }, BackupScheduleModel.pausedRefusedText)
        await refused({ try await model.setPassword("an attacker password 1", confirm: "an attacker password 1", master: Self.master) },
                      BackupScheduleModel.alreadySetText)
        XCTAssertEqual(model.record, oldRecord)
        XCTAssertEqual(model.keySeen?.keyID, newRecord.keyID)
        XCTAssertTrue(model.paused)

        // The password of the record seen here writes it back into the vault; backups run again, to the new key.
        try await model.confirmKey(password: newest)
        XCTAssertEqual(model.record, newRecord)
        XCTAssertFalse(model.paused)
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        let url = defaultFolder.appendingPathComponent(try XCTUnwrap(owned(defaultFolder).first))
        guard case .v3(let info) = try FullBackup.inspect(try Data(contentsOf: url)) else { return XCTFail("not v3") }
        XCTAssertEqual(info.recipient.keyID, newRecord.keyID)
    }

    /// 16c: a v1 file (stored password) from before the migration comes back after a record was seen here: it is
    /// migrated (the password goes) but stays paused; its password removes nothing.
    func testOlderCopyWithAStoredPasswordStaysPaused() async throws {
        try writeLegacySecret()
        let legacyCopy = try Data(contentsOf: secretFile)
        let model = makeModel()
        _ = await model.migrateIfNeeded()
        clockNow = clockNow.addingTimeInterval(86_400)
        let newest = "the new backup password 2026"
        try await model.changePassword(old: Self.backupPassword, new: newest, confirm: newest, relock: false)
        let newRecord = try XCTUnwrap(model.record)
        try legacyCopy.write(to: secretFile)
        model.recoveryPhraseChanged(removed: false)
        XCTAssertEqual(model.keyState, .legacy)
        do { try await model.removeKey(proof: .password(Self.backupPassword)); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), BackupScheduleModel.pausedRefusedText) }
        let migrated = await model.migrateIfNeeded()
        XCTAssertTrue(migrated)
        XCTAssertNil(try XCTUnwrap(model.secret()).backupPassword)
        XCTAssertTrue(model.paused)
        XCTAssertEqual(model.pausedNotice,
                       BackupScheduleModel.olderCopyPausedText(seen: BackupScheduleModel.day(newRecord.setAt, calendar)))
        do { try await model.confirmKey(password: Self.backupPassword); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), "That is not the current backup password.") }
        try await model.confirmKey(password: newest)
        XCTAssertEqual(model.record, newRecord)
        XCTAssertFalse(model.paused)
    }

    /// M2 + 16c: a file that no longer opens (here a flipped byte) is damaged, not "not set": Set and Remove are
    /// refused; the seen record's password plus the master password, or a reset with the bound current phrase, go on.
    func testCorruptedFileCannotBeReplacedWithoutProof() async throws {
        let first = [UInt8]((0..<32).map { UInt8($0) })
        let salt = [UInt8](repeating: 3, count: 16)
        vault.recovery = RecoveryWrapper.VaultKey(salt: salt, key: try ResetAuthority.phraseKey(entropy: first, salt: salt))
        let model = makeModel()
        model.frequency = "daily"
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let record = try XCTUnwrap(model.record)
        var bytes = [UInt8](try Data(contentsOf: secretFile))
        bytes[bytes.count - 1] ^= 0x01
        try Data(bytes).write(to: secretFile)
        model.recoveryPhraseChanged(removed: false)
        XCTAssertEqual(model.keyState, .damaged(""))
        XCTAssertEqual(model.pause, .damaged)
        XCTAssertTrue(model.proofNeedsMaster)
        XCTAssertEqual(model.status.warning, BackupScheduleModel.pausedSkippedText)
        do { try await model.setPassword("an attacker password 1", confirm: "an attacker password 1", master: Self.master); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), BackupScheduleModel.pausedRefusedText) }
        do { try await model.removeKey(proof: .password("anything at all")); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), BackupScheduleModel.pausedRefusedText) }
        XCTAssertEqual(try Data(contentsOf: secretFile), Data(bytes))   // untouched
        // Proof (a) needs the master password too (the file's keys are rebuilt from it).
        do { try await model.confirmKey(password: Self.backupPassword); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), BackupScheduleModel.masterNeededText) }
        // Proof (b): a phrase that is not bound is refused; the bound current one resets the seen record.
        let other = try BIP39.phrase(entropy: Data((1...32).map { UInt8($0) }))
        do { try await model.resetPassword(phrase: other, new: "a reset backup password", confirm: "a reset backup password",
                                           master: Self.master); XCTFail() }
        catch { XCTAssertTrue(BackupScheduleModel.describe(error).hasPrefix("This is not the recovery phrase")) }
        try await model.resetPassword(phrase: try BIP39.phrase(entropy: Data(first)), new: "a reset backup password",
                                      confirm: "a reset backup password", master: Self.master)
        let reset = try XCTUnwrap(model.record)
        XCTAssertEqual(reset.setBy, "reset")
        XCTAssertEqual(reset.history.first?.keyID, record.keyID)
        XCTAssertFalse(model.paused)
        let secret = try XCTUnwrap(model.secret())
        XCTAssertTrue(secret.passwordKey.matches(Self.master))
        XCTAssertNotNil(secret.recovery)
    }

    /// 16c: a missing record after one was seen here: only its password (with the master password) writes it back.
    /// A device that never saw a record behaves as before (Set with the master password).
    func testMissingRecordNeedsTheSeenPassword() async throws {
        let model = makeModel()
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let record = try XCTUnwrap(model.record)
        try FileManager.default.removeItem(at: secretFile)
        model.recoveryPhraseChanged(removed: false)
        XCTAssertEqual(model.keyState, .none)
        XCTAssertEqual(model.pause, .missing)
        do { try await model.setPassword("an attacker password 1", confirm: "an attacker password 1", master: Self.master); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), BackupScheduleModel.pausedRefusedText) }
        do { try await model.confirmKey(password: "not the backup password", master: Self.master); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), "That is not the current backup password.") }
        do { try await model.confirmKey(password: Self.backupPassword, master: "not the master password"); XCTFail() }
        catch { XCTAssertEqual(BackupScheduleModel.describe(error), "That password isn't right.") }
        XCTAssertFalse(FileManager.default.fileExists(atPath: secretFile.path))
        try await model.confirmKey(password: Self.backupPassword, master: Self.master)
        XCTAssertEqual(model.record, record)
        XCTAssertFalse(model.paused)
        XCTAssertTrue(try XCTUnwrap(model.secret()).passwordKey.matches(Self.master))

        // Never seen on this device: a damaged file is replaced with the master password, as before.
        defaults.removeObject(forKey: BackupScheduleModel.seenRecordKey)
        try Data([1, 2, 3]).write(to: secretFile)
        model.recoveryPhraseChanged(removed: false)
        XCTAssertNil(model.pause)
        try await model.setPassword("a fresh backup password", confirm: "a fresh backup password", master: Self.master)
        XCTAssertEqual(model.record?.setBy, "set")
    }

    /// A master password change to the backup password drops the record (`MacVault`): proving it never writes it
    /// back; the Mac starts over and Set asks for a different password.
    func testRecordDroppedForTheMasterPasswordIsNotWrittenBack() async throws {
        let model = makeModel()
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        try FileManager.default.removeItem(at: secretFile)   // what the rotation does
        vault.right = Self.backupPassword
        model.recoveryPhraseChanged(removed: false)
        XCTAssertEqual(model.pause, .missing)
        try await model.confirmKey(password: Self.backupPassword, master: Self.backupPassword)
        XCTAssertEqual(model.lastNotice, BackupScheduleModel.sameText)
        XCTAssertFalse(FileManager.default.fileExists(atPath: secretFile.path))
        XCTAssertNil(model.pause)
        try await model.setPassword("a different backup password", confirm: "a different backup password", master: Self.backupPassword)
        XCTAssertEqual(model.record?.setBy, "set")
    }

    /// M2: a file that can't be read (an I/O error) refuses every key operation and is never shown as "not set".
    func testUnreadableFileRefusesEveryOperation() async throws {
        let model = makeModel()
        model.frequency = "daily"
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let before = try Data(contentsOf: secretFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: secretFile.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: secretFile.path) }
        model.recoveryPhraseChanged(removed: false)
        XCTAssertEqual(model.keyState, .unreadable)
        XCTAssertEqual(model.keyLine, BackupScheduleModel.unreadableText)
        XCTAssertEqual(model.status.warning, BackupScheduleModel.unreadableText)
        let unreadable = BackupScheduleModel.unreadableText
        for body in [
            { try await model.setPassword("another backup password", confirm: "another backup password", master: Self.master) },
            { try await model.removeKey(proof: .password(Self.backupPassword)) },
            { _ = try await model.changePassword(old: Self.backupPassword, new: "another backup password", confirm: "another backup password",
                                                 relock: false) },
            { try await model.rebind(password: Self.backupPassword) },
            { try await model.confirmKey(password: Self.backupPassword, master: Self.master) },
        ] as [() async throws -> Void] {
            do { try await body(); XCTFail("accepted an unreadable file") }
            catch { XCTAssertEqual(BackupScheduleModel.describe(error), unreadable) }
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: secretFile.path)
        XCTAssertEqual(try Data(contentsOf: secretFile), before)
    }

    /// L1: a re-locked file never keeps a checksum file that no longer matches; without a new one it still restores.
    func testRelockNeverLeavesAStaleChecksumFile() async throws {
        let model = makeModel()
        model.frequency = "daily"
        try await model.setPassword(Self.backupPassword, confirm: Self.backupPassword, master: Self.master)
        let now = at(0, 13)
        let backup = fullBackup(try store()) { now }
        let s = scheduler(model, clock: { now }, writer: { backup })
        XCTAssertTrue(s.tick(now: now))
        await s.settled()
        let url = defaultFolder.appendingPathComponent(try XCTUnwrap(owned(defaultFolder).first))
        let manifest = ChecksumManifest.url(for: url)
        // A checksum file the re-lock can't rewrite (not JSON): it is moved out of the way, not left stale.
        try Data("not json".utf8).write(to: manifest)
        let new = "the new backup password 2026"
        let text = try await model.changePassword(old: Self.backupPassword, new: new, confirm: new, relock: true)
        XCTAssertTrue(text.contains("Re-locked 1 backup to the new backup password."), text)
        XCTAssertFalse(FileManager.default.fileExists(atPath: manifest.path))
        let inventory = try await backup.verify(url: url, password: new, vaultPassword: Self.master)
        XCTAssertEqual(inventory.version, 3)
    }

    /// L5: a newest scheduled file whose header does not parse is not the one protected after the migration.
    func testMigrationNeverProtectsABrokenFile() async throws {
        let backup = fullBackup(try store()) { [unowned self] in self.at(-3, 12) }
        let old = try await oldFormatBackup(backup, at: at(-3, 12), in: defaultFolder)
        let broken = defaultFolder.appendingPathComponent(try BackupSchedule.scheduledFilename(tag: BackupScheduleModel.profileTag,
                                                                                               when: at(-1, 12), calendar: calendar))
        try Data("partial".utf8).write(to: broken)
        try writeLegacySecret()
        let model = makeModel()
        let s = scheduler(model, clock: { [unowned self] in self.at(0, 13) }, writer: { nil })   // sets the default folder
        let migrated = await model.migrateIfNeeded()
        XCTAssertTrue(migrated)
        XCTAssertEqual(model.protectedOld, [old.lastPathComponent])
        _ = s
    }

    func testRestoreTellsWhichBackupPassword() throws {
        let calendar = self.calendar
        let v3 = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("tests/vectors/backup/v3", isDirectory: true)
        let records = try CanonicalJSON.parse(Array(Data(contentsOf: v3.appendingPathComponent("record.json"))))
        guard case .object(let o) = records, case .object(let named)? = o["records"] else { return XCTFail() }
        func record(_ name: String) throws -> BackupKeyRecord {
            guard case .object(let e)? = named[name], let r = e["record"] else { throw XCTSkip(name) }
            return try BackupKeyRecord(validating: r)
        }
        let set = try record("set"), changed = try record("changed"), reset = try record("reset")
        func recipient(_ r: BackupKeyRecord) -> FullBackupV3.Recipient {
            FullBackupV3.Recipient(keyID: r.keyID, keySetAt: r.setAt, kdf: r.kdf, ephemeralPublicKey: [UInt8](repeating: 9, count: 32),
                                   wrapped: [UInt8](repeating: 1, count: 48))
        }
        func day(_ s: Int64) -> String { BackupScheduleModel.day(s, calendar) }
        let also = " " + RecoveryCentreModel.masterAlsoText
        XCTAssertEqual(RecoveryCentreModel.keyText(recipient: recipient(changed), oldFormatDate: nil, record: changed, calendar: calendar),
                       "This backup uses your current backup password (set on \(day(changed.setAt)))." + also)
        XCTAssertEqual(RecoveryCentreModel.keyText(recipient: recipient(set), oldFormatDate: nil, record: changed, calendar: calendar),
                       "This backup uses the backup password set on \(day(set.setAt)). It was changed on \(day(changed.setAt))." + also)
        XCTAssertEqual(RecoveryCentreModel.keyText(recipient: recipient(changed), oldFormatDate: nil, record: reset, calendar: calendar),
                       "This backup uses the backup password set on \(day(changed.setAt)). It was reset on \(day(reset.setAt)); the new password does not open it." + also)
        XCTAssertEqual(RecoveryCentreModel.keyText(recipient: recipient(set), oldFormatDate: nil, record: nil, calendar: calendar),
                       "This backup uses the backup password set on \(day(set.setAt)) on the device that made it." + also)
        let name = try BackupSchedule.scheduledFilename(tag: "0123abcd", when: at(-5, 9), calendar: calendar)
        let date = try XCTUnwrap(RecoveryCentreModel.scheduledDate(name, calendar: calendar))
        XCTAssertEqual(date, at(-5, 9))
        XCTAssertEqual(RecoveryCentreModel.keyText(recipient: nil, oldFormatDate: date, record: set, calendar: calendar),
                       "This backup uses the backup password that was in use when it was made (\(day(Int64(date.timeIntervalSince1970))))." + also)
        XCTAssertNil(RecoveryCentreModel.scheduledDate("LocalGateKeys-backup-2026-10-01-120000.lgk", calendar: calendar))
    }
}
