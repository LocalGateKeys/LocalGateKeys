import Foundation
import AppKit
import os
import LGKCore
import AppSharedMac

/// Writes one scheduled backup (the live one is `MacFullBackup`): staging name, full check, rename, `.sha256.json`.
@MainActor
protocol ScheduledBackupWriting: AnyObject {
    func createScheduled(to url: URL, backupPassword: String, passwordKey: DesktopVaultFile.PasswordKey,
                         recovery: RecoveryWrapper.VaultKey?) async throws -> BackupInventory
}

extension MacFullBackup: ScheduledBackupWriting {}

/// Runs scheduled backups (Windows `app/schedule.py` `ScheduleRunner`, `backup_schedule.run_scheduled_backup`).
///
/// There is no background agent (Ruling 8): `tick` runs at unlock, on `NSWorkspace.didWakeNotification` and every 15
/// minutes while unlocked, and a slot missed while the Mac slept or the app was closed runs at the next check (Windows
/// `is_due` catch-up). Nothing is checked while locked: the timer and wake observer stop at lock and are armed again at unlock (there is no key then). One run:
///
/// 1. the folder (bookmark, else `Backups` on this Mac) gets `Scheduled/`; a bookmark that no longer resolves stops
///    here with "Choose the backup folder again" — a backup is never silently redirected;
/// 2. inside the vault's lock (no key rotation, password attempt or restore meanwhile), `MacFullBackup.createScheduled`
///    writes to a staging name, checks every member and the vault layer, renames it and writes `.sha256.json`;
/// 3. only then are older scheduled backups of this vault pruned (`keep`), the state file and `BackupHistory` record
///    the success;
/// 4. with a mirror folder, the finished file is copied there (temporary name, SHA-256 compared, renamed) and the
///    mirror pruned; a mirror problem never undoes the local backup.
///
/// A failure keeps every older file, shows the Windows message and is retried after 30 minutes.
@MainActor
final class MacBackupScheduler {
    static let intervalSeconds: TimeInterval = 15 * 60
    /// Runs the body inside the vault's lock and hands back its result (the written file).
    typealias Exclusive = @MainActor (_ body: @MainActor () async throws -> URL) async throws -> URL

    private static let log = Logger(subsystem: "app.localgatekeys.mac", category: "scheduled-backup")

    let model: BackupScheduleModel
    private let history: BackupHistory
    private let isUnlocked: @MainActor () -> Bool
    private let makeWriter: @MainActor () -> (any ScheduledBackupWriting)?
    private let exclusive: Exclusive
    /// The vault's `Backups` folder (used when no folder was chosen).
    private let defaultFolder: @MainActor () -> URL?
    private let now: () -> Date
    private let calendar: Calendar
    private var timer: Timer?
    private var wakeObserver: NSObjectProtocol?
    private var runTask: Task<Void, Never>?
    private var failedAt: Date?
    /// Whether `arm` may start the 15-minute timer and the wake observer (tests turn them off).
    private let useTimer: Bool
    private let useWake: Bool
    #if DEBUG
    /// Runs started (tests and diagnostics).
    private(set) var started = 0
    /// The 15-minute timer is scheduled (tests).
    var timerArmed: Bool { timer != nil }
    /// The wake observer is registered (tests).
    var wakeArmed: Bool { wakeObserver != nil }
    #endif

    /// The production scheduler: the 15-minute timer and the wake observer are armed at unlock and stopped at lock.
    convenience init(model: BackupScheduleModel, history: BackupHistory = BackupHistory(), isUnlocked: @escaping @MainActor () -> Bool,
                     makeWriter: @escaping @MainActor () -> (any ScheduledBackupWriting)?, exclusive: @escaping Exclusive,
                     defaultFolder: @escaping @MainActor () -> URL?) {
        self.init(model: model, history: history, isUnlocked: isUnlocked, makeWriter: makeWriter, exclusive: exclusive,
                  defaultFolder: defaultFolder, seamNow: Date.init, seamCalendar: .current, startTimer: true, observeWake: true)
    }

    #if DEBUG
    /// Tests: a fixed clock and calendar, and the timer and wake observer optional.
    convenience init(model: BackupScheduleModel, history: BackupHistory = BackupHistory(), isUnlocked: @escaping @MainActor () -> Bool,
                     makeWriter: @escaping @MainActor () -> (any ScheduledBackupWriting)?, exclusive: @escaping Exclusive,
                     defaultFolder: @escaping @MainActor () -> URL?, now: @escaping () -> Date, calendar: Calendar,
                     startTimer: Bool, observeWake: Bool) {
        self.init(model: model, history: history, isUnlocked: isUnlocked, makeWriter: makeWriter, exclusive: exclusive,
                  defaultFolder: defaultFolder, seamNow: now, seamCalendar: calendar, startTimer: startTimer, observeWake: observeWake)
    }
    #endif

    private init(model: BackupScheduleModel, history: BackupHistory, isUnlocked: @escaping @MainActor () -> Bool,
                 makeWriter: @escaping @MainActor () -> (any ScheduledBackupWriting)?, exclusive: @escaping Exclusive,
                 defaultFolder: @escaping @MainActor () -> URL?, seamNow now: @escaping () -> Date, seamCalendar calendar: Calendar,
                 startTimer: Bool, observeWake: Bool) {
        self.model = model; self.history = history; self.isUnlocked = isUnlocked; self.makeWriter = makeWriter
        self.exclusive = exclusive; self.defaultFolder = defaultFolder; self.now = now; self.calendar = calendar
        self.useTimer = startTimer; self.useWake = observeWake
        model.isUnlocked = isUnlocked
        if isUnlocked() { arm() }
        refreshLastSuccess()
    }

    isolated deinit { disarm() }

    /// Starts the 15-minute timer and the wake observer; a second call adds nothing.
    func arm() {
        if useTimer, timer == nil {
            let t = Timer(timeInterval: Self.intervalSeconds, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated { guard let self else { return }; self.tick(now: self.now()) }
            }
            RunLoop.main.add(t, forMode: .common)
            timer = t
        }
        if useWake, wakeObserver == nil {
            wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didWakeNotification, object: nil,
                                                                             queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { guard let self else { return }; self.woke(now: self.now()) }
            }
        }
    }

    /// Stops the timer and the wake observer (at lock). A run already started still finishes (Task 9 ruling).
    func disarm() {
        timer?.invalidate()
        timer = nil
        if let wakeObserver { NSWorkspace.shared.notificationCenter.removeObserver(wakeObserver) }
        wakeObserver = nil
    }

    /// The vault locked: nothing more is checked until the next unlock.
    func locked() { disarm() }

    /// The live scheduler over the lock model: a `MacFullBackup` over `lock.store` per run, the vault's lock as the
    /// exclusive section, and the hooks for unlock and master password or phrase changes.
    static func live(lock: MacLockModel, model: BackupScheduleModel) -> MacBackupScheduler {
        let scheduler = MacBackupScheduler(
            model: model, isUnlocked: { [weak lock] in lock?.state == .unlocked },
            makeWriter: { [weak lock] in
                guard let lock, lock.state == .unlocked, let store = lock.store, let profile = lock.desktopProfile else { return nil }
                return MacFullBackup(store: store, profile: profile, passwords: lock, gate: StrictItemGate(passwords: lock), local: lock,
                                     attachmentFolder: AttachmentFiles.localFolder())
            },
            exclusive: { [weak lock] body in
                guard let lock else { throw CancellationError() }
                return try await lock.withoutRotation(body)
            },
            defaultFolder: { [weak lock] in lock.map { MacFullBackup.backupsFolder($0.vaultDirectory) } })
        lock.onLock.append { [weak scheduler] in scheduler?.locked() }
        lock.onUnlock.append { [weak scheduler] in
            guard let scheduler else { return }
            scheduler.arm()
            // Just after the window is up (Windows: 3 s after unlock).
            Task { @MainActor in try? await Task.sleep(nanoseconds: 3_000_000_000); scheduler.unlocked(now: scheduler.now()) }
        }
        lock.onRecoveryPhraseChange.append { [weak model] removed in model?.recoveryPhraseChanged(removed: removed) }
        return scheduler
    }

    // MARK: triggers

    @discardableResult func unlocked(now: Date) -> Bool { arm(); refreshLastSuccess(); return tick(now: now) }
    @discardableResult func woke(now: Date) -> Bool { tick(now: now) }

    /// Starts a run when one is due; true when it started.
    @discardableResult
    func tick(now: Date) -> Bool {
        let model = self.model
        guard isUnlocked(), model.frequency != "off", runTask == nil, model.keychain != nil else { return false }
        let base: URL
        do {
            guard let chosen = try model.resolveFolder() ?? defaultFolder() else { return false }
            base = chosen
        } catch { return false }   // "Choose the backup folder again"
        let directory = base.appendingPathComponent(BackupSchedule.scheduledDirName, isDirectory: true)
        let last = withScope(base) { BackupSchedule.readLastSuccess(directory) }
        model.noteLastSuccess(last)
        guard BackupSchedule.isDue(now: now, lastSuccess: last, frequency: model.frequency, time: model.time,
                                   weekday: model.weekday, calendar: calendar) else { return false }
        // If the clock goes backwards after a failure, the interval is negative and the retry stays blocked until the
        // clock passes failedAt + 30 minutes again (Python `ScheduleRunner` behaves the same).
        if let failedAt, now.timeIntervalSince(failedAt) < BackupSchedule.retryAfter { return false }
        guard model.hasPassword, var secret = model.secret() else {
            if !model.skipWarned { model.skipWarned = true; model.lastNotice = BackupScheduleModel.skippedText }
            return false
        }
        guard let writer = makeWriter() else { secret.wipe(); return false }
        #if DEBUG
        started += 1
        #endif
        let (keep, mirror) = (model.keep, model.mirror == nil ? nil : model.resolveMirror())
        let hadMirror = model.mirror != nil
        let taken = secret
        secret.wipe()
        runTask = Task { [weak self] in
            var secret = taken
            defer { secret.wipe() }
            await self?.run(writer: writer, secret: secret, base: base, directory: directory, keep: keep, when: now,
                            mirror: mirror, hadMirror: hadMirror)
            self?.runTask = nil
        }
        return true
    }

    #if DEBUG
    /// Waits for the run in flight (tests).
    func settled() async { await runTask?.value }
    #endif

    private func refreshLastSuccess() {
        guard let base = (try? model.resolveFolder()) ?? defaultFolder() else { return }
        let directory = base.appendingPathComponent(BackupSchedule.scheduledDirName, isDirectory: true)
        model.noteLastSuccess(withScope(base) { BackupSchedule.readLastSuccess(directory) })
    }

    private func withScope<T>(_ url: URL, _ body: () throws -> T) rethrows -> T {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        return try body()
    }

    // MARK: one run

    private func run(writer: any ScheduledBackupWriting, secret: ScheduledBackupSecret, base: URL, directory: URL, keep: Int,
                     when: Date, mirror: URL?, hadMirror: Bool) async {
        let scoped = base.startAccessingSecurityScopedResource()
        defer { if scoped { base.stopAccessingSecurityScopedResource() } }
        let destination: URL
        do {
            destination = try await exclusive {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                let target = try BackupSchedule.uniqueDestination(in: directory, tag: BackupScheduleModel.profileTag, when: when,
                                                                  calendar: self.calendar)
                // A failed `.sha256.json` write throws here: the renamed .lgk is verified but has no manifest, and since
                // this counts as a failure nothing is pruned below, so every older backup stays.
                _ = try await writer.createScheduled(to: target, backupPassword: secret.backupPassword,
                                                     passwordKey: secret.passwordKey, recovery: secret.recovery)
                return target
            }
        } catch MacVaultError.busy {
            // A password attempt, key rotation or restore holds the vault: not a failure, the next check tries again.
            return
        } catch let e as RecoveryError where e.message == MacFullBackup.busyMessage {
            return
        } catch {
            Self.log.error("Scheduled backup failed: \(String(describing: type(of: error)), privacy: .public)")
            failedAt = now()
            model.runWarning = BackupScheduleModel.failedText
            model.lastNotice = BackupScheduleModel.failedText
            return
        }
        failedAt = nil
        BackupSchedule.prune(in: directory, tag: BackupScheduleModel.profileTag, keep: keep, protect: destination)
        do { try BackupSchedule.writeLastSuccess(directory, when) } catch {
            Self.log.error("Scheduled backup state not saved: \(String(describing: type(of: error)), privacy: .public)")
        }
        history.lastBackup = when
        history.lastVerified = when
        model.noteLastSuccess(when)
        model.runWarning = nil
        guard hadMirror else { model.lastNotice = BackupScheduleModel.savedText; return }
        do {
            guard isUnlocked() else { return }   // locked meanwhile: nothing more runs
            guard let mirror else { throw RecoveryError(BackupScheduleModel.chooseMirrorAgainText) }
            try Self.mirror(destination, to: mirror, keep: keep)
            model.lastNotice = BackupScheduleModel.mirroredText
        } catch {
            Self.log.error("Mirror copy failed: \(String(describing: type(of: error)), privacy: .public)")
            let reason = (error as? RecoveryError)?.message ?? String(localized: "Could not copy the backup to the mirror folder")
            model.runWarning = String(localized: "Scheduled backup saved. Mirror copy failed: \(reason)")
            model.lastNotice = model.runWarning
        }
    }

    /// Windows `mirror_backup`: only a scheduled backup of this vault; never into a missing root or the local folder;
    /// temporary name, SHA-256 compared with the source, renamed, then the mirror pruned.
    nonisolated static func mirror(_ source: URL, to mirror: URL, keep: Int) throws {
        let tag = BackupScheduleModel.profileTag
        guard BackupSchedule.parse(source.lastPathComponent, tag: tag) != nil else {
            throw RecoveryError(String(localized: "Only scheduled LocalGateKeys backups are mirrored"))
        }
        let scoped = mirror.startAccessingSecurityScopedResource()
        defer { if scoped { mirror.stopAccessingSecurityScopedResource() } }
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: mirror.path, isDirectory: &isDir), isDir.boolValue else {
            throw RecoveryError(BackupScheduleModel.chooseMirrorAgainText)
        }
        guard mirror.resolvingSymlinksInPath().standardizedFileURL != source.deletingLastPathComponent().resolvingSymlinksInPath().standardizedFileURL else {
            throw RecoveryError(String(localized: "The mirror folder must be different from the local backup folder"))
        }
        let temporary = mirror.appendingPathComponent(".lgk-mirror-\(UUID().uuidString).tmp")
        defer { try? FileManager.default.removeItem(at: temporary) }
        do {
            try FileManager.default.copyItem(at: source, to: temporary)
            guard try ChecksumManifest.sha256(of: temporary) == ChecksumManifest.sha256(of: source) else {
                throw RecoveryError(String(localized: "The mirror copy did not match the backup"))
            }
            let destination = mirror.appendingPathComponent(source.lastPathComponent)
            if FileManager.default.fileExists(atPath: destination.path) {
                _ = try FileManager.default.replaceItemAt(destination, withItemAt: temporary)
            } else {
                try FileManager.default.moveItem(at: temporary, to: destination)
            }
            BackupSchedule.prune(in: mirror, tag: tag, keep: keep, protect: destination)
        } catch let e as RecoveryError {
            throw e
        } catch {
            throw RecoveryError(String(localized: "Could not copy the backup to the mirror folder"))
        }
    }
}
