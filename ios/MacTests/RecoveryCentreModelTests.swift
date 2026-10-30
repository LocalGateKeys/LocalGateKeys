import XCTest
import LGKCore
@testable import AppSharedMac

/// The Recovery centre's status (last backup, last check, recovery phrase, schedule, warnings), the old-backup
/// cleanup (Windows `plan_backup_rotation` / `cleanup_recovery_artifacts`, keep 3) and its copy.
@MainActor
final class RecoveryCentreModelTests: XCTestCase {
    private var dir: URL!
    private var suite: String!
    private var defaults: UserDefaults!
    private var now = Date(timeIntervalSince1970: 1_800_000_000)
    private var phrase = false

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-recovery-centre-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        suite = "lgk-recovery-centre-tests-\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)!
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
        UserDefaults().removePersistentDomain(forName: suite)
    }

    private func model() -> RecoveryCentreModel {
        RecoveryCentreModel(backup: nil, passwords: nil, history: BackupHistory(defaults: defaults),
                            hasPhrase: { [unowned self] in self.phrase }, now: { [unowned self] in self.now })
    }

    func testStatusNoBackupWarns() {
        let m = model()
        let status = m.status
        XCTAssertNil(status.lastBackup)
        XCTAssertNil(status.lastVerified)
        XCTAssertTrue(status.stale)
        XCTAssertEqual(status.warnings.first, RecoveryCentreModel.noBackupWarning)
        XCTAssertEqual(RecoveryCentreModel.overviewText(status, now: now), "No backup yet")
        let row = SecurityModel.backupPanel(status, now: now).rows[0]
        XCTAssertEqual(row.label, "Last backup")
        XCTAssertEqual(row.meta, "No backup yet")
        XCTAssertEqual(row.tone, .warning)
        XCTAssertEqual(row.buttonLabel, "Back up now")
        XCTAssertEqual(row.action, .recoveryCentre(nil))
    }

    func testStaleBackupAfterSevenDays() {
        XCTAssertEqual(RecoveryCentreModel.staleSeconds, 7 * 86_400, "Windows STALE_BACKUP_SECONDS")
        let history = BackupHistory(defaults: defaults)
        history.lastBackup = now.addingTimeInterval(-7 * 86_400)
        var status = model().status
        XCTAssertFalse(status.stale, "exactly 7 days is not stale yet (Windows uses >)")
        XCTAssertFalse(status.warnings.contains(RecoveryCentreModel.staleWarning))
        XCTAssertEqual(RecoveryCentreModel.overviewText(status, now: now), "Last backup 7 d ago")
        XCTAssertEqual(SecurityModel.backupPanel(status, now: now).rows[0].tone, .neutral)

        history.lastBackup = now.addingTimeInterval(-7 * 86_400 - 1)
        status = model().status
        XCTAssertTrue(status.stale)
        XCTAssertTrue(status.warnings.contains(RecoveryCentreModel.staleWarning))
        let row = SecurityModel.backupPanel(status, now: now).rows[0]
        XCTAssertEqual(row.meta, "7 days ago")
        XCTAssertEqual(row.tone, .warning)

        history.lastBackup = now.addingTimeInterval(-90 * 60)
        status = model().status
        XCTAssertEqual(RecoveryCentreModel.overviewText(status, now: now), "Last backup 1 h ago")
        XCTAssertEqual(SecurityModel.backupPanel(status, now: now).rows[0].meta, "1 hour ago")
    }

    func testPhraseStatusShown() {
        phrase = false
        var m = model()
        XCTAssertFalse(m.status.phraseEnrolled)
        XCTAssertEqual(m.phraseText, "Not set")
        XCTAssertEqual(m.phraseButtons, ["Create…"])
        XCTAssertTrue(m.status.warnings.contains(RecoveryCentreModel.noPhraseWarning))
        var row = SecurityModel.recoveryPhraseRow(enrolled: false)
        XCTAssertEqual(row.meta, "Not set")
        XCTAssertEqual(row.buttonLabel, "Set up")
        XCTAssertEqual(row.tone, .warning)

        phrase = true
        m = model()
        XCTAssertTrue(m.status.phraseEnrolled)
        XCTAssertEqual(m.phraseText, "Set · unlocks if you forget the master password")
        XCTAssertEqual(m.phraseButtons, ["Replace…", "Remove…"])
        XCTAssertFalse(m.status.warnings.contains(RecoveryCentreModel.noPhraseWarning))
        row = SecurityModel.recoveryPhraseRow(enrolled: true)
        XCTAssertEqual(row.buttonLabel, "Manage")
        XCTAssertEqual(row.tone, .neutral)
    }

    func testCleanupNeedsConfirmation() throws {
        let fm = FileManager.default
        // Five backups, oldest first, each with its checksum file; one orphan checksum; one unrelated file.
        for i in 0..<5 {
            let url = dir.appendingPathComponent("LocalGateKeys-backup-\(i).lgk")
            try Data("backup \(i)".utf8).write(to: url)
            try Data("{}".utf8).write(to: ChecksumManifest.url(for: url))
            try fm.setAttributes([.modificationDate: now.addingTimeInterval(TimeInterval(i * 60))], ofItemAtPath: url.path)
        }
        try Data("{}".utf8).write(to: dir.appendingPathComponent("gone.lgk.sha256.json"))
        try Data("notes".utf8).write(to: dir.appendingPathComponent("notes.txt"))

        let m = model()
        m.planCleanup(folder: dir)
        let plan = try XCTUnwrap(m.pendingCleanup, "a cleanup that removes files asks first")
        XCTAssertEqual(plan.keep, 3)
        XCTAssertEqual(plan.retained, ["LocalGateKeys-backup-4.lgk", "LocalGateKeys-backup-3.lgk", "LocalGateKeys-backup-2.lgk"])
        XCTAssertEqual(plan.remove, ["LocalGateKeys-backup-1.lgk", "LocalGateKeys-backup-0.lgk"])
        XCTAssertEqual(plan.orphanManifests, ["gone.lgk.sha256.json"])
        XCTAssertTrue(plan.requiresConfirmation)
        XCTAssertEqual(RecoveryCentreModel.cleanupQuestion(plan),
                       "2 older backups and 1 checksum file without its backup will be deleted from this folder. The newest 3 backups are kept.")
        // Nothing is deleted by planning, or by cancelling.
        XCTAssertEqual(try fm.contentsOfDirectory(atPath: dir.path).count, 12)
        m.cancelCleanup()
        XCTAssertNil(m.pendingCleanup)
        XCTAssertEqual(try fm.contentsOfDirectory(atPath: dir.path).count, 12)

        m.planCleanup(folder: dir)
        m.confirmCleanup(try XCTUnwrap(m.pendingCleanup))
        // The removed backups' own checksum files go with them (Windows leaves them for the next cleanup).
        XCTAssertEqual(Set(try fm.contentsOfDirectory(atPath: dir.path)), [
            "LocalGateKeys-backup-4.lgk", "LocalGateKeys-backup-3.lgk", "LocalGateKeys-backup-2.lgk",
            "LocalGateKeys-backup-4.lgk.sha256.json", "LocalGateKeys-backup-3.lgk.sha256.json",
            "LocalGateKeys-backup-2.lgk.sha256.json", "notes.txt"])
        XCTAssertNil(m.pendingCleanup)
        XCTAssertEqual(m.message, "Deleted 2 older backups and 1 checksum file. The newest 3 backups are kept.")

        // With nothing to remove there is no question, only a note.
        m.planCleanup(folder: dir)
        XCTAssertNil(m.pendingCleanup)
        XCTAssertEqual(m.message, "Nothing to clean up. The newest 3 backups are kept.")
    }

    func testCopySaysThisMac() {
        for text in RecoveryCentreModel.copy {
            XCTAssertFalse(text.contains("PC"), text)
            XCTAssertFalse(text.contains("this computer"), text)
            XCTAssertFalse(text.contains("Windows Hello"), text)
        }
        XCTAssertTrue(RecoveryCentreModel.intro.contains("this Mac"))
        XCTAssertTrue(RecoveryCentreModel.safetyText.contains("this Mac"))
    }

    /// The gate only queues the request: the result is reported once, after approval, and is this restore's own.
    func testRestoreFinishesOnceAfterApproval() async throws {
        let vaultDir = dir.appendingPathComponent("vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDir, withIntermediateDirectories: true)
        let key = (0..<32).map { UInt8($0 &* 7 &+ 1) }
        let store = try LocalStore.open(directory: vaultDir, vault: MemoryKeyVault(localKey: key, base: InMemoryKeychainVault()),
                                        limitHints: nil)
        let passwords = CentreFakeVault("fixture master password 2026")
        let gate = StrictItemGate(passwords: passwords)
        let backup = MacFullBackup(store: store, profile: DesktopProfileStore(directory: vaultDir, localKey: key),
                                   passwords: passwords, gate: gate, local: nil)
        let m = RecoveryCentreModel(backup: backup, passwords: passwords, history: BackupHistory(defaults: defaults),
                                    hasPhrase: { false }, now: { [unowned self] in self.now })
        let missing = dir.appendingPathComponent("missing.lgk")
        let copy = MacFullBackup.SafetyCopy(folder: dir.appendingPathComponent("before-restore-1"), createdAtMillis: 1)

        for run in 1...2 {
            if run == 1 {
                m.approveRestore(.init(url: missing, password: "backup password 1", vaultPassword: "x",
                                       preview: try XCTUnwrap(Self.preview)))
                m.startApprovedRestore()
            } else {
                m.putBack(copy)
            }
            XCTAssertNotNil(gate.pending)
            XCTAssertEqual(m.finishedRestores.count, run - 1, "nothing reported before approval")
            await gate.submit("fixture master password 2026")
            _ = await backup.restoreTask?.value
            await Task.yield()
            XCTAssertEqual(m.finishedRestores, Array(repeating: false, count: run), "once, with this restore's result")
            XCTAssertNotNil(m.error)
        }
    }

    private static let preview: RestorePreview? = RestorePreview(
        profileName: "p", createdAt: nil, logins: 0, otherItems: 0, keptOnly: 0, attachments: 0,
        recoveryPhraseEnrolled: false, currentItems: 0, added: 0, replaced: 0, unchanged: 0, removed: 0,
        backupIsNewer: nil, syncs: false)

    /// A new vault starts with no backup dates.
    func testHistoryClearedForNewVault() {
        let history = BackupHistory(defaults: defaults)
        history.lastBackup = now
        history.lastVerified = now
        history.reset()
        XCTAssertNil(history.lastBackup)
        XCTAssertNil(history.lastVerified)
    }
}

@MainActor
private final class CentreFakeVault: MasterPasswordService {
    let right: String
    init(_ right: String) { self.right = right }
    var hasVault = true
    var isUnlocked = true
    var touchIDAvailable = false
    func verifyPassword(_ password: String) async throws {
        guard password == right else { throw MacVaultError.wrongPassword(retryAfter: nil) }
    }
    func changePassword(old: String, new: String) async throws {}
    func setTouchID(_ on: Bool, password: String) async throws {}
}
