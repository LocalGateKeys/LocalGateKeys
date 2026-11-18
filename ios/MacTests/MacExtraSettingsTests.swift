import XCTest
import AppKit
import Carbon.HIToolbox
import StoreKitTest
import LGKCore
@testable import AppSharedMac

/// The Windows settings added to the Mac on 2026-11-14 (MacExtraSettings, MacTOTPConfirm, MacDocumentOpen,
/// MacAutomaticBackups, HotKeyCombo).
@MainActor
final class MacExtraSettingsTests: XCTestCase {
    private var suite: String!
    private var defaults: UserDefaults!
    private var settings: AppSettings!
    private var dir: URL!

    override func setUp() async throws {
        suite = "lgk-extra-settings-tests-\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)!
        settings = AppSettings(defaults: defaults)
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-extra-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() async throws {
        UserDefaults().removePersistentDomain(forName: suite)
        try? FileManager.default.removeItem(at: dir)
    }

    private func model() -> MacSettingsModel {
        MacSettingsModel(settings: settings, pro: ProModel(purchases: StoreKitPurchases(), licenseKeys: [:]), passwords: nil)
    }

    // MARK: idle source

    func testIdleSourceDefaultsToComputerAndPersists() {
        XCTAssertEqual(MacExtraSettings.idleSource(defaults), .computer)
        let m = model()
        XCTAssertEqual(m.idleSource, .computer)
        m.idleSource = .vault
        XCTAssertEqual(MacExtraSettings.idleSource(defaults), .vault)
        XCTAssertEqual(model().idleSource, .vault)
        defaults.set("bogus", forKey: MacExtraSettings.idleSourceKey)
        XCTAssertEqual(MacExtraSettings.idleSource(defaults), .computer, "an unknown value falls back like Windows")
    }

    func testIdleSourceChoosesWhichActivityCounts() {
        // Typing in another app (system idle 10 s) while the vault's window sat unused for 1000 s.
        XCTAssertEqual(MacExtraSettings.IdleSource.computer.idleSeconds(system: 10, app: 1000), 10)
        XCTAssertEqual(MacExtraSettings.IdleSource.vault.idleSeconds(system: 10, app: 1000), 1000)
        // Input in the app counts for both.
        XCTAssertEqual(MacExtraSettings.IdleSource.computer.idleSeconds(system: 500, app: 5), 5)
        XCTAssertEqual(MacExtraSettings.IdleSource.vault.idleSeconds(system: 500, app: 5), 5)
    }

    // MARK: 2FA confirm

    func testTOTPConfirmOffCopiesWithoutAsking() {
        XCTAssertFalse(model().totpConfirm)
        var asked = 0
        XCTAssertTrue(MacTOTPConfirm.allow(title: "Bank", defaults: defaults, ask: { _ in asked += 1; return false }))
        XCTAssertEqual(asked, 0)
    }

    func testTOTPConfirmOnAsksEveryTime() {
        let m = model()
        m.totpConfirm = true
        XCTAssertTrue(MacExtraSettings.totpConfirm(defaults))
        var titles: [String] = []
        XCTAssertTrue(MacTOTPConfirm.allow(title: "Bank", defaults: defaults, ask: { titles.append($0); return true }))
        XCTAssertFalse(MacTOTPConfirm.allow(title: "Mail", defaults: defaults, ask: { titles.append($0); return false }))
        XCTAssertEqual(titles, ["Bank", "Mail"])
        defaults.set("yes", forKey: MacExtraSettings.totpConfirmKey)
        XCTAssertFalse(MacExtraSettings.totpConfirm(defaults), "only an exact true turns it on (Windows)")
    }

    // MARK: documents

    func testDocumentOpenStepsFollowWindowsOrder() {
        XCTAssertTrue(model().documentOpenEnabled, "on by default")
        XCTAssertEqual(MacDocumentOpen.nextStep(name: "passport.pdf", defaults: defaults), .warn)
        defaults.set(true, forKey: MacExtraSettings.documentOpenWarningSeenKey)
        XCTAssertEqual(MacDocumentOpen.nextStep(name: "passport.pdf", defaults: defaults), .open)
        XCTAssertEqual(MacDocumentOpen.nextStep(name: "setup.app", defaults: defaults), .notAllowed)
        let m = model()
        m.documentOpenEnabled = false
        XCTAssertEqual(MacDocumentOpen.nextStep(name: "passport.pdf", defaults: defaults), .off)
        XCTAssertEqual(MacDocumentOpen.nextStep(name: "setup.app", defaults: defaults), .off, "the setting is checked first")
    }

    func testDocumentAllowList() {
        for name in ["a.pdf", "B.JPG", "notes.txt", "sheet.xlsx", "old.doc", "clip.mov"] {
            XCTAssertTrue(MacDocumentOpen.canOpen(name), name)
        }
        for name in ["run.command", "x.sh", "app.pkg", "disk.dmg", "page.html", "img.svg", "a.zip", "noextension", "x.docm"] {
            XCTAssertFalse(MacDocumentOpen.canOpen(name), name)
        }
        // A right-to-left override can't disguise a script as a PDF: the name is judged without it.
        XCTAssertFalse(MacDocumentOpen.canOpen("Invoice\u{202E}fdp.command"))
        XCTAssertEqual(MacDocumentOpen.copyName("Invoice\u{202E}fdp.command"), "Invoicefdp.command")
    }

    func testOpenedCopyIsPrivateMarkedAndSwept() throws {
        let root = dir.appendingPathComponent("opened", isDirectory: true)
        var marked: [URL] = []
        let url = try MacDocumentOpen.writeCopy(Data("secret".utf8), name: "passport.pdf", root: root,
                                                mark: { marked.append($0); return true })
        XCTAssertEqual(url.lastPathComponent, "passport.pdf")
        XCTAssertEqual(url.deletingLastPathComponent().deletingLastPathComponent().standardizedFileURL, root.standardizedFileURL)
        XCTAssertEqual(try Data(contentsOf: url), Data("secret".utf8))
        XCTAssertEqual(marked, [url])
        let fileMode = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int)
        XCTAssertEqual(fileMode & 0o777, 0o600)
        let folderMode = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: url.deletingLastPathComponent().path)[.posixPermissions] as? Int)
        XCTAssertEqual(folderMode & 0o777, 0o700)
        // Two copies of the same file get separate folders.
        let second = try MacDocumentOpen.writeCopy(Data("secret".utf8), name: "passport.pdf", root: root, mark: { _ in true })
        XCTAssertNotEqual(second.deletingLastPathComponent(), url.deletingLastPathComponent())

        XCTAssertEqual(MacDocumentOpen.sweep(root), [])
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.path))
    }

    func testRefusedCopiesLeaveNothing() throws {
        let root = dir.appendingPathComponent("opened", isDirectory: true)
        XCTAssertThrowsError(try MacDocumentOpen.writeCopy(Data("x".utf8), name: "tool.command", root: root, mark: { _ in true })) {
            XCTAssertEqual($0 as? MacDocumentOpen.Failure, .notAllowed)
        }
        // A macro-capable type opens only with the quarantine mark.
        XCTAssertThrowsError(try MacDocumentOpen.writeCopy(Data("x".utf8), name: "old.doc", root: root, mark: { _ in false })) {
            XCTAssertEqual($0 as? MacDocumentOpen.Failure, .notMarked)
        }
        let left = (try? FileManager.default.contentsOfDirectory(atPath: root.path)) ?? []
        XCTAssertEqual(left, [])
        // Other types still open when the mark can't be set (as on Windows off NTFS).
        XCTAssertNoThrow(try MacDocumentOpen.writeCopy(Data("x".utf8), name: "a.pdf", root: root, mark: { _ in false }))
    }

    func testSweepRemovesLinksWithoutFollowingThem() throws {
        let root = dir.appendingPathComponent("opened", isDirectory: true)
        let outside = dir.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        let kept = outside.appendingPathComponent("keep.txt")
        try Data("keep".utf8).write(to: kept)
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("link"), withDestinationURL: outside)
        MacDocumentOpen.sweep(root)
        XCTAssertTrue(FileManager.default.fileExists(atPath: kept.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.path))
    }

    // MARK: automatic backup count

    func testAutomaticBackupCountValidation() {
        XCTAssertEqual(MacExtraSettings.automaticBackupCount(defaults), 5)
        XCTAssertEqual(MacExtraSettings.validatedBackupCount(nil), 5)
        XCTAssertEqual(MacExtraSettings.validatedBackupCount(0), 0)
        XCTAssertEqual(MacExtraSettings.validatedBackupCount(20), 20)
        XCTAssertEqual(MacExtraSettings.validatedBackupCount(21), 5)
        XCTAssertEqual(MacExtraSettings.validatedBackupCount(-1), 5)
        XCTAssertEqual(MacExtraSettings.validatedBackupCount(true), 5)
        XCTAssertEqual(MacExtraSettings.validatedBackupCount("3"), 5)
        let m = model()
        m.automaticBackupCount = 10
        XCTAssertEqual(MacExtraSettings.automaticBackupCount(defaults), 10)
        XCTAssertEqual(model().automaticBackupCount, 10)
        XCTAssertEqual(MacExtraSettings.backupCountOptions(current: 7), [0, 3, 5, 7, 10, 20])
        XCTAssertEqual(MacExtraSettings.backupCountLabel(0), String(localized: "Off"))
    }

    private func profile(_ key: UInt8 = 7) -> DesktopProfileStore {
        DesktopProfileStore(directory: dir, localKey: [UInt8](repeating: key, count: 32))
    }

    func testAutomaticBackupsKeepTheNewestCount() throws {
        let p = profile()
        try FileManager.default.createDirectory(at: p.attachmentsURL, withIntermediateDirectories: true)
        try Data("blob".utf8).write(to: p.attachmentsURL.appendingPathComponent("a1.blob"))
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        for i in 0..<6 {
            try MacAutomaticBackups.write(records: ["n\(i)": .string("v\(i)")], revision: Int64(i), profile: p,
                                          now: start.addingTimeInterval(Double(i)))
        }
        let kept = MacAutomaticBackups.prune(profile: p, keep: 3)
        XCTAssertEqual(kept.map(\.createdAtMillis), [5, 4, 3].map { 1_800_000_000_000 + Int64($0) * 1000 })
        XCTAssertEqual(MacAutomaticBackups.copies(in: dir).count, 3)
        let newest = try XCTUnwrap(MacAutomaticBackups.restorable(in: p).first)
        let opened = try p.openRecords(newest.folder.appendingPathComponent("records.bin"))
        XCTAssertEqual(opened.records, ["n5": .string("v5")])
        XCTAssertEqual(opened.revision, 5)
        XCTAssertTrue(FileManager.default.fileExists(atPath: newest.folder.appendingPathComponent("Attachments/a1.blob").path))
        // The safety copies (before-restore-) are a separate list.
        XCTAssertEqual(MacFullBackup.safetyCopies(in: dir), [])
    }

    func testAutomaticBackupsUnderAnOldKeyAreDroppedAndTempFoldersCleared() throws {
        let old = profile(1)
        try MacAutomaticBackups.write(records: [:], revision: 1, profile: old, now: Date(timeIntervalSince1970: 1))
        let current = profile(2)
        try MacAutomaticBackups.write(records: [:], revision: 2, profile: current, now: Date(timeIntervalSince1970: 2))
        let unfinished = MacFullBackup.backupsFolder(dir).appendingPathComponent(".automatic-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: unfinished, withIntermediateDirectories: true)
        XCTAssertEqual(MacAutomaticBackups.restorable(in: current).map(\.createdAtMillis), [2000])
        MacAutomaticBackups.prune(profile: current, keep: 5)
        XCTAssertEqual(MacAutomaticBackups.copies(in: dir).map(\.createdAtMillis), [2000])
        XCTAssertFalse(FileManager.default.fileExists(atPath: unfinished.path))
    }

    // MARK: shortcut

    func testShortcutDefaultsToControlOptionK() {
        XCTAssertEqual(HotKeyCombo.load(defaults), .standard)
        XCTAssertEqual(HotKeyCombo.standard.label, "⌃⌥K")
    }

    func testShortcutPersists() throws {
        let combo = try XCTUnwrap(HotKeyCombo(keyCode: kVK_ANSI_P, flags: [.command, .shift], characters: "p"))
        XCTAssertEqual(combo.label, "⇧⌘P")
        XCTAssertTrue(combo.isValid)
        combo.save(defaults)
        XCTAssertEqual(HotKeyCombo.load(defaults), combo)
        HotKeyCombo.standard.save(defaults)
        XCTAssertNil(defaults.object(forKey: QuickAccessSettings.hotKeyComboKey), "the standard keys remove the saved value")
        defaults.set(Data("junk".utf8), forKey: QuickAccessSettings.hotKeyComboKey)
        XCTAssertEqual(HotKeyCombo.load(defaults), .standard)
        // A saved combination without ⌃, ⌥ or ⌘ is never used.
        let shiftOnly = HotKeyCombo(keyCode: UInt32(kVK_ANSI_A), modifiers: UInt32(shiftKey), key: "A")
        defaults.set(try JSONEncoder().encode(shiftOnly), forKey: QuickAccessSettings.hotKeyComboKey)
        XCTAssertEqual(HotKeyCombo.load(defaults), .standard)
    }

    func testShortcutKeyRules() {
        XCTAssertNil(HotKeyCombo(keyCode: kVK_Escape, flags: [.control], characters: "\u{1B}"))
        XCTAssertNil(HotKeyCombo(keyCode: kVK_Return, flags: [.command], characters: "\r"))
        XCTAssertEqual(HotKeyCombo(keyCode: kVK_Space, flags: [.option], characters: " ")?.label, "⌥Space")
        XCTAssertEqual(HotKeyCombo(keyCode: kVK_F5, flags: [.control], characters: nil)?.label, "⌃F5")
        XCTAssertEqual(HotKeyCombo(keyCode: kVK_ANSI_1, flags: [.control, .option], characters: "1")?.label, "⌃⌥1")
        XCTAssertEqual(HotKeyCombo(keyCode: kVK_ANSI_K, flags: [.shift], characters: "k")?.isValid, false)
    }
}
