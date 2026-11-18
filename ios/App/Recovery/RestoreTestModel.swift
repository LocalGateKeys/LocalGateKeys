import Foundation
import Observation
import LGKCore
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// The "Last backup restore test" row (sub-plan 12, Windows Security check row), shared by the iPhone's Settings ›
/// Lock & security and the Mac's Security centre. The test itself is LGKCore `RestoreTest`; this keeps the last
/// result in `restore-test.json` (no secret, no title), the weekly setting (default on) and the row's text.
///
/// The backup and its password come from the caller for each run and are dropped when it finishes: nothing here
/// stores a password. A weekly test needs the backup password (backups are sealed with it, or with a key only it
/// opens), so after unlock a due test is shown on the row ("A weekly test is due") for "Test now".
@MainActor @Observable
final class RestoreTestModel {
    nonisolated static let weeklyKey = "restoreTestWeekly"
    nonisolated static let title = String(localized: "Last backup restore test")
    nonisolated static let testNow = String(localized: "Test now")
    nonisolated static let weeklyLabel = String(localized: "Test a backup restore every week")
    nonisolated static let dueText = String(localized: "A weekly test is due.")
    nonisolated static let neverRun = String(localized: "Never run")
    nonisolated static let passwordPrompt = String(localized: "The backup password is used for this test only and is not kept.")

    private(set) var last: RestoreTest.Result?
    private(set) var running = false
    var weekly: Bool { didSet { defaults.set(weekly, forKey: Self.weeklyKey) } }

    @ObservationIgnored let stateURL: URL
    @ObservationIgnored let scratchRoot: URL
    @ObservationIgnored private let defaults: UserDefaults

    /// `folder`: where `restore-test.json` and the `restore-test/<uuid>` scratch folders go (the app's data folder).
    init(folder: URL, defaults: UserDefaults = AppSettings.shared.defaults) {
        stateURL = folder.appendingPathComponent(RestoreTest.stateFile)
        scratchRoot = folder.appendingPathComponent(RestoreTest.scratchName, isDirectory: true)
        self.defaults = defaults
        weekly = (defaults.object(forKey: Self.weeklyKey) as? Bool) ?? true
        last = RestoreTest.load(from: stateURL)
    }

    /// Application Support (the app's own container), or the temporary folder when it can't be made.
    static func defaultFolder() -> URL {
        (try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true))
            ?? FileManager.default.temporaryDirectory
    }

    nonisolated static func now() -> Int64 { Int64(Date().timeIntervalSince1970) }

    func isDue(now: Int64 = RestoreTestModel.now()) -> Bool { RestoreTest.due(last: last, now: now, enabled: weekly) }

    /// The row's text: never run, passed on a date with the item count, or failed with the reason.
    var rowText: String { Self.rowText(last) }

    nonisolated static func rowText(_ result: RestoreTest.Result?) -> String {
        guard let result else { return neverRun }
        if result.ok {
            let date = Date(timeIntervalSince1970: TimeInterval(result.testedAt)).formatted(date: .abbreviated, time: .omitted)
            return String(localized: "Passed on \(date), \(result.items) items")
        }
        return String(localized: "Failed: \(reasonText(result.failure ?? .unreadable))")
    }

    nonisolated static func reasonText(_ reason: RestoreTest.Reason) -> String {
        switch reason {
        case .unreadable: String(localized: "the backup can't be read")
        case .oldPassword: String(localized: "the backup uses an old password")
        case .noBackup: String(localized: "no backup was found")
        }
    }

    /// Restores `backup` into a scratch folder off the main thread (the scratch folder is always removed), then keeps
    /// the result. `restore` holds the password only for this run.
    @discardableResult
    /// `scope`: the security-scoped URL to open around the run (a bookmarked backup folder); nil uses `backup` (a file
    /// picked in the document picker).
    func run(backup: URL?, scope: URL? = nil, restore: @escaping RestoreTest.Restorer) async -> RestoreTest.Result {
        running = true
        defer { running = false }
        let root = scratchRoot, now = Self.now(), access = scope ?? backup
        let result = await Task.detached(priority: .userInitiated) { () -> RestoreTest.Result in
            let scoped = access?.startAccessingSecurityScopedResource() ?? false
            defer { if scoped { access?.stopAccessingSecurityScopedResource() } }
            return RestoreTest.run(backup: backup, scratchRoot: root, now: now, restore: restore)
        }.value
        last = result
        try? RestoreTest.save(result, to: stateURL)
        return result
    }
}
