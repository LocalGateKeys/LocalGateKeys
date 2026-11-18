import Foundation

/// The weekly backup restore test (sub-plan 12, Windows `restore_test.py`, Android `RestoreTest.kt`).
///
/// The newest backup is restored into `<scratch root>/<uuid>` (never the live vault), unlocked once and its items
/// counted; the scratch folder is always deleted again, whatever happened. The result holds no secret and no title:
/// a pass/fail flag, the backup's path and age, the item count and a reason (`unreadable`, `old_password`,
/// `no_backup`). It is kept as `restore-test.json` with the same keys as Windows. Passwords and keys reach a restorer
/// only as arguments; nothing here stores them.
public enum RestoreTest {
    /// At most one automatic run a week.
    public static let week: Int64 = 7 * 24 * 3600
    /// The scratch folder's name under the app's data folder (Windows `restore-test`).
    public static let scratchName = "restore-test"
    /// The result file's name (Windows `restore-test.json`).
    public static let stateFile = "restore-test.json"

    public enum Reason: String, CaseIterable, Sendable {
        case unreadable
        case oldPassword = "old_password"
        case noBackup = "no_backup"
    }

    /// Thrown by a restorer: why the backup could not be restored.
    public struct Failure: Error, Equatable, Sendable {
        public let reason: Reason
        public init(_ reason: Reason) { self.reason = reason }
    }

    /// What a restorer found in the scratch copy: the item count and the backup's export time (Unix seconds, 0 unknown).
    public struct Restored: Equatable, Sendable {
        public let items: Int
        public let exportedAt: Int64
        public init(items: Int, exportedAt: Int64) { self.items = items; self.exportedAt = exportedAt }
    }

    /// One test's result (Windows `RestoreTestResult`). `reason` is "" when `ok`.
    public struct Result: Codable, Equatable, Sendable {
        public let ok: Bool
        public let backupPath: String
        /// Seconds between the backup's export and the test (0 when unknown).
        public let backupAge: Int64
        public let items: Int
        public let reason: String
        public let testedAt: Int64

        enum CodingKeys: String, CodingKey {
            case ok, items, reason
            case backupPath = "backup_path", backupAge = "backup_age", testedAt = "tested_at"
        }

        public init(ok: Bool, backupPath: String, backupAge: Int64, items: Int, reason: Reason?, testedAt: Int64) {
            self.ok = ok; self.backupPath = backupPath; self.backupAge = backupAge; self.items = items
            self.reason = reason?.rawValue ?? ""; self.testedAt = testedAt
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            ok = try c.decode(Bool.self, forKey: .ok)
            backupPath = try c.decode(String.self, forKey: .backupPath)
            backupAge = try c.decode(Int64.self, forKey: .backupAge)
            items = try c.decode(Int.self, forKey: .items)
            reason = try c.decodeIfPresent(String.self, forKey: .reason) ?? ""
            testedAt = try c.decodeIfPresent(Int64.self, forKey: .testedAt) ?? 0
            guard reason.isEmpty || Reason(rawValue: reason) != nil else {
                throw DecodingError.dataCorruptedError(forKey: .reason, in: c, debugDescription: "unknown reason")
            }
        }

        /// The failure's reason; nil when the test passed.
        public var failure: Reason? { ok ? nil : Reason(rawValue: reason) ?? .unreadable }
    }

    /// The restorer: (backup file, empty scratch folder) -> what it restored, or `Failure`. Any other error counts as
    /// `unreadable`.
    public typealias Restorer = @Sendable (URL, URL) throws -> Restored

    /// Test-restores `backup` into a fresh `<scratchRoot>/<uuid>` folder, which is removed before this returns.
    public static func run(backup: URL?, scratchRoot: URL, now: Int64, restore: (URL, URL) throws -> Restored) -> Result {
        let path = backup?.path ?? ""
        var isDirectory: ObjCBool = false
        guard let backup, FileManager.default.fileExists(atPath: backup.path, isDirectory: &isDirectory), !isDirectory.boolValue else {
            return Result(ok: false, backupPath: path, backupAge: 0, items: 0, reason: .noBackup, testedAt: now)
        }
        let scratch = scratchRoot.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: scratch) }
        do {
            try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
            let restored = try restore(backup, scratch)
            let age = restored.exportedAt > 0 ? max(0, now - restored.exportedAt) : 0
            return Result(ok: true, backupPath: path, backupAge: age, items: restored.items, reason: nil, testedAt: now)
        } catch let failure as Failure {
            return Result(ok: false, backupPath: path, backupAge: 0, items: 0, reason: failure.reason, testedAt: now)
        } catch {
            return Result(ok: false, backupPath: path, backupAge: 0, items: 0, reason: .unreadable, testedAt: now)
        }
    }

    /// Windows `due`: on, and never run or the last run a week or more ago.
    public static func due(last: Result?, now: Int64, enabled: Bool) -> Bool {
        guard enabled else { return false }
        guard let last else { return true }
        return now - last.testedAt >= week
    }

    /// The newest file in `directory` with one of `extensions` (by modification date), or nil.
    public static func newestBackup(in directory: URL, extensions: Set<String>) -> URL? {
        let keys: [URLResourceKey] = [.contentModificationDateKey, .isRegularFileKey]
        guard let urls = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: keys) else { return nil }
        let files = urls.filter { url in
            extensions.contains(url.pathExtension.lowercased())
                && ((try? url.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile ?? false)
        }
        func modified(_ url: URL) -> Date {
            (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? .distantPast
        }
        return files.max { modified($0) < modified($1) }
    }

    // MARK: the result file

    public static func save(_ result: Result, to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encoder.encode(result).write(to: url, options: .atomic)
    }

    /// The saved result, or nil (none, unreadable or with an unknown reason).
    public static func load(from url: URL) -> Result? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(Result.self, from: data)
    }

    // MARK: restorers

    /// An `LGKMBAK1` phone backup (`.lgkm`): copied into the scratch folder and opened there with `password` (the
    /// unlock), counting the live logins and typed items. A wrong password is `old_password`, anything else
    /// `unreadable` (Windows maps a backup error naming the password the same way).
    public static func phoneBackup(password: String) -> Restorer {
        { backup, scratch in
            // Read the bytes (as Import does) and write the scratch copy from them: `copyItem` fails on files picked
            // from iCloud Drive and other file providers, which made every such test "unreadable".
            let copy = scratch.appendingPathComponent("backup.lgkm")
            let data: Data
            do {
                data = try Data(contentsOf: backup)
                try data.write(to: copy)
            } catch { throw Failure(.unreadable) }
            let payload: BackupPayload
            do { payload = try PhoneBackup.open(data, password: password) }
            catch PhoneBackup.Error.wrongPassword { throw Failure(.oldPassword) }
            catch { throw Failure(.unreadable) }
            return Restored(items: liveItems(payload.states), exportedAt: payload.createdAt)
        }
    }

    /// A computer's full backup (`.lgk`/`.lgkfull`, version 2 or 3) tested on a phone: opened with the backup password,
    /// then its vault with the computer's master password (the phone has no stored key for it); the item count comes
    /// from the opened vault. Nothing is kept. A wrong password of either kind is `old_password`.
    public static func computerBackup(password: String, masterPassword: String) -> Restorer {
        { backup, _ in
            let data: Data
            do { data = try Data(contentsOf: backup) } catch { throw Failure(.unreadable) }
            let contents: FullBackupContents
            do { contents = try FullBackup.open(data, password: password) }
            catch FullBackupError.wrongPasswordOrModified { throw Failure(.oldPassword) }
            catch is BackupKeyError { throw Failure(.oldPassword) }
            catch { throw Failure(.unreadable) }
            let items: [JSONValue]
            do { items = try DesktopVaultFile.open(contents.vault, password: masterPassword).items }
            catch { throw Failure(.oldPassword) }
            return Restored(items: items.count, exportedAt: contents.createdAt ?? 0)
        }
    }

    /// True for a computer's full backup (a zip container: `PK`), false for a phone backup (`LGKMBAK1`).
    public static func isComputerBackup(_ url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            return ["lgk", "lgkfull"].contains(url.pathExtension.lowercased())
        }
        defer { try? handle.close() }
        return (try? handle.read(upToCount: 2)) == Data("PK".utf8)
    }

    /// Live logins and typed items in a phone backup (not tombstones, licences or collection states).
    static func liveItems(_ states: [BackupState]) -> Int {
        states.filter { state in
            guard !state.deleted, case .object(let o)? = state.item, case .string(let ns)? = o["ns"] else { return false }
            return ns == Namespace.entry.rawValue || ns == Namespace.item.rawValue
        }.count
    }

    /// A full backup (`.lgk`, version 2 or 3): opened with the backup password, its `vault.json` written into the
    /// scratch folder and unlocked there with the vault's stored password key (no master password is typed). A wrong
    /// backup password, or a vault sealed under an older master password, is `old_password`.
    public static func fullBackup(password: String, passwordKey: DesktopVaultFile.PasswordKey) -> Restorer {
        { backup, scratch in
            let data: Data
            do { data = try Data(contentsOf: backup, options: .alwaysMapped) } catch { throw Failure(.unreadable) }
            let contents: FullBackupContents
            do { contents = try FullBackup.open(data, password: password) }
            catch FullBackupError.wrongPasswordOrModified { throw Failure(.oldPassword) }
            catch is BackupKeyError { throw Failure(.oldPassword) }
            catch { throw Failure(.unreadable) }
            let vaultFile = scratch.appendingPathComponent("vault.json")
            let vault: Data
            do {
                try contents.vault.write(to: vaultFile, options: .withoutOverwriting)
                vault = try Data(contentsOf: vaultFile)
            } catch { throw Failure(.unreadable) }
            let payload: [String: JSONValue]
            do { payload = try DesktopVaultFile.openPayload(vault, passwordKey: passwordKey).payload }
            catch { throw Failure(.oldPassword) }
            var items = 0
            for key in ["entries", "items"] { if case .array(let rows)? = payload[key] { items += rows.count } }
            return Restored(items: items, exportedAt: contents.createdAt ?? 0)
        }
    }
}
