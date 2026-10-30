#if os(macOS)
import Foundation
import Darwin

/// The crash-safe journal for a local key rotation (Windows `_rotate_data_key`). The rotating side (`MacVault`)
/// stages, under `<vault>/.rotate/`, every file sealed under the old key re-sealed under the new one, mirroring the
/// paths it replaces (`g<rev>/` and `CURRENT` for the store, `local-data.bin`, `desktop-profile.bin`,
/// `Backups/before-restore-*/…`), then `master-key.json`, then `READY`. Then:
///
/// 1. **commit**: `.rotate/master-key.json` is renamed over `master-key.json` (the only commit point);
/// 2. **roll forward**: the store generation, then `CURRENT`, then every other staged file is renamed into place;
///    older store generations, `tmp-*` and stale restore staging folders (all under the old key) are removed;
///    `.rotate` goes last.
///
/// `finish` runs before any key file is read (app and extensions): staging without a commit is discarded (the old
/// key still opens everything), a committed one is rolled forward (the new key then opens everything). So the vault
/// opens with the old key or the new one, never a mix. Every step holds the store's `.lock` flock.
public enum KeyRotation {
    public static let stagingName = ".rotate"
    static let readyName = "READY"
    static let currentName = "CURRENT"
    /// A staged empty `<path>` + this suffix removes the live `<path>` when the rotation rolls forward (a file the new
    /// key must not leave behind under the old one).
    public static let dropSuffix = ".lgk-drop"
    static let restoreStagingPrefix = "restore-staging-"

    /// The points a DEBUG test may stop a rotation at, as if the app died there.
    public enum Step: CaseIterable, Sendable { case staged, committed, storeMoved, filesMoved }

    #if DEBUG
    /// Thrown by the DEBUG crash seam: nothing is cleaned up, as after a real crash.
    public struct SimulatedCrash: Error {
        public init() {}
    }
    #endif

    public static func stagingURL(_ directory: URL) -> URL { directory.appendingPathComponent(stagingName, isDirectory: true) }

    /// Runs `body` holding the vault's `.lock` flock (shared with `LocalStore` commits), blocking.
    public static func withLock<T>(_ directory: URL, _ body: () throws -> T) throws -> T {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fd = Darwin.open(directory.appendingPathComponent(".lock").path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw CocoaError(.fileLocking) }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }

    /// Settles an interrupted rotation (see the type). Skipped while another holder has the lock: that is the
    /// rotation itself (or a commit), which settles it. Best effort; never throws.
    public static func finish(directory: URL) {
        let staging = stagingURL(directory)
        guard FileManager.default.fileExists(atPath: staging.path) else { return }
        let fd = Darwin.open(directory.appendingPathComponent(".lock").path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { return }
        defer { close(fd) }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { return }
        defer { flock(fd, LOCK_UN) }
        try? settleLocked(directory: directory) { _ in }
    }

    /// A roll-forward step that failed (a rename or remove refused). `.rotate` stays, `READY` included, so the next
    /// open retries from where this one stopped.
    public struct RollForwardError: Error, Equatable {
        public let step: RollForwardOp
    }

    /// The file operations of the roll-forward, in order.
    public enum RollForwardOp: CaseIterable, Sendable { case moveGeneration, moveCurrent, moveFile, removeOld, removeStaging }

    #if DEBUG
    /// Test seam: the next roll-forward operation of this kind fails once, as a refused rename or remove would.
    nonisolated(unsafe) public static var injectedFailure: RollForwardOp?
    #endif

    /// Runs one file operation (after the DEBUG injected failure, which refuses it before it runs); a false result
    /// stops the roll-forward.
    private static func check(_ ok: @autoclosure () -> Bool, _ op: RollForwardOp) throws {
        #if DEBUG
        if injectedFailure == op { injectedFailure = nil; throw RollForwardError(step: op) }
        #endif
        guard ok() else { throw RollForwardError(step: op) }
    }

    /// With the lock held: discards an uncommitted staging, rolls a committed one forward. Throws when a step fails;
    /// the staging is then left as it is for the next attempt.
    public static func settleLocked(directory: URL, after: (Step) throws -> Void) throws {
        let fm = FileManager.default
        let staging = stagingURL(directory)
        guard fm.fileExists(atPath: staging.path) else { return }
        let committed = fm.fileExists(atPath: staging.appendingPathComponent(readyName).path)
            && !fm.fileExists(atPath: staging.appendingPathComponent(MasterPasswordUnlock.keyFileName).path)
        guard committed else {
            // Not committed (or half written): the old key still opens everything; the staging is only discarded.
            try check((try? fm.removeItem(at: staging)) != nil, .removeStaging)
            return
        }
        try rollForward(directory: directory, after: after)
    }

    /// Step 1: `.rotate/master-key.json` replaces `master-key.json`.
    public static func commit(directory: URL) throws {
        let staged = stagingURL(directory).appendingPathComponent(MasterPasswordUnlock.keyFileName)
        guard rename(staged.path, directory.appendingPathComponent(MasterPasswordUnlock.keyFileName).path) == 0 else {
            throw CocoaError(.fileWriteUnknown)
        }
        syncDirectory(directory)
    }

    /// Idempotent: each step moves what is still staged, so a retry continues where a failed attempt stopped.
    private static func rollForward(directory: URL, after: (Step) throws -> Void) throws {
        let fm = FileManager.default
        let staging = stagingURL(directory)
        let names = try fm.contentsOfDirectory(atPath: staging.path).sorted()
        // 1. The staged generation moves in under its own (new, unused) name; nothing live is touched.
        for name in names where isGeneration(name) {
            let target = directory.appendingPathComponent(name, isDirectory: true)
            try check(!fm.fileExists(atPath: target.path), .moveGeneration)   // staged under a fresh name: never replaced
            try check(rename(staging.appendingPathComponent(name).path, target.path) == 0, .moveGeneration)
        }
        syncDirectory(directory)
        try after(.storeMoved)
        // 2. CURRENT names it (one atomic rename), only once that generation is complete in place.
        let stagedCurrent = staging.appendingPathComponent(currentName)
        if fm.fileExists(atPath: stagedCurrent.path) {
            let named = (try? String(contentsOf: stagedCurrent, encoding: .ascii)).flatMap {
                Int64($0.trimmingCharacters(in: .whitespacesAndNewlines))
            }
            let state = named.map { directory.appendingPathComponent("g\($0)/state.blob").path }
            try check(state.map { fm.fileExists(atPath: $0) } == true, .moveCurrent)
            try check(rename(stagedCurrent.path, directory.appendingPathComponent(currentName).path) == 0, .moveCurrent)
            syncDirectory(directory)
        }
        // 3. Every other staged file, at the same relative path; a safety copy deleted meanwhile is skipped.
        var files: [URL] = []
        if let walker = fm.enumerator(at: staging, includingPropertiesForKeys: [.isRegularFileKey]) {
            for case let url as URL in walker where (try? url.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true {
                files.append(url)
            }
        }
        let base = staging.resolvingSymlinksInPath().path
        for url in files {
            let rel = String(url.resolvingSymlinksInPath().path.dropFirst(base.count + 1))
            guard rel != readyName else { continue }
            if rel.hasSuffix(dropSuffix) {
                let live = directory.appendingPathComponent(String(rel.dropLast(dropSuffix.count)))
                if fm.fileExists(atPath: live.path) {
                    try check((try? fm.removeItem(at: live)) != nil, .moveFile)
                    syncDirectory(live.deletingLastPathComponent())
                }
                try check((try? fm.removeItem(at: url)) != nil, .moveFile)
                continue
            }
            let target = directory.appendingPathComponent(rel)
            let parent = target.deletingLastPathComponent()
            guard fm.fileExists(atPath: parent.path) else { continue }   // its folder is gone: nothing to replace
            try check(rename(url.path, target.path) == 0, .moveFile)
            syncDirectory(parent)
        }
        try after(.filesMoved)
        // 4. Anything still under the old key: older store generations, abandoned commits, restore staging.
        let current = (try? String(contentsOf: directory.appendingPathComponent(currentName), encoding: .ascii))
            .flatMap { Int64($0.trimmingCharacters(in: .whitespacesAndNewlines)) }
        for name in try fm.contentsOfDirectory(atPath: directory.path) {
            let stale = (isGeneration(name) && Int64(name.dropFirst()) != current) || name.hasPrefix("tmp-")
                || name.hasPrefix(restoreStagingPrefix)
            if stale { try check((try? fm.removeItem(at: directory.appendingPathComponent(name))) != nil, .removeOld) }
        }
        // 5. The staging goes last, READY with it.
        try check((try? fm.removeItem(at: staging)) != nil, .removeStaging)
        syncDirectory(directory)
    }

    public static func isGeneration(_ name: String) -> Bool {
        name.hasPrefix("g") && name.count > 1 && name.utf8.dropFirst().allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
    }

    /// Writes a new file and flushes it (F_FULLFSYNC), creating its folder.
    public static func writeSynced(_ data: Data, to url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let fd = Darwin.open(url.path, O_CREAT | O_TRUNC | O_WRONLY, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { close(fd) }
        try data.withUnsafeBytes { raw in
            var off = 0
            while off < raw.count {
                let w = Darwin.write(fd, raw.baseAddress! + off, raw.count - off)
                guard w > 0 else { throw CocoaError(.fileWriteUnknown) }
                off += w
            }
        }
        if fcntl(fd, F_FULLFSYNC) != 0 && fsync(fd) != 0 { throw CocoaError(.fileWriteUnknown) }
    }

    static func syncDirectory(_ url: URL) {
        let fd = Darwin.open(url.path, O_RDONLY)
        guard fd >= 0 else { return }
        defer { close(fd) }
        if fcntl(fd, F_FULLFSYNC) != 0 { _ = fsync(fd) }
    }
}
#endif
