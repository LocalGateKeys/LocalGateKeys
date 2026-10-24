import Foundation
import AppShared

/// `FolderAccess` over the folder the user picked (iCloud Drive, OneDrive, Dropbox, Google Drive...).
///
/// Every read and write goes through `NSFileCoordinator`, so the provider's File Provider sees them.
/// iCloud placeholders are downloaded explicitly (`startDownloadingUbiquitousItem`) and waited for with
/// a bounded timeout; other providers materialise the file during the coordinated read. Writes go to a
/// temp file in the same directory (`.<name>.<uuid>.tmp`, the pattern `FolderSync` sweeps) and are moved
/// over the target in one coordinated replace.
final class CoordinatedFolder: FolderAccess, @unchecked Sendable {
    let root: URL
    /// Total time this folder (one sync run) may spend waiting for iCloud downloads.
    let downloadTimeout: TimeInterval
    private let scoped: Bool
    private let lock = NSLock()
    private var downloadDeadline: Date?

    /// `root` must come from a resolved security-scoped bookmark; access starts here and stops on deinit.
    init(root: URL, downloadTimeout: TimeInterval = 30) {
        self.root = root; self.downloadTimeout = downloadTimeout
        scoped = root.startAccessingSecurityScopedResource()
    }

    deinit { if scoped { root.stopAccessingSecurityScopedResource() } }

    func url(_ path: String) throws -> URL {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !parts.isEmpty, !parts.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) else {
            throw FolderAccessError.io("bad path \(path)")
        }
        return parts.reduce(root) { $0.appendingPathComponent(String($1)) }
    }

    /// iCloud's placeholder for a not-yet-downloaded `name` (older iOS layouts): `.name.icloud`.
    static func placeholder(of url: URL) -> URL {
        url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).icloud")
    }

    private func coordinate<T>(read url: URL, options: NSFileCoordinator.ReadingOptions = [], _ body: (URL) throws -> T) throws -> T {
        var coordError: NSError?
        var result: Result<T, Error>?
        NSFileCoordinator(filePresenter: nil).coordinate(readingItemAt: url, options: options, error: &coordError) { u in
            result = Result { try body(u) }
        }
        if let coordError { throw Self.mapped(coordError, url) }
        guard let result else { throw FolderAccessError.io("coordination failed: \(url.lastPathComponent)") }
        return try result.get()
    }

    private func coordinate<T>(write url: URL, options: NSFileCoordinator.WritingOptions, _ body: (URL) throws -> T) throws -> T {
        var coordError: NSError?
        var result: Result<T, Error>?
        NSFileCoordinator(filePresenter: nil).coordinate(writingItemAt: url, options: options, error: &coordError) { u in
            result = Result { try body(u) }
        }
        if let coordError { throw Self.mapped(coordError, url) }
        guard let result else { throw FolderAccessError.io("coordination failed: \(url.lastPathComponent)") }
        return try result.get()
    }

    static func mapped(_ error: Error, _ url: URL) -> Error {
        if error is FolderAccessError { return error }
        let ns = error as NSError
        if ns.domain == NSCocoaErrorDomain && [NSFileNoSuchFileError, NSFileReadNoSuchFileError].contains(ns.code) {
            return FolderAccessError.notFound(url.lastPathComponent)
        }
        if ns.domain == NSPOSIXErrorDomain && ns.code == Int(ENOENT) { return FolderAccessError.notFound(url.lastPathComponent) }
        return FolderAccessError.io("\(url.lastPathComponent): \(ns.localizedDescription)")
    }

    private func present(_ url: URL) -> Bool {
        let fm = FileManager.default
        return fm.fileExists(atPath: url.path) || fm.fileExists(atPath: Self.placeholder(of: url).path)
    }

    /// One wait budget per folder instance (per run), started by the first wait.
    private func budgetDeadline() -> Date {
        lock.withLock {
            if let d = downloadDeadline { return d }
            let d = Date().addingTimeInterval(downloadTimeout); downloadDeadline = d; return d
        }
    }

    /// Starts and waits for the download of an iCloud item that is not current (also a legacy
    /// `.name.icloud` placeholder); no-op for other providers. Blocks its thread (polling with
    /// `Thread.sleep`): callers run it on a GCD thread, never a Swift-concurrency cooperative thread
    /// (`SyncCoordinator.runAll` dispatches `folderRun`).
    func ensureDownloaded(_ url: URL) throws {
        let fm = FileManager.default
        let keys: Set<URLResourceKey> = [.isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey]
        func current() -> Bool {
            guard fm.fileExists(atPath: url.path) else { return false }
            var fresh = url; fresh.removeAllCachedResourceValues()
            guard let v = try? fresh.resourceValues(forKeys: keys), v.isUbiquitousItem == true else { return true }
            return v.ubiquitousItemDownloadingStatus == .current
        }
        let legacy = !fm.fileExists(atPath: url.path) && fm.fileExists(atPath: Self.placeholder(of: url).path)
        if !legacy {
            guard let values = try? url.resourceValues(forKeys: keys), values.isUbiquitousItem == true else { return }
            if values.ubiquitousItemDownloadingStatus == .current { return }
        }
        do { try fm.startDownloadingUbiquitousItem(at: url) } catch { throw Self.mapped(error, url) }
        let deadline = budgetDeadline()
        while Date() < deadline {
            if current() { return }
            Thread.sleep(forTimeInterval: 0.2)
        }
        if current() { return }
        throw FolderAccessError.io("\(url.lastPathComponent): the cloud app has not finished downloading this file")
    }

    // MARK: FolderAccess

    func list(_ dir: String) throws -> [String] {
        let u = try url(dir)
        guard present(u) else { throw FolderAccessError.notFound(dir) }
        return try coordinate(read: u) { d in
            do {
                let names = try FileManager.default.contentsOfDirectory(atPath: d.path)
                // An iCloud placeholder `.name.icloud` stands for `name`.
                return Array(Set(names.map { n in
                    n.hasPrefix(".") && n.hasSuffix(".icloud") && n.count > 8 ? String(n.dropFirst().dropLast(7)) : n
                }))
            } catch { throw Self.mapped(error, d) }
        }
    }

    func read(_ path: String, limit: Int) throws -> [UInt8] {
        let u = try url(path)
        guard present(u) else { throw FolderAccessError.notFound(path) }
        try ensureDownloaded(u)
        return try coordinate(read: u) { f in
            do {
                let h = try FileHandle(forReadingFrom: f)
                defer { try? h.close() }
                return Array(try h.read(upToCount: max(0, limit)) ?? Data())
            } catch { throw Self.mapped(error, f) }
        }
    }

    func writeAtomic(_ path: String, _ data: [UInt8]) throws {
        let target = try url(path)
        let dir = target.deletingLastPathComponent()
        let fm = FileManager.default
        if !fm.fileExists(atPath: dir.path) {
            try coordinate(write: dir, options: []) { d in
                do { try fm.createDirectory(at: d, withIntermediateDirectories: true) } catch { throw Self.mapped(error, d) }
            }
        }
        let tmp = dir.appendingPathComponent(".\(target.lastPathComponent).\(UUID().uuidString).tmp")
        // One coordinated access covers both: write the temp file (.forMoving), then replace the target.
        var coordError: NSError?
        var failure: Error?
        NSFileCoordinator(filePresenter: nil).coordinate(writingItemAt: tmp, options: .forMoving, writingItemAt: target,
                                                         options: .forReplacing, error: &coordError) { tmpURL, targetURL in
            do {
                try Data(data).write(to: tmpURL, options: [.withoutOverwriting])
                if fm.fileExists(atPath: targetURL.path) {
                    _ = try fm.replaceItemAt(targetURL, withItemAt: tmpURL, backupItemName: nil, options: [])
                } else {
                    try fm.moveItem(at: tmpURL, to: targetURL)
                }
            } catch { failure = Self.mapped(error, targetURL) }
        }
        if let error = failure ?? coordError.map({ Self.mapped($0, target) }) {
            try? fm.removeItem(at: tmp)
            throw error
        }
    }

    func remove(_ path: String) throws {
        let u = try url(path)
        guard present(u) else { throw FolderAccessError.notFound(path) }
        try coordinate(write: u, options: .forDeleting) { f in
            do { try FileManager.default.removeItem(at: f) } catch { throw Self.mapped(error, f) }
        }
    }

    func exists(_ path: String) -> Bool {
        guard let u = try? url(path) else { return false }
        return present(u)
    }
}

// MARK: bookmarks

/// Turns a picked folder into a stored bookmark and a bookmark back into a `FolderAccess`.
protocol FolderOpening: Sendable {
    /// Bookmark bytes for a folder URL from the document picker (called while its scope is accessible).
    func bookmark(for url: URL) throws -> [UInt8]
    /// The folder for stored bookmark bytes, plus fresh bookmark bytes when the stored ones were stale.
    func open(bookmark: [UInt8]) throws -> (folder: any FolderAccess, refreshed: [UInt8]?)
}

struct SecurityScopedFolderOpener: FolderOpening {
    func bookmark(for url: URL) throws -> [UInt8] {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        return Array(try url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil))
    }

    func open(bookmark: [UInt8]) throws -> (folder: any FolderAccess, refreshed: [UInt8]?) {
        var stale = false
        let url: URL
        do { url = try URL(resolvingBookmarkData: Data(bookmark), options: [], relativeTo: nil, bookmarkDataIsStale: &stale) }
        catch { throw FolderAccessError.io("the chosen folder is no longer available") }
        let folder = CoordinatedFolder(root: url)
        // A stale bookmark still resolves; save a fresh one while the scope is open.
        let refreshed = stale ? (try? url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)).map(Array.init) : nil
        return (folder, refreshed)
    }
}
