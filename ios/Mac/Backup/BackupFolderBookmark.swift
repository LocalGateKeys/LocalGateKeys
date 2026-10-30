import Foundation
import LGKCore
import AppSharedMac

/// Turns a folder chosen in an `NSOpenPanel` into bookmark bytes and back. Live: app-scoped security-scoped bookmarks
/// (`com.apple.security.files.bookmarks.app-scope`); tests use plain paths.
protocol BookmarkResolving: Sendable {
    /// Called while the panel's grant is open.
    func bookmark(for url: URL) throws -> [UInt8]
    /// The folder, and fresh bytes when the stored ones were stale but still resolved. Throws when the folder is gone.
    func resolve(_ bytes: [UInt8]) throws -> (url: URL, refreshed: [UInt8]?)
}

struct SecurityScopedBookmarks: BookmarkResolving {
    func bookmark(for url: URL) throws -> [UInt8] {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        return Array(try url.bookmarkData(options: SecurityScopedFolderOpener.createOptions, includingResourceValuesForKeys: nil,
                                          relativeTo: nil))
    }

    func resolve(_ bytes: [UInt8]) throws -> (url: URL, refreshed: [UInt8]?) {
        var stale = false
        let url: URL
        do {
            url = try URL(resolvingBookmarkData: Data(bytes), options: SecurityScopedFolderOpener.resolveOptions, relativeTo: nil,
                          bookmarkDataIsStale: &stale)
        } catch { throw BackupFolderBookmark.unavailable }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue else {
            throw BackupFolderBookmark.unavailable
        }
        let refreshed = stale ? (try? url.bookmarkData(options: SecurityScopedFolderOpener.createOptions,
                                                        includingResourceValuesForKeys: nil, relativeTo: nil)).map(Array.init) : nil
        return (url, refreshed)
    }
}

/// A folder the user chose for scheduled backups, their mirror or a manual backup, kept as a bookmark in the app-only
/// Keychain group (Global Constraints) with the path it had, for display. Nothing in it is secret.
struct BackupFolderBookmark: Equatable, Sendable {
    let bookmark: [UInt8]
    /// Where the folder was when chosen (shown on the page; the bookmark follows a moved folder).
    let path: String

    static let unavailable = RecoveryError(String(localized: "Choose the backup folder again"))

    var name: String { URL(fileURLWithPath: path).lastPathComponent }

    func encoded() throws -> [UInt8] {
        try CanonicalJSON.encode(.object(["v": .int(1), "bookmark": .string(Base64.encode(bookmark)), "path": .string(path)]),
                                 dialect: .utf8)
    }

    init(bookmark: [UInt8], path: String) { self.bookmark = bookmark; self.path = path }

    init?(encoded: [UInt8]) {
        guard case .object(let o)? = try? CanonicalJSON.parse(encoded), o["v"] == .int(1),
              case .string(let b)? = o["bookmark"], let bytes = try? Base64.decodeStrict(b), !bytes.isEmpty,
              case .string(let path)? = o["path"] else { return nil }
        self.init(bookmark: bytes, path: path)
    }

    static func load(_ slot: VaultSlot, from keychain: (any KeychainVault)?) -> BackupFolderBookmark? {
        guard let bytes = try? keychain?.read(slot) else { return nil }
        return BackupFolderBookmark(encoded: bytes)
    }

    func save(_ slot: VaultSlot, to keychain: (any KeychainVault)?) throws {
        guard let keychain else { throw RecoveryError(BackupScheduleModel.unavailableText) }
        try keychain.write(slot, try encoded())
    }

    /// The folder now; a stale bookmark that still resolves is saved again with fresh bytes. Throws `unavailable`.
    func resolve(with bookmarks: any BookmarkResolving, slot: VaultSlot, keychain: (any KeychainVault)?) throws -> URL {
        let (url, refreshed) = try bookmarks.resolve(bookmark)
        if let refreshed { try? BackupFolderBookmark(bookmark: refreshed, path: url.path).save(slot, to: keychain) }
        return url
    }
}

/// Runs `body` with the folder's security scope open (sandbox), and closes it afterwards.
func withSecurityScope<T>(_ url: URL, _ body: () async throws -> T) async rethrows -> T {
    let scoped = url.startAccessingSecurityScopedResource()
    defer { if scoped { url.stopAccessingSecurityScopedResource() } }
    return try await body()
}
