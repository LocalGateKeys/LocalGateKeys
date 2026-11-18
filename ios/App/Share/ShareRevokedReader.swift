import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// Verified revoke notices in the cloud sync folder (`LocalGateKeys Sync/revoked/*.lgkrevoke`, desktop
/// `share_revoke.collect`), for `Share.open(revoked:)`. Trusted signers are the member signing keys of the keyring
/// this device trusts, as kept in the removal watch file next to the vault. Best effort: no sync, no folder or any
/// read error gives an empty set. Shared by the iPhone and the Mac.
enum ShareRevokedReader {
    static var revokedDir: String { "\(FolderLayout.syncDir)/\(ShareRevoke.directoryName)" }

    static func read(watchURL: URL, keychain: (any KeychainVault)?,
                     folders: any FolderOpening = SecurityScopedFolderOpener()) -> Set<String> {
        guard let keychain, let raw = FileRemovalWatchStore(url: watchURL, folder: "").load(),
              let watch = RemovalWatch.parse(raw), !watch.signers.isEmpty,
              let bookmark = (try? keychain.read(.folderBookmark)) ?? nil,
              let opened = try? folders.open(bookmark: bookmark) else { return [] }
        return read(folder: opened.folder, trusted: watch.signers)
    }

    static func read(folder: any FolderAccess, trusted: [String: String]) -> Set<String> {
        guard let names = try? folder.list(revokedDir) else { return [] }
        let notices = names.filter { $0.hasSuffix(ShareRevoke.suffix) }.sorted().prefix(ShareRevoke.maxNotices)
        var files: [(name: String, data: [UInt8])] = []
        for name in notices {
            guard let data = try? folder.read("\(revokedDir)/\(name)", limit: ShareRevoke.maxBytes + 1) else { continue }
            files.append((name: name, data: data))
        }
        return ShareRevoke.collect(files: files, trusted: trusted)
    }
}
