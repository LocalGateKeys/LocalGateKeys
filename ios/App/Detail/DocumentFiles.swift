import Foundation
import UniformTypeIdentifiers
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// This device's attachment files (task 12): `<Application Support>/LocalGateKeys/attachments/<blob_id>.lgkblob`.
/// Each file is the sealed sync blob (`AttachmentSync`), encrypted under the attachment's own random key, which
/// is kept only inside the encrypted vault record. Nothing here is ever written in clear, except the short-lived
/// open copies (`temporaryCopy`), which are deleted after use and at every launch.
enum AttachmentFiles {
    static func localFolder() -> BlobFolder? {
        guard let base = try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                      appropriateFor: nil, create: true) else { return nil }
        let folder = BlobFolder(root: base.appendingPathComponent("LocalGateKeys", isDirectory: true))
        try? FileManager.default.createDirectory(at: folder.dir, withIntermediateDirectories: true)
        // The files are encrypted already; still keep them out of reach while the device is locked.
        #if os(iOS)
        try? FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: folder.dir.path)
        #endif
        return folder
    }

    /// Where open copies live; emptied at launch and after each preview or share.
    static var openCopiesDirectory: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("LocalGateKeys open copies", isDirectory: true)
    }

    /// Deletes every open copy left behind (a crash during a preview).
    static func purgeOpenCopies() {
        try? FileManager.default.removeItem(at: openCopiesDirectory)
    }
}

/// Add, open, rename and delete documents (shared by the iPhone and the Mac). Pro only to add; 25 MB per file.
enum DocumentFiles {
    enum AddResult: Equatable { case saved(String), needsPro, tooLarge, unavailable, failed }

    static let maxBytes = AttachmentSync.maxFileBytes
    static let tooLargeMessage = String(localized: "This file is over 25 MB. Choose a smaller file.")
    static let proMessage = String(localized: "Adding files needs Pro. Files you already have stay available.")

    /// "application/pdf" for "passport.pdf"; "application/octet-stream" when unknown.
    static func mimeType(forFileName name: String) -> String {
        let ext = (name as NSString).pathExtension
        return UTType(filenameExtension: ext)?.preferredMIMEType ?? "application/octet-stream"
    }

    /// Stores `data` as a new document item: the blob first, then the record (so a record never points at a
    /// file that is not there).
    static func add(data: Data, fileName: String, title: String = "", isPro: Bool, store: any ItemStore,
                    blobs: (any AttachmentBlobStore)?, clock: any UnixClock, random: any RandomSource) -> AddResult {
        guard isPro else { return .needsPro }
        guard data.count <= maxBytes else { return .tooLarge }
        guard let blobs else { return .unavailable }
        do {
            var snap = try store.load()
            let made = try AttachmentDocuments.make(data: Array(data), fileName: fileName, mimeType: mimeType(forFileName: fileName),
                                                    title: title, now: clock.now, random: random, blobs: blobs)
            guard snap.records[made.id] == nil else { return .failed }
            snap.records[made.id] = made.wrapper
            try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
            return .saved(made.id)
        } catch let e as AttachmentSyncError where e.reason == "too-large" {
            return .tooLarge
        } catch {
            return .failed
        }
    }

    /// The stored reference of document `id` (name, type and size for the screen), or nil.
    static func reference(id: String, store: any ItemStore) -> AttachmentRef? {
        guard let snap = try? store.load() else { return nil }
        return AttachmentDocuments.ref(of: snap.records[id])
    }

    /// The decrypted file bytes of document `id`, verified against its reference.
    static func contents(id: String, store: any ItemStore, blobs: (any AttachmentBlobStore)?) throws -> (ref: AttachmentRef, data: Data) {
        guard let blobs else { throw AttachmentSyncError("attachment-missing") }
        let snap = try store.load()
        let opened = try AttachmentDocuments.open(snap.records[id], blobs: blobs)
        return (opened.ref, Data(opened.data))
    }

    /// A short-lived clear copy for Quick Look or Share, in its own folder under `openCopiesDirectory`.
    /// The caller deletes it with `removeTemporaryCopy` as soon as the preview or share sheet closes.
    static func temporaryCopy(id: String, store: any ItemStore, blobs: (any AttachmentBlobStore)?) throws -> URL {
        let opened = try contents(id: id, store: store, blobs: blobs)
        let folder = AttachmentFiles.openCopiesDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let url = folder.appendingPathComponent(AttachmentDocuments.safeFileName(opened.ref.name))
        #if os(iOS)
        try opened.data.write(to: url, options: [.withoutOverwriting, .completeFileProtection])
        #else
        try opened.data.write(to: url, options: [.withoutOverwriting])
        #endif
        return url
    }

    static func removeTemporaryCopy(_ url: URL?) {
        guard let url else { return }
        let folder = url.deletingLastPathComponent()
        guard folder.deletingLastPathComponent().standardizedFileURL == AttachmentFiles.openCopiesDirectory.standardizedFileURL else { return }
        try? FileManager.default.removeItem(at: folder)
    }

    /// Rename changes only the item title (owner decision 2026-10-29); the stored file name stays.
    static func rename(id: String, title: String, store: any ItemStore, clock: any UnixClock) -> SaveResult {
        do {
            var snap = try store.load()
            guard let current = snap.records[id] else { return .unchanged }
            guard let renamed = AttachmentDocuments.renamed(current, title: title, now: clock.now) else { return .invalid }
            snap.records[id] = renamed
            try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
            return .saved
        } catch {
            return .failed
        }
    }

    /// "2.4 MB" for the screen.
    static func sizeText(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }
}
