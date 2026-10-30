import Foundation
import Observation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

// Secure local sharing (UX plan workstream 9, `docs/formats/LGKSHARE_V1.md`): one item as a `.lgkshare` file
// (AirDrop, share sheet, Files) or a QR code when the package is at most 2048 bytes, opened with a six-word
// code the sender reads out. Shared by the iPhone and the Mac (no UIKit / AppKit here).

enum ShareText {
    static let shareTitle = String(localized: "Share item")
    static let receiveTitle = String(localized: "Shared item")
    static let codeHint = String(localized: "Tell the other person these six words, in person or by phone. Never send them with the file.")
    static let qrHint = String(localized: "Or let them scan this code with LocalGateKeys › Receive a shared item.")
    static let expiresHint = String(localized: "The shared copy can be opened once, within 24 hours.")
    static let cannotShare = String(localized: "Passkeys and items with attached files cannot be shared.")
    static let notAShare = String(localized: "This is not a shared LocalGateKeys item.")
    static let threeWrong = String(localized: "Three wrong codes. The shared item was deleted. Ask for it to be shared again.")
    static let saved = String(localized: "The shared item was added to your vault.")
    static let needsPro = String(localized: "The free plan holds 4 items. Upgrade to Pro to add this shared item.")
    static let cannotSave = String(localized: "This item can't be saved on this device.")
    static let enterCode = String(localized: "Enter the six words the sender gave you.")

    static func from(_ sender: String) -> String { String(localized: "\(sender) shared an item with you.") }

    static func wrongCode(left: Int) -> String {
        String(localized: "That code does not open this item. Check the six words. \(left) tries left.")
    }
}

/// A sealed package ready to send: the file in a private temporary folder, deleted when the sheet closes.
struct OutgoingShare: Identifiable, Equatable {
    let id: String
    let code: String
    let fileURL: URL
    /// The package text, when it fits one QR code (`Share.qrLimit`); nil otherwise.
    let packageQRText: String?
    /// The second QR (the code), `lgkshare-code:…`.
    let codeQRText: String

    var codeWords: [String] { code.split(separator: " ").map(String.init) }
}

enum ShareOutbox {
    /// Not the item's title: the file name travels in the clear.
    static let fileName = "LocalGateKeys item.lgkshare"

    static func directory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("LocalGateKeys share", isDirectory: true)
    }

    static func make(item: VaultItem, sender: String, now: Int64, random: any RandomSource = SystemRandomSource(),
                     directory: URL = ShareOutbox.directory()) throws -> OutgoingShare {
        let code = try Share.generateCode(random: random)
        let data = try Share.seal(item: Share.withoutLocalRefs(item.record), code: code, sender: sender, now: now, random: random)
        let header = try Share.readHeader(data)
        let folder = directory.appendingPathComponent(header.id, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let file = folder.appendingPathComponent(fileName)
        #if os(iOS)
        try Data(data).write(to: file, options: [.atomic, .completeFileProtection])
        #else
        try Data(data).write(to: file, options: [.atomic])
        #endif
        return OutgoingShare(id: header.id, code: code, fileURL: file,
                             packageQRText: Share.fitsQR(data) ? String(decoding: data, as: UTF8.self) : nil,
                             codeQRText: try Share.codeQRText(code))
    }

    /// Deletes one package's temporary folder.
    static func remove(_ share: OutgoingShare) {
        try? FileManager.default.removeItem(at: share.fileURL.deletingLastPathComponent())
    }

    /// Deletes every package left over (a crash while the sheet was open); called at launch.
    static func purge(directory: URL = ShareOutbox.directory()) {
        try? FileManager.default.removeItem(at: directory)
    }
}

/// Received packages: moved into private storage, opened with the code, previewed, then saved or rejected.
/// The package is deleted after Save or Reject, after three wrong codes, or 24 h after it arrived; the
/// opened ids are kept so a package opens only once on this device.
@MainActor
@Observable
final class ShareInbox {
    struct Pending: Equatable {
        let id: String
        let sender: String
        let file: URL
    }

    enum SaveOutcome: Equatable { case saved, needsPro, failed }

    static let maxWrongCodes = 3
    static let maxOpenedIDs = 500

    private(set) var pending: Pending?
    private(set) var preview: Share.Opened?
    private(set) var message: String?
    private(set) var wrongCodes = 0

    @ObservationIgnored let directory: URL
    @ObservationIgnored let clock: any UnixClock
    /// The app's own folders: a delivered copy inside them (iOS `Documents/Inbox`) is deleted after it is read.
    @ObservationIgnored let ownedFolders: [URL]

    static func defaultDirectory() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("LocalGateKeys/incoming shares", isDirectory: true)
    }

    static func defaultOwnedFolders() -> [URL] {
        #if os(iOS)
        return FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        #else
        return []
        #endif
    }

    init(directory: URL = ShareInbox.defaultDirectory(), clock: any UnixClock = SystemClock(),
         ownedFolders: [URL] = ShareInbox.defaultOwnedFolders()) {
        self.directory = directory; self.clock = clock; self.ownedFolders = ownedFolders
        purgeExpired()
    }

    // MARK: delivery

    /// A `.lgkshare` file opened with the app (AirDrop, Files, Finder). False for any other URL.
    @discardableResult
    func deliver(fileURL url: URL) -> Bool {
        guard url.isFileURL, url.pathExtension.lowercased() == Share.fileExtension else { return false }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        guard size <= Share.maxPackage, let data = try? Data(contentsOf: url) else {
            message = ShareText.notAShare; return true
        }
        let path = url.standardizedFileURL.path
        if ownedFolders.contains(where: { path.hasPrefix($0.standardizedFileURL.path + "/") }) {
            try? FileManager.default.removeItem(at: url)   // the delivered copy; ours is in private storage
        }
        accept(Array(data))
        return true
    }

    /// A scanned QR: the package text (or a code QR, which only makes sense on the code field).
    @discardableResult
    func deliver(text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("{") else { message = ShareText.notAShare; return false }
        accept(Array(trimmed.utf8))
        return pending != nil
    }

    private func accept(_ data: [UInt8]) {
        message = nil; preview = nil; wrongCodes = 0
        let header: Share.Header
        do { header = try Share.readHeader(data) } catch let e as ShareError {
            message = e.message; return
        } catch { message = ShareText.notAShare; return }
        if openedIDs().contains(header.id) {
            message = String(localized: "This shared item was already opened on this device."); return
        }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let file = directory.appendingPathComponent(header.id + "." + Share.fileExtension)
            #if os(iOS)
            try Data(data).write(to: file, options: [.atomic, .completeFileProtection])
            #else
            try Data(data).write(to: file, options: [.atomic])
            #endif
            if let old = pending, old.file != file { try? FileManager.default.removeItem(at: old.file) }
            pending = Pending(id: header.id, sender: header.sender, file: file)
        } catch {
            message = ShareText.cannotSave
        }
    }

    // MARK: open, save, reject

    /// Opens the pending package with `code` (six words, or a scanned `lgkshare-code:` QR).
    @discardableResult
    func open(code: String) -> Bool {
        guard let pending else { return false }
        message = nil
        let text = code.trimmingCharacters(in: .whitespacesAndNewlines)
        let words: String
        do {
            words = text.hasPrefix(Share.codeQRPrefix) ? try Share.code(fromQRText: text) : try Share.normalizeCode(text)
        } catch { message = ShareText.enterCode; return false }
        guard let data = try? Data(contentsOf: pending.file) else { discard(); message = ShareText.notAShare; return false }
        do {
            let opened = try Share.open(Array(data), code: words, now: clock.now, opened: openedIDs())
            recordOpened(opened.id)
            // A kind this device can't store is refused before any preview (the kind is inside the encryption).
            if (try? Share.vaultForm(opened.item, id: "00000000-0000-4000-8000-000000000000", now: clock.now)) == nil {
                discard(); message = Share.cannotSaveHere.message
                return false
            }
            preview = opened
            return true
        } catch let e as ShareError {
            switch e.reason {
            case "wrong-code":
                wrongCodes += 1
                // Burned: the same package delivered again is refused, so the count cannot be reset.
                if wrongCodes >= Self.maxWrongCodes { recordOpened(pending.id); discard(); message = ShareText.threeWrong }
                else { message = ShareText.wrongCode(left: Self.maxWrongCodes - wrongCodes) }
            case "bad-code":
                message = e.message
            default:
                discard(); message = e.message
            }
            return false
        } catch {
            discard(); message = ShareText.notAShare
            return false
        }
    }

    /// Adds the previewed item as a new item (new id, not a favorite; policies reset by the normal form).
    /// Counts toward the free plan's limit.
    func save(store: any ItemStore, isPro: Bool, random: any RandomSource = SystemRandomSource()) -> SaveOutcome {
        guard let preview else { return .failed }
        let outcome = Self.add(preview.item, store: store, isPro: isPro, now: clock.now, random: random)
        switch outcome {
        case .saved: discard(); message = ShareText.saved
        case .needsPro: message = ShareText.needsPro
        case .failed: message = ShareText.cannotSave
        }
        return outcome
    }

    nonisolated static func add(_ item: [String: JSONValue], store: any ItemStore, isPro: Bool, now: Int64,
                                random: any RandomSource) -> SaveOutcome {
        // The same conversion as a synced peer record: Windows/Android `urls` and `fields` become `scope`/`payload`.
        guard let (ns, normal) = try? Share.vaultForm(item, id: EditorModel.uuid4(random), now: now),
              case .object(let o) = normal, case .string(let id)? = o["id"] else { return .failed }
        for _ in 0..<2 {
            guard var snap = try? store.load() else { return .failed }
            guard ItemLimit.allows(.create, snapshot: snap, isPro: isPro) else { return .needsPro }
            guard snap.records[id] == nil else { return .failed }
            snap.records[id] = Wrapper.make(ns: ns, record: normal)
            do {
                try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
                return .saved
            } catch LocalStoreError.stale {
                continue
            } catch {
                return .failed
            }
        }
        return .failed
    }

    /// Reject (or close the sheet): the package is deleted.
    func reject() { discard() }

    func clearMessage() { message = nil }

    private func discard() {
        if let pending { try? FileManager.default.removeItem(at: pending.file) }
        pending = nil; preview = nil; wrongCodes = 0
    }

    /// Packages older than 24 h (by arrival) are deleted.
    func purgeExpired() {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.contentModificationDateKey]) else { return }
        let cutoff = Date(timeIntervalSince1970: TimeInterval(clock.now - Share.lifetime))
        for f in files where f.pathExtension == Share.fileExtension {
            let date = (try? f.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            if date < cutoff, f != pending?.file { try? fm.removeItem(at: f) }
        }
    }

    // MARK: opened list

    private var openedFile: URL { directory.appendingPathComponent("opened.json") }

    func openedIDs() -> Set<String> {
        guard let data = try? Data(contentsOf: openedFile),
              let ids = try? JSONDecoder().decode([String].self, from: data) else { return [] }
        return Set(ids)
    }

    private func recordOpened(_ id: String) {
        var ids = (try? JSONDecoder().decode([String].self, from: (try? Data(contentsOf: openedFile)) ?? Data())) ?? []
        if !ids.contains(id) { ids.append(id) }
        if ids.count > Self.maxOpenedIDs { ids.removeFirst(ids.count - Self.maxOpenedIDs) }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try? JSONEncoder().encode(ids).write(to: openedFile, options: [.atomic])
    }
}
