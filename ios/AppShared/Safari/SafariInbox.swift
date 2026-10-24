import Foundation
import LGKCore

/// One login saved from Safari and waiting for the app to import it.
public struct SafariInboxEntry: Equatable, Sendable {
    /// The lowercase UUID of its file `<id>.blob`.
    public let id: String
    public let origin: String
    public let username: String
    public let password: String
    /// Unix seconds on the phone clock when it was saved.
    public let capturedAt: Int64

    public init(id: String, origin: String, username: String, password: String, capturedAt: Int64) {
        self.id = id; self.origin = origin; self.username = username; self.password = password
        self.capturedAt = capturedAt
    }
}

public enum SafariInboxError: Error, Equatable, Sendable {
    /// `SafariInbox.capacity` entries are already waiting.
    case full
    /// Empty username or password.
    case invalid
    /// The entry could not be sealed or written.
    case unavailable
}

/// The sealed inbox `<app group>/SafariSave/inbox/`: one `<uuid>.blob` per login saved from Safari, read
/// and emptied by the app at its next unlock.
///
/// Each blob is `nonce(12) || AES-256-GCM` under the device-only inbox key, AAD
/// `"localgatekeys|safari-inbox|v1|" + uuid` (so a blob renamed to another uuid fails), over the canonical
/// JSON `{"captured_at","origin","password","username"}`. The origin is stored as given: callers
/// canonicalise it first.
public struct SafariInbox: Sendable {
    public static let capacity = 50
    /// Entries older than this (seconds, 7 days) are deleted unread. Short (audit 2026-10-24 L-18, was 30
    /// days): a capture waits only for the next unlock, where the app asks before importing it.
    public static let lifetime: Int64 = 604_800
    public static let directoryName = "inbox"
    static let fileExtension = "blob"
    static let aadPrefix = "localgatekeys|safari-inbox|v1|"

    /// The inbox folder itself.
    public let directory: URL
    private let key: [UInt8]
    private let now: @Sendable () -> Int64
    private let random: any RandomSource

    public init(directory: URL, key: [UInt8], now: @escaping @Sendable () -> Int64 = { SystemClock().now },
                random: any RandomSource = SystemRandomSource()) {
        self.directory = directory; self.key = key; self.now = now; self.random = random
    }

    /// `<app group>/SafariSave/inbox` (the inbox folder itself is created on the first `add`).
    public static func defaultDirectory() throws -> URL {
        try SafariSaveFiles.directory().appendingPathComponent(directoryName, isDirectory: true)
    }

    /// Seals a login into a new `<uuid>.blob`. Expires old entries first; a capture identical to a waiting
    /// one (same origin, username and password) writes nothing. Throws `.invalid` for an empty username
    /// or password, `.full` when `capacity` entries (damaged ones included) are waiting, `.unavailable`
    /// when it cannot be sealed or written.
    public func add(origin: String, username: String, password: String) throws {
        guard !username.isEmpty, !password.isEmpty else { throw SafariInboxError.invalid }
        expire()
        let waiting = entries()
        if waiting.entries.contains(where: { $0.origin == origin && $0.username == username && $0.password == password }) {
            return
        }
        guard waiting.entries.count + waiting.damaged.count < Self.capacity else { throw SafariInboxError.full }
        let id = UUID().uuidString.lowercased()
        do {
            let plain = try CanonicalJSON.encode(.object([
                "captured_at": .int(now()), "origin": .string(origin),
                "password": .string(password), "username": .string(username),
            ]), dialect: .utf8)
            let blob = try SealedBlob.seal(plain, key: key, aad: Self.aadPrefix + id, random: random)
            try SafariSaveFiles.writeAtomically(blob, to: url(of: id))
        } catch {
            throw SafariInboxError.unavailable
        }
    }

    /// Every waiting entry, oldest `capturedAt` first, then by id; and the ids of blobs that do not open
    /// (tampered, renamed, another key) or do not decode. Files other than `<lowercase uuid>.blob`, such as
    /// temp files of a write in progress, are ignored. A missing or unreadable folder is empty.
    public func entries() -> (entries: [SafariInboxEntry], damaged: [String]) {
        var good: [SafariInboxEntry] = []
        var damaged: [String] = []
        for (id, url) in blobFiles() {
            if let entry = read(id: id, url: url) { good.append(entry) } else { damaged.append(id) }
        }
        good.sort { $0.capturedAt != $1.capturedAt ? $0.capturedAt < $1.capturedAt : $0.id < $1.id }
        return (good, damaged.sorted())
    }

    /// Deletes the blobs of `ids`. Ids that are not lowercase UUIDs (and so name no inbox file) are skipped.
    public func remove(ids: [String]) {
        for id in ids where Self.isEntryID(id) {
            try? FileManager.default.removeItem(at: url(of: id))
        }
    }

    /// Deletes entries saved more than `lifetime` seconds ago. An entry from the future (the clock moved
    /// back) is kept, and expires `lifetime` after its own time. Damaged blobs are left for the app.
    public func expire() {
        let t = now()
        remove(ids: entries().entries.filter { Self.isExpired(capturedAt: $0.capturedAt, now: t) }.map(\.id))
    }

    // MARK: files

    static func isExpired(capturedAt: Int64, now: Int64) -> Bool {
        guard capturedAt < now else { return false }
        let (age, overflow) = now.subtractingReportingOverflow(capturedAt)
        return overflow || age > lifetime
    }

    /// A lowercase, hyphenated UUID: the only names `add` writes.
    static func isEntryID(_ s: String) -> Bool {
        guard let uuid = UUID(uuidString: s) else { return false }
        return uuid.uuidString.lowercased() == s
    }

    private func url(of id: String) -> URL {
        directory.appendingPathComponent("\(id).\(Self.fileExtension)", isDirectory: false)
    }

    private func blobFiles() -> [(id: String, url: URL)] {
        guard let urls = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil,
                                                                       options: [.skipsHiddenFiles]) else { return [] }
        return urls.compactMap { url -> (id: String, url: URL)? in
            guard url.pathExtension == Self.fileExtension else { return nil }
            let id = url.deletingPathExtension().lastPathComponent
            return Self.isEntryID(id) ? (id, url) : nil
        }
    }

    /// nil when the blob cannot be read, opened or decoded.
    private func read(id: String, url: URL) -> SafariInboxEntry? {
        guard let data = try? Data(contentsOf: url),
              let plain = try? SealedBlob.open(Array(data), key: key, aad: Self.aadPrefix + id),
              case .object(let o)? = try? CanonicalJSON.parse(plain),
              Set(o.keys) == ["captured_at", "origin", "password", "username"],
              case .int(let capturedAt)? = o["captured_at"], case .string(let origin)? = o["origin"],
              case .string(let password)? = o["password"], case .string(let username)? = o["username"]
        else { return nil }
        return SafariInboxEntry(id: id, origin: origin, username: username, password: password, capturedAt: capturedAt)
    }
}
