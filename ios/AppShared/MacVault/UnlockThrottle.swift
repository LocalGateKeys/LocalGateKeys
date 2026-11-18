#if os(macOS)
import Foundation
import CryptoKit
import Security

/// Small records kept outside the vault folder (Windows `outside_marks`), so putting back a copy of the folder does not
/// reset the unlock throttle. Production: `KeychainThrottleMarks`; tests: a memory store.
public protocol ThrottleMarkStoring: Sendable {
    /// The value, or nil when there is none; throws when it cannot be read.
    func read(_ name: String) throws -> Data?
    func write(_ name: String, _ data: Data) throws
    func delete(_ name: String) throws
}

/// Keychain generic passwords in the shared access group (the Mac app and its AutoFill extension read the same marks),
/// readable after the first unlock without user presence: they hold a failure count and a date, never a secret.
public struct KeychainThrottleMarks: ThrottleMarkStoring {
    public static let service = "com.localgatekeys.throttle-mark"
    let accessGroup: String?
    public init(accessGroup: String?) { self.accessGroup = accessGroup }

    private func base(_ name: String) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Self.service,
                                kSecAttrAccount as String: name, kSecUseDataProtectionKeychain as String: true]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    public func read(_ name: String) throws -> Data? {
        var q = base(name)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecItemNotFound { return nil }
        guard st == errSecSuccess, let d = out as? Data else { throw CocoaError(.fileReadUnknown) }
        return d
    }

    public func write(_ name: String, _ data: Data) throws {
        let st = SecItemUpdate(base(name) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if st == errSecSuccess { return }
        guard st == errSecItemNotFound else { throw CocoaError(.fileWriteUnknown) }
        var q = base(name)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(q as CFDictionary, nil) == errSecSuccess else { throw CocoaError(.fileWriteUnknown) }
    }

    public func delete(_ name: String) throws {
        let st = SecItemDelete(base(name) as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw CocoaError(.fileWriteUnknown) }
    }
}

/// Desktop unlock throttle: the first 5 failures are free, then the wait doubles from 2 s up to 60 s.
/// A success resets it. Persisted in the vault directory as `throttle.json`, shared by the Mac app and its
/// AutoFill extension: every update is a read-modify-write under an `flock` on `throttle.lock`, written
/// atomically, so neither process loses the other's failures.
///
/// Each failure also raises a high-water mark kept outside the folder (`markStore`: a Keychain item named after the
/// vault folder's path, Windows `outside_marks`), and the state read is the larger of the two, so copying the folder
/// before guessing and putting it back no longer resets the count. A missing or unreadable mark falls back to the file
/// (never a lock-out, never lower); a malformed one fails closed like a corrupt file. A success clears both.
public struct UnlockThrottle: Codable, Equatable, Sendable {
    public static let freeFailures = 5
    public static let firstDelay: TimeInterval = 2
    public static let maxDelay: TimeInterval = 60
    public static let fileName = "throttle.json"
    public static let lockFileName = "throttle.lock"
    /// Desktop THROTTLE_FAIL_CLOSED_FAILURES: an unreadable throttle file counts as this many failures.
    public static let failClosedFailures = 10

    public private(set) var failures: Int = 0
    public private(set) var lastFailure: Date?

    enum CodingKeys: String, CodingKey { case failures, lastFailure = "last_failure" }

    public init() {}
    init(failures: Int, lastFailure: Date?) { self.failures = failures; self.lastFailure = lastFailure }

    public mutating func recordFailure(at date: Date) { failures += 1; lastFailure = date }
    public mutating func recordSuccess() { failures = 0; lastFailure = nil }

    /// The wait after the latest failure, or nil while failures are still free.
    public var delay: TimeInterval? {
        let over = failures - Self.freeFailures
        guard over >= 1 else { return nil }
        let exp = min(over - 1, 6)   // 2·2^5 = 64 > 60, so capping the exponent avoids overflow
        return min(Self.firstDelay * pow(2, Double(exp)), Self.maxDelay)
    }

    /// When the next attempt is allowed, or nil if there is no wait.
    public func waitUntil() -> Date? {
        guard let delay, let lastFailure else { return nil }
        return lastFailure.addingTimeInterval(delay)
    }


    public func save(to directory: URL) throws {
        let enc = JSONEncoder()
        enc.outputFormatting = .sortedKeys
        enc.dateEncodingStrategy = .secondsSince1970
        let url = directory.appendingPathComponent(Self.fileName)
        try enc.encode(self).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    /// Reads the shared throttle under the file lock, lets `body` change it, and saves it if it changed.
    /// The lock is held only for this read-modify-write, never across Argon2: two processes can each run one
    /// guess in parallel, and both outcomes are recorded.
    ///
    /// Fails closed: a corrupt file counts as `failClosedFailures` failures (persisted, so the wait runs from
    /// the first time it was seen). If the lock cannot be taken or the file cannot be read or written, the
    /// state is kept in a per-process backstop instead (starting fail-closed when nothing was readable), so
    /// a blocked or unwritable throttle never disables it. The effective state is the file merged with any
    /// failures this process could not persist (the larger count and the later failure).
    @discardableResult
    public static func update<T>(in directory: URL, now: Date, _ body: (inout UnlockThrottle) -> T) -> T {
        let key = directory.standardizedFileURL.path
        return backstopLock.withLock {
            let pending = backstop[key]
            let marks = markStore
            let mark = marks.map { readMark($0, directory: directory, now: now) } ?? .absent
            do {
                return try withFileLock(directory) {
                    let (file, corrupt) = read(directory, now: now)
                    // A corrupt read is fail-closed "at now"; once this process holds a state for the directory,
                    // keep that one, so a corrupt file that cannot be rewritten does not slide the wait forward.
                    var t = corrupt ? (pending ?? file) : merged(file, pending)
                    t = merged(t, mark.throttle)
                    let result = body(&t)
                    if t != file || corrupt {
                        do { try t.save(to: directory); backstop[key] = nil } catch { backstop[key] = t }
                    } else {
                        backstop[key] = nil
                    }
                    if let marks { syncMark(marks, directory: directory, t, was: mark) }
                    return result
                }
            } catch {
                var t = merged(pending ?? UnlockThrottle(failures: failClosedFailures, lastFailure: now), mark.throttle)
                let result = body(&t)
                backstop[key] = t
                if let marks { syncMark(marks, directory: directory, t, was: mark) }
                return result
            }
        }
    }

    // MARK: outside mark (audit 2026-11-10, Windows `outside_marks`)

    /// Where the marks live. Nil (tests, and any process that never sets it): the throttle uses its file only. The Mac
    /// app and its AutoFill extension set the Keychain store at launch.
    public static var markStore: (any ThrottleMarkStoring)? {
        get { markLock.withLock { _markStore } }
        set { markLock.withLock { _markStore = newValue } }
    }
    nonisolated(unsafe) private static var _markStore: (any ThrottleMarkStoring)?
    private static let markLock = NSLock()

    /// The mark's name for a vault folder: a hash of its standardized path, so the name says nothing about the folder.
    public static func markName(for directory: URL) -> String {
        let digest = SHA256.hash(data: Data(("unlock-throttle|" + directory.standardizedFileURL.path).utf8))
        return "throttle/" + digest.map { String(format: "%02x", $0) }.joined()
    }

    enum Mark: Equatable {
        case absent
        case value(UnlockThrottle)
        /// Malformed: read as `failClosedFailures` at the time it was first seen, and rewritten.
        case malformed(UnlockThrottle)

        var throttle: UnlockThrottle? {
            switch self {
            case .absent: nil
            case .value(let t), .malformed(let t): t
            }
        }
    }

    static func readMark(_ store: any ThrottleMarkStoring, directory: URL, now: Date) -> Mark {
        guard let data = try? store.read(markName(for: directory)) else { return .absent }   // none, or unreadable
        if let t = try? decoder.decode(UnlockThrottle.self, from: data), t.failures >= 0 { return .value(t) }
        return .malformed(UnlockThrottle(failures: failClosedFailures, lastFailure: now))
    }

    /// Keeps the mark at the state just written: cleared by a success, raised (never lowered) by a failure. Best
    /// effort: a mark that cannot be written leaves the file and the per-process backstop in charge.
    static func syncMark(_ store: any ThrottleMarkStoring, directory: URL, _ t: UnlockThrottle, was: Mark) {
        let name = markName(for: directory)
        if t.failures == 0 {
            if was != .absent { try? store.delete(name) }
            return
        }
        if case .value(let old) = was, old == t { return }
        let enc = JSONEncoder()
        enc.outputFormatting = .sortedKeys
        enc.dateEncodingStrategy = .secondsSince1970
        if let data = try? enc.encode(t) { try? store.write(name, data) }
    }

    /// The shared throttle as it is now (see `update`).
    public static func current(in directory: URL, now: Date) -> UnlockThrottle {
        update(in: directory, now: now) { $0 }
    }

    /// Per-process failures that could not be written to `throttle.json`, by vault directory.
    nonisolated(unsafe) private static var backstop: [String: UnlockThrottle] = [:]
    private static let backstopLock = NSLock()

    static func merged(_ file: UnlockThrottle, _ pending: UnlockThrottle?) -> UnlockThrottle {
        guard let pending else { return file }
        let last: Date? = switch (file.lastFailure, pending.lastFailure) {
        case let (a?, b?): max(a, b)
        case let (a, b): a ?? b
        }
        return UnlockThrottle(failures: max(file.failures, pending.failures), lastFailure: last)
    }

    /// A missing file is a fresh start (first run). An unreadable or corrupt one fails closed: it counts as
    /// `failClosedFailures` failures at `now`, so the wait applies. A writer of the vault directory could still
    /// delete the file; accepted, since they could equally copy master-key.json and guess offline.
    private static func read(_ directory: URL, now: Date) -> (throttle: UnlockThrottle, corrupt: Bool) {
        let path = directory.appendingPathComponent(fileName).path
        guard FileManager.default.fileExists(atPath: path) else { return (UnlockThrottle(), false) }
        if let data = FileManager.default.contents(atPath: path),
           let t = try? decoder.decode(UnlockThrottle.self, from: data), t.failures >= 0 { return (t, false) }
        return (UnlockThrottle(failures: failClosedFailures, lastFailure: now), true)
    }

    private static func withFileLock<T>(_ directory: URL, _ body: () throws -> T) throws -> T {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fd = Darwin.open(directory.appendingPathComponent(lockFileName).path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }

    private static var decoder: JSONDecoder {
        let d = JSONDecoder(); d.dateDecodingStrategy = .secondsSince1970; return d
    }
}
#endif
