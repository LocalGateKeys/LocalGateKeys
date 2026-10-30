import Foundation
import Darwin
import LGKCore

/// The Mac-only data file `local-data.bin` in the vault directory: Recently deleted, activity, reminders and
/// collections. It never syncs. Sealed with AES-GCM under a key derived from the vault's local key; a file
/// that can't be read (corrupt, another vault's key) is set aside as `local-data.bin.bad` and starts empty,
/// so it can never block unlock.
@MainActor
final class MacLocalStore {
    static let fileName = "local-data.bin"
    /// Unreadable files are kept as `local-data.bin.bad.<unix seconds>`, so older evidence is never replaced.
    static let badFilePrefix = "local-data.bin.bad."
    static let info = Array("localgatekeys|mac-local-data|v1".utf8)
    static let aad = Array("localgatekeys|mac-local-data|v1".utf8)
    static let formatVersion: UInt8 = 1
    static let resetMessage = String(localized: "Recently deleted, reminders and activity on this Mac couldn't be read and were reset.")

    enum Failure: Error { case format, io(String), unreadableFileInPlace }

    let directory: URL
    private let key: [UInt8]
    private let random: any RandomSource
    private let clock: () -> Date
    /// Set when an unreadable file couldn't be moved aside: saving would overwrite it, so saves are refused.
    private var blocked = false
    /// True when an unreadable file is still in place (it could not be moved aside): nothing may overwrite it.
    var isBlocked: Bool { blocked }
    #if DEBUG
    /// Test seam: moving an unreadable file aside fails.
    nonisolated(unsafe) static var failMoveAside = false
    #endif

    init(directory: URL, localKey: [UInt8], random: any RandomSource = SystemRandomSource(),
         clock: @escaping () -> Date = Date.init) {
        self.clock = clock
        self.directory = directory
        self.key = CryptoBox.hkdf(ikm: localKey, salt: [], info: Self.info, length: 32)
        self.random = random
    }

    var fileURL: URL { directory.appendingPathComponent(Self.fileName) }

    /// The stored data (starter collections added on first use), or empty data and the reset message when the
    /// file can't be read. Never throws.
    func load() -> (LocalData, message: String?) {
        let fm = FileManager.default
        let now = Int64(clock().timeIntervalSince1970)
        var fresh = LocalData.empty
        fresh.ensureStarterCollections(now: now)
        // Missing (never written) is the only case that starts empty without a message.
        guard fm.fileExists(atPath: fileURL.path) else {
            return (fresh, nil)
        }
        do {
            let bytes = try Data(contentsOf: fileURL)   // unreadable (permissions, I/O) is treated like corrupt
            return (try decode(Array(bytes)), nil)
        } catch {
            var bad = directory.appendingPathComponent(Self.badFilePrefix + "\(now)")
            var n = 1
            while fm.fileExists(atPath: bad.path) { bad = directory.appendingPathComponent(Self.badFilePrefix + "\(now)-\(n)"); n += 1 }
            var skipMove = false
            #if DEBUG
            skipMove = Self.failMoveAside
            #endif
            let moved = !skipMove && (try? fm.moveItem(at: fileURL, to: bad)) != nil
            if !moved { blocked = true }
            return (fresh, Self.resetMessage)
        }
    }

    /// Validates, seals under a fresh nonce and writes atomically.
    func save(_ data: LocalData) throws {
        guard !blocked else { throw Failure.unreadableFileInPlace }
        let valid = try data.validated()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let plain = Array(try encoder.encode(valid))
        let nonce = random.bytes(count: 12)
        let sealed = try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: plain, aad: Self.aad)
        try writeDurably([Self.formatVersion] + nonce + sealed, to: fileURL)
    }

    private func decode(_ bytes: [UInt8]) throws -> LocalData {
        guard bytes.count > 1 + 12 + 16, bytes[0] == Self.formatVersion else { throw Failure.format }
        let nonce = Array(bytes[1..<13])
        let plain = try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: Array(bytes[13...]), aad: Self.aad)
        return try JSONDecoder().decode(LocalData.self, from: Data(plain)).validated()
    }

    /// Temp file in the same directory, full sync, rename over the target, sync the directory (as LocalStore).
    private func writeDurably(_ bytes: [UInt8], to url: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let tmp = directory.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        do {
            let fd = Darwin.open(tmp.path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
            guard fd >= 0 else { throw Failure.io("create") }
            defer { close(fd) }
            var off = 0
            while off < bytes.count {
                let w = bytes[off...].withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
                guard w > 0 else { throw Failure.io("write") }
                off += w
            }
            if fcntl(fd, F_FULLFSYNC) != 0 && fsync(fd) != 0 { throw Failure.io("sync") }
            guard rename(tmp.path, url.path) == 0 else { throw Failure.io("rename") }
            let dfd = Darwin.open(directory.path, O_RDONLY)
            if dfd >= 0 { _ = fcntl(dfd, F_FULLFSYNC); close(dfd) }
        } catch { try? FileManager.default.removeItem(at: tmp); throw error }
    }
}
