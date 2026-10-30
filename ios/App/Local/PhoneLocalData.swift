import Foundation
import Observation
import AppShared

/// Where the iPhone's never-synced data lives (Recently deleted, reminders): the same `LocalData` schema the
/// Mac keeps in `MacLocalStore`. Tests use `InMemoryPhoneLocal`.
@MainActor
protocol PhoneLocalHosting: AnyObject {
    /// The current data, nil while it is not open.
    var localData: LocalData? { get }
    /// Validates and saves `data`, then makes it current. Throws (and changes nothing) when it can't be saved.
    func commitLocalData(_ data: LocalData) throws
}

/// `local-data.bin` in the vault directory, sealed with AES-GCM under a key derived from the vault's local key
/// (a different HKDF label from the Mac's). It never syncs and is deleted with the vault (Erase removes the
/// directory). A file that can't be read is set aside as `local-data.bin.bad.<seconds>` and starts empty, so it
/// can never block unlock; if it can't be moved aside, saves are refused rather than overwrite it.
@MainActor @Observable
final class PhoneLocalData: PhoneLocalHosting {
    nonisolated static let fileName = "local-data.bin"
    nonisolated static let badFilePrefix = "local-data.bin.bad."
    nonisolated static let info = Array("localgatekeys|ios-local-data|v1".utf8)
    nonisolated static let aad = Array("localgatekeys|ios-local-data|v1".utf8)
    nonisolated static let formatVersion: UInt8 = 1
    nonisolated static let resetMessage = String(localized: "Recently deleted and reminders on this iPhone couldn't be read and were reset.")

    enum Failure: Error { case format, unreadableFileInPlace }

    private(set) var localData: LocalData?
    /// Set when the stored file couldn't be read (shown once in Settings › Recently deleted).
    private(set) var loadMessage: String?

    @ObservationIgnored let fileURL: URL
    @ObservationIgnored private let key: [UInt8]
    @ObservationIgnored private let random: any RandomSource
    @ObservationIgnored private let clock: () -> Date
    @ObservationIgnored private var blocked = false

    init(directory: URL, key: [UInt8], random: any RandomSource = SystemRandomSource(), clock: @escaping () -> Date = Date.init) {
        fileURL = directory.appendingPathComponent(Self.fileName)
        self.key = key; self.random = random; self.clock = clock
        load()
    }

    /// The local data of an unlocked `LocalStore` (nil for any other store, e.g. in tests).
    static func open(for store: any ItemStore) -> PhoneLocalData? {
        guard let local = store as? LocalStore else { return nil }
        return PhoneLocalData(directory: local.directory, key: local.derivedKey(info: info))
    }

    private func load() {
        let fm = FileManager.default
        guard fm.fileExists(atPath: fileURL.path) else { localData = .empty; return }
        do {
            localData = try decode(Array(try Data(contentsOf: fileURL)))
        } catch {
            let now = Int64(clock().timeIntervalSince1970)
            let dir = fileURL.deletingLastPathComponent()
            var bad = dir.appendingPathComponent(Self.badFilePrefix + "\(now)")
            var n = 1
            while fm.fileExists(atPath: bad.path) { bad = dir.appendingPathComponent(Self.badFilePrefix + "\(now)-\(n)"); n += 1 }
            if (try? fm.moveItem(at: fileURL, to: bad)) == nil { blocked = true }
            localData = .empty
            loadMessage = Self.resetMessage
        }
    }

    func commitLocalData(_ data: LocalData) throws {
        guard !blocked else { throw Failure.unreadableFileInPlace }
        let valid = try data.validated()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let plain = Array(try encoder.encode(valid))
        let nonce = random.bytes(count: 12)
        let sealed = try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: plain, aad: Self.aad)
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data([Self.formatVersion] + nonce + sealed).write(to: fileURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        localData = valid
    }

    private func decode(_ bytes: [UInt8]) throws -> LocalData {
        guard bytes.count > 1 + 12 + 16, bytes[0] == Self.formatVersion else { throw Failure.format }
        let nonce = Array(bytes[1..<13])
        let plain = try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: Array(bytes[13...]), aad: Self.aad)
        return try JSONDecoder().decode(LocalData.self, from: Data(plain)).validated()
    }
}

/// Local data in memory only (tests and previews).
@MainActor @Observable
final class InMemoryPhoneLocal: PhoneLocalHosting {
    private(set) var localData: LocalData?
    @ObservationIgnored var failSaves = false
    init(_ data: LocalData = .empty) { localData = data }
    func commitLocalData(_ data: LocalData) throws {
        if failSaves { throw LocalDataError.invalid("save failed") }
        localData = try data.validated()
    }
}
