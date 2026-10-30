import Foundation
import Darwin
import AppSharedMac

/// What a Windows full backup carries that the Mac vault has no place for, kept so that a Windows backup restored
/// on this Mac and backed up again loses nothing: the catalog's non-record fields (`trash`, `history`, `templates`,
/// `attachments` with their keys, `license`, …), the items that never sync (`document`), the profile's
/// `settings.json` and the backup's profile name, in `desktop-profile.bin` (sealed like `local-data.bin`), and the
/// attachment sidecars in `Attachments/<id>.blob` (already encrypted by Windows with keys held in the catalog).
/// Nothing here syncs.
@MainActor
final class DesktopProfileStore {
    nonisolated static let fileName = "desktop-profile.bin"
    nonisolated static let attachmentsName = "Attachments"
    nonisolated static let info = Array("localgatekeys|mac-desktop-profile|v1".utf8)
    nonisolated static let aad = Array("localgatekeys|mac-desktop-profile|v1".utf8)
    nonisolated static let formatVersion: UInt8 = 1

    struct Contents: Equatable, Sendable {
        /// Catalog fields other than the records (`DesktopVaultFile.seal` `settings:`).
        var payload: [String: JSONValue] = [:]
        /// Records of kinds that never sync (Windows documents), passed through to the next backup.
        var unsynced: [JSONValue] = []
        /// Windows `settings.json`, as restored.
        var settings: Data?
        var profileName: String?
        static let empty = Contents()
    }

    enum Failure: Error, Equatable { case format, io(String) }

    /// The derived file key, zeroed when the store goes (lock). The local key itself is never kept.
    final class KeyBox: @unchecked Sendable {
        var bytes: [UInt8]
        init(_ bytes: [UInt8]) { self.bytes = bytes }
        deinit { for i in bytes.indices { bytes[i] = 0 } }
    }

    let directory: URL
    private let keyBox: KeyBox
    private var key: [UInt8] { keyBox.bytes }
    private let random: any RandomSource

    init(directory: URL, localKey: [UInt8], random: any RandomSource = SystemRandomSource()) {
        self.directory = directory
        self.keyBox = KeyBox(CryptoBox.hkdf(ikm: localKey, salt: [], info: Self.info, length: 32))
        self.random = random
    }

    var fileURL: URL { directory.appendingPathComponent(Self.fileName) }
    var attachmentsURL: URL { directory.appendingPathComponent(Self.attachmentsName, isDirectory: true) }

    /// The kept contents; empty when nothing was ever restored.
    func load() throws -> Contents {
        try Self.read(fileURL, key: key)
    }

    /// The attachment sidecars by id, memory-mapped.
    func attachments() throws -> [(id: String, data: Data)] { try Self.attachments(in: attachmentsURL) }

    /// The sealed bytes of `contents`.
    func seal(_ contents: Contents) throws -> Data {
        let o: [String: JSONValue] = [
            "v": .int(1), "payload": .object(contents.payload), "unsynced": .array(contents.unsynced),
            "settings": contents.settings.map { .string($0.base64EncodedString()) } ?? .null,
            "profile_name": contents.profileName.map { .string($0) } ?? .null,
        ]
        let plain = try CanonicalJSON.encode(.object(o), dialect: .utf8)
        let nonce = random.bytes(count: 12)
        return Data([Self.formatVersion] + nonce + (try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: plain, aad: Self.aad)))
    }

    nonisolated static let recordsAAD = Array("localgatekeys|mac-desktop-profile|records|v1".utf8)

    /// Store records (a staged restore, a safety copy), sealed under the same derived key.
    func sealRecords(_ records: [String: JSONValue], revision: Int64) throws -> Data {
        let plain = try CanonicalJSON.encode(.object(["v": .int(1), "revision": .int(revision), "records": .object(records)]),
                                             dialect: .utf8)
        let nonce = random.bytes(count: 12)
        return Data([Self.formatVersion] + nonce + (try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: plain, aad: Self.recordsAAD)))
    }

    func openRecords(_ url: URL) throws -> (records: [String: JSONValue], revision: Int64) {
        guard let bytes = try? Array(Data(contentsOf: url)) else { throw Failure.io("read") }
        guard bytes.count > 1 + 12 + 16, bytes[0] == Self.formatVersion else { throw Failure.format }
        let plain = try CryptoBox.openGCM(key: key, nonce: Array(bytes[1..<13]), ciphertext: Array(bytes[13...]), aad: Self.recordsAAD)
        guard case .object(let o) = try CanonicalJSON.parse(plain), o["v"] == .int(1), case .int(let rev)? = o["revision"],
              case .object(let records)? = o["records"] else { throw Failure.format }
        return (records, rev)
    }

    /// Reads a sealed file written by `seal` (missing: empty).
    func read(_ url: URL) throws -> Contents { try Self.read(url, key: key) }

    nonisolated static func read(_ url: URL, key: [UInt8]) throws -> Contents {
        guard FileManager.default.fileExists(atPath: url.path) else { return .empty }
        guard let bytes = try? Array(Data(contentsOf: url)) else { throw Failure.io("read") }
        guard bytes.count > 1 + 12 + 16, bytes[0] == formatVersion else { throw Failure.format }
        let plain = try CryptoBox.openGCM(key: key, nonce: Array(bytes[1..<13]), ciphertext: Array(bytes[13...]), aad: aad)
        guard case .object(let o) = try CanonicalJSON.parse(plain), o["v"] == .int(1),
              case .object(let payload)? = o["payload"], case .array(let unsynced)? = o["unsynced"] else { throw Failure.format }
        var c = Contents(payload: payload, unsynced: unsynced)
        if case .string(let s)? = o["settings"] {
            guard let d = Data(base64Encoded: s) else { throw Failure.format }
            c.settings = d
        }
        if case .string(let s)? = o["profile_name"] { c.profileName = s }
        return c
    }

    nonisolated static func attachments(in folder: URL) throws -> [(id: String, data: Data)] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: folder.path) else { return [] }
        let names = try fm.contentsOfDirectory(atPath: folder.path).filter { $0.hasSuffix(".blob") }.sorted()
        return try names.map { name in
            (id: String(name.dropLast(5)), data: try Data(contentsOf: folder.appendingPathComponent(name), options: .alwaysMapped))
        }
    }
}
