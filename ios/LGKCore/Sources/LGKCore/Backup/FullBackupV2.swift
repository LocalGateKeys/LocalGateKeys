import Crypto
import Foundation

/// What `FullBackupV2.inspect` can tell without the password (the public header).
public struct FullBackupInfo: Equatable, Sendable {
    public let kdf: FullBackupV2.KDF
    public let entryCount: Int
    public let bytes: Int
}

/// One attachment sidecar from a backup: still encrypted with the vault's attachment key, opaque here.
public struct FullBackupAttachment: Equatable, Sendable {
    public let id: String
    public let data: Data
    public let sidecarSize: Int
}

/// Every member of a backup, authenticated (manifest, AES-GCM tag, size and SHA-256) before any was parsed.
public struct FullBackupContents: Equatable, Sendable {
    public let profileName: String
    public let createdAt: Int64?
    /// The Windows `vault.json` envelope, sealed with the master password (`DesktopVaultFile`).
    public let vault: Data
    /// Windows `settings.json` (a JSON object of at most 1 MiB), as stored.
    public let settings: Data
    /// Windows `vault.generation.json` (rollback anchor), when the backup has one.
    public let generation: Data?
    /// Sorted by member order (Windows writes them sorted by id).
    public let attachments: [FullBackupAttachment]
    public let entries: [FullBackupEntry]
}

/// The Windows full backup v2 container (`backup.py` `export_full_backup` / `_full_read_container`), byte for byte:
/// a classic stored zip holding `header.json` (public: format, version, KDF, cipher, entry count), `manifest.bin`
/// (AES-256-GCM, AAD = `FULL_BACKUP_AAD + header`) and one `data/NNNNNNNN.bin` per entry (AES-256-GCM, AAD =
/// `FULL_BACKUP_AAD + header + SHA-256(manifest) + member name`), each blob `nonce(12) || ciphertext || tag(16)`.
/// The key is Argon2id(backup password) with the header's salt. No zip64, no compressed or encrypted zip members.
public enum FullBackupV2 {
    public static let format = "localgatekeys-full-backup"
    public static let version: Int64 = 2
    static let aad = Array("localgatekeys|encrypted-full-profile-backup|v2".utf8)
    /// 2 GiB; clamped to `Int.max` on 32-bit watchOS devices (arm64_32), where 2 GiB does not fit in `Int`.
    public static let maxBackupBytes = Int(clamping: Int64(2) * 1024 * 1024 * 1024)
    public static let maxEntries = 20_005
    public static let maxMemberBytes = 32 * 1024 * 1024
    public static let maxManifestBytes = 32 * 1024 * 1024
    public static let maxHeaderBytes = 64 * 1024
    public static let maxSettingsBytes = 1024 * 1024

    /// Argon2id parameters. New backups use `.default` (the vault default); readers accept t 1-10, p 1-16 and the
    /// vault memory range (8-512 MiB), as Windows does, and refuse anything else before deriving.
    public struct KDF: Equatable, Sendable {
        public var timeCost: UInt32
        public var memoryKiB: UInt32
        public var parallelism: UInt32
        public init(timeCost: UInt32, memoryKiB: UInt32, parallelism: UInt32) {
            self.timeCost = timeCost; self.memoryKiB = memoryKiB; self.parallelism = parallelism
        }
        public static let `default` = KDF(timeCost: 3, memoryKiB: 65536, parallelism: 4)

        var isAccepted: Bool {
            (1...10).contains(timeCost) && (8 * 1024...512 * 1024).contains(memoryKiB) && (1...16).contains(parallelism)
        }
    }

    // MARK: - write

    /// A new full backup. `settings` is the profile's `settings.json` (a JSON object); `attachments` are the
    /// encrypted sidecars by id. `progress` gets `("export", done, total)` per entry; `cancel` is polled before every
    /// entry and before returning, and a cancelled write returns nothing. `kdf` other than `.default` is for tests.
    public static func write(vault: Data, settings: Data, attachments: [(id: String, data: Data)], password: String,
                             random: any RandomSource, progress: (String, Int, Int) -> Void, cancel: () -> Bool,
                             generation: Data? = nil, profileName: String, createdAt: Int64? = nil,
                             kdf: KDF = .default) throws -> Data {
        func check() throws { if cancel() { throw FullBackupError.cancelled } }
        try check()
        guard vault.count <= maxMemberBytes else { throw FullBackupError.invalid("Vault is too large") }
        _ = try FullBackupManifest.object(Array(vault), label: "Vault")
        guard settings.count <= maxSettingsBytes else { throw FullBackupError.invalid("Profile settings are too large") }
        _ = try FullBackupManifest.object(Array(settings), label: "Profile settings")
        var rows: [(kind: FullBackupEntry.Kind, target: String, data: Data, id: String?, sidecar: Int?)] = [
            (.vault, "vault.json", vault, nil, nil), (.settings, "settings.json", settings, nil, nil),
        ]
        if let generation {
            guard generation.count <= 64 * 1024 else { throw FullBackupError.invalid("Vault generation metadata is too large") }
            try FullBackupManifest.validateGeneration(Array(generation))
            rows.append((.generation, "generation.json", generation, nil, nil))
        }
        var sidecars: [(id: String, data: Data, size: Int)] = []
        for a in attachments {
            guard let id = FullBackupManifest.canonicalUUID(a.id), id == a.id.lowercased() else {
                throw FullBackupError.invalid("Attachment sidecar ID is malformed")
            }
            guard a.data.count <= maxMemberBytes else { throw FullBackupError.invalid("Attachment sidecar is too large") }
            sidecars.append((id, a.data, try FullBackupManifest.sidecarSize(a.data, expectedID: id)))
        }
        sidecars.sort { "\($0.id).blob" < "\($1.id).blob" }
        guard Set(sidecars.map(\.id)).count == sidecars.count else { throw FullBackupError.invalid("Full backup contains duplicate targets") }
        for s in sidecars { rows.append((.attachment, "\(s.id).blob", s.data, s.id, s.size)) }
        guard rows.count <= maxEntries else { throw FullBackupError.invalid("Full backup contains too many entries") }
        guard FullBackupManifest.validProfileName(profileName) else { throw FullBackupError.invalid("Profile name is malformed") }

        let salt = random.bytes(count: 16)
        guard kdf.isAccepted else { throw FullBackupError.unsupportedEncryption }
        var key = try derive(password, salt: salt, kdf: kdf)
        defer { wipe(&key) }
        let header: JSONValue = .object([
            "format": .string(format), "version": .int(version),
            "kdf": .object(["name": .string("argon2id"), "time_cost": .int(Int64(kdf.timeCost)),
                            "memory_cost_kib": .int(Int64(kdf.memoryKiB)), "parallelism": .int(Int64(kdf.parallelism)),
                            "salt": .string(Base64.encode(salt))]),
            "cipher": .object(["name": .string("aes-256-gcm"), "nonce_bytes": .int(12), "tag_bytes": .int(16)]),
            "entry_count": .int(Int64(rows.count)),
        ])
        let headerData = try CanonicalJSON.encode(header, dialect: .utf8)
        guard headerData.count <= maxHeaderBytes else { throw FullBackupError.invalid("Full backup header is too large") }
        var records: [JSONValue] = []
        for (index, row) in rows.enumerated() {
            var r: [String: JSONValue] = [
                "kind": .string(row.kind.rawValue), "target": .string(row.target), "size": .int(Int64(row.data.count)),
                "sha256": .string(lowerHex(SHA256.hash(data: row.data))), "member": .string(FullBackupManifest.member(index)),
            ]
            if let id = row.id, let size = row.sidecar {
                r["attachment_id"] = .string(id); r["sidecar_size"] = .int(Int64(size))
            }
            records.append(.object(r))
        }
        let manifest: JSONValue = .object([
            "version": .int(version), "profile_name": .string(profileName), "entries": .array(records),
            "created_at": .int(createdAt ?? SystemClock().now),
        ])
        let manifestData = try CanonicalJSON.encode(manifest, dialect: .utf8)
        guard manifestData.count <= maxManifestBytes else { throw FullBackupError.invalid("Full backup manifest is too large") }
        let manifestDigest = Array(SHA256.hash(data: manifestData))
        var zip = ZipWriter()
        do {
            try zip.addStored(name: "header.json", data: headerData)
            try zip.addStored(name: "manifest.bin", data: try seal(manifestData, key: key, aad: aad + headerData, random: random))
            for (index, row) in rows.enumerated() {
                try check()
                let member = FullBackupManifest.member(index)
                let blob = try seal(Array(row.data), key: key, aad: aad + headerData + manifestDigest + Array(member.utf8), random: random)
                try zip.addStored(name: member, data: blob)
                guard zip.size <= maxBackupBytes else { throw FullBackupError.tooLarge }
                progress("export", index + 1, rows.count)
            }
        } catch is ZipWriter.Failure {
            throw FullBackupError.tooLarge
        }
        let archive = try zip.finish()
        guard archive.count <= maxBackupBytes else { throw FullBackupError.tooLarge }
        try check()
        return archive
    }

    // MARK: - read

    /// The public header only (no password, no key derivation).
    public static func inspect(_ data: Data) throws -> FullBackupInfo {
        let (reader, entries) = try container(data)
        let (_, _, kdf, _, count) = try readHeader(reader, entries)
        return FullBackupInfo(kdf: kdf, entryCount: Int(count), bytes: data.count)
    }

    /// Opens and authenticates every member, then checks the settings, generation and sidecar framing.
    /// A wrong password and any tampering give the same message.
    public static func open(_ data: Data, password: String, progress: (String, Int, Int) -> Void = { _, _, _ in },
                            cancel: () -> Bool = { false }) throws -> FullBackupContents {
        func check() throws { if cancel() { throw FullBackupError.cancelled } }
        try check()
        let (reader, zipEntries) = try container(data)
        let (headerData, _, kdf, salt, entryCount) = try readHeader(reader, zipEntries)
        guard let manifestEntry = zipEntries["manifest.bin"] else { throw FullBackupError.invalid("Missing full backup manifest") }
        let manifestBlob = try read(reader, manifestEntry, limit: maxManifestBytes + 64)
        guard manifestBlob.count >= 12 + 16 else { throw FullBackupError.invalid("Full backup manifest is truncated") }
        var key = try derive(password, salt: salt, kdf: kdf)
        defer { wipe(&key) }
        let manifestData = try openBlob(manifestBlob, key: key, aad: aad + headerData)
        guard manifestData.count <= maxManifestBytes else { throw FullBackupError.invalid("Full backup manifest is too large") }
        let manifest = try FullBackupManifest.object(manifestData, label: "Full backup manifest")
        let entries = try FullBackupManifest.entries(manifest, entryCount: entryCount)
        guard Set(zipEntries.keys) == Set(["header.json", "manifest.bin"] + entries.map(\.member)) else {
            throw FullBackupError.membersMismatch
        }
        let manifestDigest = Array(SHA256.hash(data: manifestData))
        // Authenticate everything first; nothing is parsed until every member has passed.
        var plain: [Data] = []
        for (index, entry) in entries.enumerated() {
            try check()
            let z = zipEntries[entry.member]!
            guard z.uncompressedSize == entry.size + 12 + 16 else {
                throw FullBackupError.invalid("Full backup member size does not match its manifest")
            }
            let blob = try read(reader, z, limit: maxMemberBytes + 64 * 1024)
            let body = try openBlob(blob, key: key, aad: aad + headerData + manifestDigest + Array(entry.member.utf8))
            guard body.count == entry.size, lowerHex(SHA256.hash(data: body)) == entry.sha256 else {
                throw FullBackupError.memberAuthentication
            }
            plain.append(Data(body))
            progress("import", index + 1, entries.count)
        }
        var vault: Data?, settings: Data?, generation: Data?
        var attachments: [FullBackupAttachment] = []
        for (entry, body) in zip(entries, plain) {
            switch entry.kind {
            case .vault:
                do { _ = try FullBackupManifest.object(Array(body), label: "Vault") } catch {
                    throw FullBackupError.invalid("Full backup contains an invalid encrypted vault")
                }
                vault = body
            case .settings:
                guard body.count <= maxSettingsBytes else { throw FullBackupError.invalid("Restored settings are too large") }
                _ = try FullBackupManifest.object(Array(body), label: "Restored settings")
                settings = body
            case .generation:
                try FullBackupManifest.validateGeneration(Array(body))
                generation = body
            case .attachment:
                let id = entry.attachmentID!
                guard try FullBackupManifest.sidecarSize(body, expectedID: id) == entry.sidecarSize else {
                    throw FullBackupError.invalid("Attachment sidecar metadata does not match its manifest")
                }
                attachments.append(FullBackupAttachment(id: id, data: body, sidecarSize: entry.sidecarSize!))
            }
        }
        guard let vault, let settings else { throw FullBackupError.invalid("Full backup is missing required profile data") }
        try check()
        return FullBackupContents(profileName: FullBackupManifest.string(manifest["profile_name"])!,
                                  createdAt: FullBackupManifest.int(manifest["created_at"]), vault: vault,
                                  settings: settings, generation: generation, attachments: attachments, entries: entries)
    }

    // MARK: - helpers

    /// The zip directory, checked as `_full_read_container` does before reading anything.
    private static func container(_ data: Data) throws -> (ZipReader, [String: ZipEntry]) {
        guard data.count <= maxBackupBytes else { throw FullBackupError.tooLarge }
        let reader: ZipReader
        do {
            reader = try ZipReader(data: data, maxBytes: maxBackupBytes, maxEntries: maxEntries + 2)
        } catch let f as ZipReader.Failure {
            switch f {
            case .unsafeName, .duplicateName: throw FullBackupError.unsafeMember
            case .tooManyEntries: throw FullBackupError.tooManyMembers
            case .tooLarge: throw FullBackupError.tooLarge
            default: throw FullBackupError.unreadable
            }
        }
        let list = reader.entries()
        guard (4...(maxEntries + 2)).contains(list.count) else { throw FullBackupError.tooManyMembers }
        var byName: [String: ZipEntry] = [:]
        for e in list {
            let name = e.name
            guard name == "header.json" || name == "manifest.bin" || (name.hasPrefix("data/") && name.hasSuffix(".bin")) else {
                throw FullBackupError.unsafeMember
            }
            guard e.flags & 0x1 == 0, e.method == 0 else { throw FullBackupError.compressedOrEncrypted }
            guard e.uncompressedSize <= maxMemberBytes + 64 * 1024 else { throw FullBackupError.memberTooLarge }
            byName[name] = e
        }
        return (reader, byName)
    }

    private static func readHeader(_ reader: ZipReader, _ entries: [String: ZipEntry])
        throws -> ([UInt8], [String: JSONValue], KDF, [UInt8], Int64) {
        guard let e = entries["header.json"] else { throw FullBackupError.invalid("Missing full backup header") }
        let headerData = try read(reader, e, limit: maxHeaderBytes)
        let header = try FullBackupManifest.object(headerData, label: "Full backup header")
        guard FullBackupManifest.string(header["format"]) == format, FullBackupManifest.int(header["version"]) == version else {
            throw FullBackupError.unsupportedFormat
        }
        guard case .object(let kdf)? = header["kdf"], case .object(let cipher)? = header["cipher"],
              FullBackupManifest.string(cipher["name"]) == "aes-256-gcm", FullBackupManifest.int(cipher["nonce_bytes"]) == 12,
              FullBackupManifest.int(cipher["tag_bytes"]) == 16 else {
            throw FullBackupError.invalid("Unsupported full backup encryption parameters")
        }
        guard FullBackupManifest.string(kdf["name"]) == "argon2id",
              let t = FullBackupManifest.int(kdf["time_cost"]), let m = FullBackupManifest.int(kdf["memory_cost_kib"]),
              let p = FullBackupManifest.int(kdf["parallelism"]),
              let t32 = UInt32(exactly: t), let m32 = UInt32(exactly: m), let p32 = UInt32(exactly: p) else {
            throw FullBackupError.unsupportedEncryption
        }
        let params = KDF(timeCost: t32, memoryKiB: m32, parallelism: p32)
        guard params.isAccepted else { throw FullBackupError.unsupportedEncryption }
        if let h = kdf["hash_len"], h != .int(32) { throw FullBackupError.unsupportedEncryption }
        let salt: [UInt8]
        do {
            guard let text = FullBackupManifest.string(kdf["salt"] ?? .string("")) else { throw Base64Error.malformed }
            salt = try Base64.decodeStrict(text)
        } catch { throw FullBackupError.invalid("Backup contains invalid encoded data") }
        guard salt.count == 16 else { throw FullBackupError.invalid("Malformed full backup KDF salt") }
        guard let count = FullBackupManifest.int(header["entry_count"]), (2...Int64(maxEntries)).contains(count) else {
            throw FullBackupError.invalid("Full backup entry count is invalid")
        }
        return (headerData, header, params, salt, count)
    }

    private static func read(_ reader: ZipReader, _ e: ZipEntry, limit: Int) throws -> [UInt8] {
        guard e.uncompressedSize <= limit else { throw FullBackupError.memberTooLarge }
        do { return Array(try reader.read(e, limit: limit)) } catch let f as ZipReader.Failure {
            throw f == .tooLarge ? FullBackupError.memberTooLarge : FullBackupError.truncated
        }
    }

    /// Windows `_derive`: 12-4096 characters (Unicode scalars, like Python `len`), UTF-8 as typed.
    static func derive(_ password: String, salt: [UInt8], kdf: KDF) throws -> [UInt8] {
        guard (12...4096).contains(password.unicodeScalars.count) else { throw FullBackupError.passwordLength }
        guard salt.count == 16 else { throw FullBackupError.invalid("Malformed encryption header") }
        guard kdf.isAccepted else { throw FullBackupError.unsupportedEncryption }
        do {
            return try Argon2id.derive(password: Array(password.utf8), salt: salt, memoryKiB: kdf.memoryKiB,
                                       iterations: kdf.timeCost, parallelism: kdf.parallelism, length: 32)
        } catch { throw FullBackupError.unreadable }
    }

    private static func seal(_ data: [UInt8], key: [UInt8], aad: [UInt8], random: any RandomSource) throws -> [UInt8] {
        let nonce = random.bytes(count: 12)
        return nonce + (try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: data, aad: aad))
    }

    private static func openBlob(_ blob: [UInt8], key: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        guard blob.count >= 28 else { throw FullBackupError.wrongPasswordOrModified }
        do { return try CryptoBox.openGCM(key: key, nonce: Array(blob[0..<12]), ciphertext: Array(blob[12...]), aad: aad) } catch {
            throw FullBackupError.wrongPasswordOrModified
        }
    }

    static func wipe(_ b: inout [UInt8]) { for i in b.indices { b[i] = 0 } }
}
