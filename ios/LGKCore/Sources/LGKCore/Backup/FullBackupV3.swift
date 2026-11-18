import Crypto
import Foundation

/// The Windows full backup **version 3** container (design `docs/design/backup-public-key-2026-10-31.md` section 3.4),
/// written by scheduled backups only. The zip layout, member names, limits and manifest are those of v2; the data
/// key `dk` is random per file and wrapped to the public backup key (`header.recipient`, `BackupKey.wrap`):
///
/// * `header.json` = `core` (format, version 3, cipher, entry count) + `recipient` (scheme, key id, key set time,
///   the key's Argon2id `kdf` with salt, the ephemeral public key, the 48-byte wrap). No other keys.
/// * manifest blob = `nonce || AES-256-GCM(dk, nonce, canon(manifest), aad = AAD_V3 || canon(core))`;
///   member blob AAD = `AAD_V3 || canon(core) || SHA-256(canon(manifest)) || member name`.
///
/// The manifest and members bind `core`, not the recipient, so re-locking (`relock`) replaces `header.json` only
/// and copies every other member byte for byte. `FullBackupV2` is not changed by any of this; `FullBackup` picks
/// the reader by `header.version`.
public enum FullBackupV3 {
    public static let version: Int64 = 3
    static let aad = Array("localgatekeys|encrypted-full-profile-backup|v3".utf8)
    static let headerFields: Set<String> = ["format", "version", "cipher", "entry_count", "recipient"]
    static let recipientFields: Set<String> = ["scheme", "key_id", "key_set_at", "kdf", "ephemeral_public_key", "wrapped_key"]
    static let cipherFields: Set<String> = ["name", "nonce_bytes", "tag_bytes"]

    /// The public recipient block (no secret): which key a backup opens with and when that key was set.
    public struct Recipient: Equatable, Sendable {
        public let keyID: String
        public let keySetAt: Int64
        public let kdf: BackupKeyKDF
        public let ephemeralPublicKey: [UInt8]
        public let wrapped: [UInt8]

        public init(keyID: String, keySetAt: Int64, kdf: BackupKeyKDF, ephemeralPublicKey: [UInt8], wrapped: [UInt8]) {
            self.keyID = keyID; self.keySetAt = keySetAt; self.kdf = kdf
            self.ephemeralPublicKey = ephemeralPublicKey; self.wrapped = wrapped
        }
    }

    /// What `inspect` tells without a password.
    public struct Info: Equatable, Sendable {
        public let entryCount: Int
        public let bytes: Int
        public let recipient: Recipient
    }

    /// A file just written or re-locked, with the secrets its self-verify needs (section 9.1). The caller keeps
    /// them only until `verifyWritten` has run, then `wipe()`s.
    public struct Written: Sendable {
        public let data: Data
        public private(set) var dataKey: [UInt8]
        public private(set) var ephemeralSecret: [UInt8]
        init(data: Data, dataKey: [UInt8], ephemeralSecret: [UInt8]) {
            self.data = data; self.dataKey = dataKey; self.ephemeralSecret = ephemeralSecret
        }
        public mutating func wipe() { BackupKey.wipe(&dataKey); BackupKey.wipe(&ephemeralSecret) }
    }

    // MARK: - write

    /// A new scheduled full backup to `record`'s public key (`export_full_backup_to_key`). The inputs and checks are
    /// those of `FullBackupV2.write`; `random` gives `dk`, then the ephemeral key, then the nonces.
    public static func write(vault: Data, settings: Data, attachments: [(id: String, data: Data)], record: BackupKeyRecord,
                             random: any RandomSource, progress: (String, Int, Int) -> Void, cancel: () -> Bool,
                             generation: Data? = nil, profileName: String, createdAt: Int64? = nil) throws -> Written {
        func check() throws { if cancel() { throw FullBackupError.cancelled } }
        try check()
        let maxMemberBytes = FullBackupV2.maxMemberBytes
        guard vault.count <= maxMemberBytes else { throw FullBackupError.invalid("Vault is too large") }
        _ = try FullBackupManifest.object(Array(vault), label: "Vault")
        guard settings.count <= FullBackupV2.maxSettingsBytes else { throw FullBackupError.invalid("Profile settings are too large") }
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
        guard rows.count <= FullBackupV2.maxEntries else { throw FullBackupError.invalid("Full backup contains too many entries") }
        guard FullBackupManifest.validProfileName(profileName) else { throw FullBackupError.invalid("Profile name is malformed") }

        var dataKey = random.bytes(count: 32)
        guard dataKey.count == 32 else { throw FullBackupError.invalid("The random source returned too few bytes") }
        var ephemeral = try BackupKey.newEphemeral(random: random)
        var keep = false
        defer { if !keep { BackupKey.wipe(&dataKey); ephemeral.wipe() } }
        let core = Self.core(entryCount: rows.count)
        let header = try Self.header(core: core, record: record, dataKey: dataKey, ephemeral: ephemeral)
        let coreData = try CanonicalJSON.encode(.object(core), dialect: .utf8)

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
        guard manifestData.count <= FullBackupV2.maxManifestBytes else { throw FullBackupError.invalid("Full backup manifest is too large") }
        let manifestDigest = Array(SHA256.hash(data: manifestData))
        var zip = ZipWriter()
        do {
            try zip.addStored(name: "header.json", data: header)
            try zip.addStored(name: "manifest.bin", data: try seal(manifestData, key: dataKey, aad: aad + coreData, random: random))
            for (index, row) in rows.enumerated() {
                try check()
                let member = FullBackupManifest.member(index)
                let blob = try seal(Array(row.data), key: dataKey, aad: aad + coreData + manifestDigest + Array(member.utf8), random: random)
                try zip.addStored(name: member, data: blob)
                guard zip.size <= FullBackupV2.maxBackupBytes else { throw FullBackupError.tooLarge }
                progress("export", index + 1, rows.count)
            }
        } catch is ZipWriter.Failure {
            throw FullBackupError.tooLarge
        }
        let archive = try zip.finish()
        guard archive.count <= FullBackupV2.maxBackupBytes else { throw FullBackupError.tooLarge }
        try check()
        keep = true
        return Written(data: archive, dataKey: dataKey, ephemeralSecret: ephemeral.secret)
    }

    static func core(entryCount: Int) -> [String: JSONValue] {
        [
            "format": .string(FullBackupV2.format), "version": .int(version),
            "cipher": .object(["name": .string("aes-256-gcm"), "nonce_bytes": .int(12), "tag_bytes": .int(16)]),
            "entry_count": .int(Int64(entryCount)),
        ]
    }

    /// `canon(core + recipient)` with a fresh wrap of `dataKey` to `record`'s public key.
    static func header(core: [String: JSONValue], record: BackupKeyRecord, dataKey: [UInt8],
                       ephemeral: BackupKey.EphemeralKey) throws -> [UInt8] {
        var body: [String: JSONValue] = [
            "scheme": .string(BackupKey.scheme), "key_id": .string(record.keyID), "key_set_at": .int(record.setAt),
            "kdf": record.kdf.json, "ephemeral_public_key": .string(Base64.encode(ephemeral.publicKey)),
        ]
        let wrapAAD = try BackupKey.wrapAAD(core: core, recipientBody: body)
        let wrapped = try BackupKey.wrap(dataKey: dataKey, publicKey: record.publicKey, ephemeral: ephemeral, aad: wrapAAD)
        body["wrapped_key"] = .string(Base64.encode(wrapped))
        var header = core
        header["recipient"] = .object(body)
        let data = try CanonicalJSON.encode(.object(header), dialect: .utf8)
        guard data.count <= FullBackupV2.maxHeaderBytes else { throw FullBackupError.invalid("Full backup header is too large") }
        return data
    }

    // MARK: - read

    /// The parsed public header.
    struct Header {
        let data: [UInt8]
        let core: [String: JSONValue]
        let coreData: [UInt8]
        let recipient: Recipient
        let entryCount: Int64
        /// The wrap AAD (`wrap_aad`): the header and the recipient without its wrap.
        let wrapAAD: [UInt8]
    }

    /// The public header only (no password, no key derivation).
    public static func inspect(_ data: Data) throws -> Info {
        let (reader, entries) = try container(data)
        let header = try readHeader(reader, entries)
        return Info(entryCount: Int(header.entryCount), bytes: data.count, recipient: header.recipient)
    }

    /// Opens with the backup password: Argon2 with the header's `kdf`, the key id check (no GCM attempt on a
    /// mismatch), the unwrap, then every member is authenticated as in v2. A wrong password, a key id of another
    /// key and any tampering give the same message.
    public static func open(_ data: Data, password: String, progress: (String, Int, Int) -> Void = { _, _, _ in },
                            cancel: () -> Bool = { false }) throws -> FullBackupContents {
        if cancel() { throw FullBackupError.cancelled }
        let (reader, entries) = try container(data)
        let header = try readHeader(reader, entries)
        let manifestBlob = try manifestBlob(reader, entries)
        let r = header.recipient
        var dataKey = try BackupKey.unwrap(password: password, kdf: r.kdf, expectedKeyID: r.keyID,
                                           ephemeralPublic: r.ephemeralPublicKey, wrapped: r.wrapped, aad: header.wrapAAD)
        defer { BackupKey.wipe(&dataKey) }
        return try openMembers(reader, entries, header: header, manifestBlob: manifestBlob, dataKey: dataKey,
                               progress: progress, cancel: cancel)
    }

    /// Section 9.1 steps 1-3 after a scheduled write or a re-lock, without any password: the header is valid, the
    /// ephemeral key and key id are the expected ones, the wrap opens with `esk` and `record`'s public key to `dk`
    /// (so the file opens with the record's private key), and every member authenticates with `dk`. Returns the
    /// contents for the caller's vault-layer check.
    public static func verifyWritten(_ data: Data, dataKey: [UInt8], ephemeralSecret: [UInt8],
                                     record: BackupKeyRecord) throws -> FullBackupContents {
        let wrong = FullBackupError.wrongPasswordOrModified
        let (reader, entries) = try container(data)
        let header = try readHeader(reader, entries)
        let manifestBlob = try manifestBlob(reader, entries)
        let r = header.recipient
        guard let epk = try? BackupKey.publicKey(of: ephemeralSecret), BackupKey.constantTimeEqual(epk, r.ephemeralPublicKey),
              r.keyID == record.keyID, r.keySetAt == record.setAt, r.kdf == record.kdf,
              var shared = BackupKey.sharedSecret(ephemeralSecret, record.publicKey) else { throw wrong }
        var kek = BackupKey.kek(shared: shared, ephemeralPublic: r.ephemeralPublicKey, publicKey: record.publicKey)
        defer { BackupKey.wipe(&shared); BackupKey.wipe(&kek) }
        guard var opened = try? CryptoBox.openGCM(key: kek, nonce: BackupKey.wrapNonce, ciphertext: r.wrapped, aad: header.wrapAAD)
        else { throw wrong }
        defer { BackupKey.wipe(&opened) }
        guard BackupKey.constantTimeEqual(opened, dataKey) else { throw wrong }
        return try openMembers(reader, entries, header: header, manifestBlob: manifestBlob, dataKey: dataKey,
                               progress: { _, _, _ in }, cancel: { false })
    }

    /// Section 7.2: the same backup to `newRecord`'s key. Only the outer layer is opened: `dk` is unwrapped with
    /// `oldKey` (the file must be under `oldKey.keyID`) and the manifest decrypted to check the pair; `vault.json` is
    /// never opened. The new `header.json` has the same `core` and a new recipient (new key id, set time, KDF and salt,
    /// fresh ephemeral key, a new wrap of the same `dk`); every other member is copied verbatim, in order. The caller
    /// writes it beside the original, runs `verifyWritten` on what it wrote, then renames it over the original.
    public static func relock(_ data: Data, oldKey: BackupKeyPair, newRecord: BackupKeyRecord,
                              random: any RandomSource) throws -> Written {
        let (reader, entries) = try container(data)
        let header = try readHeader(reader, entries)
        let r = header.recipient
        guard BackupKey.constantTimeEqual(Array(r.keyID.utf8), Array(oldKey.keyID.utf8)) else {
            throw FullBackupError.wrongPasswordOrModified
        }
        let manifestBlob = try manifestBlob(reader, entries)
        var dataKey = try BackupKey.unwrap(privateKey: oldKey.privateKey, ephemeralPublic: r.ephemeralPublicKey,
                                           wrapped: r.wrapped, aad: header.wrapAAD)
        var keep = false
        defer { if !keep { BackupKey.wipe(&dataKey) } }
        var manifestData = try openBlob(manifestBlob, key: dataKey, aad: aad + header.coreData)
        BackupKey.wipe(&manifestData)
        var fresh = try BackupKey.newEphemeral(random: random)
        defer { if !keep { fresh.wipe() } }
        let newHeader = try Self.header(core: header.core, record: newRecord, dataKey: dataKey, ephemeral: fresh)
        var zip = ZipWriter()
        do {
            try zip.addStored(name: "header.json", data: newHeader)
            for e in reader.entries() where e.name != "header.json" {
                try zip.addStored(name: e.name, data: try read(reader, e, limit: FullBackupV2.maxMemberBytes + 64 * 1024))
            }
        } catch is ZipWriter.Failure {
            throw FullBackupError.tooLarge
        }
        let archive = try zip.finish()
        guard archive.count <= FullBackupV2.maxBackupBytes else { throw FullBackupError.tooLarge }
        keep = true
        return Written(data: archive, dataKey: dataKey, ephemeralSecret: fresh.secret)
    }

    // MARK: - helpers

    /// The zip directory, checked as `FullBackupV2` does (same members, limits and refusals).
    static func container(_ data: Data) throws -> (ZipReader, [String: ZipEntry]) {
        let maxBackupBytes = FullBackupV2.maxBackupBytes, maxEntries = FullBackupV2.maxEntries
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
            guard e.uncompressedSize <= FullBackupV2.maxMemberBytes + 64 * 1024 else { throw FullBackupError.memberTooLarge }
            byName[name] = e
        }
        return (reader, byName)
    }

    /// The header's `version` (nil when the file is not a readable full backup). Reads `header.json` only.
    static func headerVersion(_ data: Data) -> Int64? {
        guard let (reader, entries) = try? container(data), let e = entries["header.json"],
              let bytes = try? read(reader, e, limit: FullBackupV2.maxHeaderBytes),
              let header = try? FullBackupManifest.object(Array(bytes), label: "Full backup header") else { return nil }
        return FullBackupManifest.int(header["version"])
    }

    /// Strict v3 header validation in the Windows reader order (`backup._v3_parse_header`, `SCHEMA.md`), with its
    /// messages: format, version and key sets → cipher → scheme → KDF keys and bounds → KDF salt → entry count →
    /// key id and key set time → ephemeral key and wrap (canonical base64) → canonical header bytes.
    static func readHeader(_ reader: ZipReader, _ entries: [String: ZipEntry]) throws -> Header {
        guard let e = entries["header.json"] else { throw FullBackupError.invalid("Missing full backup header") }
        let headerData = Array(try read(reader, e, limit: FullBackupV2.maxHeaderBytes))
        let header = try FullBackupManifest.object(headerData, label: "Full backup header")
        guard FullBackupManifest.string(header["format"]) == FullBackupV2.format, FullBackupManifest.int(header["version"]) == version,
              Set(header.keys) == headerFields, case .object(let rcpt)? = header["recipient"], Set(rcpt.keys) == recipientFields else {
            throw FullBackupError.unsupportedFormat
        }
        guard case .object(let cipher)? = header["cipher"], Set(cipher.keys) == cipherFields,
              FullBackupManifest.string(cipher["name"]) == "aes-256-gcm", FullBackupManifest.int(cipher["nonce_bytes"]) == 12,
              FullBackupManifest.int(cipher["tag_bytes"]) == 16,
              FullBackupManifest.string(rcpt["scheme"]) == BackupKey.scheme else {
            throw Messages.unsupportedCipher
        }
        guard case .object(let kdfObject)? = rcpt["kdf"], Set(kdfObject.keys) == BackupKeyKDF.fields,
              case .string("argon2id")? = kdfObject["name"],
              case .int(let t)? = kdfObject["time_cost"], case .int(let m)? = kdfObject["memory_cost_kib"],
              case .int(let p)? = kdfObject["parallelism"],
              let t32 = UInt32(exactly: t), let m32 = UInt32(exactly: m), let p32 = UInt32(exactly: p) else {
            throw FullBackupError.unsupportedEncryption
        }
        let parameters = FullBackupV2.KDF(timeCost: t32, memoryKiB: m32, parallelism: p32)
        guard parameters.isAccepted else { throw FullBackupError.unsupportedEncryption }
        guard case .string(let saltText)? = kdfObject["salt"], let salt = try? Base64.decodeStrict(saltText), salt.count == 16 else {
            throw FullBackupError.invalid("Malformed full backup KDF salt")
        }
        let kdf = try BackupKeyKDF(parameters: parameters, salt: salt)
        guard let count = FullBackupManifest.int(header["entry_count"]), (2...Int64(FullBackupV2.maxEntries)).contains(count) else {
            throw FullBackupError.invalid("Full backup entry count is invalid")
        }
        guard case .string(let keyID)? = rcpt["key_id"], BackupKey.isKeyID(keyID),
              let setAt = BackupKeyRecord.timestamp(rcpt["key_set_at"]),
              case .string(let epkText)? = rcpt["ephemeral_public_key"], let epk = try? Base64.decodeStrict(epkText), epk.count == 32,
              case .string(let wrappedText)? = rcpt["wrapped_key"], let wrapped = try? Base64.decodeStrict(wrappedText),
              wrapped.count == BackupKey.wrappedBytes else { throw Messages.malformedRecipient }
        // The AADs are recomputed from canonical bytes, so a header.json that is not canonical is a modified file.
        guard (try? CanonicalJSON.encode(.object(header), dialect: .utf8)) == headerData else {
            throw FullBackupError.wrongPasswordOrModified
        }
        var core = header
        core["recipient"] = nil
        var body = rcpt
        body["wrapped_key"] = nil
        let coreData = try CanonicalJSON.encode(.object(core), dialect: .utf8)
        return Header(data: headerData, core: core, coreData: coreData,
                      recipient: Recipient(keyID: keyID, keySetAt: setAt, kdf: kdf, ephemeralPublicKey: epk, wrapped: wrapped),
                      entryCount: count, wrapAAD: try BackupKey.wrapAAD(core: core, recipientBody: body))
    }

    /// The Windows messages for a refused v3 header (`backup.py`), in one place.
    enum Messages {
        static var malformedRecipient: FullBackupError { .invalid("Malformed full backup recipient") }
        static var unsupportedCipher: FullBackupError { .invalid("Unsupported full backup encryption parameters") }
    }

    static func manifestBlob(_ reader: ZipReader, _ entries: [String: ZipEntry]) throws -> [UInt8] {
        guard let manifestEntry = entries["manifest.bin"] else { throw FullBackupError.invalid("Missing full backup manifest") }
        let blob = Array(try read(reader, manifestEntry, limit: FullBackupV2.maxManifestBytes + 64))
        guard blob.count >= 12 + 16 else { throw FullBackupError.invalid("Full backup manifest is truncated") }
        return blob
    }

    /// The v2 member flow with `dk` and the v3 AADs: manifest, member set, every member's tag, size and SHA-256
    /// before anything is parsed, then the settings, generation and sidecar framing.
    static func openMembers(_ reader: ZipReader, _ zipEntries: [String: ZipEntry], header: Header, manifestBlob: [UInt8],
                            dataKey: [UInt8], progress: (String, Int, Int) -> Void, cancel: () -> Bool) throws -> FullBackupContents {
        func check() throws { if cancel() { throw FullBackupError.cancelled } }
        try check()
        let manifestData = try openBlob(manifestBlob, key: dataKey, aad: aad + header.coreData)
        guard manifestData.count <= FullBackupV2.maxManifestBytes else { throw FullBackupError.invalid("Full backup manifest is too large") }
        let manifest = try FullBackupManifest.object(manifestData, label: "Full backup manifest")
        let entries = try FullBackupManifest.entries(manifest, entryCount: header.entryCount, version: version)
        guard Set(zipEntries.keys) == Set(["header.json", "manifest.bin"] + entries.map(\.member)) else {
            throw FullBackupError.membersMismatch
        }
        let manifestDigest = Array(SHA256.hash(data: manifestData))
        var plain: [Data] = []
        for (index, entry) in entries.enumerated() {
            try check()
            let z = zipEntries[entry.member]!
            guard z.uncompressedSize == entry.size + 12 + 16 else {
                throw FullBackupError.invalid("Full backup member size does not match its manifest")
            }
            let blob = Array(try read(reader, z, limit: FullBackupV2.maxMemberBytes + 64 * 1024))
            let body = try openBlob(blob, key: dataKey, aad: aad + header.coreData + manifestDigest + Array(entry.member.utf8))
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
                guard body.count <= FullBackupV2.maxSettingsBytes else { throw FullBackupError.invalid("Restored settings are too large") }
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

    static func read(_ reader: ZipReader, _ e: ZipEntry, limit: Int) throws -> Data {
        guard e.uncompressedSize <= limit else { throw FullBackupError.memberTooLarge }
        do { return try reader.read(e, limit: limit) } catch let f as ZipReader.Failure {
            throw f == .tooLarge ? FullBackupError.memberTooLarge : FullBackupError.truncated
        }
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
}

/// Picks the full backup reader by `header.version`: 3 is `FullBackupV3`, anything else goes to `FullBackupV2`
/// exactly as before (its messages included). Old-format backups keep their reader unchanged (hard rule 1.1).
public enum FullBackup {
    public enum Info: Equatable, Sendable {
        case v2(FullBackupInfo)
        case v3(FullBackupV3.Info)
    }

    /// The header's version, reading `header.json` only (nil when not a readable full backup).
    public static func headerVersion(_ data: Data) -> Int64? { FullBackupV3.headerVersion(data) }

    public static func inspect(_ data: Data) throws -> Info {
        if headerVersion(data) == FullBackupV3.version { return .v3(try FullBackupV3.inspect(data)) }
        return .v2(try FullBackupV2.inspect(data))
    }

    public static func open(_ data: Data, password: String, progress: (String, Int, Int) -> Void = { _, _, _ in },
                            cancel: () -> Bool = { false }) throws -> FullBackupContents {
        if headerVersion(data) == FullBackupV3.version {
            return try FullBackupV3.open(data, password: password, progress: progress, cancel: cancel)
        }
        return try FullBackupV2.open(data, password: password, progress: progress, cancel: cancel)
    }
}
