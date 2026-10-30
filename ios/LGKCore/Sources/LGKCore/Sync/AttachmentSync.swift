import Foundation
import Crypto

/// A blob, reference or message was refused; `reason` is a stable code (desktop `AttachmentSyncError`).
public struct AttachmentSyncError: Error, Equatable, Sendable, CustomStringConvertible {
    public let reason: String
    public let detail: String
    public init(_ reason: String, _ detail: String = "") { self.reason = reason; self.detail = detail }
    public var description: String { detail.isEmpty ? reason : "\(reason): \(detail)" }
}

/// Synced file attachments, format 1 (desktop `sync/attachment_sync.py`; docs/SYNC.md
/// "Documents and files"; vectors `tests/vectors/sync/attachments`).
///
/// A blob is one immutable encrypted file per attachment, addressed by the SHA-256 of its bytes:
/// `"LGKABLB1" || nonce || AES-256-GCM(k, nonce, u64_be(len) || data || zero padding to 64 KiB, aad)`, with
/// `nonce = HMAC-SHA256(k, label || id || "|" || SHA256(data))[0:12]` and `aad = "lgk-sync-attachment-v1|" || id`.
public enum AttachmentSync {
    public static let format = 1
    public static let blobMagic: [UInt8] = Array("LGKABLB1".utf8)
    public static let blobAAD: [UInt8] = Array("lgk-sync-attachment-v1|".utf8)
    public static let nonceLabel: [UInt8] = Array("lgk-sync-attachment-nonce-v1|".utf8)
    public static let padBlock = 64 * 1024
    public static let maxFileBytes = 25 * 1024 * 1024
    public static let maxAttachments = 500
    static let keyLength = 32
    static let nonceLength = 12
    static let tagLength = 16
    static let lengthPrefix = 8
    /// Magic, nonce and tag around the padded frame.
    static let overhead = 8 + 12 + 16
    public static let maxBlobBytes = overhead + paddedLength(maxFileBytes)
    public static let minBlobBytes = overhead + padBlock
    public static let maxName = 255
    public static let maxMime = 255
    public static let blobsDirName = "attachments"
    public static let blobSuffix = ".lgkblob"
    public static let chunkBytes = 512 * 1024
    public static let maxChunks = (maxBlobBytes + chunkBytes - 1) / chunkBytes
    /// An unreferenced blob in the shared folder is removed only after this long.
    public static let sweepMinAgeSeconds: Int64 = 7 * 86400
    /// Blob id of the capability probe (never a real blob).
    public static let probeBlob = String(repeating: "0", count: 64)

    // MARK: small checks

    public static func isBlobID(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }

    static func checkBlobID(_ value: String) throws -> String {
        guard isBlobID(value) else { throw AttachmentSyncError("bad-blob-id") }
        return value
    }

    /// Canonical lowercase 8-4-4-4-12 UUID (Python `str(uuid.UUID(value)) == value`).
    public static func isCanonicalUUID(_ value: String) -> Bool {
        let b = Array(value.utf8)
        guard b.count == 36 else { return false }
        for (i, c) in b.enumerated() {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                if c != 0x2D { return false }
            } else if !((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66)) {
                return false
            }
        }
        return true
    }

    static func checkKey(_ key: [UInt8]) throws -> [UInt8] {
        guard key.count == keyLength else { throw AttachmentSyncError("bad-key") }
        return key
    }

    static func sha256(_ bytes: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: bytes)) }

    /// Constant-time equality of two byte strings of public length.
    static func same(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in a.indices { diff |= a[i] ^ b[i] }
        return diff == 0
    }

    // MARK: blob

    /// Length of the framed plaintext `P` for a file of `size` bytes.
    public static func paddedLength(_ size: Int) -> Int {
        (lengthPrefix + size + padBlock - 1) / padBlock * padBlock
    }

    /// `36 + paddedLength(size)`: the blob length of a file of `size` bytes.
    public static func blobSize(forFileSize size: Int) -> Int { overhead + paddedLength(size) }

    public static func blobNonce(key: [UInt8], attachmentID: String, data: [UInt8]) throws -> [UInt8] {
        let message = nonceLabel + Array(attachmentID.utf8) + [0x7C] + sha256(data)
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: try checkKey(key)))
        return Array(Array(mac).prefix(nonceLength))
    }

    public static func sealBlob(key: [UInt8], attachmentID: String, data: [UInt8]) throws -> [UInt8] {
        let key = try checkKey(key)
        guard isCanonicalUUID(attachmentID) else { throw AttachmentSyncError("bad-ref", "attachment id") }
        guard data.count <= maxFileBytes else { throw AttachmentSyncError("too-large") }
        var frame = [UInt8](repeating: 0, count: paddedLength(data.count))
        var n = UInt64(data.count)
        for i in stride(from: lengthPrefix - 1, through: 0, by: -1) { frame[i] = UInt8(n & 0xFF); n >>= 8 }
        frame.replaceSubrange(lengthPrefix..<(lengthPrefix + data.count), with: data)
        defer { for i in frame.indices { frame[i] = 0 } }
        let nonce = try blobNonce(key: key, attachmentID: attachmentID, data: data)
        let sealed = try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: frame, aad: blobAAD + Array(attachmentID.utf8))
        return blobMagic + nonce + sealed
    }

    public static func blobID(_ blob: [UInt8]) -> String { lowerHex(sha256(blob)) }

    /// Size, magic and (when given) content address; no key needed.
    @discardableResult
    public static func checkBlobShape(_ blob: [UInt8], expectedID: String? = nil) throws -> [UInt8] {
        guard blob.count >= minBlobBytes, blob.count <= maxBlobBytes else { throw AttachmentSyncError("bad-blob", "size") }
        guard (blob.count - overhead) % padBlock == 0 else { throw AttachmentSyncError("bad-blob", "size") }
        guard Array(blob[0..<blobMagic.count]) == blobMagic else { throw AttachmentSyncError("bad-blob", "magic") }
        if let expectedID {
            let wanted = try checkBlobID(expectedID)
            guard same(Array(blobID(blob).utf8), Array(wanted.utf8)) else { throw AttachmentSyncError("tampered", "content address") }
        }
        return blob
    }

    /// Verifies `blob` against its reference (plan "Open, in this order") and returns the file bytes.
    public static func openBlob(_ blob: [UInt8], ref: AttachmentRef) throws -> [UInt8] {
        try checkBlobShape(blob, expectedID: ref.blob)
        guard blob.count == ref.blobSize, blob.count == blobSize(forFileSize: ref.size) else {
            throw AttachmentSyncError("tampered", "length")
        }
        let start = blobMagic.count
        let nonce = Array(blob[start..<(start + nonceLength)])
        var frame: [UInt8]
        do {
            frame = try CryptoBox.openGCM(key: ref.key, nonce: nonce, ciphertext: Array(blob[(start + nonceLength)...]),
                                          aad: blobAAD + Array(ref.attachmentID.utf8))
        } catch {
            throw AttachmentSyncError("tampered", "authentication")
        }
        defer { for i in frame.indices { frame[i] = 0 } }
        var size: UInt64 = 0
        for i in 0..<lengthPrefix { size = (size << 8) | UInt64(frame[i]) }
        guard size == UInt64(ref.size), frame[(lengthPrefix + ref.size)...].allSatisfy({ $0 == 0 }) else {
            throw AttachmentSyncError("tampered", "frame")
        }
        let data = Array(frame[lengthPrefix..<(lengthPrefix + ref.size)])
        guard same(Array(lowerHex(sha256(data)).utf8), Array(ref.sha256.utf8)) else { throw AttachmentSyncError("tampered", "digest") }
        guard same(nonce, try blobNonce(key: ref.key, attachmentID: ref.attachmentID, data: data)) else {
            throw AttachmentSyncError("tampered", "nonce")
        }
        return data
    }

    // MARK: references

    /// Index references by attachment id: at most `maxAttachments`, one blob per id.
    public static func checkRefs(_ refs: [AttachmentRef]) throws -> [String: AttachmentRef] {
        var out: [String: AttachmentRef] = [:]
        for ref in refs {
            if out.count >= maxAttachments && out[ref.attachmentID] == nil { throw AttachmentSyncError("too-many") }
            if let previous = out[ref.attachmentID], previous != ref { throw AttachmentSyncError("conflict", ref.attachmentID) }
            out[ref.attachmentID] = ref
        }
        return out
    }

    /// References whose blob is not in `present` (blob ids), sorted by blob id.
    public static func wanted(_ refs: [AttachmentRef], presentBlobs: Set<String>) throws -> [AttachmentRef] {
        try checkRefs(refs).values.filter { !presentBlobs.contains($0.blob) }.sorted { $0.blob < $1.blob }
    }

    // MARK: Wi-Fi chunks

    /// The `blob` message for chunk `seq` of `blob`.
    public static func chunk(_ blob: [UInt8], seq: Int) throws -> LanMessage {
        try checkBlobShape(blob)
        let total = (blob.count + chunkBytes - 1) / chunkBytes
        guard seq >= 0, seq < total else { throw AttachmentSyncError("bad-chunk") }
        let part = Array(blob[(seq * chunkBytes)..<min(blob.count, (seq + 1) * chunkBytes)])
        return .blob(blob: blobID(blob), seq: Int64(seq), total: Int64(total), size: Int64(blob.count), data: Base64.encode(part))
    }
}

/// The reference carried inside the sealed view, under the document wrapper's `attachment` key:
/// exactly `{"blob","blob_size","id","key","mime_type","name","sha256","size"}`.
public struct AttachmentRef: Equatable, Hashable, Sendable, CustomStringConvertible {
    public let attachmentID: String
    public let blob: String
    public let blobSize: Int
    public let name: String
    public let mimeType: String
    public let size: Int
    public let sha256: String
    public let key: [UInt8]

    static let fields: Set<String> = ["id", "blob", "blob_size", "name", "mime_type", "size", "sha256", "key"]

    public init(attachmentID: String, blob: String, blobSize: Int, name: String, mimeType: String, size: Int,
                sha256: String, key: [UInt8]) throws {
        func bad(_ d: String) -> AttachmentSyncError { AttachmentSyncError("bad-ref", d) }
        guard AttachmentSync.isCanonicalUUID(attachmentID) else { throw bad("attachment id") }
        guard AttachmentSync.isBlobID(blob) else { throw AttachmentSyncError("bad-blob-id") }
        try Self.checkText(name, "name", AttachmentSync.maxName)
        guard name != ".", name != "..", !name.contains("/"), !name.contains("\\") else { throw bad("name") }
        try Self.checkText(mimeType, "mime type", AttachmentSync.maxMime)
        guard (0...AttachmentSync.maxFileBytes).contains(size) else { throw bad("size") }
        guard blobSize == AttachmentSync.blobSize(forFileSize: size) else { throw bad("blob size") }
        guard AttachmentSync.isBlobID(sha256) else { throw bad("sha256") }
        guard key.count == AttachmentSync.keyLength else { throw AttachmentSyncError("bad-key") }
        self.attachmentID = attachmentID; self.blob = blob; self.blobSize = blobSize; self.name = name
        self.mimeType = mimeType; self.size = size; self.sha256 = sha256; self.key = key
    }

    static func checkText(_ s: String, _ what: String, _ limit: Int) throws {
        let scalars = s.unicodeScalars
        guard !scalars.isEmpty, scalars.count <= limit, !scalars.contains(where: { $0.value < 32 || $0.value == 127 }) else {
            throw AttachmentSyncError("bad-ref", what)
        }
    }

    /// Never prints the key.
    public var description: String { "AttachmentRef(id=\(attachmentID), blob=\(blob), size=\(size))" }

    /// The reference for a sealed blob of `data`.
    public static func forBlob(_ blob: [UInt8], attachmentID: String, name: String, mimeType: String, data: [UInt8],
                               key: [UInt8]) throws -> AttachmentRef {
        try AttachmentRef(attachmentID: attachmentID, blob: AttachmentSync.blobID(blob), blobSize: blob.count, name: name,
                          mimeType: mimeType.isEmpty ? "application/octet-stream" : mimeType, size: data.count,
                          sha256: lowerHex(AttachmentSync.sha256(data)), key: key)
    }

    public var json: JSONValue {
        .object(["id": .string(attachmentID), "blob": .string(blob), "blob_size": .int(Int64(blobSize)), "name": .string(name),
                 "mime_type": .string(mimeType), "size": .int(Int64(size)), "sha256": .string(sha256),
                 "key": .string(Base64.encode(key))])
    }

    /// `AttachmentRef.from_value`: exactly the reference keys, strict base64 key; else `bad-ref`.
    public init(json value: JSONValue?) throws {
        guard case .object(let o)? = value, Set(o.keys) == Self.fields else { throw AttachmentSyncError("bad-ref", "fields") }
        guard case .string(let keyText)? = o["key"], let key = try? Base64.decodeStrict(keyText), key.count == AttachmentSync.keyLength else {
            throw AttachmentSyncError("bad-ref", "key")
        }
        guard case .string(let id)? = o["id"] else { throw AttachmentSyncError("bad-ref", "attachment id") }
        guard case .string(let blob)? = o["blob"] else { throw AttachmentSyncError("bad-blob-id") }
        guard case .string(let name)? = o["name"] else { throw AttachmentSyncError("bad-ref", "name") }
        guard case .string(let mime)? = o["mime_type"] else { throw AttachmentSyncError("bad-ref", "mime type") }
        guard case .int(let size)? = o["size"], size >= 0, size <= Int64(AttachmentSync.maxFileBytes) else {
            throw AttachmentSyncError("bad-ref", "size")
        }
        guard case .int(let blobSize)? = o["blob_size"], blobSize >= 0, blobSize <= Int64(AttachmentSync.maxBlobBytes) + 1 else {
            throw AttachmentSyncError("bad-ref", "blob size")
        }
        guard case .string(let digest)? = o["sha256"] else { throw AttachmentSyncError("bad-ref", "sha256") }
        try self.init(attachmentID: id, blob: blob, blobSize: Int(blobSize), name: name, mimeType: mime, size: Int(size),
                      sha256: digest, key: key)
    }
}

/// Collects the chunks of one blob in order and verifies the content address at the end (desktop `BlobDownload`).
public struct BlobDownload: Sendable {
    public let ref: AttachmentRef
    private var parts: [UInt8] = []
    public private(set) var nextSeq: Int64 = 0
    private var total: Int64?

    public init(ref: AttachmentRef) { self.ref = ref }

    /// The whole blob after the last chunk, else nil.
    public mutating func add(_ message: LanMessage) throws -> [UInt8]? {
        guard case let .blob(blob, seq, total, size, data) = message, blob == ref.blob, size == Int64(ref.blobSize) else {
            throw AttachmentSyncError("bad-chunk")
        }
        guard seq == nextSeq, self.total == nil || self.total == total else { throw AttachmentSyncError("bad-chunk") }
        guard let part = try? Base64.decodeStrict(data) else { throw AttachmentSyncError("bad-chunk") }
        let expected = min(Int64(AttachmentSync.chunkBytes), size - seq * Int64(AttachmentSync.chunkBytes))
        guard Int64(part.count) == expected else { throw AttachmentSyncError("bad-chunk") }
        self.total = total
        parts += part
        nextSeq += 1
        if nextSeq < total { return nil }
        return try AttachmentSync.checkBlobShape(parts, expectedID: ref.blob)
    }
}

/// Where sealed blobs are kept: the shared sync folder, or this device's own encrypted attachment directory.
public protocol AttachmentBlobStore: Sendable {
    func has(_ blobID: String) -> Bool
    /// The verified blob bytes (size, magic and content address), or nil.
    func read(_ blobID: String) -> [UInt8]?
    /// Stores a blob once (content addressed) and returns its id.
    @discardableResult func write(_ blob: [UInt8]) throws -> String
    /// Every well-named blob id present.
    func ids() -> Set<String>
}

/// `<root>/attachments/<blob_id>.lgkblob` (desktop `BlobFolder`): the sync folder's blob directory, and also
/// the layout each app uses for its own attachment files (a sealed blob is already encrypted under the
/// attachment's key, which lives only inside the encrypted vault record).
public struct BlobFolder: AttachmentBlobStore {
    public let dir: URL

    public init(root: URL) { dir = root.appendingPathComponent(AttachmentSync.blobsDirName, isDirectory: true) }

    public func path(_ blobID: String) throws -> URL {
        let url = dir.appendingPathComponent(try AttachmentSync.checkBlobID(blobID) + AttachmentSync.blobSuffix)
        guard url.deletingLastPathComponent().standardizedFileURL.path == dir.standardizedFileURL.path else {
            throw AttachmentSyncError("bad-blob-id")
        }
        return url
    }

    static func isRegularFile(_ url: URL) -> Bool {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path) else { return false }
        return (attrs[.type] as? FileAttributeType) == .typeRegular
    }

    public func ids() -> Set<String> {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else { return [] }
        var out = Set<String>()
        for name in names where name.hasSuffix(AttachmentSync.blobSuffix) {
            let stem = String(name.dropLast(AttachmentSync.blobSuffix.count))
            if AttachmentSync.isBlobID(stem), Self.isRegularFile(dir.appendingPathComponent(name)) { out.insert(stem) }
        }
        return out
    }

    public func has(_ blobID: String) -> Bool {
        guard let url = try? path(blobID) else { return false }
        return Self.isRegularFile(url)
    }

    @discardableResult
    public func write(_ blob: [UInt8]) throws -> String { try write(blob, replace: false) }

    /// Stores a blob once; an existing file with that name is kept (content addressed) unless `replace`.
    @discardableResult
    public func write(_ blob: [UInt8], replace: Bool) throws -> String {
        try AttachmentSync.checkBlobShape(blob)
        let name = AttachmentSync.blobID(blob)
        let target = try path(name)
        if Self.isRegularFile(target) && !replace { return name }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let temporary = dir.appendingPathComponent(".\(name).\(UUID().uuidString.lowercased().prefix(12)).tmp")
        defer { try? FileManager.default.removeItem(at: temporary) }
        try Data(blob).write(to: temporary, options: [.withoutOverwriting])
        if let handle = try? FileHandle(forWritingTo: temporary) { try? handle.synchronize(); try? handle.close() }
        if Self.isRegularFile(target) {
            if !replace { return name }
            _ = try FileManager.default.replaceItemAt(target, withItemAt: temporary)
            return name
        }
        try FileManager.default.moveItem(at: temporary, to: target)
        return name
    }

    /// Desktop `BlobFolder.keep`: whether a stored blob has the expected length; refreshes its modification
    /// date once it is half the sweep age old, so another device's sweep cannot remove a blob a writer is about
    /// to reference again. False (missing, wrong length, unreadable): the writer rewrites it with `replace`, and
    /// only a successful write counts the blob as present.
    public func keep(_ blobID: String, size: Int, now: Date) -> Bool {
        guard let url = try? path(blobID), Self.isRegularFile(url),
              let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let length = (attrs[.size] as? NSNumber)?.intValue, length == size,
              let modified = attrs[.modificationDate] as? Date else { return false }
        if now.timeIntervalSince(modified) >= TimeInterval(AttachmentSync.sweepMinAgeSeconds) / 2 {
            do { try FileManager.default.setAttributes([.modificationDate: now], ofItemAtPath: url.path) } catch { return false }
        }
        return true
    }

    /// Desktop `attachment_flow.publish_folder_blobs` for one blob: keep it, or (re)write it. Returns whether the
    /// blob is now present with the right length; a failed write never counts as present.
    public func publish(_ blob: [UInt8], now: Date) -> Bool {
        let id = AttachmentSync.blobID(blob)
        if keep(id, size: blob.count, now: now) { return true }
        do { try write(blob, replace: has(id)) } catch { return false }
        return keep(id, size: blob.count, now: now)
    }

    public func read(_ blobID: String) -> [UInt8]? {
        guard let url = try? path(blobID), Self.isRegularFile(url),
              let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let size = (attrs[.size] as? NSNumber)?.intValue, size <= AttachmentSync.maxBlobBytes,
              let data = try? Data(contentsOf: url) else { return nil }
        let raw = Array(data)
        return (try? AttachmentSync.checkBlobShape(raw, expectedID: blobID)) == nil ? nil : raw
    }

    /// Removes blobs no view references, only once older than `minAge` seconds (a writer may be mid-publish).
    @discardableResult
    public func sweep(referenced: Set<String>, now: Date, minAge: TimeInterval = TimeInterval(AttachmentSync.sweepMinAgeSeconds)) -> [String] {
        var removed: [String] = []
        for name in ids().subtracting(referenced).sorted() {
            guard let url = try? path(name), let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
                  let modified = attrs[.modificationDate] as? Date else { continue }
            if now.timeIntervalSince(modified) < minAge { continue }
            if (try? FileManager.default.removeItem(at: url)) != nil { removed.append(name) }
        }
        return removed
    }

    /// Removes the named blob now (this device's own directory only: a document deleted for good).
    public func remove(_ blobID: String) {
        guard let url = try? path(blobID) else { return }
        try? FileManager.default.removeItem(at: url)
    }
}
