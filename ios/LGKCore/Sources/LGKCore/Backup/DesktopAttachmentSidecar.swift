import Foundation

/// The Windows attachment sidecar `Attachments/<id>.blob` (desktop `attachments.AttachmentStore._write_blob`,
/// version 2): `"LGKATT1\0" || u32_be(len(header)) || header || nonce(12) || AES-256-GCM(key, nonce, data, header)`,
/// where `header` is the compact sorted JSON `{"format":"localgatekeys-attachment","id","store_id","version":2}`
/// and `key` is the attachment's catalog key (the same key the sync blob uses). Full backups carry these files
/// next to the catalog rows `payload["attachments"]`, so a Windows restore of a Mac backup finds every document's file.
public enum DesktopAttachmentSidecar {
    public static let magic: [UInt8] = Array("LGKATT1".utf8) + [0]
    public static let version: Int64 = 2
    static let headerLimit = 8 * 1024

    static func header(id: String, storeID: String) throws -> [UInt8] {
        try CanonicalJSON.encode(.object(["format": .string("localgatekeys-attachment"), "version": .int(version),
                                          "id": .string(id), "store_id": .string(storeID)]), dialect: .ascii)
    }

    public static func seal(id: String, data: [UInt8], storeID: String, key: [UInt8], random: any RandomSource) throws -> [UInt8] {
        guard AttachmentSync.isCanonicalUUID(id), AttachmentSync.isCanonicalUUID(storeID) else {
            throw AttachmentSyncError("bad-ref", "sidecar id")
        }
        let h = try header(id: id, storeID: storeID)
        let nonce = random.bytes(count: 12)
        let sealed = try CryptoBox.sealGCM(key: key, nonce: nonce, plaintext: data, aad: h)
        var n = UInt32(h.count)
        var length = [UInt8](repeating: 0, count: 4)
        for i in stride(from: 3, through: 0, by: -1) { length[i] = UInt8(n & 0xFF); n >>= 8 }
        return magic + length + h + nonce + sealed
    }

    /// The file bytes of a version-2 sidecar for attachment `id` of the store `storeID`.
    public static func open(_ sidecar: [UInt8], id: String, storeID: String, key: [UInt8]) throws -> [UInt8] {
        let bad = AttachmentSyncError("bad-blob", "sidecar")
        guard sidecar.count >= magic.count + 4 + 12 + 16, Array(sidecar[0..<magic.count]) == magic else { throw bad }
        var length = 0
        for b in sidecar[magic.count..<(magic.count + 4)] { length = (length << 8) | Int(b) }
        let start = magic.count + 4
        guard (1...headerLimit).contains(length), start + length + 12 + 16 <= sidecar.count else { throw bad }
        let h = Array(sidecar[start..<(start + length)])
        guard h == (try header(id: id, storeID: storeID)) else { throw AttachmentSyncError("tampered", "sidecar header") }
        let nonce = Array(sidecar[(start + length)..<(start + length + 12)])
        do {
            return try CryptoBox.openGCM(key: key, nonce: nonce, ciphertext: Array(sidecar[(start + length + 12)...]), aad: h)
        } catch { throw AttachmentSyncError("tampered", "sidecar authentication") }
    }

    /// What a full backup adds for this device's own documents (desktop catalog rows and sidecars): every live
    /// document whose sync blob opens. `existing` are the catalog ids already in the payload (kept Windows rows);
    /// those are left alone. Documents whose file is not on this device are returned in `skipped` (left out of
    /// the backup, as Windows refuses a document without its catalog row).
    public static func backupRows(documents: [(record: JSONValue, wrapper: JSONValue)], existing: Set<String>, storeID: String,
                                  blobs: any AttachmentBlobStore, random: any RandomSource)
        -> (rows: [JSONValue], sidecars: [(id: String, data: Data)], skipped: Set<String>) {
        var rows: [JSONValue] = [], sidecars: [(id: String, data: Data)] = [], skipped = Set<String>()
        var done = existing
        for doc in documents {
            guard case .object(let r) = doc.record, case .string(let itemID)? = r["id"] else { continue }
            guard let opened = try? AttachmentDocuments.open(doc.wrapper, blobs: blobs) else { skipped.insert(itemID); continue }
            let ref = opened.ref
            if done.contains(ref.attachmentID) { continue }
            guard let sidecar = try? seal(id: ref.attachmentID, data: opened.data, storeID: storeID, key: ref.key, random: random) else {
                skipped.insert(itemID); continue
            }
            done.insert(ref.attachmentID)
            rows.append(.object(["id": .string(ref.attachmentID), "name": .string(ref.name), "mime_type": .string(ref.mimeType),
                                 "size": .int(Int64(ref.size)), "sha256": .string(ref.sha256), "key": .string(Base64.encode(ref.key))]))
            sidecars.append((ref.attachmentID, Data(sidecar)))
        }
        return (rows, sidecars, skipped)
    }

    /// A restored Windows document as a Mac/iPhone document: its catalog row and sidecar opened, the file sealed
    /// as a sync blob into `blobs`, and the wrapper with its reference. nil when anything is missing or wrong.
    public static func restoredDocument(record: JSONValue, catalog: [JSONValue], sidecars: [String: Data], storeID: String,
                                        blobs: any AttachmentBlobStore) -> JSONValue? {
        guard case .object(let r) = record, case .object(let payload)? = r["payload"],
              case .string(let attachmentID)? = payload["attachment_id"],
              let row = catalog.first(where: { if case .object(let o) = $0 { return o["id"] == .string(attachmentID) }; return false }),
              case .object(let o) = row, case .string(let keyText)? = o["key"], let key = try? Base64.decodeStrict(keyText),
              case .string(let name)? = o["name"], let sidecar = sidecars[attachmentID],
              let data = try? open(Array(sidecar), id: attachmentID, storeID: storeID, key: key),
              let blob = try? AttachmentSync.sealBlob(key: key, attachmentID: attachmentID, data: data) else { return nil }
        let mime: String = { if case .string(let m)? = o["mime_type"], !m.isEmpty { return m }; return "application/octet-stream" }()
        guard let ref = try? AttachmentRef.forBlob(blob, attachmentID: attachmentID, name: AttachmentDocuments.safeFileName(name),
                                                   mimeType: mime, data: data, key: key),
              (try? blobs.write(blob)) != nil else { return nil }
        return AttachmentDocuments.wrapper(record: record, ref: ref)
    }
}
