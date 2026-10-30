import Foundation

/// `document` items and their files (desktop `vault_bridge` documents section and `attachment_flow`).
///
/// On the phone and the Mac a document's wrapper is stored exactly as it syncs: `{"ns":"item", "schema",
/// "updated_at", "record", "attachment": <AttachmentRef>}`, with `record.kind == "document"` and
/// `record.payload.attachment_id == attachment.id`. The file itself is the sealed blob, kept in this device's
/// own `BlobFolder` (encrypted under the attachment key, which lives only in the encrypted record).
public enum AttachmentDocuments {
    public static let kind = "document"

    /// Whether a wrapper is a document item (`is_document_state`).
    public static func isDocument(_ item: JSONValue?) -> Bool {
        guard case .object(let w)? = item, w["ns"] == .string(Namespace.item.rawValue),
              case .object(let r)? = w["record"] else { return false }
        return r["kind"] == .string(kind)
    }

    public static func isDocumentState(_ state: ItemState) -> Bool { isDocument(state.item) }

    /// The reference of a document wrapper, or nil when it has none or it is malformed.
    public static func ref(of item: JSONValue?) -> AttachmentRef? {
        guard isDocument(item), case .object(let w)? = item else { return nil }
        return try? AttachmentRef(json: w["attachment"])
    }

    /// `_check_remote_document`: the reference is well formed and names its record's attachment.
    static func checkRemote(wrapper: [String: JSONValue], record: [String: JSONValue]) throws -> AttachmentRef {
        let ref: AttachmentRef
        do { ref = try AttachmentRef(json: wrapper["attachment"]) } catch let e as AttachmentSyncError {
            throw AttachmentSyncError(e.reason, "malformed attachment")
        }
        guard case .object(let payload)? = record["payload"], payload["attachment_id"] == .string(ref.attachmentID) else {
            throw AttachmentSyncError("bad-ref", "names another attachment")
        }
        return ref
    }

    /// `publishable`: without `documents` the document items are left out (older readers). Tombstones stay.
    public static func publishable(_ states: [ItemState], documents: Bool) -> [ItemState] {
        documents ? states : states.filter { !isDocumentState($0) }
    }

    /// The well-formed references of the live document states (`document_refs`).
    public static func refs(_ states: [ItemState]) -> [AttachmentRef] {
        states.compactMap { $0.deleted ? nil : ref(of: $0.item) }
    }

    /// The references of the live documents stored on this device.
    public static func storedRefs(_ snapshot: StoreSnapshot) -> [AttachmentRef] {
        snapshot.records.compactMap { id, wrapper in snapshot.meta[id]?.deleted == true ? nil : ref(of: wrapper) }
    }

    /// The blob of one of this device's own live documents named `blobID`, else nil (the LAN responder serves
    /// nothing else; the probe id never matches).
    public static func ownBlob(_ blobID: String, snapshot: StoreSnapshot, blobs: any AttachmentBlobStore) -> [UInt8]? {
        guard blobID != AttachmentSync.probeBlob, storedRefs(snapshot).contains(where: { $0.blob == blobID }) else { return nil }
        return blobs.read(blobID)
    }

    /// The document wrapper for `record` (kind `document`, `payload.attachment_id == ref.attachmentID`).
    public static func wrapper(record: JSONValue, ref: AttachmentRef) -> JSONValue {
        guard case .object(var w) = Wrapper.make(ns: .item, record: record) else { return record }
        w["attachment"] = ref.json
        return .object(w)
    }

    /// A new document: seals `data` under a fresh key and attachment id, stores the blob in `blobs`, and returns
    /// the wrapper to store under the new record id. `title` defaults to the file name.
    public static func make(data: [UInt8], fileName: String, mimeType: String, title: String, now: Int64,
                            random: any RandomSource, blobs: any AttachmentBlobStore) throws -> (id: String, wrapper: JSONValue, ref: AttachmentRef) {
        guard data.count <= AttachmentSync.maxFileBytes else { throw AttachmentSyncError("too-large") }
        let name = safeFileName(fileName)
        let key = random.bytes(count: 32)
        let attachmentID = uuid4(random)
        let blob = try AttachmentSync.sealBlob(key: key, attachmentID: attachmentID, data: data)
        let ref = try AttachmentRef.forBlob(blob, attachmentID: attachmentID, name: name, mimeType: safeMime(mimeType),
                                            data: data, key: key)
        try blobs.write(blob)
        let id = uuid4(random)
        let cleanTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
        let record: JSONValue = .object([
            "id": .string(id), "kind": .string(kind), "title": .string(cleanTitle.isEmpty ? name : String(cleanTitle.prefix(200))),
            "created_at": .int(now), "updated_at": .int(now), "favorite": .bool(false), "tags": .array([]),
            "payload": .object(["attachment_id": .string(attachmentID), "description": .string(""), "template_id": .null]),
        ])
        return (id, wrapper(record: record, ref: ref), ref)
    }

    /// The document renamed: only the record title changes (owner decision 2026-10-29); the file name stays.
    public static func renamed(_ item: JSONValue, title: String, now: Int64) -> JSONValue? {
        guard isDocument(item), case .object(var w) = item, case .object(var r)? = w["record"] else { return nil }
        let clean = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty else { return nil }
        r["title"] = .string(String(clean.prefix(200)))
        r["updated_at"] = .int(now)
        w["record"] = .object(r)
        w["updated_at"] = .int(Wrapper.rank(.object(r)))
        return .object(w)
    }

    /// The file bytes of a stored document, verified against its reference.
    public static func open(_ item: JSONValue?, blobs: any AttachmentBlobStore) throws -> (ref: AttachmentRef, data: [UInt8]) {
        guard let ref = ref(of: item) else { throw AttachmentSyncError("bad-ref") }
        guard let blob = blobs.read(ref.blob) else { throw AttachmentSyncError("attachment-missing") }
        return (ref, try AttachmentSync.openBlob(blob, ref: ref))
    }

    /// A display file name: no separators or control characters, not `.`/`..`, at most 255 scalars.
    public static func safeFileName(_ name: String) -> String {
        let cleaned = String(String.UnicodeScalarView(name.unicodeScalars.map { sc -> Unicode.Scalar in
            (sc.value < 32 || sc.value == 127 || sc == "/" || sc == "\\") ? "_" : sc
        }.prefix(AttachmentSync.maxName))).trimmingCharacters(in: .whitespaces)
        return (cleaned.isEmpty || cleaned == "." || cleaned == "..") ? "file" : cleaned
    }

    static func safeMime(_ mime: String) -> String {
        let ok = !mime.isEmpty && mime.unicodeScalars.count <= AttachmentSync.maxMime
            && !mime.unicodeScalars.contains { $0.value < 32 || $0.value == 127 }
        return ok ? mime : "application/octet-stream"
    }

    /// Python `str(uuid.uuid4())`.
    static func uuid4(_ random: any RandomSource) -> String {
        var b = random.bytes(count: 16)
        b[6] = (b[6] & 0x0F) | 0x40; b[8] = (b[8] & 0x3F) | 0x80
        let h = Array(lowerHex(b))
        return [0..<8, 8..<12, 12..<16, 16..<20, 20..<32].map { String(h[$0]) }.joined(separator: "-")
    }

    /// Removes this device's blobs that no stored document references (live or in `keep`, e.g. the trash).
    @discardableResult
    public static func collectGarbage(snapshot: StoreSnapshot, blobs: BlobFolder, keep: Set<String> = []) -> [String] {
        let referenced = Set(snapshot.records.values.compactMap { ref(of: $0)?.blob }).union(keep)
        var removed: [String] = []
        for id in blobs.ids().subtracting(referenced).sorted() { blobs.remove(id); removed.append(id) }
        return removed
    }
}

extension AttachmentDocuments {
    /// Key under which a Recently deleted row keeps a document's reference (the row stores the record only).
    public static let trashRefKey = "_lgk_attachment"

    /// The record a Recently deleted row stores for `wrapper`: the record, plus the file reference of a document.
    public static func trashRecord(_ wrapper: JSONValue) -> JSONValue? {
        guard case .object(let w) = wrapper, case .object(var r)? = w["record"] else { return nil }
        if isDocument(wrapper), let attachment = w["attachment"] { r[trashRefKey] = attachment }
        return .object(r)
    }

    /// The wrapper to store when a Recently deleted row comes back: a document gets its reference again.
    public static func restoredWrapper(_ record: JSONValue, ns: Namespace) -> JSONValue {
        guard case .object(var r) = record, let attachment = r.removeValue(forKey: trashRefKey) else {
            return Wrapper.make(ns: ns, record: record)
        }
        guard ns == .item, let ref = try? AttachmentRef(json: attachment) else { return Wrapper.make(ns: ns, record: .object(r)) }
        return wrapper(record: .object(r), ref: ref)
    }

    /// Blob ids still referenced by Recently deleted rows (kept by `collectGarbage`).
    public static func trashBlobs(_ records: [JSONValue]) -> Set<String> {
        Set(records.compactMap { record -> String? in
            guard case .object(let r) = record, let ref = try? AttachmentRef(json: r[trashRefKey]) else { return nil }
            return ref.blob
        })
    }

    /// After Recently deleted rows are purged for good: removes this device's files no live document and no
    /// remaining Recently deleted row references. A plain delete never calls this (the row still needs the file).
    @discardableResult
    public static func collectGarbage(store: any ItemStore, trash: [JSONValue], blobs: BlobFolder?) -> [String] {
        guard let blobs, let snap = try? store.load() else { return [] }
        return collectGarbage(snapshot: snap, blobs: blobs, keep: trashBlobs(trash))
    }

    /// Most peers kept in `SyncGroupState.attachmentPeers`.
    public static let maxAttachmentPeers = 64

    /// `attachmentPeers` with `peer` added or removed (sorted, bounded); nil when nothing changes.
    public static func peers(_ current: [String], setting peer: String, capable: Bool) -> [String]? {
        var set = Set(current)
        if capable {
            guard !set.contains(peer), set.count < maxAttachmentPeers, Identifier.isValid(peer) else { return nil }
            set.insert(peer)
        } else {
            guard set.remove(peer) != nil else { return nil }
        }
        return set.sorted()
    }

    /// Persists a peer's attachment capability in the group state (desktop `set_attachment_peer`): one commit,
    /// only when the list changes. Returns whether it changed.
    @discardableResult
    public static func setPeer(_ peer: String, capable: Bool, store: any ItemStore) -> Bool {
        guard let snap = try? store.load(), var state = snap.sync,
              let next = peers(state.attachmentPeers, setting: peer, capable: capable) else { return false }
        state.attachmentPeers = next
        return (try? store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta,
                                              sync: state))) != nil
    }
}

/// Wi-Fi peers that answered a `blob-get` in this unlock session (desktop `attachment_peers`, kept in memory
/// here): they get document items in views. Thread-safe.
public final class AttachmentPeerMemory: @unchecked Sendable {
    private let lock = NSLock()
    private var peers: Set<String> = []
    public init() {}
    public func contains(_ peer: String) -> Bool { lock.withLock { peers.contains(peer) } }
    public func set(_ peer: String, capable: Bool) {
        lock.withLock { if capable { peers.insert(peer) } else { peers.remove(peer) } }
    }
}
