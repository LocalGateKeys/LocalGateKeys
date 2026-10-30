/// A refused LAN sync step or message; `reason` is a stable code (desktop `LanSyncError`).
public struct LanSyncError: Error, Equatable, Sendable, CustomStringConvertible {
    public let reason: String
    public let detail: String
    public init(_ reason: String, _ detail: String = "") { self.reason = reason; self.detail = detail }
    public var description: String { detail.isEmpty ? reason : "\(reason): \(detail)" }
}

/// One message inside the authenticated channel (desktop `lan_sync` "Messages").
public enum LanMessage: Equatable, Sendable {
    case view(groupID: String, epoch: Int64, transfer: String, seq: Int64, total: Int64, size: Int64, view: String)
    case next(transfer: String, seq: Int64)
    case ack(transfer: String, seq: Int64)
    case error(reason: String)
    /// Rollback witness (2026-10-29): `view` is standard base64 of a witness file (format 2, zero records).
    case witness(groupID: String, epoch: Int64, view: String)
    /// Attachment sync (2026-10-29): ask for chunk `seq` of a blob (`AttachmentSync`).
    case blobGet(blob: String, seq: Int64)
    /// One chunk of a blob: `data` is standard base64 of bytes `[seq*512 KiB, ...)`.
    case blob(blob: String, seq: Int64, total: Int64, size: Int64, data: String)
}

public enum LanMessages {
    /// Raw view bytes per chunk when sending.
    public static let chunkBytes = 512 * 1024
    /// Largest chunk accepted.
    public static let chunkLimit = 560 * 1024
    public static let maxViewBytes = ViewFile.maxBytes
    public static let maxChunks: Int64 = 65536
    static let maxInt53: Int64 = (1 << 53) - 1

    /// Every reason a responder can send in an `error` message.
    public static let errorReasons = [
        "bad-chunk", "bad-message", "bad-view", "device-mismatch", "epoch-behind", "group-mismatch",
        "local-data", "not-joined", "peer-epoch-behind", "rejoin-required", "revoked", "too-large",
        "unknown-peer",
    ]

    /// Attachment sync refusals (desktop `ATTACHMENT_ERROR_REASONS`), kept apart from the view protocol's list.
    public static let attachmentErrorReasons = ["no-blob"]

    static let fields: [String: Set<String>] = [
        "view": ["type", "group_id", "epoch", "transfer", "seq", "total", "size", "view"],
        "next": ["type", "transfer", "seq"],
        "ack": ["type", "transfer", "seq"],
        "error": ["type", "reason"],
        "witness": ["type", "group_id", "epoch", "view"],
        "blob-get": ["type", "blob", "seq"],
        "blob": ["type", "blob", "seq", "total", "size", "data"],
    ]

    /// Canonical ASCII JSON of the message.
    public static func encode(_ m: LanMessage) throws -> [UInt8] {
        let o: [String: JSONValue]
        switch m {
        case let .view(g, e, t, s, total, size, v):
            o = ["type": .string("view"), "group_id": .string(g), "epoch": .int(e), "transfer": .string(t), "seq": .int(s),
                 "total": .int(total), "size": .int(size), "view": .string(v)]
        case let .next(t, s): o = ["type": .string("next"), "transfer": .string(t), "seq": .int(s)]
        case let .ack(t, s): o = ["type": .string("ack"), "transfer": .string(t), "seq": .int(s)]
        case let .error(r): o = ["type": .string("error"), "reason": .string(r)]
        case let .witness(g, e, v): o = ["type": .string("witness"), "group_id": .string(g), "epoch": .int(e), "view": .string(v)]
        case let .blobGet(b, s): o = ["type": .string("blob-get"), "blob": .string(b), "seq": .int(s)]
        case let .blob(b, s, total, size, d):
            o = ["type": .string("blob"), "blob": .string(b), "seq": .int(s), "total": .int(total), "size": .int(size),
                 "data": .string(d)]
        }
        return try CanonicalJSON.encode(.object(o), dialect: .ascii)
    }

    private static func int(_ v: JSONValue?, _ low: Int64, _ high: Int64 = maxInt53) -> Int64? {
        guard case .int(let i)? = v, i >= low, i <= high else { return nil }
        return i
    }

    /// `parse_message`: shape checks; throws `too-large` or `bad-message`.
    public static func parse(_ raw: [UInt8]) throws -> LanMessage {
        guard raw.count <= LanTransport.maxMessageBytes else { throw LanSyncError("too-large") }
        guard case .object(let o)? = try? CanonicalJSON.parse(raw), case .string(let type)? = o["type"],
              let want = fields[type], Set(o.keys) == want else { throw LanSyncError("bad-message") }
        if type == "error" {
            guard case .string(let r)? = o["reason"], (1...64).contains(r.unicodeScalars.count) else { throw LanSyncError("bad-message") }
            return .error(reason: r)
        }
        if type == "witness" {
            guard case .string(let group)? = o["group_id"], let epoch = int(o["epoch"], 1), case .string(let view)? = o["view"] else {
                throw LanSyncError("bad-message")
            }
            if view.utf8.count > 4 * ((Witness.maxWitnessBytes + 2) / 3) { throw LanSyncError("too-large") }
            return .witness(groupID: group, epoch: epoch, view: view)
        }
        if type == "blob-get" || type == "blob" { return try parseBlob(type, o) }
        guard case .string(let transfer)? = o["transfer"], transfer.utf8.count == 32,
              transfer.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }),
              let seq = int(o["seq"], 0, maxChunks - 1) else { throw LanSyncError("bad-message") }
        if type == "next" { return .next(transfer: transfer, seq: seq) }
        if type == "ack" { return .ack(transfer: transfer, seq: seq) }
        guard case .string(let group)? = o["group_id"], let epoch = int(o["epoch"], 1) else { throw LanSyncError("bad-message") }
        guard let total = int(o["total"], 1), let size = int(o["size"], 1), case .string(let view)? = o["view"] else {
            throw LanSyncError("bad-message")
        }
        if size > Int64(maxViewBytes) || total > maxChunks { throw LanSyncError("too-large") }
        if seq >= total || total > size { throw LanSyncError("bad-message") }
        if view.utf8.count > 4 * ((chunkLimit + 2) / 3) { throw LanSyncError("too-large") }
        return .view(groupID: group, epoch: epoch, transfer: transfer, seq: seq, total: total, size: size, view: view)
    }

    /// `attachment_sync.parse_message` for `blob-get` / `blob`.
    static func parseBlob(_ type: String, _ o: [String: JSONValue]) throws -> LanMessage {
        guard case .string(let blob)? = o["blob"], AttachmentSync.isBlobID(blob),
              let seq = int(o["seq"], 0, Int64(AttachmentSync.maxChunks - 1)) else { throw LanSyncError("bad-message") }
        if type == "blob-get" { return .blobGet(blob: blob, seq: seq) }
        guard case .int(let size)? = o["size"], size >= Int64(AttachmentSync.minBlobBytes),
              size <= Int64(AttachmentSync.maxBlobBytes) else { throw LanSyncError("too-large") }
        let chunk = Int64(AttachmentSync.chunkBytes)
        guard case .int(let total)? = o["total"], total == (size + chunk - 1) / chunk, seq < total else {
            throw LanSyncError("bad-message")
        }
        guard case .string(let data)? = o["data"] else { throw LanSyncError("bad-message") }
        if data.utf8.count > 4 * ((AttachmentSync.chunkBytes + 2) / 3) { throw LanSyncError("too-large") }
        return .blob(blob: blob, seq: seq, total: total, size: size, data: data)
    }

    /// Chunks of `chunkBytes` (the last is what is left).
    public static func splitView(_ raw: [UInt8]) -> [[UInt8]] {
        stride(from: 0, to: raw.count, by: chunkBytes).map { Array(raw[$0..<min($0 + chunkBytes, raw.count)]) }
    }
}
