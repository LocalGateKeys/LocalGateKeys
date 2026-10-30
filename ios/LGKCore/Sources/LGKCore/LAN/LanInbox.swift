/// Chunk buffers of one responder, keyed by peer device id (desktop `lan_sync.LanInbox`): one transfer
/// per peer each way, at most `maxTransfers` per direction (the oldest is dropped), each dropped
/// `transferTTL` seconds after it started.
public struct LanInbox: Sendable {
    /// Desktop `TRANSFER_TTL_SECONDS`.
    public static let transferTTL: Int64 = 300
    /// Desktop `MAX_TRANSFERS`.
    public static let maxTransfers = 2

    struct Incoming: Sendable {
        let transfer: String
        let total: Int64
        let size: Int64
        let started: Int64
        var parts: [[UInt8]] = []
        var received = 0
    }

    struct Outgoing: Sendable {
        let transfer: String
        let parts: [[UInt8]]
        let size: Int64
        let groupKey: GroupKey
        let started: Int64
        var sent = 1
    }

    var incoming: [String: Incoming] = [:]
    var outgoing: [String: Outgoing] = [:]

    public init() {}

    public var incomingCount: Int { incoming.count }
    public var outgoingCount: Int { outgoing.count }

    mutating func expire(now: Int64) {
        incoming = incoming.filter { $0.value.started >= now - Self.transferTTL }
        outgoing = outgoing.filter { $0.value.started >= now - Self.transferTTL }
    }

    /// Drops the oldest transfers past `maxTransfers`, never `keep` (the one just started).
    private static func bounded<V>(_ table: inout [String: V], keep: String, started: (V) -> Int64) {
        while table.count > maxTransfers,
              let oldest = table.filter({ $0.key != keep }).min(by: { (started($0.value), $0.key) < (started($1.value), $1.key) }) {
            table[oldest.key] = nil
        }
    }

    /// `_receive_chunk`: buffers one chunk; returns the whole view after the last one, else nil.
    mutating func receive(peer: String, transfer: String, seq: Int64, total: Int64, size: Int64, view: String,
                          now: Int64) throws -> [UInt8]? {
        guard let data = try? Base64.decodeStrict(view), !data.isEmpty else { throw LanSyncError("bad-chunk") }
        if data.count > LanMessages.chunkLimit {
            incoming[peer] = nil
            throw LanSyncError("too-large")
        }
        if seq == 0 {
            incoming[peer] = Incoming(transfer: transfer, total: total, size: size, started: now)
            Self.bounded(&incoming, keep: peer, started: \.started)   // as the desktop: may drop the oldest other transfer
        }
        guard var current = incoming[peer], current.transfer == transfer, Int64(current.parts.count) == seq,
              current.total == total, current.size == size else {
            incoming[peer] = nil
            throw LanSyncError("bad-chunk")
        }
        current.parts.append(data)
        current.received += data.count
        if Int64(current.received) > size {
            incoming[peer] = nil
            throw LanSyncError("bad-chunk")
        }
        if seq < total - 1 {
            incoming[peer] = current
            return nil
        }
        incoming[peer] = nil
        guard Int64(current.received) == size else { throw LanSyncError("bad-chunk") }
        return current.parts.flatMap { $0 }
    }

    /// Keeps the rest of a view sent in several chunks for `next`.
    mutating func store(_ out: Outgoing?, peer: String) {
        outgoing[peer] = out
        if out != nil { Self.bounded(&outgoing, keep: peer, started: \.started) }
    }

    /// `_next_chunk`.
    mutating func next(peer: String, transfer: String, seq: Int64) -> LanMessage {
        guard var out = outgoing[peer], out.transfer == transfer, seq == Int64(out.sent) else {
            outgoing[peer] = nil
            return .error(reason: "bad-chunk")
        }
        let reply = LanResponder.viewMessage(out.groupKey, transfer: out.transfer, seq: out.sent, parts: out.parts, size: out.size)
        out.sent += 1
        outgoing[peer] = out.sent >= out.parts.count ? nil : out
        return reply
    }
}
