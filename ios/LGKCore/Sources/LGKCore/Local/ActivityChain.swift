import Crypto
import Foundation

/// The hash-chained access log (Windows `activity.py`): each event's `prev_hash` is the SHA-256 of the previous
/// event's canonical JSON (keys sorted, no spaces, UTF-8 as is); the first kept event links to the checkpoint left
/// by pruning, or to 64 zeros. Byte-exact with Windows for the event vocabulary (pinned by the shared vector in
/// `ActivityChainTests` and `tests/test_activity_chain.py`).
public enum ActivityChain {
    public static let genesis = String(repeating: "0", count: 64)

    /// One event as the chain sees it; `prevHash` nil means an event recorded before the chain existed.
    public struct Event: Equatable, Sendable {
        public var id: String
        public var eventType: String
        public var timestamp: Int64
        public var itemID: String?
        public var result: String
        public var count: Int64
        public var prevHash: String?
        public init(id: String, eventType: String, timestamp: Int64, itemID: String? = nil, result: String = "ok",
                    count: Int64 = 0, prevHash: String? = nil) {
            self.id = id; self.eventType = eventType; self.timestamp = timestamp; self.itemID = itemID
            self.result = result; self.count = count; self.prevHash = prevHash
        }
    }

    public struct Report: Equatable, Sendable {
        public let ok: Bool
        public let firstBadID: String?
    }

    /// `{"count":…,"event_type":…,"id":…,"item_id":…,["prev_hash":…,]"result":…,"timestamp":…}`.
    public static func canonical(_ e: Event) -> String {
        var parts = ["\"count\":\(e.count)", "\"event_type\":\(quote(e.eventType))", "\"id\":\(quote(e.id))",
                     "\"item_id\":\(e.itemID.map(quote) ?? "null")"]
        if let prev = e.prevHash { parts.append("\"prev_hash\":\(quote(prev))") }
        parts.append("\"result\":\(quote(e.result))")
        parts.append("\"timestamp\":\(e.timestamp)")
        return "{" + parts.joined(separator: ",") + "}"
    }

    public static func hash(_ e: Event) -> String {
        lowerHex(Array(SHA256.hash(data: Array(canonical(e).utf8))))
    }

    /// The `prevHash` for an event appended after `events` (or after `checkpoint` when none is kept).
    public static func link(after events: [Event], checkpoint: String? = nil) -> String {
        if let last = events.last { return hash(last) }
        return checkpoint ?? genesis
    }

    public static func verify(_ events: [Event], checkpoint: String? = nil, head: String? = nil) -> Report {
        var expected = checkpoint ?? genesis
        var chained = false
        for (index, event) in events.enumerated() {
            guard let prev = event.prevHash else {
                if chained { return Report(ok: false, firstBadID: event.id) }
                expected = hash(event)
                continue
            }
            chained = true
            if prev != expected { return Report(ok: false, firstBadID: index > 0 ? events[index - 1].id : event.id) }
            expected = hash(event)
        }
        // Once a chain exists its head must match: catches a cut-off tail, an emptied log and stripped hashes.
        if let head, head != expected { return Report(ok: false, firstBadID: events.last?.id) }
        return Report(ok: true, firstBadID: nil)
    }

    private static func quote(_ s: String) -> String {
        var out = "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }
}
