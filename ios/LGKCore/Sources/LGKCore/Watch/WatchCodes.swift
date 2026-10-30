import Foundation

/// UX plan workstream 12: the 2FA codes pinned on the iPhone and shown inside the watch app (no complication).
/// Only what a code needs crosses to the watch: a title and the TOTP parameters. Never a password, username,
/// note or website. The watch generates codes itself with `TOTP.code`, so they work with the phone away.
public struct WatchCode: Codable, Equatable, Sendable, Identifiable {
    /// The vault item's id (pin bookkeeping only).
    public let id: String
    public let title: String
    public let secret: String
    public let algorithm: String
    public let digits: Int
    public let period: Int

    public init(id: String, title: String, secret: String, algorithm: String = "SHA1", digits: Int = 6, period: Int = 30) {
        self.id = id; self.title = title; self.secret = secret; self.algorithm = algorithm
        self.digits = digits; self.period = period
    }

    /// A code and its countdown at `now` (Unix seconds); nil when the secret or parameters are invalid.
    public func current(at now: Int64) -> (code: String, secondsRemaining: Int)? {
        guard let code = try? TOTP.code(secret: secret, algorithm: algorithm, digits: digits, period: period, at: now)
        else { return nil }
        return (code, period - Int(now % Int64(period)))
    }
}

/// What the iPhone sends over WatchConnectivity. Each message is the whole state: `replace` with the pinned
/// codes (an unpinned code is simply missing), or `forget` (lock with "Forget on watch", or an erase).
public enum WatchMessage: Equatable, Sendable {
    case replace([WatchCode])
    case forget

    /// The single WatchConnectivity key (a property-list dictionary carries one `Data` value).
    public static let key = "lgk.watch.v1"
    /// "Pin up to 10" (plan).
    public static let maxPins = 10

    private struct Wire: Codable { let v: Int; let op: String; let codes: [WatchCode]? }

    public enum Failure: Error, Equatable { case tooManyPins, malformed }

    public func encoded() throws -> Data {
        let wire: Wire
        switch self {
        case .replace(let codes):
            guard codes.count <= Self.maxPins else { throw Failure.tooManyPins }
            wire = Wire(v: 1, op: "replace", codes: codes)
        case .forget:
            wire = Wire(v: 1, op: "forget", codes: nil)
        }
        let e = JSONEncoder(); e.outputFormatting = .sortedKeys
        return try e.encode(wire)
    }

    public static func decode(_ data: Data) throws -> WatchMessage {
        guard data.count <= 64 * 1024, let w = try? JSONDecoder().decode(Wire.self, from: data), w.v == 1 else {
            throw Failure.malformed
        }
        switch w.op {
        case "forget": return .forget
        case "replace":
            guard let codes = w.codes, codes.count <= maxPins,
                  Set(codes.map(\.id)).count == codes.count else { throw Failure.malformed }
            return .replace(codes)
        default: throw Failure.malformed
        }
    }

    /// The WatchConnectivity user-info dictionary.
    public func userInfo() throws -> [String: Data] { [Self.key: try encoded()] }

    public static func from(userInfo: [String: Any]) throws -> WatchMessage {
        guard let data = userInfo[key] as? Data else { throw Failure.malformed }
        return try decode(data)
    }
}

/// The phone's pin list (item ids, in pin order) and the codes it turns into.
public enum WatchPins {
    /// Pins `id` (at the end) or unpins it. Pinning an 11th code is refused (returns nil).
    public static func toggle(_ id: String, in pins: [String]) -> [String]? {
        if pins.contains(id) { return pins.filter { $0 != id } }
        guard pins.count < WatchMessage.maxPins else { return nil }
        return pins + [id]
    }

    /// The codes for the pins, from a snapshot: live items with a `totp.secret`, in pin order. Deleted
    /// items and items whose 2FA was removed are dropped (the next `replace` removes them from the watch).
    public static func codes(pins: [String], snapshot: StoreSnapshot) -> [WatchCode] {
        pins.prefix(WatchMessage.maxPins).compactMap { id in
            if snapshot.meta[id]?.deleted == true { return nil }
            guard case .object(let w)? = snapshot.records[id], case .object(let r)? = w["record"],
                  case .object(let t)? = r["totp"], case .string(let secret)? = t["secret"], !secret.isEmpty else { return nil }
            func str(_ k: String) -> String { if case .string(let s)? = r[k] { return s }; return "" }
            func int(_ k: String, _ d: Int) -> Int { if case .int(let n)? = t[k] { return Int(n) }; return d }
            var alg = "SHA1"
            if case .string(let a)? = t["algorithm"] { alg = a }
            var title = str("title")
            if title.isEmpty { title = str("label") }
            if title.isEmpty, case .object(let scope)? = r["scope"], case .string(let o)? = scope["origin"] { title = o }
            return WatchCode(id: id, title: title, secret: secret, algorithm: alg, digits: int("digits", 6),
                             period: int("period", 30))
        }
    }
}
