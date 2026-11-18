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

    /// `seq` (sub-plan 06): the iPhone's send order, optional so stored items and older builds still decode.
    private struct Wire: Codable { let v: Int; let op: String; let codes: [WatchCode]?; var seq: Int64? = nil }

    public enum Failure: Error, Equatable { case tooManyPins, malformed }

    /// `sequence`: the iPhone's send order (`nextSequence`); nil for the stored copy, which needs none.
    public func encoded(sequence: Int64? = nil) throws -> Data {
        var wire: Wire
        switch self {
        case .replace(let codes):
            guard codes.count <= Self.maxPins else { throw Failure.tooManyPins }
            wire = Wire(v: 1, op: "replace", codes: codes)
        case .forget:
            wire = Wire(v: 1, op: "forget", codes: nil)
        }
        wire.seq = sequence
        let e = JSONEncoder(); e.outputFormatting = .sortedKeys
        return try e.encode(wire)
    }

    public static func decode(_ data: Data) throws -> WatchMessage { try decodeSequenced(data).message }

    /// The message and its send order (nil from a build before sub-plan 06).
    public static func decodeSequenced(_ data: Data) throws -> (message: WatchMessage, sequence: Int64?) {
        guard data.count <= 64 * 1024, let w = try? JSONDecoder().decode(Wire.self, from: data), w.v == 1 else {
            throw Failure.malformed
        }
        switch w.op {
        case "forget": return (message: .forget, sequence: w.seq)
        case "replace":
            guard let codes = w.codes, codes.count <= maxPins,
                  Set(codes.map(\.id)).count == codes.count else { throw Failure.malformed }
            return (message: .replace(codes), sequence: w.seq)
        default: throw Failure.malformed
        }
    }

    /// The WatchConnectivity user-info dictionary.
    public func userInfo(sequence: Int64? = nil) throws -> [String: Data] {
        [Self.key: try encoded(sequence: sequence)]
    }

    public static func from(userInfo: [String: Any]) throws -> WatchMessage { try sequenced(from: userInfo).message }

    public static func sequenced(from userInfo: [String: Any]) throws -> (message: WatchMessage, sequence: Int64?) {
        guard let data = userInfo[key] as? Data else { throw Failure.malformed }
        return try decodeSequenced(data)
    }

    /// The iPhone's next send order: above `last` and at least the current time in milliseconds, so it keeps
    /// rising across a clock change and after a reinstall (which starts again from the clock).
    public static func nextSequence(after last: Int64, now: Date) -> Int64 {
        let t = now.timeIntervalSince1970 * 1000
        let clock: Int64 = t.isFinite && t > 0 && t < 9e15 ? Int64(t) : 0
        return max(last < Int64.max ? last + 1 : last, clock)
    }

    /// True when a message with `sequence` must be ignored because the watch already applied `lastApplied`, a
    /// newer or equal one. Every message is the whole state, so an older one arriving late (a code update still in
    /// transit when Forget on lock was sent) would only bring back what a newer one removed. A message without a
    /// sequence (an iPhone build before sub-plan 06) is applied as before.
    public static func isStale(sequence: Int64?, lastApplied: Int64?) -> Bool {
        guard let sequence, let lastApplied else { return false }
        return sequence <= lastApplied
    }

    /// Whether the watch applies `message`, and the send order it then keeps as the last applied.
    /// - A forget is always applied, whatever its order (it can only remove codes), and its own order becomes the
    ///   last applied, even if lower: after an iPhone reinstall, a new iPhone or a lost counter (order starting
    ///   lower again), the next forget resets the watch and the updates after it are accepted. Without this, every
    ///   later message, forget included, would be dropped.
    /// - A code update is applied only when newer than the last applied (`isStale`).
    /// - A stored last order that is negative or more than a day ahead of `now` is implausible (corrupt, or from a
    ///   wrong clock) and is dropped, so it cannot block every update.
    public static func ordering(of message: WatchMessage, sequence: Int64?, lastApplied: Int64?,
                                now: Date) -> (apply: Bool, lastApplied: Int64?) {
        let last = plausible(lastApplied, now: now)
        if message == .forget { return (apply: true, lastApplied: sequence ?? last) }
        if isStale(sequence: sequence, lastApplied: last) { return (apply: false, lastApplied: last) }
        return (apply: true, lastApplied: sequence ?? last)
    }

    /// `lastApplied` when it could be a real send order at `now` (0 ... clock ms + 1 day), else nil.
    static func plausible(_ lastApplied: Int64?, now: Date) -> Int64? {
        guard let lastApplied, lastApplied >= 0 else { return nil }
        let t = now.timeIntervalSince1970 * 1000 + 86_400_000
        guard t.isFinite, t > 0, t < 9e15 else { return lastApplied }
        return lastApplied <= Int64(t) ? lastApplied : nil
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
            // A collection state is never an item (`StoreSnapshot.itemRecords`).
            guard !CollectionStates.isReserved(id, snapshot.records[id]),
                  case .object(let w)? = snapshot.records[id], case .object(let r)? = w["record"],
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
