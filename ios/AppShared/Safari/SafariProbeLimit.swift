import Foundation
import LGKCore

/// Limits the Safari extension's `classify` requests per origin, as the desktop broker limits its checks
/// (`browser_broker.py`: 10 per origin per minute). A page script that drives the save prompt can then ask
/// "is this username saved here?" only a few times a minute (audit 2026-10-24 M-3). Per origin only, never one
/// global budget, so one busy site cannot stop the prompts of another (L-14).
///
/// The extension's process may end after each request, so the counts live in `<SafariSave>/probes.json`:
/// canonical JSON `{"origins":{"<b64 HMAC of the origin>":[t, ...]},"version":1}`. Origins are keyed by an
/// HMAC under the index key, so the file does not list the sites visited. Best effort: two requests racing
/// may each count once on the same old file (a lost count, never a lost answer), and an unreadable file
/// starts empty.
public struct SafariProbeLimit: Sendable {
    public static let perOrigin = 10
    public static let window: Int64 = 60
    /// At most this many origins are remembered; the least recently asked ones are dropped first.
    static let maxOrigins = 256
    static let fileName = "probes.json"
    static let version: Int64 = 1

    let directory: URL
    let key: [UInt8]
    let now: @Sendable () -> Int64

    public init(directory: URL, key: [UInt8], now: @escaping @Sendable () -> Int64) {
        self.directory = directory; self.key = key; self.now = now
    }

    /// Counts one request for `origin` (canonical) and answers whether it is within the limit. A refused
    /// request is not counted, so the origin is free again `window` seconds after its oldest counted one.
    public func allow(origin: String) -> Bool {
        guard let mac = SafariIndex.mac([.string("probe"), .string(origin)], key: key) else { return false }
        let id = Base64.encode(mac)
        let t = now()
        var table = read().compactMapValues { times -> [Int64]? in
            let recent = times.filter { Self.isRecent($0, now: t) }
            return recent.isEmpty ? nil : recent
        }
        var times = table[id] ?? []
        guard times.count < Self.perOrigin else { write(table); return false }
        times.append(t)
        table[id] = times
        if table.count > Self.maxOrigins {
            let oldest = table.sorted { ($0.value.max() ?? 0) < ($1.value.max() ?? 0) }
                .prefix(table.count - Self.maxOrigins).map(\.key)
            for k in oldest { table[k] = nil }
        }
        write(table)
        return true
    }

    /// Within `window` of now either way, so a clock moved back does not keep an origin locked for long.
    static func isRecent(_ t: Int64, now: Int64) -> Bool {
        let (d, overflow) = now.subtractingReportingOverflow(t)
        return !overflow && d > -window && d < window
    }

    var url: URL { directory.appendingPathComponent(Self.fileName, isDirectory: false) }

    private func read() -> [String: [Int64]] {
        guard let data = try? Data(contentsOf: url),
              case .object(let o)? = try? CanonicalJSON.parse(Array(data)),
              o["version"] == .int(Self.version), case .object(let origins)? = o["origins"] else { return [:] }
        var out: [String: [Int64]] = [:]
        for (k, v) in origins {
            guard case .array(let rows) = v else { continue }
            let times = rows.compactMap { row -> Int64? in if case .int(let n) = row { return n }; return nil }
            out[k] = Array(times.suffix(Self.perOrigin))
        }
        return out
    }

    private func write(_ table: [String: [Int64]]) {
        let origins = table.mapValues { JSONValue.array($0.map { .int($0) }) }
        guard let bytes = try? CanonicalJSON.encode(.object(["version": .int(Self.version), "origins": .object(origins)]),
                                                    dialect: .utf8) else { return }
        try? SafariSaveFiles.writeAtomically(bytes, to: url)
    }
}
