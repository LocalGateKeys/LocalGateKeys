import Foundation
import Crypto

/// The shared helpers of the 2026-11-15 feature pack contract (§0 "Shared helpers"): `fold`, `canon` and `digest`.
public enum RecordDigest {
    /// `canon(v)`: canonical JSON, UTF-8 dialect (`vault_bridge.wrapper_digest`).
    public static func canon(_ value: JSONValue) throws -> [UInt8] { try CanonicalJSON.encode(value, dialect: .utf8) }

    /// `digest(record)`: lower-hex SHA-256 of `canon(record)`; "" when the value cannot be encoded.
    public static func digest(_ value: JSONValue) -> String {
        guard let bytes = try? canon(value) else { return "" }
        return lowerHex(Array(SHA256.hash(data: bytes)))
    }

    /// `fold(s)`: Python `str.strip()` then `str.casefold()`.
    public static func fold(_ s: String) -> String { Casefold.fold(Normalise.pyStrip(s)) }

    /// `fold(s)` as code points, for sets and equality that must match Python (Swift `String` equality is canonical
    /// equivalence, Python's is not).
    public static func foldKey(_ s: String) -> [UInt32] { fold(s).unicodeScalars.map(\.value) }

    /// Code-point equality (Python `==` on `str`).
    public static func same(_ a: String, _ b: String) -> Bool { Array(a.unicodeScalars) == Array(b.unicodeScalars) }

    /// Python `str` order (code points).
    public static func less(_ a: String, _ b: String) -> Bool { scalarOrder(a, b) }

    /// `today`: the device's local calendar date as `YYYY-MM-DD`.
    public static func today(_ date: Date = Date(), calendar: Calendar = .current) -> String {
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", c.year ?? 1970, c.month ?? 1, c.day ?? 1)
    }

    /// The value at a dotted path (`payload.number`) in an object, nil when any step is missing or not an object.
    static func value(at path: String, in object: [String: JSONValue]) -> JSONValue? {
        let parts = path.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        var current: JSONValue = .object(object)
        for p in parts {
            guard case .object(let o) = current, let next = o[p] else { return nil }
            current = next
        }
        return current
    }

    /// `object` with the dotted `path` set to `value` (nil removes it); missing objects on the way are created.
    static func setting(_ path: String, to value: JSONValue?, in object: [String: JSONValue]) -> [String: JSONValue] {
        let parts = path.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        return set(parts[...], value, object)
    }

    private static func set(_ parts: ArraySlice<String>, _ value: JSONValue?, _ object: [String: JSONValue]) -> [String: JSONValue] {
        var out = object
        guard let head = parts.first else { return out }
        if parts.count == 1 {
            out[head] = value
            return out
        }
        let child: [String: JSONValue]
        if case .object(let o)? = out[head] { child = o } else {
            if value == nil { return out }   // nothing to remove below a missing object
            child = [:]
        }
        out[head] = .object(set(parts.dropFirst(), value, child))
        return out
    }
}

/// The login password history push (`vault.py` `update_entry`, iPhone `EditorModel.withPasswordHistory`): when the
/// password actually changes (byte comparison) from a non-empty one, the old password goes first as
/// `{password, changed_at}`, keeping at most `writeLimit` rows from the last 365 days.
public enum PasswordHistoryPush {
    /// The writers' cap (`EditorModel.historyWriteLimit`; Windows and Android still refuse more than 5).
    public static let writeLimit = 5
    public static let keepSeconds: Int64 = 365 * 86_400

    /// `record` with `previous` pushed into its `password_history` when it differs from `record["password"]`.
    public static func pushing(_ previous: String, into record: [String: JSONValue], now: Int64) -> [String: JSONValue] {
        guard !previous.isEmpty, case .string(let new)? = record["password"], Array(previous.utf8) != Array(new.utf8) else {
            return record
        }
        var out = record
        var history: [JSONValue] = if case .array(let a)? = record["password_history"] { a } else { [] }
        history.removeAll { row in
            guard case .object(let o) = row else { return false }
            let at: Int64? = if case .int(let n)? = o["changed_at"] ?? o["replaced_at"] { n } else { nil }
            return at.map { now - $0 > keepSeconds } ?? false
        }
        history.insert(.object(["password": .string(previous), "changed_at": .int(now)]), at: 0)
        out["password_history"] = .array(Array(history.prefix(writeLimit)))
        return out
    }
}
