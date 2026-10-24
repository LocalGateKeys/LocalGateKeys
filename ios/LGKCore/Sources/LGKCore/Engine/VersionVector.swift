/// Malformed input to the merge engine (desktop `EngineError`).
public struct EngineError: Error, Equatable, Sendable, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

/// Version vectors: device id -> counter in 0...2^53-1; missing entries equal 0.
public enum VersionVector {
    public static let maxCounter: Int64 = (1 << 53) - 1

    public enum Relation: Equatable, Sendable { case equal, a, b, concurrent }

    static func check(_ vv: [String: Int64]) throws {
        for (dev, n) in vv {
            guard Identifier.isValid(dev) else { throw EngineError("invalid device id: \(dev)") }
            guard (0...maxCounter).contains(n) else { throw EngineError("invalid counter for \(dev): \(n)") }
        }
    }

    /// `.a` means *a* dominates.
    public static func compare(_ a: [String: Int64], _ b: [String: Int64]) throws -> Relation {
        try check(a); try check(b)
        var aAhead = false, bAhead = false
        for dev in Set(a.keys).union(b.keys) {
            let x = a[dev] ?? 0, y = b[dev] ?? 0
            if x > y { aAhead = true } else if y > x { bAhead = true }
        }
        switch (aAhead, bAhead) {
        case (true, true): return .concurrent
        case (true, false): return .a
        case (false, true): return .b
        default: return .equal
        }
    }

    /// Vector for a local edit or delete by `device`: `vv[device] += 1`, zero entries dropped.
    public static func bump(_ vv: [String: Int64], device: String) throws -> [String: Int64] {
        try check(vv); try check([device: 1])
        let n = (vv[device] ?? 0) + 1
        guard n <= maxCounter else { throw EngineError("counter for \(device) overflows") }
        var out = vv.filter { $0.value != 0 }
        out[device] = n
        return out
    }

    /// Element-wise maximum, zero entries dropped.
    public static func max(_ a: [String: Int64], _ b: [String: Int64]) -> [String: Int64] {
        var out: [String: Int64] = [:]
        for dev in Set(a.keys).union(b.keys) {
            let n = Swift.max(a[dev] ?? 0, b[dev] ?? 0)
            if n != 0 { out[dev] = n }
        }
        return out
    }
}
