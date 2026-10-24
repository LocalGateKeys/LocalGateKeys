public enum CanonicalJSON {
    public static func encode(_ v: JSONValue, dialect: Dialect) throws -> [UInt8] {
        var out = [UInt8]()
        try write(v, dialect, &out)
        return out
    }

    private static let hex = Array("0123456789abcdef".utf8)

    private static func write(_ v: JSONValue, _ d: Dialect, _ out: inout [UInt8]) throws {
        switch v {
        case .null: out += Array("null".utf8)
        case .bool(let b): out += Array((b ? "true" : "false").utf8)
        case .int(let i): out += Array(String(i).utf8)
        case .float(let f):
            guard f.isFinite else { throw JSONError.nonFinite }
            out += Array(PythonFloat.repr(f).utf8)
        case .string(let s): writeString(s, d, &out)
        case .array(let a):
            out.append(0x5B)
            for (i, e) in a.enumerated() {
                if i > 0 { out.append(0x2C) }
                try write(e, d, &out)
            }
            out.append(0x5D)
        case .object(let o):
            // Sort by Unicode code point (Python str order), not UTF-16 or canonical equivalence.
            let keyed = o.map { (Array($0.key.unicodeScalars.map(\.value)), $0.key, $0.value) }
            let sorted = keyed.sorted { $0.0.lexicographicallyPrecedes($1.0) }
            out.append(0x7B)
            for (i, e) in sorted.enumerated() {
                if i > 0 { out.append(0x2C) }
                writeString(e.1, d, &out)
                out.append(0x3A)
                try write(e.2, d, &out)
            }
            out.append(0x7D)
        }
    }

    private static func u4(_ x: UInt32, _ out: inout [UInt8]) {
        out += [0x5C, 0x75]
        for shift in stride(from: 12, through: 0, by: -4) { out.append(hex[Int((x >> UInt32(shift)) & 0xF)]) }
    }

    private static func writeString(_ s: String, _ d: Dialect, _ out: inout [UInt8]) {
        out.append(0x22)
        for sc in s.unicodeScalars {
            let c = sc.value
            switch c {
            case 0x22: out += [0x5C, 0x22]
            case 0x5C: out += [0x5C, 0x5C]
            case 0x08: out += [0x5C, 0x62]
            case 0x0C: out += [0x5C, 0x66]
            case 0x0A: out += [0x5C, 0x6E]
            case 0x0D: out += [0x5C, 0x72]
            case 0x09: out += [0x5C, 0x74]
            case 0..<0x20: u4(c, &out)
            case 0x20...0x7E: out.append(UInt8(c))
            default:
                if d == .utf8 {
                    out += Array(String(sc).utf8)
                } else if c >= 0x10000 {
                    let x = c - 0x10000
                    u4(0xD800 + (x >> 10), &out)
                    u4(0xDC00 + (x & 0x3FF), &out)
                } else {
                    u4(c, &out)
                }
            }
        }
        out.append(0x22)
    }
}
