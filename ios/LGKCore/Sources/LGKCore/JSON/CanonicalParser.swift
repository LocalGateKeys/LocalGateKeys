extension CanonicalJSON {
    /// Strict byte-level JSON parser. Rejects duplicate keys, NaN/Infinity, lone surrogate
    /// escapes and integers outside Int64 (excluding Int64.min, per the ±(2^63−1) rule).
    public static func parse(_ data: [UInt8]) throws -> JSONValue {
        var p = Parser(b: data)
        p.skipWS()
        let v = try p.value(depth: 0)
        p.skipWS()
        guard p.i == data.count else { throw JSONError.syntax }
        return v
    }

    private struct Parser {
        let b: [UInt8]
        var i = 0
        init(b: [UInt8]) { self.b = b }

        mutating func skipWS() {
            while i < b.count, b[i] == 0x20 || b[i] == 0x09 || b[i] == 0x0A || b[i] == 0x0D { i += 1 }
        }

        func peek() -> UInt8? { i < b.count ? b[i] : nil }

        mutating func literal(_ s: String) -> Bool {
            let u = Array(s.utf8)
            guard i + u.count <= b.count, Array(b[i..<i + u.count]) == u else { return false }
            i += u.count
            return true
        }

        mutating func value(depth: Int) throws -> JSONValue {
            guard depth < 512 else { throw JSONError.syntax }
            guard let c = peek() else { throw JSONError.syntax }
            switch c {
            case 0x7B: return try object(depth)
            case 0x5B: return try array(depth)
            case 0x22: return .string(try string())
            case 0x74: if literal("true") { return .bool(true) }; throw JSONError.syntax
            case 0x66: if literal("false") { return .bool(false) }; throw JSONError.syntax
            case 0x6E: if literal("null") { return .null }; throw JSONError.syntax
            case 0x4E: if literal("NaN") { throw JSONError.nonFinite }; throw JSONError.syntax
            case 0x49: if literal("Infinity") { throw JSONError.nonFinite }; throw JSONError.syntax
            case 0x2D, 0x30...0x39:
                if c == 0x2D, i + 1 < b.count, b[i + 1] == 0x49 {
                    i += 1
                    if literal("Infinity") { throw JSONError.nonFinite }
                    throw JSONError.syntax
                }
                return try number()
            default: throw JSONError.syntax
            }
        }

        mutating func number() throws -> JSONValue {
            let start = i
            var isFloat = false
            if peek() == 0x2D { i += 1 }
            guard let f = peek() else { throw JSONError.syntax }
            if f == 0x30 { i += 1 }
            else if (0x31...0x39).contains(f) { while let d = peek(), (0x30...0x39).contains(d) { i += 1 } }
            else { throw JSONError.syntax }
            if peek() == 0x2E {
                isFloat = true; i += 1
                guard let d = peek(), (0x30...0x39).contains(d) else { throw JSONError.syntax }
                while let d = peek(), (0x30...0x39).contains(d) { i += 1 }
            }
            if let e = peek(), e == 0x65 || e == 0x45 {
                isFloat = true; i += 1
                if let s = peek(), s == 0x2B || s == 0x2D { i += 1 }
                guard let d = peek(), (0x30...0x39).contains(d) else { throw JSONError.syntax }
                while let d = peek(), (0x30...0x39).contains(d) { i += 1 }
            }
            let text = String(decoding: b[start..<i], as: UTF8.self)
            if isFloat {
                guard let d = Double(text) else { throw JSONError.syntax }
                guard d.isFinite else { throw JSONError.nonFinite }
                return .float(d)
            }
            guard let n = Int64(text), n != Int64.min else { throw JSONError.intOutOfRange }
            return .int(n)
        }

        mutating func hex4() throws -> UInt32 {
            guard i + 4 <= b.count else { throw JSONError.syntax }
            var v: UInt32 = 0
            for k in 0..<4 {
                let c = b[i + k]
                let d: UInt32
                switch c {
                case 0x30...0x39: d = UInt32(c) - 0x30
                case 0x61...0x66: d = UInt32(c) - 0x61 + 10
                case 0x41...0x46: d = UInt32(c) - 0x41 + 10
                default: throw JSONError.syntax
                }
                v = v << 4 | d
            }
            i += 4
            return v
        }

        mutating func string() throws -> String {
            i += 1 // opening quote
            var scalars = String.UnicodeScalarView()
            while true {
                guard let c = peek() else { throw JSONError.syntax }
                if c == 0x22 { i += 1; return String(scalars) }
                if c < 0x20 { throw JSONError.syntax }
                if c == 0x5C {
                    i += 1
                    guard let e = peek() else { throw JSONError.syntax }
                    i += 1
                    switch e {
                    case 0x22: scalars.append("\"")
                    case 0x5C: scalars.append("\\")
                    case 0x2F: scalars.append("/")
                    case 0x62: scalars.append("\u{08}")
                    case 0x66: scalars.append("\u{0C}")
                    case 0x6E: scalars.append("\n")
                    case 0x72: scalars.append("\r")
                    case 0x74: scalars.append("\t")
                    case 0x75:
                        let u = try hex4()
                        if (0xD800...0xDBFF).contains(u) {
                            guard i + 1 < b.count, b[i] == 0x5C, b[i + 1] == 0x75 else { throw JSONError.loneSurrogate }
                            i += 2
                            let lo = try hex4()
                            guard (0xDC00...0xDFFF).contains(lo) else { throw JSONError.loneSurrogate }
                            scalars.append(Unicode.Scalar(0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00))!)
                        } else if (0xDC00...0xDFFF).contains(u) {
                            throw JSONError.loneSurrogate
                        } else {
                            scalars.append(Unicode.Scalar(u)!)
                        }
                    default: throw JSONError.syntax
                    }
                } else if c < 0x80 {
                    scalars.append(Unicode.Scalar(c)); i += 1
                } else {
                    scalars.append(try utf8Scalar())
                }
            }
        }

        mutating func utf8Scalar() throws -> Unicode.Scalar {
            let c = b[i]
            let n: Int, minV: UInt32
            var v: UInt32
            switch c {
            case 0xC2...0xDF: n = 1; v = UInt32(c & 0x1F); minV = 0x80
            case 0xE0...0xEF: n = 2; v = UInt32(c & 0x0F); minV = 0x800
            case 0xF0...0xF4: n = 3; v = UInt32(c & 0x07); minV = 0x10000
            default: throw JSONError.syntax
            }
            for k in 1...n {
                guard i + k < b.count, b[i + k] & 0xC0 == 0x80 else { throw JSONError.syntax }
                v = v << 6 | UInt32(b[i + k] & 0x3F)
            }
            guard v >= minV, let s = Unicode.Scalar(v) else { throw JSONError.syntax }
            i += n + 1
            return s
        }

        mutating func array(_ depth: Int) throws -> JSONValue {
            i += 1
            var out = [JSONValue]()
            skipWS()
            if peek() == 0x5D { i += 1; return .array(out) }
            while true {
                skipWS()
                out.append(try value(depth: depth + 1))
                skipWS()
                guard let c = peek() else { throw JSONError.syntax }
                i += 1
                if c == 0x2C { continue }
                if c == 0x5D { return .array(out) }
                throw JSONError.syntax
            }
        }

        mutating func object(_ depth: Int) throws -> JSONValue {
            i += 1
            var out = [String: JSONValue]()
            skipWS()
            if peek() == 0x7D { i += 1; return .object(out) }
            while true {
                skipWS()
                guard peek() == 0x22 else { throw JSONError.syntax }
                let k = try string()
                skipWS()
                guard peek() == 0x3A else { throw JSONError.syntax }
                i += 1
                skipWS()
                let v = try value(depth: depth + 1)
                // Swift String equality is canonical equivalence; a collision of distinct
                // scalar sequences cannot be represented by [String: JSONValue], so refuse it.
                if out[k] != nil { throw JSONError.duplicateKey }
                out[k] = v
                skipWS()
                guard let c = peek() else { throw JSONError.syntax }
                i += 1
                if c == 0x2C { continue }
                if c == 0x7D { return .object(out) }
                throw JSONError.syntax
            }
        }
    }
}
