/// The CBOR subset WebAuthn needs (desktop `passkeys.cbor_encode`): ints, byte and text strings,
/// maps whose keys keep the given order.
public indirect enum CBOR {
    case int(Int64)
    case bytes([UInt8])
    case text(String)
    case map([(CBOR, CBOR)])

    public var encoded: [UInt8] {
        var out = [UInt8](); append(to: &out); return out
    }

    private static func head(_ major: UInt8, _ value: UInt64, _ out: inout [UInt8]) {
        let m = major << 5
        switch value {
        case ..<24: out.append(m | UInt8(value))
        case ...0xFF: out += [m | 24, UInt8(value)]
        case ...0xFFFF: out.append(m | 25); out += (0..<2).reversed().map { UInt8((value >> (8 * UInt64($0))) & 0xFF) }
        case ...0xFFFF_FFFF: out.append(m | 26); out += (0..<4).reversed().map { UInt8((value >> (8 * UInt64($0))) & 0xFF) }
        default: out.append(m | 27); out += (0..<8).reversed().map { UInt8((value >> (8 * UInt64($0))) & 0xFF) }
        }
    }

    private func append(to out: inout [UInt8]) {
        switch self {
        case .int(let n):
            if n >= 0 { CBOR.head(0, UInt64(n), &out) } else { CBOR.head(1, UInt64(-1 - n), &out) }
        case .bytes(let b): CBOR.head(2, UInt64(b.count), &out); out += b
        case .text(let s): let u = Array(s.utf8); CBOR.head(3, UInt64(u.count), &out); out += u
        case .map(let pairs):
            CBOR.head(5, UInt64(pairs.count), &out)
            for (k, v) in pairs { k.append(to: &out); v.append(to: &out) }
        }
    }
}
