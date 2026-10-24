/// The address ranges a LAN sync endpoint may use (desktop `sync.lan_address`).
///
/// Literal IPv4/IPv6 text only, parsed like Python's `ipaddress.ip_address`. Accepted networks:
/// 10/8, 172.16/12, 192.168/16, 169.254/16, 127/8, ::1/128, fe80::/10, fc00::/7. An IPv4-mapped
/// IPv6 address is never accepted, nor is an IPv6 address with a zone id (`fe80::1%eth0`).
public enum LanAddress {
    public enum Parsed: Equatable, Sendable {
        case v4([UInt8])
        case v6([UInt8])
    }

    public static let networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                                  "127.0.0.0/8", "::1/128", "fe80::/10", "fc00::/7"]

    public static func isLAN(_ text: String) -> Bool {
        guard let p = parse(text) else { return false }
        return isLAN(p)
    }

    static func isLAN(_ p: Parsed) -> Bool {
        switch p {
        case .v4(let b):
            return b[0] == 10 || (b[0] == 172 && b[1] & 0xF0 == 16) || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254) || b[0] == 127
        case .v6(let b):
            if b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return true }
            return (b[0] == 0xFE && b[1] & 0xC0 == 0x80) || b[0] & 0xFE == 0xFC
        }
    }

    /// The canonical text (Python `str(ip_address(text))`) of a LAN address, or nil.
    static func normalisedLAN(_ text: String) -> String? {
        guard let p = parse(text), isLAN(p) else { return nil }
        return format(p)
    }

    /// Python `ipaddress.ip_address` parsing; a zone id (`%...`) returns nil (never accepted here).
    public static func parse(_ text: String) -> Parsed? {
        guard text.utf8.count <= 255, text.unicodeScalars.allSatisfy({ $0.isASCII }) else { return nil }
        if let v4 = parseV4(Substring(text)) { return .v4(v4) }
        if text.contains("%") { return nil }
        if let v6 = parseV6(text) { return .v6(v6) }
        return nil
    }

    private static func parseV4(_ s: Substring) -> [UInt8]? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var out = [UInt8]()
        for p in parts {
            guard (1...3).contains(p.count), p.allSatisfy({ $0 >= "0" && $0 <= "9" }) else { return nil }
            if p.count > 1 && p.first == "0" { return nil }  // Python rejects leading zeros
            guard let v = Int(p), v <= 255 else { return nil }
            out.append(UInt8(v))
        }
        return out
    }

    private static func parseV6(_ text: String) -> [UInt8]? {
        var parts = text.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 3 else { return nil }
        if let last = parts.last, last.contains(".") {
            guard let v4 = parseV4(Substring(last)) else { return nil }
            parts.removeLast()
            parts.append(String(UInt16(v4[0]) << 8 | UInt16(v4[1]), radix: 16))
            parts.append(String(UInt16(v4[2]) << 8 | UInt16(v4[3]), radix: 16))
        }
        guard parts.count <= 9 else { return nil }
        var skip: Int? = nil
        for i in 1..<(parts.count - 1) where parts[i].isEmpty {
            if skip != nil { return nil }
            skip = i
        }
        var hextets = [UInt16]()
        func hex(_ s: String) -> UInt16? {
            guard (1...4).contains(s.count), s.allSatisfy({ $0.isHexDigit }) else { return nil }
            return UInt16(s, radix: 16)
        }
        if let skip {
            var head = Array(parts[..<skip]), rest = Array(parts[(skip + 1)...])
            if head.first == "" { guard head.count == 1 else { return nil }; head = [] }
            if rest.last == "" { guard rest.count == 1 else { return nil }; rest = [] }
            let missing = 8 - head.count - rest.count
            guard missing >= 1 else { return nil }
            for p in head { guard let h = hex(p) else { return nil }; hextets.append(h) }
            hextets += Array(repeating: 0, count: missing)
            for p in rest { guard let h = hex(p) else { return nil }; hextets.append(h) }
        } else {
            guard parts.count == 8 else { return nil }
            for p in parts { guard let h = hex(p) else { return nil }; hextets.append(h) }
        }
        guard hextets.count == 8 else { return nil }
        return hextets.flatMap { [UInt8($0 >> 8), UInt8($0 & 0xFF)] }
    }

    /// Python `str()` of the address: dotted IPv4, RFC 5952-style compressed lowercase IPv6.
    static func format(_ p: Parsed) -> String {
        switch p {
        case .v4(let b): return b.map(String.init).joined(separator: ".")
        case .v6(let b):
            let h = (0..<8).map { UInt16(b[2 * $0]) << 8 | UInt16(b[2 * $0 + 1]) }
            var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0
            for (i, v) in h.enumerated() {
                if v == 0 {
                    if curStart < 0 { curStart = i; curLen = 0 }
                    curLen += 1
                    if curLen > bestLen { bestStart = curStart; bestLen = curLen }
                } else { curStart = -1; curLen = 0 }
            }
            let words = h.map { String($0, radix: 16) }
            guard bestLen > 1 else { return words.joined(separator: ":") }
            let head = words[..<bestStart].joined(separator: ":")
            let rest = words[(bestStart + bestLen)...].joined(separator: ":")
            return head + "::" + rest
        }
    }
}
