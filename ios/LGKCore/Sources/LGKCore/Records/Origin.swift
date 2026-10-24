/// Origin canonicalisation (desktop `localvault.origin`), ASCII hosts only.
///
/// Mirrors Python's `urlsplit` + `canonicalize_origin` / `normalize_url`. A non-ASCII host throws
/// `.needsPunycode`: the phone does not carry UTS-46, so the editor asks for the `xn--` form.
public enum OriginError: Error, Equatable, Sendable {
    case invalid(String)
    case needsPunycode
}

public enum Origin {
    struct Split {
        var scheme: String
        var netloc: String
        var hasNetloc: Bool
        var path: String
        var query: String
        var fragment: String

        var hasUserInfo: Bool { netloc.contains("@") }

        /// Text after the last `@`.
        private var hostinfo: String {
            if let at = netloc.lastIndex(of: "@") { return String(netloc[netloc.index(after: at)...]) }
            return netloc
        }

        /// Python `SplitResult.hostname`: lower-cased, nil when empty.
        var hostname: String? {
            let info = hostinfo
            var host: Substring
            if let open = info.firstIndex(of: "[") {
                let rest = info[info.index(after: open)...]
                host = rest.firstIndex(of: "]").map { rest[..<$0] } ?? rest
            } else {
                host = info.firstIndex(of: ":").map { info[..<$0] } ?? info[...]
            }
            return host.isEmpty ? nil : host.lowercased()
        }

        /// Python 3.14 `SplitResult.port`.
        func port() throws -> Int? {
            let info = hostinfo
            var tail: Substring
            if let close = info.firstIndex(of: "]") {
                tail = info[info.index(after: close)...]
                guard let colon = tail.firstIndex(of: ":") else { return nil }
                tail = tail[tail.index(after: colon)...]
            } else {
                guard let colon = info.firstIndex(of: ":") else { return nil }
                tail = info[info.index(after: colon)...]
            }
            if tail.isEmpty { return nil }
            guard tail.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), let n = Int(tail), n <= 65535 else {
                throw OriginError.invalid("Invalid port")
            }
            return n
        }
    }

    private static let schemeChars = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.".unicodeScalars)

    /// Python 3.14 `urllib.parse._check_bracketed_host`: an IPvFuture literal (`[vV][hex]+\..+`), or an IPv6
    /// address (a `%zone` is allowed here; `urlHost` refuses it later).
    private static func checkBracketedHost(_ hostname: String) throws {
        let h = Array(hostname.unicodeScalars)
        if let first = h.first, first == "v" || first == "V" {
            var i = 1
            while i < h.count, h[i].properties.isASCIIHexDigit { i += 1 }
            guard i > 1, i < h.count, h[i] == ".", i + 1 < h.count, !h[(i + 1)...].contains("\n") else {
                throw OriginError.invalid("Invalid IPv6 URL")
            }
            return
        }
        // `ipaddress.ip_address`: an IPv4 address is refused in brackets.
        var addr = hostname
        if let pct = hostname.firstIndex(of: "%") {
            let zone = hostname[hostname.index(after: pct)...]
            if zone.isEmpty || zone.contains("%") { throw OriginError.invalid("Invalid IPv6 URL") }
            addr = String(hostname[..<pct])
        }
        if ipv6(addr) == nil { throw OriginError.invalid("Invalid IPv6 URL") }
    }

    /// Python 3.14 `urllib.parse._check_bracketed_netloc`: nothing before `[`, nothing between `]` and `:port`,
    /// and a valid bracketed host. `https://evil.com[::1]` is refused, not read as `https://[::1]`.
    private static func checkBracketedNetloc(_ netloc: [Unicode.Scalar]) throws {
        let hostAndPort = netloc.lastIndex(of: "@").map { Array(netloc[($0 + 1)...]) } ?? netloc
        var hostname: [Unicode.Scalar]
        if let open = hostAndPort.firstIndex(of: "[") {
            if open > 0 { throw OriginError.invalid("Invalid IPv6 URL") }
            let bracketed = Array(hostAndPort[(open + 1)...])
            var port: [Unicode.Scalar] = []
            if let close = bracketed.firstIndex(of: "]") {
                hostname = Array(bracketed[..<close])
                port = Array(bracketed[(close + 1)...])
            } else {
                hostname = bracketed
            }
            if !port.isEmpty && port[0] != ":" { throw OriginError.invalid("Invalid IPv6 URL") }
        } else {
            hostname = hostAndPort.firstIndex(of: ":").map { Array(hostAndPort[..<$0]) } ?? hostAndPort
        }
        try checkBracketedHost(String(String.UnicodeScalarView(hostname)))
    }

    /// Python `urllib.parse.urlsplit` (3.14 rules, including the bracketed-netloc checks). Only the left is stripped.
    static func split(_ value: String) throws -> Split {
        var s = Array(value.unicodeScalars)
        while let f = s.first, f.value <= 0x20 { s.removeFirst() }
        s.removeAll { $0 == "\t" || $0 == "\r" || $0 == "\n" }
        var scheme = ""
        if let colon = s.firstIndex(of: ":"), colon > 0, s[0].properties.isAlphabetic, s[0].isASCII,
           s[..<colon].allSatisfy({ schemeChars.contains($0) }) {
            scheme = String(String.UnicodeScalarView(s[..<colon])).lowercased()
            s = Array(s[(colon + 1)...])
        }
        var netloc: [Unicode.Scalar] = []
        var hasNetloc = false
        if s.count >= 2, s[0] == "/", s[1] == "/" {
            hasNetloc = true
            let rest = s[2...]
            let end = rest.firstIndex { $0 == "/" || $0 == "?" || $0 == "#" } ?? s.endIndex
            netloc = Array(s[2..<end])
            s = Array(s[end...])
            let open = netloc.contains("["), close = netloc.contains("]")
            if open != close { throw OriginError.invalid("Invalid IPv6 URL") }
            if open { try checkBracketedNetloc(netloc) }
        }
        var fragment: [Unicode.Scalar] = []
        if let hash = s.firstIndex(of: "#") { fragment = Array(s[(hash + 1)...]); s = Array(s[..<hash]) }
        var query: [Unicode.Scalar] = []
        if let q = s.firstIndex(of: "?") { query = Array(s[(q + 1)...]); s = Array(s[..<q]) }
        func str(_ a: [Unicode.Scalar]) -> String { String(String.UnicodeScalarView(a)) }
        return Split(scheme: scheme, netloc: str(netloc), hasNetloc: hasNetloc, path: str(s), query: str(query),
                     fragment: str(fragment))
    }

    /// WHATWG forbidden domain code points (C0 controls and whitespace are checked separately).
    private static let forbiddenHostChars = Set("#/:<>?@[\\]^|%\u{7F}".unicodeScalars)

    /// Desktop `_has_space_or_control`: a C0 control or Python whitespace anywhere.
    static func hasSpaceOrControl(_ s: String) -> Bool {
        s.unicodeScalars.contains { $0.value < 32 || isPySpace($0) }
    }

    /// Desktop `_check_host_chars`: refuse a host browsers would refuse (`paypal.com\.evil.com`).
    private static func checkHostChars(_ host: Substring) throws {
        if host.unicodeScalars.contains(where: { $0.value < 32 || isPySpace($0) || forbiddenHostChars.contains($0) }) {
            throw OriginError.invalid("Host contains a character that browsers do not allow")
        }
    }

    /// Lower-case, strip one trailing dot, refuse forbidden code points, and apply Python's ASCII IDNA label checks.
    static func asciiHost(_ raw: String) throws -> String {
        var host = Substring(raw)
        if host.hasSuffix(".") { host = host.dropLast() }
        if host.isEmpty { throw OriginError.invalid("Origin is missing a host") }
        try checkHostChars(host)
        if host.hasSuffix(".") { throw OriginError.invalid("Invalid internationalized host name") }
        guard host.unicodeScalars.allSatisfy(\.isASCII) else { throw OriginError.needsPunycode }
        let lower = host.lowercased()
        let labels = lower.split(separator: ".", omittingEmptySubsequences: false)
        for label in labels.dropLast() where label.isEmpty || label.utf8.count >= 64 {
            throw OriginError.invalid("Invalid internationalized host name")
        }
        if labels.last!.utf8.count >= 64 { throw OriginError.invalid("Invalid internationalized host name") }
        return lower
    }

    static func ipv4(_ s: String) -> [UInt8]? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var out: [UInt8] = []
        for p in parts {
            guard (1...3).contains(p.utf8.count), p.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
                  p.count == 1 || !p.hasPrefix("0"), let n = Int(p), n <= 255 else { return nil }
            out.append(UInt8(n))
        }
        return out
    }

    /// Python `ipaddress.IPv6Address` parsing (no zone ids).
    static func ipv6(_ s: String) -> [UInt8]? {
        guard !s.isEmpty, !s.contains("%"), s.unicodeScalars.allSatisfy(\.isASCII) else { return nil }
        func groups(_ text: Substring, allowV4: Bool) -> [UInt16]? {
            if text.isEmpty { return [] }
            var out: [UInt16] = []
            let parts = text.split(separator: ":", omittingEmptySubsequences: false)
            for (i, g) in parts.enumerated() {
                if allowV4 && i == parts.count - 1 && g.contains(".") {
                    guard let v4 = ipv4(String(g)) else { return nil }
                    out += [UInt16(v4[0]) << 8 | UInt16(v4[1]), UInt16(v4[2]) << 8 | UInt16(v4[3])]
                    continue
                }
                guard (1...4).contains(g.utf8.count), g.unicodeScalars.allSatisfy(\.properties.isASCIIHexDigit),
                      let v = UInt16(g, radix: 16) else { return nil }
                out.append(v)
            }
            return out
        }
        var all: [UInt16]
        if let r = s.range(of: "::") {
            let left = s[..<r.lowerBound], right = s[r.upperBound...]
            if right.contains("::") { return nil }
            guard let l = groups(left, allowV4: false), let rr = groups(right, allowV4: true), l.count + rr.count < 8 else {
                return nil
            }
            all = l + Array(repeating: 0, count: 8 - l.count - rr.count) + rr
        } else {
            guard let g = groups(s[...], allowV4: true), g.count == 8 else { return nil }
            all = g
        }
        return all.flatMap { [UInt8($0 >> 8), UInt8($0 & 0xFF)] }
    }

    static func isLoopback(_ host: String) -> Bool {
        if host == "localhost" || host.hasSuffix(".localhost") { return true }
        if let v4 = ipv4(host) { return v4[0] == 127 }
        if let v6 = ipv6(host) { return v6 == Array(repeating: 0, count: 15) + [1] }
        return false
    }

    static func render(_ host: String) -> String {
        ipv4(host) == nil && ipv6(host) != nil ? "[\(host)]" : host
    }

    /// Desktop `_url_host`: a bracketed host must be a plain IPv6 address (no zone id, not IPv4-mapped, not
    /// IPvFuture); any other host goes through `asciiHost`.
    static func urlHost(_ p: Split, missing: String) throws -> String {
        guard let raw = p.hostname else { throw OriginError.invalid(missing) }
        let info = p.netloc.lastIndex(of: "@").map { p.netloc[p.netloc.index(after: $0)...] } ?? p.netloc[...]
        if !info.contains("[") { return try asciiHost(raw) }
        if raw.contains("%") { throw OriginError.invalid("IPv6 zone identifiers are not supported") }
        guard let v6 = ipv6(raw) else { throw OriginError.invalid("Invalid IPv6 URL") }
        if v6[..<10].allSatisfy({ $0 == 0 }) && v6[10] == 0xFF && v6[11] == 0xFF {
            throw OriginError.invalid("IPv4-mapped IPv6 addresses are not supported")
        }
        return raw
    }

    /// Desktop `canonicalize_origin`: exact `scheme://host[:port]` for credential scoping.
    public static func canonicalize(_ value: String) throws -> String {
        let n = value.unicodeScalars.count
        guard n > 0, n <= 2048 else {
            throw OriginError.invalid("Origin must be a non-empty string shorter than 2049 characters")
        }
        if hasSpaceOrControl(value) { throw OriginError.invalid("Origin contains whitespace or a control character") }
        let p = try split(value)
        if p.hasUserInfo { throw OriginError.invalid("Origins must not contain user information") }
        if !p.query.isEmpty || !p.fragment.isEmpty {
            throw OriginError.invalid("Expected an origin, not a URL with a query or fragment")
        }
        if p.path != "" && p.path != "/" { throw OriginError.invalid("Expected an origin without a path") }
        guard p.scheme == "https" || p.scheme == "http" else {
            throw OriginError.invalid("Only HTTPS origins are allowed (HTTP is limited to localhost)")
        }
        let host = try urlHost(p, missing: "Origin is missing a host")
        if p.scheme == "http" && !isLoopback(host) {
            throw OriginError.invalid("Plain HTTP is allowed only for loopback test origins")
        }
        let port = try p.port()
        let def = p.scheme == "https" ? 443 : 80
        let suffix = port == nil || port == def ? "" : ":\(port!)"
        return "\(p.scheme)://\(render(host))\(suffix)"
    }

    /// Python `str.isspace` for one scalar.
    static func isPySpace(_ c: Unicode.Scalar) -> Bool {
        c.properties.isWhitespace || (0x1C...0x1F).contains(c.value)
    }

    /// Desktop `_split_url`: (scheme, ascii host, port or nil, path, query).
    static func splitURL(_ value: String) throws -> (String, String, Int?, String, String) {
        let n = value.unicodeScalars.count
        guard n > 0, n <= 4096 else { throw OriginError.invalid("URL must be a non-empty string shorter than 4097 characters") }
        if hasSpaceOrControl(value) { throw OriginError.invalid("URL contains whitespace or a control character") }
        let p = try split(value)
        guard p.scheme == "https" || p.scheme == "http" else { throw OriginError.invalid("Only http(s) URLs can be matched") }
        if p.hasUserInfo { throw OriginError.invalid("URLs must not contain user information") }
        let host = try urlHost(p, missing: "URL is missing a host")
        var port = try p.port()
        if port == (p.scheme == "https" ? 443 : 80) { port = nil }
        return (p.scheme, host, port, p.path.isEmpty ? "/" : p.path, p.query)
    }

    /// Desktop `normalize_url`.
    public static func normalizeURL(_ value: String) throws -> String {
        let (scheme, host, port, path, query) = try splitURL(value)
        var out = "\(scheme)://\(render(host))" + (port.map { ":\($0)" } ?? "")
        out += path.hasPrefix("/") ? path : "/" + path
        if !query.isEmpty { out += "?" + query }
        return out
    }

    /// Desktop `origin_of`.
    public static func originOf(_ value: String) throws -> String {
        let (scheme, host, port, _, _) = try splitURL(value)
        return "\(scheme)://\(render(host))" + (port.map { ":\($0)" } ?? "")
    }
}
