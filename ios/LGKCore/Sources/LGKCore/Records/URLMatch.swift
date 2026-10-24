/// Multi-URL credential matching: a port of the desktop's `localvault.origin` (`match_rank`, `entry_urls`,
/// `candidates_for`, `base_domain`, `public_suffix`, `parse_suffix_rules`).
///
/// Every string comparison here is by Unicode scalars (`Scalars`), never `String ==`, which applies
/// canonical equivalence where Python compares code points.
///
/// Hosts are ASCII on the phone (`Origin.asciiHost` throws `.needsPunycode` for a non-ASCII host), so a
/// candidate or stored URL with a non-ASCII host fails closed: it matches nothing. Stored origins are
/// A-label already (the desktop normalises them), and browsers report A-label hosts.

/// Code-point comparisons, as Python `str` compares. Swift `String` ==, hasPrefix and contains use
/// canonical equivalence, so NFC "café" would equal NFD "café"; the desktop treats them as different.
public enum Scalars {
    public static func contains(_ a: String, _ n: String) -> Bool {
        let h = Array(a.unicodeScalars), nd = Array(n.unicodeScalars)
        if nd.isEmpty { return true }
        guard nd.count <= h.count else { return false }
        for i in 0...(h.count - nd.count) where h[i] == nd[0] && h[i..<(i + nd.count)].elementsEqual(nd) { return true }
        return false
    }

    public static func equal(_ a: String, _ b: String) -> Bool {
        a.unicodeScalars.elementsEqual(b.unicodeScalars)
    }

    public static func hasPrefix(_ s: String, _ prefix: String) -> Bool {
        s.unicodeScalars.starts(with: prefix.unicodeScalars)
    }

    /// Python `str` ordering (code point by code point).
    public static func less(_ a: String, _ b: String) -> Bool {
        a.unicodeScalars.lexicographicallyPrecedes(b.unicodeScalars)
    }
}

/// The four closed match modes, in rank order (`MATCH_MODES`).
public enum URLMatchMode: String, CaseIterable, Sendable {
    case exactOrigin = "exact_origin"
    case host = "host"
    case baseDomain = "base_domain"
    case startsWith = "starts_with"

    public var rank: Int { Self.allCases.firstIndex(of: self)! }

    /// Exact code-point lookup of a stored mode string.
    public init?(stored: String) {
        guard let m = Self.allCases.first(where: { Scalars.equal($0.rawValue, stored) }) else { return nil }
        self = m
    }
}

/// One `{"url", "match"}` row.
public struct URLRow: Equatable, Sendable {
    public var url: String
    public var mode: URLMatchMode
    public init(url: String, mode: URLMatchMode) { self.url = url; self.mode = mode }
}

/// Public Suffix List rules in A-label form (`SuffixRules`).
public struct PublicSuffixRules: Sendable {
    public let normal: Set<[Unicode.Scalar]>
    public let wildcard: Set<[Unicode.Scalar]>
    public let exception: Set<[Unicode.Scalar]>

    /// The desktop's `_LOCAL_SUFFIX_RULES` (they only ever narrow a registrable domain).
    public static let localRules = ["*.web.core.windows.net"]

    /// `parse_suffix_rules` over the list text, plus `localRules`. Nil when the list is truncated
    /// (`<= 1000` normal rules), which makes `base_domain` fail closed like the desktop.
    public static func load(listText: String) -> PublicSuffixRules? {
        var r = parse(lines: listText.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r\n" || $0 == "\r" }).map(String.init))
        let local = parse(lines: localRules)
        r = PublicSuffixRules(normal: r.normal.union(local.normal), wildcard: r.wildcard.union(local.wildcard),
                              exception: r.exception.union(local.exception))
        return r.normal.count > 1000 ? r : nil
    }

    init(normal: Set<[Unicode.Scalar]>, wildcard: Set<[Unicode.Scalar]>, exception: Set<[Unicode.Scalar]>) {
        self.normal = normal; self.wildcard = wildcard; self.exception = exception
    }

    /// `parse_suffix_rules`.
    public static func parse(lines: [String]) -> PublicSuffixRules {
        var normal = Set<[Unicode.Scalar]>(), wildcard = Set<[Unicode.Scalar]>(), exception = Set<[Unicode.Scalar]>()
        for raw in lines {
            let line = pyStrip(Array(raw.unicodeScalars))
            if line.isEmpty || line.starts(with: ["/", "/"]) { continue }
            var rule = Array(line.split(whereSeparator: Origin.isPySpace)[0])
            var target = 0
            if rule.first == "!" { target = 2; rule.removeFirst() }
            else if rule.starts(with: ["*", "."]) { target = 1; rule.removeFirst(2) }
            if rule.isEmpty || rule.contains("*") || rule.contains("!") { continue }
            guard let ascii = ruleToASCII(rule) else { continue }
            switch target {
            case 1: wildcard.insert(ascii)
            case 2: exception.insert(ascii)
            default: normal.insert(ascii)
            }
        }
        return PublicSuffixRules(normal: normal, wildcard: wildcard, exception: exception)
    }

    /// Python `str.strip()`.
    static func pyStrip(_ s: [Unicode.Scalar]) -> [Unicode.Scalar] {
        var lo = 0, hi = s.count
        while lo < hi && Origin.isPySpace(s[lo]) { lo += 1 }
        while hi > lo && Origin.isPySpace(s[hi - 1]) { hi -= 1 }
        return Array(s[lo..<hi])
    }

    /// `_rule_to_ascii`: ASCII labels lower-cased, others IDNA-encoded (nil = rule ignored).
    static func ruleToASCII(_ rule: [Unicode.Scalar]) -> [Unicode.Scalar]? {
        var out: [Unicode.Scalar] = []
        for (i, label) in rule.split(separator: ".", omittingEmptySubsequences: false).enumerated() {
            if i > 0 { out.append(".") }
            if label.allSatisfy(\.isASCII) {
                out += label.map { ("A"..."Z").contains($0) ? Unicode.Scalar($0.value + 32)! : $0 }
            } else {
                guard let a = Punycode.idnaLabel(Array(label)) else { return nil }
                out += a
            }
        }
        return out
    }

    /// `public_suffix` for an A-label host.
    public func publicSuffix(_ host: [Unicode.Scalar]) -> [Unicode.Scalar] {
        let labels = host.split(separator: ".", omittingEmptySubsequences: false).map(Array.init)
        func join(_ from: Int) -> [Unicode.Scalar] { Array(labels[from...].joined(separator: ["."])) }
        let count = labels.count
        for i in 0..<count where exception.contains(join(i)) {
            return i + 1 < count ? join(i + 1) : []
        }
        for i in 0..<count {
            if normal.contains(join(i)) { return join(i) }
            if i + 1 < count && wildcard.contains(join(i + 1)) { return join(i) }
        }
        return labels[count - 1]
    }
}

/// RFC 3492 Punycode for PSL rules. PSL rules are already lower-case NFC, the form UTS-46 mapping
/// leaves unchanged, so `xn--` + Punycode equals the desktop's `idna.encode(..., uts46=True)` for them
/// (checked against the desktop's parsed rule set in `URLMatchTests`).
enum Punycode {
    static func idnaLabel(_ label: [Unicode.Scalar]) -> [Unicode.Scalar]? {
        let lowered = label.flatMap { Array(String($0).lowercased().unicodeScalars) }
        guard let enc = encode(lowered.map(\.value)) else { return nil }
        let out = Array("xn--".unicodeScalars) + enc
        return out.count < 64 ? out : nil
    }

    static func encode(_ input: [UInt32]) -> [Unicode.Scalar]? {
        let base: UInt32 = 36, tMin: UInt32 = 1, tMax: UInt32 = 26, skew: UInt32 = 38, damp: UInt32 = 700
        var n: UInt32 = 128, delta: UInt32 = 0, bias: UInt32 = 72
        var out: [Unicode.Scalar] = input.filter { $0 < 128 }.map { Unicode.Scalar($0)! }
        let b = UInt32(out.count)
        var h = b
        if b > 0 { out.append("-") }
        func digit(_ d: UInt32) -> Unicode.Scalar { Unicode.Scalar(d < 26 ? d + 97 : d + 22)! }
        func adapt(_ d: UInt32, _ numPoints: UInt32, _ first: Bool) -> UInt32 {
            var delta = first ? d / damp : d / 2
            delta += delta / numPoints
            var k: UInt32 = 0
            while delta > ((base - tMin) * tMax) / 2 { delta /= base - tMin; k += base }
            return k + (base - tMin + 1) * delta / (delta + skew)
        }
        while h < UInt32(input.count) {
            guard let m = input.filter({ $0 >= n }).min() else { return nil }
            let (mul, o1) = (m - n).multipliedReportingOverflow(by: h + 1)
            let (d2, o2) = delta.addingReportingOverflow(mul)
            if o1 || o2 { return nil }
            delta = d2; n = m
            for c in input {
                if c < n { delta += 1 }
                if c == n {
                    var q = delta, k = base
                    while true {
                        let t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias)
                        if q < t { break }
                        out.append(digit(t + (q - t) % (base - t)))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    out.append(digit(q))
                    bias = adapt(delta, h + 1, h == b)
                    delta = 0; h += 1
                }
            }
            delta += 1; n += 1
        }
        return out
    }
}

/// The desktop's URL matcher. `rules` nil = no usable suffix list (`base_domain` matches the exact host).
public struct URLMatcher: Sendable {
    public let rules: PublicSuffixRules?
    public init(rules: PublicSuffixRules?) { self.rules = rules }

    /// `host_of`.
    public static func hostOf(_ url: String) throws -> String { try Origin.splitURL(url).1 }

    /// `base_domain` for an A-label host.
    public func baseDomain(_ rawHost: String) throws -> String {
        if rawHost.contains(":") {   // an IPv6 literal (`hostOf` gives it without brackets)
            if rawHost.contains("%") { throw OriginError.invalid("IPv6 zone identifiers are not supported") }
            guard Origin.ipv6(rawHost) != nil else { throw OriginError.invalid("Invalid IPv6 URL") }
            return rawHost.lowercased()
        }
        let host = try Origin.asciiHost(rawHost)
        if Origin.ipv4(host) != nil || Origin.ipv6(host) != nil { return host }
        let scalars = Array(host.unicodeScalars)
        guard let rules, scalars.contains(".") else { return host }
        let suffix = rules.publicSuffix(scalars)
        if suffix == scalars { return host }
        let head = scalars[..<(scalars.count - suffix.count - 1)]
        let registrable = head.split(separator: ".", omittingEmptySubsequences: false).last.map(Array.init) ?? []
        return String(String.UnicodeScalarView(registrable + ["."] + suffix))
    }

    public func baseDomainOf(_ url: String) throws -> String { try baseDomain(try Self.hostOf(url)) }

    /// `_starts_with` on normalised URLs, at a path boundary.
    static func startsWith(stored: String, candidate: String) -> Bool {
        let s = Array(stored.unicodeScalars), c = Array(candidate.unicodeScalars)
        if s == c { return true }
        guard c.starts(with: s) else { return false }
        if s.last == "/" { return true }
        return c[s.count] == "/" || c[s.count] == "?"
    }

    /// `_row_matches`.
    func rowMatches(_ row: URLRow, candidate: String) throws -> Bool {
        switch row.mode {
        case .exactOrigin: return Scalars.equal(try Origin.originOf(row.url), try Origin.originOf(candidate))
        case .host:
            // Audit 2026-10-24 I-13: the port counts too (a default port equals no port, whatever the scheme).
            let r = try Origin.splitURL(row.url), c = try Origin.splitURL(candidate)
            return Scalars.equal(r.1, c.1) && r.2 == c.2
        case .baseDomain: return Scalars.equal(try baseDomainOf(row.url), try baseDomainOf(candidate))
        case .startsWith:
            return Self.startsWith(stored: try Origin.normalizeURL(row.url), candidate: try Origin.normalizeURL(candidate))
        }
    }

    /// `match_rank`: the best (lowest) mode rank, nil for no match or a malformed candidate. A plain-HTTP
    /// candidate on a non-loopback host (one `Origin.canonicalize` refuses) never matches, so `host` /
    /// `base_domain` rows, which ignore the scheme, cannot offer an HTTPS login to an `http://` page (audit M-4).
    public func matchRank(_ rows: [URLRow], candidate: String) -> Int? {
        guard let parts = try? Origin.splitURL(candidate) else { return nil }
        if parts.0 == "http" && !Origin.isLoopback(parts.1) { return nil }
        var best: Int?
        for row in rows where (try? rowMatches(row, candidate: candidate)) == true {
            best = min(best ?? row.mode.rank, row.mode.rank)
        }
        return best
    }

    /// `entry_urls`: the URL rows of a web login, migrating the legacy single origin. Bare-string rows
    /// are skipped here exactly as the desktop's `entry_urls` skips them (normalisation turns them into
    /// `{"url", "match"}` rows before they are stored).
    public static func entryURLs(_ record: [String: JSONValue]) -> [URLRow] {
        guard case .object(let scope)? = record["scope"] else { return [] }
        var rows: [URLRow] = []
        if case .array(let list)? = scope["urls"] {
            for case .object(let row) in list {
                guard case .string(let url)? = row["url"] else { continue }
                var mode = URLMatchMode.exactOrigin
                if case .string(let m)? = row["match"], let parsed = URLMatchMode(stored: m) { mode = parsed }
                rows.append(URLRow(url: url, mode: mode))
            }
        }
        if rows.isEmpty, case .string(let origin)? = scope["origin"], !origin.isEmpty {
            rows.append(URLRow(url: origin, mode: .exactOrigin))
        }
        return rows
    }

    /// `candidates_for` over several candidate URLs (one AutoFill request may name several service
    /// identifiers): web records that match any of them, ranked by best mode, then most recently
    /// updated, then id. Returns the indices into `records`.
    public func candidates(_ records: [[String: JSONValue]], urls: [String]) -> [Int] {
        var ranked: [(rank: Int, updated: Int64, id: String, index: Int)] = []
        for (i, r) in records.enumerated() {
            guard case .string(let kind)? = r["kind"], Scalars.equal(kind, "web") else { continue }
            let rows = Self.entryURLs(r)
            guard let rank = urls.compactMap({ matchRank(rows, candidate: $0) }).min() else { continue }
            var updated: Int64 = 0
            switch r["updated_at"] {
            case .int(let n)?: updated = n
            case .bool(let b)?: updated = b ? 1 : 0   // Python: bool is an int
            default: break
            }
            var id = ""
            if case .string(let s)? = r["id"] { id = s }
            ranked.append((rank, updated, id, i))
        }
        ranked.sort { a, b in
            if a.rank != b.rank { return a.rank < b.rank }
            if a.updated != b.updated { return a.updated > b.updated }
            return Scalars.less(a.id, b.id)
        }
        return ranked.map(\.index)
    }
}
