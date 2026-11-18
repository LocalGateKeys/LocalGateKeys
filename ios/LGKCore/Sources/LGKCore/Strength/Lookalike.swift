import Foundation

/// `kind`: `exact`, `related`, `lookalike` or `unknown`. `matched` is the saved origin exactly as given, or nil.
public struct LookalikeVerdict: Equatable, Sendable {
    public let kind: String
    public let matched: String?
    public let reason: String
    public init(kind: String, matched: String?, reason: String) {
        self.kind = kind; self.matched = matched; self.reason = reason
    }
}

/// Lookalike-domain classifier for the phishing shield: a port of desktop `lookalike.py` / extension `lookalike.js`
/// and Kotlin `Lookalike` (read the Python module doc for the verdicts and their order). Shared vectors:
/// `tests/vectors/lookalike/cases.json`.
///
/// Verdicts, strongest first: `exact/same-origin`, `related/same-host`, `related/same-site` (same registrable
/// domain by `rules`), then `lookalike` by `homoglyph`, `other-suffix`, `embedded`, `edit-distance` (2 edits from 9
/// characters; for a saved label of 5-8 characters 1 edit, where a substitution must swap look-alike characters);
/// ties go to the smallest distance, then the earliest saved origin. With no match, a host label that mixes
/// scripts beyond UTS #39 "highly restrictive" is `lookalike/mixed-script`; otherwise `unknown/no-match`. An
/// unreadable origin is `unknown/invalid-origin`.
///
/// Everything runs on the device. There is no UTS-46 library here, so the host checks the desktop takes from the
/// `idna` package are done as in the Kotlin port: Punycode round trip, NFC, "already in mapped form" (NFKC of the
/// Python casefold, keeping the deviation characters), no leading combining mark, CheckJoiners and the RFC 5893
/// Bidi rule on labels with right-to-left characters (tables in `LookalikeTables`, from the desktop's Unicode).
/// Scripts are read from the character name, as the desktop does. Labels are compared as code points, never as
/// Swift `String`s (which compare canonically equivalent text as equal).
///
/// Without `rules`, every host is its own registrable domain and no label check runs (as on the desktop).
public struct Lookalike: Sendable {
    public let rules: PublicSuffixRules?

    public init(rules: PublicSuffixRules?) { self.rules = rules }

    struct Site {
        let scheme: String
        /// A-label form (ASCII), or the rendered IP address.
        let host: String
        let port: Int?
        let ip: Bool
        let registrable: String
        /// Labels left of the registrable domain, A-label form.
        let sub: String
        /// The registrable label, Unicode code points (empty when the host is a public suffix).
        let label: [Unicode.Scalar]
        /// Every host label, Unicode.
        let labels: [[Unicode.Scalar]]
    }

    private struct Refused: Error {}

    /// Classifies `origin` (the page) against the vault's `saved` origins.
    public func classify(_ origin: String, saved: [String]) -> LookalikeVerdict {
        guard let site = self.site(origin, bareHostOk: false) else {
            return LookalikeVerdict(kind: "unknown", matched: nil, reason: "invalid-origin")
        }
        var best: (key: [Int], reason: String, matched: String)?
        for (index, raw) in saved.enumerated() {
            guard let other = self.site(raw, bareHostOk: true), let found = Self.compare(site, other),
                  let rank = Self.ranks[found.reason] else { continue }
            let key = [rank, found.distance, index]
            if let current = best, !key.lexicographicallyPrecedes(current.key) { continue }
            best = (key, found.reason, raw)
        }
        if let best {
            return LookalikeVerdict(kind: Self.kinds[best.reason] ?? "lookalike", matched: best.matched, reason: best.reason)
        }
        if !site.ip && site.labels.contains(where: Self.mixedScript) {
            return LookalikeVerdict(kind: "lookalike", matched: nil, reason: "mixed-script")
        }
        return LookalikeVerdict(kind: "unknown", matched: nil, reason: "no-match")
    }

    /// The phishing shield's verdict (desktop `lookalike.classify`): `classify` except that "related" (the "Related
    /// site" badge) is kept only for the same host, or the same host with or without a leading `www.`. Another host on
    /// the same registrable domain is `unknown/same-site` naming the saved origin (no badge, no guard), since a domain
    /// can host other people's pages without being on the Public Suffix List; a mixed-script host there is
    /// `lookalike/mixed-script`. Vectors: `crosscheck.json` `shield_pairs` and `shield_lists`.
    public func shield(_ origin: String, saved: [String]) -> LookalikeVerdict {
        guard let site = self.site(origin, bareHostOk: false) else {
            return LookalikeVerdict(kind: "unknown", matched: nil, reason: "invalid-origin")
        }
        var best: (key: [Int], reason: String, matched: String)?
        for (index, raw) in saved.enumerated() {
            guard let other = self.site(raw, bareHostOk: true), var found = Self.compare(site, other) else { continue }
            if found.reason == "same-site" && (site.host == "www." + other.host || other.host == "www." + site.host) {
                found = ("www-host", 0)
            }
            guard let rank = Self.ranks[found.reason == "www-host" ? "same-host" : found.reason] else { continue }
            let key = [rank, found.distance, index]
            if let current = best, !key.lexicographicallyPrecedes(current.key) { continue }
            best = (key, found.reason, raw)
        }
        let mixed = !site.ip && site.labels.contains(where: Self.mixedScript)
        if let best, !(best.reason == "same-site" && mixed) {
            return LookalikeVerdict(kind: Self.shieldKinds[best.reason] ?? "lookalike", matched: best.matched,
                                    reason: best.reason)
        }
        if mixed { return LookalikeVerdict(kind: "lookalike", matched: nil, reason: "mixed-script") }
        if let best { return LookalikeVerdict(kind: "unknown", matched: best.matched, reason: "same-site") }
        return LookalikeVerdict(kind: "unknown", matched: nil, reason: "no-match")
    }

    /// The A-label host of a saved origin as the classifier reads it (a bare host is allowed), for the "looks like
    /// <host>" text; nil when it cannot be read.
    public func host(_ saved: String) -> String? { site(saved, bareHostOk: true)?.host }

    // MARK: parsing (desktop `_split_url` / `_url_host` / `_ascii_host`, then `lookalike._site`)

    func site(_ input: String, bareHostOk: Bool) -> Site? {
        var value = input
        if value.isEmpty { return nil }
        if bareHostOk && !value.contains("://") { value = "https://" + value }
        let n = value.unicodeScalars.count
        if n <= 0 || n > 4096 || Origin.hasSpaceOrControl(value) { return nil }
        return try? parse(value)
    }

    private func parse(_ value: String) throws -> Site? {
        let p = try Origin.split(value)
        guard p.scheme == "https" || p.scheme == "http" else { return nil }
        if p.hasUserInfo { return nil }
        guard let raw = p.hostname else { return nil }
        let info = p.netloc.lastIndex(of: "@").map { String(p.netloc[p.netloc.index(after: $0)...]) } ?? p.netloc
        var host = try (info.contains("[") ? Origin.urlHost(p, missing: "URL is missing a host") : Self.unicodeASCIIHost(raw))
        var port = try p.port()
        if port == (p.scheme == "https" ? 443 : 80) { port = nil }
        let scheme = p.scheme
        if host.contains(":") {
            guard let bytes = Origin.ipv6(host) else { return nil }
            host = Self.compressedIPv6(bytes)
            let label = Array(host.unicodeScalars)
            return Site(scheme: scheme, host: host, port: port, ip: true, registrable: host, sub: "", label: label, labels: [label])
        }
        if Self.endsInNumber(host) {
            guard let v4 = Self.whatwgIPv4(host) else { return nil }
            let label = Array(v4.unicodeScalars)
            return Site(scheme: scheme, host: v4, port: port, ip: true, registrable: v4, sub: "", label: label, labels: [label])
        }
        let labels = try host.split(separator: ".", omittingEmptySubsequences: false).map { try Self.decodeLabel(Array($0.unicodeScalars)) }
        for label in labels { try Self.checkBidi(label) }
        var suffix = ""
        if let rules, host.contains(".") {
            suffix = String(String.UnicodeScalarView(rules.publicSuffix(Array(host.unicodeScalars))))
        }
        if suffix.isEmpty || suffix == host {
            return Site(scheme: scheme, host: host, port: port, ip: false, registrable: host, sub: "", label: [], labels: labels)
        }
        // The host is ASCII here, so characters are code points.
        let head = String(host.dropLast(suffix.count + 1))
        let cut = head.lastIndex(of: ".")
        let sub = cut.map { String(head[..<$0]) } ?? ""
        let regLabel = cut.map { String(head[head.index(after: $0)...]) } ?? head
        let at = sub.isEmpty ? 0 : sub.split(separator: ".", omittingEmptySubsequences: false).count
        guard at < labels.count else { return nil }
        return Site(scheme: scheme, host: host, port: port, ip: false, registrable: "\(regLabel).\(suffix)", sub: sub,
                    label: labels[at], labels: labels)
    }

    private static func string(_ scalars: [Unicode.Scalar]) -> String { String(String.UnicodeScalarView(scalars)) }

    /// Desktop `_ascii_host`: ASCII hosts keep the historical label checks (`Origin.asciiHost`); a non-ASCII host
    /// is mapped (UTS-46 style) and each non-ASCII label encoded to its `xn--` form.
    static func unicodeASCIIHost(_ raw: String) throws -> String {
        var host: [Unicode.Scalar] = raw.lowercased().unicodeScalars.map {
            ($0 == "\u{3002}" || $0 == "\u{FF0E}" || $0 == "\u{FF61}") ? "." : $0
        }
        if host.allSatisfy(\.isASCII) { return try Origin.asciiHost(string(host)) }
        if host.last == "." { host.removeLast() }
        guard !host.isEmpty, host.last != "." else { throw Refused() }
        try checkHostChars(host)
        let mapped = nfc(uts46Map(host))
        var out: [Unicode.Scalar] = []
        for (i, part) in mapped.split(separator: ".", omittingEmptySubsequences: false).enumerated() {
            let label = Array(part)
            guard !label.isEmpty else { throw Refused() }
            if i > 0 { out.append(".") }
            if label.allSatisfy(\.isASCII) { out += label; continue }
            // `idna.encode` (IDNA 2008) on a typed Unicode host: letters, marks and digits only (no emoji or symbols).
            guard label.allSatisfy(idna2008Like) else { throw Refused() }
            try checkLabel(label)
            if label.count >= 4 && label[2] == "-" && label[3] == "-" { throw Refused() }
            if label.first == "-" || label.last == "-" { throw Refused() }
            guard let encoded = Punycode.encode(label.map(\.value)) else { throw Refused() }
            out += Array("xn--".unicodeScalars) + encoded
        }
        try checkHostChars(out)
        return try Origin.asciiHost(string(out))
    }

    private static let forbiddenHostChars = Set("#/:<>?@[\\]^|%\u{7F}".unicodeScalars)

    private static func checkHostChars(_ host: [Unicode.Scalar]) throws {
        if host.contains(where: { $0.value < 32 || Origin.isPySpace($0) || forbiddenHostChars.contains($0) }) { throw Refused() }
    }

    private static func idna2008Like(_ s: Unicode.Scalar) -> Bool {
        if s.isASCII { return ("a"..."z").contains(s) || ("0"..."9").contains(s) || s == "-" }
        if s.value == zwnj || s.value == zwj || contexto.contains(s.value) { return true }
        switch s.properties.generalCategory {
        case .lowercaseLetter, .otherLetter, .modifierLetter, .nonspacingMark, .spacingMark, .decimalNumber: return true
        default: return false
        }
    }

    private static func nfc(_ s: [Unicode.Scalar]) -> [Unicode.Scalar] {
        Array(string(s).precomposedStringWithCanonicalMapping.unicodeScalars)
    }

    /// `uts46_remap` approximation: ignored code points dropped, NFKC of the casefold, deviation characters kept.
    static func uts46Map(_ s: [Unicode.Scalar]) -> [Unicode.Scalar] {
        var out: [Unicode.Scalar] = []
        for c in s {
            if contains(ignored, c.value) { continue }
            if deviations.contains(c.value) || c == "." { out.append(c); continue }
            let once = String(c).precomposedStringWithCompatibilityMapping
            out += Casefold.fold(once).precomposedStringWithCompatibilityMapping.unicodeScalars
        }
        return out
    }

    /// UTS-46 validity of a Unicode label: no disallowed code point, already mapped, NFC, no leading mark, joiners
    /// in context.
    private static func checkLabel(_ label: [Unicode.Scalar]) throws {
        for c in label where !deviations.contains(c.value) {
            switch c.properties.generalCategory {
            case .control, .privateUse, .surrogate, .unassigned, .format, .spaceSeparator, .lineSeparator, .paragraphSeparator:
                throw Refused()
            default: break
            }
            if (c.value & 0xFFFE) == 0xFFFE || (0xFDD0...0xFDEF).contains(c.value) { throw Refused() }
        }
        guard uts46Map(label) == label, nfc(label) == label else { throw Refused() }
        if let first = label.first, isMark(first) { throw Refused() }
        let cps = label.map(\.value)
        for i in cps.indices where (cps[i] == zwnj || cps[i] == zwj) && !validContextJ(cps, i) { throw Refused() }
    }

    /// `lookalike._decode_label`: the Unicode form of one A-label, refusing what browsers refuse.
    static func decodeLabel(_ label: [Unicode.Scalar]) throws -> [Unicode.Scalar] {
        guard label.count >= 4, label[0] == "x", label[1] == "n", label[2] == "-", label[3] == "-" else { return label }
        let tail = Array(label[4...])
        guard let cps = Punycode.decode(tail), cps.contains(where: { $0 >= 0x80 }),
              let again = Punycode.encode(cps), again == tail,
              !cps.contains(where: { (0xD800...0xDFFF).contains($0) }) else { throw Refused() }
        var decoded: [Unicode.Scalar] = []
        decoded.reserveCapacity(cps.count)
        for cp in cps {
            guard let s = Unicode.Scalar(cp) else { throw Refused() }
            decoded.append(s)
        }
        try checkLabel(decoded)
        return decoded
    }

    private static func isMark(_ s: Unicode.Scalar) -> Bool {
        switch s.properties.generalCategory {
        case .nonspacingMark, .enclosingMark, .spacingMark: return true
        default: return false
        }
    }

    /// `idna.valid_contextj`.
    private static func validContextJ(_ cps: [UInt32], _ pos: Int) -> Bool {
        if pos > 0 && contains(virama, cps[pos - 1]) { return true }
        if cps[pos] == zwj { return false }
        var ok = false
        var i = pos - 1
        while i >= 0 {
            if contains(joiningT, cps[i]) { i -= 1; continue }
            ok = contains(joiningL, cps[i]) || contains(joiningD, cps[i])
            break
        }
        if !ok { return false }
        for j in (pos + 1)..<max(pos + 1, cps.count) {
            if contains(joiningT, cps[j]) { continue }
            return contains(joiningR, cps[j]) || contains(joiningD, cps[j])
        }
        return false
    }

    enum Bidi: Hashable, Sendable { case l, r, al, en, es, et, an, cs, nsm, bn, on, unassigned, other }

    private static let rtlAllowed: Set<Bidi> = [.r, .al, .an, .en, .es, .cs, .et, .on, .bn, .nsm]
    private static let rtlEnding: Set<Bidi> = [.r, .al, .en, .an]
    private static let ltrAllowed: Set<Bidi> = [.l, .en, .es, .cs, .et, .on, .bn, .nsm]
    private static let bidiNames: [Substring: Bidi] = ["R": .r, "AL": .al, "EN": .en, "ES": .es, "ET": .et, "AN": .an,
                                                       "CS": .cs, "NSM": .nsm, "BN": .bn, "ON": .on, "U": .unassigned, "L": .l]

    static func bidi(_ cp: UInt32) -> Bidi {
        var lo = 0, hi = bidiRuns.count - 1
        while lo <= hi {
            let mid = (lo + hi) / 2
            let run = bidiRuns[mid]
            if cp < run.0.lowerBound { hi = mid - 1 } else if cp > run.0.upperBound { lo = mid + 1 } else { return run.1 }
        }
        return .l
    }

    /// `idna.check_bidi(label)` with `check_ltr=False`: only labels holding R, AL or AN characters are checked.
    static func checkBidi(_ label: [Unicode.Scalar]) throws {
        let dirs = label.map { bidi($0.value) }
        if dirs.contains(.unassigned) { throw Refused() }
        if !dirs.contains(where: { $0 == .r || $0 == .al || $0 == .an }) { return }
        let rtl: Bool
        switch dirs.first {
        case .r?, .al?: rtl = true
        case .l?: rtl = false
        default: throw Refused()
        }
        var validEnding = false
        var numberType: Bidi?
        for d in dirs {
            if rtl {
                guard rtlAllowed.contains(d) else { throw Refused() }
                if rtlEnding.contains(d) { validEnding = true } else if d != .nsm { validEnding = false }
                if d == .an || d == .en {
                    if let numberType { if numberType != d { throw Refused() } } else { numberType = d }
                }
            } else {
                guard ltrAllowed.contains(d) else { throw Refused() }
                if d == .l || d == .en { validEnding = true } else if d != .nsm { validEnding = false }
            }
        }
        if !validEnding { throw Refused() }
    }

    static func compressedIPv6(_ b: [UInt8]) -> String {
        let groups = (0..<8).map { (UInt16(b[2 * $0]) << 8) | UInt16(b[2 * $0 + 1]) }
        var bestStart = -1, bestLen = 0, i = 0
        while i < 8 {
            if groups[i] == 0 {
                var j = i
                while j < 8 && groups[j] == 0 { j += 1 }
                if j - i > bestLen { bestStart = i; bestLen = j - i }
                i = j
            } else {
                i += 1
            }
        }
        let hex = { (g: UInt16) in String(g, radix: 16) }
        if bestLen < 2 { return groups.map(hex).joined(separator: ":") }
        let left = groups[..<bestStart].map(hex).joined(separator: ":")
        let right = groups[(bestStart + bestLen)...].map(hex).joined(separator: ":")
        return "\(left)::\(right)"
    }

    /// One WHATWG IPv4 number (decimal, 0x hex or 0 octal); nil if invalid. A value too large for 64 bits is
    /// kept as `UInt64.max` (still a number, still not an address), as Python's unbounded int would be.
    static func number(_ part: Substring) -> UInt64? {
        let chars = Array(part.unicodeScalars)
        let digits: ArraySlice<Unicode.Scalar>, base: UInt64
        if chars.count >= 2, chars[0] == "0", chars[1] == "x" || chars[1] == "X" {
            digits = chars[2...]; base = 16
        } else if chars.count > 1, chars[0] == "0" {
            digits = chars[1...]; base = 8
        } else {
            digits = chars[...]; base = 10
        }
        if digits.isEmpty { return base == 16 ? 0 : nil }
        var value: UInt64 = 0
        for c in digits {
            let d: UInt64
            switch c.value {
            case 0x30...0x39: d = UInt64(c.value - 0x30)
            case 0x61...0x66: d = UInt64(c.value - 0x61 + 10)
            case 0x41...0x46: d = UInt64(c.value - 0x41 + 10)
            default: return nil
            }
            guard d < base else { return nil }
            let (m, o1) = value.multipliedReportingOverflow(by: base)
            let (s, o2) = m.addingReportingOverflow(d)
            value = (o1 || o2 || value == .max) ? .max : s
        }
        return value
    }

    static func endsInNumber(_ host: String) -> Bool {
        let last = host.split(separator: ".", omittingEmptySubsequences: false).last ?? ""
        if !last.isEmpty && last.unicodeScalars.allSatisfy({ ("0"..."9").contains($0) }) { return true }
        return last.count >= 2 && last.prefix(2).lowercased() == "0x" && number(last) != nil
    }

    /// The WHATWG URL parser's IPv4 reading (`127.1` is `127.0.0.1`).
    static func whatwgIPv4(_ host: String) -> String? {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count > 4 || parts.contains(where: \.isEmpty) { return nil }
        var values: [UInt64] = []
        for part in parts {
            guard let v = number(part) else { return nil }
            values.append(v)
        }
        guard let last = values.last else { return nil }
        if values.dropLast().contains(where: { $0 > 255 }) { return nil }
        if last >= (UInt64(1) << UInt64(8 * (5 - values.count))) { return nil }
        var address = last
        for (index, v) in values.dropLast().enumerated() { address += v << UInt64(8 * (3 - index)) }
        return "\((address >> 24) & 255).\((address >> 16) & 255).\((address >> 8) & 255).\(address & 255)"
    }

    // MARK: comparison (desktop `_compare`)

    static func skeleton(_ label: [Unicode.Scalar]) -> [UInt32] {
        let folded = string(label).lowercased().decomposedStringWithCompatibilityMapping
        var out: [UInt32] = []
        for c in folded.unicodeScalars where !isMark(c) { out.append(confusables[c.value] ?? c.value) }
        return out
    }

    private static func fallbackName(_ s: Unicode.Scalar) -> String {
        // Algorithmic names, in case the runtime has none for them.
        switch s.value {
        case 0xAC00...0xD7A3: return "HANGUL SYLLABLE"
        case 0x3400...0x4DBF, 0x4E00...0x9FFF, 0x20000...0x2A6DF, 0x2A700...0x2EE5D, 0x30000...0x323AF: return "CJK UNIFIED IDEOGRAPH"
        case 0xF900...0xFAFF, 0x2F800...0x2FA1F: return "CJK COMPATIBILITY IDEOGRAPH"
        default: return ""
        }
    }

    /// Desktop `_script`: from the character name, as `unicodedata.name` gives it.
    static func script(_ s: Unicode.Scalar) -> String? {
        if s.isASCII { return ("a"..."z").contains(s) || ("A"..."Z").contains(s) ? "LATIN" : nil }
        if let fixed = scriptFixed[s.value] { return fixed }
        switch s.properties.generalCategory {
        case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .modifierLetter, .otherLetter,
             .decimalNumber, .letterNumber, .otherNumber: break
        default: return nil
        }
        let name = s.properties.name ?? fallbackName(s)
        if name.hasPrefix("CJK ") { return "HAN" }
        for script in scripts where name.hasPrefix(script + " ") || name.hasPrefix(script + "-") { return script }
        return "OTHER"
    }

    static func mixedScript(_ label: [Unicode.Scalar]) -> Bool {
        let found = Set(label.compactMap(script))
        return found.count > 1 && !allowedMixes.contains { found.isSubset(of: $0) }
    }

    private static func shortEditCounts(_ a: [UInt32], _ b: [UInt32]) -> Bool {
        if a.count != b.count { return true }
        let diff = a.indices.filter { a[$0] != b[$0] }
        if diff.count == 1 { return visualPairs.contains([a[diff[0]], b[diff[0]]].sorted()) }
        return true  // an adjacent transposition
    }

    /// Damerau-Levenshtein distance, optimal string alignment variant, on code points.
    static func osaDistance(_ a: [UInt32], _ b: [UInt32]) -> Int {
        var rows: [[Int]] = [Array(0...b.count)]
        if a.isEmpty { return b.count }
        for i in 1...a.count {
            var row = [Int](repeating: 0, count: b.count + 1)
            row[0] = i
            if !b.isEmpty {
                for j in 1...b.count {
                    let cost = a[i - 1] == b[j - 1] ? 0 : 1
                    row[j] = min(rows[i - 1][j] + 1, row[j - 1] + 1, rows[i - 1][j - 1] + cost)
                    if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] { row[j] = min(row[j], rows[i - 2][j - 2] + 1) }
                }
            }
            rows.append(row)
        }
        return rows[a.count][b.count]
    }

    static func compare(_ site: Site, _ saved: Site) -> (reason: String, distance: Int)? {
        if site.host == saved.host {
            return site.scheme == saved.scheme && site.port == saved.port ? ("same-origin", 0) : ("same-host", 0)
        }
        if site.ip || saved.ip { return nil }
        if site.registrable == saved.registrable { return ("same-site", 0) }
        if site.label.isEmpty || saved.label.isEmpty { return nil }
        let mine = skeleton(site.label), theirs = skeleton(saved.label)
        if mine == theirs && site.label != saved.label { return ("homoglyph", 0) }
        let longEnough = theirs.count >= minEditLabel
        if longEnough && site.label == saved.label { return ("other-suffix", 0) }
        if !site.sub.isEmpty && ".\(site.sub).".contains(".\(saved.registrable).") { return ("embedded", 0) }
        let limit = theirs.count >= longEditLabel ? longEditDistance : shortEditDistance
        if longEnough && abs(mine.count - theirs.count) <= limit {
            let distance = osaDistance(mine, theirs)
            if distance <= limit && (limit > shortEditDistance || shortEditCounts(mine, theirs)) { return ("edit-distance", distance) }
        }
        return nil
    }

    // MARK: tables

    public static let minEditLabel = 5
    public static let shortEditDistance = 1
    public static let longEditLabel = 9
    public static let longEditDistance = 2

    /// Same text as lookalike.py / lookalike.js / Lookalike.kt.
    public static let visualPairsTable = "0o 1i 1l 2z 5s 8b 9g 9q gq il uv nm"
    public static let confusablesTable =
        "0430a 0441c 0501d 0435e 04bbh 0456i 0458j 043ak 04cfl 043eo 0440p 051bq 0455s 0443y 0445x 051dw 04afy " +
        "03b1a 03b5e 03b9i 03bak 03bdv 03bfo 03c1p 03c4t 03c5u 03c7x 03b3y " +
        "0585o 057du 0581g 0570h 0578n 0566q " +
        "0131i 0251a 0261g 0237j"
    public static let scriptTable = "3005h 3006h 3007h 303bh 309bk 309ck 30a0k 30fbk 30fck"

    private static let visualPairs: Set<[UInt32]> = Set(visualPairsTable.split(separator: " ").map { pair in
        pair.unicodeScalars.map(\.value).sorted()
    })
    private static let confusables: [UInt32: UInt32] = Dictionary(uniqueKeysWithValues: confusablesTable.split(separator: " ").map { item in
        (UInt32(item.prefix(4), radix: 16)!, item.unicodeScalars.last!.value)
    })
    private static let scriptFixed: [UInt32: String] = Dictionary(uniqueKeysWithValues: scriptTable.split(separator: " ").map { item in
        (UInt32(item.prefix(4), radix: 16)!, item.hasSuffix("h") ? "HAN" : "KATAKANA")
    })
    /// Desktop `_SCRIPTS`, in its order.
    private static let scripts = ["LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC", "HIRAGANA", "KATAKANA",
                                  "HANGUL", "BOPOMOFO", "THAI", "DEVANAGARI", "GEORGIAN", "CHEROKEE"]
    private static let allowedMixes: [Set<String>] = [
        ["LATIN", "HAN", "HIRAGANA", "KATAKANA"],
        ["LATIN", "HAN", "BOPOMOFO"],
        ["LATIN", "HAN", "HANGUL"],
    ]
    private static let ranks: [String: Int] = ["same-origin": 0, "same-host": 1, "same-site": 2, "homoglyph": 3,
                                               "other-suffix": 4, "embedded": 5, "edit-distance": 6]
    private static let kinds: [String: String] = ["same-origin": "exact", "same-host": "related", "same-site": "related"]
    private static let shieldKinds: [String: String] = ["same-origin": "exact", "same-host": "related",
                                                        "www-host": "related", "same-site": "unknown"]

    private static let zwnj: UInt32 = 0x200C
    private static let zwj: UInt32 = 0x200D
    /// Non-transitional UTS-46 keeps these as they are.
    private static let deviations: Set<UInt32> = [0x00DF, 0x03C2, zwnj, zwj]
    /// IDNA 2008 CONTEXTO code points (their context rules are not checked).
    private static let contexto: Set<UInt32> = Set([0x00B7, 0x0375, 0x05F3, 0x05F4, 0x30FB] + Array(0x0660...0x0669) + Array(0x06F0...0x06F9))
    /// UTS-46 "ignored": mapped to nothing (soft hyphen, variation selectors, zero width space...).
    private static let ignored = Lookalike.ranges("ad 34f 115f-1160 17b4-17b5 180b-180f 200b 2060-2064 206a-206f 3164 fe00-fe0f feff ffa0 1bca0-1bca3 1d173-1d17a e0100-e01ef")
    private static let virama = Lookalike.ranges(LookalikeTables.virama)
    private static let joiningL = Lookalike.ranges(LookalikeTables.joiningL)
    private static let joiningD = Lookalike.ranges(LookalikeTables.joiningD)
    private static let joiningR = Lookalike.ranges(LookalikeTables.joiningR)
    private static let joiningT = Lookalike.ranges(LookalikeTables.joiningT)
    private static let bidiRuns: [(ClosedRange<UInt32>, Bidi)] = LookalikeTables.bidi
        .split(whereSeparator: { $0 == " " || $0 == "\n" })
        .map { item in
            let parts = item.split(separator: ":")
            return (Lookalike.range(parts[0]), Lookalike.bidiNames[parts[1]] ?? .other)
        }

    private static func range(_ item: Substring) -> ClosedRange<UInt32> {
        if let dash = item.firstIndex(of: "-") {
            return UInt32(item[..<dash], radix: 16)!...UInt32(item[item.index(after: dash)...], radix: 16)!
        }
        let v = UInt32(item, radix: 16)!
        return v...v
    }

    /// Sorted inclusive ranges from a table (hex, `a-b`, separated by spaces or newlines).
    static func ranges(_ table: String) -> [ClosedRange<UInt32>] {
        table.split(whereSeparator: { $0 == " " || $0 == "\n" }).map(range)
    }

    static func contains(_ ranges: [ClosedRange<UInt32>], _ cp: UInt32) -> Bool {
        var lo = 0, hi = ranges.count - 1
        while lo <= hi {
            let mid = (lo + hi) / 2
            if cp < ranges[mid].lowerBound { hi = mid - 1 } else if cp > ranges[mid].upperBound { lo = mid + 1 } else { return true }
        }
        return false
    }
}
