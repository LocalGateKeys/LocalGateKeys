import Foundation
import AppShared

/// A type filter (desktop `FilterOption` without collections and smart views).
enum VaultFilter: Hashable, Sendable {
    case all, favorites, kind(String)

    var label: String {
        switch self {
        case .all: "All types"
        case .favorites: "Favorites"
        case .kind("web"): "Browser"
        case .kind("desktop"): "Desktop"
        case .kind(let k): VaultItem.kindLabel(k)
        }
    }

    func matches(_ item: VaultItem) -> Bool {
        switch self {
        case .all: true
        case .favorites: item.favorite
        case .kind(let k): item.kind == k
        }
    }
}

/// Port of the desktop list search (`agent.py` `parse_search_query` / `search_fields` / `search_rank` /
/// `rank_search_results`): casefolded, every token must match; `tag:`, `url:`, `type:`, `user:` restrict
/// one field; rank exact title > title prefix > contains > fuzzy (difflib, cutoff 0.72, tokens of 3+).
/// Only list metadata is searched, never passwords, notes or payloads.
enum VaultSearch {
    static let prefixes = ["tag": "tags", "url": "url", "type": "kind", "user": "username"]
    static let rankExact = 0, rankPrefix = 1, rankContains = 2, rankFuzzy = 3
    static let fuzzyCutoff = 0.72
    static let fuzzyMinLength = 3

    /// Python `str.casefold()` (LGKCore `Casefold`, generated from Python), per scalar, no normalisation.
    static func casefold(_ s: String) -> String { Casefold.fold(s) }

    static func parse(_ query: String) -> [(field: String?, token: String)] {
        var out: [(String?, String)] = []
        for raw in query.split(whereSeparator: { $0.isWhitespace }) {
            let token = casefold(String(raw))
            if let colon = token.firstIndex(of: ":"), let field = prefixes[String(token[..<colon])] {
                let value = String(token[token.index(after: colon)...])
                if !value.isEmpty { out.append((field, value)) }
                continue
            }
            out.append((nil, token))
        }
        return out
    }

    static func fields(_ item: VaultItem) -> [String: String] {
        return ["title": casefold(item.title), "username": casefold(item.username), "url": casefold(item.target),
                "kind": casefold("\(item.kind) \(item.kindLabel)"), "tags": casefold(item.tags.joined(separator: " "))]
    }

    /// `re.split(r"[^0-9a-z]+", value)` over code points.
    static func words(_ s: String) -> [String] {
        s.unicodeScalars.split(whereSeparator: { !((0x30...0x39).contains($0.value) || (0x61...0x7A).contains($0.value)) })
            .map { String(String.UnicodeScalarView($0)) }
    }

    static func fuzzyHit(_ token: String, _ f: [String: String]) -> Bool {
        guard token.unicodeScalars.count >= fuzzyMinLength else { return false }
        for name in ["title", "username", "url", "tags"] {
            guard let v = f[name], !v.isEmpty else { continue }
            for c in [v] + words(v) where SequenceRatio.ratio(c, token) >= fuzzyCutoff { return true }
        }
        return false
    }

    static func tokenRank(_ f: [String: String], _ field: String?, _ token: String) -> Int? {
        if let field { return Scalars.contains(f[field] ?? "", token) ? rankContains : nil }
        let title = f["title"] ?? ""
        if Scalars.equal(title, token) { return rankExact }
        if Scalars.hasPrefix(title, token) { return rankPrefix }
        if f.values.contains(where: { Scalars.contains($0, token) }) { return rankContains }
        return fuzzyHit(token, f) ? rankFuzzy : nil
    }

    /// Matching items, best rank first, then most recently updated. Empty query keeps everything.
    static func rank(_ items: [VaultItem], query: String) -> [VaultItem] {
        let tokens = parse(query)
        let ordered = items.sorted { $0.id < $1.id }   // stable input order (the store is a dictionary)
        var ranked: [(Int, Int64, Int, VaultItem)] = []
        for (i, item) in ordered.enumerated() {
            let f = fields(item)
            var r = rankExact
            var hit = true
            for (field, token) in tokens {
                guard let t = tokenRank(f, field, token) else { hit = false; break }
                r = max(r, t)
            }
            if hit { ranked.append((r, -item.updatedAt, i, item)) }
        }
        ranked.sort { ($0.0, $0.1, $0.2) < ($1.0, $1.1, $1.2) }
        return ranked.map(\.3)
    }

    static func apply(_ items: [VaultItem], query: String, filter: VaultFilter) -> [VaultItem] {
        rank(items.filter(filter.matches), query: query)
    }

    /// Desktop `KIND_ORDER`: web, desktop, then the other kinds by label.
    static func filterOptions(_ items: [VaultItem]) -> [VaultFilter] {
        let present = Set(items.map(\.kind))
        let rest = present.subtracting(["web", "desktop"]).sorted {
            (casefold(VaultItem.kindLabel($0)), $0) < (casefold(VaultItem.kindLabel($1)), $1)
        }
        return [.all, .favorites] + ["web", "desktop"].filter(present.contains).map { .kind($0) } + rest.map { .kind($0) }
    }
}

/// `difflib.SequenceMatcher(None, a, b).ratio()` over Unicode scalars, including autojunk on `b`.
enum SequenceRatio {
    static func ratio(_ a: String, _ b: String) -> Double {
        let x = Array(a.unicodeScalars), y = Array(b.unicodeScalars)
        let total = x.count + y.count
        guard total > 0 else { return 1 }
        var b2j: [Unicode.Scalar: [Int]] = [:]
        for (j, c) in y.enumerated() { b2j[c, default: []].append(j) }
        if y.count >= 200 {
            let ntest = y.count / 100 + 1
            for (c, idx) in b2j where idx.count > ntest { b2j[c] = nil }
        }
        func longest(_ alo: Int, _ ahi: Int, _ blo: Int, _ bhi: Int) -> (Int, Int, Int) {
            var bi = alo, bj = blo, size = 0
            var j2len: [Int: Int] = [:]
            for i in alo..<ahi {
                var next: [Int: Int] = [:]
                for j in b2j[x[i]] ?? [] {
                    if j < blo { continue }
                    if j >= bhi { break }
                    let k = (j2len[j - 1] ?? 0) + 1
                    next[j] = k
                    if k > size { bi = i - k + 1; bj = j - k + 1; size = k }
                }
                j2len = next
            }
            // No junk set (isjunk is None), but popular elements were dropped: extend over equal ones.
            while bi > alo && bj > blo && x[bi - 1] == y[bj - 1] && b2j[y[bj - 1]] == nil { bi -= 1; bj -= 1; size += 1 }
            while bi + size < ahi && bj + size < bhi && x[bi + size] == y[bj + size] && b2j[y[bj + size]] == nil { size += 1 }
            return (bi, bj, size)
        }
        var matches = 0
        var queue = [(0, x.count, 0, y.count)]
        while let (alo, ahi, blo, bhi) = queue.popLast() {
            guard alo < ahi, blo < bhi else { continue }
            let (i, j, k) = longest(alo, ahi, blo, bhi)
            guard k > 0 else { continue }
            matches += k
            queue.append((alo, i, blo, j)); queue.append((i + k, ahi, j + k, bhi))
        }
        return 2.0 * Double(matches) / Double(total)
    }
}
