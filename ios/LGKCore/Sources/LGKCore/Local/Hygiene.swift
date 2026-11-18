import Foundation

/// The clean-up sweep (feature pack contract §3): duplicates, items not changed in 2 years and expired cards and
/// licences. No network access; findings are computed on demand and never stored. Callers pass only the records the
/// person can see (travel mode applied); desktop logins are skipped here.
public enum Hygiene {
    public enum FindingType: String, Sendable, CaseIterable {
        case sameLogin = "same_login"
        case sameAccountOtherPassword = "same_account_other_password"
        case sameSite = "same_site"
        case sameItem = "same_item"
        case notChanged2y = "not_changed_2y"
        case expired

        public var isDuplicate: Bool { self != .notChanged2y && self != .expired }
    }

    public struct Finding: Equatable, Sendable, Identifiable {
        public let type: FindingType
        /// Sorted by `updated_at` descending, then id.
        public let ids: [String]
        public var id: String { type.rawValue + ":" + ids.joined(separator: ",") }
        public init(type: FindingType, ids: [String]) { self.type = type; self.ids = ids }
    }

    /// The summary counts (`hygiene.summary`): distinct items in any duplicate group, old items, expired items.
    public struct Summary: Equatable, Sendable {
        public let duplicates: Int
        public let notChanged: Int
        public let expired: Int
    }

    public static let notChangedSeconds: Int64 = 730 * 86_400

    // MARK: - Findings

    /// Every finding over `records` (id → record). `matcher` reduces hosts to registrable domains; `today` is the
    /// local `YYYY-MM-DD`.
    public static func findings(_ records: [String: [String: JSONValue]], now: Int64, today: String,
                                matcher: URLMatcher) -> [Finding] {
        let live = records.filter { $0.value["kind"] != .string("desktop") }
        func updated(_ id: String) -> Int64 { if case .int(let n)? = live[id]?["updated_at"] { return n }; return 0 }
        func order(_ ids: [String]) -> [String] {
            ids.sorted { a, b in
                let ua = updated(a), ub = updated(b)
                return ua != ub ? ua > ub : scalarOrder(a, b)
            }
        }
        var out: [Finding] = []
        func add(_ type: FindingType, _ groups: [[String]]) {
            for g in groups where g.count > 1 { out.append(Finding(type: type, ids: order(g))) }
        }

        // Logins.
        let logins = live.filter { $0.value["kind"] == .string("web") }
        var byAccount: [[UInt32]: [String]] = [:]
        var bySite: [[UInt32]: [String]] = [:]
        for (id, r) in logins {
            let origin = text(scope(r)["origin"])
            let user = RecordDigest.foldKey(text(r["username"]))
            byAccount[key([origin.unicodeScalars.map(\.value), user]), default: []].append(id)
            if !user.isEmpty, !origin.isEmpty, let domain = try? matcher.baseDomainOf(origin) {
                bySite[key([domain.unicodeScalars.map(\.value), user]), default: []].append(id)
            }
        }
        var sameLogin: [[String]] = [], otherPassword: [[String]] = []
        for (_, ids) in byAccount where ids.count > 1 {
            var byPassword: [[UInt8]: [String]] = [:]
            for id in ids { byPassword[Array(text(logins[id]?["password"]).utf8), default: []].append(id) }
            sameLogin.append(contentsOf: byPassword.values.filter { $0.count > 1 })
            if byPassword.count > 1 { otherPassword.append(ids) }
        }
        var sameSite: [[String]] = []
        for (_, ids) in bySite {
            let origins = Set(ids.map { text(scope(logins[$0] ?? [:])["origin"]).unicodeScalars.map(\.value) })
            if origins.count > 1 { sameSite.append(ids) }
        }
        add(.sameLogin, sameLogin)
        add(.sameAccountOtherPassword, otherPassword)
        add(.sameSite, sameSite)

        // Typed items.
        var byItem: [[UInt8]: [String]] = [:]
        for (id, r) in live where r["kind"] != .string("web") {
            if let k = itemKey(r) { byItem[k, default: []].append(id) }
        }
        add(.sameItem, Array(byItem.values))

        // Not changed in 2 years, expired.
        // Only a whole-number `updated_at` counts (desktop `findings`).
        let old = live.keys.filter { id in
            guard case .int(let n)? = live[id]?["updated_at"] else { return false }
            return n < now - notChangedSeconds
        }
        if !old.isEmpty { out.append(Finding(type: .notChanged2y, ids: order(Array(old)))) }
        let expired = live.filter { isExpired($0.value, today: today) }.map(\.key)
        if !expired.isEmpty { out.append(Finding(type: .expired, ids: order(expired))) }

        let rank = Dictionary(uniqueKeysWithValues: FindingType.allCases.enumerated().map { ($1, $0) })
        return out.sorted { a, b in
            a.type != b.type ? rank[a.type]! < rank[b.type]! : scalarOrder(a.ids.joined(separator: ","), b.ids.joined(separator: ","))
        }
    }

    public static func summary(_ findings: [Finding]) -> Summary {
        Summary(duplicates: Set(findings.filter(\.type.isDuplicate).flatMap(\.ids)).count,
                notChanged: findings.first { $0.type == .notChanged2y }?.ids.count ?? 0,
                expired: findings.first { $0.type == .expired }?.ids.count ?? 0)
    }

    static func text(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }

    /// Python truthiness of a JSON value (`None`, false, 0, "", [] and {} are false).
    static func truthy(_ v: JSONValue?) -> Bool {
        switch v {
        case nil, .null?: return false
        case .bool(let b)?: return b
        case .int(let n)?: return n != 0
        case .float(let d)?: return d != 0
        case .string(let s)?: return !s.isEmpty
        case .array(let a)?: return !a.isEmpty
        case .object(let o)?: return !o.isEmpty
        }
    }
    static func scope(_ r: [String: JSONValue]) -> [String: JSONValue] { if case .object(let s)? = r["scope"] { return s }; return [:] }
    static func key(_ parts: [[UInt32]]) -> [UInt32] {
        var out: [UInt32] = []
        for p in parts { out.append(contentsOf: p); out.append(0xFFFF_FFFF) }
        return out
    }

    /// The `same_item` key of a typed record, nil when it never matches.
    static func itemKey(_ r: [String: JSONValue]) -> [UInt8]? {
        let kind = text(r["kind"])
        let payload: [String: JSONValue] = if case .object(let p)? = r["payload"] { p } else { [:] }
        switch kind {
        case "passkey":
            // Relying party trimmed and case-folded, credential id as stored; both required (desktop `_passkey_key`).
            let rp = RecordDigest.fold(text(payload["relying_party_id"])), cred = text(payload["credential_id"])
            guard !rp.isEmpty, !cred.isEmpty else { return nil }
            return Array(("passkey\u{0}" + rp + "\u{0}" + cred).utf8)
        case "card":
            let number = text(payload["number"])
            guard !number.isEmpty else { return nil }
            return Array(("card\u{0}" + number).utf8)
        default:
            var p = payload
            p["notes"] = nil; p["template_id"] = nil; p["document_ids"] = nil
            guard let body = try? RecordDigest.canon(.object(p)) else { return nil }
            return Array((kind + "\u{0}" + RecordDigest.fold(text(r["title"])) + "\u{0}").utf8) + body
        }
    }

    // MARK: - Expired

    /// `expired`: a card `MM/YY` before this month; a licence, purchase, warranty or subscription
    /// `expiration_date` or an API key `expires` before `today` when it reads `YYYY-MM-DD` or `YYYYMMDD`. An inactive
    /// subscription is skipped.
    public static func isExpired(_ r: [String: JSONValue], today: String) -> Bool {
        let payload: [String: JSONValue] = if case .object(let p)? = r["payload"] { p } else { [:] }
        guard let t = ymd(today) else { return false }
        let (ty, tm) = (t.0, t.1)
        switch text(r["kind"]) {
        case "card":
            // `M/YY`, `MM/YY`, `M/YYYY` or `MM/YYYY`, trimmed (desktop `is_expired`).
            let parts = Normalise.pyStrip(text(payload["expiry"])).split(separator: "/",
                                                                                                      omittingEmptySubsequences: false)
            func digits(_ p: Substring) -> Bool { p.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }
            guard parts.count == 2, (1...2).contains(parts[0].utf8.count), [2, 4].contains(parts[1].utf8.count),
                  digits(parts[0]), digits(parts[1]), let m = Int(parts[0]), let y = Int(parts[1]) else { return false }
            return (parts[1].utf8.count == 4 ? y : 2000 + y, m) < (ty, tm)
        case "license", "purchase", "warranty", "subscription", "api_key":
            if text(r["kind"]) == "subscription", payload["active"] == .bool(false) { return false }
            let field = text(r["kind"]) == "api_key" ? "expires" : "expiration_date"
            guard let date = dashDate(text(payload[field])) else { return false }
            return scalarOrder(date, today)
        default:
            return false
        }
    }

    /// `YYYY-MM-DD` from `YYYY-MM-DD` or `YYYYMMDD` naming a real day; nil for anything else (week dates).
    static func dashDate(_ s: String) -> String? {
        if LocalData.isISODate(s) { return s }
        let u = Array(s.utf8)
        guard u.count == 8, u.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return nil }
        let d = String(decoding: u[0..<4], as: UTF8.self) + "-" + String(decoding: u[4..<6], as: UTF8.self) + "-"
            + String(decoding: u[6..<8], as: UTF8.self)
        return LocalData.isISODate(d) ? d : nil
    }

    static func ymd(_ s: String) -> (Int, Int, Int)? {
        guard LocalData.isISODate(s), let y = Int(s.prefix(4)), let m = Int(s.dropFirst(5).prefix(2)),
              let d = Int(s.suffix(2)) else { return nil }
        return (y, m, d)
    }

    // MARK: - Merge

    public enum MergeRefusal: String, Error, Equatable, Sendable {
        case tooManyTags = "too_many_tags"
        case tooManyValues = "too_many_values"
        case notesTooLong = "notes_too_long"
        /// The two records are not a pair the sweep merges (different kinds, or typed items that are not `same_item`).
        case notMergeable = "not_mergeable"
    }

    public static let maxNotes = 20_000

    /// The merged keeper (§3.2). `keeper` is the person's pick; the other record goes to Recently deleted (the caller's
    /// job, as is capturing both versions in history). Logins merge passwords, codes, fields and URLs; typed items
    /// only tags and notes (collections are merged by the caller with `mergedCollections`).
    public static func merge(keeper: [String: JSONValue], other: [String: JSONValue],
                             now: Int64) throws(MergeRefusal) -> [String: JSONValue] {
        let kind = text(keeper["kind"])
        guard kind == text(other["kind"]), kind != "desktop" else { throw .notMergeable }
        var out = keeper
        // Keys are written only when either record has them, as Windows `hygiene.merge` does (same digest on every
        // platform). Tags: keeper's then the other's, through the tag normaliser.
        if keeper["tags"] != nil || other["tags"] != nil {
            let tags = (strings(keeper["tags"]) + strings(other["tags"]))
            do { out["tags"] = .array(try Normalise.tags(tags).map(JSONValue.string)) } catch { throw .tooManyTags }
        }
        if keeper["favorite"] != nil || other["favorite"] != nil {
            out["favorite"] = .bool(keeper["favorite"] == .bool(true) || other["favorite"] == .bool(true))
        }
        if kind == "web" {
            if case .string(let otherPassword)? = other["password"] {
                out = PasswordHistoryPush.pushing(otherPassword, into: out, now: now)
            }
            // Python `not keeper.get("totp") and other.get("totp")`: an empty value counts as none.
            if !truthy(keeper["totp"]), let t = other["totp"], truthy(t) { out["totp"] = t }
            out["recovery_codes"] = try union(keeper["recovery_codes"], other["recovery_codes"], cap: 100)
            out["custom_fields"] = try union(keeper["custom_fields"], other["custom_fields"], cap: 50)
            var s = scope(keeper)
            let os = scope(other)
            // The other login's addresses (its urls, or its legacy origin) are kept as rows; `scope.origin` stays the
            // keeper's. Nothing new → `scope.urls` is left exactly as the keeper had it.
            let keeperRows = URLMatcher.entryURLs(keeper)
            let rows = try mergedURLRows(keeperRows, URLMatcher.entryURLs(other))
            if !sameRows(rows, keeperRows) {
                s["urls"] = .array(rows.map { .object(["url": .string($0.url), "match": .string($0.mode.rawValue)]) })
            }
            s[AccessRules.scopeKey] = AccessRules.stricter(s[AccessRules.scopeKey], os[AccessRules.scopeKey])
            out["scope"] = .object(s)
            if let policy = AccessRules.stricterPolicy(keeper["policy"], other["policy"]) { out["policy"] = policy }
            if keeper["notes"] != nil || other["notes"] != nil {
                out["notes"] = .string(try mergedNotes(keeper["notes"], other["notes"]) ?? text(keeper["notes"]))
            }
        } else {
            var p: [String: JSONValue] = if case .object(let o)? = keeper["payload"] { o } else { [:] }
            let op: [String: JSONValue] = if case .object(let o)? = other["payload"] { o } else { [:] }
            if p["notes"] != nil || op["notes"] != nil {
                p["notes"] = .string(try mergedNotes(p["notes"], op["notes"]) ?? text(p["notes"]))
            }
            out["payload"] = .object(p)
            // A record that carries its collections (the vectors, a Recently deleted row): their union, at most 20.
            // Store records never do; the caller merges memberships with `mergedCollections`.
            if keeper["collection_ids"] != nil || other["collection_ids"] != nil {
                out["collection_ids"] = try union(keeper["collection_ids"], other["collection_ids"],
                                                  cap: LocalData.maxCollectionMemberships)
            }
        }
        out["updated_at"] = .int(now)
        return out
    }

    /// Typed-item collections: union keeping the keeper's order, at most 20.
    public static func mergedCollections(_ keeper: [String], _ other: [String]) throws(MergeRefusal) -> [String] {
        var out = keeper
        for id in other where !out.contains(where: { $0.lowercased() == id.lowercased() }) { out.append(id) }
        guard out.count <= LocalData.maxCollectionMemberships else { throw .tooManyValues }
        return out
    }

    static func strings(_ v: JSONValue?) -> [String] {
        guard case .array(let a)? = v else { return [] }
        return a.compactMap { if case .string(let s) = $0 { return s }; return nil }
    }

    /// Union keeping `a`'s order, deduplicated by exact value; nil when both are absent.
    static func union(_ a: JSONValue?, _ b: JSONValue?, cap: Int) throws(MergeRefusal) -> JSONValue? {
        if a == nil && b == nil { return nil }
        var out: [JSONValue] = []
        var seen = Set<[UInt8]>()
        for v in (arr(a) + arr(b)) {
            let k = (try? RecordDigest.canon(v)) ?? []
            if seen.insert(k).inserted { out.append(v) }
        }
        guard out.count <= cap else { throw .tooManyValues }
        return .array(out)
    }

    static func arr(_ v: JSONValue?) -> [JSONValue] { if case .array(let a)? = v { return a }; return [] }

    /// The keeper's URL rows then the other's, deduplicated by `(url, match)` (exact code points), at most 20.
    static func mergedURLRows(_ keeper: [URLRow], _ other: [URLRow]) throws(MergeRefusal) -> [URLRow] {
        var out: [URLRow] = []
        var seen = Set<[UInt32]>()
        for row in keeper + other where seen.insert(rowKey(row)).inserted { out.append(row) }
        guard out.count <= 20 else { throw .tooManyValues }
        return out
    }

    static func sameRows(_ a: [URLRow], _ b: [URLRow]) -> Bool {
        a.count == b.count && zip(a, b).allSatisfy { rowKey($0) == rowKey($1) }
    }

    /// The row's mode rank, then its URL's code points (Python `str` equality, not Unicode canonical equivalence).
    static func rowKey(_ row: URLRow) -> [UInt32] { [UInt32(row.mode.rank)] + row.url.unicodeScalars.map(\.value) }

    /// The keeper's notes with the other's appended after a blank line when they differ and are not empty; nil when
    /// nothing changes.
    static func mergedNotes(_ keeper: JSONValue?, _ other: JSONValue?) throws(MergeRefusal) -> String? {
        let k = text(keeper), o = text(other)
        guard !o.isEmpty, !RecordDigest.same(k, o) else { return nil }
        let merged = k.isEmpty ? o : k + "\n\n" + o
        guard merged.unicodeScalars.count <= maxNotes else { throw .notesTooLong }
        return merged
    }

    // MARK: - Undo of a bulk action

    /// The in-memory journal of the last bulk action (§3.3): items moved to Recently deleted, and merged keepers with
    /// the record before the merge and the digest the merge wrote. Held until the vault locks or the next bulk action.
    public struct UndoJournal: Equatable, Sendable {
        public var trashed: [String]
        public var merged: [String: MergedKeeper]
        public init(trashed: [String] = [], merged: [String: MergedKeeper] = [:]) { self.trashed = trashed; self.merged = merged }
        public struct MergedKeeper: Equatable, Sendable {
            public let before: [String: JSONValue]
            public let writtenDigest: String
            public init(before: [String: JSONValue], writtenDigest: String) { self.before = before; self.writtenDigest = writtenDigest }
        }

        /// The keepers to put back: those whose current record still has the digest the merge wrote.
        public func revertibleKeepers(current: [String: [String: JSONValue]]) -> [String: [String: JSONValue]] {
            var out: [String: [String: JSONValue]] = [:]
            for (id, m) in merged {
                guard let now = current[id], RecordDigest.digest(.object(now)) == m.writtenDigest else { continue }
                out[id] = m.before
            }
            return out
        }
    }
}
