import Foundation

/// The switch report and the one-level undo of an import (feature pack contract §6.1). The journal is device-local
/// (`LocalData.lastImport`, key `last_import`), kept until the next import or 7 days.
public struct ImportJournal: Codable, Sendable, Equatable {
    public static let keepSeconds: Int64 = 7 * 86_400

    public var importID: String
    public var at: Int64
    public var source: String
    /// Created id → digest of the record the import wrote.
    public var created: [String: String]
    /// Replaced id → the record before the import (canonical JSON text) and the digest written.
    public var replaced: [String: Replaced]

    public struct Replaced: Codable, Sendable, Equatable {
        public var beforeJSON: String
        public var after: String
        public init(before: JSONValue, after: String) throws {
            beforeJSON = String(decoding: try RecordDigest.canon(before), as: UTF8.self)
            self.after = after
        }
        public init(beforeJSON: String, after: String) { self.beforeJSON = beforeJSON; self.after = after }
        public func before() throws -> JSONValue { try CanonicalJSON.parse(Array(beforeJSON.utf8)) }
        enum CodingKeys: String, CodingKey { case beforeJSON = "before", after }
    }

    public init(importID: String, at: Int64, source: String, created: [String: String] = [:], replaced: [String: Replaced] = [:]) {
        self.importID = importID; self.at = at; self.source = source; self.created = created; self.replaced = replaced
    }

    enum CodingKeys: String, CodingKey { case importID = "import_id", at, source, created, replaced }

    /// Still offered at `now`.
    public func isUndoable(now: Int64) -> Bool { now - at <= Self.keepSeconds && !(created.isEmpty && replaced.isEmpty) }

    /// The journal of one import: `before` and `after` are the live records (id → record) around the commit, `ids` the
    /// ids the import created or replaced (read back after the commit).
    public static func make(importID: String, at: Int64, source: String, ids: [String],
                            before: [String: [String: JSONValue]], after: [String: [String: JSONValue]]) throws -> ImportJournal {
        var j = ImportJournal(importID: importID, at: at, source: source)
        for id in ids {
            guard let written = after[id] else { continue }
            let digest = RecordDigest.digest(.object(written))
            if let old = before[id] {
                guard RecordDigest.digest(.object(old)) != digest else { continue }
                j.replaced[id] = try Replaced(before: .object(old), after: digest)
            } else {
                j.created[id] = digest
            }
        }
        return j
    }

    /// What an undo does to the current live records.
    public struct Undo: Equatable, Sendable {
        /// Created and untouched: move to Recently deleted.
        public var trash: [String]
        /// Replaced and untouched: the record before the import (with `updated_at = now`).
        public var restore: [String: [String: JSONValue]]
        /// Changed since the import (or gone): kept and listed.
        public var kept: [String]
    }

    /// The undo plan over `current` (id → live record).
    public func undo(current: [String: [String: JSONValue]], now: Int64) -> Undo {
        var u = Undo(trash: [], restore: [:], kept: [])
        for (id, digest) in created {
            if let r = current[id], RecordDigest.digest(.object(r)) == digest { u.trash.append(id) } else if current[id] != nil {
                u.kept.append(id)
            }
        }
        for (id, row) in replaced {
            guard let r = current[id], RecordDigest.digest(.object(r)) == row.after,
                  case .object(var before)? = try? row.before() else {
                if current[id] != nil { u.kept.append(id) }
                continue
            }
            before["updated_at"] = .int(now)
            u.restore[id] = before
        }
        u.trash.sort(by: scalarOrder); u.kept.sort(by: scalarOrder)
        return u
    }

    // MARK: - Report

    /// Skipped-row reason codes.
    public enum SkipReason: String, Sendable, CaseIterable {
        case duplicate, unsupported, invalid
        case overFreeLimit = "over_free_limit"
        case notInSourceFormat = "not_in_source_format"
    }

    /// Counts by kind of what was committed (logins are `web`; `passkey` counted on its own), read back from the store.
    public static func counts(ids: [String], committed: [String: [String: JSONValue]]) -> [String: Int] {
        var out: [String: Int] = [:]
        for id in Set(ids) {
            guard case .string(let kind)? = committed[id]?["kind"] else { continue }
            out[kind, default: 0] += 1
        }
        return out
    }
}

/// Passkey upgrade prompt dismissals (§6.3): registrable domain → when it was dismissed; shown again after 90 days;
/// at most 500 entries (the oldest dropped). Kept in `LocalData.passkeyUpgradeDismissed`.
public enum PasskeyUpgrade {
    public static let again: Int64 = 90 * 86_400
    public static let maxEntries = 500

    public static func isDismissed(_ domain: String, in dismissed: [String: Int64], now: Int64) -> Bool {
        guard let at = dismissed[domain.lowercased()] else { return false }
        return now - at < again
    }

    public static func dismissing(_ domain: String, in dismissed: [String: Int64], now: Int64) -> [String: Int64] {
        var out = dismissed
        out[domain.lowercased()] = now
        if out.count > maxEntries {
            let kept = out.sorted { $0.value != $1.value ? $0.value > $1.value : scalarOrder($0.key, $1.key) }.prefix(maxEntries)
            out = Dictionary(uniqueKeysWithValues: kept.map { ($0.key, $0.value) })
        }
        return out
    }

    /// The registrable domain the prompt is about for a `web` login: its origin's domain when the site lists
    /// `passkey` and no passkey item exists for that domain (the health `passkey` finding); nil otherwise.
    public static func domain(for record: [String: JSONValue], features: SiteFeatures, passkeyDomains: Set<String>) -> String? {
        guard record["kind"] == .string("web"), !features.isEmpty else { return nil }
        var urls: [String] = []
        if case .object(let scope)? = record["scope"] {
            if case .string(let o)? = scope["origin"], !o.isEmpty { urls.append(o) }
            if case .array(let rows)? = scope["urls"] {
                for row in rows { if case .object(let r) = row, case .string(let u)? = r["url"] { urls.append(u) } }
            }
        }
        for host in URLMatcher.webHosts(urls).hosts {
            guard let d = features.registrableDomain(of: host) else { continue }
            if features.supports(host: d, feature: "passkey") && !passkeyDomains.contains(d) { return d }
        }
        return nil
    }
}
