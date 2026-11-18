import Foundation

/// Item history with field-level diff (feature pack contract §1): per device, never synced. Each device snapshots the
/// version it is about to replace (its own edits, every version sync delivers, restores, imports and merges). Rows
/// live in `LocalData.itemHistory` (key `item_history`); `password_history` inside logins is untouched.
public enum ItemHistory {
    public enum ChangeType: String, Codable, Sendable, CaseIterable {
        case update, sync, restore
        case `import` = "import"
        case merge
    }

    /// One snapshot row `{snapshot_id, item_id, ns, created_at, change_type, record}`. The record is held as its
    /// canonical JSON text (like `LocalData.TrashRow`), so a restore gives back exactly the bytes that were stored.
    public struct Row: Codable, Sendable, Equatable, Identifiable {
        public var snapshotID: String
        public var itemID: String
        /// "entry" or "item".
        public var ns: String
        /// When this version was replaced (Unix seconds).
        public var createdAt: Int64
        /// A `ChangeType` raw value (kept as text so a newer build's value never breaks the file).
        public var changeType: String
        public var recordJSON: String

        public var id: String { snapshotID }

        public init(snapshotID: String, itemID: String, ns: String, createdAt: Int64, changeType: String, recordJSON: String) {
            self.snapshotID = snapshotID; self.itemID = itemID; self.ns = ns; self.createdAt = createdAt
            self.changeType = changeType; self.recordJSON = recordJSON
        }

        public init(snapshotID: String, itemID: String, ns: String, createdAt: Int64, changeType: ChangeType,
                    record: JSONValue) throws {
            self.init(snapshotID: snapshotID, itemID: itemID, ns: ns, createdAt: createdAt, changeType: changeType.rawValue,
                      recordJSON: String(decoding: try RecordDigest.canon(record), as: UTF8.self))
        }

        /// The stored record, parsed back with the canonical parser.
        public func record() throws -> JSONValue { try CanonicalJSON.parse(Array(recordJSON.utf8)) }

        /// The record as an object (empty when the text is damaged).
        public var recordObject: [String: JSONValue] {
            if case .object(let o)? = try? record() { return o }
            return [:]
        }

        /// `len(canon(row))` with the record as a JSON object (the contract's byte cap), computed without parsing the
        /// record: its canonical text is stored as is, so it is spliced in by length.
        public var canonicalSize: Int {
            let shell: JSONValue = .object([
                "snapshot_id": .string(snapshotID), "item_id": .string(itemID), "ns": .string(ns),
                "created_at": .int(createdAt), "change_type": .string(changeType), "record": .int(0),
            ])
            let base = (try? RecordDigest.canon(shell).count) ?? 0
            return base - 1 + recordJSON.utf8.count
        }

        enum CodingKeys: String, CodingKey {
            case snapshotID = "snapshot_id", itemID = "item_id", ns, createdAt = "created_at"
            case changeType = "change_type", recordJSON = "record"
        }
    }

    /// Retention limits (§1.4).
    public struct Limits: Equatable, Sendable {
        public var maxVersions: Int
        public var maxAgeDays: Int64
        public var maxBytes: Int
        public init(maxVersions: Int, maxAgeDays: Int64, maxBytes: Int) {
            self.maxVersions = maxVersions; self.maxAgeDays = maxAgeDays; self.maxBytes = maxBytes
        }
        /// 8 MiB on phones and the Mac.
        public static let deviceBytes = 8 * 1024 * 1024
        public static let free = Limits(maxVersions: 5, maxAgeDays: 30, maxBytes: deviceBytes)
        public static let pro = Limits(maxVersions: 30, maxAgeDays: 365, maxBytes: deviceBytes)
        public static func plan(isPro: Bool) -> Limits { isPro ? .pro : .free }
    }

    // MARK: - Retention

    /// `prune(rows, now, limits)`: age cut, then the newest `maxVersions` per item, then the globally oldest rows
    /// while the total canonical size is over `maxBytes`. Kept rows stay in their input order.
    public static func prune(_ rows: [Row], now: Int64, limits: Limits) -> [Row] {
        let cutoff = now - limits.maxAgeDays * 86_400
        var kept = rows.filter { $0.createdAt >= cutoff }
        // Per item: newest first, then snapshot id ascending.
        var keepIDs = Set<String>()
        let byItem = Dictionary(grouping: kept, by: \.itemID)
        for (_, group) in byItem {
            let ordered = group.sorted { a, b in
                a.createdAt != b.createdAt ? a.createdAt > b.createdAt : scalarOrder(a.snapshotID, b.snapshotID)
            }
            for r in ordered.prefix(max(0, limits.maxVersions)) { keepIDs.insert(r.snapshotID) }
        }
        kept = kept.filter { keepIDs.contains($0.snapshotID) }
        var total = kept.reduce(0) { $0 + $1.canonicalSize }
        if total > limits.maxBytes {
            let oldestFirst = kept.sorted { a, b in
                a.createdAt != b.createdAt ? a.createdAt < b.createdAt : scalarOrder(a.snapshotID, b.snapshotID)
            }
            var dropped = Set<String>()
            for r in oldestFirst where total > limits.maxBytes {
                dropped.insert(r.snapshotID)
                total -= r.canonicalSize
            }
            kept = kept.filter { !dropped.contains($0.snapshotID) }
        }
        return kept
    }

    // MARK: - Capture

    /// Fields whose only change never makes a version (§1.3 "Never snapshot ... records whose only change is a
    /// local-only field").
    static func comparable(_ record: [String: JSONValue]) -> JSONValue {
        var r = record
        r["site_icon"] = nil; r["collection_ids"] = nil; r["revision"] = nil
        if case .object(var scope)? = r["scope"] {
            for key in Normalise.localTrustScopeKeys { scope[key] = nil }
            r["scope"] = .object(scope)
        }
        if case .object(var p)? = r["policy"] { p["sign_in"] = nil; r["policy"] = .object(p) }
        return .object(r)
    }

    /// The `(ns, record)` of a stored wrapper that history covers: an `entry` or `item` wrapper of a live record that is
    /// not a collection state, a licence or the emergency access plan.
    static func historyRecord(_ id: String, _ wrapper: JSONValue?, deleted: Bool) -> (String, [String: JSONValue])? {
        guard !deleted, let wrapper, !CollectionStates.isReserved(id, wrapper), id != Heir.stateID,
              !id.hasPrefix(License.idPrefix), case .object(let w) = wrapper, case .string(let ns)? = w["ns"],
              ns == Namespace.entry.rawValue || ns == Namespace.item.rawValue,
              case .object(let r)? = w["record"] else { return nil }
        return (ns, r)
    }

    /// The rows one store commit adds: for each id live before and after whose record changed (local-only fields
    /// ignored), the version before, minus `site_icon`.
    public static func rows(before: StoreSnapshot, records: [String: JSONValue], meta: [String: SyncMeta],
                            changeType: ChangeType, now: Int64,
                            newID: () -> String = { UUID().uuidString.lowercased() }) -> [Row] {
        var out: [Row] = []
        for id in before.records.keys.sorted(by: scalarOrder) {
            guard let old = historyRecord(id, before.records[id], deleted: before.meta[id]?.deleted == true),
                  let new = historyRecord(id, records[id], deleted: meta[id]?.deleted == true) else { continue }
            guard RecordDigest.digest(comparable(old.1)) != RecordDigest.digest(comparable(new.1)) else { continue }
            let ns = old.0
            var stored = old.1
            stored["site_icon"] = nil
            if let row = try? Row(snapshotID: newID(), itemID: id, ns: ns, createdAt: now, changeType: changeType,
                                  record: .object(stored)) {
                out.append(row)
            }
        }
        return out
    }

    /// The rows for one item, newest first.
    public static func versions(of itemID: String, in rows: [Row]) -> [Row] {
        rows.filter { RecordDigest.same($0.itemID, itemID) }.sorted { a, b in
            a.createdAt != b.createdAt ? a.createdAt > b.createdAt : scalarOrder(a.snapshotID, b.snapshotID)
        }
    }

    // MARK: - Diff

    public struct FieldChange: Equatable, Sendable, Identifiable {
        public let field: String
        /// nil: missing on that side.
        public let before: JSONValue?
        public let after: JSONValue?
        public let secret: Bool
        public var id: String { field }
        public init(field: String, before: JSONValue?, after: JSONValue?, secret: Bool) {
            self.field = field; self.before = before; self.after = after; self.secret = secret
        }
    }

    /// The constant marker a hidden secret shows (`history._mask`): never a length or a fragment.
    public static let protectedMarker = "[protected]"

    static let ignoredPaths: [String] = ["id", "created_at", "updated_at", "revision", "collection_ids", "password_history",
                                         "site_icon", "payload.document_ids", "policy.sign_in"]
        + Normalise.localTrustScopeKeys.map { "scope." + $0 }

    static func matches(_ path: String, _ prefix: String) -> Bool { path == prefix || path.hasPrefix(prefix + ".") }

    public static func isIgnored(_ path: String) -> Bool { ignoredPaths.contains { matches(path, $0) } }

    /// The secret paths of §1.5.
    public static func isSecret(_ path: String, kind: String) -> Bool {
        let list: [String]
        switch kind {
        case "web", "desktop": list = ["password", "totp", "recovery_codes", "custom_fields", "notes"]
        case "note": list = ["payload.body", "payload.fields"]
        case "card": list = ["payload.number", "payload.cvv", "payload.pin"]
        case "bank_account": list = ["payload.account_number", "payload.pin"]
        case "identity": return path.hasPrefix("payload.") && !matches(path, "payload.template_id")
        case "license": list = ["payload.license_value", "payload.notes"]
        case "ssh_key": list = ["payload.private_key", "payload.passphrase"]
        case "api_key": list = ["payload.key", "payload.secret"]
        case "wifi": list = ["payload.password"]
        case "passkey": list = ["payload.private_key", "payload.user_handle"]
        case "bookmark": list = ["payload.url", "payload.notes"]
        case "purchase", "warranty", "subscription": list = ["payload.notes"]
        default: list = []
        }
        return list.contains { matches(path, $0) }
    }

    /// `history._flatten`: objects recurse with dotted paths, a list is one field, scalars as is.
    static func flatten(_ value: JSONValue, prefix: String = "", into out: inout [String: JSONValue]) {
        switch value {
        case .object(let o):
            for (key, child) in o { flatten(child, prefix: prefix.isEmpty ? key : prefix + "." + key, into: &out) }
        default:
            out[prefix] = value
        }
    }

    /// `diff(before, after, kind)`: changed fields in code-point order of their paths, ignored paths left out. With
    /// `reveal` false, both sides of a secret field are `"[protected]"`.
    public static func diff(before: [String: JSONValue], after: [String: JSONValue], kind: String,
                            reveal: Bool = false) -> [FieldChange] {
        var a: [String: JSONValue] = [:], b: [String: JSONValue] = [:]
        flatten(.object(before), into: &a)
        flatten(.object(after), into: &b)
        let paths = Set(a.keys).union(b.keys).filter { !isIgnored($0) }.sorted(by: scalarOrder)
        var out: [FieldChange] = []
        for path in paths {
            let l = a[path], r = b[path]
            if l == r { continue }
            let secret = isSecret(path, kind: kind)
            // A secret value is masked; a missing side stays null (desktop `diff`).
            let hide = secret && !reveal
            out.append(FieldChange(field: path, before: hide ? l.map { _ in .string(protectedMarker) } : l,
                                   after: hide ? r.map { _ in .string(protectedMarker) } : r, secret: secret))
        }
        return out
    }

    // MARK: - Restore one field

    public enum RestoreError: String, Error, Equatable, Sendable {
        case notRestorable = "not_restorable"
        case invalidOnThisDevice = "invalid_on_this_device"
    }

    static let fixedPaths = ["id", "kind", "created_at", "updated_at", "password_history"]

    public static func isRestorable(_ path: String) -> Bool {
        !path.isEmpty && !fixedPaths.contains(where: { matches(path, $0) }) && !isIgnored(path)
    }

    /// `restore_field(current, snapshot_record, path, now)`: `path` of `current` set to the snapshot's value (removed
    /// when the snapshot lacks it; a list replaces the whole list), `password` also pushing the current one into
    /// `password_history`, `updated_at = now`. The result must pass the platform normaliser
    /// (`invalidOnThisDevice` otherwise) and is returned as edited, not normalised (desktop `restore_field`).
    public static func restoreField(current: [String: JSONValue], snapshot: [String: JSONValue], path: String,
                                    now: Int64) throws(RestoreError) -> JSONValue {
        guard isRestorable(path) else { throw .notRestorable }
        var edited = RecordDigest.setting(path, to: RecordDigest.value(at: path, in: snapshot), in: current)
        if path == "password", case .string(let previous)? = current["password"] {
            edited = PasswordHistoryPush.pushing(previous, into: edited, now: now)
        }
        edited["updated_at"] = .int(now)
        let ns: Namespace = (current["kind"] == .string("web") || current["kind"] == .string("desktop")) ? .entry : .item
        do { _ = try Normalise.normalForm(ns: ns, record: .object(edited)) } catch { throw .invalidOnThisDevice }
        return .object(edited)
    }
}
