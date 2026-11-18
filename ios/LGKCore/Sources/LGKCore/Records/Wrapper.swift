/// Synced record namespaces.
public enum Namespace: String, Sendable {
    case entry, item, license
    /// The owner's emergency access plan (sub-plan 08), one state `heir:plan` (`Heir`).
    case heir
}

/// A record-level sync failure. `reason`: `update-needed`, `bad-remote` (both name `itemID`) or
/// `vault-changed`; `nil` reason means a malformed call (programming error, never a peer's fault).
public struct RecordError: Error, Equatable, Sendable, CustomStringConvertible {
    public let reason: String?
    public let itemID: String?
    public let detail: String
    public init(_ reason: String?, _ itemID: String?, _ detail: String) {
        self.reason = reason; self.itemID = itemID; self.detail = detail
    }
    public var description: String { "\(reason ?? "error"): \(itemID ?? "-"): \(detail)" }
}

/// The item wrapper `{"ns", "schema", "updated_at", "record"}` (vectors README "Item wrapper").
public enum Wrapper {
    public static let schema: Int64 = 1
    static let entryKinds: Set<String> = ["web", "desktop"]
    static let unsyncedItemKinds: Set<String> = ["document"]

    /// The engine's newest-edit rank: the record's int `updated_at` in 0...2^53-1, else 0.
    public static func rank(_ record: JSONValue) -> Int64 {
        if case .object(let o) = record, case .int(let n)? = o["updated_at"], (0...VersionVector.maxCounter).contains(n) {
            return n
        }
        return 0
    }

    /// Wraps a record; a licence always ranks 0, the emergency access plan by its `created`.
    public static func make(ns: Namespace, record: JSONValue) -> JSONValue {
        let updated: Int64
        switch ns {
        case .license: updated = 0
        case .heir:
            if case .object(let o) = record, case .int(let c)? = o["created"] { updated = c } else { updated = 0 }
        default: updated = rank(record)
        }
        return .object(["ns": .string(ns.rawValue), "schema": .int(schema), "updated_at": .int(updated), "record": record])
    }

    static func isHeirID(_ id: String) -> Bool { id == Heir.stateID }

    /// The checked synced plan record of a `heir` state (desktop `_unwrap_heir`): the live state is `heir:plan` with
    /// no `id`; a conflict copy keeps its own id. The record must pass `merge_synced(None, record)` and the wrapper's
    /// `updated_at` must be the record's `created`.
    static func unwrapHeir(_ state: ItemState, _ item: [String: JSONValue], isCopy: Bool) throws -> JSONValue {
        let id = state.itemID
        func bad(_ d: String) -> RecordError { RecordError("bad-remote", id, d) }
        if !isCopy && (item["id"] != nil || !isHeirID(id)) { throw bad("malformed emergency access state") }
        if isCopy && (isHeirID(id) || item["id"] != .string(id)) { throw bad("malformed emergency access state") }
        let record = item["record"]!
        do { _ = try Heir.mergeSynced(local: nil, remote: record) } catch { throw bad("malformed emergency access plan") }
        guard case .object(let r) = record, case .int(let created)? = r["created"], item["updated_at"] == .int(created) else {
            throw bad("rank does not match its record")
        }
        return record
    }

    static func nsOf(_ record: [String: JSONValue]) -> Namespace {
        if case .string(let k)? = record["kind"], entryKinds.contains(k) { return .entry }
        return .item
    }

    static func isLicenseID(_ id: String) -> Bool { id.hasPrefix(License.idPrefix) }

    /// Namespace and record of a live remote state (desktop `_unwrap`). A conflict copy (`isCopy`) gets the
    /// copy id as its record id. Licences are verified against `licenseKeys`.
    public static func unwrap(_ state: ItemState, isCopy: Bool,
                              licenseKeys: [String: [UInt8]] = [:]) throws -> (Namespace, JSONValue) {
        let id = state.itemID
        func bad(_ d: String) -> RecordError { RecordError("bad-remote", id, d) }
        let wrapper: [String: JSONValue]?
        if case .object(let o)? = state.item { wrapper = o } else { wrapper = nil }
        // The schema comes first: a newer schema may add wrapper fields.
        if case .int(let s)? = wrapper?["schema"], s > schema {
            throw RecordError("update-needed", id, "written by a newer LocalGateKeys")
        }
        // A document (attachment sync, 2026-10-29) carries one more key: `attachment`, its file's reference.
        let document = AttachmentDocuments.isDocument(state.item)
        let base: Set<String> = ["ns", "schema", "updated_at", "record"]
        let required = document ? base.union(["attachment"]) : base
        let allowed = isCopy ? required.union(["id"]) : required
        guard let item = wrapper, required.isSubset(of: item.keys), Set(item.keys).isSubset(of: allowed) else {
            throw bad("malformed wrapper")
        }
        guard case .int(let s)? = item["schema"], s >= 1 else { throw bad("malformed schema") }
        if item["ns"] == .string(Namespace.license.rawValue) {
            return (.license, try unwrapLicense(state, item, isCopy: isCopy, keys: licenseKeys))
        }
        if item["ns"] == .string(Namespace.heir.rawValue) {
            return (.heir, try unwrapHeir(state, item, isCopy: isCopy))
        }
        guard case .string(let nsText)? = item["ns"], let ns = Namespace(rawValue: nsText), ns != .license, ns != .heir,
              case .object(var record)? = item["record"], !isLicenseID(id), !isHeirID(id) else {
            throw bad("malformed wrapper")
        }
        // Personal collection states (`col:`, `cm:`, `csl:`) are reserved ids: no entry or item may use one.
        if CollectionStates.isStateID(id) { throw bad("reserved id") }
        guard case .int(let u)? = item["updated_at"], u == rank(.object(record)) else {
            throw bad("rank does not match its record")
        }
        if isCopy {
            guard item["id"] == .string(id) else { throw bad("malformed conflict copy") }
            record["id"] = .string(id)
        } else if record["id"] != .string(id) {
            throw bad("state does not match its record")
        }
        if nsOf(record) != ns { throw bad("wrong namespace") }
        if document {
            do { _ = try AttachmentDocuments.checkRemote(wrapper: item, record: record) } catch {
                throw bad("malformed attachment (\(error))")
            }
        } else if ns == .item, case .string(let k)? = record["kind"], unsyncedItemKinds.contains(k) {
            throw bad("a kind that does not sync")
        }
        return (ns, .object(record))
    }

    static func unwrapLicense(_ state: ItemState, _ item: [String: JSONValue], isCopy: Bool,
                              keys: [String: [UInt8]]) throws -> JSONValue {
        let id = state.itemID
        if isCopy || item["id"] != nil || !isLicenseID(id) { throw RecordError("bad-remote", id, "malformed licence state") }
        guard item["updated_at"] == .int(0) else { throw RecordError("bad-remote", id, "malformed licence state") }
        let bundle = item["record"]!
        let info: LicenseInfo
        do {
            info = try License.verify(bundle: bundle, keys: keys)
        } catch let e as LicenseError {
            if e.reason == "unknown-key" || e.reason == "bad-alg" || License.newerFormat(bundle: bundle, keys: keys) {
                throw RecordError("update-needed", id, "licence needs a newer LocalGateKeys")
            }
            throw RecordError("bad-remote", id, "licence does not verify (\(e.reason))")
        }
        if License.stateID(licenseID: info.licenseID) != id { throw RecordError("bad-remote", id, "licence id mismatch") }
        return bundle
    }
}
