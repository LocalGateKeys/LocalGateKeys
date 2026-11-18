/// Personal collection states (sub-plan 07 Task 4; desktop `vault_bridge` "Personal collections"; Kotlin
/// `CollectionStates`), byte for byte with `tests/vectors/share/collections/states.json`. They travel in the personal
/// group as namespace `collection`, only between devices that all read them (a folder member's signed `.lgkcol` file,
/// `FeatureCapability`; a Wi-Fi peer's `features` answer, `LanFeatures`):
///
/// - `col:<collection id>`: `{"kind":"collection","collection_id","name","description","created_at","updated_at"}`.
/// - `cm:<item id>`: `{"kind":"membership","item_id","collection_ids"}` (sorted, unique, 1..20; none is a tombstone).
/// - `csl:<collection id>`: `{"kind":"share-link","collection_id","mode","role"}` (never a group id, key or member).
///
/// Collection sync (`CollectionSync`, `SyncRunner.run(collections:)`) publishes and accepts them only with peers that
/// claimed the feature; in a run without it they are stripped, and a stray one is `bad-remote` (`Wrapper.unwrap`).
public enum CollectionStates {
    public static let namespace = "collection"
    public static let catalogPrefix = "col:"
    public static let membershipPrefix = "cm:"
    public static let linkPrefix = "csl:"
    public static let maxMemberships = 20
    public static let maxName = 100
    public static let maxDescription = 500
    public static let linkModes: Set<String> = ["read", "edit"]
    public static let linkRoles: Set<String> = ["owner", "member"]
    static let catalogFields: Set<String> = ["kind", "collection_id", "name", "description", "created_at", "updated_at"]
    static let membershipFields: Set<String> = ["kind", "item_id", "collection_ids"]
    static let linkFields: Set<String> = ["kind", "collection_id", "mode", "role"]
    static let wrapperFields: Set<String> = ["ns", "schema", "updated_at", "record"]

    /// Whether `id` names a collection state (no entry or item may use these prefixes).
    public static func isStateID(_ id: String) -> Bool {
        id.utf8.starts(with: catalogPrefix.utf8) || id.utf8.starts(with: membershipPrefix.utf8)
            || id.utf8.starts(with: linkPrefix.utf8)
    }

    public static func catalog(collectionID: String, name: String, description: String, createdAt: Int64,
                               updatedAt: Int64) -> JSONValue {
        .object(["kind": .string("collection"), "collection_id": .string(collectionID), "name": .string(name),
                 "description": .string(description), "created_at": .int(createdAt), "updated_at": .int(updatedAt)])
    }

    public static func membership(itemID: String, collectionIDs: [String]) -> JSONValue {
        .object(["kind": .string("membership"), "item_id": .string(itemID),
                 "collection_ids": .array(ShareKeyring.sortedIDs(collectionIDs).map { .string($0) })])
    }

    public static func link(collectionID: String, mode: String, role: String) -> JSONValue {
        .object(["kind": .string("share-link"), "collection_id": .string(collectionID), "mode": .string(mode),
                 "role": .string(role)])
    }

    /// The state id a record belongs to.
    public static func stateID(_ record: JSONValue) -> String? {
        guard case .object(let r) = record, case .string(let kind)? = r["kind"] else { return nil }
        switch kind {
        case "collection": if case .string(let c)? = r["collection_id"] { return catalogPrefix + c }
        case "membership": if case .string(let i)? = r["item_id"] { return membershipPrefix + i }
        case "share-link": if case .string(let c)? = r["collection_id"] { return linkPrefix + c }
        default: break
        }
        return nil
    }

    /// `{"ns":"collection","schema":1,"updated_at":rank,"record"}` (desktop `_collection_wrapper`).
    public static func wrapper(_ record: JSONValue) -> JSONValue {
        .object(["ns": .string(namespace), "schema": .int(Wrapper.schema), "updated_at": .int(Wrapper.rank(record)),
                 "record": record])
    }

    static func same(_ a: String, _ b: String) -> Bool { Array(a.utf8) == Array(b.utf8) }

    static func text(_ v: JSONValue?, limit: Int, allowEmpty: Bool) -> String? {
        guard case .string(let t)? = v else { return nil }
        if !allowEmpty && t.unicodeScalars.isEmpty { return nil }
        if t.unicodeScalars.count > limit || t.unicodeScalars.contains("\u{0}") { return nil }
        return t
    }

    /// An int in 0...2^63-1 (a bool is never an int here).
    static func time(_ v: JSONValue?) -> Int64? {
        guard case .int(let n)? = v, n >= 0 else { return nil }
        return n
    }

    /// The record of a collection state if it is exactly well formed for `stateID` (desktop
    /// `_check_collection_record`), else `bad-remote`.
    @discardableResult
    public static func checkRecord(_ stateID: String, _ record: JSONValue?) throws -> [String: JSONValue] {
        let bad = RecordError("bad-remote", stateID, "malformed collection state")
        guard case .object(let r)? = record, case .string(let kind)? = r["kind"] else { throw bad }
        switch kind {
        case "collection":
            guard Set(r.keys) == catalogFields, case .string(let cid)? = r["collection_id"],
                  ShareKeyring.isCanonicalUUID(cid), same(stateID, catalogPrefix + cid),
                  let name = text(r["name"], limit: maxName, allowEmpty: false), same(Normalise.pyStrip(name), name),
                  text(r["description"], limit: maxDescription, allowEmpty: true) != nil,
                  let created = time(r["created_at"]), let updated = time(r["updated_at"]), updated >= created
            else { throw bad }
        case "membership":
            guard Set(r.keys) == membershipFields, case .string(let item)? = r["item_id"],
                  ShareKeyring.isCanonicalUUID(item), same(stateID, membershipPrefix + item),
                  case .array(let list)? = r["collection_ids"] else { throw bad }
            var ids: [String] = []
            for v in list {
                guard case .string(let s) = v, ShareKeyring.isCanonicalUUID(s) else { throw bad }
                ids.append(s)
            }
            guard (1...maxMemberships).contains(ids.count) else { throw bad }
            // Sorted and unique: strictly increasing in code point order.
            for (a, b) in zip(ids, ids.dropFirst()) where !scalarOrder(a, b) { throw bad }
        case "share-link":
            guard Set(r.keys) == linkFields, case .string(let cid)? = r["collection_id"],
                  ShareKeyring.isCanonicalUUID(cid), same(stateID, linkPrefix + cid),
                  case .string(let mode)? = r["mode"], linkModes.contains(where: { same($0, mode) }),
                  case .string(let role)? = r["role"], linkRoles.contains(where: { same($0, role) }) else { throw bad }
        default:
            throw bad
        }
        return r
    }

    /// The checked record of a live collection state (desktop `_unwrap` + `_unwrap_collection`); a conflict copy
    /// (`isCopy`) is checked against the state id its record names. `update-needed` for a newer schema, else
    /// `bad-remote`.
    public static func unwrap(_ state: ItemState, isCopy: Bool) throws -> [String: JSONValue] {
        let id = state.itemID
        let wrapperObject: [String: JSONValue]?
        if case .object(let o)? = state.item { wrapperObject = o } else { wrapperObject = nil }
        var schemaValue: Int64?
        if case .int(let s)? = wrapperObject?["schema"] { schemaValue = s }
        if let s = schemaValue, s > Wrapper.schema { throw RecordError("update-needed", id, "written by a newer LocalGateKeys") }
        let allowed = isCopy ? wrapperFields.union(["id"]) : wrapperFields
        guard let item = wrapperObject, wrapperFields.isSubset(of: item.keys), Set(item.keys).isSubset(of: allowed) else {
            throw RecordError("bad-remote", id, "malformed wrapper")
        }
        guard let schema = schemaValue, schema >= 1, item["ns"] == .string(namespace) else {
            throw RecordError("bad-remote", id, "malformed wrapper")
        }
        let record = item["record"]
        let target: String
        if isCopy {
            guard case .string(let copyID)? = item["id"], same(copyID, id) else {
                throw RecordError("bad-remote", id, "malformed conflict copy")
            }
            guard let named = stateID(record ?? .null) else { throw RecordError("bad-remote", id, "malformed conflict copy") }
            target = named
        } else {
            guard isStateID(id) else { throw RecordError("bad-remote", id, "not a collection state id") }
            target = id
        }
        let checked = try checkRecord(target, record)
        guard case .int(let u)? = item["updated_at"], u == Wrapper.rank(.object(checked)) else {
            throw RecordError("bad-remote", id, "rank does not match its record")
        }
        return checked
    }

    /// Two devices changed one membership at once: both sides' collections are kept (desktop "keep the union"). Nil
    /// when the union would exceed `maxMemberships` (the membership then waits).
    public static func union(_ a: [String], _ b: [String]) -> [String]? {
        let all = ShareKeyring.sortedIDs(a + b)
        return all.count <= maxMemberships ? all : nil
    }
}
