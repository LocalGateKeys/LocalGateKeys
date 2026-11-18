/// What a share group publishes and accepts (sub-plan 07; desktop `vault_bridge` "Shared collections"; Kotlin
/// `ShareView`), byte for byte with `tests/vectors/share/collections/view.json`.
///
/// - Only typed items tagged with the collection are shared: never logins, documents (so no attachment file),
///   licences, the trash, untagged items or settings.
/// - A published record carries `collection_ids == [collection]` (the owner's other collections stay private);
///   `revision`, `tags`, `favorite` and `payload.document_ids` stay on the device (each person keeps their own).
/// - An incoming record must be a typed item that claims exactly `[collection]` (`bad-remote` otherwise).
public enum ShareView {
    /// Item fields a share never carries (desktop `SHARE_LOCAL_ONLY_ITEM_FIELDS`).
    public static let localOnlyItemFields = ["revision", "tags", "favorite"]
    static let entryKinds: Set<String> = ["web", "desktop"]
    static let unsharedKinds: Set<String> = ["document"]

    static func isExactly(_ v: JSONValue?, _ collectionID: String) -> Bool {
        guard case .string(let s)? = v else { return false }
        return Array(s.utf8) == Array(collectionID.utf8)
    }

    /// Whether the live `record` belongs in the share view of `collectionID`.
    public static func isShared(_ record: JSONValue, collectionID: String) -> Bool {
        guard case .object(let r) = record, case .string(let kind)? = r["kind"],
              !entryKinds.contains(kind), !unsharedKinds.contains(kind),
              case .array(let ids)? = r["collection_ids"] else { return false }
        return ids.contains { isExactly($0, collectionID) }
    }

    /// The share wrapper of a typed item (desktop `_wrapper("item", record, scope)`): the normal form without the
    /// local fields, tagged with only `collectionID`. Throws `NormaliseError` for a record the share cannot carry.
    public static func wrapper(_ record: JSONValue, collectionID: String) throws -> JSONValue {
        guard isShared(record, collectionID: collectionID) else { throw NormaliseError.rejected("not in the shared collection") }
        guard case .object(var normal) = try Normalise.normalForm(ns: .item, record: record) else {
            throw NormaliseError.rejected("not an item")
        }
        for name in localOnlyItemFields { normal[name] = nil }
        normal["collection_ids"] = .array([.string(collectionID)])
        return Wrapper.make(ns: .item, record: .object(normal))
    }

    /// The record of a live state a share member sent (desktop `_unwrap_remote` with a share scope): `bad-remote`
    /// unless it is a typed item claiming exactly `[collectionID]` whose content passes the normal form (the peer's
    /// local fields are dropped, never refused); `update-needed` for a newer wrapper schema. Documents never travel
    /// in a share.
    public static func checkIncoming(_ state: ItemState, collectionID: String) throws -> JSONValue {
        let id = state.itemID
        let (ns, record) = try Wrapper.unwrap(state, isCopy: false)
        guard ns == .item, case .object(let r) = record else {
            throw RecordError("bad-remote", id, "not an item of the shared collection")
        }
        if case .string(let kind)? = r["kind"], unsharedKinds.contains(kind) {
            throw RecordError("bad-remote", id, "a kind that does not sync")
        }
        guard case .array(let ids)? = r["collection_ids"], ids.count == 1, isExactly(ids[0], collectionID) else {
            throw RecordError("bad-remote", id, "claims another collection")
        }
        var stripped = r
        for name in localOnlyItemFields { stripped[name] = nil }
        do { _ = try Normalise.normalForm(ns: .item, record: .object(stripped)) } catch {
            throw RecordError("bad-remote", id, "invalid record")
        }
        return record
    }
}
