package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.NormaliseException
import app.localgatekeys.core.records.RecordException
import app.localgatekeys.core.records.Wrapper

/**
 * What a share group publishes and accepts (sub-plan 07; desktop `vault_bridge` "Shared collections"), byte for byte
 * with `tests/vectors/share/collections/view.json`.
 *
 * - Only typed items tagged with the collection are shared: never logins, documents (so no attachment file), licences,
 *   the trash, untagged items or settings.
 * - A published record carries `collection_ids == [collection]` (the owner's other collections stay private); `revision`,
 *   `tags`, `favorite` and `payload.document_ids` stay on the device (each person keeps their own).
 * - An incoming record must be a typed item that claims exactly `[collection]` (`bad-remote` otherwise).
 */
object ShareView {
    /** Item fields a share never carries (desktop `SHARE_LOCAL_ONLY_ITEM_FIELDS`). */
    val LOCAL_ONLY_ITEM_FIELDS: List<String> = listOf("revision", "tags", "favorite")
    private val entryKinds = setOf("web", "desktop")
    private val unsharedKinds = setOf("document")

    private fun fields(record: JsonValue): Map<String, JsonValue>? = (record as? JsonValue.Obj)?.fields

    /** Whether the live [record] belongs in the share view of [collectionId]. */
    fun isShared(record: JsonValue, collectionId: String): Boolean {
        val r = fields(record) ?: return false
        val kind = (r["kind"] as? JsonValue.Str)?.v ?: return false
        if (kind in entryKinds || kind in unsharedKinds) return false
        val ids = (r["collection_ids"] as? JsonValue.Arr)?.items ?: return false
        return JsonValue.Str(collectionId) in ids
    }

    /**
     * The share wrapper of a typed item (desktop `_wrapper("item", record, scope)`): the normal form without the local
     * fields, tagged with only [collectionId]. Throws [NormaliseException] for a record the share cannot carry.
     */
    fun wrapper(record: JsonValue, collectionId: String): JsonValue {
        if (!isShared(record, collectionId)) throw NormaliseException(NormaliseException.Kind.REJECTED, "not in the shared collection")
        val normal = LinkedHashMap(fields(Normalise.normalForm(Namespace.ITEM, record))!!)
        for (name in LOCAL_ONLY_ITEM_FIELDS) normal.remove(name)
        normal["collection_ids"] = JsonValue.Arr(listOf(JsonValue.Str(collectionId)))
        return Wrapper.make(Namespace.ITEM, JsonValue.Obj(normal))
    }

    /**
     * The record of a live state a share member sent (desktop `_unwrap_remote` with a share scope): `bad-remote` unless
     * it is a typed item claiming exactly `[collectionId]` whose content passes the normal form (the peer's local
     * fields are dropped, never refused); `update-needed` for a newer wrapper schema.
     */
    fun checkIncoming(state: ItemState, collectionId: String): JsonValue {
        val (ns, record) = Wrapper.unwrap(state, isCopy = false)
        val id = state.itemId
        if (ns != Namespace.ITEM) throw RecordException("bad-remote", id, "not an item of the shared collection")
        val r = fields(record)!!
        if (r["collection_ids"] != JsonValue.Arr(listOf(JsonValue.Str(collectionId)))) {
            throw RecordException("bad-remote", id, "claims another collection")
        }
        val stripped = LinkedHashMap(r)
        for (name in LOCAL_ONLY_ITEM_FIELDS) stripped.remove(name)
        try {
            Normalise.normalForm(Namespace.ITEM, JsonValue.Obj(stripped))
        } catch (e: NormaliseException) {
            throw RecordException("bad-remote", id, "invalid record")
        }
        return record
    }
}
