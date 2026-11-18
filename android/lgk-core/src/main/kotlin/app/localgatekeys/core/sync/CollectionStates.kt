package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.PyStrip
import app.localgatekeys.core.records.RecordException
import app.localgatekeys.core.records.Wrapper

/**
 * Personal collection states (sub-plan 07 Task 4; desktop `vault_bridge` "Personal collections"), byte for byte with
 * `tests/vectors/share/collections/states.json`. They travel in the personal group as namespace `collection`, only
 * between devices that all read them (a folder member's signed `.lgkcol` file, [FeatureCapability]; a Wi-Fi peer's
 * `features` answer, [app.localgatekeys.core.lan.LanFeatures]):
 *
 * - `col:<collection id>`: `{"kind":"collection","collection_id","name","description","created_at","updated_at"}`.
 * - `cm:<item id>`: `{"kind":"membership","item_id","collection_ids"}` (sorted, unique, 1..20; none is a tombstone).
 * - `csl:<collection id>`: `{"kind":"share-link","collection_id","mode","role"}` (never a group id, key or member).
 *
 * The store holds them as records ([CollectionCatalog]); collection sync ([CollectionSync], `SyncRunner.run(collections =)`)
 * publishes and accepts them only with peers that claimed the feature. In a run without it they are stripped, and a
 * stray one is `bad-remote` ([app.localgatekeys.core.records.Wrapper.unwrap]).
 */
object CollectionStates {
    const val NAMESPACE = "collection"
    const val CATALOG_PREFIX = "col:"
    const val MEMBERSHIP_PREFIX = "cm:"
    const val LINK_PREFIX = "csl:"
    const val MAX_MEMBERSHIPS = 20
    const val MAX_NAME = 100
    const val MAX_DESCRIPTION = 500
    val LINK_MODES: Set<String> = setOf("read", "edit")
    val LINK_ROLES: Set<String> = setOf("owner", "member")
    private const val MAX_INT63 = Long.MAX_VALUE
    private val catalogFields = setOf("kind", "collection_id", "name", "description", "created_at", "updated_at")
    private val membershipFields = setOf("kind", "item_id", "collection_ids")
    private val linkFields = setOf("kind", "collection_id", "mode", "role")

    /** Whether [id] names a collection state (no entry or item may use these prefixes). */
    fun isStateId(id: String): Boolean = id.startsWith(CATALOG_PREFIX) || id.startsWith(MEMBERSHIP_PREFIX) || id.startsWith(LINK_PREFIX)

    /** A collection state as stored: a reserved id (`col:`/`cm:`/`csl:`), or a wrapper of namespace `collection`. */
    fun isReserved(id: String, wrapper: JsonValue?): Boolean =
        isStateId(id) || (wrapper as? JsonValue.Obj)?.fields?.get("ns") == JsonValue.Str(NAMESPACE)

    private fun s(v: String) = JsonValue.Str(v)

    fun catalog(collectionId: String, name: String, description: String, createdAt: Long, updatedAt: Long): JsonValue =
        JsonValue.Obj(
            mapOf(
                "kind" to s("collection"), "collection_id" to s(collectionId), "name" to s(name),
                "description" to s(description), "created_at" to JsonValue.Int(createdAt), "updated_at" to JsonValue.Int(updatedAt),
            ),
        )

    fun membership(itemId: String, collectionIds: Collection<String>): JsonValue = JsonValue.Obj(
        mapOf(
            "kind" to s("membership"), "item_id" to s(itemId),
            "collection_ids" to JsonValue.Arr(sortedIds(collectionIds).map { s(it) }),
        ),
    )

    fun link(collectionId: String, mode: String, role: String): JsonValue =
        JsonValue.Obj(mapOf("kind" to s("share-link"), "collection_id" to s(collectionId), "mode" to s(mode), "role" to s(role)))

    /** The state id a record belongs to. */
    fun stateId(record: JsonValue): String? {
        val r = (record as? JsonValue.Obj)?.fields ?: return null
        return when ((r["kind"] as? JsonValue.Str)?.v) {
            "collection" -> (r["collection_id"] as? JsonValue.Str)?.v?.let { CATALOG_PREFIX + it }
            "membership" -> (r["item_id"] as? JsonValue.Str)?.v?.let { MEMBERSHIP_PREFIX + it }
            "share-link" -> (r["collection_id"] as? JsonValue.Str)?.v?.let { LINK_PREFIX + it }
            else -> null
        }
    }

    /** `{"ns":"collection","schema":1,"updated_at":rank,"record"}` (desktop `_collection_wrapper`). */
    fun wrapper(record: JsonValue): JsonValue = JsonValue.Obj(
        mapOf("ns" to s(NAMESPACE), "schema" to JsonValue.Int(Wrapper.SCHEMA), "updated_at" to JsonValue.Int(Wrapper.rank(record)), "record" to record),
    )

    private fun sortedIds(ids: Collection<String>): List<String> = ids.toSortedSet { a, b -> Scalars.compare(a, b) }.toList()

    private fun text(v: JsonValue?, limit: Int, allowEmpty: Boolean): String? {
        val t = (v as? JsonValue.Str)?.v ?: return null
        if ((!allowEmpty && t.isEmpty()) || Scalars.count(t) > limit || t.contains('\u0000')) return null
        return t
    }

    private fun time(v: JsonValue?): Long? = (v as? JsonValue.Int)?.v?.takeIf { it in 0..MAX_INT63 }

    /**
     * The record of a collection state if it is exactly well formed for [stateId] (desktop `_check_collection_record`),
     * else `bad-remote`.
     */
    fun checkRecord(stateId: String, record: JsonValue?): Map<String, JsonValue> {
        fun bad(): Nothing = throw RecordException("bad-remote", stateId, "malformed collection state")
        val r = (record as? JsonValue.Obj)?.fields ?: bad()
        when ((r["kind"] as? JsonValue.Str)?.v) {
            "collection" -> {
                if (r.keys != catalogFields) bad()
                val cid = (r["collection_id"] as? JsonValue.Str)?.v
                if (!ShareKeyring.isCanonicalUuid(cid) || stateId != CATALOG_PREFIX + cid) bad()
                val name = text(r["name"], MAX_NAME, allowEmpty = false) ?: bad()
                if (PyStrip.strip(name) != name) bad()
                text(r["description"], MAX_DESCRIPTION, allowEmpty = true) ?: bad()
                val created = time(r["created_at"]) ?: bad()
                val updated = time(r["updated_at"]) ?: bad()
                if (updated < created) bad()
            }
            "membership" -> {
                if (r.keys != membershipFields) bad()
                val item = (r["item_id"] as? JsonValue.Str)?.v
                if (!ShareKeyring.isCanonicalUuid(item) || stateId != MEMBERSHIP_PREFIX + item) bad()
                val ids = (r["collection_ids"] as? JsonValue.Arr)?.items?.map { (it as? JsonValue.Str)?.v ?: bad() } ?: bad()
                if (ids.size !in 1..MAX_MEMBERSHIPS || ids != sortedIds(ids) || !ids.all { ShareKeyring.isCanonicalUuid(it) }) bad()
            }
            "share-link" -> {
                if (r.keys != linkFields) bad()
                val cid = (r["collection_id"] as? JsonValue.Str)?.v
                if (!ShareKeyring.isCanonicalUuid(cid) || stateId != LINK_PREFIX + cid) bad()
                if ((r["mode"] as? JsonValue.Str)?.v !in LINK_MODES || (r["role"] as? JsonValue.Str)?.v !in LINK_ROLES) bad()
            }
            else -> bad()
        }
        return r
    }

    /**
     * The checked record of a live collection state (desktop `_unwrap` + `_unwrap_collection`); a conflict copy
     * ([isCopy]) is checked against the state id its record names. `update-needed` for a newer schema, else `bad-remote`.
     */
    fun unwrap(state: ItemState, isCopy: Boolean): Map<String, JsonValue> {
        val id = state.itemId
        val item = (state.item as? JsonValue.Obj)?.fields
        val schema = (item?.get("schema") as? JsonValue.Int)?.v
        if (schema != null && schema > Wrapper.SCHEMA) throw RecordException("update-needed", id, "written by a newer LocalGateKeys")
        val required = setOf("ns", "schema", "updated_at", "record")
        val allowed = if (isCopy) required + "id" else required
        if (item == null || !item.keys.containsAll(required) || !allowed.containsAll(item.keys)) {
            throw RecordException("bad-remote", id, "malformed wrapper")
        }
        if (schema == null || schema < 1 || item["ns"] != s(NAMESPACE)) throw RecordException("bad-remote", id, "malformed wrapper")
        val record = item["record"]
        val stateId = if (isCopy) {
            if (item["id"] != s(id)) throw RecordException("bad-remote", id, "malformed conflict copy")
            stateId(record ?: JsonValue.Null) ?: throw RecordException("bad-remote", id, "malformed conflict copy")
        } else {
            if (!isStateId(id)) throw RecordException("bad-remote", id, "not a collection state id")
            id
        }
        val checked = checkRecord(stateId, record)
        val u = item["updated_at"] as? JsonValue.Int
        if (u == null || u.v != Wrapper.rank(JsonValue.Obj(checked))) throw RecordException("bad-remote", id, "rank does not match its record")
        return checked
    }

    /**
     * Two devices changed one membership at once: both sides' collections are kept (desktop "keep the union"). Null
     * when the union would exceed [MAX_MEMBERSHIPS] (the membership then waits).
     */
    fun union(a: Collection<String>, b: Collection<String>): List<String>? =
        sortedIds(a + b).takeIf { it.size <= MAX_MEMBERSHIPS }
}
