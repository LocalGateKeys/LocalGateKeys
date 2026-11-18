package app.localgatekeys.core.sync

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.primitives.Casefold
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.PyStrip
import java.util.UUID

/** Why a collection change was refused ([CollectionCatalog.Failure]); never carries content. */
class CollectionCatalogException(val failure: CollectionCatalog.Failure) : Exception(failure.code)

/**
 * Personal collections kept in the item store (sub-plan 07 Task 5j, the Kotlin port of LGKCore `CollectionCatalog`):
 * the catalog rows are `col:` records and the memberships `cm:` records, stored as their collection-state wrappers
 * ([CollectionStates]), so the store is the one source of truth that sync relays byte for byte. Item records keep their
 * v1 shape: an item never carries `collection_ids` in the store (a Recently deleted row does, as Windows' trash entry
 * does).
 *
 * The Windows rules (`collections.py`, `item_schema.py`): collections are free; at most 500; a name is 1..100 code
 * points, stored stripped and unique ignoring case (Python `casefold`); a description is at most 500; an item is in at
 * most 20 collections; logins (`web`, `desktop`) and documents are never added; deleting a collection keeps its items
 * and removes it from every membership and every Recently deleted row. Starters: Personal, Work, Travel, Emergency
 * (`ensure_starters`; only on request, never seeded automatically). Read-only shares refuse through
 * [ShareAccess.checkWritable].
 *
 * Pure: every builder returns the [StoreChange] to commit (records only; meta and sync state untouched), or null when
 * nothing changes. Every reader that lists or counts items uses [itemRecords], which leaves the collection states out.
 * Recently deleted rows live in the app's local data: they come in and go out as their records ([JsonValue]), in order.
 */
object CollectionCatalog {
    const val MAX_COLLECTIONS = 500
    val STARTER_NAMES: List<String> = listOf("Personal", "Work", "Travel", "Emergency")

    /** Item kinds that are never added to a collection (Windows logins have no `collection_ids`; documents never enter a share). */
    val NON_MEMBER_KINDS: Set<String> = setOf("web", "desktop", "document")
    internal val LOGIN_KINDS: Set<String> = setOf("web", "desktop")

    enum class Failure(val code: String) {
        /** 500 collections already. */
        LIMIT("collection-limit"),
        EMPTY_NAME("empty-name"),
        LONG_NAME("long-name"),
        DUPLICATE_NAME("duplicate-name"),
        LONG_DESCRIPTION("long-description"),

        /** A name or description with a NUL character. */
        INVALID_TEXT("invalid-text"),

        /** A new collection id that is malformed or already used (never with random UUIDs). */
        INVALID_ID("invalid-id"),

        /** No such collection or item. */
        NOT_FOUND("not-found"),

        /** A login or a document cannot be added to a collection. */
        NOT_MEMBER("not-member"),

        /** More than 20 collections on one item. */
        TOO_MANY("too-many"),

        /** A membership names a collection this vault does not know. */
        UNKNOWN_COLLECTION("unknown-collection"),

        /** The collection is shared on this device or read-only here: stop sharing (or leave) first. */
        SHARED("shared"),

        /** A collection-state id (`col:`/`cm:`/`csl:`) where an item id was expected. */
        RESERVED("reserved"),
    }

    private fun fail(f: Failure): Nothing = throw CollectionCatalogException(f)

    /** One catalog row (`col:` record). */
    data class Collection(val id: String, val name: String, val description: String, val createdAt: Long, val updatedAt: Long)

    // ---- reads ----

    /** The well-formed catalog rows, by name ignoring case, then id. A malformed `col:` record is not shown. */
    fun collections(snapshot: StoreSnapshot): List<Collection> = collections(snapshot.records)

    internal fun collections(records: Map<String, JsonValue>): List<Collection> {
        val out = ArrayList<Collection>()
        for ((id, wrapper) in records) {
            if (!id.startsWith(CollectionStates.CATALOG_PREFIX)) continue
            val r = checked(id, wrapper) ?: continue
            val cid = str(r["collection_id"]) ?: continue
            val name = str(r["name"]) ?: continue
            val description = str(r["description"]) ?: continue
            val created = (r["created_at"] as? JsonValue.Int)?.v ?: continue
            val updated = (r["updated_at"] as? JsonValue.Int)?.v ?: continue
            out.add(Collection(cid, name, description, created, updated))
        }
        return out.sortedWith { a, b ->
            val c = Scalars.compare(Casefold.fold(a.name), Casefold.fold(b.name))
            if (c != 0) c else Scalars.compare(a.id, b.id)
        }
    }

    /** The collection ids [itemId] belongs to (sorted; ids of collections this vault does not know are kept). */
    fun memberships(itemId: String, snapshot: StoreSnapshot): List<String> = memberships(itemId, snapshot.records)

    /** The live items in [collectionId], sorted by id. */
    fun items(collectionId: String, snapshot: StoreSnapshot): List<String> {
        val live = snapshot.itemRecords
        val out = ArrayList<String>()
        for ((id, wrapper) in snapshot.records) {
            if (!id.startsWith(CollectionStates.MEMBERSHIP_PREFIX)) continue
            val r = checked(id, wrapper) ?: continue
            val item = str(r["item_id"]) ?: continue
            if (live[item] == null || snapshot.meta[item]?.deleted == true) continue
            if (collectionId !in strings(r["collection_ids"])) continue
            out.add(item)
        }
        return out.sortedWith { a, b -> Scalars.compare(a, b) }
    }

    /**
     * Collections another of this person's devices holds as a member of a read-only share (`csl:` links with mode
     * `read` and role `member`): edits there are refused here too (desktop `linked_read_only_collection_ids`).
     */
    fun linkedReadOnlyIds(snapshot: StoreSnapshot): Set<String> = linkedReadOnlyIds(snapshot.records)

    internal fun linkedReadOnlyIds(records: Map<String, JsonValue>): Set<String> {
        val out = HashSet<String>()
        for ((id, wrapper) in records) {
            if (!id.startsWith(CollectionStates.LINK_PREFIX)) continue
            val r = checked(id, wrapper) ?: continue
            val cid = str(r["collection_id"]) ?: continue
            if (str(r["mode"]) == "read" && str(r["role"]) == "member") out.add(cid)
        }
        return out
    }

    // ---- catalog changes ----

    /** Creates a collection (`CollectionService.create`): the change and the new id. */
    fun create(
        name: String,
        description: String = "",
        snapshot: StoreSnapshot,
        now: Long,
        newId: () -> String = { UUID.randomUUID().toString() },
    ): Pair<StoreChange, String> {
        val existing = collections(snapshot.records)
        if (existing.size >= MAX_COLLECTIONS) fail(Failure.LIMIT)
        val stored = checkedName(name, existing, except = null)
        checkDescription(description)
        val id = newId()
        if (!ShareKeyring.isCanonicalUuid(id) || snapshot.records[CollectionStates.CATALOG_PREFIX + id] != null) fail(Failure.INVALID_ID)
        val at = maxOf(0L, now)
        val records = LinkedHashMap(snapshot.records)
        records[CollectionStates.CATALOG_PREFIX + id] = catalogWrapper(id, stored, description, at, at)
        return change(snapshot, records) to id
    }

    /**
     * Renames a collection and, when [description] is given, replaces its description. Null when nothing changes.
     * `updated_at` never goes back (the newest edit wins in sync). A collection another of this person's devices holds
     * as a member of a read-only share ([linkedReadOnlyIds]) is refused ([Failure.SHARED]): that device would
     * republish its own row over the change anyway ([CollectionSync]).
     */
    fun rename(id: String, name: String, description: String? = null, snapshot: StoreSnapshot, now: Long): StoreChange? {
        val existing = collections(snapshot.records)
        val row = existing.firstOrNull { it.id == id } ?: fail(Failure.NOT_FOUND)
        if (id in linkedReadOnlyIds(snapshot.records)) fail(Failure.SHARED)
        val stored = checkedName(name, existing, except = id)
        val newDescription = description ?: row.description
        checkDescription(newDescription)
        if (stored == row.name && newDescription == row.description) return null
        val records = LinkedHashMap(snapshot.records)
        records[CollectionStates.CATALOG_PREFIX + id] =
            catalogWrapper(id, stored, newDescription, row.createdAt, maxOf(now, row.updatedAt, row.createdAt))
        return change(snapshot, records)
    }

    /** What [delete] did: the store change and the new Recently deleted records (null when none changed). */
    class Deletion(val change: StoreChange, val trash: List<JsonValue>?)

    /**
     * Deletes a collection: its id leaves every membership and every Recently deleted record ([trash], in order); the
     * items stay.
     *
     * A shared collection is never deleted ([Failure.SHARED]: it is left or stopped first), so no share group is ever
     * orphaned, on this device or, once collections sync, on the device that holds the share. Refused when it has a
     * `csl:` share link (whichever of this person's devices shares it) or is in [protected] (the collections of this
     * device's share records, and read-only ones). [protected] has no default: the caller always passes them.
     */
    fun delete(id: String, snapshot: StoreSnapshot, trash: List<JsonValue>, protected: Set<String>): Deletion {
        if (collections(snapshot.records).none { it.id == id }) fail(Failure.NOT_FOUND)
        if (id in protected || snapshot.records[CollectionStates.LINK_PREFIX + id] != null) fail(Failure.SHARED)
        val records = LinkedHashMap(snapshot.records)
        records.remove(CollectionStates.CATALOG_PREFIX + id)
        for ((sid, wrapper) in snapshot.records) {
            if (!sid.startsWith(CollectionStates.MEMBERSHIP_PREFIX)) continue
            val r = checked(sid, wrapper) ?: continue
            val item = str(r["item_id"]) ?: continue
            val ids = strings(r["collection_ids"])
            if (id !in ids) continue
            setOrRemove(records, sid, membershipWrapper(item, ids.filter { it != id }))
        }
        var touched = false
        val rows = trash.map { record ->
            val r = (record as? JsonValue.Obj)?.fields ?: return@map record
            val list = (r["collection_ids"] as? JsonValue.Arr)?.items ?: return@map record
            val kept = list.filter { (it as? JsonValue.Str)?.v != id }
            if (kept.size == list.size) return@map record
            touched = true
            val out = LinkedHashMap(r)
            if (kept.isEmpty()) out.remove("collection_ids") else out["collection_ids"] = JsonValue.Arr(kept)
            JsonValue.Obj(out)
        }
        return Deletion(change(snapshot, records), if (touched) rows else null)
    }

    /**
     * The starter collections that are missing by name (`ensure_starters`): the change (null when all exist) and the ids
     * it creates (the app keeps them as its starter ids; the flag never syncs). Only on the person's request.
     */
    fun starters(
        snapshot: StoreSnapshot,
        now: Long,
        newId: () -> String = { UUID.randomUUID().toString() },
    ): Pair<StoreChange?, List<String>> {
        var current = snapshot
        val made = ArrayList<String>()
        for (name in STARTER_NAMES) {
            val existing = collections(current.records)
            if (existing.any { Casefold.fold(it.name) == Casefold.fold(name) }) continue
            if (existing.size >= MAX_COLLECTIONS) break
            val (c, id) = create(name, snapshot = current, now = now, newId = newId)
            current = current.copy(records = c.records)
            made.add(id)
        }
        return (if (made.isEmpty()) null else change(snapshot, current.records)) to made
    }

    // ---- memberships ----

    /**
     * Sets which collections the item [itemId] (of [kind]) belongs to (`CollectionService.set_membership`). Null when
     * nothing changes. Ids this vault does not know are kept only when the item already had them (from another device);
     * any other must name a known collection. Logins and documents are never added (removing an old membership is
     * allowed). [readOnly]: collections this device may not change ([ShareAccess]): an item in one is neither moved in
     * nor out ([ReadOnlyCollectionException]). The read-only links from this person's other devices
     * ([linkedReadOnlyIds]) always count too.
     */
    fun setMemberships(
        itemId: String,
        kind: String,
        wanted: List<String>,
        snapshot: StoreSnapshot,
        readOnly: Set<String> = emptySet(),
    ): StoreChange? {
        if (CollectionStates.isStateId(itemId)) fail(Failure.RESERVED)
        val item = snapshot.records[itemId]
        if (item == null || CollectionStates.isReserved(itemId, item) || snapshot.meta[itemId]?.deleted == true) fail(Failure.NOT_FOUND)
        val current = memberships(itemId, snapshot.records)
        val next = sortedIds(wanted)
        if (next == current) return null
        val known = collections(snapshot.records).map { it.id }.toSet()
        for (id in next) if (id !in known && id !in current) fail(Failure.UNKNOWN_COLLECTION)
        if (kind in NON_MEMBER_KINDS && !next.all { it in current }) fail(Failure.NOT_MEMBER)
        if (next.size > CollectionStates.MAX_MEMBERSHIPS) fail(Failure.TOO_MANY)
        ShareAccess.checkWritable(
            readOnly + linkedReadOnlyIds(snapshot.records),
            JsonValue.Obj(mapOf("collection_ids" to JsonValue.Arr(current.map { JsonValue.Str(it) }))),
            JsonValue.Obj(mapOf("collection_ids" to JsonValue.Arr(next.map { JsonValue.Str(it) }))),
        )
        val records = LinkedHashMap(snapshot.records)
        setOrRemove(records, CollectionStates.MEMBERSHIP_PREFIX + itemId, membershipWrapper(itemId, next))
        return change(snapshot, records)
    }

    // ---- Recently deleted ----

    /**
     * The trash copy of [record] (the item [itemId] being deleted): its memberships ride along as `collection_ids`, as
     * on Windows. Remove the membership from the store in the same commit ([withoutMembership]).
     */
    fun trashRecord(record: JsonValue, itemId: String, snapshot: StoreSnapshot): JsonValue {
        val ids = memberships(itemId, snapshot.records)
        val r = (record as? JsonValue.Obj)?.fields
        if (ids.isEmpty() || r == null) return record
        return JsonValue.Obj(LinkedHashMap(r).also { it["collection_ids"] = JsonValue.Arr(ids.map { s -> JsonValue.Str(s) }) })
    }

    /** [records] without the membership of [itemId]. */
    fun withoutMembership(itemId: String, records: Map<String, JsonValue>): Map<String, JsonValue> =
        LinkedHashMap(records).also { it.remove(CollectionStates.MEMBERSHIP_PREFIX + itemId) }

    /**
     * A Recently deleted record going back live: the record without `collection_ids` (the store form) and the records
     * with its membership back, for the collections that still exist (at most 20).
     */
    fun restored(record: Map<String, JsonValue>, itemId: String, records: Map<String, JsonValue>): Pair<Map<String, JsonValue>, Map<String, JsonValue>> {
        val r = LinkedHashMap(record)
        // A login never has collections, even if an old row says so.
        var ids = strings(r["collection_ids"])
        if (str(r["kind"]) in LOGIN_KINDS) ids = emptyList()
        r.remove("collection_ids")
        val out = LinkedHashMap(records)
        val known = collections(records).map { it.id }.toSet()
        val kept = sortedIds(ids.filter { it in known } + memberships(itemId, records))
        if (kept.isNotEmpty() && kept.size <= CollectionStates.MAX_MEMBERSHIPS) {
            val wrapper = try {
                membershipWrapper(itemId, kept)
            } catch (e: Exception) {
                null
            }
            if (wrapper != null) out[CollectionStates.MEMBERSHIP_PREFIX + itemId] = wrapper
        }
        return r to out
    }

    /**
     * A full restore replaces the items: the catalog rows and share links of [current] stay, and each membership whose
     * item is live in [restored]. A backup carries no collection states. A safety copy (a whole store) does: then its
     * own catalog and memberships come back as they were, and only [current]'s share links are added (they stand for
     * share records this device holds now). A reserved id holding anything but a collection state is dropped.
     */
    fun carriedOver(current: Map<String, JsonValue>, restored: Map<String, JsonValue>): Map<String, JsonValue> {
        val out = LinkedHashMap(restored.filter { !CollectionStates.isReserved(it.key, it.value) })
        val wholeStore = restored.any { CollectionStates.isStateId(it.key) && checked(it.key, it.value) != null }
        val fromCurrent = if (wholeStore) current.filterKeys { it.startsWith(CollectionStates.LINK_PREFIX) } else current
        for (source in listOf(restored, fromCurrent)) {
            for ((id, wrapper) in source) {
                if (!CollectionStates.isStateId(id) || out.containsKey(id)) continue
                if (checked(id, wrapper) == null) continue
                if (id.startsWith(CollectionStates.MEMBERSHIP_PREFIX)) {
                    val item = id.substring(CollectionStates.MEMBERSHIP_PREFIX.length)
                    val w = out[item]
                    if (w == null || CollectionStates.isReserved(item, w)) continue
                }
                out[id] = wrapper
            }
        }
        return out
    }

    // ---- migration of old local collections ----

    /** One collection of an older app's local data (the Mac's `LocalData.collections`, Android's `extra["collections"]`). */
    data class LegacyCollection(
        val id: String,
        val name: String,
        val description: String = "",
        val createdAt: Long,
        val updatedAt: Long,
        val starter: Boolean = false,
    )

    /** What [migrate] did. */
    class Migration(
        /** The store change (null: the store already holds everything). */
        val change: StoreChange?,
        /** The Recently deleted records after the move, in order: memberships of deleted items moved into them. */
        val trash: List<JsonValue>,
        /** The starter ids to keep (only of collections the store holds). */
        val starterIds: List<String>,
        /** Collections added to the store, and how many were renamed " (n)" next to a store collection of the same name. */
        val collections: Int,
        val renamed: Int,
        /** Memberships moved into the store and into Recently deleted records. */
        val memberships: Int,
        val trashMemberships: Int,
        /** Memberships that could not be kept: of a login, of an item that is neither live nor deleted, or past 20. */
        val dropped: Int,
    )

    /**
     * Moves an older app's local collections and memberships into the store (sub-plan 07 "Storage design"). Null when
     * there is nothing to move. Lossless and idempotent: a collection whose `col:` record exists already is kept as the
     * store has it, memberships are merged with the store's, so a run interrupted after the store commit and run again
     * changes nothing more. Commit [Migration.change] first, then save the local data without its collections.
     */
    fun migrate(
        legacy: List<LegacyCollection>,
        legacyMemberships: Map<String, List<String>>,
        trash: List<JsonValue>,
        starterIds: List<String>,
        snapshot: StoreSnapshot,
    ): Migration? {
        if (legacy.isEmpty() && legacyMemberships.isEmpty()) return null
        val records = LinkedHashMap(snapshot.records)
        val rows = ArrayList(trash)
        var added = 0
        var renamed = 0
        var moved = 0
        var toTrash = 0
        var dropped = 0
        val starters = ArrayList(starterIds)
        for (c in legacy.sortedWith { a, b -> Scalars.compare(a.id, b.id) }) {
            if (c.starter && c.id !in starters) starters.add(c.id)
            val sid = CollectionStates.CATALOG_PREFIX + c.id
            if (records.containsKey(sid)) continue
            val taken = collections(records).map { it.name }
            // An old name that strips to nothing (checked before stripping) gets a plain one.
            val stripped = PyStrip.strip(c.name)
            val name = uniqueName(stripped.ifEmpty { "Collection" }, taken)
            if (name != c.name) renamed++
            records[sid] = catalogWrapper(c.id, name, c.description, c.createdAt, maxOf(c.updatedAt, c.createdAt))
            added++
        }
        // Where each deleted item's rows are (an item can be deleted more than once).
        val trashed = HashMap<String, MutableList<Int>>()
        for ((i, row) in rows.withIndex()) {
            val id = str((row as? JsonValue.Obj)?.fields?.get("id")) ?: continue
            trashed.getOrPut(id.lowercase()) { ArrayList() }.add(i)
        }
        val live = snapshot.itemRecords
        for (item in legacyMemberships.keys.sortedWith { a, b -> Scalars.compare(a, b) }) {
            val ids = sortedIds(legacyMemberships[item] ?: emptyList())
            if (ids.isEmpty()) continue
            val wrapper = live[item]
            val at = trashed[item]
            if (wrapper != null && snapshot.meta[item]?.deleted != true) {
                if ((wrapper as? JsonValue.Obj)?.fields?.get("ns") != JsonValue.Str(Namespace.ITEM.wire)) {
                    dropped++
                    continue
                }
                val merged = CollectionStates.union(ids, memberships(item, records))
                if (merged == null) {
                    dropped++
                    continue
                }
                setOrRemove(records, CollectionStates.MEMBERSHIP_PREFIX + item, membershipWrapper(item, merged))
                moved++
            } else if (at != null) {
                // Only typed items keep collections (a login's row never gets them); counted once per item.
                var kept = false
                for (i in at) {
                    val r = (rows[i] as? JsonValue.Obj)?.fields ?: continue
                    val kind = str(r["kind"]) ?: continue
                    if (kind in LOGIN_KINDS) continue
                    val merged = CollectionStates.union(ids, strings(r["collection_ids"])) ?: continue
                    rows[i] = JsonValue.Obj(LinkedHashMap(r).also { it["collection_ids"] = JsonValue.Arr(merged.map { s -> JsonValue.Str(s) }) })
                    kept = true
                }
                if (kept) toTrash++ else dropped++
            } else {
                dropped++
            }
        }
        val storeChange = if (records == snapshot.records) null else change(snapshot, records)
        return Migration(
            storeChange, rows, starters.filter { records.containsKey(CollectionStates.CATALOG_PREFIX + it) },
            added, renamed, moved, toTrash, dropped,
        )
    }

    // ---- rules ----

    /** The stored name (Python `strip`), or why it can't be used: 1..100 code points, unique ignoring case. */
    fun checkedName(raw: String, existing: List<Collection>, except: String?): String {
        if (raw.contains('\u0000')) fail(Failure.INVALID_TEXT)
        val name = PyStrip.strip(raw)
        if (name.isEmpty()) fail(Failure.EMPTY_NAME)
        if (Scalars.count(name) > CollectionStates.MAX_NAME) fail(Failure.LONG_NAME)
        val folded = Casefold.fold(name)
        if (existing.any { it.id != except && Casefold.fold(it.name) == folded }) fail(Failure.DUPLICATE_NAME)
        return name
    }

    internal fun checkDescription(d: String) {
        if (d.contains('\u0000')) fail(Failure.INVALID_TEXT)
        if (Scalars.count(d) > CollectionStates.MAX_DESCRIPTION) fail(Failure.LONG_DESCRIPTION)
    }

    /** [name], or [name] with the first free " (n)" suffix (desktop `_unique_name`). */
    internal fun uniqueName(name: String, taken: List<String>): String {
        val used = taken.map { Casefold.fold(it) }.toSet()
        var candidate = name
        var n = 2
        while (Casefold.fold(candidate) in used) {
            val suffix = " ($n)"
            val head = Scalars.truncate(name, CollectionStates.MAX_NAME - Scalars.count(suffix))
            candidate = pyRStrip(head) + suffix
            n++
        }
        return candidate
    }

    private fun pyRStrip(s: String): String {
        var end = s.length
        while (end > 0) {
            val c = s.codePointBefore(end)
            if (!PyStrip.isSpace(c)) break
            end -= Character.charCount(c)
        }
        return s.substring(0, end)
    }

    // ---- helpers ----

    internal fun str(v: JsonValue?): String? = (v as? JsonValue.Str)?.v

    internal fun strings(v: JsonValue?): List<String> = (v as? JsonValue.Arr)?.items?.mapNotNull { (it as? JsonValue.Str)?.v } ?: emptyList()

    /** Unique ids in code-point order (LGKCore `ShareKeyring.sortedIDs`). */
    internal fun sortedIds(ids: Iterable<String>): List<String> = ids.toSortedSet { a, b -> Scalars.compare(a, b) }.toList()

    /** The checked record of the collection state [id] stored as [wrapper], or null. */
    internal fun checked(id: String, wrapper: JsonValue?): Map<String, JsonValue>? {
        val w = (wrapper as? JsonValue.Obj)?.fields ?: return null
        if (w["ns"] != JsonValue.Str(CollectionStates.NAMESPACE)) return null
        return try {
            CollectionStates.checkRecord(id, w["record"])
        } catch (e: Exception) {
            null
        }
    }

    internal fun memberships(itemId: String, records: Map<String, JsonValue>): List<String> {
        val sid = CollectionStates.MEMBERSHIP_PREFIX + itemId
        val r = checked(sid, records[sid] ?: return emptyList()) ?: return emptyList()
        return strings(r["collection_ids"])
    }

    internal fun catalogWrapper(id: String, name: String, description: String, createdAt: Long, updatedAt: Long): JsonValue {
        val record = CollectionStates.catalog(id, name, description, createdAt, updatedAt)
        CollectionStates.checkRecord(CollectionStates.CATALOG_PREFIX + id, record)
        return CollectionStates.wrapper(record)
    }

    /** The membership wrapper, or null (no record) for no collection. */
    internal fun membershipWrapper(itemId: String, ids: List<String>): JsonValue? {
        if (ids.isEmpty()) return null
        val record = CollectionStates.membership(itemId, ids)
        CollectionStates.checkRecord(CollectionStates.MEMBERSHIP_PREFIX + itemId, record)
        return CollectionStates.wrapper(record)
    }

    internal fun setOrRemove(records: MutableMap<String, JsonValue>, id: String, wrapper: JsonValue?) {
        if (wrapper == null) records.remove(id) else records[id] = wrapper
    }

    private fun change(snapshot: StoreSnapshot, records: Map<String, JsonValue>): StoreChange =
        StoreChange(snapshot.revision, records, snapshot.meta, snapshot.sync)
}

/**
 * Every stored record but the collection states: what item lists, search, counts, AutoFill, the watch, the security
 * check, exports, backups, restores and the trash read (sub-plan 07 "Storage design").
 */
val StoreSnapshot.itemRecords: Map<String, JsonValue>
    get() = records.filter { !CollectionStates.isReserved(it.key, it.value) }
