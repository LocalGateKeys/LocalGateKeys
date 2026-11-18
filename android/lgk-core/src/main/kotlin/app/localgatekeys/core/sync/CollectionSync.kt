package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.VersionVector
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Casefold
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.RecordException
import app.localgatekeys.core.records.SyncMeta

/**
 * What this device's share records say for personal collection sync (sub-plan 07 Task 5j; desktop
 * `share_group.share_links` and `read_only_collection_ids`). Only a mode and a role per collection ever reach the
 * personal group: never a group id, key, keyring, member, folder or owner key.
 */
data class CollectionShares(
    /**
     * Collections shared on this device: this device speaks for their `csl:` link, and a catalog tombstone from another
     * device never deletes them here (their row is republished). Null: the share store could not be read; then no link
     * is published, tombstoned or replaced and no catalog tombstone is applied (they wait).
     */
    val links: Map<String, Link>? = emptyMap(),
    /**
     * Collections this device holds as a member of a read-only share ([ShareAccess.readOnlyCollectionIds], which fails
     * closed): another of this person's devices never edits, deletes, moves or renames them here; this device's copy is
     * republished above the change. Applies in every personal run, with or without collections.
     */
    val readOnly: Set<String> = emptySet(),
) {
    /** What a `csl:` share link says: `read`/`edit` and this device's role, `owner`/`member`. */
    data class Link(val mode: String, val role: String)

    companion object {
        /** No share on this device (every device before share sync, desktop `share_links` == {}). */
        val NONE = CollectionShares()
    }
}

/**
 * Personal collection sync (sub-plan 07 Task 5j; desktop `vault_bridge` "Personal collections", `_collection_view`,
 * `_collection_states` and `_Collections`; the port of LGKCore `CollectionSync`). The store holds the `col:`/`cm:`/`csl:`
 * states as records ([CollectionCatalog]), so:
 *
 * - Published ([addStates]): every well-formed catalog row; the membership of every live item (`ns` `item`); a share
 *   link for each collection shared on this device ([CollectionShares.links], only for a row this device has); the links
 *   learned from another device, relayed only exactly as received. A state this device no longer has becomes a
 *   tombstone; an unreadable record is left alone (no state, meta untouched). Collection states never push the view past
 *   the record cap: then none is published and their meta stays (they wait; everything else still syncs).
 * - Applied ([Applier]), in the order catalog, then items, then memberships and links:
 *   - two collections of one name: the larger id gets " (n)", the same on every device, `updated_at` untouched;
 *   - a catalog tombstone deletes the row and takes it out of every membership (the items stay), unless it is shared on
 *     this device (republished); a change of a read-only share's row is refused the same way;
 *   - a membership waits (no meta) until its item and every named collection are here; collections this device holds
 *     read-only are never added or removed by another device ([Applier.target]);
 *   - two devices changing one membership at once keep the union (the engine's conflict copy is never stored and never
 *     counted as a conflict); a losing catalog row or link copy is dropped (the winner was applied);
 *   - a link of a collection shared on this device is this device's own: it is republished above anything else.
 */
internal object CollectionSync {
    private const val CAT = CollectionStates.CATALOG_PREFIX
    private const val MEM = CollectionStates.MEMBERSHIP_PREFIX
    private const val LNK = CollectionStates.LINK_PREFIX

    /** A collection state, or a conflict copy of one (its id is a plain uuid; desktop `_is_collection_state`). */
    fun isCollectionState(state: ItemState): Boolean =
        CollectionStates.isStateId(state.itemId) ||
            (state.item as? JsonValue.Obj)?.fields?.get("ns") == JsonValue.Str(CollectionStates.NAMESPACE)

    /** Whether [id] is a live item (a typed item, namespace `item`) in [records]. */
    fun isLiveItem(id: String, records: Map<String, JsonValue>): Boolean {
        val w = records[id] ?: return false
        if (CollectionStates.isReserved(id, w)) return false
        return SyncMeta.nsName(w) == Namespace.ITEM.wire
    }

    /** The well-formed catalog rows: collection id -> checked record. */
    fun rows(records: Map<String, JsonValue>): MutableMap<String, Map<String, JsonValue>> {
        val out = LinkedHashMap<String, Map<String, JsonValue>>()
        for ((id, wrapper) in records) {
            if (!id.startsWith(CAT)) continue
            val r = CollectionCatalog.checked(id, wrapper) ?: continue
            out[id.substring(CAT.length)] = r
        }
        return out
    }

    /** The `csl:` wrapper this device publishes for its own share of [collectionId], null when [link] is malformed. */
    fun linkWrapper(collectionId: String, link: CollectionShares.Link): JsonValue? {
        val record = CollectionStates.link(collectionId, link.mode, link.role)
        return try {
            CollectionStates.checkRecord(LNK + collectionId, record)
            CollectionStates.wrapper(record)
        } catch (e: RecordException) {
            null
        }
    }

    private fun wrap(r: Map<String, JsonValue>): JsonValue = CollectionStates.wrapper(JsonValue.Obj(r))

    /** The record inside a collection-state wrapper. */
    private fun recordOf(wrapper: JsonValue): JsonValue? = (wrapper as? JsonValue.Obj)?.fields?.get("record")

    /**
     * Whether link record [mine] wins over [theirs] when two of this person's devices share one collection (re-review
     * wave B, B1; desktop `_link_beats`, LGKCore `CollectionSync.linkBeats`): the owner role over a member's, then the
     * larger canonical record. The same on every device, so the two stop republishing over each other: only the
     * winner's link is published, the loser relays it as received.
     */
    fun linkBeats(mine: JsonValue, theirs: JsonValue): Boolean {
        fun owner(r: JsonValue) = (r as? JsonValue.Obj)?.fields?.get("role") == JsonValue.Str("owner")
        if (owner(mine) != owner(theirs)) return owner(mine)
        val a = CanonicalJson.encode(mine, Dialect.UTF8)
        val b = CanonicalJson.encode(theirs, Dialect.UTF8)
        for (i in 0 until minOf(a.size, b.size)) {
            val c = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (c != 0) return c > 0
        }
        return a.size > b.size
    }

    /** Whether this device's own link [mine] is published over the [stored] link of another device (null: none). */
    private fun ownWins(mine: JsonValue, stored: JsonValue?): Boolean {
        if (stored == null || SyncMeta.digest(stored) == SyncMeta.digest(mine)) return true
        val a = recordOf(mine) ?: return true
        val b = recordOf(stored) ?: return true
        return linkBeats(a, b)
    }

    // ---- local view ----

    /**
     * Adds the collection states to [states] (desktop `_collection_states`) and returns the meta to keep: [meta] as it
     * was when the view would exceed the record cap.
     */
    fun addStates(
        records: Map<String, JsonValue>,
        skipped: Map<String, String>,
        meta: Map<String, SyncMeta>,
        states: MutableMap<String, ItemState>,
        device: String,
        now: Long,
        shares: CollectionShares,
    ): Map<String, SyncMeta> {
        val own = LinkedHashMap<String, JsonValue>() // states this device stands for (bumped when they change)
        val relay = LinkedHashMap<String, JsonValue>() // links learned from another device: republished only as received
        val quiet = HashSet<String>() // unreadable here: no state, meta untouched
        val rowIds = HashSet<String>()
        for ((id, wrapper) in records) {
            if (!CollectionStates.isStateId(id)) continue
            val r = CollectionCatalog.checked(id, wrapper)
            if (r == null) {
                quiet.add(id)
                continue
            }
            when {
                id.startsWith(CAT) -> {
                    own[id] = wrap(r)
                    rowIds.add(id.substring(CAT.length))
                }
                id.startsWith(MEM) -> {
                    val item = id.substring(MEM.length)
                    if (skipped.containsKey(item)) {
                        quiet.add(id)
                        continue
                    }
                    // The membership of an item that is not live here (deleted, or a login) is not published.
                    if (isLiveItem(item, records)) own[id] = wrap(r)
                }
                else -> relay[id] = wrap(r)
            }
        }
        val links = shares.links
        if (links != null) {
            for ((cid, link) in links) {
                if (cid !in rowIds) continue
                val wrapper = linkWrapper(cid, link) ?: continue
                // Another of this person's devices shares it too and its link wins: relayed as received (B1).
                if (!ownWins(wrapper, relay[LNK + cid])) continue
                own[LNK + cid] = wrapper
                relay.remove(LNK + cid)
            }
        }
        val work = LinkedHashMap(meta)
        val found = LinkedHashMap<String, ItemState>()
        for ((id, wrapper) in own) {
            var m = work[id]
            val d = SyncMeta.digest(wrapper)
            if (m == null || m.deleted || m.digest != d) {
                val vv = SyncMeta.bumped(m?.vv ?: emptyMap(), device) ?: continue
                m = SyncMeta.live(wrapper, vv)
                work[id] = m
            }
            found[id] = ItemState(id, m.vv, false, null, wrapper)
        }
        for ((id, wrapper) in relay) {
            val m = work[id] ?: continue
            if (m.deleted || m.digest != SyncMeta.digest(wrapper)) continue
            found[id] = ItemState(id, m.vv, false, null, wrapper)
        }
        for ((id, m) in work.entries.toList()) {
            if (!CollectionStates.isStateId(id) || own.containsKey(id) || relay.containsKey(id) || id in quiet) continue
            // A relayed link that changed here goes quiet until it comes again; own links are unknown without shares.
            if (id.startsWith(LNK) && links == null) continue
            if (!Identifier.isValid(id)) continue
            var t = m
            if (!m.deleted) {
                val vv = SyncMeta.bumped(m.vv, device) ?: continue
                t = SyncMeta.tomb(vv, now)
                work[id] = t
            }
            found[id] = ItemState(id, t.vv, true, t.deletedAt, null)
        }
        if (states.size + found.size > SyncMeta.MAX_RECORDS || work.size > SyncMeta.MAX_RECORDS) return meta
        states.putAll(found)
        return work
    }

    // ---- apply ----

    /**
     * Applies the collection states of one personal-group outcome (desktop `_Collections`). Works in place on the
     * caller's own copies of the records and meta ([SyncMeta.applyRemote]'s working maps).
     */
    class Applier(
        val records: MutableMap<String, JsonValue>,
        val meta: MutableMap<String, SyncMeta>,
        private val device: String,
        private val now: Long,
        private val shares: CollectionShares,
    ) {
        private val rows: MutableMap<String, Map<String, JsonValue>> = rows(records)
        private val readOnly: Set<String> get() = shares.readOnly

        private fun room(id: String): Boolean = meta.containsKey(id) || meta.size < SyncMeta.MAX_RECORDS

        private fun bump(vv: Map<String, Long>): Map<String, Long> = VersionVector.bump(vv, device)

        private fun digest(v: JsonValue): String = SyncMeta.digest(v)

        private fun memberships(item: String): List<String> = CollectionCatalog.memberships(item, records)

        /** What this device publishes now for the catalog row or membership [id] (desktop `_Collections._current`). */
        private fun current(id: String): JsonValue? {
            if (id.startsWith(CAT)) return rows[id.substring(CAT.length)]?.let { wrap(it) }
            val item = id.substring(MEM.length)
            if (!isLiveItem(item, records)) return null
            val r = CollectionCatalog.checked(id, records[id] ?: return null) ?: return null
            return wrap(r)
        }

        /** A stored catalog row or membership this device cannot read: incoming states for it are left out. */
        fun unreadable(id: String): Boolean {
            val w = records[id] ?: return false
            return CollectionCatalog.checked(id, w) == null
        }

        /** `vault-changed` when the catalog row or membership [id] changed since the view was taken. */
        fun checkFresh(id: String) {
            if (id.startsWith(LNK)) return // links change only here and through the share actions
            val m = meta[id]
            val published = current(id)
            val fresh = if (m == null || m.deleted) published == null else published != null && digest(published) == m.digest
            if (!fresh) throw RecordException("vault-changed", id, "The vault changed since the sync view was taken; sync again")
        }

        // ---- catalog rows ----

        private fun storeRow(cid: String, record: Map<String, JsonValue>) {
            val name = CollectionCatalog.str(record["name"])
            val description = CollectionCatalog.str(record["description"])
            val created = (record["created_at"] as? JsonValue.Int)?.v
            val updated = (record["updated_at"] as? JsonValue.Int)?.v
            if (name == null || description == null || created == null || updated == null) {
                throw RecordException(null, null, "malformed collection row")
            }
            val wrapper = CollectionCatalog.catalogWrapper(cid, name, description, created, updated)
            val stored = ((wrapper as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields
            records[CAT + cid] = wrapper
            rows[cid] = stored
        }

        fun catalogUpsert(s: ItemState, record: Map<String, JsonValue>): Boolean {
            val sid = s.itemId
            val cid = sid.substring(CAT.length)
            val row = rows[cid]
            if ((row == null && rows.size >= CollectionCatalog.MAX_COLLECTIONS) || !room(sid)) return false // waits
            val incoming = wrap(record)
            if (row != null && cid in readOnly) {
                // A read-only share's row never changes from another device: this device's row is republished.
                val mine = wrap(row)
                meta[sid] = SyncMeta.live(mine, if (digest(mine) == digest(incoming)) s.vv else bump(s.vv))
                return false
            }
            val new = LinkedHashMap(record)
            val name = CollectionCatalog.str(record["name"]) ?: throw RecordException(null, null, "malformed collection row")
            val folded = Casefold.fold(name)
            // The smallest such id when duplicates already exist, so the choice never depends on map order.
            val match = rows.entries.filter { it.key != cid && sameName(it.value, folded) }
                .minWithOrNull { a, b -> Scalars.compare(a.key, b.key) }
            val otherName = match?.let { CollectionCatalog.str(it.value["name"]) }
            if (match != null && otherName != null) {
                val otherId = match.key
                // Two collections of one name (made on two devices): the larger id gets a number, the same on every
                // device, and its updated_at stays, so devices that rename alike agree.
                val names = rows.entries.filter { it.key != cid && it.key != otherId }.mapNotNull { CollectionCatalog.str(it.value["name"]) }
                if (Scalars.compare(otherId, cid) < 0) {
                    new["name"] = JsonValue.Str(CollectionCatalog.uniqueName(name, names + otherName))
                } else {
                    val renamed = LinkedHashMap(match.value)
                    renamed["name"] = JsonValue.Str(CollectionCatalog.uniqueName(otherName, names + name))
                    storeRow(otherId, renamed)
                }
            }
            storeRow(cid, new)
            val stored = wrap(rows.getValue(cid))
            meta[sid] = SyncMeta.live(stored, if (digest(stored) == digest(incoming)) s.vv else bump(s.vv))
            if (row == null) return true
            return digest(wrap(row)) != digest(stored)
        }

        private fun sameName(row: Map<String, JsonValue>, folded: String): Boolean {
            val n = CollectionCatalog.str(row["name"]) ?: return false
            return Casefold.fold(n) == folded
        }

        fun catalogDelete(s: ItemState, at: Long): Boolean {
            val sid = s.itemId
            val cid = sid.substring(CAT.length)
            val row = rows[cid]
            // Whether it is shared on this device cannot be told without the share records: decide nothing now.
            val links = shares.links ?: return false
            if (row != null && (links.containsKey(cid) || cid in readOnly)) {
                // Shared on this device: only leaving the share removes it here; this row is republished.
                meta[sid] = SyncMeta.live(wrap(row), bump(s.vv))
                return false
            }
            if (!room(sid)) return false
            meta[sid] = SyncMeta.tomb(s.vv, at)
            if (row == null) return false
            rows.remove(cid)
            records.remove(sid)
            // As `CollectionCatalog.delete`: the items stay, only their membership goes (their meta is untouched, so the
            // next view publishes the change). Recently deleted rows are the app's: a restore re-adds only collections
            // that still exist.
            for ((mid, wrapper) in records.entries.toList()) {
                if (!mid.startsWith(MEM)) continue
                val r = CollectionCatalog.checked(mid, wrapper) ?: continue
                val item = CollectionCatalog.str(r["item_id"]) ?: continue
                val ids = CollectionCatalog.strings(r["collection_ids"])
                if (cid !in ids) continue
                CollectionCatalog.setOrRemove(records, mid, CollectionCatalog.membershipWrapper(item, ids.filter { it != cid }))
            }
            records.remove(LNK + cid)
            return true
        }

        // ---- memberships ----

        /**
         * The membership to store: [wanted] minus unknown and read-only-share collections, plus this device's own
         * read-only-share ones; null while a wanted collection is not known here yet (or past 20).
         */
        fun target(wanted: List<String>, current: List<String>): List<String>? {
            val known = ArrayList<String>()
            for (cid in wanted) {
                if (rows.containsKey(cid)) {
                    known.add(cid)
                    continue
                }
                val m = meta[CAT + cid]
                if (m == null || !m.deleted) return null // its catalog row has not arrived yet: wait (no meta)
            }
            val kept = current.filter { it in readOnly }
            val added = CollectionCatalog.sortedIds(known).filter { it !in readOnly && it !in kept }
            val target = CollectionCatalog.sortedIds(kept + added)
            return if (target.size <= CollectionStates.MAX_MEMBERSHIPS) target else null
        }

        fun membershipUpsert(s: ItemState, record: Map<String, JsonValue>, union: Boolean = false): Boolean {
            val item = CollectionCatalog.str(record["item_id"]) ?: throw RecordException(null, null, "malformed membership")
            val sid = MEM + item
            if (!isLiveItem(item, records) || !room(sid)) return false // the item is not here (yet): it waits
            val have = memberships(item)
            val incoming = CollectionCatalog.strings(record["collection_ids"])
            val next = target(if (union) have + incoming else incoming, have) ?: return false
            val changed = CollectionCatalog.sortedIds(have) != next
            val stored = CollectionCatalog.membershipWrapper(item, next)
            if (changed) CollectionCatalog.setOrRemove(records, sid, stored)
            if (union) {
                // Both sides' collections are kept: published above both as this device's own change.
                if (changed) {
                    val vv = bump(meta[sid]?.vv ?: emptyMap())
                    meta[sid] = if (stored != null) SyncMeta.live(stored, vv) else SyncMeta.tomb(vv, now)
                }
                return changed
            }
            meta[sid] = if (stored != null) {
                SyncMeta.live(stored, if (digest(stored) == digest(wrap(record))) s.vv else bump(s.vv))
            } else {
                SyncMeta.tomb(bump(s.vv), now)
            }
            return changed
        }

        fun membershipDelete(s: ItemState, at: Long): Boolean {
            val sid = s.itemId
            if (!room(sid)) return false
            val item = sid.substring(MEM.length)
            if (!isLiveItem(item, records)) {
                records.remove(sid) // the stale membership of an item that is gone
                meta[sid] = SyncMeta.tomb(s.vv, at)
                return false
            }
            val have = memberships(item)
            val kept = CollectionCatalog.sortedIds(have.filter { it in readOnly })
            val changed = CollectionCatalog.sortedIds(have) != kept
            val stored = CollectionCatalog.membershipWrapper(item, kept)
            if (changed) CollectionCatalog.setOrRemove(records, sid, stored)
            // Its read-only collections stay.
            meta[sid] = if (stored != null) SyncMeta.live(stored, bump(s.vv)) else SyncMeta.tomb(s.vv, at)
            return changed
        }

        // ---- share links ----

        fun linkUpsert(s: ItemState, record: Map<String, JsonValue>): Boolean {
            val sid = s.itemId
            val cid = sid.substring(LNK.length)
            // No room, or this device's own shares cannot be read: decide nothing now.
            if (!room(sid)) return false
            val links = shares.links ?: return false
            val incoming = wrap(record)
            val link = links[cid]
            if (link != null && rows.containsKey(cid)) {
                val mine = linkWrapper(cid, link) ?: return false
                if (digest(mine) == digest(incoming)) {
                    // The same link: no other device shares it differently (any such link stored here goes).
                    val changed = records.remove(sid) != null
                    meta[sid] = SyncMeta.live(mine, s.vv)
                    return changed
                }
                // Shared from two of this person's devices (re-review wave B, B1). Both keep the other's link (the share
                // page warns); only the winner's is published: the winner republishes its own above, the loser records
                // the peer's vector and relays the winner's link as received, so the two stop.
                val before = records[sid]
                val changed = before == null || digest(before) != digest(incoming)
                records[sid] = incoming
                meta[sid] = if (ownWins(mine, incoming)) SyncMeta.live(mine, bump(s.vv)) else SyncMeta.live(incoming, s.vv)
                return changed
            }
            val before = records[sid]
            val changed = before == null || digest(before) != digest(incoming)
            records[sid] = incoming
            meta[sid] = SyncMeta.live(incoming, s.vv)
            return changed
        }

        fun linkDelete(s: ItemState, at: Long): Boolean {
            val sid = s.itemId
            val cid = sid.substring(LNK.length)
            if (!room(sid)) return false
            val links = shares.links ?: return false
            val link = links[cid]
            if (link != null && rows.containsKey(cid)) {
                // This device speaks for its own share; another device's link of it, if one was stored, is gone.
                val mine = linkWrapper(cid, link) ?: return false
                val changed = records.remove(sid) != null
                meta[sid] = SyncMeta.live(mine, bump(s.vv))
                return changed
            }
            val changed = records.remove(sid) != null
            meta[sid] = SyncMeta.tomb(s.vv, at)
            return changed
        }
    }
}
