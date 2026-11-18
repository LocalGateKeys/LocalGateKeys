package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.RecordException
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.records.Wrapper

/**
 * The share view of the vault for one share group (sub-plan 07 "Storage design"; the Kotlin port of LGKCore
 * `ShareItemStore`, desktop `vault_bridge` "Shared collections" with a share scope). A share run sees only this; [commit]
 * writes what the run changed back into the main store in ONE commit (items, their memberships and the share's own
 * state and meta).
 *
 * What the share view holds ([load]):
 * - only live typed items whose membership (`cm:`) names the collection: never logins, documents (so no attachment
 *   file), licences, collection states, the trash, other items or settings;
 * - each as [ShareView.wrapper]: `collection_ids == [collection]` (this person's other collections stay private),
 *   `revision`, `tags`, `favorite` and `payload.document_ids` left out (each person keeps their own). When only such
 *   local fields changed, the last published `updated_at` is kept (desktop `_view_wrapper`), so it is no share edit;
 * - the share's own sync meta and state ([ShareRecord]), never the personal group's.
 *
 * An item that leaves the collection (untagged or deleted here) becomes a tombstone in the share only: members lose it,
 * this device keeps it. An item that cannot be read is left alone (no state, meta untouched, nothing applied over it).
 * Read-only (a member of a `read` share): a local change (edit, new tagged item, untag, delete) is never published and
 * its meta is left alone; the owner's version replaces it on the next run.
 *
 * What comes in ([ShareProjection.filter], then [commit]):
 * - a live state must be a typed item claiming exactly `[collection]` ([ShareView.checkIncoming]), else `bad-peer-record`
 *   (`update-needed` for a newer schema), and only that state is left out;
 * - it may replace or restore only an item of the collection, or one this share last saw live: an id of a personal item
 *   (live, or in Recently deleted outside the collection) is `bad-peer-record`, and a tombstone for one is recorded in
 *   the share's meta without touching the vault;
 * - an edit of an item this device untagged meanwhile is skipped quietly (the tombstone stays published);
 * - an incoming item lands in the collection with this device's own other collections, tags and favourite (none for a
 *   new item); a remote tombstone takes the item out of the store, which the app's store moves to Recently deleted.
 */
class ShareItemStore(val base: ItemStore, val groupId: String, val trash: ShareTrash) : ItemStore {
    /** The share view (records, the share's meta and state) at the main store's revision. */
    override fun load(): StoreSnapshot = projection().snapshot

    internal fun projection(): ShareProjection = ShareProjection(base.load(), groupId, trash)

    /**
     * Writes a share run's result: `change.records`/`change.meta` are the share view after the run, `change.sync` the
     * share's new state (its group, device, epoch, key and keyring never change here: `bad-state`). Refused
     * (`store-changed`) when the main store moved since `change.baseRevision`, and (`bad-remote`) for anything that would
     * reach outside the collection. `change.shares` is ignored (the share's own record is what changes).
     */
    override fun commit(change: StoreChange) {
        val main = base.load()
        if (main.revision != change.baseRevision) {
            throw ShareGroupException("store-changed", "the vault changed since the share view was taken; sync again")
        }
        base.commit(ShareProjection(main, groupId, trash).mainChange(change))
    }

    override fun toString(): String = "ShareItemStore(group=$groupId)"
}

/** One share group's view of a main store snapshot, and the way back ([ShareItemStore]). */
internal class ShareProjection(val main: StoreSnapshot, val groupId: String, val trash: ShareTrash) {
    val record: ShareRecord = ShareGroups.records(main)[groupId]
        ?: throw ShareGroupException("not-joined", "this vault is not in that share group")
    val collectionId: String = record.collectionId

    /** What the share run sees. */
    val snapshot: StoreSnapshot

    /**
     * Stored share meta the run does not see (unreadable items; read-only local changes): written back unchanged unless
     * the run settled the id.
     */
    val hidden: Map<String, SyncMeta>

    /** Live items of the collection that the share can carry (typed, not a document), readable or not. */
    val tagged: Set<String>

    /** Tagged items that cannot be read: id -> why. */
    val skipped: Map<String, String>

    /** Live items this device took out of the collection (a tombstone in the share): incoming edits skipped quietly. */
    val quiet: Set<String>

    /** Ids no share peer may write (personal items, live or in Recently deleted). */
    val personal: Set<String>

    init {
        val cid = collectionId
        val stored = record.meta
        val records = LinkedHashMap<String, JsonValue>()
        val meta = LinkedHashMap(stored)
        val hidden = LinkedHashMap<String, SyncMeta>()
        val tagged = HashSet<String>()
        val skipped = LinkedHashMap<String, String>()
        val quiet = HashSet<String>()
        val personal = HashSet<String>()
        val items = main.itemRecords
        for ((id, w) in items) {
            if (SyncMeta.nsName(w) != Namespace.ITEM.wire) continue
            val r = ((w as? JsonValue.Obj)?.fields?.get("record") as? JsonValue.Obj)?.fields ?: continue
            val ids = CollectionCatalog.memberships(id, main.records)
            if (cid !in ids) continue
            val withIds = JsonValue.Obj(LinkedHashMap(r).also { it["collection_ids"] = JsonValue.Arr(ids.map { s -> JsonValue.Str(s) }) })
            if (!ShareView.isShared(withIds, cid)) continue // a document never travels
            tagged.add(id)
            if (!Identifier.isValid(id)) {
                skipped[id] = "invalid-id"
                continue
            }
            try {
                records[id] = keepingSyncedTime(ShareView.wrapper(withIds, cid), stored[id])
            } catch (e: Exception) {
                skipped[id] = e.message ?: e.javaClass.simpleName
            }
        }
        for (id in skipped.keys) meta.remove(id)?.let { hidden[id] = it }
        if (record.isReadOnly) {
            // A local change is never published: neither the change (no bump) nor a tombstone. Without its meta the run
            // takes the owner's version as new, which then replaces the local one.
            for ((id, m) in stored) {
                if (meta[id] == null) continue
                val current = records[id]
                val changed = when {
                    m.deleted -> current != null
                    current != null -> (try {
                        SyncMeta.digest(current)
                    } catch (e: Exception) {
                        null
                    }) != m.digest
                    else -> true
                }
                if (changed) {
                    hidden[id] = m
                    meta.remove(id)
                    records.remove(id)
                }
            }
            for (id in records.keys.toList()) if (meta[id] == null) records.remove(id) // new here: never published
        }
        for ((id, w) in items) {
            if (id in tagged) continue
            val m = stored[id]
            if (m != null && (m.deleted || !record.isReadOnly)) {
                // Untagged (or never shareable) here and a tombstone in the share, now or after this run's view.
                quiet.add(id)
                continue
            }
            val restorable = m != null && !m.deleted
            val isItem = SyncMeta.nsName(w) == Namespace.ITEM.wire
            val room = CollectionCatalog.memberships(id, main.records).size < CollectionStates.MAX_MEMBERSHIPS
            if (!(restorable && isItem && room)) personal.add(id)
        }
        for ((id, ids) in trash.collections) {
            if (items[id] != null) continue
            val inCollection = cid in ids
            val restorable = stored[id]?.let { !it.deleted } ?: false
            if (!inCollection && !restorable) personal.add(id)
        }
        this.snapshot = StoreSnapshot(records, meta, record.state, main.revision)
        this.hidden = hidden
        this.tagged = tagged
        this.skipped = skipped
        this.quiet = quiet
        this.personal = personal
    }

    /**
     * The peers' views without what the share must not apply: states of unreadable items (dropped quietly), edits of
     * items untagged here (dropped quietly), live states for personal ids and live states that are not an item of the
     * collection (each reported and left out alone).
     */
    fun filter(views: List<PeerView>): Pair<List<PeerView>, List<SyncIssue>> {
        val issues = ArrayList<SyncIssue>()
        val out = ArrayList<PeerView>()
        for (view in views) {
            val kept = ArrayList<app.localgatekeys.core.engine.ItemState>()
            for (s in view.states) {
                val id = s.itemId
                if (skipped.containsKey(id)) continue
                if (s.deleted) {
                    kept.add(s)
                    continue
                }
                if (id in quiet) continue
                // Every shared item (and every conflict copy) has a canonical uuid id: its membership needs one.
                if (id in personal || !ShareKeyring.isCanonicalUuid(id)) {
                    issues.add(SyncIssue("bad-peer-record", "${view.deviceId}:$id"))
                    continue
                }
                try {
                    ShareView.checkIncoming(s, collectionId)
                } catch (e: RecordException) {
                    issues.add(SyncIssue(if (e.reason == "update-needed") "update-needed" else "bad-peer-record", "${view.deviceId}:$id"))
                    continue
                } catch (e: Exception) {
                    issues.add(SyncIssue("bad-peer-record", "${view.deviceId}:$id"))
                    continue
                }
                kept.add(s)
            }
            out.add(if (kept.size == view.states.size) view else PeerView(view.deviceId, kept))
        }
        return out to issues
    }

    /** The main store change for a share run's result (see [ShareItemStore.commit]). */
    fun mainChange(change: StoreChange): StoreChange {
        val old = record.state
        val state = change.sync
        if (state == null || state.groupId != old.groupId || state.deviceId != old.deviceId || state.identity != old.identity ||
            state.epoch != old.epoch || !state.key.contentEquals(old.key) || !(state.keyring contentEquals old.keyring) ||
            state.installId != old.installId
        ) {
            throw ShareGroupException("bad-state", "a share run cannot change the group, device, key or keyring")
        }
        val cid = collectionId
        val records = LinkedHashMap(main.records)
        val meta = LinkedHashMap(change.meta)
        for ((id, m) in hidden) if (meta[id] == null) meta[id] = m
        // A remote tombstone the run applied: the item leaves the store (the app moves it to Recently deleted).
        for (id in tagged) {
            if (change.records[id] != null || skipped.containsKey(id)) continue
            val shared = snapshot.records[id] != null || hidden[id] != null
            if (shared && change.meta[id]?.deleted == true) {
                records.remove(id)
                records.remove(CollectionStates.MEMBERSHIP_PREFIX + id)
            }
        }
        // Incoming items, changed or new (conflict copies included).
        for ((id, w) in change.records) {
            val before = snapshot.records[id]
            if (before != null && sameJson(before, w)) continue
            if (CollectionStates.isStateId(id) || id in personal || id in quiet || skipped.containsKey(id)) throw badRemote(id)
            val wo = (w as? JsonValue.Obj)?.fields ?: throw badRemote(id)
            if (wo["ns"] != JsonValue.Str(Namespace.ITEM.wire)) throw badRemote(id)
            val r = LinkedHashMap((wo["record"] as? JsonValue.Obj)?.fields ?: throw badRemote(id))
            var local: Map<String, JsonValue>? = null
            var ids = CollectionCatalog.memberships(id, main.records)
            val current = main.records[id]
            if (current != null) {
                if (CollectionStates.isReserved(id, current) || SyncMeta.nsName(current) != Namespace.ITEM.wire) throw badRemote(id)
                local = ((current as? JsonValue.Obj)?.fields?.get("record") as? JsonValue.Obj)?.fields ?: throw badRemote(id)
            } else {
                val deleted = trash.records[id]
                if (deleted != null) {
                    // Back from Recently deleted: this device's own fields and its collections that still exist come back.
                    local = deleted
                    val known = CollectionCatalog.collections(main).map { it.id }.toSet()
                    ids = CollectionCatalog.sortedIds(ids + CollectionCatalog.strings(deleted["collection_ids"]).filter { it in known })
                }
            }
            r.remove("collection_ids")
            r.remove("revision")
            // Tags and favourites are personal: this device's own (none for a new item), never the peer's.
            r["tags"] = local?.get("tags") ?: JsonValue.Arr(emptyList())
            r["favorite"] = local?.get("favorite") ?: JsonValue.Bool(false)
            val payload = (r["payload"] as? JsonValue.Obj)?.fields
            if (payload != null) {
                val p = LinkedHashMap(payload)
                p.remove("document_ids")
                val docs = ((local?.get("payload") as? JsonValue.Obj)?.fields)?.get("document_ids")
                if (docs != null) p["document_ids"] = docs
                r["payload"] = JsonValue.Obj(p)
            }
            records[id] = Wrapper.make(Namespace.ITEM, JsonValue.Obj(r))
            if (cid !in ids) ids = ids + cid
            if (ids.size > CollectionStates.MAX_MEMBERSHIPS) throw badRemote(id)
            val membership = try {
                CollectionCatalog.membershipWrapper(id, ids)
            } catch (e: Exception) {
                null
            } ?: throw badRemote(id)
            records[CollectionStates.MEMBERSHIP_PREFIX + id] = membership
            // What this device publishes for it from now on: when the stored form differs from what the peer sent (a
            // field this device normalises), that is this device's own edit (desktop: `bump` unless stored == remote).
            val shared = LinkedHashMap(r)
            shared["collection_ids"] = JsonValue.Arr(CollectionCatalog.sortedIds(ids).map { JsonValue.Str(it) })
            val m = meta[id]
            if (m != null && !m.deleted) {
                val mine = try {
                    ShareView.wrapper(JsonValue.Obj(shared), cid)
                } catch (e: Exception) {
                    null
                }
                if (mine != null && !sameJson(mine, w)) {
                    // An overflowing counter (only a vector stored before the bounds) leaves the peer's meta: never the run.
                    val vv = SyncMeta.bumped(m.vv, state.deviceId)
                    if (vv != null) meta[id] = SyncMeta.live(mine, vv)
                }
            }
        }
        if (meta.size > SyncMeta.MAX_RECORDS) throw ShareGroupException("bad-state", "share meta exceeds its bound")
        val all = LinkedHashMap(ShareGroups.records(main))
        all[groupId] = record.copy(state = state, meta = meta)
        return StoreChange(main.revision, records, main.meta, main.sync, StoreChange.Shares.Replace(ShareRecord.encode(all)))
    }

    companion object {
        fun badRemote(id: String) = ShareGroupException("bad-remote", "$id: reaches outside the shared collection")

        /** Exact JSON equality: the same canonical bytes (never canonical string equivalence); false when one cannot be encoded. */
        fun sameJson(a: JsonValue, b: JsonValue): Boolean = try {
            CanonicalJson.encode(a, Dialect.UTF8).contentEquals(CanonicalJson.encode(b, Dialect.UTF8))
        } catch (e: Exception) {
            false
        }

        /** The share wrapper with the last published `updated_at` when nothing but local fields changed (desktop `_view_wrapper`). */
        fun keepingSyncedTime(wrapper: JsonValue, m: SyncMeta?): JsonValue {
            if (m == null || m.deleted) return wrapper
            val w = (wrapper as? JsonValue.Obj)?.fields ?: return wrapper
            val r = (w["record"] as? JsonValue.Obj)?.fields ?: return wrapper
            val stamp = (r["updated_at"] as? JsonValue.Int)?.v
            if (stamp == m.updatedAt) return wrapper
            if (SyncMeta.bodyDigest(wrapper) != m.body) return wrapper
            val r2 = LinkedHashMap(r)
            val u = m.updatedAt
            if (u != null) r2["updated_at"] = JsonValue.Int(u) else r2.remove("updated_at")
            val w2 = LinkedHashMap(w)
            w2["record"] = JsonValue.Obj(r2)
            w2["updated_at"] = JsonValue.Int(Wrapper.rank(JsonValue.Obj(r2)))
            return JsonValue.Obj(w2)
        }
    }
}
