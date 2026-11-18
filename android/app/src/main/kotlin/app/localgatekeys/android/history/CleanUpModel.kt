package app.localgatekeys.android.history

import app.localgatekeys.android.collections.CollectionsModel
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.trash.PhoneTrash
import app.localgatekeys.core.history.ItemHistory
import app.localgatekeys.core.hygiene.Hygiene
import app.localgatekeys.core.hygiene.MergeException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.TravelMode
import app.localgatekeys.core.sync.itemRecords
import java.time.LocalDate

/**
 * The clean-up sweep (contract section 3): findings on demand (no network, never stored; travel-hidden items left
 * out), confirmed merges (the other copy to Recently deleted, both versions in history as `merge`) and deletes. Free:
 * one pair or one item at a time. Pro (`hygiene_bulk`): many deletes, "merge all same login", and Undo of the last bulk
 * action (in-memory journal, until lock or the next bulk action).
 */
class CleanUpModel(
    private val store: ItemStore,
    private val trash: PhoneTrash?,
    private val clock: UnixClock,
    private val isPro: () -> Boolean,
    private val baseDomainOf: (String) -> String,
    private val travel: () -> TravelMode.Setting = { TravelMode.Setting.OFF },
) {
    sealed class Result {
        object Done : Result()
        object NeedsPro : Result()
        data class Refused(val code: String) : Result()
        object Failed : Result()
    }

    /** One bulk action to undo: keepers' wrappers before the merge (and the digest the merge wrote), trashed ids. */
    private data class Journal(val keepers: Map<String, Pair<JsonValue, String>>, val trashed: List<String>)

    private var journal: Journal? = null

    val canUndo: Boolean get() = journal != null

    /** The live records the sweep reads (entries and typed items, not hidden by travel mode). */
    fun records(snap: StoreSnapshot): List<Map<String, JsonValue>> {
        val hidden = TravelMode.hiddenIds(snap, travel())
        return snap.itemRecords.mapNotNull { (id, w) ->
            if (snap.meta[id]?.deleted == true || id in hidden) return@mapNotNull null
            val f = (w as? JsonValue.Obj)?.fields ?: return@mapNotNull null
            val ns = (f["ns"] as? JsonValue.Str)?.v
            if (ns != Namespace.ENTRY.wire && ns != Namespace.ITEM.wire) return@mapNotNull null
            val r = (f["record"] as? JsonValue.Obj)?.fields ?: return@mapNotNull null
            if (r["id"] == null) r + ("id" to JsonValue.Str(id)) else r
        }
    }

    fun findings(snap: StoreSnapshot = store.load(), today: LocalDate = LocalDate.now()): List<Hygiene.Finding> =
        Hygiene.findings(records(snap), clock.now, today, baseDomainOf)

    private fun mergeOne(keeperId: String, otherId: String, keepers: MutableMap<String, Pair<JsonValue, String>>, trashed: MutableList<String>): Result {
        val snap = store.load()
        val kw = (snap.records[keeperId] as? JsonValue.Obj)?.fields
        val ow = (snap.records[otherId] as? JsonValue.Obj)?.fields
        val kr = (kw?.get("record") as? JsonValue.Obj)?.fields
        val or = (ow?.get("record") as? JsonValue.Obj)?.fields
        val ns = (kw?.get("ns") as? JsonValue.Str)?.v?.let { Namespace.fromWire(it) }
        if (kr == null || or == null || ns == null || kw["ns"] != ow["ns"]) return Result.Failed
        if (CollectionsModel.itemIsReadOnly(keeperId, snap) || CollectionsModel.itemIsReadOnly(otherId, snap)) return Result.Refused("read_only")
        val merged = try {
            Hygiene.merge(kr, or, clock.now)
        } catch (e: MergeException) {
            return Result.Refused(e.code)
        }
        val wrapper = Wrapper.make(ns, JsonValue.Obj(merged))
        val records = LinkedHashMap(snap.records)
        records[keeperId] = wrapper
        val deleted = CommitOrigin.with("merge") {
            store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
            try {
                PhoneTrash.deleteItem(otherId, store, clock, trash)
            } catch (e: Exception) {
                SaveResult.FAILED
            }
        }
        if (deleted != SaveResult.SAVED) {
            // The other copy could not go to Recently deleted: the keeper goes back (unless it changed since), so a
            // failure never leaves both copies with the keeper already merged (scan A-L8).
            runCatching { revert(mapOf(keeperId to (JsonValue.Obj(kw) to ItemHistory.digest(wrapper)))) }
            return Result.Failed
        }
        // The version before the first merge, with the digest of the last one (a keeper merged twice still reverts; scan A-L3).
        keepers[keeperId] = (keepers[keeperId]?.first ?: JsonValue.Obj(kw)) to ItemHistory.digest(wrapper)
        trashed.add(otherId)
        return Result.Done
    }

    /** Merges [otherId] into [keeperId] (one pair: Free). */
    fun merge(keeperId: String, otherId: String): Result = try {
        mergeOne(keeperId, otherId, LinkedHashMap(), ArrayList())
    } catch (e: Exception) {
        Result.Failed
    }

    /** Deletes [ids] to Recently deleted; more than one needs Pro (and can be undone). */
    fun delete(ids: List<String>): Result = try {
        if (ids.size > 1 && !isPro()) {
            Result.NeedsPro
        } else {
            val done = ArrayList<String>()
            for (id in ids) if (PhoneTrash.deleteItem(id, store, clock, trash) == SaveResult.SAVED) done.add(id)
            if (ids.size > 1) journal = Journal(emptyMap(), done)
            if (done.isEmpty()) Result.Failed else Result.Done
        }
    } catch (e: Exception) {
        Result.Failed
    }

    /** Pro: merges every `same_login` group into its newest login (the finding's first id). */
    fun mergeAllSameLogin(): Result = try {
        if (!isPro()) {
            Result.NeedsPro
        } else {
            val keepers = LinkedHashMap<String, Pair<JsonValue, String>>()
            val trashed = ArrayList<String>()
            var last: Result = Result.Done
            for (f in findings().filter { it.type == Hygiene.SAME_LOGIN }) {
                for (other in f.ids.drop(1)) {
                    val r = mergeOne(f.ids.first(), other, keepers, trashed)
                    if (r != Result.Done) last = r
                }
            }
            journal = Journal(keepers, trashed)
            last
        }
    } catch (e: Exception) {
        Result.Failed
    }

    /** Undoes the last bulk action: trashed ids come back; a keeper reverts only if nobody changed it since. */
    fun undo(): Result = try {
        val j = journal ?: return Result.Failed
        journal = null
        val t = trash ?: return Result.Failed
        for (id in j.trashed) {
            val row = t.rows.value.firstOrNull { it.itemId == id } ?: continue
            t.restore(row.id, isPro())
        }
        if (j.keepers.isNotEmpty()) revert(j.keepers)
        Result.Done
    } catch (e: Exception) {
        Result.Failed
    }

    /**
     * Puts each keeper's version from before the merge back, only if its digest still equals what the merge wrote. The
     * reverted record gets `updated_at = now`, so other devices take the revert instead of keeping the newer merge
     * (scan A-L9; the contract's rule for import undo).
     */
    private fun revert(keepers: Map<String, Pair<JsonValue, String>>) {
        val snap = store.load()
        val records = LinkedHashMap(snap.records)
        var changed = false
        for ((id, pair) in keepers) {
            val current = snap.records[id] ?: continue
            if (ItemHistory.digest(current) != pair.second) continue
            records[id] = restamped(pair.first, clock.now) ?: continue
            changed = true
        }
        if (changed) CommitOrigin.with("restore") { store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync)) }
    }

    companion object {
        /** [wrapper] with its record's `updated_at` set to [now]; null when it is not a record wrapper. */
        internal fun restamped(wrapper: JsonValue, now: Long): JsonValue? {
            val w = (wrapper as? JsonValue.Obj)?.fields ?: return null
            val ns = (w["ns"] as? JsonValue.Str)?.v?.let { Namespace.fromWire(it) } ?: return null
            val r = (w["record"] as? JsonValue.Obj)?.fields ?: return null
            val made = Wrapper.make(ns, JsonValue.Obj(LinkedHashMap(r).apply { put("updated_at", JsonValue.Int(now)) })) as JsonValue.Obj
            // Other wrapper fields (a document's file reference) are kept.
            return JsonValue.Obj(LinkedHashMap(w).apply { putAll(made.fields) })
        }
    }

    /** Lock: the journal goes. */
    fun clear() {
        journal = null
    }
}
