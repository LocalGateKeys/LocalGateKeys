package app.localgatekeys.core.engine

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.Identifier
import java.security.MessageDigest

data class MergeOutcome(
    val upserts: List<ItemState>,
    val deletes: List<ItemState>,
    /** (local, remote) pairs. */
    val conflicts: List<Pair<ItemState, ItemState>>,
    /** Conflict copies not already held locally or in the remote batch. */
    val copies: List<ItemState>,
)

/** A peer's states, as decoded from its view. */
data class PeerView(val deviceId: String, val states: List<ItemState>)

/** A peer record left out of a fold: [reason] is what the record check returned. */
data class FoldQuarantine(val device: String, val item: String, val reason: String)

data class FoldResult(
    /** Combined outcome against the original local map (sorted by id within each list). */
    val outcome: MergeOutcome,
    /** Peer records removed and reported once each. */
    val quarantined: List<FoldQuarantine>,
    /** Device ids of views dropped as a whole (`"?"` for an invalid device id). */
    val badViews: List<String>,
)

/** Pure version-vector merge engine; mirrors `localvault.sync.engine` and `runner.run_merge`. */
object Engine {
    internal fun sha256Hex(v: JsonValue): String =
        Hex.lower(MessageDigest.getInstance("SHA-256").digest(CanonicalJson.encode(v, Dialect.UTF8)))

    private fun canonical(v: JsonValue): ByteArray = CanonicalJson.encode(v, Dialect.UTF8)

    private fun identical(a: ItemState, b: ItemState): Boolean {
        if (a.deleted || b.deleted) return a.deleted && b.deleted
        return canonical(a.item!!).contentEquals(canonical(b.item!!))
    }

    private fun updatedAt(item: JsonValue): Long {
        val n = (item as? JsonValue.Obj)?.fields?.get("updated_at") as? JsonValue.Int ?: return 0L
        return if (n.v in 0..VersionVector.MAX_COUNTER) n.v else 0L
    }

    /** True when [r] outranks [l]: larger updated_at, then larger sha256 hex of the canonical item. */
    private fun outranks(r: ItemState, l: ItemState): Boolean {
        val ur = updatedAt(r.item!!)
        val ul = updatedAt(l.item!!)
        if (ur != ul) return ur > ul
        return sha256Hex(r.item) > sha256Hex(l.item)
    }

    /** Decide what to apply locally given remote states. Pure and order-independent. */
    fun merge(local: Map<String, ItemState>, remote: List<ItemState>): MergeOutcome {
        for ((key, st) in local) {
            if (st.itemId != key) throw EngineException("local state keyed $key is inconsistent")
        }
        val seen = HashSet<String>()
        for (r in remote) {
            if (!seen.add(r.itemId)) throw EngineException("duplicate remote item id: ${r.itemId}")
        }
        val upserts = ArrayList<ItemState>()
        val deletes = ArrayList<ItemState>()
        val copies = ArrayList<ItemState>()
        val conflicts = ArrayList<Pair<ItemState, ItemState>>()

        // Ids are ASCII, so String ordering equals Python's code point ordering.
        for (r in remote.sortedBy { it.itemId }) {
            val loc = local[r.itemId]
            if (loc == null) {
                if (r.deleted) deletes.add(r) else upserts.add(r)
                continue
            }
            val rel = VersionVector.compare(loc.vv, r.vv)
            if (rel == VersionVector.Relation.A) continue
            if (rel == VersionVector.Relation.B) {
                if (r.deleted) deletes.add(r) else upserts.add(r)
                continue
            }
            val merged = VersionVector.max(loc.vv, r.vv)
            if (loc.deleted && r.deleted) {
                val at = listOfNotNull(loc.deletedAt, r.deletedAt).maxOrNull()
                if (rel != VersionVector.Relation.EQUAL || at != loc.deletedAt) deletes.add(r.with(merged, at))
                continue
            }
            val same = identical(loc, r)
            if (rel == VersionVector.Relation.EQUAL && same) continue
            if (same) {
                upserts.add(r.with(merged, null))
            } else if (loc.deleted || r.deleted) {
                val live = if (r.deleted) loc else r
                upserts.add(live.with(merged, null))
                conflicts.add(loc to r)
            } else {
                val (win, lose) = if (outranks(r, loc)) r to loc else loc to r
                upserts.add(win.with(merged, null))
                val cid = ConflictCopy.id(r.itemId, ConflictCopy.contentDigest(lose.item!!))
                if (local[cid] == null && cid !in seen) {
                    val body = (lose.item as? JsonValue.Obj) ?: throw EngineException("item must be a dict")
                    copies.add(ItemState(cid, lose.vv, false, null, JsonValue.Obj(body.fields + ("id" to JsonValue.Str(cid)))))
                }
                conflicts.add(loc to r)
            }
        }
        return MergeOutcome(upserts, deletes, conflicts, copies)
    }

    /**
     * Merge peer views one after another into [local], mirroring desktop `runner.run_merge`.
     *
     * Views are merged in device-id order (stable). A conflict copy made earlier in the fold that a
     * later view carries is replaced by that view's version before it merges. A view the engine
     * rejects is dropped (`badViews`). [check] plays the vault bridge's role: a non-null reason for a
     * changed state quarantines the peer record that caused it (or drops the view when the same
     * record fails again) and the fold restarts without it. Views from [ownDeviceId] are ignored.
     */
    fun fold(
        local: Map<String, ItemState>,
        views: List<PeerView>,
        ownDeviceId: String? = null,
        check: (ItemState) -> String? = { null },
    ): FoldResult {
        val bad = ArrayList<String>()
        var peers = ArrayList<PeerView>()
        for (v in views) {
            if (!Identifier.isValid(v.deviceId)) bad.add("?") else if (v.deviceId != ownDeviceId) peers.add(v)
        }
        peers = ArrayList(peers.sortedBy { it.deviceId }) // stable

        val quarantined = ArrayList<FoldQuarantine>()
        val seenQuarantine = HashSet<Pair<String, String>>()
        while (true) {
            val combined = combine(local, peers, bad)
            peers = ArrayList(combined.used)
            val outcome = combined.outcome
            var failing: Pair<ItemState, String>? = null
            for (s in outcome.upserts + outcome.deletes + outcome.copies) {
                val r = check(s)
                if (r != null) {
                    failing = s to r
                    break
                }
            }
            val origin = failing?.let { combined.origin[it.first.itemId] }
            if (failing == null || origin == null) return FoldResult(outcome, quarantined, bad)
            val (dev, recordId) = origin
            val reason = failing.second
            var removed = false
            peers = ArrayList(
                peers.map { v ->
                    if (v.deviceId != dev) {
                        v
                    } else {
                        val kept = v.states.filter { it.itemId != recordId }
                        if (kept.size != v.states.size) removed = true
                        PeerView(v.deviceId, kept)
                    }
                },
            )
            if (removed && seenQuarantine.add(dev to recordId)) {
                quarantined.add(FoldQuarantine(dev, recordId, reason))
            } else {
                bad.add(dev)
                peers.removeAll { it.deviceId == dev }
            }
        }
    }

    private class Combined(val outcome: MergeOutcome, val origin: Map<String, Pair<String, String>>, val used: List<PeerView>)

    private fun combine(local: Map<String, ItemState>, views: List<PeerView>, bad: MutableList<String>): Combined {
        var working: Map<String, ItemState> = local
        var pending: Set<String> = emptySet()
        val origin = HashMap<String, Pair<String, String>>()
        val conflicts = ArrayList<Pair<ItemState, ItemState>>()
        val used = ArrayList<PeerView>()
        for (view in views) {
            val dev = view.deviceId
            val trial = HashMap(working)
            val trialPending = HashSet(pending)
            for (id in view.states.map { it.itemId }.toSet().intersect(trialPending)) {
                trial.remove(id)
                trialPending.remove(id)
            }
            val out: MergeOutcome
            val copyCause = HashMap<String, String>()
            try {
                out = merge(trial, view.states)
                for ((loc, remote) in out.conflicts) {
                    for (side in listOf(loc, remote)) {
                        val item = side.item
                        if (item != null) {
                            copyCause[ConflictCopy.id(remote.itemId, ConflictCopy.contentDigest(item))] = remote.itemId
                        }
                    }
                }
            } catch (e: EngineException) {
                bad.add(dev)
                continue
            } catch (e: JsonException) {
                bad.add(dev)
                continue
            }
            for (s in out.upserts + out.deletes) {
                trial[s.itemId] = s
                trialPending.remove(s.itemId)
                origin[s.itemId] = dev to s.itemId
            }
            for (s in out.copies) {
                trial[s.itemId] = s
                trialPending.add(s.itemId)
                origin[s.itemId] = dev to (copyCause[s.itemId] ?: s.itemId)
            }
            working = trial
            pending = trialPending
            conflicts.addAll(out.conflicts)
            used.add(view)
        }
        val upserts = ArrayList<ItemState>()
        val deletes = ArrayList<ItemState>()
        val copies = ArrayList<ItemState>()
        for (id in working.keys.sorted()) {
            val s = working.getValue(id)
            if (local[id] == s) continue
            if (id in pending) copies.add(s) else if (s.deleted) deletes.add(s) else upserts.add(s)
        }
        return Combined(MergeOutcome(upserts, deletes, conflicts, copies), origin, used)
    }
}
