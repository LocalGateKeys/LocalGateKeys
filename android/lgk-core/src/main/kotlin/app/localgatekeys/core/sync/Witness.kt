package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.group.ViewHeader
import app.localgatekeys.core.primitives.Identifier

/** One peer's published generation and witness, from a format-2 view or a witness file (desktop `witness.Observation`). */
data class Observation(val peerId: String, val vaultGeneration: Long, val witness: Map<String, Long> = emptyMap())

/** Desktop `witness.WitnessResult`; [capable]: peer ids that showed format-2 support in this check. */
data class WitnessResult(
    val issues: List<SyncIssue>,
    val peerGenerations: Map<String, Long>,
    val rollbackSuspected: Long,
    val capable: Set<String> = emptySet(),
)

/**
 * Rollback detection through sync peers (desktop `sync/witness.py`, plan 2026-10-22 "Part B update (2026-10-29)").
 * Pure rules, ported one for one:
 *
 * - a peer generation below the remembered one gives `peer-vault-rollback` (detail: the peer id); the remembered
 *   value is never lowered;
 * - a peer's `witness[ownId]` above the own generation raises `rollbackSuspected`, unless it is more than
 *   [MAX_WITNESS_JUMP] above it (`witness-implausible`, never stored);
 * - `rollbackSuspected` is sticky: while it is non-zero every check reports `vault-rollback`. Only the user's explicit
 *   acknowledgement ([acknowledgeVaultRollback]) clears it; there is no automatic acknowledgement after a restore;
 * - a view without a generation (format 1 and no matching witness file) is not checked.
 */
object Witness {
    const val MAX_GENERATION: Long = (1L shl 53) - 1

    /** A witness of this vault more than this far above its own generation is ignored (`witness-implausible`). */
    const val MAX_WITNESS_JUMP: Long = 10_000

    /** Largest witness file (folder `witness/` and LAN `witness` message). */
    const val MAX_WITNESS_BYTES: Int = 16 * 1024

    /** A peer's risen generation is saved at most this often during a session (LAN; seconds). */
    const val SAVE_INTERVAL_SECONDS: Long = 600

    /** Consecutive `bad-view` refusals of a format-2 view that drop a peer's format-2 support. */
    const val FORMAT_REFUSALS_TO_DROP: Int = 2

    fun clamp(generation: Long): Long = generation.coerceIn(0, MAX_GENERATION)

    /**
     * This vault's generation as a header value: the store's committed revision plus the state's
     * [SyncGroupState.generationOffset] (raised only by the acknowledgement). Grows only with committed writes, so a
     * restored copy of the store publishes a lower one.
     */
    fun generation(snapshot: StoreSnapshot): Long? {
        val state = snapshot.sync ?: return null
        val sum = snapshot.revision + state.generationOffset
        return clamp(if (sum < snapshot.revision) MAX_GENERATION else sum)
    }

    /**
     * What a view publishes: its own format-2 header, else the matching [witnessFile], else null. A witness file counts
     * only when it is format 2, holds no records, and names the same group, device, epoch and counter as [view].
     */
    fun observation(view: ViewHeader, witnessFile: Pair<ViewHeader, List<ItemState>>? = null): Observation? {
        if (view.format == ViewFile.FORMAT_WITNESS) return Observation(view.deviceId, view.vaultGeneration!!, view.witness)
        val (w, states) = witnessFile ?: return null
        if (w.format != ViewFile.FORMAT_WITNESS || states.isNotEmpty()) return null
        if (w.groupId != view.groupId || w.deviceId != view.deviceId || w.epoch != view.epoch || w.counter != view.counter) {
            return null
        }
        return Observation(view.deviceId, w.vaultGeneration!!, w.witness)
    }

    /** The rules above; returns the issues and the updated state. */
    fun check(
        ownId: String,
        ownGeneration: Long,
        observations: Iterable<Observation>,
        peerGenerations: Map<String, Long>,
        rollbackSuspected: Long,
    ): WitnessResult {
        val remembered = LinkedHashMap(peerGenerations)
        var suspected = rollbackSuspected
        val issues = ArrayList<SyncIssue>()
        val capable = LinkedHashSet<String>()
        for (obs in observations) {
            if (obs.peerId == ownId) continue
            capable.add(obs.peerId)
            val last = remembered[obs.peerId]
            if (last != null && obs.vaultGeneration < last) {
                issues.add(SyncIssue("peer-vault-rollback", obs.peerId))
            } else {
                remembered[obs.peerId] = obs.vaultGeneration
            }
            val seenOfUs = obs.witness[ownId]
            if (seenOfUs != null && seenOfUs - ownGeneration > MAX_WITNESS_JUMP) {
                // Far above anything this vault could have reached: a forged witness. Reported, never remembered.
                issues.add(SyncIssue("witness-implausible", obs.peerId))
            } else if (seenOfUs != null && seenOfUs > ownGeneration) {
                suspected = maxOf(suspected, seenOfUs)
            }
        }
        if (suspected > 0) issues.add(SyncIssue("vault-rollback", ""))
        return WitnessResult(issues, remembered, suspected, capable)
    }

    /** The witness this device publishes: remembered generations of current members only, at most 64 (sorted by id). */
    fun ownWitness(peerGenerations: Map<String, Long>, members: Iterable<String>, ownId: String): Map<String, Long> {
        val keep = members.filter { it != ownId && Identifier.isValid(it) }.toSet()
        return peerGenerations.filterKeys { it in keep }.mapValues { clamp(it.value) }.toSortedMap().entries
            .take(ViewFile.MAX_WITNESS).associate { it.key to it.value }
    }

    /** [peerGenerations] limited to the ids in [keep], at most 64 entries (sorted by id). */
    fun <V> prune(peerGenerations: Map<String, V>, keep: Set<String>): Map<String, V> =
        peerGenerations.filterKeys { it in keep }.toSortedMap().entries.take(ViewFile.MAX_WITNESS).associate { it.key to it.value }

    /** Sorted [ids] limited to [keep], at most 64. */
    fun pruneIds(ids: Iterable<String>, keep: Set<String>): List<String> =
        ids.filter { it in keep }.toSortedSet().take(ViewFile.MAX_WITNESS)

    /**
     * The user confirmed this vault was restored on purpose (`vault-rollback`, "This was me" after re-authenticating;
     * desktop `vault_bridge.acknowledge_vault_rollback`). Raises the generation above every value a peer witnessed
     * (`rollbackSuspected + 1`) and clears `rollbackSuspected` in the same commit. False (nothing written) when nothing
     * was suspected. Never called automatically.
     */
    fun acknowledgeVaultRollback(store: ItemStore): Boolean {
        val snapshot = store.load()
        val state = snapshot.sync ?: return false
        if (state.rollbackSuspected <= 0) return false
        val floor = minOf(state.rollbackSuspected + 1, MAX_GENERATION)
        val offset = maxOf(state.generationOffset, floor - snapshot.revision)
        store.commit(
            StoreChange(snapshot.revision, snapshot.records, snapshot.meta, state.copy(generationOffset = offset, rollbackSuspected = 0)),
        )
        return true
    }

    /**
     * The user dismissed `peer-vault-rollback` for [peerId]: accept its older copy (desktop `forget_peer_generation`).
     * The value is dropped from the store and from the session's [memory].
     */
    fun forgetPeerGeneration(store: ItemStore, peerId: String, memory: WitnessMemory? = null): Boolean {
        val snapshot = store.load()
        val state = snapshot.sync ?: return false
        memory?.forget(peerId)
        if (peerId !in state.peerGenerations) return false
        store.commit(
            StoreChange(snapshot.revision, snapshot.records, snapshot.meta, state.copy(peerGenerations = state.peerGenerations - peerId)),
        )
        return true
    }

    /** Peers whose generations this device keeps and publishes: keyring members and the paired LAN peer. */
    fun witnessIds(state: SyncGroupState, lanPeers: Iterable<String> = emptyList()): Set<String> =
        (state.members + lanPeers).filter { it != state.deviceId }.toSet()

    /**
     * Check [observations] from a LAN exchange (desktop `lan_sync.apply_witness`) against the session's in-memory
     * generations and return the issues plus the state to commit, or null when nothing worth a save changed: saved on a
     * new peer, a change of `witnessPeers` or `rollbackSuspected`, or a risen generation of a peer not saved in the
     * last [SAVE_INTERVAL_SECONDS]. [dropCapable] removes that peer from `witnessPeers`.
     */
    fun applyLan(
        state: SyncGroupState,
        ownGeneration: Long,
        observations: List<Observation>,
        memory: WitnessMemory?,
        lanPeers: Iterable<String>,
        nowSeconds: Long,
        dropCapable: String? = null,
    ): Pair<List<SyncIssue>, SyncGroupState?> {
        val known = memory?.merged(state) ?: state.peerGenerations
        val checked = check(state.deviceId, ownGeneration, observations, known, state.rollbackSuspected)
        val keep = witnessIds(state, lanPeers)
        val generations = prune(checked.peerGenerations, keep)
        val capable = (state.witnessPeers + checked.capable).toMutableSet()
        if (dropCapable != null) capable.remove(dropCapable)
        val capableList = pruneIds(capable, keep)
        val stored = state.peerGenerations
        memory?.remember(state, generations)
        val risen = generations.filter { (d, g) -> stored[d] != null && g > stored[d]!! }.keys
        val due = memory == null || risen.any { memory.dueForSave(it, nowSeconds) }
        val worth = checked.rollbackSuspected != state.rollbackSuspected || capableList != state.witnessPeers ||
            generations.keys.any { it !in stored } || (risen.isNotEmpty() && due)
        if (!worth) return checked.issues to null
        return checked.issues to state.copy(
            peerGenerations = generations, rollbackSuspected = checked.rollbackSuspected, witnessPeers = capableList,
        )
    }
}

/**
 * In-memory witness state for one unlock session (desktop `witness_memory.WitnessMemory`, 2026-10-29 review fix). The
 * highest generation checked from each peer is kept here for the session and is what every check and every published
 * witness uses; the stored value catches up when a LAN exchange saves (throttled), when a folder run commits, and when
 * [flush] runs at the end of every sync run. Bound to the group and device it was filled for; another starts empty.
 * Thread-safe.
 */
class WitnessMemory {
    private var groupId: String? = null
    private var deviceId: String? = null
    private val generations = HashMap<String, Long>()
    private val savedAt = HashMap<String, Long>()
    private val refusals = HashMap<String, Int>()

    private fun bind(state: SyncGroupState) {
        if (groupId != state.groupId || deviceId != state.deviceId) {
            groupId = state.groupId
            deviceId = state.deviceId
            generations.clear()
            savedAt.clear()
            refusals.clear()
        }
    }

    /** The stored generations of [state] raised to the remembered ones (never lowered). */
    @Synchronized
    fun merged(state: SyncGroupState): Map<String, Long> {
        bind(state)
        val out = LinkedHashMap(state.peerGenerations)
        for ((d, g) in generations) if (g > (out[d] ?: -1)) out[d] = g
        return out
    }

    @Synchronized
    fun remember(state: SyncGroupState, checked: Map<String, Long>) {
        bind(state)
        generations.clear()
        generations.putAll(checked)
    }

    @Synchronized
    internal fun forget(peerId: String) {
        generations.remove(peerId)
    }

    @Synchronized
    fun dueForSave(peerId: String, nowSeconds: Long): Boolean {
        val at = savedAt[peerId] ?: return true
        return nowSeconds - at >= Witness.SAVE_INTERVAL_SECONDS
    }

    /** Every peer in [saved] was just stored. */
    @Synchronized
    fun markSaved(saved: Iterable<String>, nowSeconds: Long) {
        for (d in saved) savedAt[d] = nowSeconds
    }

    /** One more `bad-view` refusal of a format-2 view by [peerId]; returns the count in a row. */
    @Synchronized
    fun refused(state: SyncGroupState, peerId: String): Int {
        bind(state)
        val n = (refusals[peerId] ?: 0) + 1
        refusals[peerId] = n
        return n
    }

    /** A format-2 exchange with [peerId] went through (or its support was dropped): the count starts again. */
    @Synchronized
    fun clearRefusals(peerId: String) {
        refusals.remove(peerId)
    }

    /**
     * Desktop `lan_sync.flush_witness`: the state with every in-memory generation above the stored one, or null when
     * nothing is above it. The caller commits it (before the vault locks) and then calls [markSaved].
     */
    fun flush(state: SyncGroupState, lanPeers: Iterable<String>): SyncGroupState? {
        val generations = Witness.prune(merged(state), Witness.witnessIds(state, lanPeers))
        if (generations == state.peerGenerations) return null
        return state.copy(peerGenerations = generations)
    }

    override fun toString(): String = "WitnessMemory(peers=${generations.size})"
}
