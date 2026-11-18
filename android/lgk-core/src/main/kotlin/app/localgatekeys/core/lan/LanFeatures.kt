package app.localgatekeys.core.lan

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange

/**
 * The Wi-Fi `features` message (sub-plan 07 Task 4; desktop `lan_sync`): `{"type":"features","features":[...]}`.
 * After a view exchange an initiator asks a peer what it reads; the peer answers with its own list, or an older app
 * answers `error` / `bad-message` (not capable). Personal collection states go only to peers that listed
 * `collections`. Vectors: `tests/vectors/share/collections/capability.json`.
 *
 * [LanMessages] carries it as [LanMessage.Features]; the phone (an initiator only) asks with [LanClient.exchangeFeatures]
 * (after the view exchange, before the witness exchange) and keeps the answer in
 * [app.localgatekeys.core.sync.SyncGroupState.collectionPeers] ([setPeer]).
 */
object LanFeatures {
    const val COLLECTIONS = "collections"
    const val MAX_FEATURES = 16
    const val MAX_NAME = 32

    /** What this version reads. */
    val OURS: List<String> = listOf(COLLECTIONS)

    /** Most peers kept in `collectionPeers` (desktop `MAX_LAN_PEERS`). */
    const val MAX_PEERS = 16
    private val fields = setOf("type", "features")

    fun encode(features: List<String>): ByteArray = CanonicalJson.encode(
        JsonValue.Obj(mapOf("type" to JsonValue.Str("features"), "features" to JsonValue.Arr(features.map { JsonValue.Str(it) }))),
        Dialect.ASCII,
    )

    /** The features a `features` message lists (desktop `parse_message`): `too-large` or `bad-message` otherwise. */
    fun parse(raw: ByteArray): List<String> {
        if (raw.size > LanTransport.MAX_MESSAGE_BYTES) throw LanSyncException("too-large")
        val o = try {
            (CanonicalJson.parse(raw) as? JsonValue.Obj)?.fields
        } catch (e: JsonException) {
            null
        } ?: throw LanSyncException("bad-message")
        if (o.keys != fields || o["type"] != JsonValue.Str("features")) throw LanSyncException("bad-message")
        return names(o["features"])
    }

    /** The `features` field: a list of at most 16 names of 1..32 code points, else `bad-message`. */
    internal fun names(value: JsonValue?): List<String> {
        val list = (value as? JsonValue.Arr)?.items ?: throw LanSyncException("bad-message")
        if (list.size > MAX_FEATURES) throw LanSyncException("bad-message")
        return list.map { v ->
            val s = (v as? JsonValue.Str)?.v
            if (s == null || Scalars.count(s) !in 1..MAX_NAME) throw LanSyncException("bad-message")
            s
        }
    }

    /** Whether a peer's list names `collections`. */
    fun readsCollections(features: List<String>): Boolean = COLLECTIONS in features

    /** `collectionPeers` with [peer] added or removed (sorted, bounded); null when nothing changes. */
    fun peers(current: List<String>, peer: String, capable: Boolean): List<String>? {
        val set = current.toMutableSet()
        if (capable) {
            if (peer in set || set.size >= MAX_PEERS || !Identifier.isValid(peer)) return null
            set.add(peer)
        } else {
            if (!set.remove(peer)) return null
        }
        return set.sorted()
    }

    /**
     * Records a peer's answer in the group state (desktop `set_collection_peer`): one commit, only when the list changes.
     * True: saved; false: nothing to change; null: not saved (the store could not be read or written, or a new peer past
     * [MAX_PEERS]).
     */
    fun setPeer(peer: String, capable: Boolean, store: ItemStore): Boolean? {
        val snap = try {
            store.load()
        } catch (e: Exception) {
            return null
        }
        val state = snap.sync ?: return null
        if (capable && peer !in state.collectionPeers && (state.collectionPeers.size >= MAX_PEERS || !Identifier.isValid(peer))) return null
        val next = peers(state.collectionPeers, peer, capable) ?: return false
        return try {
            store.commit(StoreChange(snap.revision, snap.records, snap.meta, state.copy(collectionPeers = next)))
            true
        } catch (e: Exception) {
            null
        }
    }
}
