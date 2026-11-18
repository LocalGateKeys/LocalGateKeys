package app.localgatekeys.android.collections

import android.util.Log
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.trash.LocalData
import app.localgatekeys.android.trash.LocalDataHosting
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.core.sync.CollectionCatalogException
import app.localgatekeys.core.sync.CollectionStates
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.ReadOnlyCollectionException
import app.localgatekeys.core.sync.ShareGroups
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.TravelMode
import app.localgatekeys.core.sync.itemRecords
import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * The phone's collections (sub-plan 07 Task 5l, the Kotlin port of the iPhone's `CollectionsModel`), over
 * [CollectionCatalog] and the item store: the list with counts, create, rename, delete (the items stay), the starters
 * and an item's memberships. Collections are free: nothing here checks Pro, and collection states never count toward
 * the free item limit (`ItemLimit` reads [itemRecords]). Starters are only ever added on request ([addStarters]).
 *
 * The never-synced local data ([local]: Recently deleted rows and the starter ids) is read and written under the same
 * lock as Recently deleted (`PhoneTrash`), so neither loses the other's change. Blocking: call every action off the main
 * thread; [state] is safe to collect on main.
 */
class CollectionsModel(
    private val store: ItemStore,
    private val local: LocalDataHosting?,
    private val clock: UnixClock,
    private val t: Txt,
    private val newId: () -> String = { UUID.randomUUID().toString() },
) {
    data class Row(
        val id: String,
        val name: String,
        /** Live items in it. */
        val count: Int,
        /** Shared from one of this person's devices: it cannot be deleted (stop sharing or leave first). */
        val isShared: Boolean,
        /** View only here: it cannot be renamed and its items do not change. */
        val isReadOnly: Boolean,
    )

    data class State(
        val rows: List<Row> = emptyList(),
        /** The catalog as the last [reload] read it (by name). */
        val collections: List<CollectionCatalog.Collection> = emptyList(),
        /** Live item id -> the collection ids it is in (items with none left out). */
        val memberships: Map<String, List<String>> = emptyMap(),
        /** Collections that are view only here (a damaged share store fails closed). */
        val readOnlyIds: Set<String> = emptySet(),
        /** Some of Personal, Work, Travel and Emergency are missing (by name). */
        val missingStarters: Boolean = false,
        /** The last refusal or failure, shown under the list. */
        val message: String? = null,
    ) {
        /** Names only: never the item ids. */
        override fun toString(): String = "State(rows=${rows.size}, missingStarters=$missingStarters, message=${message != null})"
    }

    /**
     * This phone's travel mode (feature pack section 2.3): hidden collections are absent and hidden items are not
     * counted. Set by the screen that owns this model; reload after a change.
     */
    @Volatile var travel: () -> TravelMode.Setting = { TravelMode.Setting.OFF }

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()

    /** Whether the item [itemId] is in a view-only collection, from the last [reload]. */
    fun isReadOnly(itemId: String): Boolean {
        val s = _state.value
        if (s.readOnlyIds.isEmpty()) return false
        return (s.memberships[itemId] ?: emptyList()).any { it in s.readOnlyIds }
    }

    fun clearMessage() = _state.update { it.copy(message = null) }

    // ---- reading ----

    fun reload() {
        val snapshot = try {
            store.load()
        } catch (e: Exception) {
            _state.value = State(message = t.s(R.string.collections_read_failed))
            return
        }
        apply(snapshot, _state.value.message)
    }

    private fun apply(snapshot: StoreSnapshot, message: String?) {
        val setting = try {
            travel()
        } catch (e: Exception) {
            TravelMode.Setting.OFF
        }
        val hiddenItems = TravelMode.hiddenIds(snapshot, setting)
        val counts = counts(snapshot, hiddenItems)
        val readOnly = readOnlyCollectionIds(snapshot)
        val shared = ShareGroups.protectedCollectionIds(snapshot)
        val collections = TravelMode.visibleCollections(CollectionCatalog.collections(snapshot), setting) { it.id }
        val rows = collections.map { c ->
            Row(
                c.id, c.name, counts[c.id] ?: 0,
                isShared = c.id in shared || snapshot.records[CollectionStates.LINK_PREFIX + c.id] != null,
                isReadOnly = c.id in readOnly,
            )
        }
        val missing = try {
            CollectionCatalog.starters(snapshot, now = 0).second.isNotEmpty()
        } catch (e: Exception) {
            false
        }
        _state.value = State(rows, collections, memberships(snapshot), readOnly, missing, message)
    }

    private fun refused(e: Exception): Boolean {
        _state.update { it.copy(message = text(e, t)) }
        return false
    }

    // ---- changes ----

    /** Creates a collection; its id, or null (and a message) when refused. */
    fun create(name: String): String? {
        _state.update { it.copy(message = null) }
        return try {
            val (change, id) = CollectionCatalog.create(name, snapshot = store.load(), now = clock.now, newId = newId)
            store.commit(change)
            reload()
            id
        } catch (e: Exception) {
            refused(e)
            null
        }
    }

    /**
     * Renames a collection; false (and a message) when refused. A view-only collection is never renamed: one this
     * device holds as a member of a read-only share (its own share records; a damaged share store fails closed) is
     * refused here, and one another of this person's devices holds that way is refused by the catalog.
     */
    fun rename(id: String, name: String): Boolean {
        _state.update { it.copy(message = null) }
        return try {
            val snapshot = store.load()
            if (id in readOnlyCollectionIds(snapshot)) {
                _state.update { it.copy(message = t.s(R.string.collections_read_only)) }
                return false
            }
            CollectionCatalog.rename(id, name, snapshot = snapshot, now = clock.now)?.let { store.commit(it) }
            reload()
            true
        } catch (e: CollectionCatalogException) {
            if (e.failure == CollectionCatalog.Failure.SHARED) {
                _state.update { it.copy(message = t.s(R.string.collections_read_only)) }
                false
            } else {
                refused(e)
            }
        } catch (e: Exception) {
            refused(e)
        }
    }

    /**
     * Deletes a collection: its items stay (they leave it), and Recently deleted rows forget it. A shared or view-only
     * collection is refused. The store goes first; a failed local save afterwards only leaves a stale id in a trash row,
     * which a restore drops ([CollectionCatalog.restored] keeps known collections only).
     */
    fun delete(id: String): Boolean {
        _state.update { it.copy(message = null) }
        return try {
            val lock: Any = local ?: this
            synchronized(lock) {
                val snapshot = store.load()
                val data = local?.localData
                val deletion = CollectionCatalog.delete(
                    id, snapshot, data?.trash?.let { rows -> rows.map { it.record() } } ?: emptyList(),
                    ShareGroups.protectedCollectionIds(snapshot),
                )
                // The Recently deleted rows are saved before the store change (as PhoneTrash does), so the item
                // history of the trashed items is kept until they are deleted for good.
                var wrote = false
                if (data != null && local != null) {
                    val wasStarter = id in data.starterCollectionIds
                    val trash = deletion.trash?.let { rows -> rowsWith(data.trash, rows) } ?: data.trash
                    if (deletion.trash != null || wasStarter) {
                        try {
                            local.commitLocalData(data.copy(trash = trash, starterCollectionIds = data.starterCollectionIds - id))
                            wrote = true
                        } catch (e: Exception) {
                            // a stale id in a trash row is dropped by restore; a stale starter id is harmless
                        }
                    }
                }
                try {
                    store.commit(deletion.change)
                } catch (e: Exception) {
                    if (wrote) try { local?.commitLocalData(data!!) } catch (e2: Exception) { /* the rows stay; the items are still live */ }
                    throw e
                }
            }
            reload()
            true
        } catch (e: Exception) {
            refused(e)
        }
    }

    /** Adds the starters that are missing by name (only on request); their ids are kept as starters in the local data. */
    fun addStarters(): Boolean {
        _state.update { it.copy(message = null) }
        return try {
            val (change, ids) = CollectionCatalog.starters(store.load(), now = clock.now, newId = newId)
            if (change != null) {
                store.commit(change)
                if (local != null) {
                    synchronized(local) {
                        val data = local.localData
                        if (data != null) {
                            try {
                                local.commitLocalData(data.copy(starterCollectionIds = data.starterCollectionIds + ids.filter { it !in data.starterCollectionIds }))
                            } catch (e: Exception) {
                                // the collections exist; only the local starter flag is missing
                            }
                        }
                    }
                }
            }
            reload()
            true
        } catch (e: Exception) {
            refused(e)
        }
    }

    /**
     * Sets the collections of the item [itemId] (of [kind]); false (and a message) when refused: a login or a document,
     * more than 20, or an item in a view-only collection (moved neither in nor out).
     */
    fun setMemberships(itemId: String, kind: String, ids: Set<String>): Boolean {
        _state.update { it.copy(message = null) }
        return try {
            val snapshot = store.load()
            CollectionCatalog.setMemberships(itemId, kind, ids.toList(), snapshot, readOnlyCollectionIds(snapshot))?.let { store.commit(it) }
            reload()
            true
        } catch (e: Exception) {
            refused(e)
        }
    }

    override fun toString(): String = "CollectionsModel(${_state.value})"

    companion object {
        private const val TAG = "Collections"

        /** Whether an item of [kind] gets the collection picker: typed items only, never logins or documents. */
        fun offersPicker(kind: String): Boolean = kind !in CollectionCatalog.NON_MEMBER_KINDS

        /** Live items per collection id, in one pass over the store ([skip]: items travel mode hides). */
        fun counts(snapshot: StoreSnapshot, skip: Set<String> = emptySet()): Map<String, Int> {
            val out = HashMap<String, Int>()
            for (id in snapshot.itemRecords.keys) {
                if (snapshot.meta[id]?.deleted == true || id in skip) continue
                for (c in CollectionCatalog.memberships(id, snapshot)) out[c] = (out[c] ?: 0) + 1
            }
            return out
        }

        /** Live item id -> its collection ids (items with none and [skip]ped ones left out). */
        fun memberships(snapshot: StoreSnapshot, skip: Set<String> = emptySet()): Map<String, List<String>> {
            val out = HashMap<String, List<String>>()
            for (id in snapshot.itemRecords.keys) {
                if (snapshot.meta[id]?.deleted == true || id in skip) continue
                val ids = CollectionCatalog.memberships(id, snapshot)
                if (ids.isNotEmpty()) out[id] = ids
            }
            return out
        }

        /**
         * Collections this vault may not change: those it holds as a member of a view-only share (a damaged share store
         * fails closed) and those another of this person's devices holds that way (`csl:` links).
         */
        fun readOnlyCollectionIds(snapshot: StoreSnapshot): Set<String> =
            ShareGroups.readOnlyCollectionIds(snapshot) + CollectionCatalog.linkedReadOnlyIds(snapshot)

        /** Whether the item [itemId] is in a view-only collection: it is neither edited, deleted nor moved here. */
        fun itemIsReadOnly(itemId: String, snapshot: StoreSnapshot): Boolean {
            val readOnly = readOnlyCollectionIds(snapshot)
            if (readOnly.isEmpty()) return false
            return CollectionCatalog.memberships(itemId, snapshot).any { it in readOnly }
        }

        /** The line shown for a refused collection change. */
        fun text(error: Throwable, t: Txt): String {
            if (error is ReadOnlyCollectionException) return t.s(R.string.collections_read_only)
            val failure = (error as? CollectionCatalogException)?.failure ?: return t.s(R.string.collections_failed)
            return t.s(
                when (failure) {
                    CollectionCatalog.Failure.LIMIT -> R.string.collections_limit
                    CollectionCatalog.Failure.EMPTY_NAME -> R.string.collections_empty_name
                    CollectionCatalog.Failure.LONG_NAME -> R.string.collections_long_name
                    CollectionCatalog.Failure.DUPLICATE_NAME -> R.string.collections_duplicate
                    CollectionCatalog.Failure.TOO_MANY -> R.string.collections_too_many
                    CollectionCatalog.Failure.INVALID_TEXT -> R.string.collections_bad_name
                    CollectionCatalog.Failure.NOT_FOUND -> R.string.collections_gone
                    CollectionCatalog.Failure.NOT_MEMBER -> R.string.collections_not_member
                    CollectionCatalog.Failure.SHARED -> R.string.collections_shared_delete
                    CollectionCatalog.Failure.LONG_DESCRIPTION, CollectionCatalog.Failure.INVALID_ID,
                    CollectionCatalog.Failure.UNKNOWN_COLLECTION, CollectionCatalog.Failure.RESERVED,
                    -> R.string.collections_failed
                },
            )
        }

        /**
         * Moves collections kept in the local data (`extra["collections"]`/`extra["memberships"]`; this phone never
         * wrote any, but the migration runs as on the Mac) into the store, once, on unlock. The store commit carries
         * the "migration done" marker ([StoreSnapshot.collectionsMigrated]) and then the local copy is saved without
         * them, so no later unlock moves anything again. Once the marker is there the store is never merged into again:
         * a local copy that still holds the old collections (the save failed, or the app quit first) is only cleared,
         * so a collection deleted meanwhile stays deleted. Nothing to move writes no marker. A failure is logged and
         * retried at the next unlock. True when something moved. Blocking.
         */
        fun migrate(store: ItemStore, local: LocalDataHosting): Boolean = try {
            synchronized(local) { migrateLocked(store, local) }
        } catch (e: Exception) {
            Log.w(TAG, "collections could not be moved into the vault: " + e.javaClass.simpleName)
            false
        }

        private fun migrateLocked(store: ItemStore, local: LocalDataHosting): Boolean {
            val data = local.localData ?: return false
            if (!data.hasLegacyCollections) return false
            val snapshot = store.load()
            val m = CollectionCatalog.migrate(
                data.legacyCollections(), data.legacyMemberships(), data.trash.map { it.record() }, data.starterCollectionIds, snapshot,
            )
            val cleared = if (m == null) {
                data.withoutLegacyCollections()
            } else {
                data.withoutLegacyCollections().copy(trash = rowsWith(data.trash, m.trash), starterCollectionIds = m.starterIds)
            }
            if (m == null || snapshot.collectionsMigrated) {
                // Nothing to move, or moved before: only the local copy is cleared.
                local.commitLocalData(cleared)
                return false
            }
            val change = m.change ?: StoreChange(snapshot.revision, snapshot.records, snapshot.meta, snapshot.sync)
            store.commit(change.copy(collectionsMigrated = true))
            local.commitLocalData(cleared)
            return true
        }

        /** [rows] with each record replaced by [records] (same order and length); an unchanged record keeps its row. */
        private fun rowsWith(rows: List<LocalData.TrashRow>, records: List<JsonValue>): List<LocalData.TrashRow> =
            rows.mapIndexed { i, row ->
                val r = records.getOrNull(i) ?: return@mapIndexed row
                val same = try { row.record() == r } catch (e: Exception) { false }
                if (same) row else LocalData.TrashRow.of(r, row.deletedAt)
            }
    }
}
