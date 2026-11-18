package app.localgatekeys.android.vault

import app.localgatekeys.android.R
import app.localgatekeys.android.collections.CollectionsModel
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.NormaliseException
import app.localgatekeys.core.records.PasswordHistory
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.TravelMode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * What the vault and search screens show: the decoded live items of the store, the query and the type filter. [onLoad]
 * gets every snapshot loaded (on the loading thread): Pro re-reads the synced licence states from it.
 */
class VaultListModel(private val store: ItemStore, private val t: Txt, private val onLoad: (StoreSnapshot) -> Unit = {}) {
    val query = MutableStateFlow("")
    val filter = MutableStateFlow<VaultFilter>(VaultFilter.All)

    private val _sort = MutableStateFlow(VaultSort())
    /** The plain list's order (a search keeps relevance order). Saved through [useSettings]. */
    val sort: StateFlow<VaultSort> = _sort.asStateFlow()
    private var settings: AppSettings? = null

    private val _items = MutableStateFlow<List<VaultItem>>(emptyList())
    val items: StateFlow<List<VaultItem>> = _items.asStateFlow()

    private val _collectionFilter = MutableStateFlow<String?>(null)

    /**
     * The Vault list's Collections filter (sub-plan 07; this phone only, never synced): a collection id, or null for All
     * items (the default). Saved through [useSettings]; a collection that no longer exists falls back to All items at
     * the next reload.
     */
    val collectionFilter: StateFlow<String?> = _collectionFilter.asStateFlow()

    private val _collections = MutableStateFlow<List<CollectionCatalog.Collection>>(emptyList())

    /** The collections, by name (the filter menu). */
    val collections: StateFlow<List<CollectionCatalog.Collection>> = _collections.asStateFlow()

    private val _collectionItemIds = MutableStateFlow<Set<String>?>(null)

    /** The live items in the chosen collection; null with no filter. */
    val collectionItemIds: StateFlow<Set<String>?> = _collectionItemIds.asStateFlow()

    /** The chosen collection's name, null with no filter. */
    val collectionFilterName: String?
        get() = _collectionFilter.value?.let { id -> _collections.value.firstOrNull { it.id == id }?.name }

    /** Chooses a collection (null: All items) and saves the choice. Reads the last loaded snapshot only. */
    fun setCollectionFilter(id: String?) {
        _collectionFilter.value = id
        settings?.vaultCollection = id
        updateCollectionItems(snapshot)
    }

    private fun updateCollectionItems(snap: StoreSnapshot?) {
        val id = _collectionFilter.value
        _collectionItemIds.value = if (id == null || snap == null) null else CollectionCatalog.items(id, snap).toSet()
    }

    /**
     * This vault's travel mode (contract section 2.3): its hidden items are left out of the list and the search. Set
     * once the unlock's local data is open; reload after a change.
     */
    @Volatile var travel: () -> TravelMode.Setting = { TravelMode.Setting.OFF }

    private val _loadError = MutableStateFlow<String?>(null)
    val loadError: StateFlow<String?> = _loadError.asStateFlow()

    /** Live synced items, for the free plan's limit. */
    private val _liveCount = MutableStateFlow(0)
    val liveCount: StateFlow<Int> = _liveCount.asStateFlow()

    // Loads run one at a time and each applies its result before the next starts, so a slow older load can never
    // overwrite a newer one: the last load to run is the freshest.
    private val loadLock = Any()

    @Volatile
    var snapshot: StoreSnapshot? = null
        private set

    private val _loads = MutableStateFlow(0)
    /** Counts the loads that worked (each one, even when the list came out the same). */
    val loads: StateFlow<Int> = _loads.asStateFlow()

    private val _recentSearches = MutableStateFlow<List<String>>(emptyList())
    /**
     * The last searches of this unlock (newest first, at most [RECENT_SEARCH_LIMIT]), shown while the search field is
     * empty. Memory only: a lock drops them with the model, as on the iPhone.
     */
    val recentSearches: StateFlow<List<String>> = _recentSearches.asStateFlow()

    /** Remembers the current query as a recent search (Return, or the search closing on an item search). */
    fun noteSearch() {
        _recentSearches.value = remember(query.value, _recentSearches.value)
    }

    val visibleItems: List<VaultItem> get() = visible(_items.value, query.value, filter.value, _sort.value, t)

    /** The Vault list's items: all of them, or those in the chosen collection. */
    val listItems: List<VaultItem> get() = inCollection(_items.value, _collectionItemIds.value)
    val filterOptions: List<VaultFilter> get() = VaultSearch.filterOptions(_items.value, t)

    /** Reads the saved sort and saves every later [setSort] there (per phone, not synced). */
    fun useSettings(settings: AppSettings) {
        this.settings = settings
        _sort.value = settings.vaultSort
        _collectionFilter.value = settings.vaultCollection
        updateCollectionItems(snapshot)
    }

    fun setSort(sort: VaultSort) {
        _sort.value = sort
        settings?.vaultSort = sort
    }

    /**
     * Marks or unmarks [id] as a favorite and bumps `updated_at`, through the editor's save path (core `Normalise`,
     * `Wrapper.make`, store commit), so it syncs like any edit. Reads and writes the store: call off the main thread,
     * and reload (and tell sync) after [SaveResult.SAVED].
     */
    fun setFavorite(id: String, favorite: Boolean, clock: UnixClock): SaveResult = setFavorite(store, id, favorite, clock)

    /** Reads the store (decrypts it: call off the main thread). A failure keeps the old list and sets [loadError]. */
    fun reload() {
        synchronized(loadLock) { loadLocked() }
    }

    private fun loadLocked() {
        try {
            val snap = store.load()
            val setting = travel()
            val hidden = TravelMode.hiddenIds(snap, setting)
            val decoded = VaultItem.items(snap).let { all -> if (hidden.isEmpty()) all else all.filter { it.id !in hidden } }
            snapshot = snap
            _collections.value = TravelMode.visibleCollections(CollectionCatalog.collections(snap), setting) { it.id }
            val chosen = _collectionFilter.value
            if (chosen != null && _collections.value.none { it.id == chosen }) {
                _collectionFilter.value = null
                settings?.vaultCollection = null
            }
            updateCollectionItems(snap)
            _items.value = decoded
            _liveCount.value = ItemLimit.liveCount(snap)
            _loadError.value = null
            onLoad(snap)
            _loads.value++
            if (filter.value !in VaultSearch.filterOptions(decoded, t)) filter.value = VaultFilter.All
        } catch (_: Exception) {
            _loadError.value = t.s(R.string.vault_load_error)
        }
    }

    companion object {
        const val RECENT_SEARCH_LIMIT = 5
        const val RECENT_ITEM_LIMIT = 5

        /** [items] in the chosen collection ([ids]); all of them when no collection is chosen. */
        fun inCollection(items: List<VaultItem>, ids: Set<String>?): List<VaultItem> =
            if (ids == null) items else items.filter { it.id in ids }

        /** [query] (trimmed) first, case-insensitive duplicates dropped, at most [RECENT_SEARCH_LIMIT]; `>` queries never. */
        fun remember(query: String, list: List<String>): List<String> {
            val q = query.trim()
            if (q.isEmpty() || SearchCommand.isCommandQuery(q)) return list
            val rest = list.filterNot { it.equals(q, ignoreCase = true) }
            return (listOf(q) + rest).take(RECENT_SEARCH_LIMIT)
        }

        /** The most recently changed items (newest first, then by id), shown under the recent searches. */
        fun recentItems(items: List<VaultItem>): List<VaultItem> =
            items.sortedWith(compareByDescending<VaultItem> { it.updatedAt }.thenByDescending { it.id }).take(RECENT_ITEM_LIMIT)

        /** The search tab's list: relevance order for a query, else the chosen [sort]. */
        fun visible(items: List<VaultItem>, query: String, filter: VaultFilter, sort: VaultSort, t: Txt): List<VaultItem> =
            if (VaultSearch.parse(query).isEmpty()) sort.apply(items.filter { filter.matches(it) })
            else VaultSearch.apply(items, query, filter, t)

        /**
         * "Restore this password" on a login's history entry [index] (workstream 8): that password is current again and
         * the one it replaces goes into the history. FAILED when the item is gone, not a login, or [index] is stale.
         */
        fun restorePassword(store: ItemStore, id: String, index: Int, clock: UnixClock): SaveResult = try {
            val snap = store.load()
            val wrapper = snap.records[id] as? JsonValue.Obj
            val ns = (wrapper?.fields?.get("ns") as? JsonValue.Str)?.v?.let { Namespace.fromWire(it) }
            val record = (wrapper?.fields?.get("record") as? JsonValue.Obj)?.fields
            val restored = if (snap.meta[id]?.deleted == true || ns != Namespace.ENTRY || record == null) null
            else if (CollectionsModel.itemIsReadOnly(id, snap)) null
            else PasswordHistory.restore(record, index, clock.now)
            if (restored == null) {
                SaveResult.FAILED
            } else {
                val stamped = LinkedHashMap(restored)
                stamped["updated_at"] = JsonValue.Int(clock.now)
                val records = LinkedHashMap(snap.records)
                records[id] = Wrapper.make(ns!!, Normalise.normalForm(ns, JsonValue.Obj(stamped)))
                store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
                SaveResult.SAVED
            }
        } catch (_: Exception) {
            SaveResult.FAILED
        }

        /** [VaultListModel.setFavorite] over any store. */
        fun setFavorite(store: ItemStore, id: String, favorite: Boolean, clock: UnixClock): SaveResult = try {
            val snap = store.load()
            val wrapper = snap.records[id] as? JsonValue.Obj
            val ns = (wrapper?.fields?.get("ns") as? JsonValue.Str)?.v?.let { Namespace.fromWire(it) }
            val record = wrapper?.fields?.get("record") as? JsonValue.Obj
            when {
                snap.meta[id]?.deleted == true || ns == null || ns == Namespace.LICENSE || ns == Namespace.HEIR || record == null -> SaveResult.FAILED
                // A view-only shared item never changes here (sub-plan 07).
                CollectionsModel.itemIsReadOnly(id, snap) -> SaveResult.INVALID
                record.fields["favorite"] == JsonValue.Bool(favorite) -> SaveResult.UNCHANGED
                else -> {
                    val stamped = LinkedHashMap(record.fields)
                    stamped["favorite"] = JsonValue.Bool(favorite)
                    stamped["updated_at"] = JsonValue.Int(clock.now)
                    val normal = try {
                        Normalise.normalForm(ns, JsonValue.Obj(stamped))
                    } catch (e: NormaliseException) {
                        // A kind the phone never edits passes through untouched apart from the two fields.
                        if (e.kind != NormaliseException.Kind.NOT_PHONE_KIND) throw e
                        JsonValue.Obj(stamped)
                    }
                    val records = LinkedHashMap(snap.records)
                    records[id] = Wrapper.make(ns, normal)
                    store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
                    SaveResult.SAVED
                }
            }
        } catch (_: Exception) {
            SaveResult.FAILED
        }
    }
}
