package app.localgatekeys.android.vault

import app.localgatekeys.android.R
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
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
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

    val visibleItems: List<VaultItem> get() = visible(_items.value, query.value, filter.value, _sort.value, t)
    val filterOptions: List<VaultFilter> get() = VaultSearch.filterOptions(_items.value, t)

    /** Reads the saved sort and saves every later [setSort] there (per phone, not synced). */
    fun useSettings(settings: AppSettings) {
        this.settings = settings
        _sort.value = settings.vaultSort
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
            val decoded = VaultItem.items(snap)
            snapshot = snap
            _items.value = decoded
            _liveCount.value = ItemLimit.liveCount(snap)
            _loadError.value = null
            onLoad(snap)
            if (filter.value !in VaultSearch.filterOptions(decoded, t)) filter.value = VaultFilter.All
        } catch (_: Exception) {
            _loadError.value = t.s(R.string.vault_load_error)
        }
    }

    companion object {
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
                snap.meta[id]?.deleted == true || ns == null || ns == Namespace.LICENSE || record == null -> SaveResult.FAILED
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
