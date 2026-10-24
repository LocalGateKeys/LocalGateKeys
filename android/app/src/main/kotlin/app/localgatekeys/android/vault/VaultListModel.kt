package app.localgatekeys.android.vault

import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreSnapshot
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * What the vault and search screens show: the decoded live items of the store, the query and the type filter. [onLoad]
 * gets every snapshot loaded (on the loading thread): Pro re-reads the synced licence states from it.
 */
class VaultListModel(private val store: ItemStore, private val onLoad: (StoreSnapshot) -> Unit = {}) {
    val query = MutableStateFlow("")
    val filter = MutableStateFlow<VaultFilter>(VaultFilter.All)

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

    val visibleItems: List<VaultItem> get() = VaultSearch.apply(_items.value, query.value, filter.value)
    val filterOptions: List<VaultFilter> get() = VaultSearch.filterOptions(_items.value)

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
            if (filter.value !in VaultSearch.filterOptions(decoded)) filter.value = VaultFilter.All
        } catch (_: Exception) {
            _loadError.value = LOAD_ERROR
        }
    }

    companion object {
        const val LOAD_ERROR = "The vault could not be read on this device."
    }
}
