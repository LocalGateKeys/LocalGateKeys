package app.localgatekeys.android.history

import app.localgatekeys.android.trash.LocalDataHosting
import app.localgatekeys.core.history.ItemHistory
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.UnixClock
import java.util.UUID

/**
 * What a store commit on this thread is (contract section 1.3 `change_type`): an edit unless a caller says otherwise
 * (a sync run, an import, a merge, a restore).
 */
object CommitOrigin {
    private val current = ThreadLocal<String?>()

    val value: String get() = current.get() ?: "update"

    /** Runs [block] with commits on this thread recorded as [type]. */
    fun <T> with(type: String, block: () -> T): T {
        val old = current.get()
        current.set(type)
        try {
            return block()
        } finally {
            current.set(old)
        }
    }

    /**
     * [store] with every commit recorded as [type] (scan A-L3: the Wi-Fi host's merge runs in the shared core, which
     * cannot name this phone's history, so its store says "sync" for it).
     */
    fun recording(type: String, store: app.localgatekeys.core.sync.ItemStore): app.localgatekeys.core.sync.ItemStore =
        object : app.localgatekeys.core.sync.ItemStore {
            override fun load() = store.load()

            override fun commit(change: app.localgatekeys.core.sync.StoreChange) = with(type) { store.commit(change) }
        }
}

/**
 * Item history on this phone (contract section 1): each commit's replaced versions are appended to the local data's
 * `item_history` and pruned with the current plan's limits (Free 5 versions / 30 days, Pro 30 / 1 year). Never synced,
 * never in a backup. A failure is swallowed: history never blocks a save or a sync.
 */
class HistoryRecorder(
    private val local: LocalDataHosting,
    private val isPro: () -> Boolean,
    private val clock: UnixClock,
    private val newId: () -> String = { UUID.randomUUID().toString() },
) {
    // The local data itself: every read-modify-write of it holds this one lock (as `PhoneTrash` does), so none loses another's change.
    private val lock: Any = local

    fun record(before: Map<String, JsonValue>, after: Map<String, JsonValue>) {
        try {
            val now = clock.now
            val rows = ItemHistory.captures(before, after, now, CommitOrigin.value, newId)
            // Ids this commit removed from the store (a delete here with no Recently deleted row, or one from another
            // device): their history goes too (scan A-M3). A delete into Recently deleted keeps it until the purge.
            val removed = before.keys - after.keys
            if (rows.isEmpty() && removed.isEmpty()) return
            synchronized(lock) {
                val data = local.localData ?: return
                val gone = if (removed.isEmpty()) emptySet() else removed - data.trashIds()
                val old = if (gone.isEmpty()) data.itemHistory else data.itemHistory.filter { ItemHistory.Row.of(it)?.itemId !in gone }
                if (rows.isEmpty() && old.size == data.itemHistory.size) return
                val all = ItemHistory.prune(old + rows, now, ItemHistory.limits(isPro()))
                local.commitLocalData(data.withItemHistory(all))
            }
        } catch (e: Exception) {
            // Best effort (contract section 1.3).
        }
    }

    /** The versions of [itemId] kept on this phone, newest first. */
    fun rows(itemId: String): List<ItemHistory.Row> =
        (local.localData?.itemHistory ?: emptyList()).mapNotNull { ItemHistory.Row.of(it) }.filter { it.itemId == itemId }
            .sortedByDescending { it.createdAt }

    /** Forgets every version of [itemId] (a permanent delete). */
    fun forget(itemId: String) = synchronized(lock) {
        try {
            val data = local.localData ?: return@synchronized
            val kept = data.itemHistory.filter { ItemHistory.Row.of(it)?.itemId != itemId }
            if (kept.size != data.itemHistory.size) local.commitLocalData(data.withItemHistory(kept))
        } catch (e: Exception) {
            // best effort
        }
    }
}
