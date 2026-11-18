package app.localgatekeys.android.sync

import app.localgatekeys.android.trash.LocalData
import app.localgatekeys.android.trash.LocalDataHosting
import app.localgatekeys.android.trash.PhoneTrash
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.ShareTrash
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.itemRecords

/**
 * A share commit that Recently deleted cannot take ([kind] `trash-full`, or `item-error` while it is not open or cannot
 * be saved). Its message starts with the kind; it never carries content.
 */
class ShareTrashRefusal(val kind: String) : Exception("$kind: share-run") {
    companion object {
        const val FULL = "trash-full"
        const val UNAVAILABLE = "item-error"
    }
}

/** The Recently deleted rows of the items a store change takes out (sub-plan 07; the iPhone's `RemovedItems`). */
object RemovedItems {
    /**
     * Live logins and typed items in [before] that [records]/[meta] no longer hold live, as trash rows with their
     * collections (restored with the item, as on Windows), in id order.
     */
    fun trashRows(before: StoreSnapshot, records: Map<String, JsonValue>, meta: Map<String, SyncMeta>, now: Long): List<LocalData.TrashRow> {
        val rows = ArrayList<LocalData.TrashRow>()
        for ((id, wrapper) in before.itemRecords.entries.sortedWith { a, b -> Scalars.compare(a.key, b.key) }) {
            if (before.meta[id]?.deleted == true) continue
            if (records[id] != null && meta[id]?.deleted != true) continue
            val w = wrapper as? JsonValue.Obj ?: continue
            val ns = (w.fields["ns"] as? JsonValue.Str)?.v
            if (ns != Namespace.ENTRY.wire && ns != Namespace.ITEM.wire) continue
            val record = PhoneTrash.trashRecord(w) ?: continue
            val row = try {
                LocalData.TrashRow.of(CollectionCatalog.trashRecord(record, id, before), now)
            } catch (e: Exception) {
                continue
            }
            rows.add(row)
        }
        return rows
    }
}

/**
 * The store a share run (and a share removal, `ShareGroups.applyShareRemoval`) commits through (sub-plan 07): every live
 * item a commit takes out goes to Recently deleted first, never deleted for good (desktop: share deletes and removals
 * land in the trash; the iPhone's `ShareTrashingStore`). Recently deleted is saved first, then the store; a failed store
 * commit takes out exactly the rows it added, so an item is never lost from both. A commit Recently deleted has no room
 * for ([LocalData.MAX_TRASH], the same limit as `ShareTrash.MAX_TRASH`) is refused before anything changes.
 *
 * [local] is locked like Recently deleted itself (`PhoneTrash`), so no row written meanwhile is lost. Blocking.
 */
class ShareTrashingStore(
    private val base: ItemStore,
    private val local: LocalDataHosting,
    private val now: () -> Long,
) : ItemStore {
    override fun load(): StoreSnapshot = base.load()

    /** What the share runner needs from Recently deleted (`FolderSync.Share.trash`, `applyShareRemoval`). */
    fun shareTrash(): ShareTrash {
        val data = synchronized(local) { local.localData } ?: return ShareTrash(null)
        return try {
            ShareTrash.of(data.trash.map { it.record() })
        } catch (e: Exception) {
            ShareTrash(null)
        }
    }

    override fun commit(change: StoreChange) {
        val before = base.load()
        val rows = RemovedItems.trashRows(before, change.records, change.meta, now())
        if (rows.isEmpty()) {
            base.commit(change)
            return
        }
        synchronized(local) {
            val data = local.localData ?: throw ShareTrashRefusal(ShareTrashRefusal.UNAVAILABLE)
            if (data.trash.size + rows.size > LocalData.MAX_TRASH) throw ShareTrashRefusal(ShareTrashRefusal.FULL)
            try {
                local.commitLocalData(data.copy(trash = data.trash + rows))
            } catch (e: Exception) {
                throw ShareTrashRefusal(ShareTrashRefusal.UNAVAILABLE)
            }
            try {
                base.commit(change)
            } catch (e: Exception) {
                remove(rows)
                throw e
            }
        }
    }

    /**
     * Every row of [itemIds] leaves Recently deleted: a share run brought those items back live (the iPhone's
     * `ShareHost.leave`). Best effort: a row that stays only shows an item that is also live.
     */
    fun leave(itemIds: Set<String>) {
        if (itemIds.isEmpty()) return
        synchronized(local) {
            val data = local.localData ?: return
            val kept = data.trash.filter { row ->
                val id = try {
                    ((row.record() as? JsonValue.Obj)?.fields?.get("id") as? JsonValue.Str)?.v
                } catch (e: Exception) {
                    null
                }
                id == null || id !in itemIds
            }
            if (kept.size == data.trash.size) return
            try {
                local.commitLocalData(data.copy(trash = kept))
            } catch (e: Exception) {
                // the rows stay until the next brought-back run or the user restores/empties them
            }
        }
    }

    /** Takes [rows] out of Recently deleted again, one match each by value, keeping everything else saved since. */
    private fun remove(rows: List<LocalData.TrashRow>) {
        val data = local.localData ?: return
        val kept = ArrayList(data.trash)
        for (row in rows) {
            val i = kept.lastIndexOf(row)
            if (i >= 0) kept.removeAt(i)
        }
        try {
            local.commitLocalData(data.copy(trash = kept))
        } catch (e: Exception) {
            // the rows stay; the items are still live, so a restore reports the same id
        }
    }

    override fun toString(): String = "ShareTrashingStore"
}
