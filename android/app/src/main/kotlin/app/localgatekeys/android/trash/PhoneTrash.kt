package app.localgatekeys.android.trash

import app.localgatekeys.android.R
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.AttachmentRef
import app.localgatekeys.core.sync.AttachmentSync
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.core.sync.CollectionStates
import app.localgatekeys.core.sync.DirectoryAttachmentVault
import app.localgatekeys.core.sync.Documents
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.TravelMode
import java.io.File
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

/**
 * The phone's Recently deleted (UX plan workstream 3), a port of `ios/App/Trash/PhoneTrash.swift` on [LocalDataHosting]:
 * deleting saves the record as a trash row first, then removes it from the store with a tombstone (so the delete still
 * syncs); restoring writes the same record back live (a tomb's vector is kept, so another device's delete is undone by
 * the next sync). Trash rows never count toward the free limit; restoring over the limit is refused. Rows past the
 * retention (1-365 days, default 30) are purged on unlock ([purgeExpired]) and on every write.
 *
 * Documents (Android differs from the iPhone here): the row keeps the document's file reference in its record
 * (`_lgk_attachment`, as on the iPhone), and the sealed file is copied into `Vault/attachments-deleted/` ([kept]),
 * because the app removes files no live record names after every vault load. A restore puts the file back; a purge
 * deletes the copy. The copy stays sealed under the attachment's own key, which only the encrypted row holds.
 *
 * Collections (sub-plan 07): a row keeps the item's collections as `collection_ids` (Windows' trash entry does too) and
 * the store delete drops its membership; a restore gives the membership back for the collections that still exist. An
 * item in a collection shared with this vault as view only is never moved here (the delete is refused).
 *
 * Blocking: the store and file calls run on the calling thread (use [Dispatchers.IO]); [rows] is safe to collect on main.
 */
class PhoneTrash(
    val local: LocalDataHosting,
    private val store: ItemStore,
    private val isPro: () -> Boolean,
    private val clock: UnixClock,
    private val t: Txt,
    /** This phone's document files (`LgkApp.attachments`); null: documents keep their row but not their file. */
    private val attachments: DirectoryAttachmentVault?,
    private val io: CoroutineContext = Dispatchers.IO,
) {
    /**
     * One row as listed. [id] is unique even when the same item was deleted twice in one second. [retentionDays] is the
     * setting the row was listed under: a changed setting lists new rows, so the screen's "N days left" follows at once.
     */
    data class Row(
        val id: String,
        val itemId: String,
        val title: String,
        val detail: String,
        val deletedAt: Long,
        internal val index: Int,
        internal val retentionDays: Int = DEFAULT_RETENTION_DAYS,
    ) {
        override fun toString(): String = "Row(id=$id, deletedAt=$deletedAt)"
    }

    sealed class RestoreOutcome {
        object Restored : RestoreOutcome()
        object Limit : RestoreOutcome()
        data class Failed(val message: String) : RestoreOutcome()
    }

    /** Where deleted documents' files wait ([attachments]' sibling folder). */
    val kept: DirectoryAttachmentVault? = attachments?.let { DirectoryAttachmentVault(File(it.dir.absoluteFile.parentFile, KEPT_DIR)) }

    /**
     * The local data itself: every read-modify-write of it (Recently deleted here, the reminders'
     * [app.localgatekeys.android.reminders.LocalReminderStore]) holds this one lock, so neither loses the other's change.
     */
    private val lock: Any = local

    /** The last deleted item, for the Undo toast. */
    @Volatile var lastDeleted: Pair<String, Long>? = null
        private set

    /** Called after Undo restored an item (the list reloads and a sync is scheduled). */
    @Volatile var onRestored: () -> Unit = {}

    /**
     * This phone's travel mode (feature pack section 2.3): rows of hidden items are left out of the list (and of
     * Empty all), never purged by it. Setting it lists the rows again.
     */
    @Volatile var travel: () -> TravelMode.Setting = { TravelMode.Setting.OFF }
        set(value) {
            field = value
            refresh()
        }

    private val _rows = MutableStateFlow(computeRows())

    /** Newest first. */
    val rows: StateFlow<List<Row>> = _rows.asStateFlow()

    /** Lists the rows again (travel mode changed). */
    fun relist() = refresh()

    private fun refresh() {
        _rows.value = computeRows()
    }

    private fun computeRows(includeHidden: Boolean = false): List<Row> {
        val trash = local.localData?.trash ?: return emptyList()
        val retention = retentionDays
        val setting = if (includeHidden) TravelMode.Setting.OFF else try {
            travel()
        } catch (e: Exception) {
            TravelMode.Setting.OFF
        }
        val hiddenIndices = if (setting.isEmpty) emptySet() else hiddenRows(trash, setting)
        val seen = HashMap<String, Int>()
        val out = trash.mapIndexed { index, row ->
            val record = try { row.record() as? JsonValue.Obj } catch (e: Exception) { null }
            val itemId = (record?.fields?.get("id") as? JsonValue.Str)?.v ?: ""
            val item = record?.let { VaultItem.of(itemId, it) }
            val kind = item?.kindLabel(t) ?: t.s(R.string.kind_unknown)
            val title = item?.let { it.title.ifEmpty { it.kindLabel(t) } } ?: kind
            val detail = if (item != null && item.isLogin && item.username.isNotEmpty()) t.s(R.string.trash_join, kind, item.username) else kind
            var key = "$itemId@${row.deletedAt}"
            val n = seen[key] ?: 0
            seen[key] = n + 1
            if (n > 0) key += "#$n"
            Row(key, itemId, title, detail, row.deletedAt, index, retention)
        }.filter { it.index !in hiddenIndices }
        return out.sortedWith(compareByDescending<Row> { it.deletedAt }.thenByDescending { it.index })
    }

    val retentionDays: Int get() = local.localData?.preferences?.trashRetentionDays ?: DEFAULT_RETENTION_DAYS

    /** Whole days left before [row] is purged (0 = goes at the next write), under the setting it was listed with. */
    fun daysLeft(row: Row): Int {
        val expires = row.deletedAt + row.retentionDays.toLong() * 86_400
        return maxOf(0L, (expires - clock.now + 86_399) / 86_400).toInt()
    }

    /** "12 days left", or "removed soon" on the last day. */
    fun daysLeftText(row: Row): String = daysLeftText(daysLeft(row), t)

    fun setRetentionDays(days: Int): Unit = synchronized(lock) {
        val data = local.localData ?: return
        val next = data.copy(preferences = data.preferences.copy(trashRetentionDays = days.coerceIn(1, 365))).purgeExpiredTrash(clock.now)
        local.commitLocalData(next)
        collectKeptFiles(next)
        refresh()
    }

    // MARK: delete

    /** [moveToTrash] as the editors' delete hook. */
    val mover: (String) -> SaveResult = { id -> moveToTrash(id) }

    /**
     * Moves a live item to Recently deleted: the row is saved first, then the store change (a failed store commit takes
     * the row out again, so the item is never lost from both). UNCHANGED when it was gone.
     */
    fun moveToTrash(id: String): SaveResult = synchronized(lock) {
        val data = local.localData ?: return SaveResult.FAILED
        val snap = try { store.load() } catch (e: Exception) { return SaveResult.FAILED }
        if (CollectionStates.isStateId(id)) return SaveResult.UNCHANGED
        val wrapper = snap.records[id] as? JsonValue.Obj ?: return SaveResult.UNCHANGED
        // The row keeps the item's collections; the store delete drops its membership.
        val record = trashRecord(wrapper)?.let { CollectionCatalog.trashRecord(it, id, snap) } ?: return SaveResult.UNCHANGED
        val now = clock.now
        val row = try { LocalData.TrashRow.of(record, now) } catch (e: Exception) { return SaveResult.FAILED }
        // A document's sealed file waits beside the vault (best effort: one still waiting for sync has none here).
        Documents.refOf(wrapper)?.let { ref -> keepFile(ref) }
        val next = (data.copy(trash = data.trash + row)).purgeExpiredTrash(now)
        try {
            local.commitLocalData(next)
        } catch (e: Exception) {
            return SaveResult.FAILED
        }
        val r = EditorModel.delete(id, store, clock)
        if (r != SaveResult.SAVED) {
            try { local.commitLocalData(data) } catch (e: Exception) { /* the row stays; the item is still live */ }
            refresh()
            return r
        }
        lastDeleted = id to now
        refresh()
        SaveResult.SAVED
    }

    // MARK: restore

    fun restore(rowId: String, isPro: Boolean): RestoreOutcome = synchronized(lock) {
        val row = computeRows().firstOrNull { it.id == rowId } ?: return RestoreOutcome.Failed(t.s(R.string.trash_gone))
        restoreRow(row, isPro)
    }

    /** The Undo toast: restores the item deleted last (if it is still in the trash). */
    fun undoLastDelete(isPro: Boolean): RestoreOutcome = synchronized(lock) {
        val last = lastDeleted
        val row = last?.let { (itemId, at) -> computeRows(includeHidden = true).firstOrNull { it.itemId == itemId && it.deletedAt == at } }
            ?: return RestoreOutcome.Failed(t.s(R.string.trash_gone))
        lastDeleted = null
        restoreRow(row, isPro)
    }

    private fun restoreRow(row: Row, isPro: Boolean): RestoreOutcome {
        val data = local.localData
        if (data == null || row.index !in data.trash.indices || data.trash[row.index].deletedAt != row.deletedAt) {
            return RestoreOutcome.Failed(t.s(R.string.trash_gone))
        }
        val record = (try { data.trash[row.index].record() } catch (e: Exception) { null }) as? JsonValue.Obj
        val id = (record?.fields?.get("id") as? JsonValue.Str)?.v
        val kind = (record?.fields?.get("kind") as? JsonValue.Str)?.v
        if (record == null || id.isNullOrEmpty() || kind == null || CollectionStates.isStateId(id)) {
            return RestoreOutcome.Failed(t.s(R.string.trash_cannot_restore))
        }
        val snap = try { store.load() } catch (e: Exception) { return RestoreOutcome.Failed(t.s(R.string.trash_vault_unreadable)) }
        if (!ItemLimit.allows(ItemLimit.Action.RESTORE, snap, isPro)) return RestoreOutcome.Limit
        if (snap.records[id] != null && snap.meta[id]?.deleted != true) return RestoreOutcome.Failed(t.s(R.string.trash_same_id))
        val ns = if (kind == "web" || kind == "desktop") Namespace.ENTRY else Namespace.ITEM
        // The row's collections become its membership again; the stored record never carries them.
        val (stored, withMembership) = CollectionCatalog.restored(record.fields, id, snap.records)
        val wrapper = restoredWrapper(JsonValue.Obj(stored), ns)
        // A document gets its file back before its record (best effort: sync fetches a missing one again).
        Documents.refOf(wrapper)?.let { ref -> returnFile(ref) }
        val records = LinkedHashMap(withMembership).apply { put(id, wrapper) }
        val meta = LinkedHashMap(snap.meta)
        val m = snap.meta[id]
        if (m != null && m.deleted) {
            // Live again: the tomb's vector is kept and bumped once at the next view, so the restore wins.
            meta[id] = SyncMeta(null, null, null, m.vv, false, null)
        }
        try {
            store.commit(StoreChange(snap.revision, records, meta, snap.sync))
        } catch (e: Exception) {
            return RestoreOutcome.Failed(t.s(R.string.trash_restore_save_failed))
        }
        val next = data.copy(trash = data.trash.filterIndexed { i, _ -> i != row.index }).purgeExpiredTrash(clock.now)
        try {
            local.commitLocalData(next)
        } catch (e: Exception) {
            // Store first, then the row: undo the store change so the item is not in both places.
            try {
                val s = store.load()
                val r2 = LinkedHashMap(s.records)
                val m2 = LinkedHashMap(s.meta)
                snap.records[id]?.let { r2[id] = it } ?: r2.remove(id)
                val membership = CollectionStates.MEMBERSHIP_PREFIX + id
                snap.records[membership]?.let { r2[membership] = it } ?: r2.remove(membership)
                snap.meta[id]?.let { m2[id] = it } ?: m2.remove(id)
                store.commit(StoreChange(s.revision, r2, m2, s.sync))
            } catch (x: Exception) {
                // the item is live and still listed here; restoring again reports the same ID
            }
            refresh()
            return RestoreOutcome.Failed(t.s(R.string.trash_save_failed))
        }
        collectKeptFiles(next)
        refresh()
        return RestoreOutcome.Restored
    }

    /** Shows "Moved to Recently deleted" with Undo for 5 seconds (after a delete that saved). */
    fun offerUndo(toast: UndoToast) {
        if (lastDeleted == null) return
        toast.show(t.s(R.string.trash_moved), t.s(R.string.trash_undo_announcement, t.s(R.string.trash_moved))) {
            when (val r = withContext(io) { undoLastDelete(isPro()) }) {
                RestoreOutcome.Restored -> {
                    onRestored()
                    toast.info(t.s(R.string.trash_item_restored))
                }
                RestoreOutcome.Limit -> toast.info(t.s(R.string.trash_restore_needs_pro), UndoToast.LONG_MILLIS)
                is RestoreOutcome.Failed -> toast.info(r.message, UndoToast.LONG_MILLIS)
            }
        }
    }

    // MARK: permanent delete

    /** Deletes the rows [rowIds] for good (their document files too). Throws when the change cannot be saved. */
    fun purge(rowIds: Set<String>): Unit = synchronized(lock) {
        val wanted = computeRows().filter { it.id in rowIds }.map { it.index }.toSet()
        val data = local.localData ?: return
        if (wanted.isEmpty()) return
        val next = data.copy(trash = data.trash.filterIndexed { i, _ -> i !in wanted })
            .forgetHistoryOf(data.trash.filterIndexed { i, _ -> i in wanted })
        local.commitLocalData(next)
        collectKeptFiles(next)
        refresh()
    }

    fun emptyAll() = purge(computeRows().map { it.id }.toSet())

    /** On unlock and when the page opens: drops rows past the retention period (and files nothing needs). */
    fun purgeExpired(): Unit = synchronized(lock) {
        val data = local.localData ?: return
        val next = data.purgeExpiredTrash(clock.now)
        if (next !== data) {
            try {
                local.commitLocalData(next)
            } catch (e: Exception) {
                return
            }
        }
        collectKeptFiles(next)
        refresh()
    }

    // MARK: document files

    private fun keepFile(ref: AttachmentRef) {
        val live = attachments ?: return
        val k = kept ?: return
        try {
            val blob = live.blob(ref) ?: return
            k.store(ref, blob)
        } catch (e: Exception) {
            // not kept: a restore leaves the document waiting for its file
        }
    }

    private fun returnFile(ref: AttachmentRef) {
        val live = attachments ?: return
        val k = kept ?: return
        try {
            val blob = k.blob(ref) ?: return
            live.store(ref, blob)
        } catch (e: Exception) {
            // sync fetches it again from a device that has it
        }
    }

    /** Removes kept files (and leftover temp files) that no remaining row names. */
    private fun collectKeptFiles(data: LocalData) {
        val dir = kept?.dir ?: return
        val names = dir.list() ?: return
        val keep = data.trash.mapNotNull { row ->
            val r = (try { row.record() } catch (e: Exception) { null }) as? JsonValue.Obj ?: return@mapNotNull null
            val ref = try { AttachmentRef.fromJson(r.fields[TRASH_REF_KEY]) } catch (e: Exception) { null } ?: return@mapNotNull null
            "${ref.attachmentId}.${ref.blob}${AttachmentSync.BLOB_SUFFIX}"
        }.toSet()
        for (name in names) if (name !in keep) File(dir, name).delete()
    }

    override fun toString(): String = "PhoneTrash(rows=${_rows.value.size})"

    companion object {
        const val UNDO_MILLIS = 5_000L

        /** Deleted documents' sealed files, next to `Vault/attachments`. */
        const val KEPT_DIR = "attachments-deleted"

        /** Key under which a Recently deleted row keeps a document's reference (iPhone `AttachmentDocuments.trashRefKey`). */
        const val TRASH_REF_KEY = "_lgk_attachment"

        val RETENTION_CHOICES = listOf(1, 7, 14, 30, 60, 90, 180, 365)

        /** The retention when none is set. */
        const val DEFAULT_RETENTION_DAYS = 30

        /**
         * Every delete of a vault item (the detail screen's Delete for desktop logins and documents, the editors): to
         * Recently deleted when [trash] is set, else the plain tombstone ([EditorModel.delete]). Blocking.
         */
        fun deleteItem(id: String, store: ItemStore, clock: UnixClock, trash: PhoneTrash?): SaveResult =
            trash?.moveToTrash(id) ?: EditorModel.delete(id, store, clock)

        /** The record a row stores for [wrapper]: the record, plus the file reference of a document. */
        /** Indices of [trash] rows whose record travel mode [setting] hides (tags; collections kept as `collection_ids`). */
        fun hiddenRows(trash: List<LocalData.TrashRow>, setting: TravelMode.Setting): Set<Int> {
            val items = ArrayList<TravelMode.Item>()
            trash.forEachIndexed { index, row ->
                val f = (try { row.record() } catch (e: Exception) { null } as? JsonValue.Obj)?.fields ?: return@forEachIndexed
                val kind = (f["kind"] as? JsonValue.Str)?.v ?: return@forEachIndexed
                fun strings(k: String) = (f[k] as? JsonValue.Arr)?.items?.mapNotNull { (it as? JsonValue.Str)?.v } ?: emptyList()
                items.add(TravelMode.Item(index.toString(), kind, strings("tags"), if (TravelMode.isLogin(kind)) emptyList() else strings("collection_ids")))
            }
            return TravelMode.hiddenIds(items, setting).mapTo(HashSet()) { it.toInt() }
        }

        fun trashRecord(wrapper: JsonValue.Obj): JsonValue? {
            val r = wrapper.fields["record"] as? JsonValue.Obj ?: return null
            val attachment = wrapper.fields["attachment"]
            return if (Documents.refOf(wrapper) != null && attachment != null) {
                JsonValue.Obj(LinkedHashMap(r.fields).apply { put(TRASH_REF_KEY, attachment) })
            } else {
                r
            }
        }

        /** The wrapper to store when a row comes back: a document gets its reference again. */
        fun restoredWrapper(record: JsonValue.Obj, ns: Namespace): JsonValue {
            val attachment = record.fields[TRASH_REF_KEY] ?: return Wrapper.make(ns, record)
            val plain = JsonValue.Obj(LinkedHashMap(record.fields).apply { remove(TRASH_REF_KEY) })
            val ref = try { AttachmentRef.fromJson(attachment) } catch (e: Exception) { null }
            if (ns != Namespace.ITEM || ref == null) return Wrapper.make(ns, plain)
            return JsonValue.Obj((Wrapper.make(Namespace.ITEM, plain) as JsonValue.Obj).fields + ("attachment" to ref.toJson()))
        }

        fun daysLeftText(days: Int, t: Txt): String =
            if (days <= 0) t.s(R.string.trash_removed_soon) else t.plural(R.plurals.trash_days_left, days, days)

        fun daysText(days: Int, t: Txt): String = t.plural(R.plurals.trash_days, days, days)
    }
}
