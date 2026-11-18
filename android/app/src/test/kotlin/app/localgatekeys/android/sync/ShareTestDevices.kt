package app.localgatekeys.android.sync

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.trash.InMemoryLocalData
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.core.sync.ShareGroups
import app.localgatekeys.core.sync.ShareRecord
import app.localgatekeys.core.sync.StoreChange
import java.io.File
import kotlinx.coroutines.CoroutineScope

// Shared collections test doubles (sub-plan 07 Task 5m; the iPhone's `ShareDevice` in SyncCoordinatorTests.swift).

/** Share passwords for the tests: Strong, 12+ characters. */
object SharePasswords {
    const val FIRST = SyncVectors.PASSWORD
    const val SECOND = "another very long passphrase 42?"
}

/**
 * One person's phone in a share test: its own vault, sealed slots, Recently deleted and coordinator (on [scope]), over
 * [folders] (by default every folder URI opens [shared]). Pro is on until a test turns it off.
 */
class ShareDevice(
    val shared: MemoryFolder,
    val clock: TestClock,
    slotsFile: File,
    scope: CoroutineScope,
    folders: FolderOpening = FakeFolders(shared),
    val lan: FakeLan = FakeLan(),
) {
    val store = LockedStore()
    val slots = SecretSlots(slotsFile.also { it.delete() }, ByteArray(32) { 5 }, SystemRandomSource())
    val local = InMemoryLocalData()
    @Volatile var pro = true
    val deps = SyncDependencies(
        slots = slots, folders = folders, lan = lan, autoFill = CountingAutoFill(), random = SystemRandomSource(), clock = clock,
        licenseKeys = emptyMap(), sleep = {},
    )
    val coordinator = SyncCoordinator(store, deps, scope, EnglishTxt()).also { c ->
        c.shareTrash = local
        c.isPro = { pro }
    }

    val shares: Map<String, ShareRecord>
        get() = try {
            ShareGroups.records(store.snapshot)
        } catch (e: Exception) {
            emptyMap()
        }

    /** The item ids in Recently deleted, oldest first. */
    fun trashIds(): List<String> = (local.localData?.trash ?: emptyList()).mapNotNull { row ->
        try {
            ((row.record() as? JsonValue.Obj)?.fields?.get("id") as? JsonValue.Str)?.v
        } catch (e: Exception) {
            null
        }
    }
}

/** A "Family" collection holding one note in [store]: (collection id, item id). */
fun sharedNote(store: LockedStore, now: Long, n: Int = 7): Pair<String, String> {
    val (change, cid) = CollectionCatalog.create("Family", snapshot = store.snapshot, now = now)
    store.commit(change)
    val (id, wrapper) = noteRecord(n, "Wi-Fi")
    var s = store.snapshot
    store.commit(StoreChange(s.revision, s.records + (id to wrapper), s.meta, s.sync))
    s = store.snapshot
    store.commit(checkNotNull(CollectionCatalog.setMemberships(id, "note", listOf(cid), s)))
    return cid to id
}

/** [itemId]'s collections set to [ids] in [store]. */
fun setCollections(store: LockedStore, itemId: String, ids: List<String>) {
    store.commit(checkNotNull(CollectionCatalog.setMemberships(itemId, "note", ids, store.snapshot)))
}

/** Logs the order of the personal Wi-Fi exchange and the share folder opens. */
class RunOrder {
    private val log = ArrayList<String>()
    val events: List<String> get() = synchronized(log) { log.toList() }
    fun add(event: String) = synchronized(log) { log.add(event) }
    fun clear() = synchronized(log) { log.clear() }
}

/** [base] that logs every open as "share" (the personal group of these tests is Wi-Fi only). */
class OrderedFolders(private val base: FakeFolders, private val order: RunOrder) : FolderOpening {
    override fun open(uri: String) = base.open(uri).also { order.add("share") }
}
