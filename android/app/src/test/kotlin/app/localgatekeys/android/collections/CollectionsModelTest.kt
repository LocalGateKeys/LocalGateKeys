package app.localgatekeys.android.collections

import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.editor.NOW
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.editor.editor
import app.localgatekeys.android.editor.numberedNotes
import app.localgatekeys.android.editor.pairedSnapshot
import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.trash.InMemoryLocalData
import app.localgatekeys.android.trash.LocalData
import app.localgatekeys.android.trash.PhoneTrash
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.VaultListModel
import app.localgatekeys.android.vault.webLogin
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.core.sync.CollectionStates
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.itemRecords
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Sub-plan 07 Task 5l (the iPhone's 5f list): the model creates, renames, deletes, filters and sets membership on the
 * free plan; logins have no picker; a read-only item refuses edit, delete and move; the migration runs once (with its
 * "done" marker); starters only on request; Recently deleted keeps and gives back collections.
 */
class CollectionsModelTest {
    private val txt = EnglishTxt()
    private val clock = TestClock(NOW)
    private val notes = numberedNotes(4)
    private fun id(k: Int) = (notes[k].fields["id"] as JsonValue.Str).v

    private val ids = ArrayDeque(
        listOf(
            "c0000000-0000-4000-8000-000000000001", "c0000000-0000-4000-8000-000000000002",
            "c0000000-0000-4000-8000-000000000003", "c0000000-0000-4000-8000-000000000004",
            "c0000000-0000-4000-8000-000000000005", "c0000000-0000-4000-8000-000000000006",
        ),
    )

    private fun model(store: CountingStore, local: InMemoryLocalData? = InMemoryLocalData()) =
        CollectionsModel(store, local, clock, txt) { ids.removeFirst() }

    private fun item(store: CountingStore, k: Int): VaultItem =
        VaultItem.items(store.snapshot).first { it.id == id(k) }

    private fun trash(store: CountingStore, local: InMemoryLocalData) =
        PhoneTrash(local, store, { false }, clock, txt, null, io = kotlinx.coroutines.Dispatchers.Unconfined)

    /** A store with collection "Family" ([FAMILY]) holding note 0, and [extra] records. */
    private fun withFamily(extra: Map<String, JsonValue> = emptyMap(), shares: JsonValue? = null): CountingStore {
        val base = pairedSnapshot(notes)
        val records = LinkedHashMap(base.records)
        records[CollectionStates.CATALOG_PREFIX + FAMILY] =
            CollectionStates.wrapper(CollectionStates.catalog(FAMILY, "Family", "", NOW - 10, NOW - 10))
        records[CollectionStates.MEMBERSHIP_PREFIX + id(0)] = CollectionStates.wrapper(CollectionStates.membership(id(0), listOf(FAMILY)))
        records.putAll(extra)
        return CountingStore(base.copy(records = records, shares = shares))
    }

    /** Another of this person's devices is a view-only member of Family (a `csl:` link). */
    private fun readOnlyLink(): Map<String, JsonValue> =
        mapOf(CollectionStates.LINK_PREFIX + FAMILY to CollectionStates.wrapper(CollectionStates.link(FAMILY, "read", "member")))

    // ---- the model ----

    @Test fun the_model_creates_renames_deletes_and_sets_membership_on_the_free_plan() {
        val store = CountingStore(pairedSnapshot(notes))
        val m = model(store)
        m.reload()
        assertTrue(m.state.value.rows.isEmpty())
        val family = m.create("  Family ")!!
        assertEquals(listOf("Family"), m.state.value.rows.map { it.name })
        assertNull(m.create("family"))
        assertEquals("A collection with this name already exists.", m.state.value.message)
        assertNull(m.create("   "))
        assertEquals("Enter a name for the collection.", m.state.value.message)

        assertTrue(m.setMemberships(id(0), "note", setOf(family)))
        assertTrue(m.setMemberships(id(1), "note", setOf(family)))
        assertEquals(2, m.state.value.rows.single().count)
        assertEquals(listOf(id(0), id(1)), CollectionCatalog.items(family, store.snapshot))
        // Collection states never count toward the free plan's item limit.
        assertEquals(4, ItemLimit.liveCount(store.snapshot))

        assertTrue(m.rename(family, "Home"))
        assertEquals("Home", m.state.value.rows.single().name)
        assertTrue(m.delete(family))
        assertTrue(m.state.value.rows.isEmpty())
        // The items stay and leave the collection.
        assertEquals(4, VaultItem.items(store.snapshot).size)
        assertTrue(store.snapshot.records.keys.none { CollectionStates.isStateId(it) })
    }

    @Test fun deleting_a_collection_forgets_it_in_recently_deleted_and_in_the_starter_ids() {
        val local = InMemoryLocalData()
        val store = withFamily()
        val m = model(store, local)
        val t = trash(store, local)
        assertEquals(SaveResult.SAVED, t.moveToTrash(id(0)))
        local.commitLocalData(local.localData!!.copy(starterCollectionIds = listOf(FAMILY)))
        val row = local.localData!!.trash.single().record() as JsonValue.Obj
        assertEquals(JsonValue.Arr(listOf(JsonValue.Str(FAMILY))), row.fields["collection_ids"])
        assertTrue(m.delete(FAMILY))
        assertNull((local.localData!!.trash.single().record() as JsonValue.Obj).fields["collection_ids"])
        assertEquals(emptyList<String>(), local.localData!!.starterCollectionIds)
    }

    @Test fun recently_deleted_keeps_an_items_collections_and_restore_gives_them_back() {
        val local = InMemoryLocalData()
        val store = withFamily()
        val t = trash(store, local)
        assertEquals(SaveResult.SAVED, t.moveToTrash(id(0)))
        assertNull(store.snapshot.records[CollectionStates.MEMBERSHIP_PREFIX + id(0)])
        assertEquals(PhoneTrash.RestoreOutcome.Restored, t.restore(t.rows.value.single().id, isPro = false))
        assertEquals(listOf(FAMILY), CollectionCatalog.memberships(id(0), store.snapshot))
        // The stored record never carries collection_ids.
        val stored = ((store.snapshot.records.getValue(id(0)) as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields
        assertNull(stored["collection_ids"])
        // A collection state is never moved to Recently deleted.
        assertEquals(SaveResult.UNCHANGED, t.moveToTrash(CollectionStates.CATALOG_PREFIX + FAMILY))
    }

    @Test fun travel_mode_hides_collections_their_items_counts_and_recently_deleted_rows() {
        val local = InMemoryLocalData()
        val store = withFamily()
        val m = model(store, local)
        val t = trash(store, local)
        assertTrue(m.setMemberships(id(1), "note", setOf(FAMILY)))
        val other = m.create("Work")!!
        assertTrue(m.setMemberships(id(1), "note", setOf(FAMILY, other)))
        assertEquals(listOf("Family" to 2, "Work" to 1), m.state.value.rows.map { it.name to it.count })
        val travel = app.localgatekeys.core.sync.TravelMode.Setting(true, listOf(FAMILY), emptyList(), 1)
        m.travel = { travel }
        m.reload()
        // Family is absent; its item 1 is hidden everywhere, so Work no longer counts it.
        assertEquals(listOf("Work" to 0), m.state.value.rows.map { it.name to it.count })
        // Recently deleted: the row of an item in a hidden collection is hidden, never purged by Empty all.
        assertEquals(SaveResult.SAVED, t.moveToTrash(id(0)))
        assertEquals(1, t.rows.value.size)
        t.travel = { travel }
        assertTrue(t.rows.value.isEmpty())
        t.emptyAll()
        assertEquals(1, local.localData!!.trash.size)
        t.travel = { app.localgatekeys.core.sync.TravelMode.Setting.OFF }
        assertEquals(1, t.rows.value.size)
        // The vault list's collection picker leaves Family out too.
        val list = VaultListModel(store, txt)
        list.travel = { travel }
        list.reload()
        assertEquals(listOf("Work"), list.collections.value.map { it.name })
    }

    @Test fun logins_and_documents_have_no_picker_and_are_never_added() {
        for (kind in listOf("web", "desktop", "document")) assertFalse(kind, CollectionsModel.offersPicker(kind))
        for (kind in listOf("note", "card", "identity", "passkey")) assertTrue(kind, CollectionsModel.offersPicker(kind))
        assertFalse(editor(CountingStore(), kind = EditorKind.WEB).offersCollections)
        assertTrue(editor(CountingStore(), kind = EditorKind.NOTE).offersCollections)

        val base = withFamily()
        val loginId = (webLogin.fields["id"] as JsonValue.Str).v
        val store = CountingStore(base.snapshot.copy(records = base.snapshot.records + (loginId to Wrapper.make(Namespace.ENTRY, webLogin))))
        val m = model(store)
        assertFalse(m.setMemberships(loginId, "web", setOf(FAMILY)))
        assertEquals("Logins and documents can't be added to a collection.", m.state.value.message)
    }

    @Test fun the_editor_saves_memberships_in_the_same_commit_and_a_membership_only_change_keeps_the_record() {
        val store = withFamily()
        val before = store.snapshot.records.getValue(id(1))
        val e = editor(store, item(store, 1))
        e.loadCollections()
        assertEquals(listOf("Family"), e.collections.value.collections.map { it.name })
        assertTrue(e.collections.value.picked.isEmpty())
        e.setPicked(setOf(FAMILY))
        assertEquals(listOf("Family"), e.collections.value.pickedNames)
        assertEquals(SaveResult.SAVED, e.save())
        assertEquals(1, store.commits)
        assertEquals(before, store.snapshot.records.getValue(id(1)))
        assertEquals(listOf(FAMILY), CollectionCatalog.memberships(id(1), store.snapshot))
        assertEquals(SaveResult.UNCHANGED, e.save())

        // A new note picked into Family is created in it in one commit.
        val n = editor(store, kind = EditorKind.NOTE, isPro = { true })
        n.loadCollections()
        n.set("title", "Passports")
        n.setPicked(setOf(FAMILY))
        assertEquals(SaveResult.SAVED, n.save())
        assertEquals(2, store.commits)
        val created = VaultItem.items(store.snapshot).first { it.title == "Passports" }
        assertEquals(listOf(FAMILY), CollectionCatalog.memberships(created.id, store.snapshot))
    }

    @Test fun a_read_only_item_refuses_edit_delete_move_and_favourite() {
        val store = withFamily(readOnlyLink())
        val local = InMemoryLocalData()
        val revision = store.snapshot.revision
        assertTrue(CollectionsModel.itemIsReadOnly(id(0), store.snapshot))
        assertFalse(CollectionsModel.itemIsReadOnly(id(1), store.snapshot))

        val e = editor(store, item(store, 0))
        e.loadCollections()
        assertTrue(e.collections.value.isReadOnly)
        e.set("title", "Changed")
        assertEquals(SaveResult.INVALID, e.save())
        assertEquals(txt.s(app.localgatekeys.android.R.string.collections_read_only_item), e.error)
        assertEquals(SaveResult.INVALID, e.delete())
        assertEquals(SaveResult.INVALID, e.delete(trash(store, local).mover))
        assertEquals(SaveResult.INVALID, trash(store, local).moveToTrash(id(0)))
        assertTrue(local.localData!!.trash.isEmpty())
        assertEquals(SaveResult.INVALID, VaultListModel.setFavorite(store, id(0), true, clock))

        val m = model(store)
        m.reload()
        assertTrue(m.isReadOnly(id(0)))
        assertTrue(m.state.value.rows.single().isReadOnly)
        assertTrue(m.state.value.rows.single().isShared)
        // Moved neither out of nor into the view-only collection.
        assertFalse(m.setMemberships(id(0), "note", emptySet()))
        assertEquals("This collection is shared with you as view only, so it can't be changed on this device.", m.state.value.message)
        assertFalse(m.setMemberships(id(1), "note", setOf(FAMILY)))
        // Not renamed, not deleted.
        assertFalse(m.rename(FAMILY, "Ours"))
        assertEquals("This collection is shared with you as view only, so it can't be changed on this device.", m.state.value.message)
        assertFalse(m.delete(FAMILY))
        assertEquals("A shared collection can't be deleted. Stop sharing it or leave it first.", m.state.value.message)
        assertEquals(revision, store.snapshot.revision)
        // A personal item next to it still changes.
        assertEquals(SaveResult.SAVED, VaultListModel.setFavorite(store, id(1), true, clock))
    }

    // Review 5l #1: a passkey is a typed item, so it can sit in a view-only collection: never renamed or deleted here
    // (the iPhone's PasskeyRenameModel refuses the same way).
    @Test fun a_read_only_passkey_is_neither_renamed_nor_deleted() {
        val passkey = app.localgatekeys.android.detail.passkeyItem()
        val pid = (passkey.fields["id"] as JsonValue.Str).v
        val store = withFamily(
            readOnlyLink() + mapOf(
                pid to Wrapper.make(Namespace.ITEM, passkey),
                CollectionStates.MEMBERSHIP_PREFIX + pid to CollectionStates.wrapper(CollectionStates.membership(pid, listOf(FAMILY))),
            ),
        )
        val revision = store.snapshot.revision
        val item = VaultItem.items(store.snapshot).first { it.id == pid }
        val m = app.localgatekeys.android.editor.PasskeyRenameModel(store, item, clock, txt)
        m.setTitle("Renamed")
        assertEquals(SaveResult.INVALID, m.save())
        assertEquals(txt.s(app.localgatekeys.android.R.string.collections_read_only_item), m.error)
        assertEquals(SaveResult.INVALID, m.delete())
        assertEquals(txt.s(app.localgatekeys.android.R.string.collections_read_only_item), m.error)
        assertEquals(revision, store.snapshot.revision)
        // Without the view-only link the same rename goes through.
        val free = withFamily(
            mapOf(
                pid to Wrapper.make(Namespace.ITEM, passkey),
                CollectionStates.MEMBERSHIP_PREFIX + pid to CollectionStates.wrapper(CollectionStates.membership(pid, listOf(FAMILY))),
            ),
        )
        val ok = app.localgatekeys.android.editor.PasskeyRenameModel(free, VaultItem.items(free.snapshot).first { it.id == pid }, clock, txt)
        ok.setTitle("Renamed")
        assertEquals(SaveResult.SAVED, ok.save())
    }

    @Test fun rename_refuses_a_collection_that_is_view_only_from_this_devices_own_share_records() {
        // A damaged share store fails closed: every collection reads as view only on this device. The catalog alone
        // (which checks only other devices' links) would allow the rename.
        val store = withFamily(shares = JsonValue.Obj(mapOf("not-a-group" to JsonValue.Str("damaged"))))
        assertNotNull(CollectionCatalog.rename(FAMILY, "Ours", snapshot = store.snapshot, now = NOW))
        val m = model(store)
        assertFalse(m.rename(FAMILY, "Ours"))
        assertEquals("This collection is shared with you as view only, so it can't be changed on this device.", m.state.value.message)
        assertEquals("Family", CollectionCatalog.collections(store.snapshot).single().name)
        assertEquals(0, store.commits)
    }

    @Test fun starters_are_never_seeded_and_come_only_from_add_starters() {
        val local = InMemoryLocalData()
        val store = CountingStore(pairedSnapshot(notes))
        val m = model(store, local)
        m.reload()
        assertTrue(CollectionsModel.migrate(store, local).not())
        assertEquals(0, store.commits)
        assertTrue(m.state.value.rows.isEmpty())
        assertTrue(m.state.value.missingStarters)
        assertTrue(m.addStarters())
        assertEquals(listOf("Emergency", "Personal", "Travel", "Work"), m.state.value.rows.map { it.name })
        assertFalse(m.state.value.missingStarters)
        assertEquals(4, local.localData!!.starterCollectionIds.size)
        assertEquals(m.state.value.rows.map { it.id }.toSet(), local.localData!!.starterCollectionIds.toSet())
    }

    // ---- migration ----

    private fun legacy(): LocalData {
        fun coll(id: String, name: String, starter: Boolean) = JsonValue.Obj(
            mapOf(
                "id" to JsonValue.Str(id), "name" to JsonValue.Str(name), "description" to JsonValue.Str(""),
                "created_at" to JsonValue.Int(NOW - 100), "updated_at" to JsonValue.Int(NOW - 50),
                "revision" to JsonValue.Int(1), "starter" to JsonValue.Bool(starter),
            ),
        )
        val deletedRow = JsonValue.Obj(mapOf("id" to JsonValue.Str(GONE), "kind" to JsonValue.Str("note"), "title" to JsonValue.Str("Old")))
        return LocalData(
            trash = listOf(LocalData.TrashRow.of(deletedRow, NOW - 5)),
            extra = mapOf(
                "collections" to JsonValue.Arr(listOf(coll(FAMILY, "Family", true), coll(WORK, "Work", false))),
                "memberships" to JsonValue.Obj(
                    mapOf(
                        id(0) to JsonValue.Arr(listOf(JsonValue.Str(FAMILY), JsonValue.Str(WORK))),
                        GONE to JsonValue.Arr(listOf(JsonValue.Str(WORK))),
                    ),
                ),
            ),
        )
    }

    @Test fun migration_runs_once_writes_the_marker_and_never_brings_back_a_deleted_collection() {
        val old = legacy()
        val local = InMemoryLocalData(old)
        val store = CountingStore(pairedSnapshot(notes))
        assertTrue(CollectionsModel.migrate(store, local))
        val snap = store.snapshot
        assertTrue(snap.collectionsMigrated)
        assertEquals(listOf("Family", "Work"), CollectionCatalog.collections(snap).map { it.name })
        assertEquals(listOf(FAMILY, WORK), CollectionCatalog.memberships(id(0), snap))
        val data = local.localData!!
        assertFalse(data.hasLegacyCollections)
        assertEquals(listOf(FAMILY), data.starterCollectionIds)
        // The deleted item's membership moved into its Recently deleted row.
        assertEquals(JsonValue.Arr(listOf(JsonValue.Str(WORK))), (data.trash.single().record() as JsonValue.Obj).fields["collection_ids"])
        assertEquals(NOW - 5, data.trash.single().deletedAt)
        // Collection states are never items.
        assertEquals(notes.size, snap.itemRecords.size)

        // Once only.
        val commits = store.commits
        assertFalse(CollectionsModel.migrate(store, local))
        assertEquals(commits, store.commits)

        // The person deletes Work; then an old local copy comes back (the save failed or the app quit before it).
        val m = model(store, local)
        assertTrue(m.delete(WORK))
        local.commitLocalData(old)
        assertFalse(CollectionsModel.migrate(store, local))
        assertEquals(listOf("Family"), CollectionCatalog.collections(store.snapshot).map { it.name })
        assertEquals(listOf(FAMILY), CollectionCatalog.memberships(id(0), store.snapshot))
        assertFalse(local.localData!!.hasLegacyCollections)
    }

    @Test fun a_failed_store_commit_leaves_the_local_collections_for_the_next_unlock() {
        val local = InMemoryLocalData(legacy())
        val store = object : app.localgatekeys.core.sync.ItemStore {
            val inner = CountingStore(pairedSnapshot(notes))
            override fun load(): StoreSnapshot = inner.load()
            override fun commit(change: StoreChange) = throw java.io.IOException("disk full")
        }
        assertFalse(CollectionsModel.migrate(store, local))
        assertTrue(local.localData!!.hasLegacyCollections)
        assertFalse(store.inner.snapshot.collectionsMigrated)
    }

    // ---- the Vault filter ----

    @Test fun the_vault_filter_shows_one_collection_is_remembered_and_falls_back_to_all_items() {
        val store = withFamily()
        val settings = AppSettings(MemoryStore())
        val list = VaultListModel(store, txt)
        list.useSettings(settings)
        list.reload()
        assertEquals(4, list.listItems.size)
        list.setCollectionFilter(FAMILY)
        assertEquals("Family", list.collectionFilterName)
        assertEquals(listOf(id(0)), list.listItems.map { it.id })
        assertEquals(FAMILY, settings.vaultCollection)
        // A new list (next unlock) reads the choice back.
        val again = VaultListModel(store, txt).also { it.useSettings(settings); it.reload() }
        assertEquals(listOf(id(0)), again.listItems.map { it.id })
        // The collection goes: All items again.
        assertTrue(model(store).delete(FAMILY))
        again.reload()
        assertNull(again.collectionFilter.value)
        assertNull(settings.vaultCollection)
        assertEquals(4, again.listItems.size)
    }

    private companion object {
        const val FAMILY = "f0000000-0000-4000-8000-000000000001"
        const val WORK = "f0000000-0000-4000-8000-000000000002"
        const val GONE = "0d000000-0000-4000-8000-000000000009"
    }
}
