package app.localgatekeys.android.sync

import app.localgatekeys.android.collections.CollectionsModel
import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.NOW
import app.localgatekeys.android.editor.numberedNotes
import app.localgatekeys.android.editor.pairedSnapshot
import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.trash.InMemoryLocalData
import app.localgatekeys.android.trash.LocalData
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.KeyringException
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.core.sync.CollectionStates
import app.localgatekeys.core.sync.FolderLayout
import app.localgatekeys.core.sync.FolderSync
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.Removal
import app.localgatekeys.core.sync.ShareGroupException
import app.localgatekeys.core.sync.ShareGroups
import app.localgatekeys.core.sync.ShareRecord
import app.localgatekeys.core.sync.ShareTrash
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import app.localgatekeys.core.sync.itemRecords
import java.io.File
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Sub-plan 07 carry-forward from 5k: the phone's store moves every live item a share commit takes out into Recently
 * deleted (never a hard delete), with one trash limit for the share runner and the app, and the share runner gets the
 * real share password rule.
 */
class ShareTrashingStoreTest {
    private val notes = numberedNotes(3)
    private fun id(k: Int) = (notes[k].fields["id"] as JsonValue.Str).v

    @Test fun one_trash_limit_for_the_share_runner_and_the_app() {
        assertEquals(ShareTrash.MAX_TRASH, LocalData.MAX_TRASH)
    }

    @Test fun a_share_commit_that_takes_items_out_moves_them_to_recently_deleted_with_their_collections() {
        val base = pairedSnapshot(notes)
        val records = LinkedHashMap(base.records)
        records[CollectionStates.CATALOG_PREFIX + CID] = CollectionStates.wrapper(CollectionStates.catalog(CID, "Family", "", NOW, NOW))
        records[CollectionStates.MEMBERSHIP_PREFIX + id(0)] = CollectionStates.wrapper(CollectionStates.membership(id(0), listOf(CID)))
        val inner = CountingStore(base.copy(records = records))
        val local = InMemoryLocalData()
        val store = ShareTrashingStore(inner, local) { NOW + 7 }
        val snap = store.load()
        // A remote delete of note 0 (and its membership), and note 1's tombstone.
        val next = LinkedHashMap(snap.records).apply {
            remove(id(0)); remove(CollectionStates.MEMBERSHIP_PREFIX + id(0)); remove(id(1))
        }
        store.commit(StoreChange(snap.revision, next, snap.meta, snap.sync))
        val rows = local.localData!!.trash
        assertEquals(listOf(id(0), id(1)), rows.map { ((it.record() as JsonValue.Obj).fields["id"] as JsonValue.Str).v })
        assertEquals(JsonValue.Arr(listOf(JsonValue.Str(CID))), (rows[0].record() as JsonValue.Obj).fields["collection_ids"])
        assertEquals(listOf(NOW + 7, NOW + 7), rows.map { it.deletedAt })
        assertEquals(setOf(id(2)), inner.snapshot.itemRecords.keys)
        // The runner reads the same rows back.
        assertEquals(2, store.shareTrash().count)
        assertEquals(listOf(CID), store.shareTrash().collections[id(0)])
        // A commit that takes nothing out writes no row.
        val again = store.load()
        store.commit(StoreChange(again.revision, again.records, again.meta, again.sync))
        assertEquals(2, local.localData!!.trash.size)
    }

    @Test fun a_full_or_closed_trash_refuses_before_anything_changes_and_a_failed_commit_takes_its_rows_back() {
        val inner = CountingStore(pairedSnapshot(notes))
        val full = InMemoryLocalData(LocalData(trash = List(LocalData.MAX_TRASH) { LocalData.TrashRow("{}", 1) }))
        val snap = inner.load()
        val drop = StoreChange(snap.revision, snap.records - id(0), snap.meta, snap.sync)
        try {
            ShareTrashingStore(inner, full) { NOW }.commit(drop)
            fail("expected trash-full")
        } catch (e: ShareTrashRefusal) {
            assertEquals("trash-full", e.kind)
        }
        assertEquals(0, inner.commits)

        val closed = object : app.localgatekeys.android.trash.LocalDataHosting {
            override val localData: LocalData? = null
            override fun commitLocalData(data: LocalData) = Unit
        }
        try {
            ShareTrashingStore(inner, closed) { NOW }.commit(drop)
            fail("expected item-error")
        } catch (e: ShareTrashRefusal) {
            assertEquals("item-error", e.kind)
        }
        assertEquals(0, inner.commits)
        assertNull(ShareTrashingStore(inner, closed) { NOW }.shareTrash().count)

        val local = InMemoryLocalData()
        val failing = object : ItemStore {
            override fun load(): StoreSnapshot = inner.load()
            override fun commit(change: StoreChange) = throw IOException("disk full")
        }
        try {
            ShareTrashingStore(failing, local) { NOW }.commit(drop)
            fail("expected the store's error")
        } catch (e: IOException) {
            // passed through
        }
        assertTrue(local.localData!!.trash.isEmpty())
        assertTrue(inner.snapshot.records.containsKey(id(0)))
    }

    // ---- the desktop's share vectors, end to end through the phone's store ----

    private val shareVectors: Map<String, JsonValue> by lazy {
        val f = File(System.getProperty("lgk.repoRoot")!!, "tests/vectors/share/collections/keyring.json")
        (CanonicalJson.parse(f.readBytes()) as JsonValue.Obj).fields
    }

    private fun obj(v: JsonValue?) = SyncVectors.obj(v)
    private fun str(v: JsonValue?) = SyncVectors.str(v)
    private fun canonical(v: JsonValue) = CanonicalJson.encode(v, Dialect.UTF8)

    private fun note(id: String, title: String): JsonValue = Wrapper.make(
        Namespace.ITEM,
        JsonValue.Obj(
            mapOf(
                "id" to JsonValue.Str(id), "kind" to JsonValue.Str("note"), "title" to JsonValue.Str(title),
                "created_at" to JsonValue.Int(NOW), "updated_at" to JsonValue.Int(NOW), "favorite" to JsonValue.Bool(false),
                "tags" to JsonValue.Arr(emptyList()),
                "payload" to JsonValue.Obj(mapOf("body" to JsonValue.Str(title), "fields" to JsonValue.Arr(emptyList()))),
            ),
        ),
    )

    /** Member B of the vectors' read-only share (holding `join_c`), with one shared item and one personal item. */
    private fun vectorMember(): Pair<SharesKeepingStore, ShareRecord> {
        val v = shareVectors
        val gid = str(v["group_id"])
        val cid = str(v["collection_id"])
        val gk1 = GroupKey(gid, 1, SyncVectors.hex(str(obj(v["create"])["group_key_hex"])))
        val joinedC = obj(v["join_c"])["keyring"]!!
        val identity = SyncVectors.identity("B")
        val state = SyncGroupState(
            gid, 1, gk1.key, identity, "install-B", true, membersEpoch = 1, members = ShareKeyring.memberIds(joinedC),
            keyring = canonical(joinedC), unackedMembers = ShareKeyring.pending(joinedC, identity.deviceId),
        )
        val record = ShareRecord(ShareRecord.Role.MEMBER, ShareKeyring.Pin.of(joinedC), state)
        val records = LinkedHashMap<String, JsonValue>()
        records[CollectionStates.CATALOG_PREFIX + cid] = CollectionStates.wrapper(CollectionStates.catalog(cid, "Family", "", NOW, NOW))
        records[ITEM_A] = note(ITEM_A, "Shared")
        records[CollectionStates.MEMBERSHIP_PREFIX + ITEM_A] = CollectionStates.wrapper(CollectionStates.membership(ITEM_A, listOf(cid)))
        records[ITEM_P] = note(ITEM_P, "Mine")
        val store = SharesKeepingStore()
        store.commit(StoreChange(0, records, emptyMap(), null, StoreChange.Shares.Replace(ShareRecord.encode(mapOf(gid to record)))))
        assertEquals(mapOf(gid to record), ShareGroups.records(store.load()))
        return store to record
    }

    @Test fun the_owners_removal_moves_the_shared_items_to_recently_deleted_never_deleting_them() {
        val (inner, record) = vectorMember()
        val local = InMemoryLocalData()
        val store = ShareTrashingStore(inner, local) { NOW }
        val r = obj(shareVectors["remove_b"])
        val folder = MemoryFolder()
        folder.files[FolderLayout.KEYRING_PATH] = canonical(r["keyring"]!!)
        folder.files[Removal.noticePath(record.state.deviceId)!!] = str(r["notice"]).toByteArray(Charsets.US_ASCII)
        val fs = FolderSync(folder, "install-B", share = FolderSync.Share(record.groupId, true, store.shareTrash()))
        val report = fs.runOnce(store, SystemRandomSource(), TestClock((shareVectors["now"] as JsonValue.Int).v + 1000))
        assertEquals(listOf("share-removed"), report.issues.map { it.kind })
        // The shared item left the vault and waits in Recently deleted with its collection; the personal one stays.
        assertEquals(setOf(ITEM_P), inner.load().itemRecords.keys)
        val row = local.localData!!.trash.single().record() as JsonValue.Obj
        assertEquals(JsonValue.Str(ITEM_A), row.fields["id"])
        assertEquals(JsonValue.Arr(listOf(JsonValue.Str(record.collectionId))), row.fields["collection_ids"])
        assertEquals(emptyMap<String, ShareRecord>(), ShareGroups.records(inner.load()))
    }

    @Test fun a_read_only_member_cannot_rename_the_shared_collection_from_its_own_share_record() {
        val (inner, record) = vectorMember()
        val snap = inner.load()
        assertTrue(record.collectionId in CollectionsModel.readOnlyCollectionIds(snap))
        // The catalog alone (other devices' links only) would allow it.
        assertTrue(CollectionCatalog.rename(record.collectionId, "Ours", snapshot = snap, now = NOW) != null)
        val m = CollectionsModel(inner, InMemoryLocalData(), TestClock(NOW), EnglishTxt())
        assertFalse(m.rename(record.collectionId, "Ours"))
        assertEquals("Family", CollectionCatalog.collections(inner.load()).single().name)
        assertTrue(CollectionsModel.itemIsReadOnly(ITEM_A, snap))
        assertFalse(CollectionsModel.itemIsReadOnly(ITEM_P, snap))
    }

    @Test fun the_share_runner_gets_the_real_share_password_rule() {
        val deps = SyncDependencies(
            slots = app.localgatekeys.android.vault.SecretSlots(
                File.createTempFile("secrets", ".bin").also { it.delete(); it.deleteOnExit() }, ByteArray(32) { 3 }, SystemRandomSource(),
            ),
            folders = FolderOpening.UNAVAILABLE,
            lan = LanTransporting.UNAVAILABLE, random = CountingRandom(), clock = TestClock(NOW), licenseKeys = emptyMap(),
        )
        assertFalse(deps.strongSharePassword("password1234"))
        assertFalse(deps.strongSharePassword("short"))
        assertTrue(deps.strongSharePassword("correct horse battery staple 42"))
        val store = CountingStore(pairedSnapshot(notes))
        val (change, cid) = CollectionCatalog.create("Family", snapshot = store.load(), now = NOW)
        store.commit(change)
        val reason = try {
            ShareGroups.create(
                store, cid, "password1234", "Phone", "edit", "install-1", isPro = true, random = SystemRandomSource(),
                clock = TestClock(NOW), strong = deps.strongSharePassword,
            )
            null
        } catch (e: KeyringException) {
            e.reason
        } catch (e: ShareGroupException) {
            e.reason
        }
        assertEquals("weak-password", reason)
        assertNull(store.snapshot.shares)
    }

    /** An in-memory store that keeps and replaces share groups as LocalStore does. */
    private class SharesKeepingStore : ItemStore {
        private var current = StoreSnapshot()

        @Synchronized override fun load(): StoreSnapshot = current

        @Synchronized override fun commit(change: StoreChange) {
            check(change.baseRevision == current.revision) { "stale" }
            val shares = when (val s = change.shares) {
                StoreChange.Shares.Keep -> current.shares
                is StoreChange.Shares.Replace -> s.value
            }
            current = StoreSnapshot(change.records, change.meta, change.sync, current.revision + 1, shares)
        }
    }

    private companion object {
        const val CID = "f0000000-0000-4000-8000-000000000001"
        const val ITEM_A = "a0000000-0000-4000-8000-00000000000a"
        const val ITEM_P = "a0000000-0000-4000-8000-00000000000b"
    }
}
