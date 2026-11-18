package app.localgatekeys.android.trash

import app.localgatekeys.android.attachments.DocumentStore
import app.localgatekeys.android.backup.INSTALL_ID
import app.localgatekeys.android.backup.BackupExporter
import app.localgatekeys.android.backup.TEST_KDF
import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.editor.NOW
import app.localgatekeys.android.editor.PHONE_DEVICE
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.editor.editor
import app.localgatekeys.android.editor.numberedNotes
import app.localgatekeys.android.editor.pairedSnapshot
import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.unlock.tempDir
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.core.backup.PhoneBackupFormat
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.DirectoryAttachmentVault
import app.localgatekeys.core.sync.Documents
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Port of the iPhone's PhoneTrashTests: delete, undo, restore rules, purge, retention, documents, and what never leaves. */
class PhoneTrashTest {
    private val txt = EnglishTxt()
    private val clock = TestClock(NOW)
    private val notes = numberedNotes(5)
    private fun id(k: Int) = (notes[k].fields["id"] as JsonValue.Str).v

    private fun trash(
        store: ItemStore,
        local: LocalDataHosting = InMemoryLocalData(),
        pro: Boolean = false,
        attachments: DirectoryAttachmentVault? = null,
    ) = PhoneTrash(local, store, { pro }, clock, txt, attachments, io = kotlinx.coroutines.Dispatchers.Unconfined)

    @Test fun delete_keeps_a_row_and_writes_the_tombstone_that_syncs() {
        val store = CountingStore(pairedSnapshot(notes.take(2)))
        val t = trash(store)
        assertEquals(SaveResult.SAVED, t.moveToTrash(id(0)))
        assertNull(store.snapshot.records[id(0)])
        val tomb = store.snapshot.meta.getValue(id(0))
        assertTrue(tomb.deleted)
        assertEquals(mapOf("desk" to 3L, PHONE_DEVICE to 1L), tomb.vv)
        val row = t.rows.value.single()
        assertEquals(id(0), row.itemId)
        assertEquals("Note 0", row.title)
        assertEquals("Note", row.detail)
        assertEquals(NOW, row.deletedAt)
        assertEquals(30, t.daysLeft(row))
        assertEquals("30 days left", t.daysLeftText(row))
        assertEquals(id(0) to NOW, t.lastDeleted)
        // A second delete of an item that is gone: unchanged, no row.
        assertEquals(SaveResult.UNCHANGED, t.moveToTrash(id(0)))
        assertEquals(1, t.rows.value.size)
    }

    @Test fun undo_restores_the_same_record_and_the_restore_wins_the_next_sync() {
        val store = CountingStore(pairedSnapshot(notes.take(2)))
        val before = store.snapshot.records.getValue(id(1))
        val t = trash(store)
        t.moveToTrash(id(1))
        assertEquals(PhoneTrash.RestoreOutcome.Restored, t.undoLastDelete(isPro = false))
        assertTrue(CanonicalJson.encode(before, Dialect.UTF8).contentEquals(CanonicalJson.encode(store.snapshot.records.getValue(id(1)), Dialect.UTF8)))
        val meta = store.snapshot.meta.getValue(id(1))
        assertFalse(meta.deleted)
        // The tomb's vector is kept, so the next local view bumps it once past the delete.
        assertEquals(mapOf("desk" to 3L, PHONE_DEVICE to 1L), meta.vv)
        assertTrue(t.rows.value.isEmpty())
        assertNull(t.lastDeleted)
        assertEquals(PhoneTrash.RestoreOutcome.Failed("It is no longer in Recently deleted."), t.undoLastDelete(false))
    }

    @Test fun the_undo_toast_restores_and_says_so() = runBlocking {
        val store = CountingStore(pairedSnapshot(notes.take(1)))
        val t = trash(store)
        var restored = 0
        t.onRestored = { restored++ }
        val toast = UndoToast()
        t.moveToTrash(id(0))
        t.offerUndo(toast)
        val shown = toast.current.value!!
        assertEquals("Moved to Recently deleted", shown.message)
        assertEquals("Moved to Recently deleted. Undo is available.", shown.announcement)
        assertEquals(PhoneTrash.UNDO_MILLIS, shown.millis)
        toast.undo()
        assertEquals(1, restored)
        assertNotNull(store.snapshot.records[id(0)])
        assertEquals("Item restored", toast.current.value!!.message)
        assertFalse(toast.current.value!!.hasUndo)
    }

    @Test fun restore_over_the_free_limit_is_refused_and_pro_restores() {
        val many = numberedNotes(app.localgatekeys.android.pro.ItemLimit.FREE_ITEMS + 1)
        val store = CountingStore(snapshot(many))
        val t = trash(store)
        t.moveToTrash((many[0].fields["id"] as JsonValue.Str).v) // FREE_ITEMS live now: the free plan is full
        val row = t.rows.value.single()
        assertEquals(PhoneTrash.RestoreOutcome.Limit, t.restore(row.id, isPro = false))
        assertEquals(1, t.rows.value.size)
        assertEquals(PhoneTrash.RestoreOutcome.Restored, t.restore(row.id, isPro = true))
        assertEquals(many.size, store.snapshot.records.size)
    }

    @Test fun an_item_with_the_same_id_blocks_a_restore() {
        val store = CountingStore(snapshot(notes.take(1)))
        val t = trash(store)
        t.moveToTrash(id(0))
        val snap = store.snapshot
        store.snapshot = StoreSnapshot(snap.records + (id(0) to notesWrapper(0)), snap.meta, snap.sync, snap.revision)
        assertEquals(PhoneTrash.RestoreOutcome.Failed("An item with the same ID already exists."), t.restore(t.rows.value.single().id, true))
    }

    private fun notesWrapper(k: Int): JsonValue = snapshot(listOf(notes[k])).records.values.single()

    @Test fun a_failed_row_save_leaves_the_item_live() {
        val store = CountingStore(snapshot(notes.take(1)))
        val local = InMemoryLocalData().apply { failSaves = true }
        val t = trash(store, local)
        assertEquals(SaveResult.FAILED, t.moveToTrash(id(0)))
        assertNotNull(store.snapshot.records[id(0)])
        assertEquals(0, store.commits)
    }

    @Test fun a_failed_store_commit_takes_the_row_out_again() {
        val failing = object : ItemStore {
            val inner = CountingStore(snapshot(notes.take(1)))
            override fun load() = inner.load()
            override fun commit(change: StoreChange) = throw IllegalStateException("disk full")
        }
        val t = trash(failing)
        assertEquals(SaveResult.FAILED, t.moveToTrash(id(0)))
        assertTrue(t.rows.value.isEmpty())
        assertTrue(t.local.localData!!.trash.isEmpty())
    }

    @Test fun a_failed_row_removal_after_restore_undoes_the_store_change() {
        val store = CountingStore(pairedSnapshot(notes.take(1)))
        val local = InMemoryLocalData()
        val t = trash(store, local)
        t.moveToTrash(id(0))
        val afterDelete = store.snapshot
        local.failSaves = true
        assertEquals(PhoneTrash.RestoreOutcome.Failed("Recently deleted could not be saved on this phone."), t.restore(t.rows.value.single().id, true))
        assertNull(store.snapshot.records[id(0)])
        assertEquals(afterDelete.meta, store.snapshot.meta)
        assertEquals(1, t.rows.value.size)
    }

    @Test fun purge_and_empty_delete_for_good() {
        val store = CountingStore(snapshot(notes.take(3)))
        val t = trash(store)
        t.moveToTrash(id(0)); clock.now += 1
        t.moveToTrash(id(1)); clock.now += 1
        t.moveToTrash(id(2))
        assertEquals(listOf(id(2), id(1), id(0)), t.rows.value.map { it.itemId })
        t.purge(setOf(t.rows.value[1].id))
        assertEquals(listOf(id(2), id(0)), t.rows.value.map { it.itemId })
        t.emptyAll()
        assertTrue(t.rows.value.isEmpty())
        assertTrue(store.snapshot.records.isEmpty())
    }

    /** Release check 2026-11-01: after changing "Keep deleted items for", the rows still said "30 days left". */
    @Test fun a_changed_retention_lists_new_rows_with_the_new_days_left() {
        val store = CountingStore(snapshot(notes.take(1)))
        val t = trash(store)
        t.moveToTrash(id(0))
        val before = t.rows.value
        assertEquals("30 days left", t.daysLeftText(before.single()))
        t.setRetentionDays(60)
        val after = t.rows.value
        assertNotEquals("a new list, so the screen recomposes", before, after)
        assertEquals("60 days left", t.daysLeftText(after.single()))
        t.setRetentionDays(7)
        assertEquals("7 days left", t.daysLeftText(t.rows.value.single()))
    }

    @Test fun rows_past_the_retention_go_on_unlock_and_when_it_shortens() {
        val store = CountingStore(snapshot(notes.take(2)))
        val t = trash(store)
        t.moveToTrash(id(0))
        clock.now += 20 * 86_400
        t.moveToTrash(id(1))
        assertEquals(10, t.daysLeft(t.rows.value.first { it.itemId == id(0) }))
        clock.now += 10 * 86_400
        val last = t.rows.value.first { it.itemId == id(0) }
        assertEquals("removed soon", t.daysLeftText(last))
        clock.now += 1
        t.purgeExpired()
        assertEquals(listOf(id(1)), t.rows.value.map { it.itemId })
        t.setRetentionDays(7)
        assertTrue(t.rows.value.isEmpty())
        assertEquals(7, t.retentionDays)
        t.setRetentionDays(9999)
        assertEquals(365, t.retentionDays)
    }

    @Test fun a_login_row_shows_its_username_and_two_deletes_of_one_item_get_their_own_rows() {
        val web = JsonValue.Obj(
            mapOf(
                "id" to JsonValue.Str("w1"), "kind" to JsonValue.Str("web"), "label" to JsonValue.Str(""), "username" to JsonValue.Str("sam@example.com"),
                "password" to JsonValue.Str("x"), "scope" to JsonValue.Obj(mapOf("origin" to JsonValue.Str("https://example.com"))),
                "created_at" to JsonValue.Int(1), "updated_at" to JsonValue.Int(2),
            ),
        )
        val local = InMemoryLocalData(LocalData(trash = listOf(LocalData.TrashRow.of(web, NOW), LocalData.TrashRow.of(web, NOW))))
        val store = CountingStore()
        val t = trash(store, local)
        val rows = t.rows.value
        assertEquals(listOf("w1@$NOW#1", "w1@$NOW"), rows.map { it.id })
        assertEquals("Website login", rows[0].title)
        assertEquals("Website login · sam@example.com", rows[0].detail)
        assertEquals(PhoneTrash.RestoreOutcome.Restored, t.restore("w1@$NOW", true))
        // A login comes back in the entry namespace.
        assertEquals(JsonValue.Str("entry"), (store.snapshot.records.getValue("w1") as JsonValue.Obj).fields["ns"])
        assertEquals(1, t.rows.value.size)
    }

    @Test fun the_editor_and_the_detail_delete_go_through_the_trash() {
        val store = CountingStore(snapshot(notes.take(2)))
        val t = trash(store)
        val item = VaultItem.items(store.snapshot).first { it.id == id(0) }
        assertEquals(SaveResult.SAVED, editor(store, item, EditorKind.NOTE).delete(t.mover))
        assertEquals(SaveResult.SAVED, PhoneTrash.deleteItem(id(1), store, clock, t))
        assertEquals(setOf(id(0), id(1)), t.rows.value.map { it.itemId }.toSet())
        // Without a trash the delete is immediate, as before.
        val other = CountingStore(snapshot(notes.take(1)))
        assertEquals(SaveResult.SAVED, PhoneTrash.deleteItem(id(0), other, clock, null))
        assertTrue(other.snapshot.records.isEmpty())
    }

    @Test fun a_document_keeps_its_sealed_file_while_in_the_trash_and_gets_it_back() {
        val dir = tempDir("trash-docs")
        val live = DirectoryAttachmentVault(File(dir, "attachments"))
        val store = CountingStore()
        val docs = DocumentStore(store, live, SystemRandomSource(), clock)
        val data = "synthetic passport scan\n".toByteArray()
        val docId = docs.add(data, "passport.pdf", "application/pdf", "", true).second!!
        val ref = Documents.refOf(store.snapshot.records[docId])!!
        val t = trash(store, attachments = live, pro = true)
        assertEquals(SaveResult.SAVED, t.moveToTrash(docId))
        val keptDir = File(dir, PhoneTrash.KEPT_DIR)
        assertEquals(1, keptDir.list()!!.size)
        // The app's garbage collection after a load removes the live copy; the kept one stays, still sealed.
        assertEquals(1, docs.collectGarbage(System.currentTimeMillis() + 3_600_000))
        assertFalse(live.has(ref))
        assertFalse(String(keptDir.listFiles()!!.single().readBytes(), Charsets.ISO_8859_1).contains("passport scan"))
        // The row keeps the reference; restore brings record and file back.
        assertEquals(PhoneTrash.RestoreOutcome.Restored, t.restore(t.rows.value.single().id, true))
        assertEquals(ref.toJson(), (store.snapshot.records.getValue(docId) as JsonValue.Obj).fields["attachment"])
        assertArrayEquals(data, docs.read(docId))
        assertTrue(keptDir.list()!!.isEmpty())
        // Delete again and purge: the kept copy goes too.
        t.moveToTrash(docId)
        assertEquals(1, keptDir.list()!!.size)
        t.emptyAll()
        assertTrue(keptDir.list()!!.isEmpty())
    }

    @Test fun nothing_in_the_trash_syncs_or_reaches_a_backup() {
        val store = CountingStore(pairedSnapshot(notes.take(2)))
        val t = trash(store)
        t.moveToTrash(id(0))
        // Sync and the backup read only the store: the deleted item is a tombstone there, without its record.
        assertNull(store.snapshot.records[id(0)])
        val stored = store.snapshot.records.values.joinToString { String(CanonicalJson.encode(it, Dialect.UTF8), Charsets.UTF_8) }
        assertFalse(stored.contains("Note 0"))
        val bytes = BackupExporter(store, clock, CountingRandom(), "1.0.0", installId = { INSTALL_ID }, isPro = { true }, kdf = TEST_KDF)
            .export("correct horse battery staple 42")
        val backup = PhoneBackupFormat.read(bytes, "correct horse battery staple 42")
        val tomb = backup.states.single { it.itemId == id(0) }
        assertTrue(tomb.deleted)
        assertNull(tomb.item)
    }
}
