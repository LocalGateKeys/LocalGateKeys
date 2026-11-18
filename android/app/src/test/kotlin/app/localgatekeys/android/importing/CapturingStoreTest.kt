package app.localgatekeys.android.importing

import app.localgatekeys.android.unlock.MemoryItemStore
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.core.importing.ImportUndo
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * The import undo journal comes from the import's own commit (scan W-L4 / Android suspicion 6): an item a sync brings in
 * while the import runs is never recorded as created by it, so Undo never trashes it.
 */
class CapturingStoreTest {
    private fun note(id: String, title: String) =
        Wrapper.make(Namespace.ITEM, rec("id" to s(id), "kind" to s("note"), "title" to s(title)))

    private fun add(snap: StoreSnapshot, vararg w: Pair<String, app.localgatekeys.core.json.JsonValue>) =
        StoreChange(snap.revision, snap.records + w, snap.meta, snap.sync)

    @Test fun a_sync_landing_during_the_import_is_not_in_its_journal() {
        val inner = MemoryItemStore(StoreSnapshot(mapOf("old" to note("old", "Old"))))
        val store = CapturingStore(inner)
        val first = store.load()
        // A sync commits straight to the store before the import writes.
        inner.commit(add(inner.load(), "synced" to note("synced", "From sync")))
        assertThrows(IllegalStateException::class.java) { store.commit(add(first, "imp" to note("imp", "Imported"))) }
        // The import's retry loads again and writes on top of the sync.
        val second = store.load()
        store.commit(add(second, "imp" to note("imp", "Imported")))
        val j = ImportUndo.journal("j", 1, "csv", recordsOf(store.base!!), recordsOf(store.after!!))
        assertEquals(setOf("imp"), j.created.keys)
        assertEquals(emptySet<String>(), j.replaced.keys)
    }

    @Test fun a_commit_not_based_on_the_last_load_records_nothing() {
        val inner = MemoryItemStore(StoreSnapshot())
        val store = CapturingStore(inner)
        val seen = store.load()
        inner.commit(add(inner.load(), "synced" to note("synced", "From sync")))
        // Committed against a revision the wrapper never loaded: no journal rather than a wrong one.
        store.commit(add(inner.load(), "imp" to note("imp", "Imported")))
        assertEquals(0L, seen.revision)
        assertNull(store.base)
        assertNull(store.after)
    }
}
