package app.localgatekeys.android

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.MemoryItemStore
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.sync.StoreSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The debug demo seed (debug source set only) holds real, normalised records: every editable item saves for real. */
class DemoSeedTest {
    @Test fun every_seeded_item_edits_and_saves_through_the_real_path() {
        val store = MemoryItemStore(StoreSnapshot(DemoSeed.wrapped()))
        val items = VaultItem.items(store.snapshot)
        assertEquals(12, items.size)
        val editable = items.filter { EditorKind.of(it.kind) != null }
        assertEquals(11, editable.size)
        for (item in editable) {
            // Opening and saving changes nothing: the seed is already in normal form.
            val same = EditorModel(store, item, EditorKind.NOTE, { true }, TestClock(1_800_000_000), CountingRandom(), EnglishTxt())
            assertEquals("${item.id}: ${same.error}", SaveResult.UNCHANGED, same.save())
            val e = EditorModel(store, item, EditorKind.NOTE, { true }, TestClock(1_800_000_000), CountingRandom(), EnglishTxt())
            e.set(e.titleKey, e.value(e.titleKey) + " edited")
            assertEquals("${item.id}: ${e.error}", SaveResult.SAVED, e.save())
        }
        assertTrue(VaultItem.items(store.snapshot).filter { EditorKind.of(it.kind) != null }.all { it.title.endsWith(" edited") })
    }
}
