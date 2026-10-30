package app.localgatekeys.android.vault

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.unlock.MemoryItemStore
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.UnixClock
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultSortTest {
    private fun JsonValue?.str() = (this as JsonValue.Str).v

    /** `tests/vectors/vault_sort/cases.json`: the rule every app shares. */
    @Test fun every_shared_sort_vector_passes() {
        val repo = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot not set"))
        val o = (CanonicalJson.parse(File(repo, "tests/vectors/vault_sort/cases.json").readBytes()) as JsonValue.Obj).fields
        val items = (o.getValue("items") as JsonValue.Arr).items.map { r ->
            val f = (r as JsonValue.Obj).fields
            VaultItem.of(f["id"].str(), JsonValue.Obj(f + ("kind" to JsonValue.Str("note"))))!!
        }
        val cases = (o.getValue("cases") as JsonValue.Arr).items
        assertEquals(8, cases.size)
        for (c in cases) {
            val f = (c as JsonValue.Obj).fields
            val option = VaultSortOption.of(f["option"].str())!!
            val first = f["favorites_first"] == JsonValue.Bool(true)
            val expected = (f.getValue("expected") as JsonValue.Arr).items.map { it.str() }
            assertEquals("$option favorites_first=$first", expected, VaultSort(option, first).apply(items).map { it.id })
        }
    }

    @Test fun title_key_folds_width_accents_and_case() {
        assertEquals("eclair", VaultSort.titleKey("Éclair"))
        assertEquals("zoom", VaultSort.titleKey("Ｚoom"))
    }

    @Test fun a_search_keeps_relevance_order_and_the_plain_list_is_sorted() {
        val items = itemsOf(webLogin, note, card)
        val az = VaultSort(VaultSortOption.TITLE_ASC)
        assertEquals(listOf("w1", "c1", "n1"), VaultListModel.visible(items, "", VaultFilter.All, az, EnglishTxt()).map { it.id })
        assertEquals(VaultSearch.apply(items, "cabin", VaultFilter.All, EnglishTxt()), VaultListModel.visible(items, "cabin", VaultFilter.All, az, EnglishTxt()))
        assertEquals(listOf("n1"), VaultListModel.visible(items, " ", VaultFilter.Favorites, az, EnglishTxt()).map { it.id })
    }

    @Test fun the_sort_is_saved_per_phone() {
        val settings = AppSettings(MemoryStore())
        assertEquals(VaultSort(), settings.vaultSort)
        val m = VaultListModel(MemoryItemStore(snapshot(emptyList())), EnglishTxt())
        m.useSettings(settings)
        m.setSort(VaultSort(VaultSortOption.CREATED_DESC, favoritesFirst = true))
        assertEquals(VaultSort(VaultSortOption.CREATED_DESC, true), settings.vaultSort)
        val again = VaultListModel(MemoryItemStore(snapshot(emptyList())), EnglishTxt())
        again.useSettings(settings)
        assertEquals(VaultSort(VaultSortOption.CREATED_DESC, true), again.sort.value)
    }

    @Test fun favorite_toggle_writes_the_flag_and_bumps_updated_at() {
        // Catalog items need a UUID id to pass the normaliser.
        val uuidNote = JsonValue.Obj(note.fields + ("id" to s(NOTE_ID)) + ("created_at" to i(1_789_956_800)))
        val store = MemoryItemStore(snapshot(listOf(webLogin, deskLogin, uuidNote)))
        val m = VaultListModel(store, EnglishTxt())
        val clock = object : UnixClock { override val now = 1_800_000_000L }
        for ((id, want) in listOf("w1" to true, "d1" to false, NOTE_ID to false)) {
            assertEquals(id, SaveResult.SAVED, m.setFavorite(id, want, clock))
            m.reload()
            val it = m.items.value.first { it.id == id }
            assertEquals(id, want, it.favorite)
            assertEquals(id, 1_800_000_000L, it.updatedAt)
        }
        assertEquals(SaveResult.UNCHANGED, m.setFavorite("w1", true, clock))
        assertEquals(SaveResult.FAILED, m.setFavorite("missing", true, clock))
        assertTrue(m.items.value.first { it.id == "w1" }.favorite)
        assertFalse(m.items.value.first { it.id == NOTE_ID }.favorite)
    }

    private companion object {
        const val NOTE_ID = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
    }
}
