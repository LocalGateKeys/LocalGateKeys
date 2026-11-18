package app.localgatekeys.android.ui.collections

import app.localgatekeys.android.ui.vault.VaultMoreMenu
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.Modifier
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.compose.material3.TextButton
import androidx.compose.material3.Text
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import app.localgatekeys.android.collections.CollectionsModel
import app.localgatekeys.android.i18n.appTxt
import app.localgatekeys.android.trash.InMemoryLocalData
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.vault.VaultScreen
import app.localgatekeys.android.ui.vault.VaultSeams
import app.localgatekeys.android.vault.Copier
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.VaultListModel
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.json.JsonValue.Obj
import app.localgatekeys.core.json.JsonValue.Str
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Sub-plan 07 Task 5l on the device: create a collection, put a note in it, filter the Vault list by it, delete the
 * collection, and the note stays.
 */
class CollectionsFlowTest {
    @get:Rule val rule = createComposeRule()

    private class Store(@Volatile var snapshot: StoreSnapshot) : ItemStore {
        override fun load() = snapshot

        @Synchronized override fun commit(change: StoreChange) {
            check(change.baseRevision == snapshot.revision)
            snapshot = StoreSnapshot(change.records, change.meta, change.sync, snapshot.revision + 1, snapshot.shares)
        }
    }

    private class FixedClock(override var now: Long) : UnixClock

    private fun note(id: String, title: String): Pair<String, JsonValue> = id to Wrapper.make(
        Namespace.ITEM,
        Obj(mapOf("id" to Str(id), "kind" to Str("note"), "title" to Str(title), "updated_at" to JsonValue.Int(10))),
    )

    private val clock = FixedClock(1_800_000_000)
    private val n1 = "00000000-0000-4000-8000-000000000001"
    private val n2 = "00000000-0000-4000-8000-000000000002"

    @Test fun create_fill_filter_and_delete_a_collection_and_the_note_stays() {
        val store = Store(StoreSnapshot(mapOf(note(n1, "Passports"), note(n2, "Garden"))))
        val collections = CollectionsModel(store, InMemoryLocalData(), clock, appTxt())

        // Vault › Collections: none yet, no starters seeded; New collection.
        rule.setContent { LgkTheme { CollectionsScreen(collections, onChange = {}, onBack = {}) } }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("collections-empty").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithTag("collections-add-starters").assertIsDisplayed()
        rule.onNodeWithTag("collections-new").performClick()
        rule.onNodeWithTag("collections-name").performTextInput("Family")
        rule.onNodeWithTag("collections-name-confirm").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("collection-row").fetchSemanticsNodes().size == 1 }
        rule.onNodeWithText("Family").assertIsDisplayed()
        val family = CollectionCatalog.collections(store.snapshot).single().id
        assertTrue(collections.setMemberships(n1, "note", setOf(family)))
        collections.reload()
        rule.waitForIdle()

        // The Vault list filtered by Family shows only the note in it.
        val list = VaultListModel(store, appTxt())
        list.reload()
        list.setCollectionFilter(family)
        assertEquals(listOf(n1), list.listItems.map(VaultItem::id))

        // Delete the collection (confirmed): the notes stay.
        rule.onNodeWithTag("collection-row-menu").performClick()
        rule.onNodeWithTag("collection-delete").performClick()
        rule.onNodeWithTag("collections-confirm-delete").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("collection-row").fetchSemanticsNodes().isEmpty() }
        assertEquals(setOf(n1, n2), VaultItem.items(store.snapshot).map { it.id }.toSet())
        assertTrue(CollectionCatalog.collections(store.snapshot).isEmpty())
    }

    @Test fun the_vault_filter_menu_picks_a_collection_and_the_chip_clears_it() {
        val store = Store(StoreSnapshot(mapOf(note(n1, "Passports"), note(n2, "Garden"))))
        val collections = CollectionsModel(store, InMemoryLocalData(), clock, appTxt())
        val family = collections.create("Family")!!
        assertTrue(collections.setMemberships(n1, "note", setOf(family)))
        val model = VaultListModel(store, appTxt())
        val seams = VaultSeams(clipboard = Copier { _, _ -> }, clock = clock, onOpenCollections = {})
        // The "more" menu sits in the root header since the vault header refresh (8840df49); the same menu is shown
        // here above the vault list, opened by a stand-in for the header's button.
        rule.setContent {
            LgkTheme {
                Column {
                    var open by remember { mutableStateOf(false) }
                    Box {
                        TextButton({ open = true }, Modifier.testTag("vault-more-menu")) { Text("More") }
                        val sort by model.sort.collectAsState()
                        val list by model.collections.collectAsState()
                        val chosen by model.collectionFilter.collectAsState()
                        VaultMoreMenu(open, { open = false }, sort, model::setSort, list, chosen, model::setCollectionFilter, seams.onOpenCollections)
                    }
                    VaultScreen(model, showCodesRow = false, seams = seams)
                }
            }
        }
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().size == 2 }
        rule.onNodeWithTag("vault-more-menu").performClick()
        rule.onNodeWithTag("collections-menu-manage").assertIsDisplayed()
        rule.onNodeWithTag("collections-menu-item").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().size == 1 }
        rule.onNodeWithTag("collection-filter-chip").assertIsDisplayed()
        rule.onNodeWithText("Passports").assertIsDisplayed()
        rule.onNodeWithTag("collection-filter-chip").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("vault-row").fetchSemanticsNodes().size == 2 }
        rule.onAllNodesWithTag("collection-filter-chip").assertCountEquals(0)
    }
}
