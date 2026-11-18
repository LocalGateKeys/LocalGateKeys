package app.localgatekeys.android.ui.trash

import androidx.compose.foundation.layout.Box
import androidx.compose.material3.Text
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.appTxt
import app.localgatekeys.android.trash.InMemoryLocalData
import app.localgatekeys.android.trash.LocalData
import app.localgatekeys.android.trash.PhoneTrash
import app.localgatekeys.android.trash.UndoToast
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.json.JsonValue.Obj
import app.localgatekeys.core.json.JsonValue.Str
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** Settings › Recently deleted and the Undo toast on a device: rows, restore, the free limit, delete forever, empty, undo. */
class RecentlyDeletedScreenTest {
    @get:Rule val rule = createComposeRule()

    private class FixedClock(override var now: Long) : UnixClock

    private class Store(var snapshot: StoreSnapshot = StoreSnapshot()) : ItemStore {
        override fun load() = snapshot
        override fun commit(change: StoreChange) {
            check(change.baseRevision == snapshot.revision)
            snapshot = StoreSnapshot(change.records, change.meta, change.sync, snapshot.revision + 1)
        }
    }

    private val now = 1_800_000_000L
    private val txt = appTxt()

    private fun note(n: Int, title: String) = Obj(
        mapOf(
            "id" to Str("00000000-0000-4000-8000-00000000000$n"), "kind" to Str("note"), "title" to Str(title),
            "created_at" to JsonValue.Int(1), "updated_at" to JsonValue.Int(2), "favorite" to JsonValue.Bool(false),
            "tags" to JsonValue.Arr(emptyList()), "payload" to Obj(mapOf("body" to Str("b"))),
        ),
    )

    private fun storeWith(vararg notes: Obj) = Store(
        StoreSnapshot(notes.associate { (it.fields["id"] as Str).v to Wrapper.make(Namespace.ITEM, it) }),
    )

    private fun show(trash: PhoneTrash, pro: Boolean = false, onUpgrade: () -> Unit = {}, restored: () -> Unit = {}) {
        rule.setContent {
            LgkTheme {
                RecentlyDeletedScreen(trash, isPro = { pro }, onUpgrade = onUpgrade, onRestored = restored, toast = null, onBack = {})
            }
        }
    }

    @Test fun an_empty_trash_says_so_and_cannot_be_emptied() {
        show(PhoneTrash(InMemoryLocalData(), Store(), { false }, FixedClock(now), txt, null))
        rule.onNodeWithText(txt.s(R.string.trash_empty)).assertIsDisplayed()
        rule.onNodeWithTag("trash-empty-all").assertIsNotEnabled()
    }

    @Test fun restore_puts_the_item_back_and_delete_forever_asks_first() {
        val store = storeWith(note(1, "Gym locker"), note(2, "Wi-Fi at home"))
        val trash = PhoneTrash(InMemoryLocalData(), store, { true }, FixedClock(now), txt, null)
        trash.moveToTrash("00000000-0000-4000-8000-000000000001")
        trash.moveToTrash("00000000-0000-4000-8000-000000000002")
        var restored = 0
        show(trash, pro = true, restored = { restored++ })
        rule.onNodeWithText("Gym locker").assertIsDisplayed()
        val second = txt.s(R.string.trash_join, txt.s(R.string.kind_note), txt.plural(R.plurals.trash_days_left, 30, 30))
        assertEquals(2, rule.onAllNodesWithText(second, useUnmergedTree = true).fetchSemanticsNodes().size)
        assertEquals(2, rule.onAllNodesWithTag("trash-row").fetchSemanticsNodes().size)
        rule.onAllNodesWithTag("trash-restore")[0].performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("trash-row").fetchSemanticsNodes().size == 1 }
        assertEquals(1, restored)
        assertEquals(1, store.snapshot.records.size)
        rule.onNodeWithTag("trash-delete-forever").performClick()
        rule.onNodeWithText(txt.s(R.string.trash_delete_forever_title)).assertIsDisplayed()
        rule.onNodeWithTag("confirm-delete-forever").performClick()
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("trash-row").fetchSemanticsNodes().isEmpty() }
        rule.onNodeWithText(txt.s(R.string.trash_empty)).assertIsDisplayed()
    }

    @Test fun restore_over_the_free_limit_opens_the_upgrade_sheet() {
        val store = storeWith(note(1, "A"), note(2, "B"), note(3, "C"), note(4, "D"), note(5, "E"), note(6, "F"), note(7, "G"), note(8, "H"))
        val trash = PhoneTrash(InMemoryLocalData(), store, { false }, FixedClock(now), txt, null)
        trash.moveToTrash("00000000-0000-4000-8000-000000000001")
        var upgrades = 0
        show(trash, pro = false, onUpgrade = { upgrades++ })
        rule.onNodeWithTag("trash-restore").performClick()
        rule.waitUntil(5_000) { upgrades == 1 }
        assertEquals(1, rule.onAllNodesWithTag("trash-row").fetchSemanticsNodes().size)
    }

    @Test fun empty_recently_deleted_is_confirmed() {
        val store = storeWith(note(1, "A"))
        val local = InMemoryLocalData()
        val trash = PhoneTrash(local, store, { true }, FixedClock(now), txt, null)
        trash.moveToTrash("00000000-0000-4000-8000-000000000001")
        show(trash)
        rule.onNodeWithTag("trash-empty-all").performClick()
        rule.onNodeWithText(txt.s(R.string.trash_empty_all_title)).assertIsDisplayed()
        rule.onNodeWithTag("confirm-empty").performClick()
        rule.waitUntil(5_000) { local.localData!!.trash.isEmpty() }
        rule.onNodeWithText(txt.s(R.string.trash_empty)).assertIsDisplayed()
    }

    @Test fun the_undo_toast_restores_the_deleted_item() {
        val store = storeWith(note(1, "Gym locker"))
        val trash = PhoneTrash(InMemoryLocalData(LocalData.EMPTY), store, { true }, FixedClock(now), txt, null)
        val toast = UndoToast()
        rule.setContent { LgkTheme { UndoToastHost(toast) { Box { Text("content") } } } }
        trash.moveToTrash("00000000-0000-4000-8000-000000000001")
        rule.runOnIdle { trash.offerUndo(toast) }
        rule.onNodeWithText(txt.s(R.string.trash_moved)).assertIsDisplayed()
        rule.onNodeWithTag("undo-button").performClick()
        rule.waitUntil(5_000) { store.snapshot.records.isNotEmpty() }
        assertNotNull(store.snapshot.records["00000000-0000-4000-8000-000000000001"])
        rule.waitUntil(5_000) { toast.current.value?.message == txt.s(R.string.trash_item_restored) }
        assertTrue(trash.rows.value.isEmpty())
    }
}
