package app.localgatekeys.android.ui.features

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import app.localgatekeys.android.history.CleanUpModel
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
import org.junit.Rule
import org.junit.Test

/** Contract section 3.2: every merge is user-confirmed, "Merge all same logins" too. */
class CleanUpDialogTest {
    @get:Rule val rule = createComposeRule()

    private class FixedClock(override var now: Long) : UnixClock

    private class Store(var snapshot: StoreSnapshot) : ItemStore {
        override fun load() = snapshot
        override fun commit(change: StoreChange) {
            check(change.baseRevision == snapshot.revision)
            snapshot = StoreSnapshot(change.records, change.meta, change.sync, snapshot.revision + 1)
        }
    }

    private fun login(n: Int, updated: Long) = Obj(
        mapOf(
            "id" to Str("00000000-0000-4000-8000-00000000000$n"), "kind" to Str("web"), "title" to Str("Dup"),
            "username" to Str("carol"), "password" to Str("Pw-Dup-33x"),
            "scope" to Obj(mapOf("origin" to Str("https://dup.example.net"))),
            "created_at" to JsonValue.Int(1), "updated_at" to JsonValue.Int(updated), "favorite" to JsonValue.Bool(false),
            "tags" to JsonValue.Arr(emptyList()),
        ),
    )

    @Test fun merge_all_asks_first_and_only_merges_after_the_confirm() {
        val store = Store(StoreSnapshot(listOf(login(1, 5), login(2, 9)).associate { (it.fields["id"] as Str).v to Wrapper.make(Namespace.ITEM, it) }))
        val model = CleanUpModel(store, null, FixedClock(1_800_000_000L), { true }, { it })
        rule.setContent { LgkTheme { CleanUpDialog(model, { it }, onNeedsPro = {}, onChanged = {}, onDone = {}) } }
        rule.onNodeWithTag("hygiene-merge-all").performClick()
        rule.onNodeWithTag("hygiene-merge-all-confirm").assertIsDisplayed()
        rule.waitForIdle()
        assertEquals("nothing is merged before the confirm", 0L, store.snapshot.revision)
        rule.onNodeWithTag("hygiene-merge-all-confirm").performClick()
        rule.waitUntil(5_000) { store.snapshot.revision > 0L }
    }
}
