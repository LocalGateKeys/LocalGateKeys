package app.localgatekeys.android.detail

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.unlock.ManualScheduler
import app.localgatekeys.android.unlock.MemoryItemStore
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.VaultListModel
import app.localgatekeys.android.vault.i
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.android.vault.strs
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.json.JsonValue.Arr
import app.localgatekeys.core.json.JsonValue.Bool
import app.localgatekeys.core.records.PasswordHistory
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Workstream 8 on the login detail: masked past passwords, reveal after the owner check, copy, restore. */
class PasswordHistoryModelTest {
    private val now = 1_800_000_000L
    private val id = "0b5e0000-0000-4000-8000-000000000002"

    private val login = rec(
        "id" to s(id), "kind" to s("web"), "label" to s("Example"), "username" to s("ada"), "password" to s("current"),
        "scope" to rec("origin" to s("https://example.com")), "tags" to strs(), "favorite" to Bool(false),
        "created_at" to i(now - 100), "updated_at" to i(now - 100),
        "password_history" to Arr(
            listOf(rec("password" to s("older"), "changed_at" to i(now - 50)), rec("password" to s("oldest"), "changed_at" to i(now - 90))),
        ),
    )

    private val clock = TestClock(now)
    private val sink = FakeClipboardSink()
    private val clipboard = SecretClipboard(sink, AppSettings(MemoryStore()), ManualScheduler(clock), clock).also { it.focusChanged(true) }

    private fun item(): VaultItem = VaultItem.items(snapshot(listOf(login)))[0]

    @Test fun masked_until_the_owner_check_passes() = runBlocking {
        var answer = false
        var asked = 0
        val m = PasswordHistoryModel(item(), clipboard) { asked++; answer }
        assertEquals(2, m.entries.size)
        assertEquals(ItemDetailModel.MASK, m.display(0))
        assertFalse(m.toggleReveal())
        assertEquals(ItemDetailModel.MASK, m.display(0))
        answer = true
        assertTrue(m.toggleReveal())
        assertEquals("older", m.display(0))
        assertTrue(m.toggleReveal()) // hiding needs no check
        assertEquals(ItemDetailModel.MASK, m.display(1))
        assertEquals(2, asked)
    }

    @Test fun no_owner_check_means_no_reveal() = runBlocking {
        val m = PasswordHistoryModel(item(), clipboard)
        assertFalse(m.canReveal)
        assertFalse(m.toggleReveal())
    }

    @Test fun copy_goes_through_the_secret_clipboard() {
        PasswordHistoryModel(item(), clipboard).copy(1)
        assertEquals(FakeClipboardSink.Write("oldest", true), sink.history.single())
        assertEquals("Password history (2)", PasswordHistoryModel.rowLabel(2, EnglishTxt()))
    }

    @Test fun restore_round_trip_through_the_store() {
        val store = MemoryItemStore(snapshot(listOf(login)))
        assertEquals(SaveResult.SAVED, VaultListModel.restorePassword(store, id, 1, clock))
        val restored = VaultItem.items(store.load())[0].record
        assertEquals(JsonValue.Str("oldest"), restored["password"])
        assertEquals(listOf("current", "older"), PasswordHistory.entries(restored).map { it.password })
        assertEquals(JsonValue.Int(now), restored["updated_at"])
        assertEquals(SaveResult.FAILED, VaultListModel.restorePassword(store, id, 9, clock))
        assertEquals(SaveResult.FAILED, VaultListModel.restorePassword(store, "missing", 0, clock))
    }
}
