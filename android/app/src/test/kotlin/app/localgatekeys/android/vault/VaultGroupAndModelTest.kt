package app.localgatekeys.android.vault

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.unlock.MemoryItemStore
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.json.JsonValue.Obj
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultGroupAndModelTest {
    private fun k(id: String, kind: String, at: Long) = rec("id" to s(id), "kind" to s(kind), "title" to s(id), "updated_at" to i(at))

    @Test fun groups_are_logins_then_cards_and_notes_then_other_newest_first() {
        val items = itemsOf(
            k("n", "note", 5), k("w1", "web", 1), k("o", "wifi", 9), k("c", "card", 4),
            k("d", "desktop", 7), k("b", "bank_account", 3), k("i", "identity", 2), k("p", "passkey", 8),
        )
        val groups = VaultGroup.groups(items)
        assertEquals(listOf("Logins", "Cards and notes", "Other"), groups.map { EnglishTxt().s(it.first) })
        assertEquals(listOf("d", "w1"), groups[0].second.map { it.id })
        assertEquals(listOf("n", "c", "b", "i"), groups[1].second.map { it.id })
        assertEquals(listOf("o", "p"), groups[2].second.map { it.id })
    }

    @Test fun empty_groups_are_left_out() {
        assertEquals(listOf("Other"), VaultGroup.groups(itemsOf(k("o", "wifi", 1))).map { EnglishTxt().s(it.first) })
        assertTrue(VaultGroup.groups(emptyList()).isEmpty())
    }

    @Test fun the_four_logins_of_the_test_data_form_one_group_each() {
        val groups = VaultGroup.groups(itemsOf(webLogin, deskLogin, note, card))
        assertEquals(listOf("Logins", "Cards and notes"), groups.map { EnglishTxt().s(it.first) })
        assertEquals(listOf("w1", "d1"), groups[0].second.map { it.id })
        assertEquals(listOf("c1", "n1"), groups[1].second.map { it.id })
    }

    @Test fun list_model_loads_and_filters() {
        val m = VaultListModel(MemoryItemStore(snapshot(listOf(webLogin, note))), EnglishTxt())
        assertNull(m.snapshot)
        m.reload()
        assertEquals(listOf("w1", "n1"), m.visibleItems.map { it.id })
        m.query.value = "cabin"
        assertEquals(listOf("n1"), m.visibleItems.map { it.id })
        m.query.value = ""
        m.filter.value = VaultFilter.Kind("web")
        assertEquals(listOf("w1"), m.visibleItems.map { it.id })
        assertEquals(2, m.liveCount.value)
        assertEquals(2, m.snapshot?.records?.size)
        assertNull(m.loadError.value)
    }

    @Test fun a_filter_that_no_longer_has_items_falls_back_to_all() {
        val store = MemoryItemStore(snapshot(listOf(webLogin, note)))
        val m = VaultListModel(store, EnglishTxt())
        m.reload()
        m.filter.value = VaultFilter.Kind("note")
        store.snapshot = snapshot(listOf(webLogin))
        m.reload()
        assertEquals(VaultFilter.All, m.filter.value)
    }

    @Test fun a_store_that_cannot_be_read_reports_the_error_and_keeps_the_old_list() {
        var fail = false
        val inner = MemoryItemStore(snapshot(listOf(webLogin)))
        val m = VaultListModel(object : ItemStore {
            override fun load(): StoreSnapshot = if (fail) throw IllegalStateException("locked") else inner.load()
            override fun commit(change: StoreChange) = inner.commit(change)
        }, EnglishTxt())
        m.reload()
        fail = true
        m.reload()
        assertEquals("The vault could not be read on this device.", m.loadError.value)
        assertEquals(listOf("w1"), m.items.value.map { it.id })
        fail = false
        m.reload()
        assertNull(m.loadError.value)
    }

    @Test fun every_load_hands_its_snapshot_to_on_load_and_a_failed_one_does_not() {
        var fail = false
        val inner = MemoryItemStore(snapshot(listOf(webLogin)))
        val loaded = mutableListOf<StoreSnapshot>()
        val m = VaultListModel(object : ItemStore {
            override fun load(): StoreSnapshot = if (fail) throw IllegalStateException("locked") else inner.load()
            override fun commit(change: StoreChange) = inner.commit(change)
        }, EnglishTxt(), onLoad = { loaded += it })
        m.reload()
        m.reload() // the same items: the licence states may still have changed, so Pro hears of every load
        assertEquals(2, loaded.size)
        assertSame(m.snapshot, loaded.last())
        fail = true
        m.reload()
        assertEquals(2, loaded.size)
    }

    @Test fun live_count_follows_the_free_plan_rules() {
        val m = VaultListModel(MemoryItemStore(snapshot(listOf(webLogin, note, card), deleted = setOf("c1"))), EnglishTxt())
        m.reload()
        assertEquals(2, m.liveCount.value)
        assertEquals(2, m.items.value.size)
    }

    @Test fun concurrent_reloads_never_let_an_older_load_overwrite_a_newer_one() {
        val older = snapshot(listOf(webLogin))
        val newer = snapshot(listOf(webLogin, note))
        var current = older
        val firstInside = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val calls = java.util.concurrent.atomic.AtomicInteger()
        val m = VaultListModel(object : ItemStore {
            override fun load(): StoreSnapshot {
                if (calls.incrementAndGet() == 1) {
                    val read = current // the slow load read the old data ...
                    firstInside.countDown()
                    release.await()
                    return read
                }
                return current
            }
            override fun commit(change: StoreChange) = error("read only")
        }, EnglishTxt())
        val slow = Thread { m.reload() }
        slow.start()
        firstInside.await()
        current = newer // ... then the store changed and a second reload was asked for
        val fast = Thread { m.reload() }
        fast.start()
        Thread.sleep(200) // the second reload waits its turn; it must not finish first and then be overwritten
        release.countDown()
        slow.join()
        fast.join()
        assertEquals(setOf("w1", "n1"), m.items.value.map { it.id }.toSet())
        assertEquals(2, m.items.value.size)
        assertEquals(2, m.liveCount.value)
    }

    @Test fun codes_row_is_newest_first() {
        val a = k("a", "web", 1).let { Obj(it.fields + ("totp" to rec("secret" to s("JBSWY3DPEHPK3PXP")))) }
        val b = k("b", "note", 9).let { Obj(it.fields + ("totp" to rec("secret" to s("JBSWY3DPEHPK3PXP")))) }
        val c = k("c", "web", 5).let { Obj(it.fields + ("totp" to rec("secret" to s("JBSWY3DPEHPK3PXP")))) }
        assertEquals(listOf("b", "c", "a"), CodesRow.items(itemsOf(a, c, b), true, EnglishTxt()).map { it.id })
    }

    @Test fun to_string_never_shows_secrets() {
        val wifi = item("wifi", "payload" to rec("password" to s("wifi-secret-xyz")))
        val login = itemsOf(webLogin).first()
        for (text in listOf(login.toString(), wifi.toString(), listOf(login).toString())) {
            assertFalse(text, text.contains("Maple-Orbit-7731"))
            assertFalse(text, text.contains("JBSWY3DPEHPK3PXP"))
            assertFalse(text, text.contains("wifi-secret-xyz"))
            assertFalse(text, text.contains("sam"))
        }
        assertEquals("VaultItem(id=w1, kind=web)", login.toString())
        val state = TotpState.of(login, 1_700_000_000)!!
        assertFalse(state.toString().contains(state.code))
        assertFalse(CodeTileModel(login, app.localgatekeys.android.unlock.TestClock(1_700_000_000)).state.toString().contains(state.code))
    }
}
